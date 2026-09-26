"""Explicit integration test: sudo unshare --net python tests/check_management_native.py.
Temporary child namespaces are created and removed. Refuses the host namespace.
"""
import copy
import importlib.util
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import patch

if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('REFUSED: run in an isolated network namespace with unshare --net.')
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
spec = importlib.util.spec_from_file_location('core_native_management', ROOT / 'core/core.py')
core = importlib.util.module_from_spec(spec)
with patch('os.makedirs'):
    spec.loader.exec_module(core)
from management import DEFAULT_POLICY
# /sys remains mounted from the host in a plain network namespace. Inspect ip instead.
core.interface_exists = lambda name: subprocess.run(['ip', 'link', 'show', 'dev', name], capture_output=True).returncode == 0
m = core.management
names = ['nrtest-' + uuid.uuid4().hex[:8] for _ in range(2)]
children = []
tmp = tempfile.TemporaryDirectory()
core.DATA = tmp.name + '/data'
core.CONFIG = tmp.name + '/config'
core.RUNTIME_DIR = tmp.name + '/run'
Path(core.DATA).mkdir()
Path(core.CONFIG).mkdir()
os.chmod(tmp.name, 0o755)

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout

def ns(index, *args):
    return run('ip', 'netns', 'exec', names[index], *args)

def connection(index, destination, port):
    code = 'import socket; s=socket.create_connection((' + repr(destination) + ',' + str(port) + '),timeout=.7); s.close()'
    result = subprocess.run(['ip', 'netns', 'exec', names[index], sys.executable, '-c', code], capture_output=True)
    return result.returncode == 0

try:
    run('ip', 'link', 'set', 'lo', 'up')
    run('sysctl', '-w', 'net.ipv4.ip_forward=1')
    for index, (router, host) in enumerate([('192.0.2.1', '192.0.2.2'), ('198.51.100.1', '198.51.100.2')]):
        run('ip', 'netns', 'add', names[index])
        run('ip', 'link', 'add', 'test' + str(index), 'type', 'veth', 'peer', 'name', 'peer' + str(index))
        run('ip', 'link', 'set', 'peer' + str(index), 'netns', names[index])
        run('ip', 'addr', 'add', router + '/24', 'dev', 'test' + str(index))
        run('ip', 'link', 'set', 'test' + str(index), 'up')
        ns(index, 'ip', 'link', 'set', 'lo', 'up')
        ns(index, 'ip', 'addr', 'add', host + '/24', 'dev', 'peer' + str(index))
        ns(index, 'ip', 'link', 'set', 'peer' + str(index), 'up')
        ns(index, 'ip', 'route', 'add', 'default', 'via', router)
    ns(1, 'ip', 'addr', 'add', '198.51.100.3/24', 'dev', 'peer1')
    ns(0, 'ip', 'addr', 'add', '192.0.2.3/24', 'dev', 'peer0')
    for index, port in [(1, 8080), (1, 8081), (0, 8080)]:
        children.append(subprocess.Popen(['ip', 'netns', 'exec', names[index], sys.executable, '-m', 'http.server', str(port), '--bind', '0.0.0.0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(.5)
    for _ in range(20):
        if connection(0, '198.51.100.2', 8080):
            break
        time.sleep(.25)
    else:
        print(run('ip', '-br', 'addr'), run('ip', 'route'), run('nft', 'list', 'ruleset'))
        print([c.poll() for c in children], ns(0, 'ip', 'route'), ns(1, 'ip', 'route'))
        raise AssertionError('Baseline TCP connectivity failed')
    allow = m.validate_rule({'source': '192.0.2.0/24', 'destination': '198.51.100.2', 'protocol': 'tcp', 'port': '8080', 'action': 'accept', 'enabled': True})
    deny = m.validate_rule({'source': '192.0.2.0/24', 'destination': '198.51.100.0/24', 'protocol': 'any', 'action': 'drop', 'enabled': True})
    policy = {**copy.deepcopy(DEFAULT_POLICY), 'enabled': True, 'items': [allow, deny]}
    m.apply_nft(policy)
    assert connection(0, '198.51.100.2', 8080), 'Explicit exception failed'
    assert not connection(0, '198.51.100.2', 8081), 'Wrong port bypassed block'
    assert not connection(0, '198.51.100.3', 8080), 'Wrong host bypassed block'
    assert connection(1, '192.0.2.2', 8080), 'Independent reverse connection unexpectedly blocked'
    policy['items'].append(m.validate_rule({'source': '198.51.100.0/24', 'destination': '192.0.2.0/24', 'protocol': 'any', 'action': 'reject', 'enabled': True}))
    m.apply_nft(policy)
    assert not connection(1, '192.0.2.2', 8080), 'Reverse direction block failed'
    assert connection(0, '198.51.100.2', 8080), 'Reply traffic must retain original exception'
    policy['items'] = [deny, allow]
    m.apply_nft(policy)
    assert not connection(0, '198.51.100.2', 8080), 'Rule ordering failed'
    policy['enabled'] = False
    m.apply_nft(policy)
    assert connection(0, '198.51.100.2', 8081), 'Disabling firewall failed'
    print('PASS: real TCP packets, exception host/port, ordering, both directions, reply and disable')
    run('ip', 'link', 'add', 'testwan', 'type', 'dummy')
    run('iptables', '-N', 'DOCKER-USER')
    run('iptables', '-A', 'FORWARD', '-j', 'DOCKER-USER')
    run('iptables', '-P', 'FORWARD', 'DROP')
    core.load_state = lambda: {'wan': 'testwan', 'lans': {'test0': {'internet': False}, 'test1': {'internet': False}}}
    assert core.rebuild_forward()['success']
    assert connection(0, '198.51.100.2', 8081), 'Docker DROP blocked managed LAN traversal'
    policy['enabled'] = True
    m.apply_nft(policy)
    assert not connection(0, '198.51.100.2', 8081), 'Docker passthrough bypassed nft block'
    policy['enabled'] = False
    m.apply_nft(policy)
    print('PASS: managed LAN forwarding with Docker DROP still respects nft blocks')


    route = {'destination': '203.0.113.0/24', 'gateway': '198.51.100.2', 'interface': 'test1', 'metric': 100, 'enabled': True}
    m.route_save(route)
    saved = m.load('routes', [])[0]
    assert '203.0.113.0/24' in run('ip', '-4', 'route', 'show', 'proto', '243')
    m.route_save({**saved, 'metric': 101})
    m.restore_routes()
    assert 'metric 101' in run('ip', '-4', 'route', 'show', 'proto', '243')
    m.route_delete(saved['id'])
    assert not run('ip', '-4', 'route', 'show', 'proto', '243').strip()
    print('PASS: native route add/edit/restore/delete')

    # A veth stands in for the physical NIC; only the hardware validation is mocked.
    original_exists = Path.exists
    with patch.object(Path, 'exists', lambda p: True if str(p) == '/sys/class/net/test0/device' else original_exists(p)):
        m.vlan_create({'parent': 'test0', 'tag': 20, 'name': 'Synthetic'})
    vlan = m.load('vlans', [])[0]
    m.verify_vlan(vlan)
    m.restore_vlans()
    m.vlan_delete(vlan['id'])
    assert not core.interface_exists('test0.20')
    print('PASS: native VLAN create/verify/restore/delete')

    # Deterministic DNS upstream, completely local to this namespace.
    run('ip', 'addr', 'add', '1.1.1.1/32', 'dev', 'lo')
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(('1.1.1.1', 53))
    def upstream():
        while True:
            try:
                data, source = dns.recvfrom(4096)
                end = 12
                while data[end]:
                    end += data[end] + 1
                end += 5  # zero label plus QTYPE/QCLASS
                reply = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00' + data[12:end] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton('203.0.113.10')
                dns.sendto(reply, source)
            except OSError:
                break
    threading.Thread(target=upstream, daemon=True).start()
    core.load_state = lambda: {'wan': 'test1', 'lans': {'test0': {'address': '192.0.2.1/24'}}}
    policy = {**copy.deepcopy(DEFAULT_POLICY), 'enabled': True, 'dns_enabled': True, 'interfaces': ['test0'],
              'domains': ['blocked.example.com'], 'allow_domains': ['ok.blocked.example.com'], 'exempt_ips': ['192.0.2.3']}
    m.configure_dns(policy)
    m.apply_nft(policy)
    def query(name, source='192.0.2.2', kind=1):
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b''.join(bytes([len(s)]) + s.encode() for s in name.split('.')) + b'\x00' + struct.pack('!HH', kind, 1)
        code = ('import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((' + repr(source) +
                ',0));s.settimeout(2);s.sendto(' + repr(query) + ',("1.1.1.1",53));r=s.recv(4096);'
                'print(r.hex())')
        response = bytes.fromhex(ns(0, sys.executable, '-c', code).strip())
        answer = '-'
        offset = 12
        def skip_name(position):
            while response[position]:
                if response[position] & 0xc0 == 0xc0:
                    return position + 2
                position += response[position] + 1
            return position + 1
        for _ in range(struct.unpack('!H', response[4:6])[0]):
            offset = skip_name(offset) + 4
        for _ in range(struct.unpack('!H', response[6:8])[0]):
            offset = skip_name(offset)
            record_type, _, _, length = struct.unpack('!HHIH', response[offset:offset + 10])
            offset += 10
            if record_type == 1 and length == 4:
                answer = socket.inet_ntoa(response[offset:offset + 4])
                break
            offset += length
        return response[3] & 15, answer
    assert query('blocked.example.com') == (0, '198.18.0.1')
    assert query('sub.blocked.example.com') == (0, '198.18.0.1')
    assert query('blocked.example.com', kind=65)[0] == 0, 'HTTPS/SVCB record bypassed DNS block'
    allowed = query('ok.blocked.example.com')
    assert allowed == (0, '203.0.113.10'), allowed
    exempt = query('blocked.example.com', source='192.0.2.3')
    assert exempt == (0, '203.0.113.10'), exempt
    policy['block_page_enabled'] = False
    m.configure_dns(policy)
    assert query('blocked.example.com')[0] == 3, 'Página desativada deveria manter resposta NXDOMAIN'
    m.configure_dns(DEFAULT_POLICY)
    dns.close()
    print('PASS: DNS interception, block-page A/HTTPS, NXDOMAIN fallback, domain and source-IP exceptions')
finally:
    try:
        m.configure_dns(DEFAULT_POLICY)
    except Exception:
        pass
    for child in children:
        child.terminate()
        child.wait(timeout=5)
    for name in names:
        subprocess.run(['ip', 'netns', 'del', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tmp.cleanup()
