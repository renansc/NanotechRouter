"""TCP/UDP hairpin integration. Run only with sudo unshare --net."""
import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import patch

if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('REFUSED: use an isolated network namespace.')
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
spec = importlib.util.spec_from_file_location('core_hairpin_test', ROOT / 'core/core.py')
core = importlib.util.module_from_spec(spec)
with patch('os.makedirs'):
    spec.loader.exec_module(core)
names = ['nrhp-' + uuid.uuid4().hex[:8] for _ in range(3)]
children = []

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout

def ns(index, *args):
    return run('ip', 'netns', 'exec', names[index], *args)

def http(index, address, port):
    code = 'import urllib.request; print(urllib.request.urlopen("http://' + address + ':' + str(port) + '",timeout=2).status)'
    return ns(index, sys.executable, '-c', code).strip()

try:
    for name in names:
        run('ip', 'netns', 'add', name)
    for index in range(3):
        ns(index, 'ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'set', 'lo', 'up')
    run('sysctl', '-w', 'net.ipv4.ip_forward=1')
    # Server namespace also holds the LAN switch. Client/server share a true subnet.
    run('ip', 'link', 'add', 'lan', 'type', 'veth', 'peer', 'name', 'lanpeer')
    run('ip', 'link', 'set', 'lanpeer', 'netns', names[1])
    run('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'lan')
    run('ip', 'link', 'set', 'lan', 'up')
    ns(1, 'ip', 'link', 'add', 'switch', 'type', 'bridge')
    ns(1, 'ip', 'link', 'set', 'lanpeer', 'master', 'switch')
    ns(1, 'ip', 'link', 'set', 'lanpeer', 'up')
    ns(1, 'ip', 'link', 'set', 'switch', 'up')
    ns(1, 'ip', 'addr', 'add', '192.0.2.3/24', 'dev', 'switch')
    ns(1, 'ip', 'route', 'add', 'default', 'via', '192.0.2.1')
    ns(1, 'ip', 'link', 'add', 'clientport', 'type', 'veth', 'peer', 'name', 'client')
    ns(1, 'ip', 'link', 'set', 'client', 'netns', names[0])
    ns(1, 'ip', 'link', 'set', 'clientport', 'master', 'switch')
    ns(1, 'ip', 'link', 'set', 'clientport', 'up')
    ns(0, 'ip', 'link', 'set', 'client', 'up')
    ns(0, 'ip', 'addr', 'add', '192.0.2.2/24', 'dev', 'client')
    ns(0, 'ip', 'route', 'add', 'default', 'via', '192.0.2.1')
    run('ip', 'link', 'add', 'wan', 'type', 'veth', 'peer', 'name', 'external')
    run('ip', 'link', 'set', 'external', 'netns', names[2])
    run('ip', 'addr', 'add', '198.51.100.1/24', 'dev', 'wan')
    run('ip', 'link', 'set', 'wan', 'up')
    ns(2, 'ip', 'addr', 'add', '198.51.100.2/24', 'dev', 'external')
    ns(2, 'ip', 'link', 'set', 'external', 'up')
    for port in (80, 8080):
        children.append(subprocess.Popen(['ip', 'netns', 'exec', names[1], sys.executable, '-m', 'http.server', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    udp = 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("0.0.0.0",81));\nwhile True:\n d,a=s.recvfrom(2048);s.sendto(d,a)'
    children.append(subprocess.Popen(['ip', 'netns', 'exec', names[1], sys.executable, '-c', udp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    for _ in range(20):
        try:
            assert http(0, '192.0.2.3', 80) == '200'
            break
        except subprocess.CalledProcessError:
            time.sleep(.25)
    else:
        raise AssertionError('Baseline server unavailable')
    run('iptables', '-N', 'DOCKER-USER')
    run('iptables', '-A', 'FORWARD', '-j', 'DOCKER-USER')
    run('iptables', '-P', 'FORWARD', 'DROP')
    core.interface_exists = lambda name: subprocess.run(['ip', 'link', 'show', 'dev', name], capture_output=True).returncode == 0
    core.load_state = lambda: {'wan': 'wan', 'lans': {'lan': {'address': '192.0.2.1/24'}}}
    core.prefer_connected_routes = lambda: {'success': True}
    rules = [{'id': proto, 'enabled': True, 'protocol': proto, 'external_port': 8080,
              'internal_ip': '192.0.2.3', 'internal_port': port} for proto, port in [('tcp', 80), ('udp', 81)]]
    core.nr_load = lambda *args: rules
    for _ in range(2):
        assert core.nr_rebuild_port_forwards()['success']
        for index, address in [(0, '192.0.2.1'), (0, '198.51.100.1'), (2, '198.51.100.1')]:
            assert http(index, address, 8080) == '200'
            code = 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b"hairpin",(' + repr(address) + ',8080));d,a=s.recvfrom(100);assert d==b"hairpin" and a==(' + repr(address) + ',8080)'
            ns(index, sys.executable, '-c', code)
    # A second mapping and a later edit use the same generic hairpin behavior.
    extra = {'id': 'second', 'enabled': True, 'protocol': 'tcp', 'external_port': 9090,
             'internal_ip': '192.0.2.3', 'internal_port': 8080}
    rules.append(extra)
    assert core.nr_rebuild_port_forwards()['success']
    assert http(0, '192.0.2.1', 9090) == '200'
    extra['external_port'] = 9091
    assert core.nr_rebuild_port_forwards()['success']
    assert http(0, '198.51.100.1', 9091) == '200'
    extra['enabled'] = False
    assert core.nr_rebuild_port_forwards()['success']
    try:
        http(0, '192.0.2.1', 9091)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError('Disabled mapping still opens new hairpin connections')
    # A direct LAN destination on the same port must not be rewritten to port 80.
    assert http(0, '192.0.2.3', 8080) == '200'
    text = run('nft', 'list', 'table', 'ip', 'nanotechrouter_pf')
    assert 'fib daddr type local' in text and 'masquerade' in text
    # Firewall remains authoritative, including when both endpoints share a LAN.
    run('nft', 'add', 'table', 'inet', 'test_policy')
    run('nft', 'add', 'chain', 'inet', 'test_policy', 'forward', '{ type filter hook forward priority -20; policy accept; }')
    run('nft', 'add', 'rule', 'inet', 'test_policy', 'forward', 'ip', 'saddr', '192.0.2.2', 'ip', 'daddr', '192.0.2.3', 'drop')
    try:
        http(0, '192.0.2.1', 8080)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError('Hairpin bypassed firewall')
    run('nft', 'delete', 'table', 'inet', 'test_policy')
    rules.clear()
    assert core.nr_rebuild_port_forwards()['success']
    assert '-A DOCKER-USER' not in run('iptables', '-S', 'DOCKER-USER')
    print('PASS: TCP/UDP via LAN gateway, WAN address from LAN, external WAN, reapply, direct access, firewall isolation and removal.')
finally:
    for child in children:
        child.terminate()
        child.wait(timeout=5)
    for name in names:
        subprocess.run(['ip', 'netns', 'del', name], capture_output=True)
