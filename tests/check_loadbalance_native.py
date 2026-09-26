"""Native multi-WAN test. Run only with: sudo unshare --net python ..."""
import importlib.util
import ast
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import patch

if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('REFUSED: execute este teste somente em sudo unshare --net.')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
spec = importlib.util.spec_from_file_location('core_native_loadbalance', ROOT / 'core/core.py')
core = importlib.util.module_from_spec(spec)
with patch('os.makedirs'):
    spec.loader.exec_module(core)

suffix = uuid.uuid4().hex[:6]
names = ['lb-client-' + suffix, 'lb-isp1-' + suffix, 'lb-isp2-' + suffix]
children = []
temporary = tempfile.TemporaryDirectory()
base = Path(temporary.name)
core.DATA = str(base / 'data')
core.CONFIG = str(base / 'config')
core.STATE_FILE = str(base / 'data/router_state.json')
core.PORT_FORWARD_FILE = str(base / 'data/forwards.json')
(base / 'data').mkdir()
(base / 'config').mkdir()
core.interface_exists = lambda name: subprocess.run(
    ['ip', 'link', 'show', 'dev', name], capture_output=True).returncode == 0
manager = core.loadbalancer


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def ns(name, *args):
    return run('ip', 'netns', 'exec', name, *args)


def fetches(count=30):
    code = ("import urllib.request,collections; c=collections.Counter(); "
            f"[(lambda b:c.update([b]))(urllib.request.urlopen('http://203.0.113.10:8000/',timeout=2).read().decode().strip()) for _ in range({count})]; "
            "print(dict(c))")
    output = ns(names[0], sys.executable, '-c', code)
    # The output is a Python dict containing only fixed synthetic labels.
    return ast.literal_eval(output.strip())


try:
    run('ip', 'link', 'set', 'lo', 'up')
    run('sysctl', '-w', 'net.ipv4.ip_forward=1')
    run('sysctl', '-w', 'net.ipv4.conf.all.rp_filter=2')
    for name in names:
        run('ip', 'netns', 'add', name)
        ns(name, 'ip', 'link', 'set', 'lo', 'up')

    links = [
        ('lan0', 'client0', names[0], '10.10.0.1/24', '10.10.0.2/24'),
        ('wan1', 'isp1', names[1], '192.0.2.2/24', '192.0.2.1/24'),
        ('wan2', 'isp2', names[2], '198.51.100.2/24', '198.51.100.1/24')]
    for root_if, peer, namespace, root_ip, peer_ip in links:
        run('ip', 'link', 'add', root_if, 'type', 'veth', 'peer', 'name', peer)
        run('ip', 'link', 'set', peer, 'netns', namespace)
        run('ip', 'addr', 'add', root_ip, 'dev', root_if)
        run('ip', 'link', 'set', root_if, 'up')
        ns(namespace, 'ip', 'addr', 'add', peer_ip, 'dev', peer)
        ns(namespace, 'ip', 'link', 'set', peer, 'up')
    ns(names[0], 'ip', 'route', 'add', 'default', 'via', '10.10.0.1')
    run('ip', 'route', 'add', 'default', 'via', '192.0.2.1', 'dev', 'wan1')

    for index in (1, 2):
        ns(names[index], 'ip', 'addr', 'add', '203.0.113.10/32', 'dev', 'lo')
        directory = base / ('provider' + str(index))
        directory.mkdir()
        (directory / 'index.html').write_text('wan' + str(index))
        children.append(subprocess.Popen([
            'ip', 'netns', 'exec', names[index], sys.executable, '-m', 'http.server', '8000',
            '--bind', '203.0.113.10', '--directory', str(directory)
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(.4)

    state = {'wan': 'wan1', 'lans': {'lan0': {'address': '10.10.0.1/24', 'internet': True}}}
    core.save_state(state)
    run('iptables', '-N', 'DOCKER-USER')
    run('iptables', '-A', 'FORWARD', '-j', 'DOCKER-USER')
    run('iptables', '-P', 'FORWARD', 'DROP')
    members = [
        {'id': 'one', 'name': 'WAN 1', 'interface': 'wan1', 'gateway': '192.0.2.1',
         'weight': 2, 'priority': 10, 'enabled': True, 'slot': 1},
        {'id': 'two', 'name': 'WAN 2', 'interface': 'wan2', 'gateway': '198.51.100.1',
         'weight': 1, 'priority': 20, 'enabled': True, 'slot': 2}]
    config = {'enabled': True, 'mode': 'balance', 'health_target': '203.0.113.10', 'members': members}
    manager.save_json(manager.config_path, config)
    statuses, _ = manager.check(config)
    if not all(value['up'] for value in statuses.values()):
        diagnostics = {
            'rules': run('ip', '-4', 'rule', 'show'),
            'table1': run('ip', '-4', 'route', 'show', 'table', '42001'),
            'table2': run('ip', '-4', 'route', 'show', 'table', '42002'),
            'links': run('ip', '-br', 'address')}
        for mark in (str(0x1101), str(0x1102)):
            probe = subprocess.run(['ping', '-m', mark, '-c', '1', '-W', '1', '203.0.113.10'],
                                   capture_output=True, text=True)
            diagnostics[mark] = probe.stdout + probe.stderr
        raise AssertionError(str(statuses) + '\n' + json.dumps(diagnostics, indent=2))
    manager.apply(config, statuses, config)
    assert core.rebuild_network_rules()['success']
    distribution = fetches(36)
    assert distribution.get('wan1', 0) > 0 and distribution.get('wan2', 0) > 0, distribution
    print('PASS: conexões novas distribuídas nos dois links:', distribution)

    ns(names[2], 'ip', 'link', 'set', 'isp2', 'down')
    statuses, _ = manager.check(config)
    assert statuses['one']['up'] and not statuses['two']['up'], statuses
    manager.apply(config, statuses, config)
    assert fetches(12) == {'wan1': 12}
    print('PASS: falha da WAN 2 remove o link sem interromper a WAN 1')

    ns(names[2], 'ip', 'link', 'set', 'isp2', 'up')
    time.sleep(.2)
    failover = {**config, 'mode': 'failover'}
    statuses, _ = manager.check(failover)
    manager.apply(failover, statuses, config)
    assert fetches(12) == {'wan1': 12}
    print('PASS: modo failover respeita a menor prioridade saudável')

    # Validate inbound port forwarding through the secondary link. The remote
    # source is outside wan2's connected subnet, so only the conntrack WAN mark
    # can return the reply through the correct provider.
    server_dir = base / 'internal'
    server_dir.mkdir()
    (server_dir / 'index.html').write_text('internal-ok')
    children.append(subprocess.Popen([
        'ip', 'netns', 'exec', names[0], sys.executable, '-m', 'http.server', '8080',
        '--bind', '10.10.0.2', '--directory', str(server_dir)
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    ns(names[2], 'ip', 'addr', 'add', '203.0.113.20/32', 'dev', 'lo')
    core.nr_save(core.PORT_FORWARD_FILE, [{
        'id': 'native-pf', 'name': 'native', 'protocol': 'tcp', 'external_port': 8080,
        'internal_ip': '10.10.0.2', 'internal_port': 8080, 'enabled': True}])
    assert core.nr_rebuild_port_forwards()['success']
    time.sleep(.2)
    body = ns(names[2], 'curl', '--fail', '--silent', '--interface', '203.0.113.20',
              '--max-time', '3', 'http://198.51.100.2:8080/')
    assert body.strip() == 'internal-ok', body
    print('PASS: Port Forward na WAN secundária mantém retorno simétrico')
finally:
    for child in children:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
    for name in names:
        subprocess.run(['ip', 'netns', 'del', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    temporary.cleanup()
