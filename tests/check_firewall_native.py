"""Check nft/iptables commands in an explicitly isolated network namespace.

Run: sudo unshare --net core/venv/bin/python tests/check_firewall_native.py
Never run this checker in the host's network namespace.
"""
import importlib.util
import os
import sys
import subprocess
import copy
from pathlib import Path
from unittest.mock import patch

if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('Use unshare --net: este teste não pode alterar a rede principal.')

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'core'))
spec = importlib.util.spec_from_file_location('firewall_check', root / 'core/core.py')
core = importlib.util.module_from_spec(spec)
with patch('os.makedirs'):
    spec.loader.exec_module(core)

subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
subprocess.run(['iptables', '-N', 'DOCKER-USER'], check=True)
state = {'wan': 'testwan', 'lans': {'testlan': {'address': '192.0.2.1/24'}}}
rules = [{'id': proto, 'enabled': True, 'protocol': proto, 'external_port': 8080,
          'internal_ip': '192.0.2.3', 'internal_port': 80} for proto in ['tcp', 'udp']]
with patch.object(core, 'load_state', return_value=state), \
     patch.object(core, 'nr_load', return_value=rules), \
     patch.object(core, 'interface_exists', return_value=True), \
     patch.object(core, 'prefer_connected_routes', return_value={'success': True}):
    for _ in range(2):
        result = core.nr_rebuild_port_forwards()
        assert result['success'], result
    installed = subprocess.check_output(['iptables', '-S', 'DOCKER-USER'], text=True)
    assert installed.count('--ctdir REPLY') == 4, installed
    assert installed.count('-A DOCKER-USER') == 8, installed
    rules.clear()
    assert core.nr_rebuild_port_forwards()['success']
    installed = subprocess.check_output(['iptables', '-S', 'DOCKER-USER'], text=True)
    assert '-A DOCKER-USER' not in installed, installed
print('Firewall nativo: TCP/UDP, retorno, reaplicação e remoção OK em namespace isolado.')

from management import DEFAULT_POLICY
forward = {'id': 'pf1', 'enabled': True, 'protocol': 'tcp', 'external_port': 8080,
           'internal_ip': '192.0.2.3', 'internal_port': 80}
policy = {**copy.deepcopy(DEFAULT_POLICY), 'enabled': True, 'isolate_networks': True}
with patch.object(core, 'load_state', return_value={
        'wan': 'testwan', 'lans': {'testlan': {'address': '192.0.2.1/24'}}}), \
     patch.object(core, 'managed_wan_interfaces', return_value=['testwan']), \
     patch.object(core, 'interface_ipv4', return_value=['198.51.100.184/24']), \
     patch.object(core, 'interface_exists', return_value=True), \
     patch.object(core, 'nr_load', return_value=[forward]):
    core.management.apply_nft(policy)
installed = subprocess.check_output(
    ['nft', 'list', 'chain', 'inet', 'nanotechrouter_policy', 'forward'], text=True)
exception = 'ct status dnat meta l4proto tcp ct original proto-dst 8080 ct reply ip saddr 192.0.2.3 ct reply proto-src 80 counter packets 0 bytes 0 accept'
lan_block = 'iifname "testlan" oifname "testwan" ip saddr 192.0.2.0/24 ip daddr 198.51.100.0/24 counter packets 0 bytes 0 drop'
wan_block = 'iifname "testwan" oifname "testlan" ip saddr 198.51.100.0/24 ip daddr 192.0.2.0/24 counter packets 0 bytes 0 drop'
assert exception in installed, installed
assert lan_block in installed, installed
assert wan_block in installed, installed
assert installed.index(exception) < installed.index(lan_block), installed
print('Isolamento nativo: sintaxe nft, exceção DNAT e bloqueios nas duas direções OK.')
