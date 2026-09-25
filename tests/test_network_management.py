import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'web'))
os.environ.setdefault('ROUTER_SECRET_KEY', 'synthetic-key-for-isolated-tests-only')
import app as web
sys.path.insert(0, str(ROOT / 'core'))
spec = importlib.util.spec_from_file_location('router_core_tests', ROOT / 'core/core.py')
core = importlib.util.module_from_spec(spec)
with patch('os.makedirs'):
    spec.loader.exec_module(core)

OK = {'success': True, 'stdout': '', 'stderr': '', 'returncode': 0}
LAN = {'address': '192.0.2.1/24', 'dhcp': True, 'dhcp_start': '192.0.2.100',
       'dhcp_end': '192.0.2.199', 'dns': '1.1.1.1', 'internet': True}
STATE = {'wan': 'eth0', 'lans': {'eth1': LAN}}
RULE = {'id': 'existing', 'name': 'Arduino', 'protocol': 'tcp', 'external_port': 8080,
        'internal_ip': '192.0.2.3', 'internal_port': 80, 'enabled': True}
RESERVATION = {'interface': 'eth1', 'mac': '02:00:00:00:00:03', 'ip': '192.0.2.3', 'hostname': 'arduino'}


class CoreManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        (base / 'config/dnsmasq').mkdir(parents=True)
        (base / 'data').mkdir()
        for key, value in {'DATA': str(base / 'data'), 'CONFIG': str(base / 'config'),
                           'STATE_FILE': str(base / 'data/router_state.json'),
                           'RESERVATIONS_FILE': str(base / 'data/reservations.json'),
                           'PORT_FORWARD_FILE': str(base / 'data/forwards.json')}.items():
            mock = patch.object(core, key, value)
            mock.start()
            self.addCleanup(mock.stop)
        core.save_state(STATE)
        self.conf = base / 'config/dnsmasq/eth1.conf'
        self.conf.write_text('interface=eth1\nlog-dhcp\ndhcp-range=192.0.2.100,192.0.2.199,255.255.255.0,12h\n')
        patch.dict(os.environ, {'ROUTER_API_TOKEN': 'synthetic-api-token'}).start()
        self.client = core.app.test_client()
        self.client.environ_base['HTTP_X_ROUTER_TOKEN'] = 'synthetic-api-token'

        self.command = patch.object(core, 'run', return_value=OK).start()
        self.addCleanup(patch.stopall)
        patch.object(core, 'stop_dhcp').start()
        patch.object(core.time, 'sleep').start()
        patch.object(core.os, 'makedirs').start()
        patch.object(core, 'get_dhcp_devices', return_value=[]).start()

    def test_reservation_create_edit_delete_updates_dnsmasq(self):
        response = self.client.post('/api/dhcp/reservation', json=RESERVATION)
        self.assertEqual(response.status_code, 200)
        item = self.client.get('/api/dhcp/reservations').json['reservations'][0]
        self.assertIn('dhcp-host=02:00:00:00:00:03,192.0.2.3,arduino', self.conf.read_text())
        self.assertIn('log-dhcp', self.conf.read_text())
        response = self.client.post('/api/dhcp/reservation', json={**item, 'ip': '192.0.2.4'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(',192.0.2.3,', self.conf.read_text())
        self.assertEqual(self.conf.read_text().count('dhcp-host='), 1)
        response = self.client.post('/api/dhcp/reservation/delete', json={'id': item['id']})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('dhcp-host=', self.conf.read_text())
        self.assertEqual(self.client.get('/api/dhcp/reservations').json['reservations'], [])
        self.assertFalse(any(call.args[0][0] in ['ip', 'nft', 'iptables', 'tc'] for call in self.command.call_args_list))

    def test_reservation_rejects_invalid_and_conflicting_entries(self):
        self.client.post('/api/dhcp/reservation', json=RESERVATION)
        for changes in [{'mac': 'invalid'}, {'mac': 'ff:ff:ff:ff:ff:ff'}, {'hostname': 'bad\ndhcp-option=3,1.1.1.1'},
                        {'ip': '198.51.100.3'}, {'ip': '192.0.2.1'}, {'ip': '192.0.2.0'}, {'ip': '192.0.2.255'},
                        {'interface': 'eth0'}, {'ip': '192.0.2.4'}, {'mac': '02:00:00:00:00:04'}, {'id': 'missing'}]:
            with self.subTest(changes=changes):
                self.assertEqual(self.client.post('/api/dhcp/reservation', json={**RESERVATION, **changes}).status_code, 400)
        self.assertEqual(len(self.client.get('/api/dhcp/reservations').json['reservations']), 1)

    def test_active_lease_owned_by_another_mac_is_rejected(self):
        with patch.object(core, 'get_dhcp_devices', return_value=[{**RESERVATION, 'mac': '02:00:00:00:00:04', 'expires': str(int(time.time()) + 3600)}]):
            self.assertEqual(self.client.post('/api/dhcp/reservation', json=RESERVATION).status_code, 400)

    def test_failed_dhcp_validation_preserves_config_and_data(self):
        before = self.conf.read_text()
        self.command.return_value = {**OK, 'success': False, 'stderr': 'syntax error'}
        self.assertEqual(self.client.post('/api/dhcp/reservation', json=RESERVATION).status_code, 500)
        self.assertEqual(self.conf.read_text(), before)
        self.assertEqual(core.nr_load(core.RESERVATIONS_FILE, []), [])
        core.stop_dhcp.assert_not_called()

    def test_failed_daemon_restart_restores_previous_configuration(self):
        before = self.conf.read_text()
        self.command.side_effect = [OK, OK, {**OK, 'success': False, 'stderr': 'start failed'}, OK]
        response = self.client.post('/api/dhcp/reservation', json=RESERVATION)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(self.conf.read_text(), before)
        self.assertEqual(core.nr_load(core.RESERVATIONS_FILE, []), [])

    def test_dhcp_start_includes_saved_reservations_and_network_mask(self):
        core.nr_save(core.RESERVATIONS_FILE, [{**RESERVATION, 'id': 'r1'}])
        core.save_state({'wan': 'eth0', 'lans': {'eth1': {**LAN, 'address': '192.0.2.1/25'}}})
        with patch.object(core, 'install_dhcp_config', return_value={'success': True}) as install:
            core.start_dhcp('eth1', '192.0.2.1', '192.0.2.20', '192.0.2.100', '1.1.1.1')
            config = install.call_args.args[1]
            self.assertIn('255.255.255.128', config)
            self.assertIn('dhcp-host=02:00:00:00:00:03,192.0.2.3,arduino', config)

    def test_edit_nat_preserves_id_and_does_not_duplicate(self):
        core.nr_save(core.PORT_FORWARD_FILE, [RULE])
        with patch.object(core, 'nr_rebuild_port_forwards', return_value=OK):
            response = self.client.post('/api/nat/forward', json={**RULE, 'external_port': 8081, 'enabled': False})
        self.assertEqual(response.status_code, 200)
        rules = core.nr_load(core.PORT_FORWARD_FILE, [])
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]['id'], RULE['id'])
        self.assertEqual(rules[0]['external_port'], 8081)
        self.assertFalse(rules[0]['enabled'])

    def test_nat_rejects_duplicate_unknown_edit_and_management_ports(self):
        core.nr_save(core.PORT_FORWARD_FILE, [RULE])
        for payload, expected in [({**RULE, 'id': ''}, 409), ({**RULE, 'id': 'missing'}, 404),
                                  ({**RULE, 'external_port': 5000}, 400), ({**RULE, 'external_port': 65536}, 400),
                                  ({**RULE, 'internal_ip': '198.51.100.2'}, 400), ({**RULE, 'internal_ip': LAN['address'].split('/')[0]}, 400)]:
            with self.subTest(payload=payload):
                self.assertEqual(self.client.post('/api/nat/forward', json=payload).status_code, expected)
        self.assertEqual(core.nr_load(core.PORT_FORWARD_FILE, []), [RULE])

    def test_failed_nat_apply_restores_stored_rule(self):
        core.nr_save(core.PORT_FORWARD_FILE, [RULE])
        with patch.object(core, 'nr_rebuild_port_forwards', side_effect=[{'success': False, 'stderr': 'nft failed'}, OK]):
            response = self.client.post('/api/nat/forward', json={**RULE, 'external_port': 8081})
        self.assertEqual(response.status_code, 500)
        self.assertIn('nft failed', response.json['message'])
        self.assertEqual(core.nr_load(core.PORT_FORWARD_FILE, []), [RULE])

    def test_connected_routes_precede_vpn_without_touching_vpn_rules(self):
        routes = [{'dst': '198.51.100.0/24', 'dev': 'eth0'}, {'dst': '192.0.2.0/24', 'dev': 'eth1'}, {'dst': '100.64.0.0/10', 'dev': 'tailscale0'}]
        rules = [{'priority': 2500, 'protocol': '242', 'dst': '203.0.113.0', 'dstlen': 24, 'table': 'main'},
                 {'priority': 5270, 'protocol': 'unspec', 'table': '52'}]
        self.command.side_effect = [{**OK, 'stdout': json.dumps(routes)}, {**OK, 'stdout': json.dumps(rules)}, OK, OK, OK]
        result = core.prefer_connected_routes()
        self.assertTrue(result['success'])
        changes = [call.args[0] for call in self.command.call_args_list[2:]]
        self.assertEqual(len(changes), 3)
        self.assertTrue(all('2500' in command and '242' in command for command in changes))
        self.assertFalse(any('52' in command or 'tailscale0' in command for command in changes))

    def test_connected_routes_are_idempotent(self):
        self.command.side_effect = [{**OK, 'stdout': json.dumps([{'dst': '192.0.2.0/24', 'dev': 'eth1'}])},
                                    {**OK, 'stdout': json.dumps([{'priority': 2500, 'protocol': '242', 'dst': '192.0.2.0', 'dstlen': 24, 'table': 'main'}])}]
        self.assertTrue(core.prefer_connected_routes()['success'])
        self.assertEqual(self.command.call_count, 2)

    def test_nat_installs_established_return_rule(self):
        core.nr_save(core.PORT_FORWARD_FILE, [RULE])
        with patch.object(core, 'prefer_connected_routes', return_value=OK), patch.object(core, 'interface_exists', return_value=True):
            self.assertTrue(core.nr_rebuild_port_forwards()['success'])
        commands = [call.args[0] for call in self.command.call_args_list]
        self.assertTrue(any('--ctdir' in c and 'REPLY' in c and '--ctorigdstport' in c
                            and '8080' in c and '--sport' in c and '80' in c for c in commands))

    def test_hairpin_is_local_destination_only_and_snat_requires_dnat(self):
        core.nr_save(core.PORT_FORWARD_FILE, [RULE])
        with patch.object(core, 'prefer_connected_routes', return_value=OK), patch.object(core, 'interface_exists', return_value=True):
            self.assertTrue(core.nr_rebuild_port_forwards()['success'])
        commands = [call.args[0] for call in self.command.call_args_list]
        hairpin = next(c for c in commands if 'fib' in c)
        self.assertIn('local', hairpin)
        self.assertIn('eth1', hairpin)
        self.assertIn('192.0.2.0/24', hairpin)
        snat = next(c for c in commands if 'masquerade' in c)
        self.assertIn('dnat', snat)
        self.assertIn('proto-dst', snat)
        self.assertIn('8080', snat)
        self.assertIn('192.0.2.3', snat)
        self.assertTrue(any('--ctstate' in c and 'DNAT' in c and 'ORIGINAL' in c for c in commands))


class WebManagementTests(unittest.TestCase):
    def setUp(self):
        self.auth_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.auth_tmp.cleanup)
        web.app.config['AUTH_DIRECTORY'] = self.auth_tmp.name
        from werkzeug.security import generate_password_hash
        admin = web.current_admin()
        import sqlite3
        with sqlite3.connect(str(Path(self.auth_tmp.name) / 'admin.sqlite3')) as db:
            db.execute('UPDATE admin SET initial=0')
        self.client = web.app.test_client()
        self.client.environ_base['HTTP_X_CSRF_TOKEN'] = 'synthetic-csrf'
        with self.client.session_transaction() as session:
            session['admin_version'] = admin['version']
            session['csrf'] = 'synthetic-csrf'

        self.data = {'/api/nat/status': {'nat': []}, '/api/nat/forwards': {'rules': [RULE]}, '/api/ports/aliases': {'aliases': {}},
                     '/api/interfaces': {'configuration': STATE}, '/api/dhcp/leases': {'leases': []},
                     '/api/dhcp/reservations': {'reservations': [{**RESERVATION, 'id': 'r1'}]}}

    def test_nat_page_with_rule_has_no_undefined_bandwidth_fields(self):
        with patch.object(web, 'get', side_effect=lambda path: self.data[path]):
            response = self.client.get('/nat?edit=existing')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'value="existing"', response.data)
        self.assertIn(b'value="8080"', response.data)
        self.assertIn(b'Editar', response.data)
        self.assertIn(b'Ativo', response.data)
        self.assertNotIn(b'Limite ativo', response.data)

    def test_nat_edit_submits_existing_id(self):
        with patch.object(web, 'post', return_value={'success': True}) as backend:
            response = self.client.post('/nat/forward', data={**RULE, 'enabled': 'on'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(backend.call_args.args[1]['id'], 'existing')
        self.assertTrue(backend.call_args.args[1]['enabled'])

    def test_reservation_form_loads_existing_and_submits_id(self):
        with patch.object(web, 'get', side_effect=lambda path: self.data[path]):
            response = self.client.get('/dhcp?edit=r1')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'value="r1"', response.data)
        self.assertIn(b'value="192.0.2.3"', response.data)
        with patch.object(web, 'post', return_value={'success': True}) as backend:
            response = self.client.post('/dhcp/reservation', data={**RESERVATION, 'id': 'r1'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(backend.call_args.args[1]['id'], 'r1')


if __name__ == '__main__':
    unittest.main()
