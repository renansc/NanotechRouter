import copy
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_network_management import core, web, STATE, OK
from management import Management, DEFAULT_POLICY, domain

ROOT = Path(__file__).resolve().parents[1]


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        web.app.config['AUTH_DIRECTORY'] = self.tmp.name
        self.client = web.app.test_client()

    def token(self):
        response = self.client.get('/login')
        return re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()

    def login(self):
        return self.client.post('/login', data={'csrf_token': self.token(), 'username': 'admin', 'password': 'admin'})

    def test_all_admin_pages_require_login(self):
        for route in ['/', '/interfaces', '/vlans', '/routes', '/firewall', '/system',
                      '/nat', '/dhcp', '/loadbalance', '/firewall/block-ca']:
            with self.subTest(route=route), patch.object(web, 'get') as backend:
                result = self.client.get(route)
                self.assertEqual(result.status_code, 302)
                self.assertTrue(result.location.endswith('/login'))
                backend.assert_not_called()

    def test_login_uses_router_specific_compatible_cookie(self):
        response = self.client.get('/login')
        cookie = '\n'.join(response.headers.getlist('Set-Cookie'))
        self.assertIn('nanotechrouter_login_csrf=', cookie)
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Lax', cookie)
        response = self.client.post('/login', data={
            'csrf_token': self.token(), 'username': 'admin', 'password': 'admin'})
        cookie = '\n'.join(response.headers.getlist('Set-Cookie'))
        self.assertIn('nanotechrouter_session=', cookie)

    def test_default_login_requires_password_change_and_invalidates_other_sessions(self):
        self.assertTrue(self.login().location.endswith('/system'))
        self.assertTrue(self.client.get('/firewall').location.endswith('/system'))
        other = web.app.test_client()
        with self.client.session_transaction() as s:
            previous = dict(s)
        with other.session_transaction() as s:
            s.update(previous)
        response = self.client.post('/system/password', data={'csrf_token': previous['csrf'], 'current_password': 'admin',
                                  'new_password': 'Synthetic-pass-123', 'confirm_password': 'Synthetic-pass-123'})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(web.current_admin()['initial'])
        with patch.object(web, 'get', return_value={'success': True, 'items': []}):
            self.assertEqual(self.client.get('/firewall').status_code, 200)
        self.assertTrue(other.get('/firewall').location.endswith('/login'))
        self.assertNotIn('Synthetic-pass-123', web.current_admin()['password'])

    def test_csrf_required_for_login_and_all_mutations(self):
        with patch.object(web, 'post') as backend:
            login = self.client.post('/login', data={})
            self.assertEqual(login.status_code, 303)
            self.assertTrue(login.location.endswith('/login?renewed=1'))
            for path in ['/wan/set', '/manage/firewall/settings', '/system/reboot', '/logout']:
                self.assertEqual(self.client.post(path, data={}).status_code, 400)
            backend.assert_not_called()

    def test_stale_login_form_renews_csrf_without_authenticating(self):
        response = self.client.post('/login', data={
            'csrf_token': 'stale-token', 'username': 'admin', 'password': 'admin'})
        self.assertEqual(response.status_code, 303)
        page = self.client.get(response.location)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'sess\xc3\xa3o do formul\xc3\xa1rio foi renovada', page.data)
        renewed = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        with self.client.session_transaction() as session:
            self.assertNotIn('admin_version', session)
        response = self.client.post('/login', data={
            'csrf_token': renewed, 'username': 'admin', 'password': 'admin'})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/system'))

    def test_login_csrf_remains_stable_across_tabs_and_stale_posts(self):
        current = self.token()
        self.assertEqual(self.token(), current)
        stale = self.client.post('/login', data={
            'csrf_token': '0' * 64, 'username': 'admin', 'password': 'admin'})
        self.assertEqual(stale.status_code, 303)
        page = self.client.get(stale.location)
        self.assertIn(current.encode(), page.data)

    def test_login_throttles_across_clients(self):
        token = self.token()
        for _ in range(5):
            self.assertEqual(self.client.post('/login', data={'csrf_token': token, 'username': 'admin', 'password': 'wrong'}).status_code, 401)
        self.assertEqual(self.login().status_code, 429)

    def test_reboot_requires_changed_password_and_explicit_confirmation(self):
        self.login()
        with self.client.session_transaction() as session:
            csrf = session['csrf']
        with patch.object(web, 'post') as backend:
            self.client.post('/system/reboot', data={'csrf_token': csrf, 'password': 'admin', 'confirmation': 'REINICIAR'})
            backend.assert_not_called()

    def test_core_rejects_missing_or_wrong_token(self):
        with patch.dict(os.environ, {'ROUTER_API_TOKEN': 'synthetic-token'}):
            client = core.app.test_client()
            for path in ['/api/firewall', '/api/config', '/api/interfaces']:
                self.assertEqual(client.get(path).status_code, 401)
                self.assertEqual(client.get(path, headers={'X-Router-Token': 'wrong'}).status_code, 401)
            self.assertEqual(client.get('/health').status_code, 200)

    def test_vlan_restore_requires_internal_token_before_network_changes(self):
        with patch.dict(os.environ, {'ROUTER_API_TOKEN': 'synthetic-token'}), \
                patch.object(core.management, 'restore_vlans') as restore:
            client = core.app.test_client()
            for headers in ({}, {'X-Router-Token': 'wrong'}):
                self.assertEqual(client.post('/api/system/restore-links', headers=headers).status_code, 401)
            restore.assert_not_called()
            self.assertEqual(client.post('/api/system/restore-links',
                             headers={'X-Router-Token': 'synthetic-token'}).status_code, 200)
            restore.assert_called_once()


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run = patch.object(core, 'run', return_value=OK).start()
        patch.object(core, 'DATA', self.tmp.name).start()
        patch.object(core, 'CONFIG', self.tmp.name).start()
        patch.object(core, 'load_state', return_value=copy.deepcopy(STATE)).start()
        patch.dict(os.environ, {'ROUTER_API_TOKEN': 'synthetic-token'}).start()
        self.addCleanup(patch.stopall)
        self.m = core.management
        self.client = core.app.test_client()
        self.client.environ_base['HTTP_X_ROUTER_TOKEN'] = 'synthetic-token'

    def rule(self, **changes):
        return {'name': 'Block network', 'source': '192.0.2.0/24', 'destination': '198.51.100.0/24',
                'protocol': 'any', 'action': 'drop', 'enabled': True, **changes}

    def test_restore_vlan_activates_parent_before_child_on_cold_and_warm_boot(self):
        row = {'id': 'v1', 'interface': 'eth1.20', 'parent': 'eth1', 'tag': 20}
        self.m.save('vlans', [row])
        for exists in (False, True):
            with self.subTest(existing_vlan=exists):
                parent_up = False

                def command(args):
                    nonlocal parent_up
                    if args == ['ip', '-j', '-d', 'link', 'show', 'dev', 'eth1.20']:
                        return {**OK, 'stdout': json.dumps([{'link': 'eth1', 'linkinfo': {
                            'info_kind': 'vlan', 'info_data': {'id': 20}}}])}
                    if args == ['ip', 'link', 'set', 'dev', 'eth1', 'up']:
                        parent_up = True
                    if args == ['ip', 'link', 'set', 'dev', 'eth1.20', 'up'] and not parent_up:
                        return {**OK, 'success': False, 'stderr': 'RTNETLINK answers: Network is down'}
                    return OK

                self.run.side_effect = command
                with patch.object(core, 'interface_exists', return_value=exists):
                    response = self.client.post('/api/system/restore-links')
                self.assertEqual(response.status_code, 200, response.json)
                self.assertTrue(parent_up)
                self.assertEqual(self.m.load('vlans', []), [row])

    def test_restore_rejects_foreign_vlan_before_activating_parent(self):
        self.m.save('vlans', [{'id': 'v1', 'interface': 'eth1.20', 'parent': 'eth1', 'tag': 20}])
        self.run.return_value = {**OK, 'stdout': json.dumps([{'link': 'eth0', 'linkinfo': {
            'info_kind': 'vlan', 'info_data': {'id': 20}}}])}
        with patch.object(core, 'interface_exists', return_value=True):
            self.assertEqual(self.client.post('/api/system/restore-links').status_code, 500)
        self.assertFalse(any(call.args[0][:3] == ['ip', 'link', 'set'] for call in self.run.call_args_list))

    def test_restore_reports_parent_activation_failure(self):
        self.m.save('vlans', [{'id': 'v1', 'interface': 'eth1.20', 'parent': 'eth1', 'tag': 20}])
        self.run.side_effect = lambda args: ({**OK, 'success': False, 'stderr': 'Parent failed'}
            if args == ['ip', 'link', 'set', 'dev', 'eth1', 'up'] else OK)
        with patch.object(core, 'interface_exists', return_value=False):
            response = self.client.post('/api/system/restore-links')
        self.assertEqual(response.status_code, 500)
        self.assertIn('Parent failed', response.json['message'])
        self.assertFalse(any(call.args[0] == ['ip', 'link', 'set', 'dev', 'eth1.20', 'up']
                             for call in self.run.call_args_list))

    def test_firewall_crud_order_and_disabled_default(self):
        self.assertFalse(self.m.policy()['enabled'])
        for data in [self.rule(), self.rule(name='Exception', destination='198.51.100.5', protocol='tcp', port='443', action='accept')]:
            self.assertEqual(self.client.post('/api/firewall/save', json=data).status_code, 200)
        rules = self.m.policy()['items']
        self.assertFalse(self.m.policy()['enabled'])
        exception = rules[1]
        self.client.post('/api/firewall/move', json={'id': exception['id'], 'direction': 'up'})
        self.assertEqual(self.m.policy()['items'][0]['id'], exception['id'])
        self.client.post('/api/firewall/save', json={**exception, 'port': '80-81'})
        self.assertEqual(self.m.policy()['items'][0]['port'], '80-81')
        self.client.post('/api/firewall/delete', json={'id': exception['id']})
        self.assertEqual(len(self.m.policy()['items']), 1)
        self.assertEqual(self.client.post('/api/firewall/delete', json={'id': 'unknown'}).status_code, 400)

    def test_bad_rules_and_injection_rejected_without_commands(self):
        for data in [self.rule(source='bad'), self.rule(port='443'), self.rule(protocol='tcp', port='65536'),
                     self.rule(protocol='tcp', port='90-80'), self.rule(action='drop; flush ruleset'),
                     self.rule(destination='::/0')]:
            self.run.reset_mock()
            self.assertEqual(self.client.post('/api/firewall/save', json=data).status_code, 400)
            self.run.assert_not_called()

    def test_nft_failure_keeps_saved_policy(self):
        self.m.save('firewall', copy.deepcopy(DEFAULT_POLICY))
        with patch.object(self.m, 'apply_nft', side_effect=[RuntimeError('invalid nft'), None]):
            result = self.client.post('/api/firewall/save', json=self.rule())
        self.assertEqual(result.status_code, 500)
        self.assertEqual(self.m.policy()['items'], [])

    def test_settings_scope_and_domains(self):
        for payload in [{'interfaces': ['eth0']}, {'dns_enabled': True, 'interfaces': []},
                        {'domains': 'https://example.com/private'}, {'domains': '0.0.0.0'}, {'categories': ['unknown']}]:
            self.assertEqual(self.client.post('/api/firewall/settings', json=payload).status_code, 400)
        self.assertEqual(domain('EXAMPLE.com.'), 'example.com')
        policy = self.m.settings({'interfaces': ['eth1'], 'dns_enabled': True, 'enabled': True,
                     'domains': 'example.com', 'allow_domains': 'ok.example.com', 'exempt_ips': '192.0.2.25'}, DEFAULT_POLICY)
        content = self.m.dns_content(policy)
        self.assertIn('local=/example.com/', content)
        self.assertIn('server=/ok.example.com/1.1.1.1', content)
        self.assertIn('listen-address=127.0.0.1,192.0.2.1', content)
        nft = self.m.nft_text(policy)
        self.assertLess(nft.index('ip saddr 192.0.2.25 return'), nft.index('redirect to :1053'))

    def test_category_requires_download_and_empty_download_preserves_cache(self):
        policy = {**copy.deepcopy(DEFAULT_POLICY), 'interfaces': ['eth1'], 'categories': ['adult']}
        with self.assertRaises(ValueError):
            self.m.dns_content(policy)
        self.m.save('category_adult', {'domains': ['blocked.example.com']})
        self.assertIn('local=/blocked.example.com/', self.m.dns_content(policy))
        with patch('urllib.request.urlopen') as download:
            download.return_value.__enter__.return_value.read.return_value = b'# empty\n'
            with self.assertRaises(ValueError):
                self.m.update_lists(['adult'])
        self.assertEqual(self.m.load('category_adult', {})['domains'], ['blocked.example.com'])

    def test_active_policy_matches_return_without_established_bypass(self):
        policy = {**copy.deepcopy(DEFAULT_POLICY), 'enabled': True, 'items': [self.m.validate_rule(self.rule())]}
        nft = self.m.nft_text(policy)
        self.assertIn('ct original ip saddr 192.0.2.0/24 ct reply ip saddr 198.51.100.0/24 counter drop', nft)
        self.assertNotIn('ct state established', nft)
        self.assertNotIn('flush ruleset', nft)

    def test_automatic_isolation_keeps_internet_and_allows_only_registered_nat(self):
        forward = {'id': 'pf1', 'enabled': True, 'protocol': 'tcp', 'external_port': 8080,
                   'internal_ip': '192.0.2.3', 'internal_port': 80}
        policy = {**copy.deepcopy(DEFAULT_POLICY), 'enabled': True, 'isolate_networks': True}
        with patch.object(core, 'managed_wan_interfaces', return_value=['eth0']), \
             patch.object(core, 'interface_ipv4', return_value=['198.51.100.184/24']), \
             patch.object(core, 'interface_exists', return_value=True), \
             patch.object(core, 'nr_load', return_value=[forward]):
            nft = self.m.nft_text(policy)
        exception = ('ct status dnat meta l4proto tcp ct original proto-dst 8080 '
                     'ct reply ip saddr 192.0.2.3 ct reply proto-src 80 counter accept')
        lan_block = ('iifname "eth1" oifname "eth0" ip saddr 192.0.2.0/24 '
                     'ip daddr 198.51.100.0/24 counter drop')
        wan_block = ('iifname "eth0" oifname "eth1" ip saddr 198.51.100.0/24 '
                     'ip daddr 192.0.2.0/24 counter drop')
        self.assertIn(exception, nft)
        self.assertIn(lan_block, nft)
        self.assertIn(wan_block, nft)
        self.assertLess(nft.index(exception), nft.index(lan_block))
        self.assertNotIn('ip daddr 0.0.0.0/0 counter drop', nft)

    def test_routes_reject_unknown_id_default_offlink_and_connected_network(self):
        data = {'destination': '203.0.113.0/24', 'gateway': '192.0.2.254', 'interface': 'eth1', 'metric': 100, 'enabled': True}
        with patch.object(core, 'interface_exists', return_value=True), patch.object(core, 'interface_ipv4', return_value=['192.0.2.1/24']):
            for changes in [{'id': 'missing'}, {'destination': '0.0.0.0/0'}, {'gateway': '198.51.100.1'}, {'metric': -1}]:
                self.assertEqual(self.client.post('/api/routes/save', json={**data, **changes}).status_code, 400)
            self.run.return_value = {**OK, 'stdout': '[{"dst":"192.0.2.0/24"}]'}
            self.assertEqual(self.client.post('/api/routes/save', json={**data, 'destination': '192.0.2.128/25'}).status_code, 400)

    def test_route_apply_failure_restores_old_without_replace(self):
        old = {'id': 'r1', 'name': 'old', 'destination': '203.0.113.0/24', 'gateway': '192.0.2.254', 'interface': 'eth1', 'metric': 100, 'enabled': True}
        self.m.save('routes', [old])
        with patch.object(core, 'interface_exists', return_value=True), patch.object(core, 'interface_ipv4', return_value=['192.0.2.1/24']):
            self.run.side_effect = [{**OK, 'stdout': '[]'}, OK, {**OK, 'success': False, 'stderr': 'conflict'}, OK]
            self.assertEqual(self.client.post('/api/routes/save', json={**old, 'metric': 200}).status_code, 500)
        self.assertEqual(self.m.load('routes', []), [old])
        self.assertTrue(all('replace' not in call.args[0] for call in self.run.call_args_list))

    def test_vlan_in_use_cannot_be_deleted(self):
        self.m.save('vlans', [{'id': 'v1', 'interface': 'eth1', 'tag': 10, 'parent': 'eth0'}])
        result = self.client.post('/api/vlans/delete', json={'id': 'v1'})
        self.assertEqual(result.status_code, 400)
        self.run.assert_not_called()

    def test_reboot_is_explicit_and_never_called_by_read(self):
        self.assertEqual(self.client.post('/api/system/reboot', json={}).status_code, 400)
        self.run.assert_not_called()
        self.assertEqual(self.client.post('/api/system/reboot', json={'confirmation': 'REINICIAR'}).status_code, 200)
        self.assertIn('/usr/bin/systemctl', self.run.call_args.args[0])

class AuthorizedViewsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        web.app.config['AUTH_DIRECTORY'] = self.tmp.name
        admin = web.current_admin()
        import sqlite3
        with sqlite3.connect(str(Path(self.tmp.name) / 'admin.sqlite3')) as db:
            db.execute('UPDATE admin SET initial=0')
        self.client = web.app.test_client()
        with self.client.session_transaction() as session:
            session['admin_version'] = admin['version']
            session['csrf'] = 'synthetic-csrf'
        self.client.environ_base['HTTP_X_CSRF_TOKEN'] = 'synthetic-csrf'

    def test_every_new_view_renders_for_authorized_admin(self):
        data = {'success': True, 'items': [], **copy.deepcopy(DEFAULT_POLICY), 'categories_info': {},
                'interfaces': [{'name': 'eth1', 'type': 'PHYSICAL', 'role': 'LAN', 'addresses': ['192.0.2.1/24']}],
                'hostname': 'synthetic-router', 'version': '0.6.0', 'uptime_seconds': 3600, 'forwarding': True,
                'members': [], 'statuses': {}, 'candidates': [], 'selected': []}
        with patch.object(web, 'get', return_value=data):
            for route in ['/vlans', '/routes', '/firewall', '/firewall?tab=profiles',
                          '/firewall?tab=blockpage', '/firewall?tab=lists', '/firewall?tab=status',
                          '/loadbalance', '/system', '/system?tab=status', '/system?tab=access']:
                with self.subTest(route=route):
                    result = self.client.get(route)
                    self.assertEqual(result.status_code, 200)
                    self.assertIn(b'csrf_token', result.data)

    def test_authorized_profile_submit_preserves_lists_and_booleans(self):
        from werkzeug.datastructures import MultiDict
        payload = MultiDict([('enabled', 'on'), ('isolate_networks', 'on'),
                             ('interfaces', 'eth1'), ('interfaces', 'eth1.20'),
                             ('categories', 'social'), ('categories', 'adult'), ('source', '192.0.2.3')])
        with patch.object(web, 'post', return_value={'success': True}) as backend:
            result = self.client.post('/manage/firewall/settings', data=payload)
        self.assertEqual(result.status_code, 302)
        args = backend.call_args.args[1]
        self.assertEqual(args['interfaces'], ['eth1', 'eth1.20'])
        self.assertEqual(args['categories'], ['social', 'adult'])
        self.assertTrue(args['enabled'])
        self.assertTrue(args['isolate_networks'])
        self.assertFalse(args['dns_enabled'])

    def test_shared_layout_exposes_accessible_mobile_navigation(self):
        with patch.object(web, 'get', return_value={'success': True, 'interfaces': [],
                                                    'configuration': {}, 'leases': []}):
            response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'class="menu-toggle"', response.data)
        self.assertIn(b'aria-controls="main-sidebar"', response.data)
        self.assertIn(b'aria-current="page"', response.data)
        self.assertIn(b'/static/app.css', response.data)
        self.assertIn(b'/static/app.js', response.data)

        css = (ROOT / 'web/static/app.css').read_text()
        script = (ROOT / 'web/static/app.js').read_text()
        self.assertIn('@media (max-width: 991.98px)', css)
        self.assertIn('@media (max-width: 767.98px)', css)
        self.assertIn("event.key === 'Escape'", script)
        self.assertIn("table.classList.add('table-mobile')", script)
