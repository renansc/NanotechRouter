import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_network_management import core, web, STATE
from management import DEFAULT_POLICY, BLOCK_PAGE_IP
from loadbalance import DEFAULT as LOADBALANCE_DEFAULT, MARK_BASE


class BlockPagePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch.object(core, 'DATA', self.tmp.name).start()
        patch.object(core, 'CONFIG', self.tmp.name).start()
        patch.object(core, 'load_state', return_value=copy.deepcopy(STATE)).start()
        patch.object(core, 'interface_exists', return_value=True).start()
        self.addCleanup(patch.stopall)
        self.manager = core.management

    def test_blocked_dns_answers_with_page_and_nft_scopes_http_https(self):
        policy = {**copy.deepcopy(DEFAULT_POLICY), 'enabled': True, 'dns_enabled': True,
                  'interfaces': ['eth1'], 'source': '192.0.2.0/24',
                  'domains': ['blocked.example'], 'block_page_enabled': True,
                  'block_page_https': True}
        dns = self.manager.dns_content(policy)
        self.assertIn('address=/blocked.example/' + BLOCK_PAGE_IP, dns)
        self.assertIn('local=/blocked.example/', dns)
        nft = self.manager.nft_text(policy)
        self.assertIn('iifname "eth1" ip saddr 192.0.2.0/24 ip daddr ' + BLOCK_PAGE_IP +
                      ' tcp dport 80 accept', nft)
        self.assertIn('tcp dport 443 accept', nft)
        self.assertIn('ip daddr ' + BLOCK_PAGE_IP + ' tcp dport { 80, 443 } drop', nft)

    def test_disabling_page_keeps_nxdomain_behavior(self):
        policy = {**copy.deepcopy(DEFAULT_POLICY), 'domains': ['blocked.example'],
                  'block_page_enabled': False}
        dns = self.manager.dns_content(policy)
        self.assertNotIn('address=/blocked.example/', dns)
        self.assertIn('local=/blocked.example/', dns)


class LoadBalanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch.object(core, 'DATA', self.tmp.name).start()
        patch.object(core, 'CONFIG', self.tmp.name).start()
        patch.object(core, 'load_state', return_value=copy.deepcopy(STATE)).start()
        patch.object(core, 'interface_exists', return_value=True).start()
        self.addCleanup(patch.stopall)
        self.manager = core.loadbalancer
        self.members = [
            {'id': 'one', 'name': 'WAN 1', 'interface': 'eth0', 'gateway': '198.51.100.1',
             'weight': 2, 'priority': 10, 'enabled': True, 'slot': 1},
            {'id': 'two', 'name': 'WAN 2', 'interface': 'eth2', 'gateway': '203.0.113.1',
             'weight': 1, 'priority': 20, 'enabled': True, 'slot': 2}
        ]

    def test_nft_balances_new_lan_connections_and_keeps_inbound_wan_symmetric(self):
        config = {**LOADBALANCE_DEFAULT, 'enabled': True, 'members': self.members}
        nft = self.manager.nft_text(config, self.members)
        self.assertIn('iifname "eth0" ct mark set ' + hex(MARK_BASE + 1), nft)
        self.assertIn('iifname "eth2" ct mark set ' + hex(MARK_BASE + 2), nft)
        self.assertIn('iifname { "eth1" } ct state established,related ct mark != 0 meta mark set ct mark', nft)
        self.assertIn('numgen random mod 3 map { 0-1 : ' + hex(MARK_BASE + 1) +
                      ', 2 : ' + hex(MARK_BASE + 2) + ' } meta mark set ct mark', nft)
        self.assertNotIn('\nmeta mark set ct mark\n', nft)

    def test_failover_selects_lowest_healthy_priority(self):
        config = {**LOADBALANCE_DEFAULT, 'enabled': True, 'mode': 'failover', 'members': self.members}
        statuses = {'one': {'up': True}, 'two': {'up': True}}
        self.assertEqual([item['id'] for item in self.manager.selected(config, statuses)], ['one'])
        statuses['one']['up'] = False
        self.assertEqual([item['id'] for item in self.manager.selected(config, statuses)], ['two'])

    def test_activation_requires_two_enabled_links(self):
        config = {**LOADBALANCE_DEFAULT, 'enabled': True, 'members': [self.members[0]]}
        with self.assertRaisesRegex(ValueError, 'pelo menos dois'):
            self.manager.validate_config(config)

    def test_failure_restores_previous_file_and_runtime(self):
        previous = {**LOADBALANCE_DEFAULT, 'members': []}
        config = {**LOADBALANCE_DEFAULT, 'members': self.members}
        with patch.object(self.manager, 'check', return_value=({}, False)), \
             patch.object(self.manager, 'apply', side_effect=[[], []]) as apply, \
             patch.object(self.manager, 'rebuild_network_rules',
                          side_effect=[{'success': False}, {'success': True}]), \
             patch.object(self.manager, 'nr_rebuild_port_forwards', return_value={'success': True}):
            with self.assertRaises(RuntimeError):
                self.manager.persist(config, previous)
        self.assertEqual(self.manager.config(), previous)
        self.assertEqual(apply.call_count, 2)


class WebViewsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        web.app.config['AUTH_DIRECTORY'] = self.tmp.name
        admin = web.current_admin()
        import sqlite3
        with sqlite3.connect(str(Path(self.tmp.name) / 'admin.sqlite3')) as database:
            database.execute('UPDATE admin SET initial=0')
        self.client = web.app.test_client()
        self.client.environ_base['HTTP_X_CSRF_TOKEN'] = 'synthetic-csrf'
        with self.client.session_transaction() as session:
            session['admin_version'] = admin['version']
            session['csrf'] = 'synthetic-csrf'

    def test_loadbalance_page_and_blockpage_tab_render(self):
        firewall = {'success': True, **copy.deepcopy(DEFAULT_POLICY), 'categories_info': {}, 'items': []}
        loadbalance = {'success': True, **LOADBALANCE_DEFAULT, 'statuses': {}, 'candidates': []}
        interfaces = {'success': True, 'interfaces': []}
        with patch.object(web, 'get', side_effect=lambda path: {
                '/api/firewall': firewall, '/api/interfaces': interfaces,
                '/api/loadbalance': loadbalance}[path]):
            self.assertIn(b'Preparar certificado', self.client.get('/firewall?tab=blockpage').data)
            self.assertIn(b'Balanceamento de Links', self.client.get('/loadbalance').data)

    def test_blockpage_submit_preserves_filter_and_returns_to_its_tab(self):
        data = {'_tab': 'blockpage', 'enabled': 'on', 'dns_enabled': 'on',
                'interfaces': 'eth1', 'domains': 'blocked.example',
                'block_page_enabled': 'on', 'block_page_https': 'on',
                'block_page_title': 'Negado', 'block_page_message': 'Política da empresa'}
        with patch.object(web, 'post', return_value={'success': True}) as backend:
            response = self.client.post('/manage/firewall/settings', data=data)
        self.assertTrue(response.location.endswith('/firewall?tab=blockpage'))
        sent = backend.call_args.args[1]
        self.assertEqual(sent['interfaces'], ['eth1'])
        self.assertEqual(sent['domains'], 'blocked.example')
        self.assertTrue(sent['block_page_https'])
        self.assertNotIn('_tab', sent)

    def test_new_mutations_require_csrf(self):
        for path in ['/loadbalance/settings', '/loadbalance/member',
                     '/loadbalance/member/delete', '/loadbalance/check',
                     '/firewall/block-ca/prepare']:
            with self.subTest(path=path), patch.object(web, 'post') as backend:
                self.assertEqual(web.app.test_client().post(path, data={}).status_code, 400)
                backend.assert_not_called()


if __name__ == '__main__':
    unittest.main()
