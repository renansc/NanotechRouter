import tempfile
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from html.parser import HTMLParser

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web'))
os.environ.setdefault('ROUTER_SECRET_KEY', 'synthetic-key-for-isolated-tests-only')
import app as web


class BandwidthTests(unittest.TestCase):
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

        self.payload = {'ip': '192.0.2.137', 'interface': 'eth1'}

    def test_rates_control_activation_without_checkbox(self):
        for down, up, enabled in [('20', '20', True), ('20', '0', True), ('0', '20', True), ('0', '0', False), ('', '', False)]:
            with self.subTest(down=down, up=up), patch.object(web, 'post', return_value={'success': True}) as backend:
                response = self.client.post('/bandwidth/rule', data={**self.payload, 'download_mbps': down, 'upload_mbps': up})
                self.assertEqual(response.status_code, 302)
                path, data = backend.call_args.args
                self.assertEqual(path, '/api/bandwidth/rule')
                self.assertEqual(data['enabled'], enabled)
                self.assertEqual(data['download_mbps'], int(down or 0))
                self.assertEqual(data['upload_mbps'], int(up or 0))
                self.assertEqual(data['ip'], self.payload['ip'])
                self.assertEqual(data['interface'], 'eth1')

    def test_invalid_rates_do_not_reach_core(self):
        for field in ['download_mbps', 'upload_mbps']:
            for invalid in ['-1', 'abc', '1.5']:
                with self.subTest(field=field, value=invalid), patch.object(web, 'post') as backend:
                    response = self.client.post('/bandwidth/rule', data={**self.payload, field: invalid})
                    self.assertEqual(response.status_code, 302)
                    backend.assert_not_called()

    def render(self, enabled, down=20, up=20):
        rule = {**self.payload, 'enabled': enabled, 'download_mbps': down, 'upload_mbps': up}
        device = {**self.payload, 'display_name': 'Cliente teste', 'mac': '', 'port_alias': 'LAN'}
        with web.app.test_request_context():
            return web.render_template('bandwidth.html', rules={'rules': [rule]}, devices={'devices': [device, device]}, aliases={})

    def test_indicator_respects_enabled_and_rates(self):
        self.assertIn('Limite ativo', self.render(True))
        self.assertNotIn('Limite ativo', self.render(False))
        self.assertIn('>Inativo<', self.render(False))
        self.assertNotIn('Limite ativo', self.render(True, 0, 0))

    def test_form_associations_are_unique_even_with_duplicate_devices(self):
        class Elements(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []
                self.inputs = []
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'form' and attrs.get('action') == '/bandwidth/rule':
                    self.forms.append(attrs)
                if tag == 'input' and attrs.get('form'):
                    self.inputs.append(attrs)
        parser = Elements()
        parser.feed(self.render(True))
        ids = [form['id'] for form in parser.forms]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)
        for form_id in ids:
            self.assertEqual({item['name'] for item in parser.inputs if item['form'] == form_id}, {'ip', 'interface', 'download_mbps', 'upload_mbps'})

    def test_core_failure_message_is_displayed(self):
        with patch.object(web, 'post', return_value={'success': False, 'message': 'Falha ao aplicar'}):
            self.client.post('/bandwidth/rule', data={**self.payload, 'download_mbps': '20'})
        with self.client.session_transaction() as session:
            self.assertIn(('message', 'Falha ao aplicar'), session['_flashes'])


if __name__ == '__main__':
    unittest.main()
