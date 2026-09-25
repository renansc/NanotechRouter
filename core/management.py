"""Persistent, scoped router management. Never flush unrelated network state."""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path
from flask import jsonify, request

CATEGORIES = {
    'social': {'name': 'Redes sociais', 'domains': ['facebook.com', 'facebook.net', 'fbcdn.net', 'instagram.com', 'cdninstagram.com', 'tiktok.com', 'tiktokcdn.com', 'tiktokv.com', 'twitter.com', 'x.com', 'twimg.com', 'snapchat.com', 'snap.com', 'reddit.com', 'redd.it', 'pinterest.com', 'pinimg.com']},
    'remote': {'name': 'Acesso remoto (domínios conhecidos)', 'domains': ['anydesk.com', 'teamviewer.com', 'teamviewer.us', 'rustdesk.com', 'logmein.com', 'remotepc.com', 'splashtop.com', 'parsec.app']},
    'adult': {'name': 'Conteúdo adulto — HaGeZi NSFW', 'file': 'nsfw'},
    'vpn': {'name': 'VPN, proxy e DNS criptografado — HaGeZi', 'file': 'doh-vpn-proxy-bypass'},
}
DEFAULT_POLICY = {'enabled': False, 'items': [], 'interfaces': [], 'source': '0.0.0.0/0',
                  'vpn_ports': False, 'remote_ports': False, 'dns_enabled': False,
                  'block_encrypted_dns': False, 'block_ipv6': False,
                  'categories': [], 'domains': [], 'allow_domains': [], 'exempt_ips': []}


def network(value):
    return str(ipaddress.IPv4Network(str(value).strip() or '0.0.0.0/0', strict=False))


def domain(value):
    value = str(value).strip().lower().rstrip('.')
    if '://' in value or '/' in value or ':' in value:
        raise ValueError('Informe o domínio (exemplo.com), sem protocolo, caminho ou porta. URLs completas HTTPS não são filtradas.')
    value = value.encode('idna').decode('ascii')
    if len(value) > 253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in value.split('.')):
        raise ValueError('Domínio inválido: ' + value[:80])
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Para endereços IP, use uma regra de firewall.')


def lines(value, validate):
    if isinstance(value, str):
        value = re.split(r'[\s,;]+', value.strip())
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError('Lista inválida ou maior que 1000 entradas.')
    return sorted(set(validate(v) for v in value if v))


class Management:
    def __init__(self, env):
        self.env = env

    def __getattr__(self, key):
        return self.env[key]

    def path(self, name):
        return Path(self.DATA) / (name + '.json')

    def load(self, name, default):
        path = self.path(name)
        if not path.exists():
            return json.loads(json.dumps(default))
        # Corrupt policies must produce an error, never silently disable protection.
        return json.loads(path.read_text())

    def save(self, name, value):
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as f:
            json.dump(value, f, indent=2)
            tmp = f.name
        os.replace(tmp, path)

    def checked(self, command):
        result = self.run(command)
        if not result.get('success'):
            raise RuntimeError(result.get('stderr') or 'Falha no comando: ' + command[0])
        return result

    def policy(self):
        return {**DEFAULT_POLICY, **self.load('firewall', DEFAULT_POLICY)}

    def token(self):
        value = os.environ.get('ROUTER_API_TOKEN', '')
        if not value:
            # Allows HUP deployment without restarting the service/DHCP children.
            path = Path(self.BASE) / '.env'
            if path.exists():
                for line in path.read_text().splitlines():
                    if line.startswith('ROUTER_API_TOKEN='):
                        value = line.split('=', 1)[1].strip()
        return value

    def validate_rule(self, data):
        proto = data.get('protocol', 'any')
        action = data.get('action', 'drop')
        if proto not in ('any', 'tcp', 'udp', 'icmp') or action not in ('accept', 'drop', 'reject'):
            raise ValueError('Protocolo ou ação inválidos.')
        port = str(data.get('port', '')).strip()
        if port:
            if proto not in ('tcp', 'udp') or not re.fullmatch(r'\d{1,5}(-\d{1,5})?', port):
                raise ValueError('Porta exige TCP/UDP; use 80 ou 8000-8100.')
            values = [int(p) for p in port.split('-')]
            if min(values) < 1 or max(values) > 65535 or values[0] > values[-1]:
                raise ValueError('Portas devem estar entre 1 e 65535 em ordem crescente.')
        return {'id': str(data.get('id') or uuid.uuid4().hex), 'name': str(data.get('name', '')).strip()[:80] or 'Regra',
                'source': network(data.get('source', '')), 'destination': network(data.get('destination', '')),
                'protocol': proto, 'port': port, 'action': action, 'enabled': data.get('enabled') is True}

    def nft_text(self, policy):
        out = ['table inet nanotechrouter_policy {', 'chain forward { type filter hook forward priority -20; policy accept;']
        if policy['enabled']:
            # Match ORIGINAL tuples also on reply packets: ordered exceptions and blocks apply symmetrically.
            for row in policy['items']:
                if not row['enabled']:
                    continue
                parts = [f'ct original ip saddr {row["source"]}', f'ct reply ip saddr {row["destination"]}']
                if row['protocol'] != 'any':
                    parts.append('meta l4proto ' + row['protocol'])
                if row['port']:
                    parts.append('ct reply proto-src ' + row['port'])
                parts.extend(['counter', row['action']])
                out.append(' '.join(parts))
            for iface in policy['interfaces']:
                prefix = f'iifname "{iface}" ip saddr {policy["source"]}'
                if policy['block_ipv6']:
                    out.append(f'iifname "{iface}" meta nfproto ipv6 counter drop')
                    out.append(f'oifname "{iface}" meta nfproto ipv6 counter drop')
                if policy['vpn_ports']:
                    out += [prefix + ' udp dport { 500, 4500, 1194, 1701, 51820 } counter drop',
                            prefix + ' tcp dport { 1194, 1723 } counter drop',
                            prefix + ' ip protocol { esp, ah, gre } counter drop']
                if policy['remote_ports']:
                    out += [prefix + ' tcp dport { 22, 23, 3389, 5900-5999, 5938, 6568, 21115-21119 } counter drop',
                            prefix + ' udp dport { 3389, 5938, 21116 } counter drop']
                if policy['dns_enabled'] and policy['block_encrypted_dns']:
                    out += [prefix + ' tcp dport 853 counter drop', prefix + ' udp dport { 853, 784, 8853 } counter drop']
        out += ['}', 'chain dns_guard { type filter hook input priority -20; policy accept;', 'iifname "lo" accept']
        if policy['enabled'] and policy['dns_enabled']:
            for iface in policy['interfaces']:
                out += [f'iifname "{iface}" ip saddr {policy["source"]} udp dport 1053 accept',
                        f'iifname "{iface}" ip saddr {policy["source"]} tcp dport 1053 accept']
        out += ['udp dport 1053 drop', 'tcp dport 1053 drop', '}',
                'chain dns_redirect { type nat hook prerouting priority -110; policy accept;']
        if policy['enabled'] and policy['dns_enabled']:
            for ip in policy['exempt_ips']:
                out.append(f'ip saddr {ip} return')
            for iface in policy['interfaces']:
                prefix = f'iifname "{iface}" ip saddr {policy["source"]}'
                out += [prefix + ' udp dport 53 redirect to :1053', prefix + ' tcp dport 53 redirect to :1053']
        return '\n'.join(out + ['}', '}']) + '\n'

    def apply_nft(self, policy):
        exists = self.run(['nft', 'list', 'table', 'inet', 'nanotechrouter_policy'])['success']
        text = ('delete table inet nanotechrouter_policy\n' if exists else '') + self.nft_text(policy)
        directory = Path(self.CONFIG) / 'nftables'
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', dir=directory, suffix='.nft', delete=False) as f:
            f.write(text)
            name = f.name
        try:
            self.checked(['nft', '--check', '-f', name])
            self.checked(['nft', '-f', name])
        finally:
            os.unlink(name)

    def dns_content(self, policy):
        blocked = set(policy['domains'])
        for category in policy['categories']:
            definition = CATEGORIES[category]
            if 'domains' in definition:
                blocked.update(definition['domains'])
            else:
                cached = self.load('category_' + category, {})
                if not cached.get('domains'):
                    raise ValueError('Atualize a lista ' + definition['name'] + ' antes de ativá-la.')
                blocked.update(cached['domains'])
        # listen only on current LAN addresses; nft input further restricts the resolver.
        state = self.load_state()
        addresses = ['127.0.0.1'] + [str(ipaddress.IPv4Interface(state['lans'][i]['address']).ip) for i in policy['interfaces']]
        out = ['port=1053', 'bind-interfaces', 'listen-address=' + ','.join(addresses),
               'no-resolv', 'server=1.1.1.1', 'server=9.9.9.9', 'cache-size=1000',
               'pid-file=' + self.env.get('RUNTIME_DIR', '/run/linux-router') + '/dns-filter.pid', 'user=nobody']
        # local= covers all query types, including HTTPS/SVCB; address alone is insufficient.
        for item in sorted(blocked):
            out.append('local=/' + item + '/')
        for item in policy['allow_domains']:
            out.append('server=/' + item + '/1.1.1.1')
        return '\n'.join(out) + '\n'

    def configure_dns(self, policy):
        active = policy['enabled'] and policy['dns_enabled']
        conf = Path(self.CONFIG) / 'dns-filter.conf'
        pidfile = Path(self.env.get('RUNTIME_DIR', '/run/linux-router')) / 'dns-filter.pid'
        content = self.dns_content(policy) if active else None
        old = conf.read_text() if conf.exists() else None
        if content is not None:
            conf.parent.mkdir(parents=True, exist_ok=True)
            candidate = conf.with_suffix('.candidate')
            candidate.write_text(content)
            try:
                self.checked(['dnsmasq', '--test', '--conf-file=' + str(candidate)])
            finally:
                candidate.unlink(missing_ok=True)
        # Avoid touching an unrelated PID after recycling.
        if pidfile.exists():
            pid = int(pidfile.read_text().strip())
            proc = Path('/proc') / str(pid) / 'cmdline'
            if proc.exists() and ('--conf-file=' + str(conf)).encode() in proc.read_bytes().split(b'\0'):
                self.checked(['kill', '-TERM', str(pid)])
                for _ in range(30):
                    if not proc.exists():
                        break
                    time.sleep(.1)
            pidfile.unlink(missing_ok=True)
        if not active:
            return
        conf.write_text(content)
        self.checked(['mkdir', '-p', str(pidfile.parent)])
        try:
            self.checked(['dnsmasq', '--conf-file=' + str(conf)])
        except Exception:
            if old is not None:
                conf.write_text(old)
                self.run(['dnsmasq', '--conf-file=' + str(conf)])
            raise

    def apply_policy(self, new, old, refresh_dns=False):
        dns_keys = ('enabled', 'dns_enabled', 'interfaces', 'source', 'categories', 'domains', 'allow_domains')
        dns_change = refresh_dns or any(new[k] != old[k] for k in dns_keys)
        try:
            if dns_change:
                self.configure_dns(new)
            self.apply_nft(new)
            self.save('firewall', new)
        except Exception as exc:
            errors = []
            try:
                if dns_change:
                    self.configure_dns(old)
                self.apply_nft(old)
            except Exception as rollback:
                errors.append(str(rollback))
            raise RuntimeError(str(exc) + ('; falha ao restaurar: ' + '; '.join(errors) if errors else ''))

    def settings(self, data, policy):
        result = dict(policy)
        for key in ('enabled', 'vpn_ports', 'remote_ports', 'dns_enabled', 'block_encrypted_dns', 'block_ipv6'):
            result[key] = data.get(key) is True
        result['interfaces'] = list(dict.fromkeys(data.get('interfaces', [])))
        lans = self.load_state().get('lans', {})
        if any(i not in lans or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', i) for i in result['interfaces']):
            raise ValueError('Selecione apenas interfaces LAN cadastradas.')
        if any(result[k] for k in ('vpn_ports', 'remote_ports', 'dns_enabled', 'block_ipv6')) and not result['interfaces']:
            raise ValueError('Selecione pelo menos uma LAN para os perfis.')
        result['source'] = network(data.get('source', ''))
        result['categories'] = list(dict.fromkeys(data.get('categories', [])))
        if any(c not in CATEGORIES for c in result['categories']):
            raise ValueError('Categoria inválida.')
        result['domains'] = lines(data.get('domains', ''), domain)
        result['allow_domains'] = lines(data.get('allow_domains', ''), domain)
        result['exempt_ips'] = lines(data.get('exempt_ips', ''), lambda v: str(ipaddress.IPv4Address(v)))
        if set(result['domains']) & set(result['allow_domains']):
            raise ValueError('Um domínio não pode estar nas duas listas.')
        return result

    def update_lists(self, categories):
        if not isinstance(categories, list) or any(c not in CATEGORIES for c in categories):
            raise ValueError('Categorias inválidas.')
        updated = []
        for key in categories:
            definition = CATEGORIES[key]
            if 'file' not in definition:
                continue
            url = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/' + definition['file'] + '-onlydomains.txt'
            with urllib.request.urlopen(url, timeout=25) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise ValueError('Lista excede 32 MB.')
            entries = set()
            for line in raw.decode('utf-8').splitlines():
                if line.strip() and not line.startswith(('#', '!')):
                    entries.add(domain(line.strip()))
            if not entries:
                raise ValueError('Lista vazia; versão anterior preservada.')
            self.save('category_' + key, {'domains': sorted(entries), 'updated': time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime()),
                                        'count': len(entries), 'sha256': hashlib.sha256(raw).hexdigest(), 'url': url})
            updated.append(key)
        # Download is separate from activation. Re-saving profiles applies the downloaded version.
        return 'Listas baixadas. Salve os perfis para aplicar a versão atualizada: ' + ', '.join(updated)

    def vlan_create(self, data):
        items = self.load('vlans', [])
        parent = str(data.get('parent', ''))
        tag = int(data.get('tag', 0))
        name = parent + '.' + str(tag)
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,12}', parent) or not self.interface_exists(parent) or parent == 'lo':
            raise ValueError('Interface física inválida.')
        if not (Path('/sys/class/net') / parent / 'device').exists():
            raise ValueError('Escolha uma interface física como porta da VLAN.')
        if not 1 <= tag <= 4094 or len(name) > 15 or self.interface_exists(name):
            raise ValueError('VLAN já existe ou ID/nome inválido (1–4094).')
        row = {'id': uuid.uuid4().hex, 'parent': parent, 'tag': tag, 'interface': name,
               'name': str(data.get('name', '')).strip()[:80] or name}
        self.checked(['ip', 'link', 'add', 'link', parent, 'name', name, 'type', 'vlan', 'id', str(tag)])
        try:
            self.checked(['ip', 'link', 'set', 'dev', name, 'up'])
            self.save('vlans', items + [row])
        except Exception:
            self.run(['ip', 'link', 'delete', 'dev', name])
            raise
        return 'VLAN criada. Em Interfaces / WAN / LAN configure endereço e DHCP; em Firewall configure o isolamento.'

    def vlan_delete(self, rid):
        items = self.load('vlans', [])
        row = next((r for r in items if r['id'] == rid), None)
        if not row:
            raise ValueError('VLAN não encontrada.')
        name = row['interface']
        state = self.load_state()
        if name == state.get('wan') or name in state.get('lans', {}) or any(r['interface'] == name for r in self.load('routes', [])) or name in self.policy()['interfaces']:
            raise ValueError('Remova primeiro o uso desta VLAN em LAN/WAN, rotas e perfis do firewall.')
        if self.interface_exists(name):
            self.verify_vlan(row)
            self.checked(['ip', 'link', 'delete', 'dev', name])
        self.save('vlans', [r for r in items if r['id'] != rid])

    def verify_vlan(self, row):
        raw = json.loads(self.checked(['ip', '-j', '-d', 'link', 'show', 'dev', row['interface']])['stdout'])
        if not raw or raw[0].get('link') != row['parent'] or raw[0].get('linkinfo', {}).get('info_kind') != 'vlan' or raw[0].get('linkinfo', {}).get('info_data', {}).get('id') != row['tag']:
            raise ValueError('Interface existente não corresponde à VLAN cadastrada.')

    def restore_vlans(self):
        for row in self.load('vlans', []):
            if not self.interface_exists(row['interface']):
                self.checked(['ip', 'link', 'add', 'link', row['parent'], 'name', row['interface'], 'type', 'vlan', 'id', str(row['tag'])])
            else:
                self.verify_vlan(row)
            self.checked(['ip', 'link', 'set', 'dev', row['interface'], 'up'])

    def route_args(self, row, operation):
        return ['ip', '-4', 'route', operation, row['destination'], 'via', row['gateway'], 'dev', row['interface'],
                'metric', str(row['metric']), 'proto', '243', 'table', 'main']

    def route_save(self, data):
        items = self.load('routes', [])
        rid = str(data.get('id') or uuid.uuid4().hex)
        old = next((r for r in items if r['id'] == rid), None)
        if data.get('id') and old is None:
            raise ValueError('Rota não encontrada.')
        row = {'id': rid, 'name': str(data.get('name', '')).strip()[:80], 'destination': network(data.get('destination', '')),
               'gateway': str(ipaddress.IPv4Address(data.get('gateway', ''))), 'interface': str(data.get('interface', '')),
               'metric': int(data.get('metric', 100)), 'enabled': data.get('enabled') is True}
        dest = ipaddress.IPv4Network(row['destination'])
        if dest.prefixlen == 0 or dest.is_loopback or dest.is_multicast or not 1 <= row['metric'] <= 65535:
            raise ValueError('Use uma rede unicast específica e métrica entre 1 e 65535; rota padrão é gerenciada pela WAN.')
        if not self.valid_interface(row['interface']) or not self.interface_exists(row['interface']):
            raise ValueError('Interface inválida.')
        addresses = [ipaddress.IPv4Interface(a) for a in self.interface_ipv4(row['interface'])]
        gateway = ipaddress.IPv4Address(row['gateway'])
        if not any(gateway in a.network and gateway not in (a.ip, a.network.network_address, a.network.broadcast_address) for a in addresses):
            raise ValueError('Gateway deve ser outro aparelho diretamente conectado à interface.')
        connected = json.loads(self.checked(['ip', '-j', '-4', 'route', 'show', 'table', 'main', 'scope', 'link'])['stdout'] or '[]')
        if any(dest.overlaps(ipaddress.IPv4Network(r['dst'], strict=False)) for r in connected if r.get('dst') and r['dst'] != 'default'):
            raise ValueError('Destino sobrepõe uma rede diretamente conectada.')
        if any(r['id'] != rid and r['destination'] == row['destination'] and r['metric'] == row['metric'] for r in items):
            raise ValueError('Destino e métrica já cadastrados.')
        removed = False
        added = False
        try:
            if old and old['enabled']:
                self.checked(self.route_args(old, 'del'))
                removed = True
            if row['enabled']:
                self.checked(self.route_args(row, 'add'))
                added = True
            self.save('routes', [row if r['id'] == rid else r for r in items] if old else items + [row])
        except Exception as exc:
            if added:
                self.run(self.route_args(row, 'del'))
            rollback = self.run(self.route_args(old, 'add')) if removed else {'success': True}
            if not rollback['success']:
                raise RuntimeError(str(exc) + '; falha ao restaurar rota anterior: ' + rollback.get('stderr', ''))
            raise

    def route_delete(self, rid):
        items = self.load('routes', [])
        row = next((r for r in items if r['id'] == rid), None)
        if not row:
            raise ValueError('Rota não encontrada.')
        if row['enabled']:
            self.checked(self.route_args(row, 'del'))
        try:
            self.save('routes', [r for r in items if r['id'] != rid])
        except Exception:
            if row['enabled']:
                self.run(self.route_args(row, 'add'))
            raise

    def restore_routes(self):
        existing = json.loads(self.checked(['ip', '-j', '-4', 'route', 'show', 'table', 'main', 'protocol', '243'])['stdout'] or '[]')
        for row in self.load('routes', []):
            if row['enabled'] and not any(r.get('dst') == row['destination'] and r.get('gateway') == row['gateway'] and r.get('dev') == row['interface'] and r.get('metric') == row['metric'] for r in existing):
                self.checked(self.route_args(row, 'add'))

    def restore_policy(self):
        policy = self.policy()
        self.apply_nft(policy)
        self.configure_dns(policy)


def register(app, env):
    m = Management(env)

    @app.before_request
    def authenticate_core():
        if request.path == '/health':
            return
        expected = m.token()
        if not expected or not hmac.compare_digest(request.headers.get('X-Router-Token', ''), expected):
            return jsonify(success=False, message='Acesso administrativo necessário.'), 401

    @app.before_request
    def guard_network_dependencies():
        if request.path not in ('/api/lan/delete', '/api/lan/set') or request.method != 'POST':
            return
        data = request.get_json(silent=True) or {}
        iface = data.get('interface', '')
        state = m.load_state()
        existing = state.get('lans', {}).get(iface, {})
        try:
            if request.path == '/api/lan/delete' or (existing and data.get('address') != existing.get('address')):
                if iface in m.policy()['interfaces'] or any(r['interface'] == iface for r in m.load('routes', [])):
                    raise ValueError('Remova primeiro esta interface dos perfis do firewall e das rotas estáticas.')
            if request.path == '/api/lan/set':
                new = ipaddress.IPv4Interface(data.get('address', ''))
                if new.ip in (new.network.network_address, new.network.broadcast_address):
                    raise ValueError('O gateway não pode ser o endereço de rede ou broadcast.')
                for item in m.get_interfaces():
                    if item['name'] != iface:
                        for address in item.get('addresses', []):
                            if new.network.overlaps(ipaddress.IPv4Interface(address).network):
                                raise ValueError('A faixa sobrepõe outra interface: ' + item['name'])
        except (ValueError, KeyError) as exc:
            return jsonify(success=False, message=str(exc)), 400

    @app.get('/api/system/info')
    def system_info():
        return jsonify(success=True, version='0.5.0', hostname=os.uname().nodename,
                       uptime_seconds=int(float(Path('/proc/uptime').read_text().split()[0])),
                       forwarding=Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1')

    @app.post('/api/system/reboot')
    def reboot():
        if (request.get_json(silent=True) or {}).get('confirmation') != 'REINICIAR':
            return jsonify(success=False, message='Confirmação de reinício ausente.'), 400
        result = m.run(['systemd-run', '--unit=nanotechrouter-reboot-' + uuid.uuid4().hex[:8], '--on-active=5s', '/usr/bin/systemctl', 'reboot'])
        return jsonify(success=result['success'], message='Reinício solicitado para daqui a 5 segundos.' if result['success'] else result['stderr']), (200 if result['success'] else 500)

    @app.get('/api/<section>')
    def management_get(section):
        if section not in ('vlans', 'routes', 'firewall'):
            return jsonify(success=False, message='Recurso não encontrado.'), 404
        try:
            if section == 'firewall':
                policy = m.policy()
                categories = {}
                for key, definition in CATEGORIES.items():
                    cached = m.load('category_' + key, {})
                    categories[key] = {'name': definition['name'], 'count': cached.get('count', len(definition.get('domains', []))), 'updated': cached.get('updated', 'Lista inicial incluída' if 'domains' in definition else 'Ainda não baixada')}
                return jsonify(success=True, **policy, categories_info=categories,
                               runtime=m.run(['nft', 'list', 'table', 'inet', 'nanotechrouter_policy']).get('stdout', ''))
            return jsonify(success=True, items=m.load(section, []))
        except Exception as exc:
            return jsonify(success=False, message=str(exc)), 500

    @app.post('/api/<section>/<operation>')
    def management_post(section, operation):
        if section not in ('vlans', 'routes', 'firewall'):
            return jsonify(success=False, message='Recurso não encontrado.'), 404
        data = request.get_json(silent=True) or {}
        try:
            with m.NETWORK_LOCK:
                message = 'Configuração salva e aplicada.'
                if section == 'vlans' and operation == 'save':
                    message = m.vlan_create(data)
                elif section == 'vlans' and operation == 'delete':
                    m.vlan_delete(data.get('id'))
                elif section == 'routes' and operation == 'save':
                    m.route_save(data)
                elif section == 'routes' and operation == 'delete':
                    m.route_delete(data.get('id'))
                elif section == 'firewall':
                    old = m.policy()
                    new = json.loads(json.dumps(old))
                    if operation == 'settings':
                        new = m.settings(data, old)
                    elif operation == 'lists':
                        return jsonify(success=True, message=m.update_lists(data.get('categories', [])))
                    else:
                        rid = data.get('id')
                        position = next((i for i, r in enumerate(new['items']) if r['id'] == rid), None)
                        if rid and position is None:
                            raise ValueError('Regra não encontrada.')
                        if operation == 'save':
                            row = m.validate_rule(data)
                            if position is None:
                                new['items'].append(row)
                            else:
                                new['items'][position] = row
                        elif operation == 'delete' and position is not None:
                            new['items'].pop(position)
                        elif operation == 'move' and position is not None:
                            target = position + (-1 if data.get('direction') == 'up' else 1)
                            if 0 <= target < len(new['items']):
                                new['items'].insert(target, new['items'].pop(position))
                        else:
                            raise ValueError('Operação inválida.')
                    m.apply_policy(new, old, refresh_dns=operation == 'settings')
                    if not new['enabled']:
                        message = 'Configuração salva. Firewall permanece desativado até ativar nos perfis.'
                else:
                    raise ValueError('Operação inválida.')
                return jsonify(success=True, message=message)
        except (ValueError, TypeError, KeyError) as exc:
            return jsonify(success=False, message=str(exc)), 400
        except Exception as exc:
            return jsonify(success=False, message=str(exc)), 500

    @app.post('/api/system/restore-links')
    def restore_links():
        try:
            with m.NETWORK_LOCK:
                m.restore_vlans()
            return jsonify(success=True)
        except Exception as exc:
            return jsonify(success=False, message=str(exc)), 500

    return m
