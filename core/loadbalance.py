"""Connection-based multi-WAN load balancing and health failover."""
import ipaddress
import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from flask import jsonify, request

DEFAULT = {'enabled': False, 'mode': 'balance', 'health_target': '1.1.1.1', 'members': []}
RULE_PROTOCOL = '244'
RULE_PRIORITY = '2600'
TABLE_BASE = 42000
MARK_BASE = 0x1100


class LoadBalancer:
    def __init__(self, env):
        self.env = env

    def __getattr__(self, key):
        return self.env[key]

    @property
    def config_path(self):
        return Path(self.DATA) / 'loadbalance.json'

    @property
    def status_path(self):
        return Path(self.DATA) / 'loadbalance_status.json'

    def load_json(self, path, default):
        try:
            return json.loads(path.read_text())
        except FileNotFoundError:
            return json.loads(json.dumps(default))

    def save_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as output:
            json.dump(value, output, indent=2)
            temporary = output.name
        os.replace(temporary, path)

    def config(self):
        return {**DEFAULT, **self.load_json(self.config_path, DEFAULT)}

    def statuses(self):
        return self.load_json(self.status_path, {})

    def checked(self, command):
        result = self.run(command)
        if not result.get('success'):
            raise RuntimeError(result.get('stderr') or result.get('message') or 'Falha executando ' + command[0])
        return result

    def candidates(self):
        state = self.load_state()
        result = []
        for item in self.get_interfaces():
            name = item['name']
            if name == 'lo' or name in state.get('lans', {}) or item['type'] in ('DOCKER', 'BRIDGE', 'VIRTUAL'):
                continue
            gateways = self.run(['ip', '-j', '-4', 'route', 'show', 'default', 'dev', name])
            try:
                gateway = next((row.get('gateway', '') for row in json.loads(gateways.get('stdout') or '[]') if row.get('gateway')), '')
            except ValueError:
                gateway = ''
            result.append({**item, 'suggested_gateway': gateway})
        return result

    def validate_member(self, data, existing=None):
        interface = str(data.get('interface', '')).strip()
        state = self.load_state()
        if not self.valid_interface(interface) or not self.interface_exists(interface) or interface == 'lo':
            raise ValueError('Interface de link inválida ou desconectada.')
        if interface in state.get('lans', {}):
            raise ValueError('Uma interface LAN não pode ser usada como link de Internet.')
        addresses = [ipaddress.IPv4Interface(value) for value in self.interface_ipv4(interface)]
        if not addresses:
            raise ValueError('Configure um IPv4 na interface antes de adicioná-la ao balanceamento.')
        gateway = ipaddress.IPv4Address(str(data.get('gateway', '')).strip())
        if not any(gateway in address.network and gateway not in
                   (address.ip, address.network.network_address, address.network.broadcast_address)
                   for address in addresses):
            raise ValueError('O gateway deve ser outro endereço diretamente conectado à interface.')
        try:
            weight = int(data.get('weight', 1))
            priority = int(data.get('priority', 10))
        except (TypeError, ValueError):
            raise ValueError('Peso e prioridade devem ser números inteiros.')
        if not 1 <= weight <= 100 or not 1 <= priority <= 100:
            raise ValueError('Peso e prioridade devem estar entre 1 e 100.')
        return {'id': (existing or {}).get('id', uuid.uuid4().hex),
                'name': str(data.get('name', '')).strip()[:80] or interface,
                'interface': interface, 'gateway': str(gateway), 'weight': weight,
                'priority': priority, 'enabled': data.get('enabled') is True,
                'slot': (existing or {}).get('slot')}

    def allocate_slot(self, members):
        used = {int(item['slot']) for item in members if item.get('slot')}
        for slot in range(1, 201):
            if slot not in used:
                return slot
        raise ValueError('Limite de 200 links cadastrados atingido.')

    def validate_config(self, config):
        if config['mode'] not in ('balance', 'failover'):
            raise ValueError('Modo de balanceamento inválido.')
        config['health_target'] = str(ipaddress.IPv4Address(config['health_target']))
        enabled = [item for item in config['members'] if item['enabled']]
        if config['enabled'] and len(enabled) < 2:
            raise ValueError('Ative pelo menos dois links antes de habilitar o balanceamento.')
        names = [item['interface'] for item in config['members']]
        if len(names) != len(set(names)):
            raise ValueError('Cada interface pode aparecer somente uma vez.')
        return config

    def check_member(self, member, target):
        if not self.interface_exists(member['interface']):
            return {'up': False, 'message': 'Interface ausente'}
        link = self.run(['ip', '-j', 'link', 'show', 'dev', member['interface']])
        try:
            details = json.loads(link.get('stdout') or '[]')[0]
        except (ValueError, IndexError):
            return {'up': False, 'message': 'Não foi possível ler a interface'}
        if details.get('operstate') not in ('UP', 'UNKNOWN'):
            return {'up': False, 'message': 'Link físico inativo'}
        if not self.interface_ipv4(member['interface']):
            return {'up': False, 'message': 'Interface sem IPv4'}
        # ip rule/nft accept hexadecimal notation; iputils ping expects decimal.
        mark = str(MARK_BASE + int(member['slot']))
        ping = self.run(['ping', '-m', mark, '-c', '1', '-W', '2', target], timeout=5)
        return {'up': ping.get('success', False),
                'message': 'Saudável' if ping.get('success') else 'Sem resposta de ' + target}

    def check(self, config=None):
        config = config or self.config()
        if config['enabled']:
            self.prepare_kernel()
        previous = self.statuses()
        current = {}
        now = time.strftime('%Y-%m-%d %H:%M:%S %z')
        for member in config['members']:
            if not config['enabled']:
                status = {'up': False, 'message': 'Aguardando ativação'}
            elif member['enabled']:
                self.install_table(member)
                status = self.check_member(member, config['health_target'])
            else:
                status = {'up': False, 'message': 'Desativado'}
            current[member['id']] = {**status, 'checked_at': now}
        self.save_json(self.status_path, current)
        changed = any(previous.get(key, {}).get('up') != value.get('up') for key, value in current.items())
        return current, changed

    def selected(self, config, statuses):
        healthy = [member for member in config['members']
                   if member['enabled'] and statuses.get(member['id'], {}).get('up')]
        if config['mode'] == 'failover' and healthy:
            healthy = [sorted(healthy, key=lambda item: (item['priority'], item['interface']))[0]]
        return healthy

    def prepare_kernel(self):
        # Loose reverse-path validation is required when the best route to a
        # source can legitimately use another provider. Marks remain part of
        # source validation for established policy-routed flows.
        self.checked(['sysctl', '-w', 'net.ipv4.conf.all.rp_filter=2'])
        self.checked(['sysctl', '-w', 'net.ipv4.conf.all.src_valid_mark=1'])

    def cleanup(self, configs):
        seen = set()
        for config in configs:
            for member in config.get('members', []):
                slot = member.get('slot')
                if not slot or slot in seen:
                    continue
                seen.add(slot)
                mark = hex(MARK_BASE + int(slot)) + '/0xffff'
                table = str(TABLE_BASE + int(slot))
                while self.run(['ip', '-4', 'rule', 'del', 'priority', RULE_PRIORITY,
                                'fwmark', mark, 'table', table, 'protocol', RULE_PROTOCOL]).get('success'):
                    pass
                self.run(['ip', '-4', 'route', 'flush', 'table', table, 'protocol', RULE_PROTOCOL])

    def nft_text(self, config, selected):
        state = self.load_state()
        lans = [name for name, value in state.get('lans', {}).items()
                if value.get('internet') and self.interface_exists(name)]
        primary = state.get('wan')
        enabled = [item for item in config['members'] if item['enabled']]
        wans = sorted(set([primary] + [item['interface'] for item in enabled]) - {None})
        lines = ['table ip nanotechrouter_lb {',
                 'chain classify { type filter hook prerouting priority -150; policy accept;']
        # Restore the selected WAN only for packets entering from a LAN. Restoring
        # it on replies arriving from a WAN would route those replies back outside.
        if lans:
            lines.append('iifname { ' + ', '.join('"' + name + '"' for name in lans) +
                         ' } ct state established,related ct mark != 0 meta mark set ct mark')
        # Remember the ingress WAN for port forwards. The reply later enters from a LAN,
        # restores this conntrack mark and leaves through the same provider.
        for member in enabled:
            lines.append('ct state new iifname "' + member['interface'] + '" ct mark set ' +
                         hex(MARK_BASE + int(member['slot'])))
        if lans and wans and selected:
            prefix = ('ct state new ct mark 0 iifname { ' + ', '.join('"' + name + '"' for name in lans) +
                      ' } fib daddr oifname { ' + ', '.join('"' + name + '"' for name in wans) + ' } ')
            if len(selected) == 1:
                lines.append(prefix + 'ct mark set ' + hex(MARK_BASE + int(selected[0]['slot'])) +
                             ' meta mark set ct mark counter')
            else:
                values = []
                position = 0
                for member in selected:
                    end = position + member['weight'] - 1
                    key = str(position) if end == position else f'{position}-{end}'
                    values.append(key + ' : ' + hex(MARK_BASE + int(member['slot'])))
                    position = end + 1
                lines.append(prefix + 'ct mark set numgen random mod ' + str(position) +
                             ' map { ' + ', '.join(values) + ' } meta mark set ct mark counter')
        lines += ['}', '}']
        return '\n'.join(lines) + '\n'

    def install_table(self, member):
        slot = int(member['slot'])
        table = str(TABLE_BASE + slot)
        mark = hex(MARK_BASE + slot) + '/0xffff'
        addresses = [ipaddress.IPv4Interface(value) for value in self.interface_ipv4(member['interface'])]
        source = addresses[0]
        while self.run(['ip', '-4', 'rule', 'del', 'priority', RULE_PRIORITY, 'fwmark', mark,
                        'table', table, 'protocol', RULE_PROTOCOL]).get('success'):
            pass
        self.checked(['ip', '-4', 'route', 'replace', str(source.network), 'dev', member['interface'],
                      'src', str(source.ip), 'table', table, 'protocol', RULE_PROTOCOL])
        self.checked(['ip', '-4', 'route', 'replace', 'default', 'via', member['gateway'],
                      'dev', member['interface'], 'table', table, 'protocol', RULE_PROTOCOL])
        self.checked(['ip', '-4', 'rule', 'add', 'priority', RULE_PRIORITY, 'fwmark', mark,
                      'table', table, 'protocol', RULE_PROTOCOL])

    def apply(self, config, statuses, previous=None):
        previous = previous or self.config()
        selected = self.selected(config, statuses) if config['enabled'] else []
        self.cleanup([previous, config])
        if config['enabled']:
            self.prepare_kernel()
        # Keep a route table for every configured link so inbound DNAT remains
        # symmetric even when that link is temporarily excluded from new sessions.
        for member in config['members']:
            if not (config['enabled'] and member['enabled']):
                continue
            self.install_table(member)
        directory = Path(self.CONFIG) / 'nftables'
        directory.mkdir(parents=True, exist_ok=True)
        exists = self.run(['nft', 'list', 'table', 'ip', 'nanotechrouter_lb']).get('success')
        text = ('delete table ip nanotechrouter_lb\n' if exists else '') + self.nft_text(config, selected)
        with tempfile.NamedTemporaryFile(mode='w', dir=directory, suffix='.nft', delete=False) as output:
            output.write(text)
            path = output.name
        try:
            self.checked(['nft', '--check', '-f', path])
            self.checked(['nft', '-f', path])
        finally:
            os.unlink(path)
        return selected

    def persist(self, config, previous):
        try:
            statuses, _ = self.check(config)
            selected = self.apply(config, statuses, previous)
            self.save_json(self.config_path, config)
            network = self.rebuild_network_rules()
            forwards = self.nr_rebuild_port_forwards()
            if not network.get('success'):
                raise RuntimeError(network.get('message') or 'Falha ao atualizar NAT/FORWARD dos links.')
            if not forwards.get('success'):
                raise RuntimeError(forwards.get('message') or forwards.get('stderr') or
                                   'Falha ao atualizar redirecionamentos de portas.')
            return selected
        except Exception as exc:
            try:
                self.save_json(self.config_path, previous)
                old_status, _ = self.check(previous)
                self.apply(previous, old_status, config)
                network = self.rebuild_network_rules()
                forwards = self.nr_rebuild_port_forwards()
                if not network.get('success') or not forwards.get('success'):
                    raise RuntimeError('NAT/FORWARD anterior não foi reaplicado.')
            except Exception as rollback:
                raise RuntimeError(str(exc) + '; falha ao restaurar balanceamento anterior: ' + str(rollback))
            raise

    def restore(self):
        config = self.config()
        self.validate_config(config)
        statuses, _ = self.check(config)
        selected = self.apply(config, statuses, config)
        return {'success': True, 'active': [member['interface'] for member in selected]}

    def active_wans(self):
        config = self.config()
        return [member['interface'] for member in config['members'] if config['enabled'] and member['enabled']]


def register(app, env):
    manager = LoadBalancer(env)

    @app.get('/api/loadbalance')
    def loadbalance_get():
        config = manager.config()
        statuses = manager.statuses()
        return jsonify(success=True, **config, statuses=statuses, candidates=manager.candidates(),
                       selected=[member['interface'] for member in manager.selected(config, statuses)])

    @app.post('/api/loadbalance/settings')
    def loadbalance_settings():
        data = request.get_json(silent=True) or {}
        previous = manager.config()
        config = {**previous, 'enabled': data.get('enabled') is True,
                  'mode': str(data.get('mode', 'balance')),
                  'health_target': str(data.get('health_target', '1.1.1.1')).strip()}
        try:
            with manager.NETWORK_LOCK:
                manager.validate_config(config)
                selected = manager.persist(config, previous)
            return jsonify(success=True, message='Balanceamento salvo e aplicado.',
                           selected=[member['interface'] for member in selected])
        except (ValueError, TypeError) as exc:
            return jsonify(success=False, message=str(exc)), 400
        except Exception as exc:
            return jsonify(success=False, message=str(exc)), 500

    @app.post('/api/loadbalance/member')
    def loadbalance_member():
        data = request.get_json(silent=True) or {}
        previous = manager.config()
        config = json.loads(json.dumps(previous))
        rid = str(data.get('id', '')).strip()
        existing = next((item for item in config['members'] if item['id'] == rid), None) if rid else None
        if rid and not existing:
            return jsonify(success=False, message='Link não encontrado.'), 404
        try:
            with manager.NETWORK_LOCK:
                member = manager.validate_member(data, existing)
                if member['slot'] is None:
                    member['slot'] = manager.allocate_slot(config['members'])
                if any(item['interface'] == member['interface'] and item['id'] != member['id'] for item in config['members']):
                    raise ValueError('Essa interface já está cadastrada.')
                config['members'] = [member if item['id'] == member['id'] else item for item in config['members']]
                if not existing:
                    config['members'].append(member)
                manager.validate_config(config)
                manager.persist(config, previous)
            return jsonify(success=True, message='Link salvo.')
        except (ValueError, TypeError) as exc:
            return jsonify(success=False, message=str(exc)), 400
        except Exception as exc:
            return jsonify(success=False, message=str(exc)), 500

    @app.post('/api/loadbalance/member/delete')
    def loadbalance_member_delete():
        data = request.get_json(silent=True) or {}
        previous = manager.config()
        rid = str(data.get('id', ''))
        if not any(item['id'] == rid for item in previous['members']):
            return jsonify(success=False, message='Link não encontrado.'), 404
        config = {**previous, 'members': [item for item in previous['members'] if item['id'] != rid]}
        try:
            with manager.NETWORK_LOCK:
                manager.validate_config(config)
                manager.persist(config, previous)
            return jsonify(success=True, message='Link removido.')
        except ValueError as exc:
            return jsonify(success=False, message=str(exc)), 400
        except Exception as exc:
            return jsonify(success=False, message=str(exc)), 500

    @app.post('/api/loadbalance/check')
    def loadbalance_check():
        try:
            with manager.NETWORK_LOCK:
                config = manager.config()
                statuses, changed = manager.check(config)
                if changed and config['enabled']:
                    selected = manager.apply(config, statuses, config)
                else:
                    selected = manager.selected(config, statuses)
            return jsonify(success=True, changed=changed, statuses=statuses,
                           selected=[member['interface'] for member in selected])
        except Exception as exc:
            return jsonify(success=False, message=str(exc)), 500

    return manager
