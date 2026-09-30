"""Run explicitly as root on a systemd host. Uses only temporary test services.

No router service, Docker daemon, interface or firewall is changed. The deployed
unit's dependency/retry settings are exercised with a delayed synthetic Docker
and a transient failure, then all temporary units are removed.
"""
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

if os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
    raise SystemExit('Requires root on a systemd host; creates temporary test units only.')

root = Path(__file__).resolve().parents[1]
prefix = 'nr-boot-test-' + uuid.uuid4().hex[:10]
units = {name: prefix + '-' + name + suffix for name, suffix in
         [('docker', '.service'), ('core', '.service'), ('network', '.target'), ('restore', '.service')]}
created = []


def systemctl(*args, check=True):
    return subprocess.run(['systemctl', *args], check=check, capture_output=True, text=True)


with tempfile.TemporaryDirectory(prefix=prefix + '-') as temporary:
    directory = Path(temporary)
    ready = directory / 'ready'
    attempts = directory / 'attempts'
    runner = directory / 'restore.sh'
    runner.write_text(
        '#!/bin/sh\n'
        f'if [ ! -f {ready} ]; then echo premature >> {attempts}; exit 1; fi\n'
        f'if [ ! -f {attempts} ]; then echo transient >> {attempts}; exit 1; fi\n'
        f'echo recovered >> {attempts}\n')
    config = (root / 'deploy/systemd/nanotechrouter-safe-restore.service').read_text()
    for original, replacement in [('docker.service', units['docker']),
                                  ('linux-router-core.service', units['core']),
                                  ('network-online.target', units['network'])]:
        config = config.replace(original, replacement)
    config = config.replace('/usr/local/sbin/nanotechrouter-safe-restore', '/bin/sh ' + str(runner))
    definitions = {
        'network': '[Unit]\nDescription=Synthetic network target\n',
        'core': '[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n',
        'docker': '[Service]\nType=oneshot\n'
                  f'ExecStart=/bin/sh -c "sleep 2; touch {ready}"\nRemainAfterExit=yes\n',
        'restore': config,
    }
    try:
        for name, content in definitions.items():
            path = Path('/run/systemd/system') / units[name]
            path.write_text(content)
            created.append(path)
        systemctl('daemon-reload')
        systemctl('start', '--no-block', units['restore'])
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if systemctl('is-active', units['restore'], check=False).stdout.strip() == 'active':
                break
            time.sleep(.25)
        else:
            raise AssertionError(systemctl('status', units['restore'], check=False).stdout)
        assert attempts.read_text().splitlines() == ['transient', 'recovered'], attempts.read_text()
        assert systemctl('show', units['restore'], '-p', 'NRestarts', '--value').stdout.strip() == '1'
        print('PASS: waits for delayed Docker, retries transient failure, remains active')
    finally:
        systemctl('stop', units['restore'], check=False)
        for name in ('core', 'docker', 'network'):
            systemctl('stop', units[name], check=False)
        systemctl('reset-failed', *units.values(), check=False)
        for path in created:
            path.unlink()
        systemctl('daemon-reload')
