"""Isolated HTTP/TLS validation for the local block page.

Uses only high loopback ports and a temporary directory. It never changes the
router network, system trust store or production data.
"""
import json
import hashlib
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def request(port, host, context=None, path='/private'):
    connection = socket.create_connection(('127.0.0.1', port), timeout=3)
    if context is not None:
        connection = context.wrap_socket(connection, server_hostname=host)
    connection.sendall(('GET ' + path + ' HTTP/1.1\r\nHost: ' + host +
                        '\r\nConnection: close\r\n\r\n').encode())
    chunks = []
    while True:
        chunk = connection.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    connection.close()
    return b''.join(chunks)


with tempfile.TemporaryDirectory() as directory:
    data = Path(directory)
    (data / 'firewall.json').write_text(json.dumps({
        'block_page_title': '<Bloqueado & seguro>',
        'block_page_message': '<script>never()</script>'
    }))
    http_port, https_port = free_port(), free_port()
    environment = {**os.environ, 'ROUTER_DATA': directory, 'BLOCKPAGE_BIND': '127.0.0.1',
                   'BLOCKPAGE_HTTP_PORT': str(http_port), 'BLOCKPAGE_HTTPS_PORT': str(https_port)}
    process = subprocess.Popen([sys.executable, str(ROOT / 'core/blockpage.py')], env=environment,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(60):
            try:
                plain = request(http_port, 'blocked.example')
                break
            except OSError:
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read().decode())
                time.sleep(.1)
        else:
            raise AssertionError('A página HTTP não iniciou.')
        assert plain.startswith(b'HTTP/1.0 451 '), plain[:100]
        assert b'&lt;Bloqueado &amp; seguro&gt;' in plain
        assert b'<script>never()</script>' not in plain
        logo = request(http_port, 'blocked.example', path='/logo.png')
        assert logo.startswith(b'HTTP/1.0 200 ') and b'Content-Type: image/png' in logo
        assert logo.endswith((ROOT / 'core/blockpage-logo.png').read_bytes())

        ca = data / 'blockpage/ca.crt'
        trusted = ssl.create_default_context(cafile=str(ca))
        secure = request(https_port, 'blocked.example', trusted)
        assert secure.startswith(b'HTTP/1.0 451 '), secure[:100]
        assert b'blocked.example' in secure

        try:
            request(https_port, 'blocked.example', ssl.create_default_context())
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise AssertionError('HTTPS sem confiar na CA deveria falhar na validação.')

        blocked_certificate = (data / 'blockpage/certificates' /
                               (hashlib.sha256(b'blocked.example').hexdigest() + '.crt'))
        details = subprocess.check_output([
            'openssl', 'x509', '-in', str(blocked_certificate),
            '-noout', '-ext', 'subjectAltName'
        ], text=True)
        assert 'DNS:blocked.example' in details, details
        print('Página de bloqueio: HTTP 451, escape HTML, HTTPS/SNI e CA validados.')
    finally:
        process.terminate()
        process.wait(timeout=10)
