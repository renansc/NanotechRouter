#!/usr/bin/env python3
"""HTTP/HTTPS block page for domains redirected by the DNS filter.

HTTPS uses certificates signed by a local CA. Clients must trust ca.crt before
the browser can display the page without stopping at a certificate warning.
"""
import argparse
import hashlib
import html
import ipaddress
import json
import os
import re
import signal
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DATA = Path(os.environ.get('ROUTER_DATA', '/opt/linux-router/data'))
DIRECTORY = DATA / 'blockpage'
POLICY = DATA / 'firewall.json'
LOGO = Path(__file__).with_name('blockpage-logo.png')
BIND = os.environ.get('BLOCKPAGE_BIND', '198.18.0.1')
HTTP_PORT = int(os.environ.get('BLOCKPAGE_HTTP_PORT', '80'))
HTTPS_PORT = int(os.environ.get('BLOCKPAGE_HTTPS_PORT', '443'))
MAX_CERTIFICATES = 500
HOST = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Falha executando ' + args[0])


def secure(path, mode):
    os.chmod(path, mode)
    return path


def ensure_ca():
    DIRECTORY.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(DIRECTORY, 0o700)
    key, certificate = DIRECTORY / 'ca.key', DIRECTORY / 'ca.crt'
    if key.exists() and certificate.exists():
        return certificate, key
    for item in (key, certificate):
        if item.exists():
            raise RuntimeError('Autoridade certificadora incompleta; preserve os arquivos e corrija manualmente.')
    command(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256',
             '-days', '3650', '-subj', '/CN=NanotechRouter Block Page CA',
             '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
             '-addext', 'subjectKeyIdentifier=hash',
             '-keyout', str(key), '-out', str(certificate)])
    secure(key, 0o600)
    secure(certificate, 0o644)
    return certificate, key


def valid_host(value):
    value = (value or '').split(':', 1)[0].strip().lower().rstrip('.')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        return 'blocked.nanotechrouter.local'
    return value if HOST.fullmatch(value) else 'blocked.nanotechrouter.local'


def certificate_for(host):
    ca, ca_key = ensure_ca()
    host = valid_host(host)
    digest = hashlib.sha256(host.encode()).hexdigest()
    directory = DIRECTORY / 'certificates'
    directory.mkdir(mode=0o700, exist_ok=True)
    certificate, key = directory / (digest + '.crt'), directory / (digest + '.key')
    if certificate.exists() and key.exists():
        return certificate, key
    existing = sorted(directory.glob('*.crt'), key=lambda item: item.stat().st_mtime)
    while len(existing) >= MAX_CERTIFICATES:
        old = existing.pop(0)
        old.unlink(missing_ok=True)
        old.with_suffix('.key').unlink(missing_ok=True)
    request = directory / (digest + '.csr')
    try:
        ipaddress.ip_address(host)
        extension = 'IP:' + host
    except ValueError:
        extension = 'DNS:' + host
    command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
             '-subj', '/CN=' + host, '-addext', 'subjectAltName=' + extension,
             '-keyout', str(key), '-out', str(request)])
    try:
        command(['openssl', 'x509', '-req', '-in', str(request), '-CA', str(ca),
                 '-CAkey', str(ca_key), '-CAcreateserial', '-days', '825', '-sha256',
                 '-copy_extensions', 'copyall', '-out', str(certificate)])
    finally:
        request.unlink(missing_ok=True)
    secure(key, 0o600)
    secure(certificate, 0o644)
    return certificate, key


def settings():
    default = {'block_page_title': 'Acesso bloqueado',
               'block_page_message': 'Este endereço foi bloqueado pela política de segurança da rede.'}
    try:
        raw = json.loads(POLICY.read_text())
        return {key: str(raw.get(key, value)) for key, value in default.items()}
    except (OSError, ValueError, TypeError):
        return default


class Handler(BaseHTTPRequestHandler):
    server_version = 'NanotechRouterBlockPage/1.0'

    def do_GET(self):
        self.respond(True)

    def do_HEAD(self):
        self.respond(False)

    def respond(self, include_body):
        if self.path.split('?', 1)[0] == '/logo.png' and LOGO.exists():
            body = LOGO.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'public, max-age=86400')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            if include_body:
                self.wfile.write(body)
            return
        policy = settings()
        host = valid_host(self.headers.get('Host', ''))
        title = html.escape(policy['block_page_title'])
        message = html.escape(policy['block_page_message'])
        target = html.escape(host)
        body = f'''<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>{title} - NanotechRouter</title><style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px;background:#f4f6f9;font-family:Arial,Helvetica,sans-serif;color:#212529}}
.card{{width:min(560px,100%);background:#fff;border-radius:18px;padding:clamp(26px,7vw,40px) clamp(22px,6vw,35px);text-align:center;box-shadow:0 10px 35px #0000001f}}
.logo{{width:150px;max-width:50vw;height:auto;margin-bottom:25px}}.logo-link{{display:inline-block}}
.icon{{width:76px;height:76px;margin:0 auto 20px;border-radius:50%;background:#dc3545;color:#fff;display:flex;align-items:center;justify-content:center;font-size:42px;font-weight:bold}}
h1{{margin:0 0 15px;font-size:clamp(1.65rem,7vw,28px)}}.description{{color:#6c757d;font-size:17px;line-height:1.5}}
.notice{{margin-top:25px;padding:16px;background:#f8f9fa;border-radius:10px;color:#555;font-size:14px;line-height:1.5;overflow-wrap:anywhere}}
.footer{{margin-top:28px;font-size:13px;color:#999}}.footer a{{color:#333;font-weight:bold;text-decoration:none}}.footer a:hover{{text-decoration:underline}}
</style></head><body><main class="card"><a class="logo-link" href="https://renansc.github.io/" target="_blank" rel="noopener noreferrer"><img class="logo" src="/logo.png" alt="Nanotec Criando Soluções"></a>
<div class="icon" aria-hidden="true">!</div><h1>{title}</h1><div class="description">{message}</div>
<div class="notice">Endereço solicitado:<br><strong>{target}</strong></div><div class="footer">Protegido por <a href="https://renansc.github.io/" target="_blank" rel="noopener noreferrer">Nanotec Criando Soluções</a></div>
</main></body></html>'''.encode()
        self.send_response(451)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, template, *args):
        print('%s - %s' % (self.client_address[0], template % args), flush=True)


def tls_context():
    certificate, key = certificate_for('blocked.nanotechrouter.local')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    cache = {}
    lock = threading.Lock()

    def choose(connection, hostname, original):
        host = valid_host(hostname)
        with lock:
            selected = cache.get(host)
            if selected is None:
                cert, cert_key = certificate_for(host)
                selected = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                selected.minimum_version = ssl.TLSVersion.TLSv1_2
                selected.load_cert_chain(cert, cert_key)
                if len(cache) >= MAX_CERTIFICATES:
                    cache.pop(next(iter(cache)))
                cache[host] = selected
        connection.context = selected
    context.set_servername_callback(choose)
    return context


def serve():
    ensure_ca()
    http = ThreadingHTTPServer((BIND, HTTP_PORT), Handler)
    https = ThreadingHTTPServer((BIND, HTTPS_PORT), Handler)
    https.socket = tls_context().wrap_socket(https.socket, server_side=True)
    stop = threading.Event()

    def shutdown(signum, frame):
        stop.set()
        threading.Thread(target=http.shutdown, daemon=True).start()
        threading.Thread(target=https.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (http, https)]
    for thread in threads:
        thread.start()
    stop.wait()
    http.server_close()
    https.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--init-ca', action='store_true')
    args = parser.parse_args()
    if args.init_ca:
        print(ensure_ca()[0])
    else:
        serve()
