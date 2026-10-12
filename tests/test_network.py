"""Loopback-only runtime checks: genuine sing-box outbound and routing, no real nodes."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import service as m
from test_service import settings


class Proxy(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        line = self.rfile.readline()
        if not line:
            return
        while self.rfile.readline() not in (b'\r\n', b'\n', b''):
            pass
        self.server.hits.append(line)
        if line.startswith(b'CONNECT '):
            self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n'); self.wfile.flush()
            line = self.rfile.readline()
            while self.rfile.readline() not in (b'\r\n', b'\n', b''):
                pass
        if line:
            body = self.server.label.encode()
            self.wfile.write(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


class LocalNetworkTests(unittest.TestCase):
    def server(self, label):
        server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Proxy)
        server.daemon_threads = True
        server.hits, server.label = [], label
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        return server

    def node(self, server, tag):
        return {'type': 'http', 'tag': tag, 'server': '127.0.0.1', 'server_port': server.server_address[1]}

    def test_proxyonly_mixed_inbound_accepts_http_and_socks(self):
        hk, sg = self.server('HK'), self.server('SG')
        s = settings()
        chosen = {'hk': [self.node(hk, 'hk-node')], 'sg': [self.node(sg, 'sg-node')]}
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        p = m.variant_profile(m.build_profile(s, chosen), 'global', False,
                              m.proxy_options({'port': [str(port)]}))
        p['dns']['servers'] = [{'type': 'local', 'tag': tag} for tag in ['bootstrap', 'dns-hk', 'dns-sg']]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'runtime.json'; path.write_bytes(m.encode(p))
            proc = subprocess.Popen([m.CORE, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if proc.poll() is not None:
                        self.fail(proc.stderr.read().decode())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1): break
                    except OSError: time.sleep(.03)
                else: self.fail('core did not start')
                for proxy in (f'http://127.0.0.1:{port}', f'socks5h://127.0.0.1:{port}'):
                    result = subprocess.run(['curl', '--silent', '--show-error', '--fail', '--proxy', proxy,
                                             '--noproxy', '', '--max-time', '3',
                                             f'http://127.0.0.3:{hk.server_address[1]}/test'],
                                            capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, (proxy, result.stderr))
                    self.assertEqual(result.stdout, b'HK')
            finally:
                proc.terminate(); proc.wait(timeout=3); proc.stderr.close()

    def test_actual_probe_uses_outbound_despite_no_proxy(self):
        proxy = self.server('proxied')
        with patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*', 'HTTPS_PROXY': 'http://127.0.0.1:1'}):
            elapsed = m.probe(self.node(proxy, 'node'), settings(),
                              url='http://unresolvable.example.invalid/test', expected_status=200)
        self.assertIsNotNone(elapsed)
        self.assertGreater(elapsed, 0)
        self.assertEqual(len(proxy.hits), 1)
        self.assertIn(b'unresolvable.example.invalid', proxy.hits[0])
        bad = self.node(proxy, 'bad'); bad['server_port'] = 1
        self.assertIsNone(m.probe(self.node(proxy, 'node'), settings(),
                                  url='http://unresolvable.example.invalid/test'))
        self.assertIsNone(m.probe(bad, settings(), url='http://unresolvable.example.invalid/test',
                                  expected_status=200))

    def test_probe_rejects_wrong_body_length_and_digest(self):
        proxy = self.server('proxied')
        node = self.node(proxy, 'node')
        url = 'http://unresolvable.example.invalid/test'
        digest = hashlib.sha256(b'proxied').hexdigest()
        with self.assertLogs(m.LOG, level='DEBUG') as captured:
            self.assertIsNotNone(m._http_probe(node, settings(), m.CORE, url, 200, 7, digest))
            self.assertIsNone(m._http_probe(node, settings(), m.CORE, url, 200, 8, digest))
            self.assertIsNone(m._http_probe(node, settings(), m.CORE, url, 200, 7, '0' * 64))
        logs = '\n'.join(captured.output)
        self.assertIn('tag=node@' + m.node_fingerprint(node), logs)
        self.assertIn('result=ok http=200 bytes=7', logs)
        self.assertIn('result=body_size http=200 bytes=7', logs)
        self.assertIn('result=body_sha256 http=200 bytes=7', logs)

    def test_actual_route_direct_precedes_sg_then_hk(self):
        direct, sg, hk = self.server('DIRECT'), self.server('SG'), self.server('HK')
        s = settings()
        s['direct'] = {'ip_cidr': ['127.0.0.1/32'], 'domain': ['direct.example.invalid'], 'domain_suffix': []}
        s['singapore'] = {'ip_cidr': ['127.0.0.1/32', '127.0.0.2/32'],
                         'domain': ['sg.example.invalid'], 'domain_suffix': [],
                         'domain_regex': [r'^sg[0-9]+\.example\.invalid$']}
        chosen = {'hk': [self.node(hk, 'hk-node')], 'sg': [self.node(sg, 'sg-node')]}
        p = m.build_profile(s, chosen)
        # Only test harness adaptations: replace Android TUN by a local HTTP inbound;
        # replace external DNS/WG endpoint with isolated loopback equivalents.
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        p['inbounds'] = [{'type': 'http', 'listen': '127.0.0.1', 'listen_port': port}]
        p['endpoints'][0]['peers'][0]['address'] = '::1'
        p['endpoints'][0]['peers'][0]['persistent_keepalive_interval'] = 0
        p['dns']['servers'] = [{'type': 'local', 'tag': tag} for tag in ['bootstrap', 'dns-hk', 'dns-sg']]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'runtime.json'; path.write_bytes(m.encode(p))
            proc = subprocess.Popen([m.CORE, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if proc.poll() is not None:
                        self.fail(proc.stderr.read().decode())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1): break
                    except OSError: time.sleep(.03)
                else: self.fail('core did not start')
                for host, expected in [('127.0.0.1', 'DIRECT'), ('127.0.0.2', 'SG'), ('127.0.0.3', 'HK'),
                                       ('sg.example.invalid', 'SG'), ('sg7.example.invalid', 'SG')]:
                    result = subprocess.run(['curl', '--silent', '--fail', '--proxy', f'http://127.0.0.1:{port}',
                                             '--noproxy', '', '--max-time', '3',
                                             f'http://{host}:{direct.server_address[1]}/test'], capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, (host, result.stderr))
                    self.assertEqual(result.stdout.decode(), expected)
            finally:
                proc.terminate(); proc.wait(timeout=3); proc.stderr.close()


if __name__ == '__main__':
    unittest.main()
