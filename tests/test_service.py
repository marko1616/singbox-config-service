import base64
import copy
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

import cli
import service as m

ROOT = Path(__file__).resolve().parents[1]


def settings():
    s = json.loads((ROOT / 'templates/private-config/settings.json').read_bytes())
    s.update(api_key='test_' + 'x' * 40, subscription_url='https://subscription.example.invalid/feed')
    s['wireguard'].update(address='10.77.0.2/32', private_key=base64.b64encode(bytes(range(32))).decode(),
                          peer_public_key=base64.b64encode(bytes(range(1, 33))).decode(), endpoint='wg.example.invalid')
    s['own_hy2'].update(server='hk.example.invalid', password='synthetic-password',
                        tls={'enabled': True, 'server_name': 'hk.example.invalid'})
    s['direct'] = json.loads((ROOT / 'data/direct.json').read_bytes())
    s['singapore'] = {'domain': ['exact.example.invalid'], 'domain_suffix': ['sg.example.invalid'],
                      'ip_cidr': ['203.0.113.0/24', '2001:db8::/32']}
    return s


def nodes():
    return [{'type': 'socks', 'tag': tag, 'server': '127.0.0.1', 'server_port': 9, 'version': '5'}
            for tag in ['HK a', 'HK b', 'HK c', 'SG a', 'SG b']]


def no_check(p):
    pass


class SelectionTests(unittest.TestCase):
    def test_all_candidates_measured_topk_sorted_no_backup_competition(self):
        s = settings(); s['top_k'] = 2
        seen = []
        def measure(n, s):
            seen.append(n['tag'])
            return {'hk-001': 90, 'hk-002': 10, 'hk-003': 30, 'sg-001': 20, 'sg-002': 15}[n['tag']]
        c, info = m.select(nodes(), s, measure, no_check)
        self.assertEqual(len(seen), 5)
        self.assertEqual([n['tag'] for n in c['hk']], ['hk-002', 'hk-003'])
        self.assertFalse(info['hk_fallback'])

    def test_partial_failure_does_not_trigger_backup(self):
        c, info = m.select(nodes(), settings(), lambda n, s: 3 if n['tag'] in ['hk-002', 'sg-001'] else None, no_check)
        self.assertEqual(c['hk'][0]['tag'], 'hk-002')
        self.assertFalse(info['hk_fallback'])

    def test_all_hk_failed_backup_then_recovery(self):
        c, info = m.select(nodes(), settings(), lambda n, s: None if n['tag'].startswith('hk-0') else 12, no_check)
        self.assertTrue(info['hk_fallback'])
        self.assertEqual(c['hk'][0]['tag'], 'hk-own-hy2')
        c, info = m.select(nodes(), settings(), lambda n, s: 20, no_check)
        self.assertFalse(info['hk_fallback'])
        self.assertNotIn('hk-own-hy2', [n['tag'] for n in c['hk']])

    def test_no_sg_no_own_or_absent_hk_fail_closed(self):
        for values, fn, error in [
            (nodes(), lambda n, s: None, 'singapore_unavailable'),
            (nodes(), lambda n, s: 2 if n['tag'].startswith('sg') else None, 'hong_kong_unavailable'),
            (nodes()[3:], lambda n, s: 2, 'missing_region')]:
            with self.subTest(error=error), self.assertRaisesRegex(m.Invalid, error):
                m.select(values, settings(), fn, no_check)

    def test_candidate_limit_refuses_truncation(self):
        s = settings(); s['max_candidates'] = 2
        with self.assertRaisesRegex(m.Invalid, 'candidate_limit'):
            m.select(nodes(), s, lambda n, s: self.fail('must not probe'), no_check)


class ConfigTests(unittest.TestCase):
    def test_validate_rejects_placeholders_ipv4_endpoint_bad_key(self):
        with self.assertRaises(m.Invalid):
            m.validate(json.loads((ROOT / 'templates/private-config/settings.json').read_bytes()))
        s = settings(); m.validate(s)
        s['wireguard']['endpoint'] = '192.0.2.1'
        with self.assertRaises(m.Invalid): m.validate(s)
        s = settings(); s['api_key'] = 'weak'
        with self.assertRaises(m.Invalid): m.validate(s)

    def test_route_order_or_semantics_and_ipv6_only(self):
        s = settings()
        c, _ = m.select(nodes(), s, lambda n, s: 1, no_check)
        p = m.build_profile(s, c)
        r = p['route']['rules']
        self.assertEqual([x.get('outbound') for x in r[1:4]], ['wg-ipv6', 'direct', 'sg'])
        self.assertEqual(p['route']['final'], 'hk')
        direct = p['route']['rule_set'][0]
        self.assertEqual(direct['tag'], 'force-direct')
        self.assertTrue(all(len(x) == 1 for x in direct['rules']))
        self.assertNotIn('geosite', json.dumps(p))
        w = p['endpoints'][0]
        self.assertEqual(w['domain_resolver']['strategy'], 'ipv6_only')
        self.assertEqual(w['peers'][0]['allowed_ips'], [m.OVERLAY])
        self.assertFalse(any(n['type'] == 'urltest' for n in p['outbounds']))
        self.assertNotIn('hk-own-hy2', json.dumps(p))

    def test_real_core_normal_fallback_empty_whitelist(self):
        self.assertTrue(Path(m.CORE).is_file(), 'real 1.14.2 core required')
        for backup in (False, True):
            for empty in (False, True):
                s = settings()
                if empty: s['singapore'] = {'ip_cidr': [], 'domain': [], 'domain_suffix': []}
                c, _ = m.select(nodes(), s, lambda n, s: None if backup and n['tag'].startswith('hk-0') else 3)
                m.check_profile(m.build_profile(s, c))

    def test_real_converter_uri_and_base64(self):
        text = b'trojan://synthetic@node.example.invalid:443?sni=node.example.invalid#HK-test\ntrojan://synthetic@other.example.invalid:443?sni=other.example.invalid#SG-test\n'
        for data in (text, base64.b64encode(text)):
            result = m.convert(data)
            self.assertEqual(len(result), 2)
            self.assertEqual({n['type'] for n in result}, {'trojan'})
            m.check_profile({'outbounds': result, 'dns': {'servers': [{'type': 'local', 'tag': 'local'}]},
                              'route': {'default_domain_resolver': 'local'}})
        with self.assertRaises(Exception): m.convert(b'not a subscription')


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.s = settings()
        self.settings = self.root / 'settings.json'
        m.atomic_write(self.settings, m.encode(self.s))
        self.p = m.Publisher(self.settings, self.root / 'snapshot.json', fetcher=lambda s: b'fixture',
                             converter=lambda b: nodes(), measure=lambda n, s: 1, checker=m.check_profile)

    def test_refresh_failure_and_restart_preserve_valid_snapshot(self):
        self.assertTrue(self.p.refresh(), self.p.status())
        old = self.p.data
        def fail(s): raise ValueError('SECRET_SUBSCRIPTION')
        self.p.fetcher = fail
        self.assertFalse(self.p.refresh())
        self.assertEqual(self.p.data, old)
        self.assertNotIn('SECRET', json.dumps(self.p.status()))
        q = m.Publisher(self.settings, self.p.snapshot); q.restore()
        self.assertEqual(q.data, old)
        self.assertEqual(self.p.snapshot.stat().st_mode & 0o777, 0o600)

    def test_invalid_then_fixed_settings_recover(self):
        m.atomic_write(self.settings, b'{}')
        self.assertFalse(self.p.refresh())
        self.assertFalse(self.p.status()['ready'])
        m.atomic_write(self.settings, m.encode(self.s))
        self.assertTrue(self.p.refresh(), self.p.status())

    def test_changed_settings_do_not_restore_old_snapshot(self):
        self.assertTrue(self.p.refresh())
        self.s['api_key'] = 'y' * 40
        m.atomic_write(self.settings, m.encode(self.s))
        q = m.Publisher(self.settings, self.p.snapshot); q.restore()
        self.assertIsNone(q.data)

    def test_http_auth_get_post_not_ready_and_key_rotation(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), m.handler_for(self.p))
        t = threading.Thread(target=server.serve_forever, daemon=True); t.start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        base = f'http://127.0.0.1:{server.server_port}'
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def request(path, key=None, method='GET'):
            req = urllib.request.Request(base + path, headers={'Authorization': 'Bearer ' + key} if key else {}, method=method)
            try: response = opener.open(req, timeout=2)
            except urllib.error.HTTPError as e: response = e
            with response: return response.status, response.read()
        self.assertEqual(request('/api/config')[0], 401)
        self.assertEqual(request('/api/config', self.s['api_key'])[0], 503)
        self.assertEqual(json.loads(request('/healthz')[1])['ready'], False)
        self.assertTrue(self.p.refresh())
        for url, key in [('/api/config', self.s['api_key']), ('/api/config?key=' + self.s['api_key'], None)]:
            status, data = request(url, key)
            self.assertEqual(status, 200); self.assertEqual(data, self.p.data)
        self.assertEqual(request('/api/config', self.s['api_key'], 'POST')[0], 405)
        old = self.s['api_key']; self.s['api_key'] = 'new_' + 'y' * 40
        m.atomic_write(self.settings, m.encode(self.s))
        self.assertEqual(request('/api/config', old)[0], 401)
        self.assertEqual(request('/api/config', self.s['api_key'])[0], 200)


class RenderTests(unittest.TestCase):
    def test_real_mount_shape_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            shutil.copytree(ROOT / 'templates', r / 'templates')
            shutil.copytree(ROOT / 'data', r / 'data')
            target = cli.initialize(r)
            with self.assertRaises(FileExistsError): cli.initialize(r)
            with self.assertRaises(m.Invalid): cli.render(r)
            s = settings(); s['direct'] = {'domain': ['extra.example.invalid'], 'domain_suffix': [], 'ip_cidr': []}
            m.atomic_write(target, m.encode(s))
            out = cli.render(r)
            result = m.load_settings(out)
            self.assertIn('extra.example.invalid', result['direct']['domain'])
            self.assertEqual(len(result['direct']['ip_cidr']), 35)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            self.assertEqual(out.parent.stat().st_mode & 0o777, 0o700)
            self.assertIn(f'LOCAL_UID={os.getuid()}', (r / '.env').read_text())
            p = m.Publisher(out, r / 'state/snapshot.json', fetcher=lambda s: b'x',
                            converter=lambda b: nodes(), measure=lambda n, s: 1)
            self.assertTrue(p.refresh(), p.status())


if __name__ == '__main__':
    unittest.main()
