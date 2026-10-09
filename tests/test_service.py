import base64
import copy
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

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
    def test_node_fingerprint_is_stable_across_order_and_tag_changes(self):
        original = {'type': 'vmess', 'tag': 'HK first', 'server': 'node.example.invalid',
                    'server_port': 443, 'uuid': 'synthetic-private-uuid'}
        reordered = {'uuid': 'synthetic-private-uuid', 'server_port': 443,
                     'server': 'node.example.invalid', 'tag': 'HK renamed', 'type': 'vmess'}
        changed = dict(original, server_port=8443)
        self.assertEqual(m.node_fingerprint(original), m.node_fingerprint(reordered))
        self.assertNotEqual(m.node_fingerprint(original), m.node_fingerprint(changed))
        self.assertRegex(m.node_fingerprint(original), r'^[0-9a-f]{12}$')
        self.assertNotIn('synthetic-private-uuid', m.node_log_tag(original))

    def test_all_candidates_measured_topk_sorted_no_backup_competition(self):
        s = settings(); s['top_k'] = 2
        seen = []
        def measure(n, s):
            seen.append(n['tag'])
            return {'hk-001': 90, 'hk-002': 10, 'hk-003': 30, 'sg-001': 20, 'sg-002': 15}[n['tag']]
        c, info = m.select(nodes(), s, measure, no_check)
        self.assertEqual(len(seen), 10)  # Google and CacheFly stages for five candidates.
        self.assertNotIn('hk-own-hy2', seen)
        self.assertEqual([n['tag'] for n in c['hk']], ['hk-002', 'hk-003', 'hk-own-hy2'])
        self.assertFalse(info['hk_fallback'])
        self.assertEqual(info['counts']['hk'], {'tested': 3, 'healthy': 3, 'retained': 3})
        profile = m.build_profile(s, c)
        hk = next(n for n in profile['outbounds'] if n['tag'] == 'hk')
        self.assertEqual(hk['default'], 'hk-002')
        self.assertEqual(hk['outbounds'], ['hk-002', 'hk-003', 'hk-own-hy2'])

    def test_partial_failure_does_not_trigger_backup(self):
        c, info = m.select(nodes(), settings(), lambda n, s: 3 if n['tag'] in ['hk-002', 'sg-001'] else None, no_check)
        self.assertEqual(c['hk'][0]['tag'], 'hk-002')
        self.assertFalse(info['hk_fallback'])

    def test_cachefly_weight_changes_order_and_rejects_failed_download(self):
        s = settings(); s['top_k'] = 1
        google = {'hk-001': 100, 'hk-002': 150, 'hk-003': 300,
                  'sg-001': 100, 'sg-002': 150}
        download = {'hk-001': 800, 'hk-002': 100, 'hk-003': 10,
                    'sg-001': None, 'sg-002': 100}
        seen = []
        def measure_download(node, settings_arg):
            seen.append(node['tag'])
            return download[node['tag']]
        chosen, info = m.select(nodes(), s, lambda n, s: google[n['tag']], no_check,
                                measure_download=measure_download)
        self.assertEqual(chosen['hk'][0]['tag'], 'hk-002')
        self.assertEqual(chosen['sg'][0]['tag'], 'sg-002')
        self.assertEqual(info['counts']['sg']['healthy'], 1)
        self.assertEqual(set(seen), set(download))

    def test_debug_explains_every_candidate_decision(self):
        s = settings(); s['top_k'] = 1
        candidates = nodes() + [
            {'type': 'socks', 'tag': 'HK d', 'server': 'node.example.invalid',
             'server_port': 1080, 'version': '5'},
            {'type': 'socks', 'tag': 'HK e', 'server': 'other.example.invalid',
             'server_port': 1080, 'version': '5'}]
        google = {'hk-001': 100, 'hk-002': 150, 'hk-003': None, 'hk-004': 400,
                  'hk-005': 500,
                  'sg-001': 100, 'sg-002': 200}
        download = {'hk-001': 500, 'hk-002': 100, 'hk-004': 200,
                    'sg-001': None, 'sg-002': 100}
        with self.assertLogs(m.LOG, level='DEBUG') as captured:
            chosen, _ = m.select(candidates, s, lambda n, s: google[n['tag']], no_check,
                                 measure_download=lambda n, s: download[n['tag']])
        self.assertEqual([n['tag'] for n in chosen['hk'][:1]], ['hk-002'])
        self.assertEqual([n['tag'] for n in chosen['sg']], ['sg-002'])
        logs = '\n'.join(captured.output)
        by_tag = {n['tag']: m.node_log_tag(n) for n in chosen['hk'] + chosen['sg']}
        # The original node config, not the selected set, supplies identifiers
        # for candidates excluded from the final profile.
        for tag, node in [('hk-001', candidates[0]), ('hk-002', candidates[1]),
                          ('hk-003', candidates[2]), ('sg-001', candidates[3]),
                          ('sg-002', candidates[4]), ('hk-004', candidates[5]),
                          ('hk-005', candidates[6])]:
            by_tag[tag] = tag + '@' + m.node_fingerprint(node)
        self.assertIn('tag=' + by_tag['hk-004'] + ' endpoint="node.example.invalid" port=1080', logs)
        for tag, result in [('hk-001', 'top_k_excluded'), ('hk-002', 'selected'),
                            ('hk-003', 'google_failed'), ('hk-005', 'not_shortlisted'),
                            ('sg-001', 'cachefly_failed'), ('sg-002', 'selected')]:
            self.assertIn('tag=' + by_tag[tag] + ' result=' + result, logs)
        self.assertIn('cachefly tag=' + by_tag['hk-002'] +
                      ' result=ok ms=100 score_ms=130.000', logs)
        self.assertNotIn('synthetic-private-uuid', logs)

    def test_all_hk_failed_backup_then_recovery(self):
        c, info = m.select(nodes(), settings(), lambda n, s: None if n['tag'].startswith('hk-0') else 12, no_check)
        self.assertTrue(info['hk_fallback'])
        self.assertEqual(c['hk'][0]['tag'], 'hk-own-hy2')
        c, info = m.select(nodes(), settings(), lambda n, s: 20, no_check)
        self.assertFalse(info['hk_fallback'])
        self.assertEqual(c['hk'][-1]['tag'], 'hk-own-hy2')
        self.assertNotEqual(c['hk'][0]['tag'], 'hk-own-hy2')

    def test_missing_region_policy(self):
        hk_only = [n for n in nodes() if n['tag'].startswith('HK')]
        sg_only = [n for n in nodes() if n['tag'].startswith('SG')]
        # No Singapore candidates: fail closed, Singapore has no backup.
        with self.assertRaisesRegex(m.Invalid, 'singapore_unavailable'):
            m.select(hk_only, settings(), lambda n, s: 2, no_check)
        # No all-failed/failed SG: fail closed too.
        with self.assertRaisesRegex(m.Invalid, 'singapore_unavailable'):
            m.select(nodes(), settings(), lambda n, s: None, no_check)
        with self.assertRaisesRegex(m.Invalid, 'hong_kong_unavailable'):
            m.select(nodes(), settings(), lambda n, s: 2 if n['tag'].startswith('sg') else None, no_check)

    def test_no_hong_kong_candidates_uses_backup(self):
        sg_only = [n for n in nodes() if n['tag'].startswith('SG')]
        chosen, info = m.select(sg_only, settings(), lambda n, s: 2, no_check)
        self.assertTrue(info['hk_fallback'])
        self.assertEqual([n['tag'] for n in chosen['hk']], ['hk-own-hy2'])
        self.assertEqual(info['counts']['hk']['retained'], 1)
        self.assertEqual(info['counts']['hk']['tested'], 0)
        # Backup unreachable as well: still fail closed.
        with self.assertRaisesRegex(m.Invalid, 'hong_kong_unavailable'):
            m.select(sg_only, settings(),
                     lambda n, s: None if n['tag'] == 'hk-own-hy2' else 2, no_check)

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
        self.assertIn('hk-own-hy2', json.dumps(p))

    def test_real_core_normal_fallback_empty_whitelist(self):
        self.assertTrue(Path(m.CORE).is_file(), 'real 1.14.2 core required')
        for backup in (False, True):
            for empty in (False, True):
                s = settings()
                if empty: s['singapore'] = {'ip_cidr': [], 'domain': [], 'domain_suffix': []}
                c, _ = m.select(nodes(), s, lambda n, s: None if backup and n['tag'].startswith('hk-0') else 3)
                m.check_profile(m.build_profile(s, c))

    def test_bare_wireguard_address_is_normalized_and_accepted(self):
        # Field regression: sing-box netip.ParsePrefix needs an explicit mask,
        # while a bare host address used to be emitted verbatim.
        s = settings(); s['wireguard']['address'] = '10.77.0.5'
        m.validate(s)
        self.assertEqual(s['wireguard']['address'], '10.77.0.5/32')
        chosen, _ = m.select(nodes(), s, lambda n, s: 1, no_check)
        profile = m.build_profile(s, chosen)
        self.assertEqual(profile['endpoints'][0]['address'], ['10.77.0.5/32'])
        m.check_profile(profile)
        # A non-host mask is still refused, and normalisation is idempotent.
        s2 = settings(); s2['wireguard']['address'] = '10.77.0.5/24'
        with self.assertRaisesRegex(m.Invalid, 'wireguard_address_must_be_host_32'):
            m.validate(s2)
        m.validate(s)
        self.assertEqual(s['wireguard']['address'], '10.77.0.5/32')

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


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "runtime").mkdir(); (self.root / "state").mkdir()
        m.atomic_write(self.root / "runtime/settings.json", b"{}\n")
        m.atomic_write(self.root / ".env", b"LOCAL_UID=1\nLOCAL_GID=1\n")

    def test_deploy_requires_render(self):
        empty = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, empty, True)
        with self.assertRaisesRegex(m.Invalid, "render_required"):
            cli.deploy("up", empty, run=lambda *a, **k: self.fail("must not run compose"))

    def test_deploy_argv_per_action(self):
        expected = {"build": ["build"], "up": ["up", "--detach"], "down": ["down"],
                    "logs": ["logs", "--tail", "100"],
                    "logs-follow": ["logs", "--follow", "--tail", "100"], "status": ["ps"]}
        for action, extra in expected.items():
            with self.subTest(action=action):
                calls = []
                with patch.object(cli, "compose_prefix", lambda root=None: (["docker", "compose", "-f", "x.yml"], False)):
                    cli.deploy(action, self.root, run=lambda argv, **k: calls.append((argv, k.get("env"))))
                argv, env = calls[0]
                self.assertEqual(argv, ["docker", "compose", "-f", "x.yml"] + extra)
                self.assertIsInstance(env, dict)

    def test_child_environment_normalizes_lowercase_proxy(self):
        with patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:2", "no_proxy": "localhost"}, clear=True):
            env = cli._child_environment()
            self.assertEqual(env["HTTPS_PROXY"], "http://proxy.invalid:2")
            self.assertEqual(env["NO_PROXY"], "localhost")
            self.assertEqual(cli.proxy_environment(), {"HTTPS_PROXY": "http://proxy.invalid:2", "NO_PROXY": "localhost"})

    def test_runtime_log_level_is_normalized_validated_and_forwarded(self):
        with patch.dict(os.environ, {"singbox_log_level": "debug"}, clear=True):
            self.assertEqual(cli.log_level_environment(), {"SINGBOX_LOG_LEVEL": "DEBUG"})
            self.assertEqual(cli._child_environment()["SINGBOX_LOG_LEVEL"], "DEBUG")
            calls = []
            with patch.object(cli, "compose_prefix", lambda root=None: (["docker", "compose"], False)):
                cli.deploy("up", self.root, run=lambda argv, **kw: calls.append(kw["env"]))
            self.assertEqual(calls[0]["SINGBOX_LOG_LEVEL"], "DEBUG")
        with patch.dict(os.environ, {"SINGBOX_LOG_LEVEL": "verbose"}, clear=True):
            with self.assertRaisesRegex(m.Invalid, "log_level"):
                cli.deploy("up", self.root, run=lambda *a, **kw: self.fail("must not run"))

    def test_deploy_rejects_unknown_action(self):
        with self.assertRaisesRegex(m.Invalid, "unknown_action"):
            cli.deploy("restart", self.root, run=lambda *a, **k: self.fail("must not run compose"))

    def test_compose_prefix_prefers_plain_then_sudo_with_proxy(self):
        with patch.object(cli.shutil, "which", lambda name: "/usr/bin/" + name), \
             patch.object(cli, "_daemon_reachable", lambda argv: argv is not None and argv[0] == "sudo"), \
             patch.object(cli, "_sudo_ready", lambda: True), \
             patch.dict(os.environ, {"http_proxy": "http://proxy.invalid:1", "no_proxy": "localhost"}, clear=True):
            prefix, elevated = cli.compose_prefix(self.root)
        self.assertTrue(elevated)
        self.assertEqual(prefix[:2], ["sudo", "--preserve-env=HTTP_PROXY,NO_PROXY"])
        self.assertIn("docker", prefix)
        self.assertNotIn("http_proxy", prefix)

    def test_sudo_preserves_runtime_log_level(self):
        with patch.object(cli.shutil, "which", lambda name: "/usr/bin/" + name), \
             patch.object(cli, "_daemon_reachable", lambda argv: argv is not None and argv[0] == "sudo"), \
             patch.object(cli, "_sudo_ready", lambda: True), \
             patch.dict(os.environ, {"SINGBOX_LOG_LEVEL": "DEBUG"}, clear=True):
            prefix, elevated = cli.compose_prefix(self.root)
        self.assertTrue(elevated)
        self.assertEqual(prefix[:2], ["sudo", "--preserve-env=SINGBOX_LOG_LEVEL"])

    def test_compose_prefix_unavailable_and_unreachable(self):
        with patch.object(cli.shutil, "which", lambda name: None):
            with self.assertRaisesRegex(m.Invalid, "compose_unavailable"):
                cli.compose_prefix(self.root)
        with patch.object(cli.shutil, "which", lambda name: "/usr/bin/" + name), \
             patch.object(cli, "_daemon_reachable", lambda argv: False), \
             patch.object(cli, "_sudo_ready", lambda: False):
            with self.assertRaisesRegex(m.Invalid, "docker_daemon_unreachable"):
                cli.compose_prefix(self.root)

    def test_cli_is_english_only_and_errors_are_actionable(self):
        source = (ROOT / "cli.py").read_text()
        self.assertFalse(re.search(r"[\u4e00-\u9fff]", source), "cli.py must contain no CJK text")
        self.assertIn("32-128", cli.explain("api_key_format"))
        self.assertEqual(cli.explain("not_a_known_code"), "not_a_known_code")
        for label, action, prompt in cli.MENU:
            self.assertFalse(re.search(r"[\u4e00-\u9fff]", (label or "") + (prompt or "")))
        self.assertEqual({a for _, a, _ in cli.MENU} - {None},
                         {"init", "render", "build", "up", "down", "logs", "logs-follow", "status", "diagnose"})

    def test_diagnose_action_argv(self):
        calls = []
        with patch.object(cli, "compose_prefix", lambda root=None: (["docker", "compose", "-f", "x.yml"], False)):
            cli.deploy("diagnose", self.root, run=lambda argv, **k: calls.append(argv))
        self.assertEqual(calls[0], ["docker", "compose", "-f", "x.yml", "exec", "config",
                                    "python3", "/app/service.py", "diagnose"])


class DiagnosticsTests(unittest.TestCase):
    def test_tool_failure_is_logged_and_nothing_is_written_to_disk(self):
        # On request, host files are gone: diagnostics belong in the container log.
        self.assertFalse(hasattr(m, "DEBUG_LOG"))
        self.assertFalse(hasattr(m, "FAILED_PROFILE"))
        with self.assertLogs(m.LOG, level="ERROR") as captured:
            with self.assertRaisesRegex(m.Invalid, "tool_failed"):
                m.checked(["/bin/sh", "-c", "echo NODE-DETAIL-EXAMPLE >&2; exit 3"])
        text = "\n".join(captured.output)
        self.assertIn("tool failed", text)
        self.assertIn("NODE-DETAIL-EXAMPLE", text)

    def test_publisher_error_is_static_while_local_log_has_detail(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        s = settings()
        sp = root / "settings.json"; m.atomic_write(sp, m.encode(s))
        def checker(profile):
            m.checked(["/bin/sh", "-c", "echo DETAIL-ONLY-IN-LOGS >&2; exit 2"])
        p = m.Publisher(sp, root / "snapshot.json", fetcher=lambda s: b"sub",
                        converter=lambda b: nodes(), measure=lambda n, s: 1, checker=checker)
        with self.assertLogs(m.LOG, level="ERROR") as captured:
            self.assertFalse(p.refresh())
        self.assertEqual(p.status()["error"], "tool_failed")
        self.assertNotIn("DETAIL-ONLY-IN-LOGS", json.dumps(p.status()))
        self.assertIn("DETAIL-ONLY-IN-LOGS", "\n".join(captured.output))
        self.assertFalse((root / "snapshot.json").exists())

    def test_register_secrets_covers_manual_credentials(self):
        s = settings()
        s["manual_nodes"] = ["hysteria2://sup3r-s3cret-pw@hk.example.invalid:443#HK own"]
        m.validate(s)
        self.assertIn("sup3r-s3cret-pw", m.SECRETS)
        self.assertNotIn("sup3r-s3cret-pw", m.scrub("auth sup3r-s3cret-pw used"))

    def test_scrub_hides_subscription_url_and_key(self):
        s = settings()
        text = "URLError: "
        text += s["subscription_url"] + " with key " + s["api_key"]
        out = m.scrub(text, s)
        self.assertNotIn(s["subscription_url"], out)
        self.assertNotIn(s["api_key"], out)
        self.assertIn("<redacted>", out)

    def test_refresh_records_network_error_without_leaking_url(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        s = settings()
        sp = root / "settings.json"; m.atomic_write(sp, m.encode(s))
        def bad_fetch(settings_arg):
            raise urllib.error.URLError("timed out fetching " + settings_arg["subscription_url"])
        p = m.Publisher(sp, root / "snapshot.json", fetcher=bad_fetch, converter=lambda b: nodes(),
                        measure=lambda n, s: 1, checker=m.check_profile)
        with self.assertLogs(m.LOG, level="ERROR") as captured:
            self.assertFalse(p.refresh())
        self.assertEqual(p.status()["error"], "operation_failed")
        self.assertEqual(p.status()["stage"], "fetch")
        text = "\n".join(captured.output)
        self.assertIn("URLError", text)
        self.assertIn("stage=fetch", text)
        self.assertNotIn(s["subscription_url"], text)
        self.assertNotIn(s["api_key"], text)

    def test_diagnose_report_hides_secrets_and_reports_fetch(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        s = settings()
        sp = root / "settings.json"; m.atomic_write(sp, m.encode(s))
        def bad_fetch(settings_arg):
            raise urllib.error.URLError("name resolution failed for " + settings_arg["subscription_url"])
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy-should-not-appear:1"}):
            text = m.diagnose_report(sp, fetcher=bad_fetch)
        self.assertIn("fetch failed", text)
        self.assertIn("URLError", text)
        self.assertIn("HTTPS_PROXY", text)
        self.assertNotIn("proxy-should-not-appear", text)
        self.assertNotIn(s["subscription_url"], text)
        self.assertIn("docker compose logs", text)

    def test_diagnose_report_includes_settings_error_without_values(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        sp = root / "settings.json"
        m.atomic_write(sp, b'{"api_key": "placeholder-value"}')
        text = m.diagnose_report(sp)
        self.assertIn("settings unusable", text)
        self.assertNotIn("placeholder-value", text)

    def test_file_based_diagnostics_are_fully_removed(self):
        for gone in ("DEBUG_LOG", "FAILED_PROFILE", "record_failure", "check_profile_or_record"):
            self.assertFalse(hasattr(m, gone), gone + " should be gone")

    def test_final_check_failure_is_static_and_logged(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        s = settings()
        sp = root / "settings.json"; m.atomic_write(sp, m.encode(s))
        def reject_on_final(profile):
            # select() checks the candidate list first; only the final profile carries rule_set.
            if "rule_set" in profile.get("route", {}):
                raise m.Invalid("tool_failed")
        p = m.Publisher(sp, root / "snapshot.json", fetcher=lambda s: b"sub",
                        converter=lambda b: nodes(), measure=lambda n, s: 1, checker=reject_on_final)
        with self.assertLogs(m.LOG, level="ERROR") as captured:
            self.assertFalse(p.refresh())
        self.assertEqual(p.status()["error"], "tool_failed")
        self.assertIsNone(p.status()["selection"])
        self.assertIn("stage=check", "\n".join(captured.output))
        self.assertFalse((root / "snapshot.json").exists(), "a rejected profile must not be published")
        self.assertEqual(sorted(p.name for p in root.iterdir()), ["settings.json"],
                         "diagnostics must not create host files")

    def test_success_is_logged_with_counts_and_no_secrets(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        s = settings()
        sp = root / "settings.json"; m.atomic_write(sp, m.encode(s))
        p = m.Publisher(sp, root / "snapshot.json", fetcher=lambda s: b"sub",
                        converter=lambda b: nodes(), measure=lambda n, s: 1, checker=m.check_profile)
        with self.assertLogs(m.LOG, level="INFO") as captured:
            self.assertTrue(p.refresh(), p.status())
        text = "\n".join(captured.output)
        self.assertIn("published", text)
        self.assertIn("hk_retained=4 hk_tested=3", text)
        self.assertIn("sg_retained=2 sg_tested=2", text)
        self.assertNotIn(s["subscription_url"], text)


class ManualNodeTests(unittest.TestCase):
    def test_validate_manual_entries(self):
        s = settings()
        s["manual_nodes"] = ["vmess://example", "hysteria2://hk.example.invalid:443?sni=hk.example.invalid#HK own"]
        m.validate(s)
        for bad in ([1], ["ftp://host"], ["vmess://a\nvmess://b"], "vmess://x", ["noscheme"], ["a" * 4097]):
            s2 = settings(); s2["manual_nodes"] = bad
            with self.subTest(bad=str(bad)[:20]), self.assertRaises(m.Invalid):
                m.validate(s2)
        s3 = settings(); s3["manual_nodes"] = ["vmess://x"] * 201
        with self.assertRaisesRegex(m.Invalid, "manual_nodes_list"):
            m.validate(s3)

    def test_merge_nodes_keeps_tags_unique(self):
        base = [{"type": "socks", "tag": "HK a", "server": "127.0.0.1", "server_port": 9, "version": "5"}]
        merged = m.merge_nodes(base, [{"tag": "HK a"}, {"tag": "SG b"}])
        self.assertEqual([n["tag"] for n in merged], ["HK a", "HK a -m1", "SG b"])

    def test_real_converter_manual_link_supplies_hong_kong(self):
        sub = b"trojan://synthetic@sg.example.invalid:443?sni=sg.example.invalid#SG sub\n"
        manual = b"trojan://synthetic@hk.example.invalid:443?sni=hk.example.invalid#HK manual\n"
        merged = m.merge_nodes(m.convert(sub), m.convert(manual))
        chosen, info = m.select(merged, settings(), lambda n, s: 3, no_check)
        self.assertFalse(info["hk_fallback"])
        self.assertEqual(len(chosen["hk"]), 2)
        self.assertEqual([n['tag'] for n in chosen['hk']], ['hk-001', 'hk-own-hy2'])

    def test_publisher_merges_and_rejects_manual_nodes(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        s = settings(); s["manual_nodes"] = ["trojan://x@hk.example.invalid:443#HK manual"]
        sp = root / "settings.json"; m.atomic_write(sp, m.encode(s))
        calls = []
        def convert(data):
            calls.append(data)
            if data == b"sub":
                return [{"type": "socks", "tag": "SG a", "server": "127.0.0.1", "server_port": 9, "version": "5"}]
            return [{"type": "socks", "tag": "HK manual", "server": "127.0.0.1", "server_port": 9, "version": "5"}]
        p = m.Publisher(sp, root / "snapshot.json", fetcher=lambda s: b"sub",
                        converter=convert, measure=lambda n, s: 1, checker=m.check_profile)
        self.assertTrue(p.refresh(), p.status())
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], b"trojan://x@hk.example.invalid:443#HK manual\n")
        self.assertEqual(p.status()["selection"]["counts"]["hk"],
                         {"tested": 1, "healthy": 1, "retained": 2})
        self.assertFalse(p.status()["selection"]["hk_fallback"])
        # A dropped manual entry must fail the cycle, not silently shrink the pool.
        p.converter = lambda data: []
        self.assertFalse(p.refresh())
        self.assertIn("manual_node_rejected", p.status()["error"])


if __name__ == '__main__':
    unittest.main()
