"""Multi-source, naming, clock separation and fail-safe publication regressions."""
import base64
import copy
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import service as m
from test_service import no_check, nodes, root_settings, settings


def multi_settings():
    s = settings()
    s.pop('subscription_url')
    s.pop('subscription_user_agent')
    s['subscriptions'] = [
        {'name': 'first', 'url': 'https://first.example.invalid/private-token'},
        {'name': 'second', 'url': 'https://second.example.invalid/private-token'}]
    return s


def documented_rules():
    text = (Path(__file__).resolve().parents[1] / 'README_zh.md').read_text()
    start = text.index('```json\n{\n  "subscriptions"') + len('```json\n')
    snippet = json.loads(text[start:text.index('\n```', start)])
    return tuple(source['rename_rules'] for source in snippet['subscriptions'])


class CatalogTests(unittest.TestCase):
    def test_curl_treats_braces_and_brackets_as_one_literal_url(self):
        source = m.subscription_sources(multi_settings())[0]
        source['subscription_url'] += '?filter[region]={hk,sg}'
        def run(command, **kwargs):
            self.assertIn('--globoff', command)
            self.assertIn(source['subscription_url'], kwargs['input'].decode())
            return subprocess.CompletedProcess(command, 0, b'body\n200', b'')
        with patch.object(m.subprocess, 'run', side_effect=run):
            self.assertEqual(m.fetch(source, attempts=1), b'body')

    def test_explicit_curl_user_agent_is_forwarded_without_exposing_url(self):
        s = multi_settings()
        s['subscriptions'][0]['user_agent'] = 'curl/8.10.1'
        source = m.subscription_sources(s)[0]
        def run(command, **kwargs):
            self.assertEqual(command[command.index('--user-agent') + 1], 'curl/8.10.1')
            self.assertNotIn(source['subscription_url'], repr(command))
            self.assertIn(source['subscription_url'], kwargs['input'].decode())
            return subprocess.CompletedProcess(command, 0, b'body\n200', b'')
        with patch.object(m.subprocess, 'run', side_effect=run):
            self.assertEqual(m.fetch(source), b'body')

    def test_tag_and_aws_source_rules_are_independent_and_no_hk_selector_is_emitted(self):
        s = multi_settings()
        tag_rules, aws_rules = documented_rules()
        s['rename_rules'] = [{'pattern': '(.*)', 'replacement': 'WRONG-$1'}]
        s['subscriptions'][0]['rename_rules'] = tag_rules
        s['subscriptions'][1]['rename_rules'] = aws_rules
        m.validate(s)
        fixtures = {
            b'first': [{'type': 'shadowsocks', 'tag': '🇭🇰 香港家宽 01丨1x HK',
                        'server': 'node.example.invalid', 'server_port': 443,
                        'method': 'aes-128-gcm', 'password': 'synthetic'}],
            b'second': [{'type': 'vless', 'tag': name, 'server': 'other.example.invalid',
                        'server_port': 443, 'uuid': '00000000-0000-4000-8000-000000000001'}
                       for name in ['🇸🇬AWS新加坡04 | 电信移动优化', '🇸🇬AWS新加坡03丨电信移动', '🇯🇵AWS日本09 | 电信移动']]}
        converted, metadata, _ = m.collect_subscriptions(s, lambda src: src['name'].encode(),
                                                        lambda data: fixtures[data])
        chosen, summary = m.select(converted, s, lambda *_: 1, no_check, metadata=metadata)
        self.assertEqual([n['tag'] for n in chosen['sg']], ['新加坡-AWS-001', '新加坡-AWS-002'])
        self.assertEqual(summary['display_types']['AWS'], 3)
        self.assertEqual(summary['display_types']['家宽'], 1)
        profile = m.build_profile(s, chosen)
        selectors = {n['tag']: n for n in profile['outbounds'] if n['type'] == 'selector'}
        self.assertEqual(set(selectors), {'proxy', 'sg'})
        self.assertEqual(selectors['proxy']['default'], '香港-家宽-001')
        self.assertIn('日本-AWS-001', selectors['proxy']['outbounds'])
        self.assertEqual(selectors['sg']['outbounds'], ['新加坡-AWS-001', '新加坡-AWS-002'])
        self.assertTrue(all(n['type'] == 'vless' for n in chosen['sg']))
        self.assertFalse(any(str(v).startswith('WRONG-') for v in m.walk(profile)))
        for mode in ('global', 'blacklist', 'whitelist'):
            for full in (True, False):
                p = m.variant_profile(profile, mode, full, m.proxy_options({}),
                                      'https://example.invalid/foreign.srs')
                self.assertNotIn('hk', list(m.walk(p)))
                m.check_profile(p)

    def test_real_https_curl_base64_converter_and_publisher_failure_recovery(self):
        if not shutil.which('openssl'):
            self.skipTest('openssl needed only to issue a loopback test certificate')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key, cert = root / 'key.pem', root / 'cert.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost',
                '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
            state = {'failed': set(), 'agents': [], 'paths': []}
            bodies = {
                '/first': base64.b64encode('trojan://synthetic@node.example.invalid:443#香港家宽%2001'.encode()),
                '/second': 'anytls://synthetic@sg.example.invalid:443#新加坡家宽%2001'.encode()}
            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *_): pass
                def do_GET(self):
                    agent = self.headers.get('User-Agent', '')
                    state['agents'].append(agent)
                    state['paths'].append(self.path)
                    path = self.path.split('?', 1)[0]
                    status = 403 if agent == 'v2rayNG' else 503 if path in state['failed'] else 200
                    body = bodies[path] if status == 200 else b'unavailable'
                    self.send_response(status); self.send_header('Content-Length', str(len(body)))
                    self.end_headers(); self.wfile.write(body)
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                s = multi_settings()
                for src, path in zip(s['subscriptions'], ('/first', '/second')):
                    src['url'] = f'https://127.0.0.1:{server.server_port}{path}'
                s['rename_rules'] = [{'pattern': r'(香港|新加坡)(家宽).*', 'replacement': '$1-$2-$index'}]
                path = root / 'settings.json'; m.atomic_write(path, m.encode(root_settings(s)))
                publisher = m.Publisher(path, root / 'snapshot.json', measure=lambda *_: 1)
                with patch.dict(os.environ, {'CURL_CA_BUNDLE': str(cert), 'NO_PROXY': '127.0.0.1', 'no_proxy': '127.0.0.1'}), \
                        patch.object(m.time, 'sleep'):
                    literal = m.subscription_sources(s)[0]
                    literal['subscription_url'] += '?filter[region]={hk,sg}'
                    self.assertEqual(m.fetch(literal), bodies['/first'])
                    self.assertEqual(state['paths'], ['/first?filter[region]={hk,sg}'])
                    self.assertTrue(publisher.refresh(), publisher.status())
                    profile = json.loads(publisher.data['phone'])
                    pool = next(n for n in profile['outbounds'] if n['tag'] == 'proxy')
                    self.assertIn('香港-家宽-001', pool['outbounds'])
                    self.assertIn('新加坡-家宽-001', pool['outbounds'])
                    self.assertTrue(all(agent.startswith('curl/') for agent in state['agents']))
                    state['failed'] = {'/first'}
                    self.assertTrue(publisher.refresh(), publisher.status())
                    self.assertIn('香港-家宽-001', publisher.data['phone'].decode())
                    self.assertEqual(publisher.status()['selection']['sources'][0]['status'], 'stale')
                    previous = publisher.snapshot.read_bytes(), copy.deepcopy(publisher.data)
                    state['failed'] = {'/first', '/second'}
                    self.assertFalse(publisher.refresh())
                    self.assertEqual(previous, (publisher.snapshot.read_bytes(), publisher.data))
                    state['failed'] = set()
                    self.assertTrue(publisher.refresh(), publisher.status())
                    self.assertFalse(publisher.status()['stale'])
                    blocked = m.subscription_sources(s)[0]; blocked['subscription_user_agent'] = 'v2rayNG'
                    with self.assertRaisesRegex(m.Invalid, 'subscription_fetch_failed'):
                        m.fetch(blocked)
            finally:
                server.shutdown(); server.server_close()

    def test_legacy_and_multi_source_validation(self):
        m.validate(settings())
        s = multi_settings()
        m.validate(s)
        source = m.subscription_sources(s)[0]
        self.assertEqual(source['subscription_fetch_method'], 'curl')
        self.assertEqual(source['subscription_user_agent'], '')
        for update, code in [({'subscriptions': []}, 'subscriptions_list'),
                             ({'subscription_url': 'https://bad.invalid'}, 'subscription_source_conflict'),
                             ({'probe_interval_seconds': 0}, 'invalid_probe_interval_seconds'),
                             ({'rename_rules': [{'pattern': '(', 'replacement': '$1'}]}, 'rename_pattern'),
                             ({'rename_rules': [{'pattern': '(a)', 'replacement': '$2'}]}, 'rename_capture'),
                             ({'rename_rules': [{'pattern': '(a)', 'replacement': '$bogus'}]}, 'rename_replacement')]:
            bad = copy.deepcopy(s); bad.update(update)
            with self.subTest(code=code), self.assertRaisesRegex(m.Invalid, '^' + code + '$'):
                m.validate(bad)

    def test_source_urls_names_and_agents_fail_safely(self):
        for entry in ({'url': 'http://bad.invalid'}, {'url': 'https://user:pass@bad.invalid'},
                      {'url': 'https://bad.invalid:99999'}, {'url': 'https://bad.invalid', 'user_agent': 'x\ny'},
                      {'url': 'https://bad.invalid', 'name': 'space name'},
                      {'url': 'https://bad.invalid', 'fetch_method': 'shell'}):
            s = multi_settings(); s['subscriptions'] = [entry]
            with self.subTest(entry=entry), self.assertRaises(m.Invalid):
                m.validate(s)

    def test_merge_sources_deduplicate_exact_aliases_without_losing_regions(self):
        s = multi_settings()
        result, metadata, reports = m.collect_subscriptions(s, lambda _: b'fixture', lambda _: nodes())
        self.assertEqual(len(result), 5)
        self.assertEqual(len(reports), 2)
        self.assertEqual(metadata['SG a']['original'], 'SG a')
        self.assertEqual(len({n['tag'] for n in result}), 5)

    def test_source_name_collision_and_per_source_rename(self):
        s = multi_settings()
        s['subscriptions'][0]['rename_rules'] = [{'pattern': '(HK) (a)', 'replacement': '$2-$1-$index'}]
        def convert(data):
            return [dict(nodes()[0], server_port=9 if data == b'first' else 10)]
        result, metadata, _ = m.collect_subscriptions(s, lambda src: src['name'].encode(), convert)
        self.assertEqual(len({n['tag'] for n in result}), 2)
        self.assertEqual({v['original'] for v in metadata.values()}, {'HK a'})
        self.assertEqual(metadata['HK a']['rename_rules'][0]['replacement'], '$2-$1-$index')

    def test_partial_outage_does_not_expose_subscription(self):
        s = multi_settings()
        def fetch(src):
            if src['name'] == 'first':
                raise RuntimeError(src['subscription_url'])
            return b'fixture'
        with self.assertLogs(m.LOG, level='WARNING') as captured:
            result, _, reports = m.collect_subscriptions(s, fetch, lambda _: nodes())
        self.assertEqual(len(result), 5)
        self.assertEqual([x['status'] for x in reports], ['failed', 'ok'])
        self.assertNotIn('private-token', '\n'.join(captured.output) + json.dumps(reports))

    def test_real_converter_base64_multiple_sources(self):
        s = multi_settings()
        uri = b'trojan://synthetic-password@node.example.invalid:443#HK%20home\n'
        result, _, _ = m.collect_subscriptions(s,
            lambda src: base64.b64encode(uri) if src['name'] == 'first' else
                b'anytls://synthetic-password@sg.example.invalid:443#SG%20normal\n', m.convert)
        self.assertEqual([n['type'] for n in result], ['trojan', 'anytls'])
        self.assertEqual([n['tag'] for n in result], ['HK home', 'SG normal'])

    def test_curl_input_hides_url_and_preserves_empty_user_agent(self):
        source = m.subscription_sources(multi_settings())[0]
        def run(command, **kwargs):
            self.assertNotIn(source['subscription_url'], repr(command))
            self.assertIn(source['subscription_url'], kwargs['input'].decode())
            self.assertNotIn('--user-agent', command)
            return subprocess.CompletedProcess(command, 0, b'base64-body\n200', b'')
        with patch.object(m.subprocess, 'run', side_effect=run):
            self.assertEqual(m.fetch(source), b'base64-body')

    def test_curl_failure_retries_without_echoing_stderr(self):
        source = m.subscription_sources(multi_settings())[0]
        response = subprocess.CompletedProcess([], 22, b'\n403', source['subscription_url'].encode())
        with patch.object(m.subprocess, 'run', return_value=response) as run, \
                patch.object(m.time, 'sleep'), self.assertLogs(m.LOG, level='WARNING') as logs:
            with self.assertRaisesRegex(m.Invalid, 'subscription_fetch_failed'):
                m.fetch(source)
        self.assertEqual(run.call_count, 3)
        self.assertNotIn('private-token', '\n'.join(logs.output))


class RenameAndPoolTests(unittest.TestCase):
    def test_documented_rules_cover_both_feeds_and_display_types(self):
        tag_rules, aws_rules = documented_rules()
        root = Path(__file__).resolve().parents[1]
        example = json.loads((root / 'docs/subscriptions.example.json').read_text())
        for filename in ('README.md', 'README_zh.md'):
            text = (root / filename).read_text()
            start = text.index('```json\n{\n  "subscriptions"') + len('```json\n')
            self.assertEqual(json.loads(text[start:text.index('\n```', start)]), example)
        m.validate_rename_rules(tag_rules); m.validate_rename_rules(aws_rules)
        tag_cases = [
            ('🇭🇰 香港 01丨1x HK', '香港-普通-001', '普通'),
            ('🇭🇰 香港家宽 01丨1x HK', '香港-家宽-001', '家宽'),
            ('🇭🇰 香港家宽 02丨1x HK', '香港-家宽-002', '家宽'),
            ('🇸🇬 新加坡家宽 01丨10x SG', '新加坡-家宽-001', '家宽'),
            ('🇺🇸 美国-纽约 01丨1x US', '美国-纽约-普通-001', '普通'),
            ('🇺🇸 美国-家宽 01丨5x US', '美国-家宽-001', '家宽'),
            ('🇯🇵 日本蜂窝5G丨10x JP', '日本-蜂窝5G-001', '蜂窝5G'),
            ('🇯🇵 日本星链丨10x JP', '日本-星链-001', '星链'),
            ('🇺🇸 美国-实验节点丨1x US', '美国-实验节点-001', '实验节点'),
            ('🇨🇦 加拿大-家宽 02丨1x CA', '加拿大-家宽-001', '家宽'),
            ('🇧🇴 玻利维亚住宅丨5x BO', '玻利维亚-住宅-001', '住宅'),
            ('🇭🇰 香港游戏丨2x HK', '香港-游戏-001', '游戏'),
            ('香港 01丨1x HK', '香港-普通-002', '普通'),
            ('🇭🇰香港家宽 03丨1x HK', '香港-家宽-003', '家宽')]
        counters = {}
        for raw, name, kind in tag_cases:
            with self.subTest(raw=raw):
                self.assertEqual(m.rename_node(raw, tag_rules, counters), (name, kind))
        counters = {}
        for raw, expected in [('🇸🇬AWS新加坡04 | 电信移动', '新加坡-AWS-001'),
                              ('🇸🇬 AWS 新加坡03丨电信', '新加坡-AWS-002'),
                              ('🇯🇵AWS日本09 | 电信移动', '日本-AWS-001')]:
            self.assertEqual(m.rename_node(raw, aws_rules, counters), (expected, 'AWS'))
        self.assertEqual(m.rename_node('unmatched name', aws_rules, counters), ('unmatched name', ''))

    def test_capture_validation_rejects_missing_defaults_and_oversized_references(self):
        for defaults in ([], {'0': 'x'}, {'3': 'x'}, {'02': 'x'}, {'2': 3}, {'2': 'bad\n'}):
            with self.subTest(defaults=defaults), self.assertRaisesRegex(m.Invalid, 'rename_capture_defaults'):
                m.validate_rename_rules([{'pattern': '(a)(b)?', 'replacement': '$1-$2',
                                         'capture_defaults': defaults}])
        with self.assertRaisesRegex(m.Invalid, 'rename_replacement'):
            m.validate_rename_rules([{'pattern': '(a)' * 10, 'replacement': '$100'}])

    def test_empty_capture_defaults_drive_both_name_and_display_type(self):
        rule = {'pattern': r'^(香港)(家宽)? .*$', 'replacement': '$1-$2-$index',
                'capture_defaults': {'2': '普通'}}
        m.validate_rename_rules([rule])
        self.assertEqual(m.rename_node('香港 01', [rule], {}), ('香港-普通-001', '普通'))
        self.assertEqual(m.rename_node('香港家宽 01', [rule], {}), ('香港-家宽-001', '家宽'))
        # Capture contents and defaults are literal; never recursively expanded.
        rule['capture_defaults']['2'] = '$index'
        self.assertEqual(m.rename_node('香港 01', [rule], {}), ('香港-$index-001', '$index'))

    def test_endpoint_name_is_reserved_for_full_profile(self):
        data = nodes() + [dict(nodes()[0], tag='wg-ipv6', server_port=12345)]
        chosen, _ = m.select(data, settings(), lambda *_: 1, no_check)
        p = m.build_profile(settings(), chosen)
        names = [n['tag'] for n in p['outbounds'] + p['endpoints']]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('wg-ipv6 [2]', names)
        m.check_profile(p)

    def test_configurable_captures_replacement_and_per_type_numbering(self):
        rules = [{'pattern': r'^(香港|新加坡)(家宽|普通).*$', 'replacement': '$1-$2-$index'}]
        counters = {}
        self.assertEqual(m.rename_node('香港家宽 01', rules, counters), ('香港-家宽-001', '家宽'))
        self.assertEqual(m.rename_node('香港家宽 02', rules, counters), ('香港-家宽-002', '家宽'))
        self.assertEqual(m.rename_node('新加坡普通 01', rules, counters), ('新加坡-普通-001', '普通'))
        swapped = [{'pattern': '(a)(b)', 'replacement': '$2/$1/$index/$$'}]
        self.assertEqual(m.rename_node('ab', swapped, {}), ('b/a/001/$', 'b'))

    def test_rename_preserves_protocol_and_singapore_classification(self):
        s = settings(); s['rename_rules'] = [
            {'pattern': '(HK|SG) (.*)', 'replacement': 'display-$2-$index'}]
        chosen, summary = m.select(nodes(), s, lambda *_: 1, no_check)
        self.assertEqual(chosen['sg'][0]['tag'], 'display-a-002')
        self.assertTrue(all(n['type'] == 'socks' for n in chosen['sg']))
        self.assertEqual(summary['display_types']['a'], 2)
        p = m.build_profile(s, chosen)
        self.assertEqual(next(n for n in p['outbounds'] if n['tag'] == 'sg')['outbounds'],
                         [n['tag'] for n in chosen['sg']])
        self.assertEqual(next(d for d in p['dns']['servers'] if d['tag'] == 'dns-sg')['detour'], 'sg')
        m.check_profile(p)

    def test_global_selector_has_all_healthy_regions_not_top_k(self):
        s = settings(); s['top_k'] = 1
        data = nodes() + [dict(nodes()[0], tag='Japan', server_port=19),
                          dict(nodes()[0], tag='United States', server_port=20)]
        chosen, _ = m.select(data, s, lambda n, _: None if n['tag'] == 'other-002' else 1, no_check)
        self.assertEqual(len(chosen['all']), 7)  # 6 subscription nodes plus verified own_hy2.
        self.assertEqual(len(chosen['sg']), 1)
        p = m.build_profile(s, chosen)
        pool = next(n for n in p['outbounds'] if n['tag'] == 'proxy')
        self.assertIn('Japan', pool['outbounds'])
        self.assertIn('HK c', pool['outbounds'])
        self.assertNotIn('United States', pool['outbounds'])
        self.assertEqual(len(pool['outbounds']), len(set(pool['outbounds'])))
        m.check_profile(p)

    def test_health_counts_do_not_mix_own_hy2_with_subscription_hk(self):
        for own_live in (True, False):
            chosen, report = m.select(nodes(), settings(),
                lambda n, _: None if n['tag'] == 'hk-own-hy2' and not own_live else 1, no_check)
            counts = report['counts']
            for group in ('hk', 'sg', 'other', 'own_hy2', 'all'):
                self.assertLessEqual(counts[group]['retained'], counts[group]['healthy'])
                self.assertLessEqual(counts[group]['healthy'], counts[group]['tested'])
            self.assertEqual(counts['all']['healthy'],
                             sum(counts[group]['healthy'] for group in ('hk', 'sg', 'other', 'own_hy2')))
            self.assertEqual(counts['all']['retained'], len(chosen['all']))

    def test_dead_own_hy2_is_not_in_any_selector(self):
        chosen, info = m.select(nodes(), settings(),
            lambda n, _: None if n['tag'] == 'hk-own-hy2' else 1, no_check)
        self.assertFalse(info['own_hy2_healthy'])
        self.assertNotIn('hk-own-hy2', json.dumps(m.build_profile(settings(), chosen)))

    def test_missing_or_failed_sg_never_uses_general_pool(self):
        with self.assertRaisesRegex(m.Invalid, 'singapore_unavailable'):
            m.select(nodes() + [dict(nodes()[0], tag='Japan')], settings(),
                lambda n, _: None if n['tag'].startswith('sg-') else 1, no_check)


class ClockAndRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.s = root_settings(); self.s['shared']['probe_interval_seconds'] = 60
        self.s['shared']['refresh_seconds'] = 300
        self.settings_path = self.path / 'settings.json'
        m.atomic_write(self.settings_path, m.encode(self.s))
        self.now = 0
        self.fetch_count, self.probes = 0, []
        def fetch(_):
            self.fetch_count += 1
            return b'fixture'
        fixtures = [dict(node, server_port=20+i) for i, node in enumerate(nodes())]
        self.p = m.Publisher(self.settings_path, self.path / 'snapshot.json', fetcher=fetch,
            converter=lambda _: fixtures, measure=lambda n, _: self.probes.append(n['tag']) or 1,
            checker=no_check, clock=lambda: self.now)

    def test_legacy_hk_snapshot_is_not_served_as_new_proxy_layout(self):
        self.assertTrue(self.p.refresh())
        snapshot = json.loads(self.p.snapshot.read_bytes())
        def legacy(value):
            if isinstance(value, dict):
                return {k: legacy(v) for k, v in value.items()}
            if isinstance(value, list):
                return [legacy(v) for v in value]
            return {'proxy': 'hk', 'dns-proxy': 'dns-hk'}.get(value, value) if isinstance(value, str) else value
        snapshot['profiles'] = legacy(snapshot['profiles'])
        snapshot.pop('version', None)  # GitHub HEAD snapshots have no version field.
        for profile in snapshot['profiles'].values():
            m.check_profile(profile)  # Old profile is valid by itself, but not as a new variant.
        m.atomic_write(self.p.snapshot, m.encode(snapshot))
        old = self.p.snapshot.read_bytes()
        q = m.Publisher(self.settings_path, self.p.snapshot, fetcher=lambda _: b'fixture',
                        converter=lambda _: nodes(), measure=lambda *_: 1)
        q.restore()
        self.assertIsNone(q.data)
        self.assertEqual(q.snapshot.read_bytes(), old)
        self.assertTrue(q.refresh(), q.status())
        profile = json.loads(q.data['phone'])
        self.assertEqual({n['tag'] for n in profile['outbounds'] if n['type'] == 'selector'}, {'proxy', 'sg'})

    def test_probe_exceptions_are_negative_cached_until_expiry(self):
        calls = []
        def broken(*_):
            calls.append(1)
            raise OSError('synthetic failure')
        for now in (0, 30, 59):
            self.now = now
            self.assertIsNone(self.p.cached_probe('test', broken, nodes()[0], self.s['shared']))
        self.assertEqual(len(calls), 1)
        self.now = 60
        self.assertIsNone(self.p.cached_probe('test', broken, nodes()[0], self.s['shared']))
        self.assertEqual(len(calls), 2)

    def test_shared_manual_rename_change_is_not_hidden_by_source_cache(self):
        shared = self.s['shared']
        shared.pop('subscription_url'); shared.pop('subscription_user_agent')
        shared['subscriptions'] = [{'url': 'https://example.invalid/feed', 'rename_rules': []}]
        shared['manual_nodes'] = ['socks://127.0.0.1:4444#Japan']
        shared['rename_rules'] = [{'pattern': '(Japan)', 'replacement': 'OLD-$1'}]
        original = self.p.converter
        self.p.converter = lambda data: ([dict(nodes()[0], tag='Japan', server_port=4444)]
                                         if data.startswith(b'socks://') else original(data))
        m.atomic_write(self.settings_path, m.encode(self.s))
        self.assertTrue(self.p.refresh(False, False))
        self.assertIn('OLD-Japan', self.p.data['phone'].decode())
        self.now = 30
        shared['rename_rules'][0]['replacement'] = 'NEW-$1'
        m.atomic_write(self.settings_path, m.encode(self.s))
        self.assertTrue(self.p.refresh(False, False))
        self.assertIn('NEW-Japan', self.p.data['phone'].decode())
        self.assertNotIn('OLD-Japan', self.p.data['phone'].decode())
        self.assertEqual(self.fetch_count, 1)

    def test_fetch_and_probe_clocks_are_independent(self):
        self.assertTrue(self.p.refresh(False, False), self.p.status())
        initial = len(self.probes)
        self.now = 30; self.assertTrue(self.p.refresh(False, False))
        self.assertEqual(len(self.probes), initial)
        self.assertEqual(self.fetch_count, 1)
        self.now = 60; self.assertTrue(self.p.refresh(False, False))
        self.assertEqual(len(self.probes), initial * 2)
        self.assertEqual(self.fetch_count, 1)
        self.now = 300; self.assertTrue(self.p.refresh(False, False))
        self.assertEqual(self.fetch_count, 2)

    def test_negative_probe_cache_expires_and_configuration_change_bypasses_cache(self):
        node = nodes()[0]
        calls = []
        def fail(*_):
            calls.append(1); return None
        s = self.s['shared']
        self.assertIsNone(self.p.cached_probe('test', fail, node, s))
        self.now = 59
        self.p.cached_probe('test', fail, dict(node, tag='renamed'), s)
        self.assertEqual(len(calls), 1)
        self.p.cached_probe('test', fail, dict(node, server_port=10), s)
        self.assertEqual(len(calls), 2)
        self.now = 60; self.p.cached_probe('test', fail, node, s)
        self.assertEqual(len(calls), 3)

    def test_all_sources_failed_preserves_exact_snapshot_and_recovers(self):
        self.assertTrue(self.p.refresh())
        old = self.p.snapshot.read_bytes(), copy.deepcopy(self.p.data)
        original = self.p.fetcher
        self.p.fetcher = lambda _: (_ for _ in ()).throw(RuntimeError('private-url-must-not-escape'))
        self.assertFalse(self.p.refresh())
        self.assertEqual(self.p.status()['error'], 'all_subscriptions_failed')
        self.assertEqual(old, (self.p.snapshot.read_bytes(), self.p.data))
        self.assertNotIn('private-url', json.dumps(self.p.status()))
        self.p.fetcher = original
        self.assertTrue(self.p.refresh())
        self.assertFalse(self.p.status()['stale'])

    def test_sg_failure_retains_previous_batch(self):
        self.assertTrue(self.p.refresh())
        old = self.p.snapshot.read_bytes(), copy.deepcopy(self.p.data)
        self.p.measure = lambda n, _: None if n['tag'].startswith('sg-') else 1
        self.assertFalse(self.p.refresh())
        self.assertEqual(self.p.status()['error'], 'singapore_unavailable')
        self.assertEqual(old, (self.p.snapshot.read_bytes(), self.p.data))


if __name__ == '__main__':
    unittest.main()
