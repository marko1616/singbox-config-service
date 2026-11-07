"""Lifecycle and capability contracts, using synthetic feeds and real core checks."""
import copy
from http.server import ThreadingHTTPServer
import itertools
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

import cli
import service as m
from test_service import root_settings, settings, nodes, no_check


def composed(names=('normal', 'sg-business', 'resolver', 'bypass')):
    root = root_settings()
    shared = root['shared']
    shared.pop('subscription_url'); shared.pop('subscription_user_agent')
    shared['subscriptions'] = [
        {'name': 'tag', 'url': 'https://tag.example.invalid/secret', 'update_policy': 'startup'},
        {'name': 'other', 'url': 'https://other.example.invalid/secret', 'update_policy': 'poll',
         'interval_seconds': 120}]
    root['services'] = {
        'normal': {'type': 'proxy'},
        'sg-business': {'type': 'singapore', 'rules': shared.pop('singapore')},
        'resolver': {'type': 'dns', 'hosts': shared.pop('dns_hosts', {})},
        'bypass': {'type': 'direct', 'rules': shared.pop('direct')},
        'overlay': {'type': 'wireguard'}}
    root['devices'][0].pop('wireguard')
    root['devices'][0].update(services=list(names), mode='global', ingress='mixed')
    shared['own_hy2'] = None
    shared['probe_interval_seconds'] = 60
    return root


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.root = composed()
        self.now = 0
        self.calls, self.probes, self.blocked, self.empty = [], [], set(), set()
        self.save()
        self.p = self.publisher()

    def save(self):
        m.atomic_write(self.path / 'settings.json', m.encode(self.root))

    def fetch(self, src):
        self.calls.append(src['name'])
        if src['name'] in self.blocked:
            raise RuntimeError('403 private-token-must-not-escape')
        return src['name'].encode()

    def convert(self, data):
        name = data.decode()
        if name in self.empty:
            return []
        # Distinct identities: retaining TAG must be observable despite deduplication.
        return [dict(n, server_port=10000 + i + (100 if name == 'tag' else 200))
                for i, n in enumerate(nodes())]

    def publisher(self):
        return m.Publisher(self.path / 'settings.json', self.path / 'snapshot.json',
            fetcher=self.fetch, converter=self.convert, measure=lambda n, _: self.probes.append(n['tag']) or 1,
            checker=no_check, clock=lambda: self.now)

    def test_startup_poll_and_health_clocks_are_independent(self):
        self.assertTrue(self.p.refresh(False, False), self.p.status())
        self.assertEqual(self.calls, ['tag', 'other'])
        before = len(self.probes)
        self.now = 60
        self.assertTrue(self.p.refresh(False, False))
        self.assertEqual(self.calls, ['tag', 'other'])
        self.assertGreater(len(self.probes), before)
        self.now = 120
        self.assertTrue(self.p.refresh(False, False))
        self.assertEqual(self.calls, ['tag', 'other', 'other'])
        self.assertTrue(self.p.refresh(True, True))
        self.assertEqual(self.calls.count('tag'), 1, 'force refresh must not violate startup policy')

    def test_restart_closed_tag_uses_private_durable_cache_and_keeps_probing(self):
        self.assertTrue(self.p.refresh())
        cached = self.p.source_cache_path.read_bytes()
        self.assertEqual(self.p.source_cache_path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b'https://tag', cached)
        self.blocked.add('tag')
        q = self.publisher(); q.restore()
        self.assertTrue(q.refresh(False, False), q.status())
        self.assertTrue(q.status()['stale'])
        self.assertEqual(q.status()['sources'][0]['status'], 'stale')
        self.assertEqual(q.status()['selection']['counts']['all']['tested'], 10)
        self.now = 500
        self.assertTrue(q.refresh(False, False))
        self.assertEqual(self.calls.count('tag'), 2, 'once per process, including failed startup')
        self.assertNotIn('private-token', json.dumps(q.status()))

    def test_first_start_failure_does_not_poll_startup_source(self):
        self.blocked.add('tag')
        self.assertTrue(self.p.refresh(False, False))
        self.assertEqual(self.p.status()['sources'][0]['status'], 'failed')
        self.now = 500
        self.blocked.clear()
        self.assertTrue(self.p.refresh(True, True))
        self.assertEqual(self.calls.count('tag'), 1)
        self.assertTrue(self.publisher().refresh())
        self.assertEqual(self.calls.count('tag'), 2)

    def test_failure_cache_and_empty_reply_never_replace_good_catalog(self):
        self.assertTrue(self.p.refresh())
        tag = next(src for src in m.subscription_sources(self.root['shared']) if src['name'] == 'tag')
        previous = copy.deepcopy(self.p._source_cache[self.p.source_key(tag)])
        self.empty.add('tag')
        q = self.publisher()
        self.assertTrue(q.refresh(), q.status())
        self.assertEqual(q._source_cache[q.source_key(tag)], previous)
        self.assertEqual(q.status()['sources'][0]['status'], 'stale')
        self.blocked.add('other')
        self.now = 120
        self.assertTrue(q.refresh(False, False))
        before = len(self.calls)
        self.now = 121
        self.assertTrue(q.refresh(False, False))
        self.assertEqual(len(self.calls), before, 'failed poll has its own bounded interval')

    def test_rename_change_reuses_raw_cache_without_reopening_feed(self):
        self.assertTrue(self.p.refresh(False, False))
        self.root['shared']['subscriptions'][0]['rename_rules'] = [
            {'pattern': '(.*)', 'replacement': 'TAG-$1'}]
        self.save(); self.now = 10
        self.assertTrue(self.p.refresh(False, False))
        self.assertIn('TAG-HK a', self.p.data['phone'].decode())
        self.assertEqual(self.calls, ['tag', 'other'])

    def test_url_change_never_reuses_other_credential_cache(self):
        self.assertTrue(self.p.refresh())
        self.root['shared']['subscriptions'][0]['url'] += '-rotated'
        self.save(); self.blocked.add('tag')
        q = self.publisher()
        self.assertTrue(q.refresh())
        self.assertEqual(q.status()['sources'][0]['status'], 'failed')
        self.assertEqual(q.status()['selection']['counts']['all']['tested'], 5)

    def test_cached_nodes_still_fail_health_without_overwriting_snapshot(self):
        self.assertTrue(self.p.refresh())
        old = self.p.snapshot.read_bytes()
        self.p.measure = lambda *_: None
        self.assertFalse(self.p.refresh(True, True))
        self.assertEqual(self.p.snapshot.read_bytes(), old)
        self.assertEqual(self.calls.count('tag'), 1)

    def test_concurrent_refreshes_do_not_duplicate_startup_fetch(self):
        jobs = [threading.Thread(target=lambda: self.p.refresh(False, False)) for _ in range(3)]
        for job in jobs: job.start()
        for job in jobs: job.join(5); self.assertFalse(job.is_alive())
        self.assertEqual(self.calls.count('tag'), 1)
        self.assertEqual(self.calls.count('other'), 1)

    def test_hot_added_startup_source_waits_for_restart_and_diagnose_skips_it(self):
        self.assertTrue(self.p.refresh())
        self.root['shared']['subscriptions'].append(
            {'name': 'new', 'url': 'https://new.example.invalid/feed', 'update_policy': 'startup'})
        self.save()
        self.assertTrue(self.p.refresh(False, False))
        self.assertNotIn('new', self.calls)
        self.assertEqual(self.p.status()['sources'][-1]['status'], 'pending_restart')
        calls = []
        report = m.diagnose_report(self.path / 'settings.json', fetcher=lambda src: calls.append(src['name']) or b'x')
        self.assertEqual(calls, ['other'])
        self.assertIn('startup-only', report)
        self.assertTrue(self.publisher().refresh())
        self.assertIn('new', self.calls)

    def test_corrupt_or_publicly_readable_source_cache_is_not_used(self):
        self.assertTrue(self.p.refresh())
        cache = self.p.source_cache_path.read_bytes()
        self.blocked.add('tag')
        for public in (False, True):
            m.atomic_write(self.p.source_cache_path, cache if public else b'{corrupt')
            if public: self.p.source_cache_path.chmod(0o644)
            q = self.publisher()
            self.assertTrue(q.refresh())
            self.assertEqual(q.status()['sources'][0]['status'], 'failed')
            self.assertEqual(q.status()['selection']['counts']['all']['tested'], 5)

    def test_no_proxy_features_skip_all_fetches_and_probes(self):
        self.root['devices'][0]['services'] = ['resolver']
        self.root['shared']['subscriptions'] = []
        self.save()
        self.assertTrue(self.p.refresh())
        self.assertEqual(self.calls, [])
        self.assertEqual(self.probes, [])
        self.assertEqual(self.p.status()['selection']['counts']['all']['tested'], 0)

    def test_proxy_only_does_not_require_any_sg_candidate(self):
        self.root['devices'][0]['services'] = ['normal']
        self.save()
        self.p.converter = lambda _: [dict(nodes()[0], tag='Japan')]
        self.assertTrue(self.p.refresh(), self.p.status())
        profile = json.loads(self.p.data['phone'])
        self.assertEqual([n['tag'] for n in profile['outbounds'] if n['type'] == 'selector'], ['proxy'])


class CompositionTests(unittest.TestCase):
    def test_shipped_composition_example_validates_after_placeholder_fill(self):
        root = json.loads((Path(__file__).resolve().parents[1] / 'docs/composition.example.json').read_bytes())
        root['public_base_url'] = 'https://profiles.example.invalid/prefix'
        for index, client in enumerate(root['devices']):
            client['api_key'] = f'client_{index}_' + 'x' * 40
        for index, source in enumerate(root['shared']['subscriptions']):
            source['url'] = f'https://feed{index}.example.invalid/feed'
        clients = m.device_settings(root)
        self.assertEqual(set(clients), {'phone', 'laptop', 'dns-client'})
        self.assertEqual(clients['phone']['ingress'], 'both')
        self.assertIsNone(clients['phone']['wireguard'])
        self.assertNotIn('singapore', m.features(clients['laptop']))
        self.assertEqual(m.features(clients['dns-client']), {'dns'})

    def test_all_sixteen_basic_combinations_and_modes_with_real_core(self):
        chosen = {'all': nodes(), 'hk': nodes()[:3], 'sg': nodes()[3:]}
        names = ['normal', 'sg-business', 'resolver', 'bypass']
        for mask in itertools.product((False, True), repeat=4):
            selected = [name for name, yes in zip(names, mask) if yes]
            root = composed(selected)
            st = m.device_settings(root)['phone']
            base = m.build_profile(st, chosen)
            tags = {n['tag'] for n in base['outbounds']}
            self.assertEqual('proxy' in tags, 'normal' in selected)
            self.assertEqual('sg' in tags, 'sg-business' in selected)
            self.assertEqual(any(r['action'] == 'hijack-dns' for r in base['route']['rules']), 'resolver' in selected)
            self.assertEqual(any(n['tag'] == 'dns-sg' for n in base['dns']['servers']),
                             {'resolver', 'sg-business'} <= set(selected))
            for mode in ('global', 'blacklist', 'whitelist') if 'normal' in selected else ('global',):
                st['mode'] = mode
                with self.subTest(selected=selected, mode=mode):
                    profile = m.client_variant(base, st, foreign_url='https://example.invalid/foreign.srs')
                    m.check_profile(profile)
                    self.assertEqual(profile['route']['final'], 'proxy' if 'normal' in selected and mode != 'whitelist' else 'direct')

    def test_ingress_is_independent_of_wireguard(self):
        for ingress, wireguard in itertools.product(('mixed', 'tun', 'both'), (False, True)):
            root = composed(['normal', 'resolver'] + (['overlay'] if wireguard else []))
            root['devices'][0]['ingress'] = ingress
            if wireguard:
                root['devices'][0]['wireguard'] = settings()['wireguard']
            st = m.device_settings(root)['phone']
            p = m.client_variant(m.build_profile(st, {'all': nodes(), 'hk': nodes()[:3], 'sg': []}), st)
            m.check_profile(p)
            self.assertEqual(bool(p['endpoints']), wireguard)
            self.assertEqual([i['type'] for i in p['inbounds']],
                             {'mixed': ['mixed'], 'tun': ['tun'], 'both': ['tun', 'mixed']}[ingress])

    def test_bad_references_duplicate_kinds_and_conflicting_legacy_settings_rejected(self):
        cases = [(['missing'], 'client_services'), (['normal', 'normal'], 'client_services'),
                 (['normal', 'other-proxy'], 'duplicate_service_type')]
        for names, code in cases:
            root = composed(names); root['services']['other-proxy'] = {'type': 'proxy'}
            with self.assertRaisesRegex(m.Invalid, code): m.device_settings(root)
        root = composed(); root['shared']['direct'] = copy.deepcopy(m.EMPTY_RULES)
        with self.assertRaisesRegex(m.Invalid, 'composition_legacy_conflict'): m.device_settings(root)
        root = composed(['overlay'])
        with self.assertRaisesRegex(m.Invalid, 'wireguard_service_config'): m.device_settings(root)
        root = composed(['resolver']); root['devices'][0]['mode'] = 'blacklist'
        with self.assertRaisesRegex(m.Invalid, 'mode_requires_proxy'): m.device_settings(root)

    def test_invalid_source_policy_and_startup_interval_rejected(self):
        for fields, code in [({'update_policy': 'start'}, 'subscription_update_policy'),
                             ({'update_policy': 'startup', 'interval_seconds': 60}, 'startup_interval_conflict'),
                             ({'update_policy': 'poll', 'interval_seconds': True}, 'subscription_interval')]:
            root = composed(); root['shared']['subscriptions'][0].update(fields)
            with self.assertRaisesRegex(m.Invalid, code): m.device_settings(root)

    def test_render_merges_builtin_direct_only_into_explicit_direct_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp); (path / 'private-config').mkdir(); (path / 'data').mkdir()
            root = composed(['normal'])
            m.atomic_write(path / 'private-config/settings.json', m.encode(root))
            m.atomic_write(path / 'data/direct.json', m.encode({'ip_cidr': ['192.0.2.5/32'], 'domain': [], 'domain_suffix': []}))
            rendered = json.loads(cli.render(path).read_bytes())
            self.assertNotIn('direct', rendered['shared'])
            self.assertIn('192.0.2.5/32', rendered['services']['bypass']['rules']['ip_cidr'])
            st = m.device_settings(rendered)['phone']
            self.assertEqual(st['direct'], m.EMPTY_RULES)

    def test_canonical_api_respects_clients_and_deselection_blocks_stale_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp); root = composed(['normal'])
            other = dict(root['devices'][0], id='dns-client', api_key='dns_' + 'z' * 40, services=['resolver'])
            root['devices'].append(other)
            settings_path = path / 'settings.json'; m.atomic_write(settings_path, m.encode(root))
            p = m.Publisher(settings_path, path / 'snapshot.json', fetcher=lambda _: b'fixture',
                            converter=lambda _: nodes(), measure=lambda *_: 1, checker=no_check)
            self.assertTrue(p.refresh())
            server = ThreadingHTTPServer(('127.0.0.1', 0), m.handler_for(p))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                def request(key, suffix='/api/config'):
                    req = urllib.request.Request(f'http://127.0.0.1:{server.server_port}{suffix}',
                                                 headers={'Authorization': 'Bearer ' + key})
                    try: result = opener.open(req, timeout=2)
                    except urllib.error.HTTPError as exc: result = exc
                    with result: return result.status, json.loads(result.read())
                key = root['devices'][0]['api_key']
                code, profile = request(key)
                self.assertEqual(code, 200)
                self.assertIn('proxy', [n['tag'] for n in profile['outbounds']])
                code, profile = request(other['api_key'])
                self.assertEqual(code, 200)
                self.assertEqual([n['tag'] for n in profile['outbounds']], ['direct'])
                self.assertEqual(request(other['api_key'], '/api/config-blacklist-proxyonly')[0], 400)
                root['devices'][0]['services'] = ['resolver']
                m.atomic_write(settings_path, m.encode(root))
                self.assertEqual(request(key), (503, {'error': 'client_configuration_pending'}))
                self.assertTrue(p.refresh(False, False))
                code, profile = request(key)
                self.assertEqual(code, 200)
                self.assertNotIn('proxy', [n['tag'] for n in profile['outbounds']])
            finally:
                server.shutdown(); server.server_close()


if __name__ == '__main__':
    unittest.main()
