"""Single-purpose sing-box 1.14.2 configuration publisher; Python stdlib only."""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

CORE = os.environ.get("SING_BOX", "/usr/local/bin/sing-box")
CONVERTER = os.environ.get("SING_BOX_SUB", "/usr/local/bin/sing-box-sub")
PROBE_URL = "https://www.google.com/generate_204"
CACHEFLY_URL = "https://cachefly.cachefly.net/1mb.test"
CACHEFLY_BYTES = 131072
CACHEFLY_SHA256 = "fa43239bcee7b97ca62f007cc68487560a39e19f74f3dde7486db3f98df8e471"
# DoH resolver for names needed before any tunnel exists (node servers, subscription host).
# It has to be an IP literal: a hostname here would need DNS to resolve itself.
BOOTSTRAP_DOH = os.environ.get('SINGBOX_BOOTSTRAP_DOH', 'https://223.5.5.5/dns-query')
OVERLAY = "10.77.0.0/24"
CONFIG_PATHS = {f'/api/config-{mode}-{scope}': (mode, scope == 'full')
                for mode in ('global', 'blacklist', 'whitelist')
                for scope in ('full', 'proxyonly')}
GEOIP_CN_URL = 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs'
GEOSITE_CN_URL = 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs'
GEOSITE_FOREIGN_URL = 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs'
FOREIGN_RULE_PATH = Path(__file__).resolve().parent / 'data/geoip-foreign.srs'
LIMIT = 8 * 1024 * 1024
# Everything goes to stdout/docker logs; nothing diagnostic is written to the host.
LOG = logging.getLogger('singbox-config-service')
LOG_LEVELS = {'DEBUG': logging.DEBUG, 'INFO': logging.INFO,
              'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
# Registered when settings load, so no log line can echo them.
SECRETS = set()
SETTINGS_PATH = os.environ.get('SINGBOX_SETTINGS', '/config/settings.json')
SNAPSHOT_PATH = os.environ.get('SINGBOX_SNAPSHOT', '/state/snapshot.json')
# Layout changes must not combine an old HK snapshot with new proxy variants.
SNAPSHOT_VERSION = 3
# URI schemes accepted in settings.manual_nodes (private, never tracked).
MANUAL_SCHEMES = ("vmess://", "vless://", "trojan://", "hysteria2://", "hysteria://",
                  "tuic://", "anytls://", "ss://", "socks://", "http://")
CATALOG_OPTIONS = {'subscriptions', 'rename_rules', 'probe_interval_seconds'}
RENAME_TOKEN = re.compile(r'\$(index|[1-9][0-9]?(?![0-9])|\$)')


class Invalid(ValueError):
    """Only static error identifiers may leave this module."""


def require(ok, code):
    if not ok:
        raise Invalid(code)


def is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def bootstrap_dns(detour=None):
    """Bootstrap over DoH: the tag stays 'bootstrap' so every route rule keeps working."""
    parts = urllib.parse.urlsplit(BOOTSTRAP_DOH)
    require(parts.scheme == 'https' and bool(parts.hostname), 'bootstrap_doh')
    require(is_ip_literal(parts.hostname), 'bootstrap_doh_ip')
    server = {'type': 'https', 'tag': 'bootstrap', 'server': parts.hostname,
              'path': parts.path or '/dns-query'}
    if parts.port:
        server['server_port'] = parts.port
    if detour:
        server['detour'] = detour
    return server


def atomic_write(path, data):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def domain(value):
    require(isinstance(value, str) and len(value) <= 253, "invalid_domain")
    require(bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value)), "invalid_domain")
    require(all(0 < len(x) <= 63 and not x.startswith('-') and not x.endswith('-') for x in value.split('.')), "invalid_domain")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    raise Invalid("domain_is_ip")


def validate_dns_hosts(hosts):
    """Validate private exact-name A/AAAA overrides without echoing values."""
    require(isinstance(hosts, dict) and len(hosts) <= 10000, 'dns_hosts_object')
    result = {}
    for name, values in hosts.items():
        require(isinstance(name, str), 'dns_hosts_domain')
        name = name.removesuffix('.').lower()
        try:
            domain(name)
        except Invalid:
            raise Invalid('dns_hosts_domain') from None
        require(name not in result, 'dns_hosts_duplicate')
        require(isinstance(values, list) and 1 <= len(values) <= 64, 'dns_hosts_addresses')
        addresses = []
        for value in values:
            require(isinstance(value, str) and '%' not in value, 'dns_hosts_ip')
            try:
                address = str(ipaddress.ip_address(value))
            except ValueError:
                raise Invalid('dns_hosts_ip') from None
            if address not in addresses:
                addresses.append(address)
        result[name] = addresses
    return result


def validate_rules(rules):
    required = {'ip_cidr', 'domain', 'domain_suffix'}
    require(isinstance(rules, dict) and required <= set(rules) <= required | {'domain_regex'}, 'rule_fields')
    for field, values in rules.items():
        require(isinstance(values, list) and len(values) <= 10000, 'rule_list')
        for v in values:
            if field == 'ip_cidr':
                ipaddress.ip_network(v, strict=False)
            elif field == 'domain_regex':
                require(isinstance(v, str) and 0 < len(v) <= 1024, 'invalid_domain_regex')
                try:
                    re.compile(v)
                except re.error:
                    raise Invalid('invalid_domain_regex') from None
            else:
                domain(v)


def validate(s):
    require(isinstance(s, dict), "settings_object")
    fields = {"api_key", "subscription_url", "subscription_user_agent", "top_k", "refresh_seconds",
              "probe_timeout_seconds", "probe_workers", "max_candidates", "hk_pattern", "sg_pattern",
              "direct", "singapore", "wireguard", "own_hy2", "manual_nodes"}
    actual = set(s) - {'dns_hosts', 'features', 'ingress', 'mode'} - CATALOG_OPTIONS
    if 'subscriptions' in s:
        actual |= {'subscription_url', 'subscription_user_agent'}
    require(actual in (fields, fields - {'wireguard'}), "settings_fields")
    if 'dns_hosts' in s:
        s['dns_hosts'] = validate_dns_hosts(s['dns_hosts'])
    require(not any(isinstance(v, str) and v.startswith('<') for v in walk(s)), "unfilled_template")
    require(isinstance(s['api_key'], str) and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', s['api_key']), "api_key_format")
    sources = subscription_sources(s)
    require(sources or 'features' in s, 'subscriptions_list')
    validate_rename_rules(s.get('rename_rules', []))
    for key, lo, hi in [('top_k', 1, 50), ('refresh_seconds', 30, 86400),
                        ('probe_timeout_seconds', 2, 30), ('probe_workers', 1, 8), ('max_candidates', 2, 5000)]:
        require(type(s[key]) is int and lo <= s[key] <= hi, 'invalid_' + key)
    interval = s.get('probe_interval_seconds', s['refresh_seconds'])
    require(type(interval) is int and 30 <= interval <= 86400, 'invalid_probe_interval_seconds')
    for key in ('hk_pattern', 'sg_pattern'):
        require(isinstance(s[key], str) and 0 < len(s[key]) < 256, "region_pattern")
        try:
            re.compile(s[key])
        except re.error:
            raise Invalid('region_pattern') from None
    require(isinstance(s['manual_nodes'], list) and len(s['manual_nodes']) <= 200, 'manual_nodes_list')
    for entry in s['manual_nodes']:
        require(isinstance(entry, str) and 0 < len(entry) <= 4096, 'manual_node_entry')
        require(not any(c in entry for c in '\r\n\t'), 'manual_node_entry')
        require('://' in entry and entry.split('://', 1)[0].lower() + '://' in MANUAL_SCHEMES,
                'manual_node_scheme')
    for key in ('direct', 'singapore'):
        validate_rules(s[key])
    w = s.get('wireguard')
    if w is not None:
        require(isinstance(w, dict) and set(w) == {'address', 'private_key', 'peer_public_key', 'endpoint', 'port', 'mtu'}, 'wireguard_fields')
        address = ipaddress.ip_interface(w['address'])
        require(address.version == 4 and address.ip in ipaddress.ip_network(OVERLAY) and address.network.prefixlen == 32, 'wireguard_address_must_be_host_32')
        # sing-box's netip.ParsePrefix needs an explicit mask.
        w['address'] = str(address)
        for key in ('private_key', 'peer_public_key'):
            require(len(base64.b64decode(w[key], validate=True)) == 32, 'wireguard_key')
        try:
            endpoint = ipaddress.ip_address(w['endpoint'])
        except ValueError:
            domain(w['endpoint'])
        else:
            require(endpoint.version == 6 and endpoint.is_global, 'wireguard_public_ipv6_required')
        require(type(w['port']) is int and 1 <= w['port'] <= 65535, 'wireguard_port')
        require(type(w['mtu']) is int and 1280 <= w['mtu'] <= 1420, 'wireguard_mtu')
    h = s['own_hy2']
    if h is None:
        register_secrets(s)
        return s
    require(set(h) == {'server', 'server_port', 'password', 'tls'}, 'hy2_fields')
    require(isinstance(h['server'], str) and h['server'], 'hy2_server')
    try:
        ipaddress.ip_address(h['server'])
    except ValueError:
        domain(h['server'])
    require(type(h['server_port']) is int and 1 <= h['server_port'] <= 65535, 'hy2_port')
    require(isinstance(h['password'], str) and h['password'], 'hy2_password')
    require(set(h['tls']) == {'enabled', 'server_name'} and h['tls']['enabled'] is True, 'hy2_tls')
    domain(h['tls']['server_name'])
    register_secrets(s)
    return s


EMPTY_RULES = {'ip_cidr': [], 'domain': [], 'domain_suffix': [], 'domain_regex': []}
FEATURE_KINDS = {'proxy', 'singapore', 'dns', 'direct', 'wireguard'}


def service_definitions(root):
    """Named reusable capabilities, not device classes; one provider per kind."""
    definitions = root.get('services')
    require(isinstance(definitions, dict) and len(definitions) <= 128, 'services_object')
    for name, item in definitions.items():
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name), 'service_name')
        require(isinstance(item, dict) and item.get('type') in FEATURE_KINDS, 'service_type')
        kind = item['type']
        fields = {'type', 'rules'} if kind in ('direct', 'singapore') else (
            {'type', 'hosts'} if kind == 'dns' else {'type'})
        require(set(item) == fields, 'service_fields')
        if kind in ('direct', 'singapore'):
            validate_rules(item['rules'])
        if kind == 'dns':
            validate_dns_hosts(item['hosts'])
    return definitions


def device_settings(root):
    """Compile named capabilities into per-client effective settings.

    Legacy documents without a service catalog keep their historical defaults.
    The compiler never merges legacy routing with an explicit composition.
    """
    require(isinstance(root, dict) and {'devices', 'shared'} <= set(root) <=
            {'devices', 'shared', 'public_base_url', 'services'}, 'settings_fields')
    if 'public_base_url' in root:
        validate_public_base_url(root['public_base_url'])
    require(isinstance(root['devices'], list) and 1 <= len(root['devices']) <= 64, 'devices_list')
    require(isinstance(root['shared'], dict), 'shared_settings')
    composed = 'services' in root
    definitions = service_definitions(root) if composed else None
    expected = {'subscription_url', 'subscription_user_agent', 'top_k', 'refresh_seconds',
                'probe_timeout_seconds', 'probe_workers', 'max_candidates', 'hk_pattern',
                'sg_pattern', 'direct', 'singapore', 'own_hy2', 'manual_nodes'}
    if composed:
        expected -= {'direct', 'singapore'}
        require(not {'direct', 'singapore', 'dns_hosts'} & set(root['shared']), 'composition_legacy_conflict')
    actual = set(root['shared']) - {'dns_hosts'} - CATALOG_OPTIONS
    if 'subscriptions' in root['shared']:
        actual |= {'subscription_url', 'subscription_user_agent'}
    require(actual == expected, 'shared_settings')
    result = {}
    keys, addresses, private_keys = set(), set(), set()
    for device in root['devices']:
        required = {'id', 'api_key', 'services'} if composed else {'id', 'api_key'}
        optional = {'wireguard', 'mode', 'ingress'} if composed else {'wireguard'}
        require(isinstance(device, dict) and required <= set(device) <= required | optional, 'device_fields')
        ident = device['id']
        require(isinstance(ident, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', ident)
                and ident not in result, 'device_id')
        effective = copy.deepcopy(root['shared'])
        effective.update(api_key=device['api_key'], wireguard=copy.deepcopy(device.get('wireguard')))
        if composed:
            names = device['services']
            require(isinstance(names, list) and all(isinstance(n, str) and n in definitions for n in names)
                    and len(set(names)) == len(names), 'client_services')
            selected = {definitions[n]['type']: definitions[n] for n in names}
            require(len(selected) == len(names), 'duplicate_service_type')
            require(('wireguard' in selected) == (device.get('wireguard') is not None), 'wireguard_service_config')
            effective.update(features=sorted(selected), mode=device.get('mode', 'global'),
                             ingress=device.get('ingress', 'mixed'))
            require(effective['mode'] in ('global', 'blacklist', 'whitelist'), 'invalid_mode')
            require(effective['ingress'] in ('mixed', 'tun', 'both'), 'client_ingress')
            require(effective['mode'] == 'global' or 'proxy' in selected, 'mode_requires_proxy')
            effective.update(direct=copy.deepcopy(selected.get('direct', {}).get('rules', EMPTY_RULES)),
                             singapore=copy.deepcopy(selected.get('singapore', {}).get('rules', EMPTY_RULES)),
                             dns_hosts=copy.deepcopy(selected.get('dns', {}).get('hosts', {})))
        validate(effective)
        require(effective['api_key'] not in keys, 'duplicate_api_key')
        keys.add(effective['api_key'])
        if effective['wireguard'] is not None:
            require(effective['wireguard']['address'] not in addresses, 'duplicate_wireguard_address')
            require(effective['wireguard']['private_key'] not in private_keys, 'duplicate_wireguard_private_key')
            addresses.add(effective['wireguard']['address'])
            private_keys.add(effective['wireguard']['private_key'])
            device['wireguard']['address'] = effective['wireguard']['address']
        result[ident] = effective
    return result


def features(s):
    return set(s.get('features', FEATURE_KINDS - ({'wireguard'} if not s.get('wireguard') else set())))


def walk(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from walk(v)
    else:
        yield value


def load_settings(path):
    st = Path(path).stat()
    require(st.st_uid == os.getuid() and st.st_mode & 0o077 == 0, 'settings_owner_permissions')
    require(st.st_size <= LIMIT, 'settings_size')
    root = json.loads(Path(path).read_bytes())
    device_settings(root)
    return root


def checked(args, timeout=30):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode != 0:
        detail = scrub((result.stderr or b'').decode('utf-8', 'replace'))[:4000]
        LOG.error('tool failed: %s | %s', ' '.join(map(str, args)), detail)
        raise Invalid('tool_failed')
    return result


def register_secrets(settings):
    """Remember values that must never appear in a log line."""
    if not isinstance(settings, dict):
        return
    values = [settings.get('subscription_url'), settings.get('api_key')]
    for source in settings.get('subscriptions', []):
        if isinstance(source, dict):
            values.append(source.get('url'))
    for device in settings.get('devices', []):
        if isinstance(device, dict):
            values.append(device.get('api_key'))
            wg = device.get('wireguard')
            if isinstance(wg, dict):
                values.append(wg.get('private_key'))
    if isinstance(settings.get('shared'), dict):
        register_secrets(settings['shared'])
    hy2 = settings.get('own_hy2')
    if isinstance(hy2, dict):
        values.append(hy2.get('password'))
    for entry in settings.get('manual_nodes') or []:
        if isinstance(entry, str) and '://' in entry:
            rest = entry.split('://', 1)[1]
            if '@' in rest:
                values.append(rest.split('@', 1)[0])
    for value in values:
        if isinstance(value, str) and len(value) >= 8:
            SECRETS.add(value)


def scrub(text, settings=None):
    """Redact the subscription URL, keys and credentials before logging."""
    text = str(text)
    values = set(SECRETS)
    if isinstance(settings, dict):
        values.update(v for v in (settings.get('subscription_url'), settings.get('api_key')) if v)
    for value in values:
        text = text.replace(str(value), '<redacted>')
    return text


def validate_rename_rules(rules):
    require(isinstance(rules, list) and len(rules) <= 100, 'rename_rules')
    for rule in rules:
        require(isinstance(rule, dict) and {'pattern', 'replacement'} <= set(rule) <=
                {'pattern', 'replacement', 'capture_defaults'}, 'rename_rule')
        pattern, replacement = rule['pattern'], rule['replacement']
        require(isinstance(pattern, str) and 0 < len(pattern) <= 1024, 'rename_pattern')
        try:
            compiled = re.compile(pattern)
        except re.error:
            raise Invalid('rename_pattern') from None
        defaults = rule.get('capture_defaults', {})
        require(isinstance(defaults, dict), 'rename_capture_defaults')
        for group, value in defaults.items():
            require(isinstance(group, str) and re.fullmatch(r'[1-9][0-9]?', group)
                    and int(group) <= compiled.groups, 'rename_capture_defaults')
            require(isinstance(value, str) and len(value) <= 512
                    and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'rename_capture_defaults')
        require(isinstance(replacement, str) and 0 < len(replacement) <= 512
                and not any(ord(c) < 32 or ord(c) == 127 for c in replacement), 'rename_replacement')
        require('$' not in RENAME_TOKEN.sub('', replacement), 'rename_replacement')
        for token in RENAME_TOKEN.findall(replacement):
            require(not token.isdigit() or int(token) <= compiled.groups, 'rename_capture')


def subscription_sources(s):
    """Normalize new named sources; a legacy single URL remains supported."""
    if 'subscriptions' not in s:
        sources = [{'url': s.get('subscription_url'),
                    'user_agent': s.get('subscription_user_agent'), 'fetch_method': 'urllib'}]
    else:
        require('subscription_url' not in s, 'subscription_source_conflict')
        sources = s['subscriptions']
        require(isinstance(sources, list) and len(sources) <= 32, 'subscriptions_list')
    result = []
    for index, entry in enumerate(sources, 1):
        require(isinstance(entry, dict) and {'url'} <= set(entry) <=
                {'url', 'name', 'user_agent', 'fetch_method', 'rename_rules', 'update_policy',
                 'interval_seconds'}, 'subscription_source')
        url = entry['url']
        require(isinstance(url, str) and 0 < len(url) <= 16000, 'subscription_https_required')
        try:
            u = urllib.parse.urlsplit(url)
            valid = (u.scheme == 'https' and bool(u.hostname) and u.username is None
                     and u.password is None and not u.fragment and u.port != 0
                     and not any(c.isspace() or ord(c) < 32 for c in url))
        except ValueError:
            valid = False
        require(valid, 'subscription_https_required')
        agent = entry.get('user_agent', s.get('subscription_user_agent', ''))
        require(isinstance(agent, str) and len(agent) <= 512
                and not any(ord(c) < 32 or ord(c) == 127 for c in agent), 'user_agent')
        method = entry.get('fetch_method', 'curl')
        require(method in ('curl', 'urllib'), 'subscription_fetch_method')
        policy = entry.get('update_policy', 'poll')
        require(policy in ('poll', 'startup'), 'subscription_update_policy')
        interval = entry.get('interval_seconds', s.get('refresh_seconds', 300))
        require(type(interval) is int and 30 <= interval <= 86400, 'subscription_interval')
        require(policy != 'startup' or 'interval_seconds' not in entry, 'startup_interval_conflict')
        name = entry.get('name', f'source-{index}')
        require(isinstance(name, str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name)), 'subscription_source_name')
        rules = entry.get('rename_rules', s.get('rename_rules', []))
        validate_rename_rules(rules)
        result.append({'subscription_url': url, 'subscription_user_agent': agent,
                       'subscription_fetch_method': method, 'name': name, 'rename_rules': rules,
                       'update_policy': policy, 'interval_seconds': interval})
    require(len({v['name'] for v in result}) == len(result), 'subscription_source_name')
    return result


def rename_node(name, rules, counters):
    """First matching rule; $index counts per expanded template/type across sources."""
    for rule in rules:
        match = re.search(rule['pattern'], name)
        if match is None:
            continue
        def capture(index):
            return match.group(index) or rule.get('capture_defaults', {}).get(str(index), '')
        display_type = capture(2) if match.re.groups >= 2 else ''
        def expand(token):
            value = token.group(1)
            if value == 'index':
                return '$index'
            return '$' if value == '$' else capture(int(value))
        template = RENAME_TOKEN.sub(expand, rule['replacement'])
        key = (template, display_type)
        counters[key] = counters.get(key, 0) + 1
        # Replace only actual $index tokens, not literal $$index text.
        def render(token):
            if token.group(1) == 'index':
                return f'{counters[key]:03d}'
            return expand(token)
        rendered = RENAME_TOKEN.sub(render, rule['replacement'])
        require(0 < len(rendered) <= 512 and not any(ord(c) < 32 or ord(c) == 127 for c in rendered),
                'renamed_node_tag')
        return rendered, display_type
    return name, ''


def node_identity(node):
    payload = {k: v for k, v in node.items() if k != 'tag'}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def collect_subscriptions(s, fetcher, converter, loader=None):
    nodes, metadata, reports, seen, tags = [], {}, [], set(), set()
    for index, source in enumerate(subscription_sources(s), 1):
        stage = 'fetch'
        try:
            if loader is None:
                data = fetcher(source)
                stage = 'convert'
                converted = converter(data)
                report = {'source': source['name'], 'status': 'ok', 'nodes': len(converted)}
            else:
                converted, report = loader(source)
        except Exception as exc:
            LOG.warning('subscription source=%d stage=%s failed class=%s', index, stage, type(exc).__name__)
            reports.append({'source': source['name'], 'status': 'failed', 'stage': stage})
            continue
        reports.append(report)
        for raw in converted:
            node = copy.deepcopy(raw)
            original = node['tag']
            identity = (node_identity(node), original)
            if identity in seen:
                continue
            seen.add(identity)
            tag, suffix = original, 1
            while tag in tags:
                suffix += 1
                tag = f'{original} [source-{index}-{suffix}]'
            tags.add(tag)
            node['tag'] = tag
            nodes.append(node)
            metadata[tag] = {'original': original, 'rename_rules': source['rename_rules']}
    if s['manual_nodes']:
        extra = converter(('\n'.join(s['manual_nodes']) + '\n').encode())
        require(len(extra) == len(s['manual_nodes']), 'manual_node_rejected')
        merged = merge_nodes(nodes, extra)
        for node, raw in zip(merged[len(nodes):], extra):
            # Manual names use the CURRENT shared rule even when the feed is cached.
            metadata[node['tag']] = {'original': raw['tag']}
        nodes = merged
    require(nodes or s.get('own_hy2') is not None, 'all_subscriptions_failed')
    return nodes, metadata, reports


def node_endpoint(node):
    """One escaped, credential-free endpoint for local diagnostics."""
    return json.dumps(scrub(str(node.get('server', ''))), ensure_ascii=True)


def node_fingerprint(node):
    """Stable short ID for a converted outbound; omit its mutable display tag."""
    payload = {key: value for key, value in node.items() if key != 'tag'}
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(canonical).hexdigest()[:12]


def node_log_tag(node):
    """Keep the client-facing tag unchanged; annotate only its log representation."""
    return f"{node['tag']}@{node_fingerprint(node)}"


def trace_probe(node, target, result, status='-', size='-', elapsed='-', curl_exit='-'):
    LOG.debug('probe target=%s tag=%s result=%s http=%s bytes=%s ms=%s curl_exit=%s',
              target, node_log_tag(node), result, status, size, elapsed, curl_exit)


def diagnose_report(settings_path=None, fetcher=None):
    """Safe to print: no secrets, proxy values reported as set/unset only."""
    lines = []
    proxy_keys = ('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy')
    lines.append('--- container proxy environment (values hidden) ---')
    lines.append(json.dumps({k: ('set' if os.environ.get(k) else 'unset') for k in proxy_keys}))
    lines.append('--- live subscription fetch (uses this container network) ---')
    try:
        s = load_settings(settings_path or SETTINGS_PATH)['shared']
    except Exception as exc:
        lines.append('settings unusable: ' + type(exc).__name__ + ': ' +
                     (str(exc) if isinstance(exc, Invalid) else 'load_failed'))
    else:
        for index, source in enumerate(subscription_sources(s), 1):
            if source['update_policy'] == 'startup':
                lines.append(f'source {index} skipped: startup-only policy; diagnostics never reopen this feed')
                continue
            start = time.monotonic()
            try:
                data = (fetcher or fetch)(source)
            except Exception as exc:
                # Static source index and exception class; never reflect an URL.
                lines.append(f'source {index} fetch failed: ' + type(exc).__name__)
            else:
                lines.append(f'source {index} fetch ok: bytes={len(data)} seconds={time.monotonic() - start:.1f}')
    lines.append('--- recent failures live in the container log ---')
    lines.append('docker compose logs --tail=100 config')
    return '\n'.join(lines) + '\n'


def check_profile(profile, core=CORE):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / 'check.json'
        p.write_bytes(encode(profile))
        checked([core, 'check', '-c', str(p)])


def fetch(s, attempts=3, backoff=(1, 3)):
    """Subscription fetch with bounded retries: the inherited proxy path drops connections."""
    request = urllib.request.Request(s['subscription_url'], headers={'User-Agent': s['subscription_user_agent']})
    # urllib inherits standard HTTP(S)_PROXY; no subscription is handed to a third-party converter.
    last = None
    for attempt in range(1, attempts + 1):
        start = time.monotonic()
        try:
            if s.get('subscription_fetch_method', 'urllib') == 'curl':
                config = 'url = "' + s['subscription_url'].replace('\\', '\\\\').replace('"', '\\"') + '"\n'
                command = ['curl', '--disable', '--globoff', '--silent', '--fail', '--location',
                           '--proto', '=https', '--proto-redir', '=https',
                           '--max-time', '30', '--max-filesize', str(LIMIT),
                           '--write-out', '\n%{http_code}', '--config', '-']
                if s['subscription_user_agent']:
                    command += ['--user-agent', s['subscription_user_agent']]
                result = subprocess.run(command, input=config.encode(), capture_output=True, timeout=35)
                data, separator, status = result.stdout.rpartition(b'\n')
                require(bool(separator) and len(status) == 3 and status.isdigit(), 'subscription_fetch_failed')
                require(result.returncode == 0 and 200 <= int(status) < 300, 'subscription_fetch_failed')
            else:
                with urllib.request.urlopen(request, timeout=30) as r:
                    require(urllib.parse.urlsplit(r.url).scheme == 'https', 'subscription_redirect_https')
                    data = r.read(LIMIT + 1)
            require(0 < len(data) <= LIMIT, 'subscription_size')
            if attempt > 1:
                LOG.info('fetch recovered attempt=%d elapsed=%.1fs', attempt, time.monotonic() - start)
            return data
        except Exception as exc:
            if isinstance(exc, Invalid) and str(exc) != 'subscription_fetch_failed':
                raise  # Settings and payload problems do not improve on a retry.
            last = exc
            LOG.warning('fetch attempt %d/%d failed after %.1fs: %s',
                        attempt, attempts, time.monotonic() - start, type(exc).__name__)
            if attempt < attempts:
                time.sleep(backoff[min(attempt - 1, len(backoff) - 1)])
    raise last


def convert(data, converter=CONVERTER):
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / 'subscription'
        output = Path(tmp) / 'nodes.json'
        source.write_bytes(data)
        result = checked([converter, str(source), '--only-nodes', '--out', str(output)], 60)
        require(b'warning' not in result.stderr.lower(), 'conversion_warning')
        obj = json.loads(output.read_bytes())
    nodes = obj if isinstance(obj, list) else obj.get('outbounds')
    require(isinstance(nodes, list) and nodes, 'no_nodes')
    allowed = {'shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'socks', 'http'}
    result = []
    for n in nodes:
        require(isinstance(n, dict) and n.get('type') in allowed and isinstance(n.get('tag'), str), 'unsupported_node')
        require('detour' not in n and 'domain_resolver' not in n, 'dependent_node')
        # Subscription data cannot introduce routes, resolver choices or outbound groups.
        node = copy.deepcopy(n)
        require(isinstance(node.get('server'), str) and node['server'], 'node_server')
        result.append(node)
    return result


def probe(node, s, core=CORE, url=PROBE_URL, expected_status=204):
    """Check the exact HTTP response through this outbound, on the container network."""
    return _http_probe(node, s, core, url, expected_status, 0 if expected_status == 204 else None)


def probe_cachefly(node, s, core=CORE):
    """Download and verify a bounded CacheFly range through the candidate node."""
    return _http_probe(node, s, core, CACHEFLY_URL, 206, CACHEFLY_BYTES,
                       CACHEFLY_SHA256, f'0-{CACHEFLY_BYTES - 1}')


def _http_probe(node, s, core, url, expected_status, expected_bytes=None,
                expected_sha256=None, byte_range=None):
    target = 'google' if expected_status == 204 else 'cachefly' if expected_status == 206 else 'custom'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    # The bootstrap DoH bypasses the tested node: resolving the node's own hostname
    # through that node would be circular, and plain DNS would leak every lookup.
    p = {'log': {'disabled': True},
         'dns': {'servers': [bootstrap_dns('direct')]},
         'inbounds': [{'type': 'http', 'listen': '127.0.0.1', 'listen_port': port}],
         'outbounds': [node, {'type': 'direct', 'tag': 'direct', 'domain_resolver': 'bootstrap'}],
         'route': {'final': node['tag'], 'default_domain_resolver': 'bootstrap'}}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'probe.json'
        path.write_bytes(encode(p))
        proc = subprocess.Popen([core, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while True:
                if proc.poll() is not None or time.monotonic() >= deadline:
                    trace_probe(node, target, 'core_start_failed')
                    return None
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            # Explicit proxy and noproxy prevent environment proxy/bypass leakage.
            output = Path(tmp) / 'response'
            args = ['curl', '--silent', '--fail', '--output', str(output),
                    '--write-out', '%{http_code} %{size_download} %{time_total}',
                    '--proxy', f'http://127.0.0.1:{port}', '--noproxy', '',
                    '--max-time', str(s['probe_timeout_seconds']),
                    '--max-filesize', str(expected_bytes if expected_bytes else 1024)]
            if byte_range is not None:
                args += ['--range', byte_range]
            r = subprocess.run(args + [url], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=s['probe_timeout_seconds'] + 2)
            fields = r.stdout.decode('ascii').split()
            status = fields[0] if len(fields) == 3 else '-'
            size = fields[1] if len(fields) == 3 else '-'
            if r.returncode != 0:
                trace_probe(node, target, 'curl_failed', status, size, curl_exit=r.returncode)
                return None
            status, size, seconds = fields
            if int(status) != expected_status:
                trace_probe(node, target, 'http_status', status, size)
                return None
            if expected_bytes is not None and (int(size) != expected_bytes or output.stat().st_size != expected_bytes):
                trace_probe(node, target, 'body_size', status, size)
                return None
            if expected_sha256 is not None and hashlib.sha256(output.read_bytes()).hexdigest() != expected_sha256:
                trace_probe(node, target, 'body_sha256', status, size)
                return None
            elapsed = round(float(seconds) * 1000, 3)
            trace_probe(node, target, 'ok', status, size, elapsed)
            return elapsed
        except subprocess.TimeoutExpired:
            trace_probe(node, target, 'process_timeout')
            return None
        except (OSError, ValueError, UnicodeError):
            trace_probe(node, target, 'invalid_response_or_io')
            return None
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def select(nodes, s, measure=probe, checker=check_profile, measure_download=None, metadata=None):
    """Verify every candidate; the default selector is not truncated by top_k."""
    if measure_download is None:
        measure_download = probe_cachefly if measure is probe else measure
    metadata = metadata or {}
    groups = {'hk': [], 'sg': [], 'other': []}
    patterns = {g: re.compile(s[g + '_pattern']) for g in ('hk', 'sg')}
    labels, counters, used, region_of = {}, {}, {'direct', 'proxy', 'sg', 'hk-own-hy2', 'wg-ipv6'}, {}
    for node in nodes:
        meta = metadata.get(node['tag'], {})
        original = meta.get('original', node['tag'])
        regions = [g for g, pattern in patterns.items() if pattern.search(original)]
        require(len(regions) <= 1, 'ambiguous_region')
        group = regions[0] if regions else 'other'
        n = copy.deepcopy(node)
        n['tag'] = f'{group}-{len(groups[group]) + 1:03d}'
        name, kind = rename_node(original, meta.get('rename_rules', s.get('rename_rules', [])), counters)
        base, suffix = name, 1
        while name in used:
            suffix += 1
            name = f'{base} [{suffix}]'
        require(0 < len(name) <= 512 and not any(ord(c) < 32 or ord(c) == 127 for c in name),
                'renamed_node_tag')
        used.add(name)
        labels[n['tag']] = (name, kind)
        region_of[n['tag']] = group
        groups[group].append(n)
        LOG.debug('candidate result=included region=%s tag=%s endpoint=%s port=%s protocol=%s',
                  group, node_log_tag(n), node_endpoint(n), n.get('server_port'), n.get('type'))
    require(groups['sg'] or 'singapore' not in features(s), 'singapore_unavailable')
    candidates = groups['hk'] + groups['sg'] + groups['other']
    require(len(candidates) <= s['max_candidates'], 'candidate_limit')
    own = (dict(copy.deepcopy(s['own_hy2']), type='hysteria2', tag='hk-own-hy2')
           if s['own_hy2'] is not None else None)
    checker({'dns': {'servers': [bootstrap_dns()]}, 'outbounds': candidates + ([own] if own else []),
             'route': {'default_domain_resolver': 'bootstrap'}})

    def measured(fn, node):
        try:
            return fn(node, s)
        except Exception as exc:
            LOG.warning('probe failed node_id=%s class=%s', node_fingerprint(node), type(exc).__name__)
            return None

    with ThreadPoolExecutor(max_workers=s['probe_workers']) as pool:
        google = list(pool.map(lambda n: measured(measure, n), candidates))
        google_times = dict(zip([n['tag'] for n in candidates], google))
        google_ok = [n for n in candidates if google_times[n['tag']] is not None]
        downloads = list(pool.map(lambda n: measured(measure_download, n), google_ok))
    download_times = dict(zip([n['tag'] for n in google_ok], downloads))
    verified = []
    for node in candidates:
        tag = node['tag']
        LOG.debug('google tag=%s result=%s ms=%s', node_log_tag(node),
                  'ok' if google_times[tag] is not None else 'failed', google_times[tag])
        if google_times[tag] is None:
            reason = 'google_failed'
        elif download_times.get(tag) is None:
            reason = 'cachefly_failed'
        else:
            score = .6 * google_times[tag] + .4 * download_times[tag]
            verified.append((score, tag, node))
            reason = 'selected'
            LOG.debug('cachefly tag=%s result=ok ms=%s score_ms=%.3f',
                      node_log_tag(node), download_times[tag], score)
        region = region_of[tag]
        LOG.debug('decision region=%s tag=%s result=%s', region, node_log_tag(node), reason)
    verified.sort(key=lambda item: (item[0], item[1]))
    healthy = [n for _, _, n in verified]
    chosen = {'all': healthy, 'hk': [], 'sg': []}
    counts = {}
    for group, values in groups.items():
        tags = {n['tag'] for n in values}
        good = [n for n in healthy if n['tag'] in tags]
        if group in ('hk', 'sg'):
            chosen[group] = good[:s['top_k']]
        counts[group] = {'tested': len(values), 'healthy': len(good),
                         'retained': len(chosen[group]) if group in chosen else len(good)}
        (LOG.info if good else LOG.warning)('region %s: tested=%d verified=%d default_retained=%d',
                                           group, len(values), len(good), len(good))
    # SG routing is never replaced by another country, even if default remains usable.
    require(chosen['sg'] or 'singapore' not in features(s), 'singapore_unavailable')
    fallback = not chosen['hk']
    own_google = measured(measure, own) if own else None
    own_download = measured(measure_download, own) if own_google is not None else None
    own_healthy = own_download is not None
    LOG.debug('decision region=hk tag=%s result=%s google_ms=%s cachefly_ms=%s',
              node_log_tag(own) if own else 'disabled', 'selected' if own_healthy else 'failed', own_google, own_download)
    if own_healthy:
        chosen['all'] = healthy + [own]
        chosen['hk'].append(own)
    # Keep subscription-region counts disjoint from the independently probed own node.
    counts['own_hy2'] = {'tested': int(own is not None), 'healthy': int(own_healthy), 'retained': int(own_healthy)}
    counts['all'] = {'tested': len(candidates) + int(own is not None), 'healthy': len(chosen['all']),
                     'retained': len(chosen['all'])}
    require(chosen['all'] or 'proxy' not in features(s), 'proxy_unavailable')
    labels['hk-own-hy2'] = ('hk-own-hy2', '自建')
    # Region classification and probing use the original names; rename once after
    # selection, sharing the same node objects between selectors (no extra fields).
    kinds = {}
    for node in chosen['all']:
        name, kind = labels[node['tag']]
        node['tag'] = name
        kinds[kind or '未分类'] = kinds.get(kind or '未分类', 0) + 1
    return chosen, {'counts': counts, 'hk_fallback': fallback and own_healthy,
                    'own_hy2_healthy': own_healthy, 'display_types': kinds}


def merge_nodes(nodes, extra):
    """Append manual nodes, keeping tags unique so region matching stays unambiguous."""
    seen = {n['tag'] for n in nodes}
    merged = list(nodes)
    for index, node in enumerate(extra, 1):
        candidate = copy.deepcopy(node)
        base, suffix = candidate['tag'], index
        while candidate['tag'] in seen:
            candidate['tag'] = f"{base} -m{suffix}"
            suffix += 1
        seen.add(candidate['tag'])
        merged.append(candidate)
    return merged


def rule_items(rules):
    # Separate source rules make domain/IP alternatives OR, never AND.
    return [{key: values} for key, values in rules.items() if values]


def proxy_options(query):
    """Validate subscription URL options without ever reflecting supplied values."""
    require(set(query) <= {'key', 'port', 'user', 'password', 'listen'}, 'invalid_query_parameter')
    require(all(len(values) == 1 for values in query.values()), 'duplicate_query_parameter')
    port = query.get('port', ['10808'])[0]
    require(bool(re.fullmatch(r'[0-9]{1,5}', port)) and 1 <= int(port) <= 65535, 'invalid_proxy_port')
    listen = query.get('listen', ['127.0.0.1'])[0]
    try:
        ipaddress.ip_address(listen)
    except ValueError:
        raise Invalid('invalid_proxy_listen') from None
    user, password = query.get('user', [''])[0], query.get('password', [''])[0]
    require(bool(user) == bool(password), 'proxy_credentials_pair_required')
    require(len(user) <= 128 and len(password) <= 256 and
            not any(ord(c) < 33 or ord(c) == 127 for c in user + password), 'invalid_proxy_credentials')
    inbound = {'type': 'mixed', 'tag': 'mixed-in', 'listen': listen, 'listen_port': int(port)}
    if user:
        inbound['users'] = [{'username': user, 'password': password}]
    return inbound


def remote_set(tag, url):
    return {'type': 'remote', 'tag': tag, 'format': 'binary', 'url': url,
            'http_client': {'detour': 'proxy'}, 'update_interval': '7d'}


def validate_public_base_url(url):
    require(isinstance(url, str) and len(url) <= 512 and not any(c in url for c in '\\ ?#\r\n\t'),
            'invalid_public_base_url')
    try:
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == 'https' and parsed.hostname and parsed.port != 0 and
                parsed.username is None and parsed.password is None and
                not parsed.query and not parsed.fragment and
                re.fullmatch(r'(?:/[A-Za-z0-9._~-]+)*/?', parsed.path) and
                all(segment not in ('.', '..') for segment in parsed.path.split('/')),
                'invalid_public_base_url')
    except ValueError:
        raise Invalid('invalid_public_base_url') from None
    return url.rstrip('/')


def foreign_rule_url(host, key, public_base_url=None):
    """Use the configured public base, falling back to the subscription host."""
    if public_base_url is not None:
        return validate_public_base_url(public_base_url) + '/api/rules/geoip-foreign.srs?' + urllib.parse.urlencode({'key': key})
    require(isinstance(host, str) and len(host) <= 253 and
            not any(c in host for c in '/?#@\\\r\n\t '), 'invalid_request_host')
    try:
        parsed = urllib.parse.urlsplit('//' + host)
        require(parsed.hostname and parsed.netloc == host and
                (parsed.port is None or 1 <= parsed.port <= 65535), 'invalid_request_host')
    except ValueError:
        raise Invalid('invalid_request_host') from None
    scheme = 'http' if parsed.hostname in ('localhost', '127.0.0.1', '::1') else 'https'
    return f'{scheme}://{host}/api/rules/geoip-foreign.srs?' + urllib.parse.urlencode({'key': key})


def variant_profile(base, mode, full, inbound, foreign_url=None):
    """full=None preserves the client's independently composed ingress and WG.

    Boolean full is the legacy URL adapter. It may remove WG/TUN, never add a
    capability absent from the compiled base. DNS and proxy remain optional.
    """
    require(mode in ('global', 'blacklist', 'whitelist'), 'invalid_mode')
    if full is True:
        require(bool(base.get('endpoints')), 'wireguard_not_configured')
    p = copy.deepcopy(base)
    has_proxy = any(o['tag'] == 'proxy' and o['type'] == 'selector' for o in p['outbounds'])
    require(mode == 'global' or has_proxy, 'mode_requires_proxy')
    dns_enabled = any(r.get('action') == 'hijack-dns' for r in base['route']['rules'])
    if full is False:
        p.pop('endpoints', None)
        p['inbounds'] = []
    if inbound is not None:
        p['inbounds'].append(inbound)
    sets = p['route']['rule_set']
    if mode != 'global':
        sets.extend([remote_set('geoip-cn', GEOIP_CN_URL), remote_set('geosite-cn', GEOSITE_CN_URL)])
    if mode == 'whitelist':
        sets.append(remote_set('geosite-foreign', GEOSITE_FOREIGN_URL))
        require(foreign_url, 'foreign_rule_url_required')
        sets.append(remote_set('geoip-foreign', foreign_url))
    tags = {item['tag'] for item in sets}
    policy = []
    if p.get('endpoints'):
        policy.append({'ip_cidr': [OVERLAY], 'action': 'route', 'outbound': 'wg-ipv6'})
    if 'force-direct' in tags:
        policy.append({'rule_set': ['force-direct'], 'action': 'route', 'outbound': 'direct'})
    if mode in ('blacklist', 'whitelist'):
        policy.append({'rule_set': ['geoip-cn', 'geosite-cn'], 'action': 'route', 'outbound': 'direct'})
    if 'singapore' in tags:
        policy.append({'rule_set': ['singapore'], 'action': 'route', 'outbound': 'sg'})
    if mode == 'whitelist':
        policy.append({'rule_set': ['geoip-foreign', 'geosite-foreign'], 'action': 'route', 'outbound': 'proxy'})
    p['route']['final'] = 'proxy' if has_proxy and mode != 'whitelist' else 'direct'
    dns_actions = [{'protocol': 'dns', 'action': 'hijack-dns'}] if dns_enabled else []
    p['route']['rules'] = [{'action': 'sniff', 'sniffer': ['http', 'tls', 'quic', 'dns']}] + hosts_resolve_rules(p['dns']) + copy.deepcopy(policy) + dns_actions + [{'action': 'resolve'}] + policy
    if dns_enabled and mode == 'blacklist':
        p['dns']['rules'].insert(len(hosts_resolve_rules(p['dns'])), {'rule_set': ['geosite-cn'], 'action': 'route', 'server': 'bootstrap'})
    if dns_enabled and mode == 'whitelist':
        p['dns']['rules'].append({'rule_set': ['geosite-foreign'], 'action': 'route', 'server': 'dns-proxy'})
        p['dns']['final'] = 'bootstrap'
    return p


def hosts_resolve_rules(dns):
    # Resolve proxy domain requests before a terminating domain-based route.
    for server in dns['servers']:
        if server['tag'] == 'dns-hosts':
            return [{'domain': list(server['predefined']), 'action': 'resolve',
                     'server': 'dns-hosts'}]
    return []


def build_profile(s, chosen):
    enabled = features(s)
    all_nodes = chosen.get('all', chosen['hk'] + chosen['sg'])
    nodes = copy.deepcopy(all_nodes if 'proxy' in enabled else chosen['sg'] if 'singapore' in enabled else [])
    outbounds = [{'type': 'direct', 'tag': 'direct', 'domain_resolver': 'bootstrap'}] + nodes
    for tag, kind, values in [('proxy', 'proxy', nodes), ('sg', 'singapore', chosen['sg'])]:
        if kind not in enabled:
            continue
        tags = list(dict.fromkeys(n['tag'] for n in values))
        require(tags, 'singapore_unavailable' if tag == 'sg' else 'proxy_unavailable')
        default = chosen['hk'][0]['tag'] if tag == 'proxy' and chosen['hk'] else tags[0]
        outbounds.append({'type': 'selector', 'tag': tag, 'outbounds': tags, 'default': default})
    sets, policy = [], []
    w = s.get('wireguard') if 'wireguard' in enabled else None
    if w is not None:
        policy.append({'ip_cidr': [OVERLAY], 'action': 'route', 'outbound': 'wg-ipv6'})
    for kind, name, tag in [('direct', 'direct', 'force-direct'), ('singapore', 'singapore', 'singapore')]:
        if kind in enabled and (kind == 'direct' or rule_items(s[name])):
            sets.append({'type': 'inline', 'tag': tag, 'rules': rule_items(s[name])})
            policy.append({'rule_set': [tag], 'action': 'route', 'outbound': 'direct' if kind == 'direct' else 'sg'})
    hosts = validate_dns_hosts(s.get('dns_hosts', {})) if 'dns' in enabled else {}
    servers = ([{'type': 'hosts', 'tag': 'dns-hosts', 'predefined': hosts}] if hosts else [])
    dns_rules = ([{'domain': list(hosts), 'action': 'route', 'server': 'dns-hosts'}] if hosts else [])
    servers.append(bootstrap_dns('direct'))
    if 'dns' in enabled:
        for kind, target in [('proxy', 'dns-proxy'), ('singapore', 'dns-sg')]:
            if kind in enabled:
                servers.append({'type': 'https', 'tag': target, 'server': '1.1.1.1',
                                'path': '/dns-query', 'detour': 'proxy' if kind == 'proxy' else 'sg'})
        for name, target in [('direct', 'bootstrap'), ('singapore', 'dns-sg')]:
            if name in enabled:
                for key in ('domain', 'domain_suffix', 'domain_regex'):
                    if s[name].get(key):
                        dns_rules.append({key: s[name][key], 'action': 'route', 'server': target})
    dns = {'servers': servers, 'rules': dns_rules,
           'final': 'dns-proxy' if {'dns', 'proxy'} <= enabled else 'bootstrap'}
    ingress = s.get('ingress', 'both' if w is not None else 'mixed')
    return {
        'log': {'level': 'warn'}, 'dns': dns,
        'inbounds': ([{'type': 'tun', 'tag': 'tun-in', 'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
                      'auto_route': True, 'strict_route': True, 'stack': 'mixed'}] if ingress in ('tun', 'both') else []),
        'endpoints': ([{'type': 'wireguard', 'tag': 'wg-ipv6', 'system': False,
                       'address': [str(ipaddress.ip_interface(w['address']))],
                       'private_key': w['private_key'], 'mtu': w['mtu'],
                       'domain_resolver': {'server': 'bootstrap', 'strategy': 'ipv6_only'},
                       'peers': [{'address': w['endpoint'], 'port': w['port'],
                                  'public_key': w['peer_public_key'], 'allowed_ips': [OVERLAY],
                                  'persistent_keepalive_interval': 25}]}] if w is not None else []),
        'outbounds': outbounds,
        'route': {'auto_detect_interface': True, 'default_domain_resolver': 'bootstrap',
                  'rule_set': sets, 'final': 'proxy' if 'proxy' in enabled else 'direct',
                  'rules': [{'action': 'sniff', 'sniffer': ['http', 'tls', 'quic', 'dns']}] +
                           hosts_resolve_rules(dns) + copy.deepcopy(policy) +
                           ([{'protocol': 'dns', 'action': 'hijack-dns'}] if 'dns' in enabled else []) +
                           [{'action': 'resolve'}] + policy}
    }


def client_variant(base, settings, inbound=None, foreign_url=None):
    ingress = settings.get('ingress', 'both' if settings.get('wireguard') else 'mixed')
    return variant_profile(base, settings.get('mode', 'global'), None,
                           (inbound or proxy_options({})) if ingress != 'tun' else None, foreign_url)


def validate_profile_variants(profile, settings, checker):
    checker(profile)
    example = 'https://example.invalid/api/rules/geoip-foreign.srs'
    checker(client_variant(profile, settings, foreign_url=example))
    for mode, full in set(CONFIG_PATHS.values()):
        if (full and not profile.get('endpoints')) or (mode != 'global' and 'proxy' not in features(settings)):
            continue
        checker(variant_profile(profile, mode, full, proxy_options({}), example))


def client_contract(settings):
    fields = ('features', 'mode', 'ingress', 'wireguard', 'direct', 'singapore', 'dns_hosts')
    return hashlib.sha256(encode({k: settings.get(k) for k in fields})).hexdigest()


class Publisher:
    def __init__(self, settings, snapshot, fetcher=fetch, converter=convert, measure=probe,
                 checker=check_profile, clock=time.monotonic, measure_download=None):
        self.settings, self.snapshot = Path(settings), Path(snapshot)
        self.fetcher, self.converter, self.measure, self.checker = fetcher, converter, measure, checker
        self.lock = threading.Lock()
        self.data = None
        self.error = None
        self.stage = 'startup'
        self.updated = None
        self.summary = None
        self.clock = clock
        self.measure_download = measure_download
        self.source_cache_path = self.snapshot.with_name(self.snapshot.name + '.sources.json')
        self._source_cache = None
        self._source_attempts = {}
        self._startup_closed = False
        self._source_errors = set()
        self.source_status = []
        self.profile_contracts = {}
        self.refresh_lock = threading.Lock()
        self._probe_cache = {}
        self._probe_lock = threading.Lock()

    def cached_probe(self, target, fn, node, settings, force=False):
        # Use full endpoint/credential/transport identity, never a renamed tag.
        key = (target, node_identity(node), settings['probe_timeout_seconds'], BOOTSTRAP_DOH)
        interval = settings.get('probe_interval_seconds', settings['refresh_seconds'])
        with self._probe_lock:
            cached = self._probe_cache.get(key)
        if not force and cached is not None and self.clock() - cached[0] < interval:
            return cached[1]  # Negative results have the same bounded retry interval.
        try:
            result = fn(node, settings)
        except Exception as exc:
            LOG.warning('probe failed node_id=%s class=%s', node_fingerprint(node), type(exc).__name__)
            result = None
        with self._probe_lock:
            self._probe_cache[key] = (self.clock(), result)
        return result

    def load_source_cache(self):
        if self._source_cache is not None:
            return
        self._source_cache = {}
        try:
            path = self.source_cache_path
            st = path.stat()
            require(st.st_uid == os.getuid() and st.st_mode & 0o077 == 0 and st.st_size <= 64 * LIMIT,
                    'source_cache_permissions')
            data = json.loads(path.read_bytes())
            require(data.get('version') == 1 and isinstance(data.get('sources'), dict), 'source_cache_version')
            for key, entry in data['sources'].items():
                require(re.fullmatch(r'[a-f0-9]{64}', key) and set(entry) == {'nodes', 'fetched_at'}, 'source_cache_entry')
                require(isinstance(entry['nodes'], list) and entry['nodes'] and
                        type(entry['fetched_at']) is int, 'source_cache_entry')
                self.check_source_nodes(entry['nodes'])
            self._source_cache = data['sources']
        except FileNotFoundError:
            pass
        except Exception:
            LOG.warning('source cache rejected; a successful fetch is required')

    def check_source_nodes(self, nodes):
        require(isinstance(nodes, list) and nodes and len(nodes) <= 5000, 'subscription_empty_or_large')
        require(all(isinstance(n, dict) and isinstance(n.get('tag'), str) and n.get('tag')
                    and isinstance(n.get('type'), str) and n.get('type') not in ('selector', 'urltest', 'direct', 'block', 'dns')
                    for n in nodes), 'subscription_nodes')
        self.checker({'dns': {'servers': [bootstrap_dns()]}, 'outbounds': nodes,
                      'route': {'default_domain_resolver': 'bootstrap'}})

    @staticmethod
    def source_key(source):
        # Names and credentials bind a cache entry. Presentation and scheduling
        # changes must not force a closed startup feed to be fetched again.
        fields = ('name', 'subscription_url', 'subscription_user_agent', 'subscription_fetch_method')
        return hashlib.sha256(encode({k: source[k] for k in fields})).hexdigest()

    def source_nodes(self, source, force=False):
        self.load_source_cache()
        key = self.source_key(source)
        policy = source['update_policy']
        attempt = self._source_attempts.get(key)
        due = ((policy == 'startup' and not self._startup_closed and attempt is None) or
               (policy == 'poll' and (attempt is None or force or
                self.clock() - attempt >= source['interval_seconds'])))
        cached = self._source_cache.get(key)
        status = 'cached' if cached else 'pending_restart'
        if due:
            self._source_attempts[key] = self.clock()  # Failed attempts are rate-limited too.
            try:
                converted = self.converter(self.fetcher(source))
                self.check_source_nodes(converted)
                entry = {'nodes': converted, 'fetched_at': int(time.time())}
                updated = dict(self._source_cache, **{key: entry})
                atomic_write(self.source_cache_path, encode({'version': 1, 'sources': updated}))
                self._source_cache, cached = updated, entry
                self._source_errors.discard(key)
                status = 'ok'
            except Exception as exc:
                self._source_errors.add(key)
                LOG.warning('source refresh failed source=%s class=%s cached=%s',
                            source['name'], type(exc).__name__, cached is not None)
        if key in self._source_errors:
            status = 'stale' if cached else 'failed'
        report = {'source': source['name'], 'status': status, 'update_policy': policy,
                  'nodes': len(cached['nodes']) if cached else 0,
                  'fetched_at': cached['fetched_at'] if cached else None}
        self.source_status.append(report)
        require(cached is not None, 'source_unavailable')
        return copy.deepcopy(cached['nodes']), report

    def restore(self):
        try:
            s = load_settings(self.settings)
            obj = json.loads(self.snapshot.read_bytes())
            require(obj.get('version') == SNAPSHOT_VERSION, 'snapshot_version_changed')
            require(obj['fingerprint'] == hashlib.sha256(encode(s)).hexdigest(), 'snapshot_settings_changed')
            devices = device_settings(s)
            require(set(obj['profiles']) == set(devices), 'snapshot_devices_changed')
            for ident, profile in obj['profiles'].items():
                validate_profile_variants(profile, devices[ident], self.checker)
            self.profile_contracts = {ident: client_contract(st) for ident, st in devices.items()}
            with self.lock:
                self.data, self.updated, self.summary = {k: encode(v) for k, v in obj['profiles'].items()}, obj['updated'], obj['summary']
                self.source_status = copy.deepcopy(self.summary.get('sources', []))
                self.stage = 'restored'
                self.error = 'subscription_refresh_degraded' if any(r['status'] in ('failed', 'stale', 'pending_restart') for r in self.source_status) else None
        except Exception:
            pass  # Never serve an unvalidated or mismatched snapshot.

    def refresh(self, force_fetch=True, force_probe=True):
        # Startup-at-most-once also holds under concurrent refresh callers.
        with self.refresh_lock:
            try:
                return self._refresh(force_fetch, force_probe)
            finally:
                self._startup_closed = True

    def _refresh(self, force_fetch, force_probe):
        stage = 'settings'
        s = None
        try:
            s = load_settings(self.settings)
            devices = device_settings(s)
            shared = s['shared']
            stage = 'subscriptions'
            self.source_status = []
            needed = set().union(*(features(st) for st in devices.values()))
            selection_settings = dict(next(iter(devices.values())), features=sorted(needed))
            if needed & {'proxy', 'singapore'}:
                self.load_source_cache()
                active_keys = {self.source_key(src) for src in subscription_sources(shared)}
                self._source_cache = {k: v for k, v in self._source_cache.items() if k in active_keys}
                nodes, metadata, sources = collect_subscriptions(shared, self.fetcher, self.converter,
                    loader=lambda source: self.source_nodes(source, force_fetch))
                # Preserve the publication if every polling source failed; a startup
                # source's successful cache remains a usable catalog across restarts.
                require(not sources or any(r['status'] in ('ok', 'cached') or r.get('update_policy') == 'startup'
                            for r in sources), 'all_subscriptions_failed')
                identities = {node_identity(n) for n in nodes}
                if shared['own_hy2'] is not None:
                    identities.add(node_identity(dict(shared['own_hy2'], type='hysteria2')))
                with self._probe_lock:
                    self._probe_cache = {k: v for k, v in self._probe_cache.items() if k[1] in identities}
                stage = 'select'
                chosen, summary = select(nodes, selection_settings,
                    lambda n, st: self.cached_probe('google', self.measure, n, st, force_probe), self.checker,
                    measure_download=lambda n, st: self.cached_probe('cachefly', self.measure_download or
                        (probe_cachefly if self.measure is probe else self.measure), n, st, force_probe),
                    metadata=metadata)
            else:
                chosen = {'all': [], 'hk': [], 'sg': []}
                summary = {'counts': {g: {'tested': 0, 'healthy': 0, 'retained': 0}
                                      for g in ('hk', 'sg', 'other', 'own_hy2', 'all')},
                           'hk_fallback': False, 'own_hy2_healthy': False, 'display_types': {}}
                sources = []
            summary['sources'] = sources
            summary['probe_interval_seconds'] = shared.get('probe_interval_seconds', shared['refresh_seconds'])
            stage = 'check'
            profiles = {ident: build_profile(settings, chosen) for ident, settings in devices.items()}
            for ident, profile in profiles.items():
                validate_profile_variants(profile, devices[ident], self.checker)
            stage = 'publish'
            updated = int(time.time())
            snapshot = {'version': SNAPSHOT_VERSION, 'fingerprint': hashlib.sha256(encode(s)).hexdigest(), 'profiles': profiles,
                        'updated': updated, 'summary': summary}
            atomic_write(self.snapshot, encode(snapshot))
            with self.lock:
                self.data, self.updated, self.summary = {k: encode(v) for k, v in profiles.items()}, updated, summary
                self.profile_contracts = {ident: client_contract(st) for ident, st in devices.items()}
                self.error = 'subscription_refresh_degraded' if any(r['status'] in ('failed', 'stale', 'pending_restart') for r in self.source_status) else None
                self.stage = 'ready'
            counts = summary['counts']
            LOG.info('published hk_retained=%s hk_tested=%s sg_retained=%s sg_tested=%s fallback=%s own_hy2_healthy=%s',
                     counts['hk']['retained'], counts['hk']['tested'],
                     counts['sg']['retained'], counts['sg']['tested'], summary['hk_fallback'], summary['own_hy2_healthy'])
            return True
        except Exception as exc:
            code = str(exc) if isinstance(exc, Invalid) else 'operation_failed'
            detail = '' if isinstance(exc, Invalid) else ' | ' + type(exc).__name__ + ': ' + scrub(str(exc), s)
            LOG.error('refresh failed stage=%s error=%s%s', stage, code, detail)
            with self.lock:
                # Only the static code is exposed through the API.
                self.error = code
                self.stage = stage
            return False

    def status(self):
        with self.lock:
            return {'ready': self.data is not None, 'stale': self.error is not None,
                    'last_success': self.updated, 'stage': self.stage, 'error': self.error,
                    'selection': self.summary, 'sources': copy.deepcopy(self.source_status)}

    def loop(self, stop):
        while not stop.is_set():
            self.refresh(force_fetch=False, force_probe=False)
            try:
                shared = load_settings(self.settings)['shared']
                interval = min([shared.get('probe_interval_seconds', shared['refresh_seconds'])] +
                               [src['interval_seconds'] for src in subscription_sources(shared)
                                if src['update_policy'] == 'poll'])
            except Exception:
                interval = 30
            stop.wait(interval)


def handler_for(publisher):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # URLs may contain credentials. No request logging.

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def reply(self, status, data, content_type='application/json'):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            if u.path == '/healthz':
                self.reply(200, encode(publisher.status()))
                return
            is_rule = u.path == '/api/rules/geoip-foreign.srs'
            if u.path not in CONFIG_PATHS and u.path != '/api/config' and not is_rule:
                self.reply(404, b'{"error":"not_found"}')
                return
            try:
                # Auth always uses the current settings, not a cached/old key.
                settings = load_settings(publisher.settings)
                query = urllib.parse.parse_qs(u.query, strict_parsing=True, keep_blank_values=True)
                header = self.headers.get('Authorization', '')
                supplied = header[7:] if header.startswith('Bearer ') else query.get('key', [''])[0]
                ident = next((d['id'] for d in settings['devices']
                              if hmac.compare_digest(d['api_key'], supplied)), None)
            except Exception:
                ident = None
            if ident is None:
                self.reply(401, b'{"error":"unauthorized"}')
                return
            if is_rule:
                if set(query) != {'key'} or len(query['key']) != 1:
                    self.reply(400, b'{"error":"invalid_query_parameter"}')
                    return
                self.reply(200, FOREIGN_RULE_PATH.read_bytes(), 'application/octet-stream')
                return
            try:
                inbound = proxy_options(query)
            except Invalid as exc:
                self.reply(400, encode({'error': str(exc)}))
                return
            effective = device_settings(settings)[ident]
            with publisher.lock:
                data = publisher.data.get(ident) if publisher.data else None
                contract = publisher.profile_contracts.get(ident)
            if data is not None and contract != client_contract(effective):
                self.reply(503, b'{"error":"client_configuration_pending"}')
                return
            if data is None:
                self.reply(503, b'{"error":"not_ready"}')
                return
            canonical = u.path == '/api/config'
            mode, full = (effective.get('mode', 'global'), None) if canonical else CONFIG_PATHS[u.path]
            base = json.loads(data)
            if full and not base.get('endpoints'):
                self.reply(409, b'{"error":"wireguard_not_configured"}')
                return
            try:
                rule_url = foreign_rule_url(self.headers.get('Host'), supplied,
                                            settings.get('public_base_url')) if mode == 'whitelist' else None
                profile = (client_variant(base, effective, inbound, rule_url) if canonical else
                           variant_profile(base, mode, full, inbound, rule_url))
            except Invalid as exc:
                self.reply(400, encode({'error': str(exc)}))
                return
            self.reply(200, encode(profile))

        def do_POST(self):
            self.reply(405, b'{"error":"method_not_allowed"}')
    return Handler


def main():
    os.umask(0o077)
    # Diagnostics go to stdout so `docker compose logs` shows them.
    level = os.environ.get('SINGBOX_LOG_LEVEL', 'INFO').upper()
    require(level in LOG_LEVELS, 'log_level')
    logging.basicConfig(stream=sys.stdout, level=LOG_LEVELS[level],
                        format='%(asctime)s %(levelname)s %(name)s %(message)s')
    if len(sys.argv) > 1 and sys.argv[1] == 'health':
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open('http://127.0.0.1:8787/healthz', timeout=3) as r:
                return 0 if json.load(r)['ready'] else 1
        except Exception:
            return 1
    if len(sys.argv) > 1 and sys.argv[1] == 'diagnose':
        sys.stdout.write(diagnose_report())
        return 0
    # Refuse a different major/minor/patch rather than validate against the wrong core.
    version = checked([CORE, 'version']).stdout.splitlines()[0].decode()
    require(version == 'sing-box version 1.14.2', 'core_version')
    LOG.info('starting: %s with %s', SETTINGS_PATH, version)
    p = Publisher(SETTINGS_PATH, SNAPSHOT_PATH)
    p.restore()
    stop = threading.Event()
    threading.Thread(target=p.loop, args=(stop,), daemon=True).start()
    server = ThreadingHTTPServer(('0.0.0.0', 8787), handler_for(p))
    try:
        server.serve_forever()
    finally:
        stop.set()
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
