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
OVERLAY = "10.77.0.0/24"
LIMIT = 8 * 1024 * 1024
# Everything goes to stdout/docker logs; nothing diagnostic is written to the host.
LOG = logging.getLogger('singbox-config-service')
LOG_LEVELS = {'DEBUG': logging.DEBUG, 'INFO': logging.INFO,
              'WARNING': logging.WARNING, 'ERROR': logging.ERROR}
# Registered when settings load, so no log line can echo them.
SECRETS = set()
SETTINGS_PATH = os.environ.get('SINGBOX_SETTINGS', '/config/settings.json')
SNAPSHOT_PATH = os.environ.get('SINGBOX_SNAPSHOT', '/state/snapshot.json')
# URI schemes accepted in settings.manual_nodes (private, never tracked).
MANUAL_SCHEMES = ("vmess://", "vless://", "trojan://", "hysteria2://", "hysteria://",
                  "tuic://", "anytls://", "ss://", "socks://", "http://")


class Invalid(ValueError):
    """Only static error identifiers may leave this module."""


def require(ok, code):
    if not ok:
        raise Invalid(code)


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


def validate(s):
    require(isinstance(s, dict), "settings_object")
    fields = {"api_key", "subscription_url", "subscription_user_agent", "top_k", "refresh_seconds",
              "probe_timeout_seconds", "probe_workers", "max_candidates", "hk_pattern", "sg_pattern",
              "direct", "singapore", "wireguard", "own_hy2", "manual_nodes"}
    require(set(s) == fields, "settings_fields")
    require(not any(isinstance(v, str) and v.startswith('<') for v in walk(s)), "unfilled_template")
    require(isinstance(s['api_key'], str) and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', s['api_key']), "api_key_format")
    u = urllib.parse.urlsplit(s['subscription_url'])
    require(u.scheme == 'https' and u.hostname and not u.username and not u.fragment, "subscription_https_required")
    require(isinstance(s['subscription_user_agent'], str) and not any(c in s['subscription_user_agent'] for c in '\r\n'), "user_agent")
    for key, lo, hi in [('top_k', 1, 50), ('refresh_seconds', 30, 86400),
                        ('probe_timeout_seconds', 2, 30), ('probe_workers', 1, 8), ('max_candidates', 2, 500)]:
        require(type(s[key]) is int and lo <= s[key] <= hi, 'invalid_' + key)
    for key in ('hk_pattern', 'sg_pattern'):
        require(isinstance(s[key], str) and 0 < len(s[key]) < 256, "region_pattern")
        re.compile(s[key])
    require(isinstance(s['manual_nodes'], list) and len(s['manual_nodes']) <= 200, 'manual_nodes_list')
    for entry in s['manual_nodes']:
        require(isinstance(entry, str) and 0 < len(entry) <= 4096, 'manual_node_entry')
        require(not any(c in entry for c in '\r\n\t'), 'manual_node_entry')
        require('://' in entry and entry.split('://', 1)[0].lower() + '://' in MANUAL_SCHEMES,
                'manual_node_scheme')
    for key in ('direct', 'singapore'):
        rules = s[key]
        require(isinstance(rules, dict) and set(rules) == {'ip_cidr', 'domain', 'domain_suffix'}, 'rule_fields')
        for field, values in rules.items():
            require(isinstance(values, list) and len(values) <= 10000, 'rule_list')
            for v in values:
                if field == 'ip_cidr':
                    ipaddress.ip_network(v, strict=False)
                else:
                    domain(v)
    w = s['wireguard']
    require(set(w) == {'address', 'private_key', 'peer_public_key', 'endpoint', 'port', 'mtu'}, 'wireguard_fields')
    address = ipaddress.ip_interface(w['address'])
    require(address.version == 4 and address.ip in ipaddress.ip_network(OVERLAY) and address.network.prefixlen == 32, 'wireguard_address_must_be_host_32')
    # ip_interface() defaults a bare IP to /32, but sing-box's netip.ParsePrefix
    # needs an explicit mask, so normalise here and in the emitted profile.
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


def device_settings(root):
    """Validate the two-level document and return effective settings by device id."""
    require(isinstance(root, dict) and set(root) == {'devices', 'shared'}, 'settings_fields')
    require(isinstance(root['devices'], list) and 1 <= len(root['devices']) <= 64, 'devices_list')
    require(isinstance(root['shared'], dict), 'shared_settings')
    expected = {'subscription_url', 'subscription_user_agent', 'top_k', 'refresh_seconds',
                'probe_timeout_seconds', 'probe_workers', 'max_candidates', 'hk_pattern',
                'sg_pattern', 'direct', 'singapore', 'own_hy2', 'manual_nodes'}
    require(set(root['shared']) == expected, 'shared_settings')
    result = {}
    keys, addresses, private_keys = set(), set(), set()
    for device in root['devices']:
        require(isinstance(device, dict) and set(device) == {'id', 'api_key', 'wireguard'}, 'device_fields')
        ident = device['id']
        require(isinstance(ident, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', ident)
                and ident not in result, 'device_id')
        effective = copy.deepcopy(root['shared'])
        effective.update(api_key=device['api_key'], wireguard=copy.deepcopy(device['wireguard']))
        validate(effective)
        require(effective['api_key'] not in keys, 'duplicate_api_key')
        require(effective['wireguard']['address'] not in addresses, 'duplicate_wireguard_address')
        require(effective['wireguard']['private_key'] not in private_keys, 'duplicate_wireguard_private_key')
        keys.add(effective['api_key'])
        addresses.add(effective['wireguard']['address'])
        private_keys.add(effective['wireguard']['private_key'])
        device['wireguard']['address'] = effective['wireguard']['address']
        result[ident] = effective
    return result


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
        start = time.monotonic()
        try:
            data = (fetcher or fetch)(s)
        except Exception as exc:
            lines.append('fetch failed: ' + type(exc).__name__ + ': ' + scrub(str(exc), s))
        else:
            lines.append(f'fetch ok: bytes={len(data)} seconds={time.monotonic() - start:.1f}')
    lines.append('--- recent failures live in the container log ---')
    lines.append('docker compose logs --tail=100 config')
    return '\n'.join(lines) + '\n'


def check_profile(profile, core=CORE):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / 'check.json'
        p.write_bytes(encode(profile))
        checked([core, 'check', '-c', str(p)])


def fetch(s):
    request = urllib.request.Request(s['subscription_url'], headers={'User-Agent': s['subscription_user_agent']})
    # urllib inherits standard HTTP(S)_PROXY; no subscription is handed to a third-party converter.
    with urllib.request.urlopen(request, timeout=30) as r:
        require(urllib.parse.urlsplit(r.url).scheme == 'https', 'subscription_redirect_https')
        data = r.read(LIMIT + 1)
    require(0 < len(data) <= LIMIT, 'subscription_size')
    return data


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
    p = {'log': {'disabled': True},
         'dns': {'servers': [{'type': 'local', 'tag': 'bootstrap'}]},
         'inbounds': [{'type': 'http', 'listen': '127.0.0.1', 'listen_port': port}],
         'outbounds': [node],
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


def select(nodes, s, measure=probe, checker=check_profile, measure_download=None):
    # A custom measure is a complete synthetic probe in tests; production uses
    # the separate CacheFly transfer after the Google response check.
    if measure_download is None:
        measure_download = probe_cachefly if measure is probe else measure
    groups = {'hk': [], 'sg': []}
    patterns = {g: re.compile(s[g + '_pattern']) for g in groups}
    for node in nodes:
        match = [g for g in groups if patterns[g].search(node['tag'])]
        if len(match) > 1:
            LOG.debug('candidate result=excluded reason=ambiguous_region node_id=%s endpoint=%s port=%s protocol=%s',
                      node_fingerprint(node), node_endpoint(node), node.get('server_port'), node.get('type'))
        require(len(match) <= 1, 'ambiguous_region')
        if match:
            n = copy.deepcopy(node)
            g = match[0]
            n['tag'] = f'{g}-{len(groups[g]) + 1:03d}'
            groups[g].append(n)
            LOG.debug('candidate result=included region=%s tag=%s endpoint=%s port=%s protocol=%s',
                      g, node_log_tag(n), node_endpoint(n), n.get('server_port'), n.get('type'))
        else:
            LOG.debug('candidate result=excluded reason=no_region_match node_id=%s endpoint=%s port=%s protocol=%s',
                      node_fingerprint(node), node_endpoint(node), node.get('server_port'), node.get('type'))
    # No Singapore entries means no Singapore path at all, and there is no
    # Singapore backup. No Hong Kong entries is the same situation as all of
    # them failing, so the owner's own hy2 may take over below.
    require(groups['sg'], 'singapore_unavailable')
    candidates = groups['hk'] + groups['sg']
    require(len(candidates) <= s['max_candidates'], 'candidate_limit')
    # Do not misclassify unsupported syntax as an unreachable node and enter fallback.
    checker({'dns': {'servers': [{'type': 'local', 'tag': 'bootstrap'}]},
             'outbounds': candidates, 'route': {'default_domain_resolver': 'bootstrap'}})
    with ThreadPoolExecutor(max_workers=s['probe_workers']) as pool:
        times = list(pool.map(lambda n: measure(n, s), candidates))
    google_times = dict(zip([n['tag'] for n in candidates], times))
    for node in candidates:
        ms = google_times[node['tag']]
        LOG.debug('google tag=%s result=%s ms=%s', node_log_tag(node),
                  'ok' if ms is not None else 'failed', ms)
    chosen = {}
    counts = {}
    for g, values in groups.items():
        google_ok = [n for n in values if google_times[n['tag']] is not None]
        google_ok.sort(key=lambda n: (google_times[n['tag']], n['tag']))
        # Download only the leading 2k candidates. If too few pass, extend the
        # shortlist until k are verified or the region is exhausted.
        verified = []
        download_results = {}
        limit = min(len(google_ok), max(2 * s['top_k'], s['top_k'] + 2))
        index = 0
        while index < len(google_ok) and (index < limit or len(verified) < s['top_k']):
            node = google_ok[index]
            download_ms = measure_download(node, s)
            download_results[node['tag']] = download_ms
            if download_ms is not None:
                score = .6 * google_times[node['tag']] + .4 * download_ms
                verified.append((score, node['tag'], node))
                LOG.debug('cachefly tag=%s result=ok ms=%s score_ms=%.3f',
                          node_log_tag(node), download_ms, score)
            else:
                LOG.debug('cachefly tag=%s result=failed', node_log_tag(node))
            index += 1
        verified.sort(key=lambda item: (item[0], item[1]))
        chosen[g] = [node for _, _, node in verified[:s['top_k']]]
        selected = {node['tag'] for node in chosen[g]}
        for node in values:
            tag = node['tag']
            reason = ('google_failed' if google_times[tag] is None else
                      'not_shortlisted' if tag not in download_results else
                      'cachefly_failed' if download_results[tag] is None else
                      'selected' if tag in selected else 'top_k_excluded')
            LOG.debug('decision region=%s tag=%s result=%s', g, node_log_tag(node), reason)
        counts[g] = {'tested': len(values), 'healthy': len(verified), 'retained': len(chosen[g])}
    require(chosen['sg'], 'singapore_unavailable')
    fallback = not chosen['hk']
    own = dict(copy.deepcopy(s['own_hy2']), type='hysteria2', tag='hk-own-hy2')
    if fallback:
        LOG.debug('candidate result=included region=hk tag=%s endpoint=%s port=%s protocol=hysteria2',
                  node_log_tag(own), node_endpoint(own), own.get('server_port'))
        own_google = measure(own, s)
        own_download = measure_download(own, s) if own_google is not None else None
        LOG.debug('decision region=hk tag=%s result=%s google_ms=%s cachefly_ms=%s',
                  node_log_tag(own), 'selected' if own_download is not None else 'fallback_failed',
                  own_google, own_download)
        require(own_download is not None, 'hong_kong_unavailable')
    else:
        LOG.debug('decision region=hk tag=%s result=manual_only_not_probed', node_log_tag(own))
    # Keep the owner's node available for manual selection even when subscription
    # HK nodes pass the server-side probe. It does not compete for top-k/default.
    chosen['hk'].append(own)
    counts['hk']['retained'] = len(chosen['hk'])
    return chosen, {'counts': counts, 'hk_fallback': fallback}


def merge_nodes(nodes, extra):
    """Append manual nodes, keeping tags unique so region matching stays unambiguous."""
    seen = {n['tag'] for n in nodes}
    merged = list(nodes)
    for index, node in enumerate(extra, 1):
        candidate = copy.deepcopy(node)
        if candidate['tag'] in seen:
            candidate['tag'] = f"{candidate['tag']} -m{index}"
        seen.add(candidate['tag'])
        merged.append(candidate)
    return merged


def rule_items(rules):
    # Separate source rules make domain/IP alternatives OR, never AND.
    return [{key: values} for key, values in rules.items() if values]


def build_profile(s, chosen):
    nodes = copy.deepcopy(chosen['hk'] + chosen['sg'])
    outbounds = [{'type': 'direct', 'tag': 'direct', 'domain_resolver': 'bootstrap'}] + nodes
    for g in ('hk', 'sg'):
        tags = [n['tag'] for n in chosen[g]]
        outbounds.append({'type': 'selector', 'tag': g, 'outbounds': tags, 'default': tags[0]})
    sets = [{'type': 'inline', 'tag': 'force-direct', 'rules': rule_items(s['direct'])}]
    if rule_items(s['singapore']):
        sets.append({'type': 'inline', 'tag': 'singapore', 'rules': rule_items(s['singapore'])})
    policy = [{'ip_cidr': [OVERLAY], 'action': 'route', 'outbound': 'wg-ipv6'},
              {'rule_set': ['force-direct'], 'action': 'route', 'outbound': 'direct'}]
    if rule_items(s['singapore']):
        policy.append({'rule_set': ['singapore'], 'action': 'route', 'outbound': 'sg'})
    dns_rules = []
    for name, target in [('direct', 'bootstrap'), ('singapore', 'dns-sg')]:
        for key in ('domain', 'domain_suffix'):
            if s[name][key]:
                dns_rules.append({key: s[name][key], 'action': 'route', 'server': target})
    w = s['wireguard']
    return {
        'log': {'level': 'warn'},
        'dns': {'servers': [
            {'type': 'local', 'tag': 'bootstrap'},
            {'type': 'https', 'tag': 'dns-hk', 'server': '1.1.1.1', 'path': '/dns-query', 'detour': 'hk'},
            {'type': 'https', 'tag': 'dns-sg', 'server': '1.1.1.1', 'path': '/dns-query', 'detour': 'sg'}],
            'rules': dns_rules, 'final': 'dns-hk'},
        'inbounds': [{'type': 'tun', 'tag': 'tun-in', 'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
                      'auto_route': True, 'strict_route': True, 'stack': 'mixed'}],
        'endpoints': [{'type': 'wireguard', 'tag': 'wg-ipv6', 'system': False,
                       'address': [str(ipaddress.ip_interface(w['address']))],
                       'private_key': w['private_key'], 'mtu': w['mtu'],
                       'domain_resolver': {'server': 'bootstrap', 'strategy': 'ipv6_only'},
                       'peers': [{'address': w['endpoint'], 'port': w['port'],
                                  'public_key': w['peer_public_key'], 'allowed_ips': [OVERLAY],
                                  'persistent_keepalive_interval': 25}]}],
        'outbounds': outbounds,
        'route': {'auto_detect_interface': True, 'default_domain_resolver': 'bootstrap',
                  'rule_set': sets, 'final': 'hk',
                  'rules': [{'action': 'sniff', 'sniffer': ['http', 'tls', 'quic', 'dns']}] + copy.deepcopy(policy) +
                           [{'protocol': 'dns', 'action': 'hijack-dns'}, {'action': 'resolve'}] + policy}
    }


class Publisher:
    def __init__(self, settings, snapshot, fetcher=fetch, converter=convert, measure=probe, checker=check_profile):
        self.settings, self.snapshot = Path(settings), Path(snapshot)
        self.fetcher, self.converter, self.measure, self.checker = fetcher, converter, measure, checker
        self.lock = threading.Lock()
        self.data = None
        self.error = None
        self.stage = 'startup'
        self.updated = None
        self.summary = None

    def restore(self):
        try:
            s = load_settings(self.settings)
            obj = json.loads(self.snapshot.read_bytes())
            require(obj['fingerprint'] == hashlib.sha256(encode(s)).hexdigest(), 'snapshot_settings_changed')
            devices = device_settings(s)
            require(set(obj['profiles']) == set(devices), 'snapshot_devices_changed')
            for profile in obj['profiles'].values():
                self.checker(profile)
            with self.lock:
                self.data, self.updated, self.summary = {k: encode(v) for k, v in obj['profiles'].items()}, obj['updated'], obj['summary']
        except Exception:
            pass  # Never serve an unvalidated or mismatched snapshot.

    def refresh(self):
        stage = 'settings'
        s = None
        try:
            s = load_settings(self.settings)
            devices = device_settings(s)
            shared = s['shared']
            stage = 'fetch'
            data = self.fetcher(shared)
            stage = 'convert'
            nodes = self.converter(data)
            if shared['manual_nodes']:
                extra = self.converter(('\n'.join(shared['manual_nodes']) + '\n').encode())
                # A dropped manual entry must not silently reduce the candidate set.
                require(len(extra) == len(shared['manual_nodes']), 'manual_node_rejected')
                nodes = merge_nodes(nodes, extra)
            stage = 'select'
            chosen, summary = select(nodes, next(iter(devices.values())), self.measure, self.checker)
            stage = 'check'
            profiles = {ident: build_profile(settings, chosen) for ident, settings in devices.items()}
            for profile in profiles.values():
                self.checker(profile)
            stage = 'publish'
            updated = int(time.time())
            snapshot = {'fingerprint': hashlib.sha256(encode(s)).hexdigest(), 'profiles': profiles,
                        'updated': updated, 'summary': summary}
            atomic_write(self.snapshot, encode(snapshot))
            with self.lock:
                self.data, self.updated, self.summary = {k: encode(v) for k, v in profiles.items()}, updated, summary
                self.error, self.stage = None, 'ready'
            counts = summary['counts']
            LOG.info('published hk_retained=%s hk_tested=%s sg_retained=%s sg_tested=%s fallback=%s',
                     counts['hk']['retained'], counts['hk']['tested'],
                     counts['sg']['retained'], counts['sg']['tested'], summary['hk_fallback'])
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
                    'selection': self.summary}

    def loop(self, stop):
        while not stop.is_set():
            self.refresh()
            try:
                interval = load_settings(self.settings)['shared']['refresh_seconds']
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

        def reply(self, status, data):
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
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
            if u.path != '/api/config':
                self.reply(404, b'{"error":"not_found"}')
                return
            try:
                # Auth always uses the current settings, not a cached/old key.
                settings = load_settings(publisher.settings)
                query = urllib.parse.parse_qs(u.query, strict_parsing=True)
                header = self.headers.get('Authorization', '')
                supplied = header[7:] if header.startswith('Bearer ') else query.get('key', [''])[0]
                ident = next((d['id'] for d in settings['devices']
                              if hmac.compare_digest(d['api_key'], supplied)), None)
            except Exception:
                ident = None
            if ident is None:
                self.reply(401, b'{"error":"unauthorized"}')
                return
            with publisher.lock:
                data = publisher.data.get(ident) if publisher.data else None
            self.reply(200 if data else 503, data or b'{"error":"not_ready"}')

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
