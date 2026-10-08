"""Single-purpose sing-box 1.14.2 configuration publisher; Python stdlib only."""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import ipaddress
import json
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
PROBE_URL = "https://www.google.com/"
OVERLAY = "10.77.0.0/24"
LIMIT = 8 * 1024 * 1024


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
              "direct", "singapore", "wireguard", "own_hy2"}
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
    return s


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
    return validate(json.loads(Path(path).read_bytes()))


def checked(args, timeout=30):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    require(result.returncode == 0, 'tool_failed')
    return result


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


def probe(node, s, core=CORE, url=PROBE_URL):
    """Actual HTTPS through this outbound; measured on container network, not ICMP."""
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
                    return None
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            # curl --proxy + --noproxy '' prevents NO_PROXY from bypassing the tested outbound.
            start = time.monotonic()
            r = subprocess.run(['curl', '--silent', '--fail', '--output', os.devnull,
                                '--proxy', f'http://127.0.0.1:{port}', '--noproxy', '',
                                '--max-time', str(s['probe_timeout_seconds']), url],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=s['probe_timeout_seconds'] + 2)
            return round((time.monotonic() - start) * 1000, 3) if r.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def select(nodes, s, measure=probe, checker=check_profile):
    groups = {'hk': [], 'sg': []}
    patterns = {g: re.compile(s[g + '_pattern']) for g in groups}
    for node in nodes:
        match = [g for g in groups if patterns[g].search(node['tag'])]
        require(len(match) <= 1, 'ambiguous_region')
        if match:
            n = copy.deepcopy(node)
            g = match[0]
            n['tag'] = f'{g}-{len(groups[g]) + 1:03d}'
            groups[g].append(n)
    require(all(groups.values()), 'missing_region')
    candidates = groups['hk'] + groups['sg']
    require(len(candidates) <= s['max_candidates'], 'candidate_limit')
    # Do not misclassify unsupported syntax as an unreachable node and enter fallback.
    checker({'dns': {'servers': [{'type': 'local', 'tag': 'bootstrap'}]},
             'outbounds': candidates, 'route': {'default_domain_resolver': 'bootstrap'}})
    with ThreadPoolExecutor(max_workers=s['probe_workers']) as pool:
        times = list(pool.map(lambda n: measure(n, s), candidates))
    scores = dict(zip([n['tag'] for n in candidates], times))
    chosen = {}
    counts = {}
    for g, values in groups.items():
        healthy = [n for n in values if scores[n['tag']] is not None]
        healthy.sort(key=lambda n: (scores[n['tag']], n['tag']))
        chosen[g] = healthy[:s['top_k']]
        counts[g] = {'tested': len(values), 'healthy': len(healthy), 'retained': len(chosen[g])}
    require(chosen['sg'], 'singapore_unavailable')
    fallback = not chosen['hk']
    if fallback:
        own = dict(copy.deepcopy(s['own_hy2']), type='hysteria2', tag='hk-own-hy2')
        require(measure(own, s) is not None, 'hong_kong_unavailable')
        chosen['hk'] = [own]
    return chosen, {'counts': counts, 'hk_fallback': fallback}


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
            'rules': dns_rules, 'final': 'dns-hk', 'independent_cache': True},
        'inbounds': [{'type': 'tun', 'tag': 'tun-in', 'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
                      'auto_route': True, 'strict_route': True, 'stack': 'mixed'}],
        'endpoints': [{'type': 'wireguard', 'tag': 'wg-ipv6', 'system': False,
                       'address': [w['address']], 'private_key': w['private_key'], 'mtu': w['mtu'],
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
            self.checker(obj['profile'])
            with self.lock:
                self.data, self.updated, self.summary = encode(obj['profile']), obj['updated'], obj['summary']
        except Exception:
            pass  # Never serve an unvalidated or mismatched snapshot.

    def refresh(self):
        stage = 'settings'
        try:
            s = load_settings(self.settings)
            stage = 'fetch'
            data = self.fetcher(s)
            stage = 'convert'
            nodes = self.converter(data)
            stage = 'select'
            chosen, summary = select(nodes, s, self.measure, self.checker)
            stage = 'check'
            p = build_profile(s, chosen)
            self.checker(p)
            stage = 'publish'
            updated = int(time.time())
            snapshot = {'fingerprint': hashlib.sha256(encode(s)).hexdigest(), 'profile': p,
                        'updated': updated, 'summary': summary}
            atomic_write(self.snapshot, encode(snapshot))
            with self.lock:
                self.data, self.updated, self.summary = encode(p), updated, summary
                self.error, self.stage = None, 'ready'
            return True
        except Exception as exc:
            with self.lock:
                # Exception contents and subscription/core output are deliberately not exposed.
                self.error = str(exc) if isinstance(exc, Invalid) else 'operation_failed'
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
                interval = load_settings(self.settings)['refresh_seconds']
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
                key = load_settings(publisher.settings)['api_key']
                query = urllib.parse.parse_qs(u.query, strict_parsing=True)
                header = self.headers.get('Authorization', '')
                supplied = header[7:] if header.startswith('Bearer ') else query.get('key', [''])[0]
                valid = hmac.compare_digest(key.encode(), supplied.encode())
            except Exception:
                valid = False
            if not valid:
                self.reply(401, b'{"error":"unauthorized"}')
                return
            with publisher.lock:
                data = publisher.data
            self.reply(200 if data else 503, data or b'{"error":"not_ready"}')

        def do_POST(self):
            self.reply(405, b'{"error":"method_not_allowed"}')
    return Handler


def main():
    os.umask(0o077)
    if len(sys.argv) > 1 and sys.argv[1] == 'health':
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open('http://127.0.0.1:8787/healthz', timeout=3) as r:
                return 0 if json.load(r)['ready'] else 1
        except Exception:
            return 1
    # Refuse a different major/minor/patch, rather than validate against the wrong core.
    require(checked([CORE, 'version']).stdout.splitlines()[0] == b'sing-box version 1.14.2', 'core_version')
    p = Publisher('/config/settings.json', '/state/snapshot.json')
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
