# sing-box config service

English | [中文](README_zh.md)

An authenticated remote-profile service for sing-box Android. It turns one HTTPS node subscription into per-device configurations, selects healthy Hong Kong and Singapore nodes, and serves profiles that the client can refresh. It does not run a proxy for clients or configure the host's WireGuard server, reverse proxy, or routing.

## Profiles

Choose a routing mode and a profile type when adding a remote profile in sing-box:

| Mode | Default routing |
| --- | --- |
| `global` | Hong Kong, except explicit direct and Singapore rules |
| `blacklist` | Chinese GeoIP/Geosite matches direct; other traffic via Hong Kong |
| `whitelist` | Matched foreign GeoIP/Geosite destinations via Hong Kong; unknown destinations direct |

Explicit direct rules take precedence over Singapore rules in every mode. The `full` type includes TUN and a device-specific WireGuard connection. The `proxyonly` type provides a local mixed proxy without TUN or WireGuard, useful for devices without a WireGuard peer.

For example, a `full` global profile uses:

```text
https://<your-profile-host>/api/config-global-full?key=<device-api-key>
```

Replace `global` with `blacklist` or `whitelist`, or `full` with `proxyonly`. If the public reverse proxy uses a path prefix, include it before `/api/`. The legacy `/api/config` endpoint is no longer available.

## Getting started

The service targets Linux/amd64 with Docker Compose. You need a reachable HTTPS node subscription, Hong Kong and Singapore nodes, an own Hong Kong Hysteria2 fallback, and an existing HTTPS reverse proxy. Keep a working client profile while setting this up.

1. Open the interactive menu with `python3 cli.py`. Its dependencies are listed in `requirements-menu.txt` and belong in a virtual environment. Alternatively, the direct actions below use only Python's standard library.
2. Choose **Initialize private settings template** (or `python3 cli.py init`). Edit the ignored `private-config/settings.json`: fill the subscription, own fallback node, each device's API key, and the public HTTPS base URL. The template starts without WireGuard; add a separate WireGuard identity and server peer for each device that needs `full`. See [the template](templates/private-config/settings.json) for the field layout.
3. Choose **Render private runtime settings** (or `python3 cli.py render`), then **Build service image** and **Start service** (or `python3 cli.py build` and `python3 cli.py up`). Rendering validates the private settings; it does not start the container.
4. Check `/healthz` for `ready: true`, not merely HTTP 200. Add a **new** remote profile URL in the client and refresh it. The service listens on `127.0.0.1:8787`; your existing HTTPS reverse proxy must forward `/api/` to it. If the proxy uses a path prefix, set `public_base_url` to that exact public base so `whitelist` can retrieve its companion rule set.

Use the menu for status, logs, diagnostics, and stopping the service. Do not commit private settings, rendered files, or snapshots. Do not log or cache key-bearing profile URLs at the reverse proxy.


## Resolver

Names that must resolve before any tunnel exists (node `server` hostnames) use the
`bootstrap` resolver: DoH over an IP literal, default `https://223.5.5.5/dns-query`.
Node hostnames therefore stop leaking as cleartext DNS to the local network; the DoH
provider still sees the query. It must stay an IP literal, otherwise resolving it would
require DNS. Override with `SINGBOX_BOOTSTRAP_DOH=https://1.1.1.1/dns-query`. Traffic
lookups keep using `dns-hk`.

## Manual DNS records

Add the optional `dns_hosts` object inside `shared` in `private-config/settings.json`:

```json
"dns_hosts": {
  "app.example.com": ["192.0.2.10"],
  "dual.example.com": ["192.0.2.20", "2001:db8::20"]
}
```

These are documentation addresses; replace them with your actual destinations. Keep real domains and addresses in private settings, not in the tracked template or Git.

- Exact names only, not subdomains. Multiple IPv4 (A) and IPv6 (AAAA) addresses are supported. Case and one trailing dot are normalized; use punycode for international names. Values must be nonempty address arrays; URLs, ports, CIDRs, zones, wildcards and CNAMEs are unsupported.
- Applies to every device, all three modes and both profile types. Static records precede DIRECT, SG and Chinese-domain DNS rules. HTTP/SOCKS domain destinations are resolved before routing so the upstream proxy does not bypass overrides by resolving again. **DNS records do not select an outbound**: existing routing still applies, with IP rules seeing the overridden IPs.
- Uses native sing-box [hosts DNS](https://sing-box.sagernet.org/configuration/dns/server/hosts/). An A-only entry returns an empty AAAA answer (and vice versa), without public-DNS fallback. Other record types return NXDOMAIN; TXT/MX/HTTPS records are not supported.
- Covers business queries entering sing-box DNS and domain-addressed proxy requests. It does not modify system hosts, authoritative DNS, subscription fetching, or node/WireGuard bootstrap resolution. Application-owned DoH, already-resolved IPs and DNS queries exempted by existing DIRECT rules are outside this guarantee.
- Omitted or `{}` preserves legacy behavior. Limits: 10000 domains, 64 addresses each. Duplicate normalized names, empty arrays and invalid addresses reject Render/refresh rather than being silently ignored. A failed live refresh preserves the last valid profile set.

**First activation:** review/apply the patch, edit private settings with an editor, then choose **Render private runtime settings**, **Build service image**, and **Start service**. Confirm a successful publication in logs; refresh and reapply the client profile. Restart applications if they retain old DNS results or connections.

**Later edits:** change private settings, Render, wait for the next successful publication, then refresh and reapply the client profile. Build/Start alone does not render private settings. Remove a name to restore its original resolver policy; use `{}` to disable all overrides. Keep the existing rescue profile.

## Logs

Every refresh logs one line per region at INFO:

```
region hk: tested=10 google_ok=0 verified=0 retained=0 decisions={'google_failed': 10}
```

When `retained=0` that line is a WARNING and is followed by
`hk pool empty: tested=10, falling back to own_hy2`, so an unusable subscription pool is
visible without raising the log level. Per-node detail (included/excluded, google and
cachefly results, curl exit codes) needs `SINGBOX_LOG_LEVEL=DEBUG python3 cli.py up`.
Subscription fetches are retried up to 3 times with 1s and 3s backoff and log
`fetch attempt n/3 failed` each time.

## Scope and documentation

The service checks candidate nodes from the container's network and retains the last valid profile set if a refresh fails. It cannot instantly change a running client profile, guarantee that the same node works from the phone's network, or automatically fail over a broken WireGuard path. A device without WireGuard can use `proxyonly`; Singapore has no fallback node.

- [Design and implementation boundaries](docs/design.md)
- [Direct-rule sources](docs/rule-source.md)
- [Local evidence and host/client acceptance checklist](docs/acceptance.md)

The repository has not been deployed or verified on the owner's server or Android devices.
