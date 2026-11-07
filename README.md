# sing-box config service

English | [中文](README_zh.md)

An authenticated remote-profile service for sing-box Android. It turns multiple HTTPS node subscriptions into per-device configurations, selects healthy nodes from every region, and serves profiles that the client can refresh. It does not run a proxy for clients or configure the host's WireGuard server, reverse proxy, or routing.

## Composable clients and startup-only TAG subscriptions

Node sources, reusable capabilities and client selections are independent. See the [composition contract](docs/composition.md) and [complete example](docs/composition.example.json).

- Define named proxy / singapore / dns / direct / wireguard capabilities in `services`; clients select names in `devices[].services`, not a device-class bundle.
- Each client chooses `mode` (global/blacklist/whitelist) and independent `ingress` (mixed/tun/both). TUN no longer requires WireGuard.
- Use `/api/config?key=<CLIENT_KEY>` for the composed profile. The six older URLs below remain compatibility adapters; they cannot enable deselected features.
- TAG can use `update_policy: "startup"`; other feeds can use poll plus interval_seconds. Health probes retain their independent clock.
- Successful per-source catalogs are private 0600 files. A failed startup fetch can reuse the same source's catalog with explicit stale status. The first upgrade has no such cache: open TAG's switch and actually restart the service within its 15-minute window.
- Documents without a service catalog remain supported. Move legacy shared.direct/singapore/dns_hosts into named definitions before opting into composition; do not mix schemas. The linked guide covers migration and rollback.

## Profiles

Choose a routing mode and a profile type when adding a remote profile in sing-box:

| Mode | Default routing |
| --- | --- |
| `global` | Default `proxy` selector, except explicit direct and Singapore rules |
| `blacklist` | Chinese GeoIP/Geosite matches direct; other traffic via the default `proxy` selector |
| `whitelist` | Matched foreign GeoIP/Geosite destinations via the default `proxy` selector; unknown destinations direct |

Explicit direct rules take precedence over Singapore rules in every mode. The `full` type includes TUN and a device-specific WireGuard connection. The `proxyonly` type provides a local mixed proxy without TUN or WireGuard, useful for devices without a WireGuard peer.

For example, a `full` global profile uses:

```text
https://<your-profile-host>/api/config-global-full?key=<device-api-key>
```

Replace `global` with `blacklist` or `whitelist`, or `full` with `proxyonly`. If the public reverse proxy uses a path prefix, include it before `/api/`. `/api/config` now serves the client-selected composition.

## Getting started

The service targets Linux/amd64 with Docker Compose. Proxy capabilities need reachable HTTPS node subscriptions; Singapore nodes are required only for clients selecting SG. Own Hong Kong Hysteria2 is optional (own_hy2=null). An existing HTTPS reverse proxy is required. Keep a working client profile while setting this up.

1. Open the interactive menu with `python3 cli.py`. Its dependencies are listed in `requirements-menu.txt` and belong in a virtual environment. Alternatively, the direct actions below use only Python's standard library.
2. Choose **Initialize private settings template** (or `python3 cli.py init`). Edit the ignored `private-config/settings.json`: fill subscriptions, client API keys, the public HTTPS base URL and selected service names. The template has own_hy2=null and no WireGuard; clients selecting overlay need a separate WireGuard identity and server peer. See [the template](templates/private-config/settings.json) for the field layout.
3. Choose **Render private runtime settings** (or `python3 cli.py render`), then **Build service image** and **Start service** (or `python3 cli.py build` and `python3 cli.py up`). Rendering validates the private settings; it does not start the container.
4. Check `/healthz` for `ready: true`, not merely HTTP 200. Add a **new** remote profile URL in the client and refresh it. The service listens on `127.0.0.1:8787`; your existing HTTPS reverse proxy must forward `/api/` to it. If the proxy uses a path prefix, set `public_base_url` to that exact public base so `whitelist` can retrieve its companion rule set.

Use the menu for status, logs, diagnostics, and stopping the service. Do not commit private settings, rendered files, or snapshots. Do not log or cache key-bearing profile URLs at the reverse proxy.


## Resolver

Names that must resolve before any tunnel exists (node `server` hostnames) use the
`bootstrap` resolver: DoH over an IP literal, default `https://223.5.5.5/dns-query`.
Node hostnames therefore stop leaking as cleartext DNS to the local network; the DoH
provider still sees the query. It must stay an IP literal, otherwise resolving it would
require DNS. Override with `SINGBOX_BOOTSTRAP_DOH=https://1.1.1.1/dns-query`. Traffic
lookups keep using `dns-proxy`.

## Manual DNS records

In composed settings, place this mapping in the selected DNS service's `services.<name>.hosts`. The `shared.dns_hosts` placement below is only for legacy documents.

Add the optional `dns_hosts` object inside `shared` in `private-config/settings.json`:

```json
"dns_hosts": {
  "app.example.com": ["192.0.2.10"],
  "dual.example.com": ["192.0.2.20", "2001:db8::20"]
}
```

These are documentation addresses; replace them with your actual destinations. Keep real domains and addresses in private settings, not in the tracked template or Git.

- Exact names only, not subdomains. Multiple IPv4 (A) and IPv6 (AAAA) addresses are supported. Case and one trailing dot are normalized; use punycode for international names. Values must be nonempty address arrays; URLs, ports, CIDRs, zones, wildcards and CNAMEs are unsupported.
- Applies to clients selecting that DNS service (all devices in legacy documents), all three modes and both profile types. Static records precede DIRECT, SG and Chinese-domain DNS rules. HTTP/SOCKS domain destinations are resolved before routing so the upstream proxy does not bypass overrides by resolving again. **DNS records do not select an outbound**: existing routing still applies, with IP rules seeing the overridden IPs.
- Uses native sing-box [hosts DNS](https://sing-box.sagernet.org/configuration/dns/server/hosts/). An A-only entry returns an empty AAAA answer (and vice versa), without public-DNS fallback. Other record types return NXDOMAIN; TXT/MX/HTTPS records are not supported.
- Covers business queries entering sing-box DNS and domain-addressed proxy requests. It does not modify system hosts, authoritative DNS, subscription fetching, or node/WireGuard bootstrap resolution. Application-owned DoH, already-resolved IPs and DNS queries exempted by existing DIRECT rules are outside this guarantee.
- Omitted or `{}` preserves legacy behavior. Limits: 10000 domains, 64 addresses each. Duplicate normalized names, empty arrays and invalid addresses reject Render/refresh rather than being silently ignored. A failed live refresh preserves the last valid profile set.

**First activation:** review/apply the patch, edit private settings with an editor, then choose **Render private runtime settings**, **Build service image**, and **Start service**. Confirm a successful publication in logs; refresh and reapply the client profile. Restart applications if they retain old DNS results or connections.

**Later edits:** change private settings, Render, wait for the next successful publication, then refresh and reapply the client profile. Build/Start alone does not render private settings. Remove a name to restore its original resolver policy; use `{}` to disable all overrides. Keep the existing rescue profile.

## Multiple subscriptions, all-node selector, test intervals and naming

In private `shared`, replace `subscription_url` with `subscriptions` (1-32 objects). Each source has an HTTPS `url`,
optional unique ASCII `name`, `user_agent`, `fetch_method` (`curl` by default, or `urllib`), and optional `rename_rules`.
Keep the remaining settings. An explicit `user_agent: "curl/8.10.1"` is a UA example, not installed-version detection or live TAG verification. Use `user_agent: ""` to retain the local curl's real native UA rather than forcing v2rayNG; curl ignores
.curlrc and inherits the container proxy environment. Legacy single-URL settings remain accepted; do not set both forms.
A shared subscription_user_agent can supply a fallback, but an explicit empty per-source UA overrides it.

```json
{
  "subscriptions": [
    {
      "name": "tag",
      "url": "<TAG_HTTPS_SUBSCRIPTION_URL>",
      "user_agent": "curl/8.10.1",
      "fetch_method": "curl",
      "rename_rules": [
        {
          "pattern": "^(?:[🇦-🇿]{2}\\s*)?(.+?)[-\\s]?(家宽|住宅|游戏|蜂窝5G|星链|实验节点)?(?:\\s+\\d+)?[丨|].*$",
          "replacement": "$1-$2-$index",
          "capture_defaults": {
            "2": "普通"
          }
        }
      ],
      "update_policy": "startup"
    },
    {
      "name": "other",
      "url": "<OTHER_HTTPS_SUBSCRIPTION_URL>",
      "user_agent": "",
      "fetch_method": "curl",
      "rename_rules": [
        {
          "pattern": "^(?:[🇦-🇿]{2}\\s*)?(?=[A-Za-z]+\\s*(香港|新加坡|日本|台湾|美国|英国|韩国))([A-Za-z]+).*",
          "replacement": "$1-$2-$index"
        }
      ],
      "update_policy": "poll",
      "interval_seconds": 300
    }
  ],
  "refresh_seconds": 300,
  "probe_interval_seconds": 900,
  "max_candidates": 1000,
  "rename_rules": []
}
```

This is a merge fragment, not a complete settings file. Enter actual URLs locally only.

- `proxy` contains every verified node from every region, not just HK/SG top-k. Duplicate connection+original-name
  pairs across sources are removed; other duplicate/reserved display names receive suffixes. Even own_hy2 must pass
  both checks before inclusion. HK remains the preferred default; verified own_hy2 is next when no subscription HK is
  healthy. Other healthy regions can still be published if HK and own_hy2 fail.
- Only selected `proxy` and `sg` capabilities emit their respective selectors. SG retains its regional top-k policy; business SG rules and `dns-sg -> sg` remain separate. HK survives only as internal health/ranking/default preference, not a selectable client group.
  General traffic, ordinary DNS and remote rule downloads use `proxy`. Switching its default to Japan does not redirect
  SG traffic. Direct/hosts/WireGuard precedence and all three routing modes remain intact.
- Each poll source uses interval_seconds (default refresh_seconds); startup sources do not poll; `probe_interval_seconds` is the positive/negative/exception probe-result TTL
  (30-86400 seconds), defaulting to refresh_seconds when omitted; new templates use 900. The loop wakes at the smallest probe/poll
  period after the previous cycle completes (not a hard real-time deadline). New/changed connection identities bypass
  cached results; display-only renaming does not change identity. A restart performs fresh probes.
- Every Google-passing node transfers 128 KiB from CacheFly per test cycle. Large/high-multiplier pools consume more
  provider quota; 10x nodes are not automatically excluded. max_candidates applies to ALL regions, with a hard failure
  rather than silent truncation. Existing configurations capped at 200 may need increasing (maximum 5000).
- A failed source may reuse its verified catalog with explicit stale state in healthz.sources; selection.sources describes the last published batch. If all poll sources fail without a usable startup catalog, or a selected SG capability has no healthy SG node, preserve the previous publication. Cached nodes still need current health checks. Never substitute another country for SG. Clients still need refresh/reapply.

### User-configured capture and replacement rules

Rules are ordered; the first matching Python regex wins. Replacement supports `$1` through `$99`, `$index` (three-digit
per-template/type counter), and `$$` (literal dollar sign). Captures and replacement layout are fully configurable.
Use per-source rules for different naming schemes rather than applying TAG patterns to every source.
TAG examples become `香港-家宽-001` and `香港-普通-001`; optional `capture_defaults: {"2": "普通"}` fills an unmatched/empty second capture in BOTH the name and status type. Defaults are literal strings, never recursively expanded.
The other source handles the visible `🇸🇬AWS新加坡04...` / `🇯🇵AWS日本09...` prefixes without assuming the truncated suffix, producing `新加坡-AWS-001` / `日本-AWS-001`.
A lookahead captures region as group 1 before group 2 captures the leading English type label. Extend the country alternatives for other inputs; unmatched formats are preserved.
Per-source rename_rules override shared rules; an empty list disables rewriting. Nonmatching names remain unchanged.
Counters follow input order across sources, including subsequently failing nodes, so health changes alone do not renumber
nodes; changed source order or node deletion can renumber. Collisions receive `[2]` etc.

Capture **$2** is the display-type label in the tag and health summary, never the protocol's real `type` field.
Native client protocol columns still show SS/AnyTLS/etc. Region classification always uses original names before renaming.

See [source examples and routing precedence](docs/subscriptions.md) for the exact merge fragment and transition limits.

Update through the existing menu: review/apply the patch, edit private JSON in Neovim, then **Render private runtime
settings -> Build service image -> Start service**. After a successful publication refresh/reapply the client. Later
URL/rule/interval-only changes need Render and the next cycle, not a rebuild. Keep original private/client files for rollback.
Subscription fetching uses curl/urllib/container resolver/proxy settings, not the DNS in generated client profiles.

## Logs

Each cycle reports tested/verified/default_retained counts for hk, sg and other (empty pools log at WARNING).
Every node passing both Google 204 and the bounded CacheFly digest test enters `proxy`; top-k does not limit this pool.
Health selection includes source status, all-pool counts and second-capture display types, never subscription URLs.
Per-candidate/Google/CacheFly/curl details remain at DEBUG; output goes to container stdout, not host diagnostic files.
Fetches retry up to three times with 1s/3s backoff. Source failures report only source index, stage and exception class.

## Scope and documentation

The service checks candidate nodes from the container's network and retains the last valid profile set if a refresh fails. It cannot instantly change a running client profile, guarantee that the same node works from the phone's network, or automatically fail over a broken WireGuard path. A device without WireGuard can use `proxyonly`; Singapore has no fallback node.

- [Design and implementation boundaries](docs/design.md)
- [Direct-rule sources](docs/rule-source.md)
- [Local evidence and host/client acceptance checklist](docs/acceptance.md)

The repository has not been deployed or verified on the owner's server or Android devices.
