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

## Scope and documentation

The service checks candidate nodes from the container's network and retains the last valid profile set if a refresh fails. It cannot instantly change a running client profile, guarantee that the same node works from the phone's network, or automatically fail over a broken WireGuard path. A device without WireGuard can use `proxyonly`; Singapore has no fallback node.

- [Design and implementation boundaries](docs/design.md)
- [Direct-rule sources](docs/rule-source.md)
- [Local evidence and host/client acceptance checklist](docs/acceptance.md)

The repository has not been deployed or verified on the owner's server or Android devices.
