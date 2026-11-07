# Acceptance: normal / transition / recovery / failure

## Risk boundaries

- No production interfaces, subscriptions, keys or machines were accessed for testing.
- Only local fixtures and loopback network listeners were used. Docker cannot be run in this environment.
- A syntax check is not proof of Android VPN routing, public IPv6 reachability, or remote TLS/UDP availability.
- Scope is a reviewable repository; public exposure/deployment still requires review of the actual host mapping.

## Current extension verification matrix

| Normal / transition / recovery / failure | Local evidence |
| --- | --- |
| Multi-source normal | Real local HTTPS curl fetch (test CA only), Base64/plain feeds, pinned converter, rename and full Publisher/core checks; source aliases deduplicated |
| Partial / total source failure | Failed source reported without URL; other source proceeds; all-source failure retains data and snapshot bytes |
| Default selector switched to Japan | Real sing-box loopback in all three modes: ordinary traffic reaches JP, SG policy still reaches SG, overlapping direct/SG IP reaches DIRECT |
| Client selector set | Only proxy and sg are emitted; no rule references the removed hk group, and the real-core JP/SG/DIRECT test asserts the exact selector set |
| Source-specific naming / UA | TAG and AWS-prefix fixtures use distinct per-source rules; group 2 displays AWS while protocol remains VLESS; explicit curl UA forwarding retains URL privacy |
| Rename / type / collision | Configured captures, swapped replacement layout, per-template numbering, protocol unchanged and SG membership based on original name |
| Probe cadence / source cadence | Controlled clock tests separate fetch and probe events; negative TTL, display-only cache reuse and changed connection identity covered |
| Review regressions | Manual-rule changes within fetch TTL; exception negative-cache expiry; reserved WG tag; literal curl URL on real HTTPS server; documented TAG/AWS captures and default display types |
| SG failure / recovery | No cross-country fallback; exact previous batch retained; later valid refresh clears stale state |

## Executed locally

| Gate | Evidence |
|---|---|
| Normal HK/SG selection | All regions tested; all verified nodes in proxy; SG top-k independent; HK ranking internal only; own hy2 tested before inclusion |
| Partial HK failure | Remaining subscription HK preferred; own hy2 stays last only if verified |
| All HK failed / recovered | Synthetic probe failure selects own hy2 as default; recovered subscription regains default while own hy2 remains manually selectable |
| No HK entries in feed | Treated as all-HK-failed: own hy2 selected, counts.hk shows tested 0 / retained 0; own_hy2 is counted separately |
| Manual candidate merge | Private manual_nodes converted and merged; duplicate tags disambiguated; dropped entry fails the cycle |
| Tool failure detail | API keeps the static code; the core's stderr is logged to stdout only (docker logs), with URL/key/credentials redacted |
| No host diagnostic files | A failed refresh writes nothing to the host; only the validated snapshot is published |
| Fetch-stage failure | Non-validation exceptions are logged with their type and stage; diagnose re-fetches live and prints proxy env as set/unset only |
| All SG failed | Reject publication; all HK+backup failure can still publish other healthy regions |
| Candidate overflow / absent region | Error, no partial probing masquerading as total failure |
| Probe actually traverses core | Real 1.14.2 → loopback proxy; NO_PROXY=* cannot bypass; failed proxy detected |
| Two-target probe | Wrong Google HTTP status is rejected; CacheFly checksum and exact-range response required; weighted ranking can reorder Google-only results |
| DEBUG diagnostics | Local probes report HTTP/size/hash failure reasons; selection emits each candidate endpoint, measured score and final reason; CLI validates/passes runtime log level including sudo |
| Stable log node ID | Converted outbound fields excluding mutable tag are canonicalized and SHA-256 abbreviated; reordering/renaming preserves the log ID, changing connection details changes it; client tags are unchanged |
| DIRECT > SG > default proxy | Real 1.14.2 local HTTP inbound with isolated proxy endpoints; shared IP goes DIRECT, SG IP/domain goes SG, remaining IP goes HK |
| WG only IPv6 | IPv4 endpoint rejected; generated domain resolver ipv6_only; core accepts WG endpoint schema |
| WG address normalisation | A bare host address is normalised to /32 and accepted by the real core; a non-/32 mask is refused |
| Config syntax | Real 1.14.2 accepts normal/backup, populated/empty SG whitelist variants |
| Conversion | Real v1.0.4 converts plain/base64 URI feeds; bad input rejected |
| Auth / readiness | Real local HTTP API: 401 before auth, 503 before ready, 200 valid Bearer/URL key, 405 POST, old key rejected after rotation |
| Multi-device isolation | Two synthetic devices with distinct keys receive distinct WG addresses/private keys; their HTTP responses match only their device; subscription probe runs once for the batch |
| Multi-device failure/restore | Duplicate IDs, keys and WG addresses rejected; one device's failed profile check keeps the previous batch; matched snapshot restores both, changed device list cannot restore |
| Refresh failures | Last valid profile remains byte-identical, static errors do not contain secret fixture text |
| Upgrade from legacy HK snapshot | Native-valid legacy layout is refused for new variants without touching its bytes; subsequent successful refresh publishes proxy/sg |
| Recovery / restart | Invalid settings corrected then publish; matched restart snapshot restored; settings mismatch refused |
| Render / mounts | Same two-level settings shape as Compose; 0600 files, 0700 directories, owner UID/GID; existing private template not overwritten |

92 regression tests pass in the edited tree, including real sing-box 1.14.2 and converter v1.0.4. The HTTPS integration test issues a temporary loopback certificate with openssl; it skips explicitly if that optional test tool is unavailable. Real proxy credentials and external providers are not used.

## Required on the actual host/client (NOT executed)

1. Docker build and startup, including base image/build/runtime proxy paths; actual UID/mount access.
   Confirm `SINGBOX_LOG_LEVEL=DEBUG` at `up` recreates the service with per-node diagnostics; return to INFO afterward.
2. HTTPS URL from each SFA device, automatic refresh/apply behavior, no key-bearing reverse-proxy logs. Confirm every device gets only its own WG address/key; old single-device snapshot intentionally cannot restore after migration.
3. Real subscription classification, proxy protocols, Google HTTPS probe results from the container.
4. Real HK subscription → own hy2 → recovered HK transitions, followed by client refresh and an actual business request.
5. SG whitelist HTTP/TLS requests and DNS routing; DIRECT public DNS requests; ordinary mainland sites follow the selected default proxy unless listed.
6. Actual WireGuard-over-IPv6 handshake and 10.77.0.0/24 SSH/file transfer, small and large packets in both directions.
7. AAAA change, A+AAAA coexistence, no AAAA, no client IPv6: WG must not fall back to IPv4/HK; manually use v2rayNG.
8. Refresh outage with previous snapshot; cold start with no snapshot returns 503; subsequent recovery publishes normally.

No claim of live failover, MTU correctness or Android business recovery follows from the local tests above.


## Composition and subscription lifecycle (2026-11-07)

The required normal/switch/recovery/failure matrix is in [composition.md](composition.md).
Test startup once per process (including failure and force refresh), poll clocks, independent health TTL,
startup cache recovery after 403/empty conversion, corrupt/over-permissive cache rejection, URL isolation,
rename-without-refetch, concurrent calls, new startup sources awaiting restart, and diagnose skipping startup.
Exercise all 16 basic proxy/SG/DNS/direct combinations, TUN/WG independently, named-service validation,
API client separation and deselected capability 503, plus real-core traffic for proxy-only/SG-only/DNS hosts-only/direct.
A 200 health response is not proof of freshness: inspect ready, stale, latest sources and last_success separately.
Private source caches are deliberate state, not diagnostic dump files, and must stay out of Git/archives.
No Docker/TUN/WG/live TAG or user-side business success is claimed from these local tests.
