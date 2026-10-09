# Acceptance: normal / transition / recovery / failure

## Risk boundaries

- No production interfaces, subscriptions, keys or machines were accessed for testing.
- Only local fixtures and loopback network listeners were used. Docker cannot be run in this environment.
- A syntax check is not proof of Android VPN routing, public IPv6 reachability, or remote TLS/UDP availability.
- Scope is a reviewable repository; public exposure/deployment still requires review of the actual host mapping.

## Executed locally

| Gate | Evidence |
|---|---|
| Normal HK/SG selection | All eligible subscription nodes probed and sorted top-k; own hy2 appended as manual HK choice, not probed or default |
| Partial HK failure | Remaining subscription HK selected as default; own hy2 stays last and is not probed |
| All HK failed / recovered | Synthetic probe failure selects own hy2 as default; recovered subscription regains default while own hy2 remains manually selectable |
| No HK entries in feed | Treated as all-HK-failed: own hy2 selected, counts.hk shows tested 0 / retained 1 |
| Manual candidate merge | Private manual_nodes converted and merged; duplicate tags disambiguated; dropped entry fails the cycle |
| Tool failure detail | API keeps the static code; the core's stderr is logged to stdout only (docker logs), with URL/key/credentials redacted |
| No host diagnostic files | A failed refresh writes nothing to the host; only the validated snapshot is published |
| Fetch-stage failure | Non-validation exceptions are logged with their type and stage; diagnose re-fetches live and prints proxy env as set/unset only |
| All SG or all HK+backup failed | Reject new publication |
| Candidate overflow / absent region | Error, no partial probing masquerading as total failure |
| Probe actually traverses core | Real 1.14.2 → loopback proxy; NO_PROXY=* cannot bypass; failed proxy detected |
| Two-target probe | Wrong Google HTTP status is rejected; CacheFly checksum and exact-range response required; weighted ranking can reorder Google-only results |
| DEBUG diagnostics | Local probes report HTTP/size/hash failure reasons; selection emits each candidate endpoint, measured score and final reason; CLI validates/passes runtime log level including sudo |
| Stable log node ID | Converted outbound fields excluding mutable tag are canonicalized and SHA-256 abbreviated; reordering/renaming preserves the log ID, changing connection details changes it; client tags are unchanged |
| DIRECT > SG > HK | Real 1.14.2 local HTTP inbound with isolated proxy endpoints; shared IP goes DIRECT, SG IP/domain goes SG, remaining IP goes HK |
| WG only IPv6 | IPv4 endpoint rejected; generated domain resolver ipv6_only; core accepts WG endpoint schema |
| WG address normalisation | A bare host address is normalised to /32 and accepted by the real core; a non-/32 mask is refused |
| Config syntax | Real 1.14.2 accepts normal/backup, populated/empty SG whitelist variants |
| Conversion | Real v1.0.4 converts plain/base64 URI feeds; bad input rejected |
| Auth / readiness | Real local HTTP API: 401 before auth, 503 before ready, 200 valid Bearer/URL key, 405 POST, old key rejected after rotation |
| Refresh failures | Last valid profile remains byte-identical, static errors do not contain secret fixture text |
| Recovery / restart | Invalid settings corrected then publish; matched restart snapshot restored; settings mismatch refused |
| Render / mounts | Same flat settings shape as Compose; 0600 files, 0700 directories, owner UID/GID; existing private template not overwritten |

## Required on the actual host/client (NOT executed)

1. Docker build and startup, including base image/build/runtime proxy paths; actual UID/mount access.
   Confirm `SINGBOX_LOG_LEVEL=DEBUG` at `up` recreates the service with per-node diagnostics; return to INFO afterward.
2. HTTPS URL from SFA, automatic refresh/apply behavior, no key-bearing reverse-proxy logs.
3. Real subscription classification, proxy protocols, Google HTTPS probe results from the container.
4. Real HK subscription → own hy2 → recovered HK transitions, followed by client refresh and an actual business request.
5. SG whitelist HTTP/TLS requests and DNS routing; DIRECT public DNS requests; ordinary mainland sites must still go HK unless listed.
6. Actual WireGuard-over-IPv6 handshake and 10.77.0.0/24 SSH/file transfer, small and large packets in both directions.
7. AAAA change, A+AAAA coexistence, no AAAA, no client IPv6: WG must not fall back to IPv4/HK; manually use v2rayNG.
8. Refresh outage with previous snapshot; cold start with no snapshot returns 503; subsequent recovery publishes normally.

No claim of live failover, MTU correctness or Android business recovery follows from the local tests above.
