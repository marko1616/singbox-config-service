# Design / source boundaries

This repository is a new local implementation proposal, not live-fetched production state.
No private inputs were read. All tests use synthetic keys and local-only mock services.
The old marko-network worktree and its uncommitted edits are untouched.

## Existing solution preflight

- Sub-Store supports subscription conversion, but its broader management surface is not needed here.
- Reuse rainbend/sing-box-subscribe-cli v1.0.4 for parsing instead of inventing another URI parser.
- The custom part is narrowly limited to agreed policy, container-side probing, private rendering, atomic snapshots and authenticated GET.

## Versioned semantics

- https://github.com/SagerNet/sing-box/blob/v1.14.2/option/group.go
  Selector has a default; URLTest has no ordered backup-only priority setting. Do not put own hy2 into an ordinary URLTest race.
- https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/wireguard/endpoint.go
  ResolvePeer uses the endpoint dialer's QueryOptions. The endpoint domain_resolver strategy is ipv6_only.
- https://github.com/SagerNet/sing-box/blob/v1.14.2/option/outbound.go
  DomainResolveOptions carries the resolver server and strategy.
- https://github.com/rainbend/sing-box-subscribe-cli/tree/v1.0.4
  Local --only-nodes conversion, not an online conversion service.

## Minimal state machine

1. Load rendered private settings (flat JSON; exactly the shape mounted by Compose).
2. Fetch HTTPS subscription, convert locally, classify all matching HK/SG candidates.
3. Check candidate syntax with pinned core; require Google 204 with an empty body for every candidate.
   Download and hash-check a bounded CacheFly range only for each region's Google-leading shortlist,
   extending it if fewer than k pass. Rank verified nodes by 60% Google time + 40% CacheFly transfer time.
4. Append own hy2 to the HK selector for manual choice on every successful publication, after subscription top-k.
   Probe it only when HK subscription nodes are empty after probing (including no HK entries); then it becomes default only if healthy.
   Singapore has no backup, so an empty or fully failing SG group refuses publication.
   Private manual_nodes are merged with subscription nodes before classification and probing.
5. Build one client profile; real sing-box check; atomically persist snapshot before making it available.
6. GET serves only a checked snapshot. Refresh failures keep the previous snapshot, expose only static errors, and retry.

On restart the snapshot is used only when the rendered settings fingerprint matches and the profile passes the core checker.
During normal operation failed refresh retains the old profile even if policy settings changed; `stale` communicates this.
API authentication is checked against the current rendered settings, independently of the old snapshot key.

## Non-goals

No live host configuration changes, protocol server creation, frp fallback, DNS API writes, scheduler installation,
instant client push, on-client latency racing, China-wide bypass, or automatic recovery to v2rayNG.
