# Design / source boundaries

This repository is the profile publisher; the current patch extends freshly fetched main, not a live deployment snapshot.
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

1. Load private settings, compile named services into client-selected capabilities (or adapt the legacy document), and validate every client and source. Accept either legacy single URL or up to 32 named
   subscriptions, never both. Sources use local curl by default (URL over stdin, optional UA, inherited proxy env) or
   explicitly urllib. There is no third-party conversion service.
2. Fetch/convert sources using poll or startup policy. Keep a verified, private per-source catalog and explicitly report stale fallback; no cache is shared across source credentials. Deduplicate exact connection+original-name pairs, disambiguate collisions and merge manual nodes. All-poll-source failure retains publication; a startup cache can continue to be probed and published. Fetch cadence and probe-result TTL are separate clocks. A client set with no proxy/SG capability does not fetch or probe nodes.
3. Classify original names into HK/SG/other BEFORE rewriting. Apply the first configured regex replacement, with arbitrary
   numbered captures and $index per expanded template/type. Optional capture_defaults fill empty/unmatched groups consistently in both replacement and type. Capture 2 is only a display label; no metadata is inserted into
   real outbound fields. Input order (not probe completion or health) determines numbering; aliases may change on input deletion.
4. Check every candidate and own_hy2 syntax using the pinned core. All candidates must pass exact Google 204 and bounded
   CacheFly range size/digest checks. Test every Google-passing node, not a shortlist; rank by 60%/40% times. Positive and
   negative results (including exceptions) have the configured TTL, keyed by full endpoint/credential/transport identity, timeout and bootstrap DNS.
5. Build default `proxy` from ALL verified nodes, without top-k truncation, and an independent SG selector with top-k. No HK selector is emitted; internal HK ranking is retained only for the initial default and health summary. Include
   own_hy2 only after it passes both tests; do not let it race for preferred default against verified subscription HK. If all
   HK and own_hy2 fail, general traffic may still use another healthy region. No usable SG refuses publication only when some client selects the SG capability. The batch remains atomic across clients.
6. General traffic, ordinary proxy DNS and remote rule downloads follow proxy. Explicit SG traffic and SG DNS stay on the
   separate sg selector. DIRECT/hosts/WG policy order is unchanged. Test every supported device/mode profile with real core,
   then atomically persist the whole batch. A failure retains exact previous data and snapshot bytes.
7. GET authenticates each device key against current settings, serves only its checked profile and requires client
   refresh/reapply. Selector changes on the client do not change explicit SG rules. No runtime automatic selector failover.

On restart the snapshot is used only when its layout version is 3, the rendered settings fingerprint and device IDs match and all profiles pass the core checker.
During normal operation failed refresh retains the old snapshot; GET refuses an old profile if the client capability/route/ingress contract changed, rather than serving deselected capabilities. `stale` communicates refresh failures.
API authentication is checked against the current rendered settings, independently of the old snapshot key.

## Non-goals

No live host configuration changes, protocol server creation, frp fallback, DNS API writes, scheduler installation,
instant client push, on-client latency racing, China-wide bypass, or automatic recovery to v2rayNG.

Concrete configuration and routing order: [subscriptions.md](subscriptions.md). Shared rules for manual nodes are read at selection time, not frozen in the fetched catalog. Ordinary DNS is named dns-proxy and detours proxy.

Legacy unversioned HK snapshots are left on disk but not restored into proxy-layout variants. First upgrade must complete a fresh publication; only version-3 snapshots use this revision's restart recovery path. Source catalogs have their own version=1 and owner/0600 validation. Native check is not a substitute for this compatibility gate.

Composition and lifecycle contract: [composition.md](composition.md). Reuse native sing-box selectors, route rules and DNS servers; no additional plugin or runtime is installed. Official semantics consulted on 2026-11-07: [route actions](https://sing-box.sagernet.org/configuration/route/rule_action/), [DNS](https://sing-box.sagernet.org/configuration/dns/), [TUN](https://sing-box.sagernet.org/configuration/inbound/tun/). Runtime tests use pinned core 1.14.2.
