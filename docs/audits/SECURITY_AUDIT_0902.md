# Security Audit — openledger-v2

**Date:** 2026-09-02
**Scope:** Entire workspace — `gl-node`, `ledger`, `p2p`, `security` crates, plus Docker, docker-compose, CI, configs, scripts, committed fixtures, and `Cargo.lock` dependencies.
**Method:** Four parallel passes: (1) adversarial re-verification of every open 09/01 finding against current HEAD (`b6bf634`), (2) fresh line-by-line hunts over the HTTP/GraphQL surface, (3) the P2P/network layer, and (4) the ledger engine, crypto crate, and deployment surface — each explicitly scoped to find what the 09/01 audit missed. Load-bearing library-behavior claims were verified against vendored registry sources (`axum` 0.8.9 / `axum-core` 0.5.6, `async-graphql`(-axum) 7.2.1, `iroh` 1.0.3, `iroh-gossip` 0.101.0, `ciborium` 0.2.2, `rust_decimal` 1.42, `ed25519-dalek` 2.2.0); the top HTTP finding was additionally confirmed with a runtime reproduction against the exact dependency versions. `cargo audit` 0.22.2 was run against the current RustSec DB. The full workspace test suite was run at HEAD.
**Baseline:** [SECURITY_AUDIT_0901.md](SECURITY_AUDIT_0901.md). Its addendum already confirmed every 08/20 finding closed; that closure was **not** re-litigated here. Finding IDs continue the 09/01 numbering: carryover items keep their IDs; new items start at **H-05 / M-12 / L-19**.

---

## Executive summary

**Nothing from the 09/01 report has been remediated.** The only commit since that audit (`b6bf634`) added the report itself plus the two fixes its addendum describes. Accordingly: **H-01 through H-04 are all still open**, as are M-04 and M-06 through M-11 and seventeen of the eighteen Lows (M-01 is confirmed fully fixed with tests; L-06's remote-path exploitability was incidentally closed by the M-01 fix, leaving only latent design debt). Section 1 has the re-verified evidence with current line references.

This audit also found **2 new High-severity issues** and **7 new Mediums** in territory the 09/01 pass did not reach:

1. **H-05** — The 2 MiB GraphQL body cap **does not work at all**. `axum`'s `DefaultBodyLimit` only applies when the extractor opts in, and `async-graphql-axum` reads the raw body stream — verified by runtime reproduction: an 8 MiB POST returns 200. The server buffers arbitrarily large request bodies into RAM (`read_to_end`), so anyone who can reach `/graphql` — any authorized key-holder, or on default configs any website via H-01's CSRF vector — can OOM the node. The source comment claiming a 2 MiB cap is false assurance.
2. **H-06** — `openledger-*` metadata keys smuggled inside the *economic body* bypass every envelope control (closed key set, 32 KiB value cap, control-char check), because the content hash strips all `openledger-*` keys before hashing. The victim stores and persists the smuggled keys; on re-serve, `extract_envelope` promotes them into the envelope — where the *next* hop's closed-key-set check rejects the directive forever. One allowlisted peer plants state that replicates to its direct victims and then poisons every honest-to-honest transfer: permanent divergence plus a perpetual re-Want livelock, in the same family as H-03 but via a second, independent hole. An innocent hand edit with a stray `openledger-` key triggers the same fate.

Among the new Mediums: the gossip allowlist authenticates only the **previous hop**, not the origin (`delivered_from` is the relay — iroh-gossip's protocol layer relays first-seen messages before the application filter runs), which makes the M-07 announce-flood amplification reachable by **unauthenticated** strangers (M-12); the HTTP server has no header/read/idle timeouts and no connection cap, so classic slowloris works pre-auth even on hardened public binds (M-13); and three committed peer configs point three concurrent nodes at the **same ledger file** with no inter-process locking — last-writer-wins silently destroys directives in the documented dev flow (M-17).

**Fix-first list:** H-02 (organic mesh wedge, still the ship-blocker) → H-05 + H-01 (the default node is drive-by writable *and* trivially OOM-able) → H-04 → H-03 + H-06 together (one remote-body canonicalization pass closes both) → M-13 → M-12/M-07. Section 8 has the complete prioritized backlog with per-task change/files/verify detail — the 09/01 findings never got a remediation backlog (docs/audits/OUTSTANDING_TASKS.md only tracks 08/20); this document now carries one for everything open.

Also in this audit: the one-time online verification that CI's pinned action SHAs match their claimed tags **passed** (all four pins good), `cargo audit` is unchanged from 09/01 (no new advisories; h2/rkyv assessments still hold), and the workspace test suite is green at HEAD except `three_node_alpn_convergence`, which is flaky under parallel execution (passes in isolation) — bad hygiene in exactly the anti-entropy area where H-02 lives.

---

## Threat model

Unchanged from 09/01 (remote API caller; malicious/compromised allowlisted peer; supply chain; the protocol itself), with two sharpenings this audit forces:

- **The "allowlisted peer" boundary is weaker than documented on the gossip path.** M-12 shows gossip Announce content is effectively unauthenticated: any host that learns the topic string and one member id can inject announces that arrive bearing an allowlisted `delivered_from`. Gossip-derived data must be treated as untrusted hints.
- **The operator's own tools are attackers of availability.** H-06 (stray hand-edited key), L-28 (editor BOM), and M-17 (documented three-nodes-one-file dev flow) all brick or corrupt without malice.

---

## 1. Status of the 2026-09-01 findings (re-verified at HEAD `b6bf634`)

Every finding was re-verified against source, not assumed. Line references below are **current** (they shifted in `union_merge.rs` and `checkpoint.rs`).

### 1.1 Fixed

| Finding | Verdict | Evidence |
|---|---|---|
| **M-01** Lamport clock poisoning | **Fixed — verified complete** | `MAX_REMOTE_LAMPORT = 1<<53` ([union_merge.rs:41-50](../../crates/p2p/src/union_merge.rs#L41-L50)); strict checks run on the **merged** metadata of every directive kind — parents count ≤256, each parent 64-hex, lamport non-empty decimal-u64 ≤2^53 ([union_merge.rs:184-230](../../crates/p2p/src/union_merge.rs#L184-L230)) — before author/signature verification ([anti_entropy_alpn.rs:242-255](../../crates/gl-node/src/anti_entropy_alpn.rs#L242-L255)), re-verified on orphan drain. Tests cover u64::MAX, non-numeric, malformed parents, and non-transaction kinds ([union_merge.rs:609-755](../../crates/p2p/src/union_merge.rs#L609-L755)). |
| **L-06** `\|`-concatenated signature message | **Remote exposure closed; latent design debt remains** | The M-01 fix guarantees remote `parents`/`lamport` are hex-CSV/decimal before `verify_remote_signature`, so `\|` can no longer be injected remotely ([signing.rs:91-103](../../crates/security/src/signing.rs#L91-L103), [union_merge.rs:206-230](../../crates/p2p/src/union_merge.rs#L206-L230)). Length-prefix the fields on the next domain bump. |

### 1.2 Still open — every other 09/01 finding

**High (all four confirmed open):**

| ID | Finding | Current key evidence |
|---|---|---|
| **H-01** | CSRF (write) + DNS rebinding (read/write) on default loopback config | Bare `GraphQLRequest` extractor, no Content-Type/Origin/Host validation anywhere ([graphql/mod.rs:98-103](../../crates/gl-node/src/graphql/mod.rs#L98-L103), [main.rs:266-302](../../crates/gl-node/src/main.rs#L266-L302)); auth defaults off ([config.rs:63-71](../../crates/gl-node/src/config.rs#L63-L71)); shipped [gl-node.config.json](../../gl-node.config.json) is auth-off + GraphiQL-on. |
| **H-02** | Anti-entropy senders violate their own receive caps → deterministic mesh sync wedge >4,096 directives | One un-chunked `WireMessage::supply` per Want ([anti_entropy_alpn.rs:84-87](../../crates/gl-node/src/anti_entropy_alpn.rs#L84-L87)) vs `MAX_SUPPLY_ENTRIES=256`; `to_wire()` never checks `MAX_MESSAGE_SIZE` ([protocol.rs:188-195](../../crates/p2p/src/protocol.rs#L188-L195)); `make_have_heads` advertises all ids unbounded ([anti_entropy.rs:42-52](../../crates/p2p/src/anti_entropy.rs#L42-L52)) vs `MAX_HAVE_HEADS=4096`. Only Want sends are chunked. |
| **H-03** | Elided-posting content-ID shift plants permanently divergent, un-replicable state | Id checked against as-sent (elided) body ([union_merge.rs:150-157](../../crates/p2p/src/union_merge.rs#L150-L157)); resolved postings stored ([service.rs:1118-1126](../../crates/ledger/src/service.rs#L1118-L1126), [validate.rs:276-291](../../crates/ledger/src/validate.rs#L276-L291)); DAG re-hashes stored body ([dag.rs:101](../../crates/ledger/src/dag.rs#L101)). |
| **H-04** | Signed-year dates persist then brick every subsequent boot | No year-range check in `DateScalar::parse` ([scalars.rs:12-21](../../crates/gl-node/src/graphql/scalars.rs#L12-L21)) or the service layer; serializer emits signed years at 11 `%Y-%m-%d` sites ([serialize.rs:115](../../crates/ledger/src/serialize.rs#L115) et al.); `read_date` requires 4 leading digits ([parse.rs:71-94](../../crates/ledger/src/parse.rs#L71-L94)) → boot aborts ([main.rs:105-111](../../crates/gl-node/src/main.rs#L105-L111)). |

**Medium (M-02, M-03, M-05 were closed pre-09/01; the rest confirmed open):**

| ID | Finding | Current key evidence |
|---|---|---|
| **M-04** | Rate limiting collapses behind a proxy; IPv6 /128 rotation | [rate_limit.rs:20-24,46-80](../../crates/gl-node/src/rate_limit.rs#L46-L80), wired at [main.rs:325-328](../../crates/gl-node/src/main.rs#L325-L328). |
| **M-06** | No I/O timeouts anywhere + serial anti-entropy loop | No `tokio::time::timeout` in [anti_entropy_alpn.rs](../../crates/gl-node/src/anti_entropy_alpn.rs) (reads/writes at :350-371 await forever); sequential peer loop [p2p_service.rs:250-258](../../crates/gl-node/src/p2p_service.rs#L250-L258). |
| **M-07** | Announce flood: unbounded task spawn + fresh QUIC dial per unknown id, no in-flight dedup | [p2p_service.rs:169-183](../../crates/gl-node/src/p2p_service.rs#L169-L183); `fetch_want` dials per call ([anti_entropy_alpn.rs:112-121](../../crates/gl-node/src/anti_entropy_alpn.rs#L112-L121)). Now worse — see M-12. |
| **M-08** | `checkpoint.rs` still dead code; balance/pad persisted unenforced | Only caller is a test; catch-all insert at [service.rs:1160-1171](../../crates/ledger/src/service.rs#L1160-L1171). The b6bf634 `checked_sub` hardening is present ([checkpoint.rs:74-78](../../crates/ledger/src/checkpoint.rs#L74-L78)) — inside still-uncalled code. |
| **M-09** | Account lifecycle arrival-order dependent; remote `close` applied unconditionally | `let _ =` on remote close/open ([service.rs:1135-1150](../../crates/ledger/src/service.rs#L1135-L1150)); tx-before-open rejected outright, orphan buffer only holds parent-missing entries ([anti_entropy_alpn.rs:256-272](../../crates/gl-node/src/anti_entropy_alpn.rs#L256-L272)). |
| **M-10** | Economic-hash dedup authorship squatting | Hash excludes all `openledger-*` ([serialize.rs:345-349](../../crates/ledger/src/serialize.rs#L345-L349)); first-arrival keeps the envelope ([service.rs:598-604,1075-1077](../../crates/ledger/src/service.rs#L598-L604)). |
| **M-11** | Gossip overlay open; eclipse empties the peer registry and idles anti-entropy | Registry populated only by allowlisted `NeighborUp` ([p2p_service.rs:198-209](../../crates/gl-node/src/p2p_service.rs#L198-L209)); loop skips when empty (:245-258); bootstrap peers never proactively dialed. |

**Low — all seventeen remaining Lows confirmed open** with only line shifts. Notables re-pinned: L-12 reconcile re-persist that erases rejected hand edits now at [service.rs:945-948](../../crates/ledger/src/service.rs#L945-L948); L-13 cap-after-mutate at [service.rs:43-52](../../crates/ledger/src/service.rs#L43-L52); L-17 heads/children backfill gap at [dag.rs:143-161](../../crates/ledger/src/dag.rs#L143-L161); L-18 open/close gossip under the write lock at [mutation.rs:158,192](../../crates/gl-node/src/graphql/mutation.rs#L158). Full carryover list: L-01…L-05, L-07…L-18 (see the 09/01 report for narratives; the consolidated register in §7 tracks them all).

---

## 2. New findings — High

### H-05 — The GraphQL body limit is silently ineffective: unbounded request bodies buffered into RAM
**Where:** [main.rs:29-30,301](../../crates/gl-node/src/main.rs#L301) (`DefaultBodyLimit::max(2 MiB)`), [graphql/mod.rs:98-103](../../crates/gl-node/src/graphql/mod.rs#L98-L103) (bare `GraphQLRequest` extractor). **Verified by runtime reproduction** with the exact dependency versions (axum 0.8.9 + async-graphql-axum 7.2.1): an 8 MiB POST under the same layer returns **200 OK**, not 413.

`axum`'s `DefaultBodyLimit` is opt-in: it only inserts an extension, and the limit applies solely when an extractor calls `into_limited_body()`. Its own docs say a direct body read bypasses it. `async-graphql-axum`'s extractor reads `req.into_body().into_data_stream()` (vendored `extract.rs:118`) — never the limited body — and `receive_batch_json` then does `read_to_end` into an unbounded `Vec`. Neither the explicit cap nor axum's built-in default applies to `POST /graphql`.

**Attack:** on the default loopback config (auth off), any local process — or any website via H-01's no-preflight CSRF — POSTs a multi-GB body (e.g. huge `variables`); the node buffers it all and OOMs. On a hardened public bind, auth runs before the body is read, but any single key-holder can still OOM the node, and the 60/min limiter permits 60 such bodies a minute. The comment on `GRAPHQL_MAX_BODY_BYTES` ("Axum's default is also 2 MiB") is false assurance — neither limit fires.

**Fix:** add `tower_http::limit::RequestBodyLimitLayer::new(GRAPHQL_MAX_BODY_BYTES)` (tower-http is already a dependency) — it wraps the body in `http_body_util::Limited`, which fails the extractor's stream read past the cap regardless of extractor behavior, and also covers multipart (async-graphql's `MultipartOptions::default()` has no size limits either). Keep `DefaultBodyLimit` or drop it, but fix the comment. **Regression test:** POST a >2 MiB body, assert 413/400.

### H-06 — Body-embedded `openledger-*` metadata bypasses every envelope control → hash-invisible payload, then next-hop poisoning and permanent divergence
**Where:** [union_merge.rs:159,235-258](../../crates/p2p/src/union_merge.rs#L235-L258) (closed key set / 32 KiB caps / control-char check run on `entry.envelope` **only**), [serialize.rs:345-349](../../crates/ledger/src/serialize.rs#L345-L349) (content hash strips **all** `openledger-*` keys, posting-level included), [gossip.rs:54-73](../../crates/p2p/src/gossip.rs#L54-L73) (`extract_envelope` promotes every `openledger-*` metadata key into the envelope on re-serve), [parse.rs:963-967](../../crates/ledger/src/parse.rs#L963-L967) (metadata after a posting attaches to the posting — uncapped: [service.rs:128-137](../../crates/ledger/src/service.rs#L128-L137) counts directive-level keys only).

The closed envelope key set is enforced against the wire envelope, but the parsed economic body can itself carry arbitrary `openledger-*` metadata lines (directive-level or per-posting, up to ~1 MiB across 1,000 postings). Because the canonical serializer strips every such key before hashing, the content-id check passes; the strict step-5 checks cover only `openledger-parents`/`-lamport` formats. So an allowlisted peer's smuggled keys are validated by nothing, stored, and persisted into the victim's `.bean`.

**Consequences (two independent failure modes):**
1. **Next-hop poisoning / divergence livelock.** When the victim re-serves the directive, `extract_envelope` promotes the smuggled key into the envelope — and every downstream node rejects it (`unsupported envelope key`). Directly-seeded replicas hold the directive forever; every honest-to-honest transfer fails forever; nodes missing it re-`Want` it every anti-entropy tick, and its descendants orphan repeatedly at the deprived nodes. Same family as H-03, via a second hole.
2. **Hash-invisible attacker bytes + byte-divergent files.** The victim's ledger file permanently carries arbitrary attacker-chosen bytes covered by no hash or signature (covert storage; planted authoritative-looking fields such as a bogus `openledger-signature` on a non-transaction). Replicas hold identical DAG ids with different file bytes — the byte-identical-file guarantee (I7) is broken silently.

An operator hand edit containing any stray `openledger-` key produces the same never-replicates outcome with no attacker.

**Fix:** after envelope/body merge, reject any directive whose body-parsed metadata (directive- **and posting-level**) contains any `openledger-*` key — the envelope is the only legal carrier; run the control-char and count caps over merged metadata. Fold this into the same remote-body canonicalization pass as H-03's elided-posting rejection (backlog T-21). **Regression tests:** body-embedded `openledger-x` at directive and posting level → rejected; hand-file with stray key → reconcile rejects rather than adopts.

---

## 3. New findings — Medium

### M-12 — Gossip allowlist authenticates only the last hop: `delivered_from` is the relay, not the origin
**Where:** [p2p_service.rs:160](../../crates/gl-node/src/p2p_service.rs#L160) (`allowlist.admits(msg.delivered_from)`). **Verified against vendored iroh-gossip 0.101.0 source:** `delivered_from` is documented as "the peer before us in the gossiping path", and the plumtree layer relays every first-seen message to neighbors **before** the application sees `Event::Received` (`proto/plumtree.rs:490-545`).

A stranger who joins the topic (membership is open — M-11) broadcasts an Announce; the allowlisted neighbor's application drops it, but its gossip layer has already relayed it; every node two-plus hops away receives it with `delivered_from` = the innocent allowlisted relay and passes the check. The 09/01 "allowlist-before-decode on gossip: sound" verdict verified ordering, not efficacy — the gate is a one-hop filter. **Impact:** the M-07 announce-flood amplification (ledger lookup + task spawn + fresh QUIC dial per unknown id) becomes reachable **unauthenticated**, and logs blame the relay. **Fix:** treat gossip content as unauthenticated hints — dedup/negative-cache announce ids, rate-limit fetch work, cap concurrency (merge with M-07's fix, backlog T-23) — or sign announces. Do not present `admits(delivered_from)` as a security boundary.

### M-13 — No HTTP server timeouts or connection cap: slowloris works pre-auth on any bind
**Where:** [main.rs:325-329](../../crates/gl-node/src/main.rs#L325-L329). **Verified in vendored axum 0.8.9:** `axum::serve` spawns one task per connection via hyper-util's auto builder with no header-read, idle, keep-alive, or request timeout; hyper 1.x sets none by default; the stack has no timeout layer and no concurrency limit.

Open many connections and: dribble headers forever, dribble a declared body, or hold completed keep-alive connections idle. Each is a live task with no ceiling → FD/task/memory exhaustion. All of this happens **before** the router runs, so rate limiting and auth never fire — it works against a fully hardened public bind. Nothing in code or config requires the TLS-terminating proxy to enforce these either. **Fix:** drive connections with explicit `header_read_timeout`/keep-alive timeouts, add a request `TimeoutLayer`, and bound concurrent connections (semaphore in the accept loop or `ConcurrencyLimit`). Document that the required proxy must also enforce them.

### M-14 — Full validation runs before dedup on the Supply write path: replayed duplicates cost full price forever
**Where:** [anti_entropy_alpn.rs:241-243](../../crates/gl-node/src/anti_entropy_alpn.rs#L241-L243) (validate first), [service.rs:1073-1077](../../crates/ledger/src/service.rs#L1073-L1077) (dedup last).

Every supplied entry is parsed (≤1 MiB beancount), canonically re-serialized, SHA-256'd, and Ed25519-verified before anything checks whether `entry.id` already exists. Unsolicited Supply is accepted on the serve path, so an allowlisted peer replays the same 256×1 MiB message in a loop: each replay costs ~16 MiB of parsing plus 256 signature verifications and changes nothing. Distinct from L-01 (read path); this is the write path, needs no request. **Fix:** check `get_directive(&entry.id)` before validating — entries whose claimed id is already present are discarded regardless of content, so the skip is semantics-preserving. One line.

### M-15 — Remote-triggered O(M×N) work under the global write lock: per-directive whole-file persist + per-drain full id-set clone, cascading into an API stall
**Where:** [service.rs:806-811](../../crates/ledger/src/service.rs#L806-L811) (persist clones every directive and rewrites the whole file, synchronous `std::fs` on the tokio runtime), invoked per remote insert (:1129, :1143, :1154, :1165); [anti_entropy_alpn.rs:280-289,308](../../crates/gl-node/src/anti_entropy_alpn.rs#L280-L308) (`drain_orphans` per inserted entry; `all_directive_ids()` clones every id String per call).

Catch-up sync of M directives on an N-directive ledger costs O(M×N) CPU and IO under the **write** lock. Cascade: the gossip loop blocks on `ledger.read()` → its channel fills → GraphQL mutations block on `send().await` — one busy (or malicious) allowlisted peer stalls the local API. Subsumes and amplifies 09/01's L-13. **Fix:** batch persist per Supply message (or debounce), keep an incremental id index instead of cloning, move file IO to `spawn_blocking` outside the lock.

### M-16 — CBOR cardinality caps enforced only after full decode; serde `Content` buffering gives ~30-60× transient amplification per frame, with unbounded inbound connections
**Where:** [protocol.rs:31](../../crates/p2p/src/protocol.rs#L31) (`#[serde(tag = "type")]` — internally tagged), [protocol.rs:175-185](../../crates/p2p/src/protocol.rs#L175-L185) (decode fully, then `check_cardinality`); **verified** vendored iroh 1.0.3 Router spawns an unbounded task per inbound connection and gl-node sets no incoming filter or per-peer cap.

A 16 MiB Want/HaveHeads frame of ~16.7M one-byte ids fully decodes — buffered first into serde's generic `Content` tree (~40-56 B/element) — roughly 0.5–1 GiB transient heap **before** the cap rejects it. Allowlisted-peer only (gossip frames are capped at 4 KiB by iroh-gossip's default — verified), but repeatable per message and multipliable across connections: one compromised peer OOMs the node. **Fix:** cheap pre-decode structural check (scan the CBOR array headers) or a much smaller frame cap for non-Supply messages; cap concurrent ALPN connections per peer (also closes L-19's pinned-allocation vector).

### M-17 — No inter-process exclusivity on the ledger file; committed configs point three concurrent nodes at the same `.bean`
**Where:** [service.rs:43-108](../../crates/ledger/src/service.rs#L43-L108) (no flock/lockfile anywhere in the workspace; the `AlreadyExists → remove_file → retry` path at :78-85 deletes a *sibling process's* in-flight temp file), [config/gl-node.peer-0.json](../../config/gl-node.peer-0.json) / peer-1 / peer-2 (all `"ledgerPath": "test-ledger.bean"`), [scripts/tests.sh](../../scripts/tests.sh) (documents running all three concurrently).

Two processes on one file hold independent DAGs and each rewrites the whole file per mutation: last-writer-wins silently discards the other's directives (no reconcile by default). This is the *documented* dev flow, and the same gap hits production on restart overlap or two containers sharing a volume. **Fix:** exclusive advisory lock (flock or sidecar lockfile) at boot, fail closed; give each sample peer config its own `ledgerPath`.

### M-18 — Boot Lamport scan ignores non-transaction directives: the clock regresses on restart and re-issues used `(author, lamport)` pairs — already visible in committed data
**Where:** [service.rs:416-421](../../crates/ledger/src/service.rs#L416-L421) (`max_lamport` updated only for `Directive::Transaction`), while envelope stamping applies lamport to opens/closes too (:781-788).

No attacker needed: if the highest lamport sits on an `open`/`close`, a restart resets the clock below it and the next mutation **signs and persists a duplicate lamport under the same author**. In-tree proof: [test-ledger.bean:35-41](../../test-ledger.bean#L35-L41) — two different `open` directives both carry `openledger-lamport: "8"`. The signed envelope's causal-ordering claim loses per-author uniqueness and the clock moves backwards relative to persisted history. **Fix:** track max lamport across all directive kinds at boot (one-line match change) + a restart round-trip regression test.

---

## 4. New findings — Low

- **L-19 — 16 MiB pre-allocation pinned per stalled stream.** `read_message` allocates `vec![0u8; len]` from the length prefix before any body byte arrives ([anti_entropy_alpn.rs:366](../../crates/gl-node/src/anti_entropy_alpn.rs#L366)); with no timeouts (M-06) and no per-peer connection cap (M-16), a peer sending 4-byte headers claiming 16 MiB then stalling pins N×16 MiB indefinitely.
- **L-20 — Orphan-buffer byte accounting undercounts 3-5×; eviction only runs on insert; duplicate-insert mislabeled.** `size_bytes` counts the economic body only ([orphan_buffer.rs:107](../../crates/p2p/src/orphan_buffer.rs#L107)) — envelope (~17 KiB legit max) and the `waiting_on` reverse index are unbudgeted; `evict_expired` runs only inside `insert` (:99) so expired orphans pin memory after a burst; the contains-check at :124 runs after the budget checks, so a duplicate insert under full budgets reports "buffer full".
- **L-21 — `compute_want` and `collect_supply` never dedup ids** ([anti_entropy.rs:15-36](../../crates/p2p/src/anti_entropy.rs#L15-L36), [anti_entropy_alpn.rs:228-233](../../crates/gl-node/src/anti_entropy_alpn.rs#L228-L233)): a repeated id is fetched, served, and revalidated once per copy (composes with M-14). Build the want as a set.
- **L-22 — `anti_entropy_interval_milliseconds: 0` silently kills replication.** No config bound; `tokio::time::interval(Duration::from_millis(0))` panics inside the spawned task ([p2p_service.rs:239](../../crates/gl-node/src/p2p_service.rs#L239)) — the process survives, anti-entropy is dead with one log line.
- **L-23 — `mesh_id` is just the swarm-topic string → cross-mesh signature replay when two meshes pick the same custom topic** ([signing.rs:94-105](../../crates/security/src/signing.rs#L94-L105); config only forbids the *default* topic). The topic also doubles as the gossip join credential. Use a random per-mesh UUID as the signature domain; treat the topic as sensitive.
- **L-24 — Rate limiter does an O(n) full-map `retain` under one global mutex on every request** ([rate_limit.rs:46-66](../../crates/gl-node/src/rate_limit.rs#L46-L66)); with IPv6 bucket churn (M-04) this is quadratic total work and a throughput choke point. Prune lazily/on threshold; shard.
- **L-25 — Unicode homoglyph account/tag spoofing; parse/API charset asymmetry.** After each segment's first ASCII-uppercase char, any Unicode alphanumeric is accepted ([parse.rs:206-296](../../crates/ledger/src/parse.rs#L206-L296)) with no normalization: `Assets:Cаsh` (Cyrillic а) is a distinct, visually identical account — balances split invisibly in every report. Meanwhile API-side `validate_tag`/`validate_link` are ASCII-only, so file and API disagree. Restrict to ASCII at parse time or NFC-normalize + confusable-check. (Control chars, RLO, zero-width, newlines are correctly rejected — injection is not possible; this is purely confusability.)
- **L-26 — Control-character policy unenforced on remote and reconciled body strings.** `reject_control_characters` guards the local API only ([service.rs:516-523](../../crates/ledger/src/service.rs#L516-L523)); remote/reconcile string fields keep ESC/NUL/`\t`/mid-line `\r` ([parse.rs:108-130](../../crates/ledger/src/parse.rs#L108-L130)) — an allowlisted peer persists ANSI escape sequences into every replica's `.bean` (terminal spoofing when operators `cat` it), and remote peers can persist what the local API rejects. Fold into T-21's canonicalization pass.
- **L-27 — Nondeterministic elided-posting fill currency when all sums are zero → nondeterministic txid.** `resolve_elided` picks `sums.iter().next()` off a `HashMap` ([weights.rs:156-169](../../crates/ledger/src/weights.rs#L156-L169)); the same logical append yields different txids across nodes/restarts (breaks retry idempotency) and randomly passes/fails currency constraints. Pick lexicographically-smallest or reject zero-imbalance elision.
- **L-28 — UTF-8 BOM bricks boot.** No BOM strip in `parse_file` ([parse.rs:388-407](../../crates/ledger/src/parse.rs#L388-L407)); an editor saving the ledger with a BOM makes every boot fail. Same availability class as H-04, triggered by an innocent edit. Strip it.
- **L-29 — Uppercase-hex parent txids defeat the orphan pre-buffer validation.** Both well-formedness checks use `is_ascii_hexdigit()` ([service.rs:120-125](../../crates/ledger/src/service.rs#L120-L125), [union_merge.rs:206-212](../../crates/p2p/src/union_merge.rs#L206-L212)) but stored ids are always lowercase and lookups are exact — an uppercase form of a *real* txid passes validation yet can never resolve: TTL-long orphan squatting + perpetual re-Want churn, precisely what the 09/01 fix aimed to prevent. Require `^[0-9a-f]{64}$`.
- **L-30 — Watcher lost-update race: a hand edit is clobbered by any concurrent local persist before reconcile sees it.** The 250 ms poll ([main.rs:205-238](../../crates/gl-node/src/main.rs#L205-L238)) is uncoupled from writes; `persist` unconditionally rewrites from memory — the user's edit is destroyed without ever being parsed (distinct from L-12, which is reconcile's own ordering). Compare the on-disk hash to last-persisted before persisting; reconcile first on mismatch.
- **L-31 — Ledger file pre-created with umask-default permissions**, bypassing the 0600 creation path: `std::fs::write(&ledger_path, "")` at [main.rs:123-129](../../crates/gl-node/src/main.rs#L123-L129) leaves the financial ledger world-readable until first mutation. Delete the pre-create (boot handles it) or chmod.
- **L-32 — `write_secret_key_file` uses `create(true)` (follows a pre-planted symlink — inconsistent with the ledger temp-file `create_new` hardening) and never fsyncs**; a crash can leave an empty key file that aborts every subsequent boot ([p2p_service.rs:318-337](../../crates/gl-node/src/p2p_service.rs#L318-L337)).

---

## 5. New informational

- **Test hygiene:** `three_node_alpn_convergence` is flaky under full-suite parallelism (failed in this audit's run, passes in isolation in ~1.3 s). A flaky convergence test can mask real regressions in exactly the H-02 area — serialize it or isolate its network setup.
- `GL_NODE_API_KEY` env var applies **only** when the config-file `apiKey` is empty ([config.rs:238-244](../../crates/gl-node/src/config.rs#L238-L244)) — env-based key rotation silently loses to a stale file value. No config-file permission check either (the file may carry the API key world-readable).
- Registry heads are never populated (`upsert(peer, vec![])` is the only writer, [p2p_service.rs:201](../../crates/gl-node/src/p2p_service.rs#L201)) — `all_remote_heads()` is always empty and GraphQL peer-head reporting is misleading.
- `head_exchange`/`filter_supply_requests` ([anti_entropy.rs:57-129](../../crates/p2p/src/anti_entropy.rs#L57-L129)) are production-dead; the latter is O(n²) if ever wired.
- The gossip loop exits permanently if the initial `subscribe` fails ([p2p_service.rs:120-126](../../crates/gl-node/src/p2p_service.rs#L120-L126)) — no retry; announces then silently drop.
- `serve_anti_entropy` classifies clean EOF by error-string substring match ([anti_entropy_alpn.rs:76](../../crates/gl-node/src/anti_entropy_alpn.rs#L76)) — fragile across iroh/quinn upgrades. `to_wire` casts length to `u32` unchecked ([protocol.rs:190](../../crates/p2p/src/protocol.rs#L190)) — unreachable under caps; add an assert.
- `reconcile_file` never refreshes `leading_comments` — hand-added header comments are silently dropped on next persist. `ReadModel::index_directive` appends without re-sorting, so journal order differs between a long-running node and the same node restarted.
- Number canonicalization is not value-normalizing: `-0` hashes differently from `0`; `1.0` vs `1.00` are distinct; misplaced digit-group commas are accepted (`1,2,3.45` → `123.45`); `rust_decimal` silently banker's-rounds beyond 28 fractional digits (verified in vendored source).
- Directive-level metadata written after the first posting silently becomes *posting* metadata ([parse.rs:960-977](../../crates/ledger/src/parse.rs#L960-L977)) — a hand-placed `openledger-author`/`-signature` is ignored and the entry adopts as unsigned (micro-mechanism behind L-11).
- The `journal` resolver's flat 512 weight (known) concretely buys up to 10,000 SHA-256 `compute_content_id` recomputations plus full clones per call under the read lock ([query.rs:278-346](../../crates/gl-node/src/graphql/query.rs#L278-L346)) — the CPU amplifier behind that finding.
- Hygiene: `.DS_Store` committed at three paths; `test-ledger.bean` force-added past the `*.bean` gitignore (test data only — and it carries M-18's duplicate-lamport evidence).
- Carried informational items from 09/01 remain (relayMode `"n0"` presence leak by default, single key for QUIC identity + signing, fixed-window limiter semantics, redacting `Debug` impls, etc.).

---

## 6. Dependencies, supply chain, and verification runs

**`cargo audit` (RustSec DB current as of 2026-09-02, 499 locked crates): unchanged from 09/01.** Same five hits, assessments re-affirmed: `h2` 0.4.15 (RUSTSEC-2026-0258 — only via hickory/iroh DoH, not the server path), `rkyv` 0.7.46 (RUSTSEC-2026-0235 — lockfile-only, not compiled), `lru` 0.18.1 (unsound advisory, live in iroh-relay, low practical risk), `chacha20` yanked, `paste` unmaintained. No new advisories. CI runs `rustsec/audit-check` on every push.

**CI action pinning — one-time online verification now done (closes the 09/01 recommendation):** `actions/checkout@11d5960a…` == tag v4.4.0 ✔; `Swatinem/rust-cache@6323deb1…` == v2.9.2's annotated-tag dereference ✔; `rustsec/audit-check@69366f33…` == v2.0.0 ✔; `dtolnay/rust-toolchain@4360b525…` is a historical commit of that repo (current master has moved on — expected under pinning; the SHA is in-repo, exercised by every CI run).

**Test suite at HEAD:** green across the workspace except the flaky `three_node_alpn_convergence` (passes in isolation; see §5). Docker base images remain tag-mutable and the image build unlocked (carryover L-10).

---

## 7. Consolidated open-findings register

Everything open as of this audit, in one place. IDs are stable across the 09/01 and 09/02 reports.

| ID | Sev | One-liner | Origin |
|---|---|---|---|
| H-01 | High | Default local node is drive-by CSRF-writable; DNS rebinding adds read | 09/01 |
| H-02 | High | Sync senders violate own receive caps → mesh wedges at ~4k directives | 09/01 |
| H-03 | High | Elided-posting id shift plants un-replicable divergent state | 09/01 |
| H-04 | High | Signed-year date persists then bricks every boot | 09/01 |
| H-05 | High | GraphQL body cap ineffective → unbounded RAM buffering / OOM | **09/02** |
| H-06 | High | Body-smuggled `openledger-*` keys: hash-invisible bytes + next-hop poisoning | **09/02** |
| M-04 | Med | Rate limiting collapses behind proxy; IPv6 /128 buckets | 09/01 |
| M-06 | Med | No P2P I/O timeouts; serial anti-entropy loop | 09/01 |
| M-07 | Med | Announce flood: unbounded spawns + dials, no dedup | 09/01 |
| M-08 | Med | Balance assertions/pads never evaluated; checkpoint.rs dead | 09/01 |
| M-09 | Med | Account lifecycle arrival-order dependent; unconditional remote close | 09/01 |
| M-10 | Med | Economic-hash dedup authorship squatting | 09/01 |
| M-11 | Med | Open gossip membership; eclipse idles anti-entropy | 09/01 |
| M-12 | Med | Gossip allowlist authenticates last hop only — announce path effectively unauthenticated | **09/02** |
| M-13 | Med | No HTTP timeouts/connection cap — pre-auth slowloris on any bind | **09/02** |
| M-14 | Med | Supply validation before dedup — full-cost replay forever | **09/02** |
| M-15 | Med | O(M×N) under write lock per remote directive; API stall cascade | **09/02** |
| M-16 | Med | Post-decode CBOR caps; ~0.5-1 GiB transient per frame; unbounded conns | **09/02** |
| M-17 | Med | No ledger-file exclusivity; shipped configs share one file across 3 nodes | **09/02** |
| M-18 | Med | Boot lamport scan skips non-transactions → duplicate (author, lamport) | **09/02** |
| L-01…L-05, L-07…L-18 | Low | Seventeen carryover Lows — see §1.2 and the 09/01 report | 09/01 |
| L-19…L-32 | Low | Fourteen new Lows — see §4 | **09/02** |
| L-06 | Latent | `\|`-delimited sig message — remote injection closed; length-prefix on next domain bump | 09/01 |

---

## 8. Remediation backlog

> **Tracking home:** this backlog is maintained as a living tracker with per-task status in
> [docs/audits/OUTSTANDING_TASKS_09.md](OUTSTANDING_TASKS_09.md) (which adds T41 for the informational sweep).
> Update statuses there; the section below is this report's snapshot.

The 09/01 findings never received a task backlog (docs/audits/OUTSTANDING_TASKS.md covers 08/20 only, all done). This section is that backlog, for everything in §7. Task numbering continues from T17. Effort: S = <½ day, M = ~1–2 days.

### Tier 1 — ship-blockers (fix before any multi-node or exposed deployment)

**☐ T18 — Send-side protocol caps + chunking (H-02) — S/M**
Chunk Supply replies to ≤256 entries and ≤16 MiB per frame; paginate or digest-summarize HaveHeads (windowed exchange). Files: [anti_entropy_alpn.rs:84-87,223-233](../../crates/gl-node/src/anti_entropy_alpn.rs#L84-L87), [anti_entropy.rs:42-52](../../crates/p2p/src/anti_entropy.rs#L42-L52), [protocol.rs:188-195](../../crates/p2p/src/protocol.rs#L188-L195). Verify: property test — every encodable outbound message decodes under the receive caps; integration test syncing a node 5,000 directives behind. Fix the flaky `three_node_alpn_convergence` alongside (§5) so the regression signal is trustworthy.

**☐ T19 — Real HTTP body limit + cross-origin hardening (H-05, H-01) — S**
(a) Add `tower_http::limit::RequestBodyLimitLayer::new(GRAPHQL_MAX_BODY_BYTES)`; correct the false comment. (b) Reject `POST /graphql` unless `Content-Type: application/json` (kills CSRF simple requests). (c) Validate `Host` against the bind address and `Origin` against the CORS allowlist (kills DNS rebinding). (d) Consider generating + requiring an API key even on loopback by default. Files: [main.rs:296-302](../../crates/gl-node/src/main.rs#L296-L302), [graphql/mod.rs:98-103](../../crates/gl-node/src/graphql/mod.rs#L98-L103), [config.rs](../../crates/gl-node/src/config.rs). Verify: >2 MiB POST → 413; `text/plain` POST → rejected; wrong-Host request → rejected.

**☐ T20 — Date range validation (H-04) — S**
Reject years outside 1..=9999 in `DateScalar::parse`; defense-in-depth range check in `service.rs` on append/open/close/remote/reconcile. Files: [scalars.rs:12-21](../../crates/gl-node/src/graphql/scalars.rs#L12-L21), [service.rs](../../crates/ledger/src/service.rs). Verify: serialize→parse round-trip property test over the full `NaiveDate` domain; `+10000-01-01` mutation rejected.

**☐ T21 — Remote-body canonicalization pass (H-03, H-06, L-26, L-29) — S/M**
In `validate_supply_entry` (and reconcile): reject entries whose body parses with `elided_count != 0`; reject any body-parsed `openledger-*` metadata key at directive **or posting** level (envelope is the only carrier); run control-char rejection over all parsed string fields; require lowercase `^[0-9a-f]{64}$` parents. Files: [union_merge.rs](../../crates/p2p/src/union_merge.rs), [service.rs:120-125](../../crates/ledger/src/service.rs#L120-L125), reconcile path. Verify: regression tests per rejected class, incl. posting-level smuggling and uppercase-hex parents.

**☐ T22 — HTTP server timeouts + connection bounds (M-13) — S/M**
Header-read/keep-alive/request timeouts via hyper-util builder + `TimeoutLayer`; bound concurrent connections. Files: [main.rs:325-329](../../crates/gl-node/src/main.rs#L325-L329). Verify: slowloris harness — stalled-header and stalled-body connections are dropped; connection count plateaus.

### Tier 2 — P2P robustness (one compromised or slow peer must not stall/OOM the mesh)

**☐ T23 — Gossip as untrusted hints (M-12, M-07) — M** — In-flight announce dedup + negative cache, bounded fetch semaphore, reuse one ALPN connection per peer; drop any claim that `delivered_from` authenticates origin (log it as "relay"). Files: [p2p_service.rs:160-183](../../crates/gl-node/src/p2p_service.rs#L160-L183), [anti_entropy_alpn.rs:112-121](../../crates/gl-node/src/anti_entropy_alpn.rs#L112-L121). Verify: flood of unique announce ids → bounded tasks/dials.
**☐ T24 — Session timeouts + concurrent peers (M-06) — S** — `tokio::time::timeout` around every connect/read/write; concurrent per-peer exchanges. Verify: a tarpit peer doesn't delay other peers' sync.
**☐ T25 — Dedup before validate + id-set hygiene (M-14, L-21) — S** — `get_directive(&entry.id)` check before validation; build Want/collect as sets. One-liners with tests.
**☐ T26 — Pre-decode frame sanity + per-peer connection cap (M-16, L-19) — M** — Structural CBOR pre-check or small cap for non-Supply frames; cap ALPN connections per peer; allocate read buffers incrementally. Verify: 16 MiB million-id frame rejected without GiB-scale allocation.
**☐ T27 — Persist/drain efficiency under lock (M-15, carryover L-13) — M** — Batch persist per Supply message; incremental directive-id index; `spawn_blocking` for file IO outside the write lock; projected-size check before mutate (closes L-13's cap-after-mutate wedge). Verify: catch-up sync of 1k directives does O(1) file rewrites; API latency bounded during sync.
**☐ T28 — Anti-entropy without neighbors (M-11) — S** — Seed the loop from `bootstrapEndpointIds` as well as live registry; treat topic string as sensitive.

### Tier 3 — integrity semantics

**☐ T29 — Deterministic account lifecycle (M-09) — M** — Derive account state from the directive set (date-ordered deterministic merge); buffer account-dependent remote transactions like parent-missing ones; apply the local "no later transactions" rule to remote closes.
**☐ T30 — Ledger-file exclusivity (M-17) — S** — flock/sidecar lock at boot, fail closed; per-peer `ledgerPath` in the three sample configs; never delete a foreign temp file.
**☐ T31 — Boot lamport across all kinds (M-18) — S** — One-line match fix + restart round-trip test asserting no duplicate `(author, lamport)`; regenerate `test-ledger.bean`.
**☐ T32 — Wire checkpoint evaluation (M-08) — M** — Call `evaluate_all_assertions` from `verify`; assertion semantics documented; `checked_sub` already landed.
**☐ T33 — Authorship binding (M-10) — M** — Fold author (or client uniqueness token) into the hashed body on the next format bump; interim: distinct "already existed" signal from `appendTransaction`.
**☐ T34 — Rate limiter correctness + cost (M-04, L-24) — S/M** — Trusted-proxy XFF option; key IPv6 by /64; lazy/threshold pruning; shard the map.

### Tier 4 — scheduled hardening (Lows + informational)

**☐ T35 — Availability-of-boot batch (L-28 BOM strip, carryover L-17 DAG backfill/in-file cycle, L-22 interval bound, L-30/L-12 reconcile ordering + pre-persist hash check) — M**
**☐ T36 — Key & file hygiene batch (L-31 umask pre-create, L-32 key-file `create_new`+fsync, carryover L-04 TOCTOU single-read, L-05 non-Unix warn, L-08 denylist/min-length) — S/M**
**☐ T37 — Determinism batch (L-27 elided fill currency, number normalization notes, L-25 charset unification ASCII-or-NFC) — S/M**
**☐ T38 — Deploy batch (carryover L-03 compose loopback publish + per-node keys, L-10 digest-pinned bases + `--locked`, config-file permission check, env-key precedence warning) — S**
**☐ T39 — Orphan/registry batch (L-20 full-cost accounting + timer eviction + duplicate-check order, L-23 mesh UUID domain, registry heads or remove the API) — S/M**
**☐ T40 — Carryover Lows sweep (L-01, L-02, L-07 `verify_strict`, L-09 health gating, L-11 sign-at-reconcile or refuse, L-14, L-15, L-16 zero/negative cost-price, L-18 gossip-outside-lock) — M**

### Finding → task coverage map

H-01→T19 · H-02→T18 · H-03→T21 · H-04→T20 · H-05→T19 · H-06→T21 · M-04→T34 · M-06→T24 · M-07→T23 · M-08→T32 · M-09→T29 · M-10→T33 · M-11→T28 · M-12→T23 · M-13→T22 · M-14→T25 · M-15→T27 · M-16→T26 · M-17→T30 · M-18→T31 · L-01/02/07/09/11/14/15/16/18→T40 · L-03/10→T38 · L-04/05/08→T36 · L-12→T35 · L-13→T27 · L-17→T35 · L-19→T26 · L-20→T39 · L-21→T25 · L-22→T35 · L-23→T39 · L-24→T34 · L-25→T37 · L-26→T21 · L-27→T37 · L-28→T35 · L-29→T21 · L-30→T35 · L-31/32→T36. (L-06 latent: length-prefix fields at the next signature-domain bump — attach to whichever of T21/T33 bumps it first.)

---

## 9. Checked and found sound (new this audit)

Beyond re-affirming the 09/01 "sound" list (no regressions found):

- **GraphQL engine:** fragment-cycle recursion capped by `check_recursive_depth` (32) in `prepare_request` before validation — runtime-verified no crash; JSON depth bombs capped (parser 64 / serde_json 128); batch requests rejected (`UnsupportedBatch`); `account(at:)` complexity weight cannot be bypassed via variables (closure resolves variables); GraphiQL HTML is static; no state-changing GET; auth inspects headers only and 401s before any body read; resolvers return owned data so the read lock is not held during response transmission; multipart unreachable for uploads (no upload fields; no `operations`/`map` → error) though the H-05 fix must cover it.
- **CORS:** empty allowlist yields no `Access-Control-Allow-Origin`; credentials and private-network unset; narrow methods/headers.
- **Wire/CBOR:** ciborium recursion hard-capped at 256; duplicate struct fields rejected by serde; content hashing is over canonical text, not CBOR bytes — non-canonical encodings cannot shift ids; gossip frames capped at 4 KiB by iroh-gossip before the app's 16 MiB cap matters; ALPN allowlist rejection closes the connection (verified iroh Router semantics); no 0-RTT on either path; no wire-reachable unwrap/index panics in p2p production paths.
- **Locking:** orphan-buffer operations are single-writer under one lock, ledger→buffer order at every site — no inversion; registry growth bounded to allowlisted NeighborUp peers.
- **Parser/serializer:** `Vec<char>`-based scanner — no multi-byte-boundary panics; CRLF safe; duplicate metadata keys collapse last-wins identically pre-hash; scientific notation/underscores unreachable; numeric overflow returns clean errors; self-parent rejected including via fast path; `read_date`'s fixed format can't parse signed years (the brick is serialize-side only).
- **Crypto:** ed25519-dalek 2.2.0 zeroizes `SigningKey` on drop; constant-time auth compare intact; OPTIONS bypass harmless (no OPTIONS-served routes).
- **Deploy:** Docker healthcheck execs the binary (no curl-pipe); no secrets in image layers; configs mounted read-only; git history since `e293a4f` is exactly the audit commit, diff matches description; no committed secrets (re-checked).

---

*Previous audits: [SECURITY_AUDIT_0901.md](SECURITY_AUDIT_0901.md) (whose addendum records 08/20 closure) · [docs/audits/CLAUDE_SECURITY_AUDIT_0820.md](CLAUDE_SECURITY_AUDIT_0820.md) · 08/20 remediation tracker: [docs/audits/OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md) (all ☑; superseded by §8 above for current work).*
