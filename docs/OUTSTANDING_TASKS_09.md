# Outstanding Security Tasks — September 2026

Remediation backlog for every open finding in [SECURITY_AUDIT_0901.md](../SECURITY_AUDIT_0901.md) and [SECURITY_AUDIT_0902.md](../SECURITY_AUDIT_0902.md).
Task numbering continues from the (fully completed) 08/20 tracker, [OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md) (T1–T17).
Finding IDs are stable across both reports; line references are current as of HEAD `b6bf634` (from the 09/02 re-verification).

Already closed before this backlog — do not re-do: 09/01 **M-01** (strict inbound lamport/parents validation, all directive kinds, tested), 09/01 **M-02/M-03/M-05** (complexity weights, mutation weights, orphan byte budgets — commit `e293a4f`), and **L-06**'s remote-path injection (incidental to M-01; the latent delimiter debt is tracked under T33/T21 below).

**Status legend:** ☐ not started · ◐ in progress · ☑ done
**Effort:** S = <½ day, M = ~1–2 days.

## Priority order at a glance

| # | Findings addressed | Sev | Effort | Status |
|---|---|---|---|---|
| T18 | H-02 — sync senders violate receive caps (mesh wedge) | High | S–M | ☑ |
| T19 | H-05 + H-01 — ineffective body limit; CSRF/DNS rebinding | High | S | ☐ |
| T20 | H-04 — signed-year dates brick boot | High | S | ☐ |
| T21 | H-03 + H-06 + L-26 + L-29 — remote-body canonicalization | High | S–M | ☐ |
| T22 | M-13 — no HTTP timeouts/connection cap (slowloris) | Med | S–M | ☐ |
| T23 | M-12 + M-07 — gossip origin auth; announce flood | Med | M | ☐ |
| T24 | M-06 — no P2P I/O timeouts; serial sync loop | Med | S | ☐ |
| T25 | M-14 + L-21 — validate-before-dedup; duplicate ids | Med | S | ☐ |
| T26 | M-16 + L-19 — post-decode CBOR caps; connection bounds | Med | M | ☐ |
| T27 | M-15 + L-13 — O(M×N) persist under write lock | Med | M | ☐ |
| T28 | M-11 — eclipse idles anti-entropy | Med | S | ☐ |
| T29 | M-09 — arrival-order account lifecycle | Med | M | ☐ |
| T30 | M-17 — no ledger-file exclusivity | Med | S | ☐ |
| T31 | M-18 — boot lamport skips non-transactions | Med | S | ☐ |
| T32 | M-08 — balance assertions never evaluated | Med | M | ☐ |
| T33 | M-10 — authorship squatting | Med | M | ☐ |
| T34 | M-04 + L-24 — rate limiter correctness + cost | Med | S–M | ☐ |
| T35 | L-28, L-17, L-22, L-30, L-12 — availability-of-boot batch | Low | M | ☐ |
| T36 | L-31, L-32, L-04, L-05, L-08 — key & file hygiene batch | Low | S–M | ☐ |
| T37 | L-27, L-25 — determinism & confusability batch | Low | S–M | ☐ |
| T38 | L-03, L-10 + config hygiene — deploy batch | Low | S | ☐ |
| T39 | L-20, L-23 + registry heads — orphan/mesh-identity batch | Low | S–M | ☐ |
| T40 | L-01, L-02, L-07, L-09, L-11, L-14, L-15, L-16, L-18 — carryover Lows sweep | Low | M | ☐ |
| T41 | Informational/hygiene sweep | Info | S | ☐ |

Coverage check — every open register entry (0902 §7) maps to exactly one task:
H-01→T19 · H-02→T18 · H-03→T21 · H-04→T20 · H-05→T19 · H-06→T21 · M-04→T34 · M-06→T24 · M-07→T23 · M-08→T32 · M-09→T29 · M-10→T33 · M-11→T28 · M-12→T23 · M-13→T22 · M-14→T25 · M-15→T27 · M-16→T26 · M-17→T30 · M-18→T31 · L-01/02/07/09/11/14/15/16/18→T40 · L-03/10→T38 · L-04/05/08→T36 · L-12→T35 · L-13→T27 · L-17→T35 · L-19→T26 · L-20→T39 · L-21→T25 · L-22→T35 · L-23→T39 · L-24→T34 · L-25→T37 · L-26→T21 · L-27→T37 · L-28→T35 · L-29→T21 · L-30→T35 · L-31/32→T36 · L-06 (latent)→T33/T21 note.

---

## Tier 1 — ship-blockers (fix before any multi-node or exposed deployment)

### ☑ T18 — Send-side protocol caps + chunking (H-02)
> **Done 2026-09-02 (in working tree, not yet committed).** Supply replies truncated to ≤256 entries / 15 MiB budget with a client re-Want progress loop; HaveHeads paginated via an additive `more` flag (client accumulation capped at 1M ids against malicious streaming); Want chunks tightened to 256; `to_wire()` now errors past 16 MiB. Property tests assert every sender page/frame decodes under the receive caps; `two_node_catchup_beyond_caps` (1,500 directives) proves end-to-end convergence and was shown to fail against the pre-fix senders; `two_node_catchup_beyond_have_heads_cap` (4,300, exercises pagination) passes in ~102 s but is `#[ignore]`d until T27 removes the O(N²) per-insert persist — run it manually or nightly. `three_node_alpn_convergence` de-flaked (network-test mutex, readiness waits, 60 s deadline).
- **Why first:** the mesh wedges itself with no attacker once any ledger exceeds 4,096 directives or any node falls >256 behind. Ship-blocker.
- **Change:** three send sites must respect the receive caps they are decoded under: (1) chunk Supply replies to ≤ `MAX_SUPPLY_ENTRIES` (256) entries per `WireMessage`; (2) budget frames to ≤ `MAX_MESSAGE_SIZE` (16 MiB) — check in `to_wire()` or size-aware batching in `collect_supply`; (3) paginate or digest-summarize `make_have_heads` to ≤ `MAX_HAVE_HEADS` (4096) — windowed exchange or heads-plus-digest.
- **Files:** [anti_entropy_alpn.rs:84-87,223-233](../crates/gl-node/src/anti_entropy_alpn.rs#L84-L87), [anti_entropy.rs:42-52](../crates/p2p/src/anti_entropy.rs#L42-L52), [protocol.rs:188-195](../crates/p2p/src/protocol.rs#L188-L195).
- **Verify:** property test — every encodable outbound message decodes under the receive caps; integration test syncing a node 5,000+ directives behind to convergence; a >4,096-directive ledger still completes head exchange. Fix the flaky `three_node_alpn_convergence` (fails under suite parallelism, passes isolated) in the same change so the convergence signal is trustworthy.

### ☐ T19 — Real HTTP body limit + cross-origin hardening (H-05, H-01)
- **Change:**
  (a) **H-05:** add `tower_http::limit::RequestBodyLimitLayer::new(GRAPHQL_MAX_BODY_BYTES)` (tower-http is already a dependency) — `DefaultBodyLimit` is opt-in and `async-graphql-axum` bypasses it (runtime-verified: 8 MiB POST → 200). The wrapping layer fails the extractor's stream read past the cap and also covers multipart. Correct the false comment on `GRAPHQL_MAX_BODY_BYTES`.
  (b) **H-01:** reject `POST /graphql` unless `Content-Type` is `application/json` (kills the `text/plain` CORS simple-request CSRF); validate `Host` against the bind address and `Origin` against the CORS allowlist (kills DNS rebinding); consider generating and requiring an API key even on loopback binds by default.
- **Files:** [main.rs:296-302](../crates/gl-node/src/main.rs#L296-L302), [graphql/mod.rs:98-103](../crates/gl-node/src/graphql/mod.rs#L98-L103), [config.rs](../crates/gl-node/src/config.rs).
- **Verify:** >2 MiB POST → 413; `text/plain` POST → rejected; wrong/absent `Host` → rejected; cross-origin `no-cors` fetch reproduction no longer mutates; existing GraphiQL + legitimate JSON clients still work.

### ☐ T20 — Date range validation (H-04)
- **Change:** reject years outside 1..=9999 in `DateScalar::parse`; defense-in-depth range check in `service.rs` on append/open/close/remote-insert/reconcile (chrono `%Y` accepts signed years the ledger's own `read_date` can never re-parse — one accepted write bricks every subsequent boot).
- **Files:** [scalars.rs:12-21](../crates/gl-node/src/graphql/scalars.rs#L12-L21), [service.rs](../crates/ledger/src/service.rs).
- **Verify:** serialize→parse round-trip property test over the full `NaiveDate` domain; `appendTransaction(date:"+10000-01-01")` and `-0001-01-01` rejected on every path; node with a pre-existing healthy file boots unchanged.

### ☐ T21 — Remote-body canonicalization pass (H-03, H-06, L-26, L-29)
- **Change:** one validation pass in `validate_supply_entry` (and mirrored on the reconcile path), run before signature verification:
  1. **H-03:** reject any entry whose `economic_bean` parses with `elided_count != 0` (honest senders always ship resolved postings; elision resolution shifts the content id after the id/signature checks).
  2. **H-06:** reject any body-parsed `openledger-*` metadata key at directive **or posting** level — the envelope is the only legal carrier (the content hash strips these keys, so they are validated by nothing, persist as hash-invisible bytes, and get promoted into the envelope on re-serve where the next hop rejects the directive forever).
  3. **L-26:** run `reject_control_characters` over all parsed body string fields (narration, payee, note, document, event, metadata values) — remote peers can currently persist ANSI escapes the local API rejects.
  4. **L-29:** tighten parent-txid well-formedness to lowercase `^[0-9a-f]{64}$` in both check sites (uppercase forms pass `is_ascii_hexdigit` but can never resolve → TTL-long orphan squatting).
- **Files:** [union_merge.rs](../crates/p2p/src/union_merge.rs) (validate path :150-258), [service.rs:120-125](../crates/ledger/src/service.rs#L120-L125), reconcile path [service.rs:821-955](../crates/ledger/src/service.rs#L821-L955).
- **Verify:** regression tests per rejected class — elided-posting SupplyEntry; body-embedded `openledger-x` at directive and at posting level; ESC/NUL in a remote narration; uppercase-hex parent. Hand-edited file with a stray `openledger-` key: reconcile rejects rather than adopts.

### ☐ T22 — HTTP server timeouts + connection bounds (M-13)
- **Change:** `axum::serve` imposes no header-read/keep-alive/request timeouts and no connection ceiling — slowloris works pre-auth and pre-rate-limit even on a hardened public bind. Drive connections through hyper-util's builder with explicit `header_read_timeout` and keep-alive timeouts; add a request `TimeoutLayer` (also closes the "no per-request GraphQL execution timeout" informational); bound concurrent connections (semaphore in the accept loop or `tower::limit::ConcurrencyLimit`). Document that the mandated TLS-terminating proxy must enforce the same.
- **Files:** [main.rs:325-329](../crates/gl-node/src/main.rs#L325-L329).
- **Verify:** slowloris harness — stalled-header, stalled-body, and idle-keep-alive connections are dropped on their timeouts; connection count plateaus at the configured cap; normal request latency unaffected.

---

## Tier 2 — P2P robustness (one compromised or slow peer must not stall or OOM the mesh)

### ☐ T23 — Treat gossip as untrusted hints (M-12, M-07)
- **Change:** `allowlist.admits(msg.delivered_from)` authenticates only the previous hop — iroh-gossip's plumtree relays first-seen messages before the application filter runs, so strangers on the topic reach every node ≥2 hops away wearing an allowlisted relay's id. Stop treating it as origin authentication (log `delivered_from` as "relay"). Then harden the announce→fetch path for unauthenticated load: in-flight announce-id dedup, negative cache for ids that failed to fetch/validate, bounded fetch semaphore, reuse one ALPN connection per peer instead of dialing per announce.
- **Files:** [p2p_service.rs:160-183](../crates/gl-node/src/p2p_service.rs#L160-L183), [anti_entropy_alpn.rs:112-121](../crates/gl-node/src/anti_entropy_alpn.rs#L112-L121).
- **Verify:** flood of unique announce ids → tasks and dials stay bounded; duplicate announces of one id cause one fetch; repeated bad ids are negative-cached.

### ☐ T24 — Session timeouts + concurrent peer exchanges (M-06)
- **Change:** `tokio::time::timeout` around every connect/read/write in the ALPN session paths; run per-peer anti-entropy exchanges concurrently (bounded) instead of the serial loop where one tarpit peer stalls all replication. Also add a per-connection request budget to `serve_anti_entropy` (T18 review note: one stream can still issue unlimited HaveHeads/Want rounds — each now cheap, but unbudgeted).
- **Files:** [anti_entropy_alpn.rs:350-371](../crates/gl-node/src/anti_entropy_alpn.rs#L350-L371) and session loops, [p2p_service.rs:250-258](../crates/gl-node/src/p2p_service.rs#L250-L258).
- **Verify:** a peer that accepts and never responds is timed out and does not delay other peers' sync round.

### ☐ T25 — Dedup before validate + id-set hygiene (M-14, L-21)
- **Change:** check `svc.get_directive(&entry.id)` **before** running parse/hash/signature on supplied entries (already-present ids are discarded regardless of content — the skip is semantics-preserving; today a replayed 256×1 MiB Supply costs full validation forever). Build `compute_want` and `collect_supply` over sets so duplicate ids aren't fetched/served/validated once per copy.
- **Files:** [anti_entropy_alpn.rs:241-243](../crates/gl-node/src/anti_entropy_alpn.rs#L241-L243), [anti_entropy.rs:15-36](../crates/p2p/src/anti_entropy.rs#L15-L36), [anti_entropy_alpn.rs:228-233](../crates/gl-node/src/anti_entropy_alpn.rs#L228-L233).
- **Verify:** test — replaying a Supply of known ids performs no signature verifications; a Want with repeated ids yields one entry per id.

### ☐ T26 — Pre-decode frame sanity + connection caps (M-16, L-19)
- **Change:** cardinality caps currently run **after** full CBOR decode, and the internally-tagged enum buffers through serde `Content` (~0.5–1 GiB transient per 16 MiB Want/HaveHeads frame). Add a cheap pre-decode structural check (scan CBOR array headers) or a much smaller frame cap for non-Supply message types; cap concurrent inbound ALPN connections per peer (iroh's Router spawns unbounded tasks); read bodies into incrementally-grown buffers instead of pre-allocating the full length-prefix claim (L-19: stalled streams pin 16 MiB each).
- **Files:** [protocol.rs:31,175-185](../crates/p2p/src/protocol.rs#L175-L185), [anti_entropy_alpn.rs:357-371](../crates/gl-node/src/anti_entropy_alpn.rs#L357-L371), router setup in [p2p_service.rs:88-93](../crates/gl-node/src/p2p_service.rs#L88-L93).
- **Verify:** a 16 MiB frame claiming millions of ids is rejected without GiB-scale allocation (assert peak RSS in test); >N concurrent connections from one peer are refused; a stalled stream holds only a small buffer.

### ☐ T27 — Persist/drain efficiency under the write lock (M-15; closes 09/01 L-13)
- **Change:** today every remote directive, under the global **write** lock, rewrites the whole `.bean` with synchronous IO on the runtime and re-clones the full directive-id set for orphan draining — O(M×N) catch-up that backpressures into a GraphQL mutation stall. Batch persist once per Supply message (or debounce); maintain an incremental directive-id index instead of `all_directive_ids()` clones; move file IO to `spawn_blocking` outside the lock; check projected serialized size **before** mutating in-memory state (L-13: today inserts succeed in memory after persist fails past the 64 MiB cap — memory/disk divergence, silent drop on restart).
- **Files:** [service.rs:43-52,596-612,806-811,1126-1131](../crates/ledger/src/service.rs#L806-L811), [anti_entropy_alpn.rs:280-308](../crates/gl-node/src/anti_entropy_alpn.rs#L280-L308).
- **Verify:** catch-up sync of 1k directives does O(1) file rewrites; API mutation latency bounded during sync; write that would exceed the file cap is rejected **before** any state changes (memory == disk afterwards).

### ☐ T28 — Anti-entropy without neighbors (M-11)
- **Change:** the peer registry is populated only by allowlisted `NeighborUp` events, so an eclipsed node (Sybil neighbors occupying gossip slots — membership is open) has an empty registry and its anti-entropy loop does nothing. Seed the loop from `bootstrapEndpointIds` as well as live neighbors; treat the swarm-topic string as sensitive (it is also the join credential — see T39/L-23).
- **Files:** [p2p_service.rs:198-209,245-258](../crates/gl-node/src/p2p_service.rs#L245-L258).
- **Verify:** node with zero gossip neighbors still syncs with configured bootstrap peers.

---

## Tier 3 — integrity semantics

### ☐ T29 — Deterministic account lifecycle (M-09)
- **Change:** derive account open/close state deterministically from the directive set (date-ordered, deterministic merge) instead of mutable arrival-order state; buffer account-dependent remote transactions the way parent-missing ones are buffered; apply the local path's "no later transactions" rule to remote closes (today one allowlisted peer's `close Assets:Cash 1970-01-01` blocks that account's local appends on every replica, and `let _ =` swallows the errors).
- **Files:** [service.rs:1118-1150](../crates/ledger/src/service.rs#L1118-L1150), [validate.rs:175-206](../crates/ledger/src/validate.rs#L175-L206), [anti_entropy_alpn.rs:256-272](../crates/gl-node/src/anti_entropy_alpn.rs#L256-L272).
- **Verify:** permutation test — any arrival order of {open, tx, close} converges to identical state on all replicas; a backdated remote close no longer blocks appends; tx-before-open is buffered and drains when the open arrives.

### ☐ T30 — Ledger-file exclusivity (M-17)
- **Change:** take an exclusive advisory lock (flock or sidecar lockfile) on the ledger at boot and fail closed; give `config/gl-node.peer-{0,1,2}.json` each their own `ledgerPath` (all three currently share `test-ledger.bean` — the documented concurrent dev flow silently loses writes); never delete another process's in-flight temp file (the `AlreadyExists → remove_file → retry` path).
- **Files:** [service.rs:43-108](../crates/ledger/src/service.rs#L43-L108), [config/](../config/), [scripts/tests.sh](../scripts/tests.sh).
- **Verify:** second process on the same file exits with a clear error; the three-peer dev flow runs on three files.

### ☐ T31 — Boot Lamport scan across all directive kinds (M-18)
- **Change:** `max_lamport` at boot is read only from `Directive::Transaction`, while stamping applies lamport to opens/closes too — a restart regresses the clock and re-issues used `(author, lamport)` pairs (committed proof: two opens in `test-ledger.bean` both carry lamport 8). One-line match fix; regenerate `test-ledger.bean`.
- **Files:** [service.rs:416-421](../crates/ledger/src/service.rs#L416-L421), [test-ledger.bean](../test-ledger.bean).
- **Verify:** restart round-trip test asserting the clock never regresses and no duplicate `(author, lamport)` is ever signed.

### ☐ T32 — Wire checkpoint evaluation (M-08)
- **Change:** `checkpoint.rs` has no production caller — `balance`/`pad` directives are persisted via the unvalidated catch-all and never evaluated, so the file format advertises an integrity feature that does nothing (and an allowlisted peer can seed false authoritative-looking assertions). Call `evaluate_all_assertions` from the GraphQL `verify` path; document assertion/pad semantics vs beancount. The prerequisite `checked_sub` hardening already landed (`checkpoint.rs:74-78`).
- **Files:** [checkpoint.rs](../crates/ledger/src/checkpoint.rs), [verify.rs](../crates/ledger/src/verify.rs), [service.rs:1160-1171](../crates/ledger/src/service.rs#L1160-L1171).
- **Verify:** a failing balance assertion surfaces in `verify`; extreme-value assertion does not panic (checked ops test).

### ☐ T33 — Authorship binding (M-10)
- **Change:** the content hash excludes all `openledger-*` metadata, so whoever inserts a given economic body first permanently owns its author/signature envelope — predictable transactions (rent, salary) can be authorship-squatted, and legitimately distinct identical events collapse. Fold the author (or a client uniqueness token) into the hashed body at the next content-format bump; interim: return a distinct "already existed" signal from `appendTransaction` instead of silent success.
- **Files:** [serialize.rs:345-349](../crates/ledger/src/serialize.rs#L345-L349), [service.rs:598-604](../crates/ledger/src/service.rs#L598-L604), [mutation.rs](../crates/gl-node/src/graphql/mutation.rs).
- **Note:** the format/domain bump here (or T21's) is where **L-06 latent** gets closed for good — switch the signed message from `|`-concatenation to length-prefixed fields.
- **Verify:** duplicate append returns the explicit already-existed signal; post-bump, identical economic bodies from different authors have distinct ids.

### ☐ T34 — Rate limiter correctness + cost (M-04, L-24)
- **Change:** (a) configurable trusted-proxy support (`X-Forwarded-For` honored only from configured proxy addresses — public binds *mandate* a proxy, behind which the whole world currently shares one 60/min bucket); (b) key IPv6 buckets by /64 prefix (per-/128 today → free bucket rotation); (c) stop the O(n) full-map `retain` under the global mutex on every request — prune lazily/on threshold, shard or cap the map.
- **Files:** [rate_limit.rs:20-24,46-80](../crates/gl-node/src/rate_limit.rs#L46-L80), [main.rs:325-328](../crates/gl-node/src/main.rs#L325-L328), [config.rs](../crates/gl-node/src/config.rs).
- **Verify:** behind a configured trusted proxy, two forwarded clients get separate buckets; two addresses in one /64 share a bucket; request cost stays O(1) with 10k tracked buckets.

---

## Tier 4 — scheduled hardening (Lows)

### ☐ T35 — Availability-of-boot batch (L-28, L-17, L-22, L-30, L-12)
- **L-28:** strip a leading UTF-8 BOM in `parse_file`/`read_ledger_file` ([parse.rs:388-407](../crates/ledger/src/parse.rs#L388-L407)) — an editor BOM currently bricks every boot.
- **L-17:** backfill DAG `children`/`heads` on out-of-order inserts ([dag.rs:143-161](../crates/ledger/src/dag.rs#L143-L161)); make an in-file cycle a rejected directive, not a boot abort ([service.rs:424](../crates/ledger/src/service.rs#L424)).
- **L-22:** bound `anti_entropy_interval_milliseconds` ≥ some floor at config validation ([p2p_service.rs:239](../crates/gl-node/src/p2p_service.rs#L239)) — zero currently panics the replication task silently.
- **L-30 + L-12:** before any persist, compare the on-disk hash to the last-persisted/reconciled hash and reconcile first on mismatch (a hand edit is currently clobbered unseen by any concurrent persist); process reconcile input in canonical order like boot, and never re-persist a file that dropped rejected hand edits without surfacing which entries were rejected.
- **Verify per item:** BOM'd file boots; out-of-order file yields correct heads and detects planted cycles gracefully; interval 0 refused at boot; hand-edit + concurrent-append test preserves the edit or reports it — never silently deletes it.

### ☐ T36 — Key & file hygiene batch (L-31, L-32, L-04, L-05, L-08)
- **L-31:** drop the `std::fs::write(&ledger_path, "")` pre-create ([main.rs:123-129](../crates/gl-node/src/main.rs#L123-L129)) — it leaves the ledger at umask perms instead of the 0600 creation path.
- **L-32:** `write_secret_key_file` → `create_new` (no symlink follow, matching the ledger temp-file hardening) + fsync ([p2p_service.rs:318-337](../crates/gl-node/src/p2p_service.rs#L318-L337)); tolerate/regenerate an empty key file from a crashed write.
- **L-04:** open the key file once, `fstat` the handle, read from the handle, share the bytes between Iroh identity and signer ([p2p_service.rs:264-296](../crates/gl-node/src/p2p_service.rs#L264-L296), [main.rs:350-368](../crates/gl-node/src/main.rs#L350-L368)) — closes the TOCTOU and the double-read identity split; zeroize hex/byte intermediates.
- **L-05:** warn loudly on non-Unix where the permission check is a no-op ([p2p_service.rs:313-316](../crates/gl-node/src/p2p_service.rs#L313-L316)).
- **L-08:** extend the sample-key denylist beyond one string (README's `"my-secret-key-here"` boots today) and enforce a minimum key length ([config.rs:274-278](../crates/gl-node/src/config.rs#L274-L278)).
- **Verify:** perm-check test on fresh ledger create; symlink pre-plant test on key write; single-open key load test; README sample key refused on public bind.

### ☐ T37 — Determinism & confusability batch (L-27, L-25)
- **L-27:** make elided-posting currency fill deterministic (lexicographically-smallest currency, or reject zero-imbalance elision) — `sums.iter().next()` off a `HashMap` currently yields nondeterministic txids ([weights.rs:156-169](../crates/ledger/src/weights.rs#L156-L169)).
- **L-25:** unify the account/tag/link charset — restrict parse-side to ASCII (matching the API-side validators) or NFC-normalize + confusable-check; today `Assets:Cаsh` (Cyrillic а) is a distinct, visually identical account ([parse.rs:206-296](../crates/ledger/src/parse.rs#L206-L296)).
- **Verify:** zero-sum multi-currency elided append yields the same txid across 100 runs and across a restart; mixed-script account name rejected (or normalized) on file and API paths alike; existing ASCII ledgers unaffected.

### ☐ T38 — Deploy & config batch (L-03, L-10, config hygiene)
- **L-03:** [deploy/docker-compose.yml](../deploy/docker-compose.yml) — publish as `"127.0.0.1:3000:3000"` (not all interfaces with `tls.mode:"terminated"` and no terminator in the stack); per-node `GL_NODE_API_KEY` values instead of one shared key.
- **L-10:** [Dockerfile](../Dockerfile) — pin base images by digest; build with `cargo build --release --locked`.
- **Config hygiene (0902 informational, promoted here):** make `GL_NODE_API_KEY` env take precedence over a non-empty file value (or warn when both set — silent stale-key wins today, [config.rs:238-244](../crates/gl-node/src/config.rs#L238-L244)); warn when the config file carrying an API key is group/other-readable.
- **Verify:** compose stack unreachable from off-host; image rebuild is digest-stable and lock-enforced; env-rotation test uses the env key.

### ☐ T39 — Orphan-buffer & mesh-identity batch (L-20, L-23, registry heads)
- **L-20:** account orphan budgets on full cost (body + envelope + `waiting_on` index, currently 3–5× undercounted, [orphan_buffer.rs:99-124](../crates/p2p/src/orphan_buffer.rs#L99-L124)); run TTL eviction on a timer, not only inside `insert`; check `contains` before budgets so duplicate inserts aren't mislabeled "buffer full".
- **L-23:** decouple the signature mesh domain from the swarm topic — a random per-mesh UUID in config as the `mesh_id` ([signing.rs:94-105](../crates/security/src/signing.rs#L94-L105)); today two meshes sharing a custom topic string accept each other's signed directives, and the topic doubles as the gossip join credential.
- **Registry heads (0902 informational):** either populate registry heads (`upsert(peer, vec![])` is the only writer today) or remove the always-empty `all_remote_heads()` API and its GraphQL exposure.
- **Verify:** orphan memory stays within budget under envelope-heavy load and drains on TTL without inserts; two-mesh replay test fails closed with distinct mesh UUIDs; peer-heads GraphQL either reports real data or is gone.

### ☐ T40 — Carryover Lows sweep (L-01, L-02, L-07, L-09, L-11, L-14, L-15, L-16, L-18)
- **L-01:** rate-limit/budget Want serving on ALPN (largely subsumed by T18 chunking + T25 dedup — confirm the read-path amplification is closed and add a tight-loop test).
- **L-02:** enforce `MAX_ECONOMIC_BEAN_LENGTH` (and field length caps) on the **local** append path so local directives can't exceed what every peer rejects ([service.rs:460-613](../crates/ledger/src/service.rs#L460-L613)).
- **L-07:** `verify` → `verify_strict` ([signing.rs:224-226](../crates/security/src/signing.rs#L224-L226)). One line.
- **L-09:** gate `/health` detail (version/heads/peers) behind auth on non-loopback binds, or reduce to a bare 200 ([health.rs:32-41](../crates/gl-node/src/health.rs#L32-L41), [main.rs:296-298](../crates/gl-node/src/main.rs#L296-L298)).
- **L-11:** sign externally-edited directives at reconcile, or refuse reconcile when signing is enabled — adopted-unsigned entries silently never replicate ([service.rs:854-873](../crates/ledger/src/service.rs#L854-L873)).
- **L-14:** cap the DAG ancestor-walk depth or keep a true reachability memo so a crafted file can't force O(M·N) boot CPU ([dag.rs:169-201](../crates/ledger/src/dag.rs#L169-L201)).
- **L-15:** close the latent serializer injectivity holes (posting with `amount: None` + `cost`/`price: Some`; `CostSpec{amount:None,date:Some}`) with explicit rejection or distinct serialization ([serialize.rs:175-215](../crates/ledger/src/serialize.rs#L175-L215)).
- **L-16:** reject zero/negative cost and price numbers (unit-minting via `{0 USD}`) ([weights.rs:54-117](../crates/ledger/src/weights.rs#L54-L117)).
- **L-18:** drop the ledger write lock before gossiping in `openAccount`/`closeAccount`, matching `appendTransaction` ([mutation.rs:158,192](../crates/gl-node/src/graphql/mutation.rs#L158)).
- **Verify:** one regression test per item (oversized local append rejected; strict-verify tamper test; unauthenticated `/health` on public bind is minimal; reconcile-with-signing round-trips to peers; adversarial-file boot time bounded; injectivity property test over the posting model; zero-cost posting rejected; gossip-channel-full test doesn't block mutations).

### ☐ T41 — Informational/hygiene sweep
Small items from both reports' informational sections, batched: add `persist-credentials: false` to CI checkout; remove committed `.DS_Store` files and gitignore them; redacting `Debug` impls for `AuthState`/`NodeConfig`; remove the unused `rand` dep in gl-node and vestigial `libssl-dev` in the builder image; delete or align production-dead code (`head_exchange`, `filter_supply_requests`, `extract_parents`/`extract_lamport`); retry gossip `subscribe` instead of exiting the loop permanently; replace string-match EOF classification in `serve_anti_entropy` with typed error handling; assert on `to_wire`'s u32 length cast; document the unsigned-pre-P2P-directives migration; consider a derived signing subkey (vs sharing the QUIC identity key); keep an eye on the `lru`/`h2` advisories via the existing CI `cargo audit`.
- **Verify:** CI green; `git status` clean of `.DS_Store`; `cargo udeps`/build confirm removals; grep shows no `data_unchecked` outside gated subscription code.

---

## Suggested landing order & regression-test manifest

Land Tier 1 as five focused PRs (T18 first — it unblocks trusting the convergence test suite), then Tier 2 can proceed in parallel with Tier 3. Tests that must exist by the end of Tier 1, per the audits:

1. Outbound-message-decodes-under-receive-caps property test (T18 / H-02).
2. Body-limit 413 test + `text/plain` rejection + wrong-Host rejection (T19 / H-05, H-01).
3. Date serialize→parse round-trip property over `NaiveDate` (T20 / H-04).
4. Elided-posting, body-`openledger-*` (directive + posting level), control-char, and uppercase-parent rejection tests on the remote path (T21 / H-03, H-06, L-26, L-29).
5. Slowloris/stalled-connection teardown test (T22 / M-13).
6. De-flaked `three_node_alpn_convergence` (T18).
