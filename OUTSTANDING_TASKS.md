# Outstanding Tasks

> Derived from a full review of [SPEC.md](SPEC.md) against the current codebase.
> All 12 implementation passes and 15 conformance tests (CT-1–CT-15) are marked complete at the library level.
> **294 tests passing · 4 crates compiling · clippy clean (warnings below)**

---

## 🔴 P1 — Live P2P Integration (Not Wired into gl-node)

The P2P crate (`crates/p2p/`) has all building blocks implemented and unit-tested, but **none are wired into the running `gl-node` binary**. Nodes cannot replicate.

- [ ] **Boot Iroh `Endpoint` + `Router`** when `p2p.enabled` is true (§3.1, §3.4)
  - Library: `crates/p2p/src/node.rs`
  - Wire into: `crates/gl-node/src/main.rs`
  - Load `SecretKey` from `p2p.secretKeyPath` config
  - Derive `EndpointId` for author identity (currently hardcoded to `"local"` in `main.rs:66`)

- [ ] **Start gossip event loop** — subscribe to `TopicId`, broadcast new directives on append (§3.4, §3.4.3)
  - Library: `crates/p2p/src/gossip.rs`, `crates/p2p/src/topic.rs`
  - On local `appendTransaction` / `openAccount` / `closeAccount` → gossip announce
  - On gossip receive → union merge into ledger

- [ ] **Start anti-entropy periodic exchange** — ALPN handler + interval loop (§3.4.1)
  - Library: `crates/p2p/src/anti_entropy.rs`, `crates/p2p/src/protocol.rs`
  - Register ALPN `openledger/anti-entropy/1` on Iroh Router
  - Run head exchange every `p2p.antiEntropyIntervalMilliseconds`

- [ ] **Wire union merge on receive** — ingest remote directives into `LedgerService` (§3.5)
  - Library: `crates/p2p/src/union_merge.rs`
  - Validate remote transactions (I1–I3, I5) before insert
  - Update read model + re-serialize `.bean` + fire subscription broadcast

- [ ] **Wire orphan buffer drain** — buffer directives with missing parents, retry on arrival (§3.4.4)
  - Library: `crates/p2p/src/orphan_buffer.rs`
  - 10K / 1-hour limits

- [ ] **Wire `peers` query** — return connected peers from `PeerRegistry` (§2.6, FR-6 AC2)
  - Currently returns `[]` in `crates/gl-node/src/graphql/query.rs:243-245`

- [ ] **Wire `health.peers` count** — return live peer count (§2.9)
  - Currently returns `0` in `crates/gl-node/src/graphql/query.rs:229`

- [ ] **Bootstrap peer connections** — connect to `p2p.bootstrapEndpointIds` on boot (§3.9)

---

## 🟡 P2 — Features Built but Not Integrated

- [ ] **Start file watcher** when `externalFileEdits: "enabled"` (§3.3, CT-12)
  - Library: `crates/ledger/src/file_watcher.rs`
  - Start in `main.rs`, connect change events to ledger service union-merge path
  - Debounce 250ms per spec

- [ ] **Wire signing into write path** based on `signing.enabled` config (§3.8.1)
  - Library: `crates/security/src/signing.rs`
  - Select `PeerKeySignatureProvider` (when enabled) or `NoopSignatureProvider`
  - Inject into `LedgerService` so `openledger-signature` is stamped on append
  - Verify signatures on remote inserts when signing is enabled

- [ ] **SSE subscription transport** (§2.6)
  - Spec requires both **WebSocket** (default) and **SSE** for `transactionAppended`
  - Only WebSocket is currently implemented via `BroadcastStream`
  - Add SSE endpoint for clients that don't negotiate WebSocket

- [ ] **Graceful shutdown: 10-second drain timeout** (§3.9)
  - Current shutdown handles SIGTERM/SIGINT but has no explicit drain timeout
  - Spec: stop accepting → drain in-flight (10s timeout) → flush `.bean` → close Iroh → exit

---

## 🟢 P3 — Polish & Hardening

- [ ] **Fix 18 compiler warnings** — unused imports, unused struct fields, dead code
  - `ledger`: unused import `tokio::time::interval`
  - `gl-node`: unused fields `signing`, `enabled`, P2P config fields (`bootstrap_endpoint_ids`, `gossip_interval_milliseconds`, `anti_entropy_interval_milliseconds`, `swarm_topic`)
  - `gl-node`: unused function `build_schema`, unused associated items `with_capacity` / `subscriber_count`
  - `gl-node` tests: unused imports `DecimalScalar`, `rust_decimal::Decimal`, `std::sync::Arc`, `tokio::sync::RwLock`

- [ ] **Multi-node convergence integration test** (§4 M6, §6 item 3)
  - Spec M6: *"Done when: a 3-node cluster converges in production-like topology"*
  - Current integration tests are single-node only
  - CT-9 (partition converge), CT-12 (external edit), CT-14 (remote validation) are library-level only

- [ ] **Perf benchmark** (§6 item 4)
  - *"p99 < 50ms for trial balance on ≤10k transactions"* — informational gate, no benchmark exists
  - *"zero calls into `.bean` parser on the read path"* — structurally true (read model), but no benchmark assertion

- [ ] **`deploy/` directory** (§5 layout)
  - Spec suggests `deploy/` for container + compose / unit files
  - Only a root `Dockerfile` exists; no compose file for multi-node setup

---

## Conformance Tests — E2E Gaps

All 15 CTs pass at the library level. These need true end-to-end validation once P2P is wired:

| CT | Invariant | Current Coverage | E2E Gap |
|----|-----------|-----------------|---------|
| CT-9 | FR-4 (partition converge) | In-memory merge test | Needs real Iroh network partition test |
| CT-12 | §3.3 (external edit enabled) | File watcher logic tested | Watcher not running in `gl-node` |
| CT-14 | §3.5 (remote validation) | Union merge validates | No live gossip path to exercise |

---

## Reference

- **Spec:** [SPEC.md](SPEC.md) (940 lines, v1.0.0)
- **Progress:** [IMPLEMENTATION_PLAN_PROGRESS.md](IMPLEMENTATION_PLAN_PROGRESS.md)
- **Test count:** 294 passing (29 gl-node + 8 integration + 193 ledger + 49 p2p + 15 security)
- **Crates:** `gl-node`, `ledger`, `p2p`, `security`
