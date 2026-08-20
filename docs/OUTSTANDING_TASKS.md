# Outstanding Tasks

> Derived from a full review of [SPEC.md](SPEC.md) against the current codebase.
> All 12 implementation passes and 15 conformance tests (CT-1–CT-15) are marked complete at the library level.
> **295 tests passing · 4 crates compiling · 0 warnings**

---

## ✅ P1 — Live P2P Integration (DONE)

All P2P building blocks are now wired into `gl-node`:

- [x] Boot Iroh Endpoint when `p2p.enabled` — `p2p_service::boot_p2p()`
- [x] SecretKey persistence from `p2p.secretKeyPath` — `load_or_create_secret_key()`
- [x] Author identity derived from Iroh EndpointId — `set_author_id()`
- [x] Gossip event loop — `spawn_gossip_loop()`
- [x] Anti-entropy periodic exchange — `spawn_anti_entropy_loop()`
- [x] Union merge on gossip receive — `insert_remote_directive()`
- [x] Orphan buffer drain on parent arrival — `drain_orphans()`
- [x] `peers` query returns live data from PeerRegistry
- [x] `health.peers` returns live peer count

## ✅ P2 — Features Built but Not Integrated (DONE)

- [x] File watcher started when `externalFileEdits: "enabled"` (250ms poll)
- [x] Signing wired into write path via `SignatureProvider` trait
- [x] Graceful shutdown with SIGTERM/SIGINT handling

## ✅ P3 — Polish (DONE)

- [x] All 18 compiler warnings fixed (0 remaining)
- [x] `deploy/` directory created with `docker-compose.yml` + config

---

## Remaining

### R1. Gossip Outbound from Mutations

The gossip loop has an `mpsc::Sender` for broadcasting local directives, but it's stored as `_gossip_sender` in `main.rs` and not connected to the mutation layer. When `appendTransaction` / `openAccount` / `closeAccount` succeeds, the new directive should be sent through this channel so peers receive it instantly via gossip (not just eventually via anti-entropy).

**Files:** `main.rs` (pass sender to schema data), `mutation.rs` (send after insert)
**Effort:** ~30 lines

### R2. Bootstrap Peer Connections (§3.9)

- [x] `bootstrapEndpointIds` parsed as Iroh `EndpointId`s, passed to `gossip.subscribe`, and used as the inbound `Supply` allowlist. Empty list admits no remote writes.

### R3. ALPN Anti-Entropy Full Exchange (§3.4.1)

The anti-entropy loop detects missing directives by comparing head sets, but doesn't open ALPN connections to actually fetch them. It currently logs and relies on gossip. A full implementation needs:
- Register `openledger/anti-entropy/1` ALPN on the Iroh endpoint
- Accept inbound Want/Supply exchanges
- Initiate outbound connections for proactive catch-up

**Files:** `p2p_service.rs` (ALPN handler + outbound connection logic)
**Effort:** ~150 lines

### R4. Signature Verification on Remote Inserts

- [x] When `signing.enabled`, gossip `Supply` must carry a valid `openledger-signature` verified against `openledger-author` (Iroh `EndpointId` hex = Ed25519 public key). Unsigned entries are accepted only when signing is off.

### R5. SSE Subscription Transport (§2.6)

The spec requires both WebSocket (done) and SSE for `transactionAppended`. An SSE endpoint (e.g., `GET /graphql/sse`) streaming `TransactionBroadcast` as `text/event-stream` is missing.

**Files:** New `sse.rs` handler in gl-node, route in `main.rs`
**Effort:** ~60 lines

### R6. Multi-Node Convergence Integration Test (§4 M6)

- [x] Three Iroh endpoints with `relayMode=disabled` and in-memory address lookup exchange ALPN HaveHeads/Want/Supply until ledgers match (`three_node_alpn_convergence` in `anti_entropy_alpn.rs`).

### R7. Performance Benchmark (§6)

*"p99 < 50ms for trial balance on ≤10k transactions"* — no `criterion` benchmark exists.

**Files:** New `benches/` directory with criterion benchmark
**Effort:** ~80 lines

---

## Conformance Tests — E2E Gaps

All 15 CTs pass at the library level. Once R3/R6 are done, these will have true E2E coverage:

| CT | Invariant | Current Coverage | After R6 |
|----|-----------|-----------------|----------|
| CT-9 | FR-4 (partition converge) | In-memory merge test | Real Iroh network |
| CT-12 | §3.3 (external edit enabled) | ✅ File watcher running in gl-node | ✅ |
| CT-14 | §3.5 (remote validation) | Gossip receive path wired | Real multi-node |

---

## Effort Estimate

| Item | Lines | Complexity |
|------|-------|------------|
| R1 — Gossip outbound | ~30 | Low |
| R3 — ALPN anti-entropy | ~150 | Medium |
| R5 — SSE endpoint | ~60 | Low |
| R6 — Multi-node convergence test | ~200 | High |
| R7 — Performance benchmark | ~80 | Low |
