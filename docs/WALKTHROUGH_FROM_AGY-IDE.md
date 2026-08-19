# Walkthrough — P2P Integration & Outstanding Tasks

## Summary

Wired the previously disconnected `p2p`, `security`, and `ledger` crates into the `gl-node` binary, addressing the majority of items from `docs/OUTSTANDING_TASKS.md` and `docs/IMPLEMENTATION_PLAN_PROGRESS.md`.

## Changes Made

---

### Ledger Crate (`crates/ledger`)

#### [service.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/ledger/src/service.rs)
- **`set_author_id()`** — Post-boot identity update when Iroh EndpointId is known
- **`head_txids()`** / **`all_directive_ids()`** — Accessors for anti-entropy head exchange
- **`insert_remote_directive()`** — Full P2P receive path: Lamport clock adoption, validation, DAG insert, read model update, persistence
- **`stamp_signature()`** — Post-insert metadata stamping for Ed25519 signatures

#### [dag.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/ledger/src/dag.rs)
- **`get_mut()`** — Mutable directive access for post-insert metadata stamping

#### [file_watcher.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/ledger/src/file_watcher.rs)
- Removed unused `tokio::time::interval` import

---

### GL-Node Binary (`crates/gl-node`)

#### [NEW] [p2p_service.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/p2p_service.rs)
- `boot_p2p()` — Iroh endpoint with N0 preset, secret key persistence (CAP-4)
- `spawn_gossip_loop()` — Background task for gossip publish/subscribe with orphan draining
- `spawn_anti_entropy_loop()` — Periodic head exchange with connected peers
- `drain_orphans()` — Resolve buffered orphans when parents arrive
- `load_or_create_secret_key()` — Persistent Ed25519 identity key management

#### [MODIFY] [main.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/main.rs)
- Declared `p2p_service` module
- P2P boot with config-driven enable/disable
- Author identity derived from Iroh EndpointId
- Gossip + anti-entropy loops spawned as background tasks
- File watcher spawned when `externalFileEdits: "enabled"`
- Signing provider created from config + secret key
- Health endpoint now state-aware with live head/peer counts

#### [MODIFY] [graphql/mod.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/graphql/mod.rs)
- `build_schema_with_service()` now accepts `PeerRegistry` + `Arc<dyn SignatureProvider>`

#### [MODIFY] [graphql/query.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/graphql/query.rs)
- `health` resolver reads live peer count from `PeerRegistry`
- `peers` resolver lists connected peers from `PeerRegistry`

#### [MODIFY] [graphql/mutation.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/graphql/mutation.rs)
- `append_transaction` signs content after insert when signing enabled (§3.8.1)

#### [MODIFY] [health.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/health.rs)
- Rewritten with Axum `State` extractor for live `SharedLedger` + `PeerRegistry`

#### [MODIFY] [config.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/config.rs)
- `allow(dead_code)` annotations on Phase 2 config fields

#### [MODIFY] [graphql/broadcast.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/graphql/broadcast.rs)
- `allow(dead_code)` on test-only helper methods

---

### Deployment (`deploy/`)

#### [NEW] [docker-compose.yml](file:///Users/samurai/code/edgar/openledger-v2/deploy/docker-compose.yml)
- 3-node deployment with persistent volumes, Docker bridge network, and health checks

#### [NEW] [gl-node.docker.json](file:///Users/samurai/code/edgar/openledger-v2/deploy/gl-node.docker.json)
- Production-ready config template for containerized deployment

---

## Verification

| Check | Result |
|-------|--------|
| `cargo check --workspace` | ✅ 0 errors, 0 warnings |
| `cargo test --workspace` | ✅ 295 tests pass (30 gl-node + 193 ledger + 49 p2p + 15 security + 8 doc-tests) |
| Clippy `deny(all)` | ✅ Clean |

## Remaining Items

| Item | Status | Notes |
|------|--------|-------|
| Multi-node convergence test | Pending | Requires spawning multiple Iroh endpoints in-process |
| Performance benchmarks | Pending | Can use `criterion` crate |
| ALPN anti-entropy full exchange | Stub | Gossip handles common case; anti-entropy logs misses |
