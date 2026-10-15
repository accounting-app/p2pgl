# Log: several company ledgers on one node

Status: in progress.

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-10-14 — Step 1: carve out one ledger

- **What changed:** no behaviour. `ledger_runtime.rs` holds the boot sequence
  `main` ran for its one ledger — directory, lock (M-17), boot, quarantine
  banner, key read once (L-04), author from the key (T80), P2P identity,
  signer, verifier, operator input finalised and history verified (H-13,
  H-20), startup compaction, P2P tasks (H-13 (d)), file watcher, access list,
  schema, auth and health state — moved verbatim and in the same order, with
  every audit comment beside its step, as `start`; `RunningLedger::stop` is
  the shutdown half (watcher, compaction, P2P router; the lock drops last).
  Each `exit(1)` became `Err(StartFailed)` after the same log line, and
  `main` exits on it as before. `config.rs`: `LedgerConfig` (the ledger's
  settings, taken from the config file by `NodeConfig::ledger_config`; the
  JSON is unchanged — `deny_unknown_fields` rules out `serde(flatten)`), and
  `P2pConfig::log_signature_domain`. `auth::access_source_for` and
  `build_signature_provider` take the ledger's settings. `main` sets up the
  node, starts the ledger, serves and stops it.
- **Tests:** none new and none changed in what they assert. Four call sites
  in tests follow the moved signatures (`access_source_for`,
  `build_signature_provider`, `log_signature_domain`), and `main`'s test
  module imports three types `main` itself no longer uses.
- **Revert specs:** U-R23 and U-R46 re-anchored on the access-list condition
  (now `auth_enabled && config.signing.enabled`). Two anchors were found
  stale in the committed tree while checking every spec file, and fixed:
  H01-R4 (`h01_l23.json`) matched twice since 002 step 3's
  `read_existing_api_key` repeated its line — now anchored on the node's own
  loader; T98-R4b (`audit_0927.json`) matched nothing since R-15 nested its
  code one level deeper — re-indented. Every spec file passes `--check`.
- **Review round** (reviewer subagent): no Important findings; the moved
  block diffs against the original as `crate::` prefixes, the nine exits and
  the two signature changes only. Taken: comments that still said `main` for
  what `ledger_runtime::start` now does (`ledger_lock.rs`, `config.rs`,
  `p2p_service.rs`, `main.rs`) are corrected. Noted: the moved lines' log
  target is now `gl_node::ledger_runtime` (same text and level; a
  `RUST_LOG=gl_node=…` filter still matches); and two things step 2 must
  change once a failed ledger no longer ends the process — an early return
  after the P2P tasks and the watcher are spawned (the `adminNodes` and T80
  returns) leaves them running without the ledger's lock, and
  `build_signature_provider` still exits the process (unreachable today:
  `start` returns first). Both are in plan.md, step 2.
- **Gate:** `scripts/gate.sh` — 1,579 passed, 0 failed, 0 ignored, the same
  count as before the refactor; and again on the final tree, after the
  comment fixes (6 min 37 s; rerun 2026-10-15, 6 min 26 s).
- **Departures from the plan:** `LedgerConfig` is built from `NodeConfig`
  rather than parsed; step 2 parses it from `ledger.json`.
- **Commit:** (pending)
