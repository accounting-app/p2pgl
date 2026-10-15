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
- **Commit:** 5369a8a

## 2026-10-15 — Step 2: ledgers from `ledgersDir`, routed by path

- **What changed:** `config.rs` — `ledgersDir` (default `./data/ledgers`)
  and `maxLedgers` (1–100, default 100) on the node; a ledger name rule
  (`is_valid_ledger_name`); `ledger_folders` (the folders, sorted; a dot entry
  skipped, `default` and bad names listed as not ledgers);
  `LedgerConfig::load_folder` (a folder's `ledger.json`, read like the config
  file, its `.bean` and `iroh.secret` always in the folder,
  `p2p.secretKeyPath` refused); `LedgerConfig::validate` — the ledger's rules,
  moved out of `NodeConfig::validate` unchanged and in order, so every folder
  gets exactly the checks the config file's ledger does; `ledgers_in_conflict`
  (a second ledger in one mesh, on one gossip topic or one fixed port, or past
  `maxLedgers`). `ledgers.rs` — the registry and the routes: each ledger
  served by a router of its own (its `/graphql` behind its own auth, its
  `/health`), reached through `/graphql` and `/health` (the `default` ledger)
  or `/ledgers/<name>/…`; a name not served answers 401 unless the caller is
  the operator (404, or 503 for a ledger refused at boot), and a named
  ledger's `/health` needs a key it accepts. `main` starts the config file's
  ledger and every folder; a refused or failed ledger is logged and recorded,
  the rest serve; the node stops only when none can. `ledger_runtime::start`
  runs in a `ledger` span (and its P2P tasks and watcher, through
  `spawn_in_span`), checks `auth.adminNodes` before touching anything, closes
  the P2P endpoint on the T80 refusal, and gets an error, not an exit, from
  `build_signature_provider` (the step 1 review's two items); its "—
  aborting" lines now say the ledger is not served. `gl-node user` and
  `gl-node --node-id` take `--ledger NAME`. README (*Several ledgers*, two
  config rows), CHANGELOG (*Added*), plan.md (step 2 as built).
- **Tests:** config — the name rule, a folder's settings and files, the
  folder listing, the conflicts, `ledgersDir` and `maxLedgers`; routing —
  each ledger's books and keys stay its own, a ledger not served is told
  only to the operator, a named `/health` needs a key; runtime — a ledger
  that cannot start touches nothing (refused `adminNodes`) or releases its
  lock (no key); the shipped binary — `default` and a folder ledger with its
  own mesh side by side, a broken folder skipped, a key per ledger, books
  apart, `--node-id --ledger`, `user --ledger`, across a restart.
- **Review round** (reviewer subagent): one Important finding, fixed. (I-1)
  A folder — or a file — named `default` in `ledgersDir` was recorded as
  refused under the name the config file's ledger was already served by, and
  the registry's plain insert replaced the running ledger: `/graphql` went
  401/503, the orphaned ledger kept writing with its lock released, and a
  single-ledger node exited. Now `start_ledgers` ignores a `default` entry,
  and the registry never replaces a held name (a refusal is dropped; a second
  running ledger is handed back and stopped); the shipped test has a stray
  `default` folder. Also taken: two ledgers with the same node key (a copied
  folder, or the config file pointed at a folder's key) are refused — the
  plan's "same key path" check, done on the key itself, right after it is
  read and before any mesh is joined (M-2); files in `ledgersDir` are skipped,
  not listed as failed ledgers; the commit and recovery tasks and the
  outbound exchange `JoinSet` carry the ledger's span (M-4); the CHANGELOG
  lists the two new refusals (*Changed*); Bug-catch wording matched to the
  reverts. Kept as residuals, written down: a served ledger's 401 can be
  slower than an unknown name's, so names are not hidden from timing (README;
  the rate limit bounds probing) (M-1); a ledger refused after its endpoint
  was built leaves its address-refresh task running (log lines only, no
  writes) — step 4's full stop of a ledger ends it (M-3); with ledger rules
  checked first, a config file with both a ledger and a node error now
  reports the ledger's first (each message unchanged); the image's working
  directory makes the default `ledgersDir` `/data/data/ledgers` — step 5.
  Three anchors the step's edits moved were re-pointed (PD-R16, U-R16,
  U-R41; the checker names only the first stale anchor per file).
- **Gate:** `scripts/gate.sh` — 1,590 passed, 0 failed, 0 ignored (6 min 24 s).
- **Revert checks:** `scripts/revert_specs/ledgers.json` — 20 of 20 bite
  (L-R1 to L-R20). L-R18 reverts both halves of the `default` protection
  together: each alone is covered by the other (the skip, and the registry's
  no-replace rule, L-R17).
- **Departures from the plan:** `/health` stays the `default` ledger's, a
  named ledger's `/health` needs its key, GraphiQL is `default`'s only, and
  the node summary moves to step 4 (plan.md updated).
- **Commit:** (pending)
