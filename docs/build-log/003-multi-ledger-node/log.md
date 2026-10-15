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
- **Commit:** 958255c

## 2026-10-15 — Step 3: fairness and scale

- **What changed:** `http.maxRequestsPerLedger` (default 64): each ledger's
  `/graphql` takes one of its own slots, after its key check, and answers
  `503 LEDGER_BUSY` with `Retry-After` when they are all in use — a flooded
  ledger slows only itself, and a stranger cannot fill a ledger's slots or
  learn from a 503 that it exists. Ledgers boot in parallel, the config
  file's first (it wins any conflict), then the folders up to one per core;
  `boot_p2p`'s error became `Send + Sync` for that. `stop_all` stops every
  ledger at once. `scripts/measure_ledgers.py` measures a node of N ledgers
  (`--p2p`, `--entries`) and a two-node mesh of paired ledgers (`--mesh`);
  the results are in `notes/measurements.md`. README (one config row),
  OPERATIONS (*Sizing a node with several ledgers*), CHANGELOG.
- **Measured** (release build, loopback; `notes/measurements.md`): 100 P2P
  ledgers boot in 2.1 s (11.2 s one after another) in 107 MiB with 466 open
  files; 30 ledgers of 10,000 entries boot in 4.5 s (17.2 s) in 1.75 GiB
  (1.24 GiB one after another: parallel boot keeps about one ledger's worth
  per core); every stop under 1.3 s; a two-node mesh of 100 paired ledgers
  replicates every entry, none into the wrong ledger. Memory is the limit:
  about 45 MiB per 10,000 entries.
- **The rate limit, per client and ledger** (the maintainer's choice,
  2026-10-15, of keep / raise / per client and ledger): the plan kept one
  GraphQL budget per client across the node, so an accountant's app working
  across 40 companies from one address shared 60 requests a minute among them.
  Now each ledger has its own limiter — the hardened table, unchanged — for
  the callers it accepts (its people, the operator), so a client's budget is
  per ledger; every other caller — no key, a wrong key, a name not served —
  shares one strangers' table per client, so made-up names buy nothing and a
  stranger's 429 comes at the same count whatever name it tries. (The first
  version chose the table by the name alone, which let a stranger spend the
  shared table on made-up names and then see which names still answered 401
  from a fresh one: an oracle for which companies are served. Caught in a
  second review round; L-R31 pins it.) The check moved from a layer on the
  GraphQL routes into `Ledgers::dispatch`, after the key checks and before
  anything else. A folder ledger's table holds at most 8,192 clients (the
  config file's keeps 65,536): full, about 0.8 MiB, so 100 folder ledgers
  under a flood of addresses hold about 80 MiB of buckets rather than about
  600 MiB, held until restart (a sweep frees entries, not capacity). Past the
  cap the M-21 shared overflow applies, as before: 8,192 distinct clients in a
  minute is still an attack, not one company's load, but it is a cheaper one
  (an IPv6 /51 rather than a /48), and the company's newcomers then share one
  budget until it ends. The full-table warning names the ledger. `/health`
  keeps its one node-wide limiter.
- **Tests:** a busy ledger slows only itself (503 with `Retry-After`, the
  other ledger answers, a stranger still gets 401, served again once a slot
  frees); `http.maxRequestsPerLedger` bounds; the rate limit per client and
  ledger, and made-up names sharing one budget; a folder ledger's smaller
  table, and a smaller table overflowing sooner.
- **Review round** (reviewer subagent; nothing Important): parallel boot had
  made two paths worse, both fixed. A panic in a folder's boot was caught by
  the `JoinSet` and the ledger vanished — no record, no name in the log, and
  any tasks it had spawned still writing after its lock dropped; it now stops
  the node, as a panic in boot always did. And which of two folders sharing a
  node key was served depended on which finished booting first; the node ids
  are now settled before the parallel boots, in a fixed order (the config
  file's ledger, then the folders by name: `settle_node_keys`), with the
  ledger's own check as the backstop. Also: the synchronous ledger boot runs
  on the blocking pool, so the P2P of ledgers already started keeps running
  while the rest boot (this is what raised boot memory: the boots now truly
  overlap); `measure_ledgers.py` kills its node on every failure, keeps the
  work directory (and the log it names) when something fails, picks UDP ports
  below the ephemeral range on both address families, and says that its P2P
  modes send the gateway port-mapping probes a production node sends; the
  sizing numbers are this build's and the boot memory per core is stated;
  OPERATIONS adds the stop grace period, that a busy ledger's slots can be
  held by its own read keys, and that a retry counts against the rate limit;
  `maxRequestsPerLedger`'s upper bound is tested; the test helper uses the
  default instead of `64`.
- **Gate:** `scripts/gate.sh` — 1,595 passed, 0 failed, 0 ignored (6 min 40 s), on the final tree with the rate-limit change.
- **Revert checks:** `ledgers.json` — L-R21 (no cap), L-R22 (slots taken
  before the key check), L-R23 (the bound), L-R24 (node keys not settled),
  L-R25 (the config file's ledger settled last), L-R26 (one set of slots for
  every ledger), L-R27 (one rate-limit table for every ledger), L-R28 (made-up
  names unlimited), L-R29 (folder ledgers get full tables), L-R30 (the table
  cap ignored), L-R31 (the table chosen by the name) bite; L-R14 and L-R19 re-anchored. None for parallel boot and
  stop themselves, the blocking-pool boot, or a panic stopping the node: the
  first three change how long, not what (the measurements pin them), and no
  test can make a boot panic without a fault-injection hook.
- **Departures from the plan:** parallel boot is new (the plan had parallel
  stop only): sequential boot measured 17 s for 30 busy ledgers.
- **Commit:** (pending)
