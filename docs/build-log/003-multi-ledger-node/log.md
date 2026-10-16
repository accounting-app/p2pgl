# Log: several company ledgers on one node

Status: done (2026-10-16, last commit acbce10).

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
- **Commit:** 156733d

## 2026-10-16 — Step 4: add, remove and restart ledgers at runtime

- **What changed:** a company's ledger is added, removed or restarted while
  the node runs, the others untouched. `gl-node ledger add NAME [--settings
  FILE] | list | restart NAME | remove NAME` (`ledger_cli.rs`) is a client of
  the node endpoint `/node/graphql` (`ledger_admin.rs`: `ledgers`,
  `addLedger`, `removeLedger`, `restartLedger`), which takes the operator key
  only — a person's key from any ledger gets 401 — behind the request guard
  and a GraphQL budget of its own. **Add** writes `.adding-<name>-…/ledger.json`
  (0700/0600, synced), loads it with boot's rules, checks it against the
  served ledgers (`ledgers_in_conflict`, `maxLedgers`), makes the node key
  when the ledger signs or replicates, renames the folder into place, and
  starts and serves it; refused, nothing is left; a start that fails moves the
  folder to `.removed/<name>-<time>-failed`. **Remove** takes the ledger out
  of the registry, waits until every request it was serving has finished (all
  its slots back, then closed: one routed to it meanwhile gets 503
  `LEDGER_BUSY`), stops it, and moves its folder to
  `.removed/<name>-<UTC time>`; nothing is deleted. **Restart** loads the
  folder and checks it before stopping anything, so refused settings leave
  the ledger serving; it also serves a folder refused at boot, or made by
  hand. One change at a time (`NodeAdmin::busy`, which the node's shutdown
  also takes), each request on a task of its own so a timeout never leaves a
  change half done. **A full stop** (`RunningLedger::stop`): every task a
  ledger spawns while it starts, and every task those spawn, is listed
  through a task-local (`LEDGER_TASKS`, in `spawn_in_span`) and aborted by its
  stop; commits and recoveries run detached (`spawn_detached_in_span`, M-39),
  so a stop never cuts a write short, and the stop takes the write permit
  once more after the P2P shutdown, so none is still writing when the lock
  is released; the stop frees the ledger's node id, and so does a refused
  start. `user_cli`'s node-and-key lookup is shared (`OperatorTarget`). README
  (*Adding and removing ledgers while the node runs*), OPERATIONS (*Adding a
  company*, backups per folder, `.removed/`), CHANGELOG.
- **Tests:** a stop leaves no task running, nested ones included; an added
  ledger is served at once and its folder is in place for the next boot, a
  signing ledger with its key; a removed ledger is stopped, its books whole in
  the moved folder, and moved back under another name it is served again with
  its node id; refused changes change nothing (bad names, `default`, settings
  that are not a `ledger.json`, a used name, a shared mesh, removing or
  restarting what is not there); a restart picks up an edit, keeps the ledger
  serving through refused ones, and serves a fixed or hand-made folder; the
  node endpoint is the operator's only; a removal waits for a request in
  flight while the other ledgers answer; the CLI parses and drives the node;
  and the shipped binary adds, lists, removes, re-adds and restarts.
  Also: a stop waits for a write begun after its compaction; a commit is
  never among a ledger's tasks; a refused start frees its node id; a change
  whose request is cut short still runs to its end.
- **Review round** (reviewer subagent). *Important:* a peer's `Supply` is
  served on iroh's tasks, not the ledger's, so its commit could start after
  the stop's compaction and, detached, still be writing after the router shut
  down and the lock was released — during a restart's boot of the same files,
  or a removal's move. The stop now takes the write permit once more after the
  router shutdown (every writer holds it to its end), and the docs say a
  record pushed in those last moments stays in the journal until the next
  start. Also fixed: the commit detach and the node endpoint's own task had no
  revert check (now L-R49, L-R51); a refused start kept its node id claimed,
  so the folder could not be served under another name (now freed; L-R50);
  the node's shutdown released `busy`, so a change queued behind it could
  start a ledger nothing would stop (it stays held); OPERATIONS says a crash
  mid-add can leave an `.adding-` folder that may be deleted; a stale comment
  on the refused-start branch. Not changed: the key-creation log line names
  the staging path.
- **Gate:** `scripts/gate.sh` — 1,616 passed, 0 failed, 0 ignored (7 min 0 s), on the final tree.
- **Revert checks:** `ledgers.json` — L-R32 to L-R51 (20) bite, two of them
  (L-R46, L-R47) through the shipped binary. A first L-R38 (remove without a
  stop) did not bite: a small ledger rewrites its `.bean` at every write, so
  no test of that size sees a compaction skipped; the test now restores the
  removed folder under another name, which works only if the stop freed its
  node id. A planned check that a refused ledger can be replaced in the
  registry did not bite either: nothing needs it (a restart takes the refused
  ledger out first), so the change was undone. Not pinned: the recovery
  reload's detach (`ledger_commit.rs`, the same mechanism as the commit's,
  L-R49) — reaching a recovery needs a failing commit inside a ledger's task.
- **Departures from the plan:** recorded in `plan.md` step 4 (*As built*):
  `restartLedger`, the key made for a signing-only ledger, a failed add moved
  aside, `default` fixed, the removal's wait, the full stop and the detached
  writes.
- **Commit:** df4cfb5

## 2026-10-16 — Step 5: packaging

- **What changed:** the image's configs (`deploy/gl-node.production.json`,
  `gl-node.docker.json`) set `ledgersDir: "/data/ledgers"`, in the volume
  beside the config file's ledger; the compose stack gives a node 60 s to
  stop (`stop_grace_period`: every ledger compacts on the way out) and its
  health check a 30 s start period. **`deploy/mesh-init.sh --ledger NAME`**
  adds a company to the running stack in a mesh of its own: a fresh
  `meshId` and topic, signing and P2P on, the next UDP port above the nodes'
  ledgers' (the same on all three; `LEDGER_PORT=` to choose); each node adds it with
  `gl-node ledger add` (its key made there, its id printed), then gets its
  peers' ids and `node-N:<port>` addresses in `ledger.json` (written aside and
  renamed) and `gl-node ledger restart`; a refusal part way takes the ledger
  off the nodes it had reached. OPERATIONS: the template's `ledgersDir`, and
  upgrade and rollback notes for this release (what is refused before, what to
  add after, what 0.1.0 does with the folders). README (*Multi-node stack*),
  CHANGELOG. **Found by the rehearsal and fixed:** on the stack, a ledger
  added at runtime logged inside another ledger's endpoint span
  (`ledger{ledger=acme}:endpoint{…}:ledger{ledger=beta}`). iroh 1.0.3's
  `Endpoint::bind` holds its `endpoint` span entered across an `.await`
  (`endpoint.rs:237-286`, around `netmon::Monitor::new().await`), so a worker
  thread ran other tasks inside it while the bind waited, and kept it when the
  bind resumed elsewhere. The node now binds on a blocking thread of its own
  (`p2p_service::bind_endpoint`, `on_a_thread_of_its_own`), where the span is
  entered and left with nothing else polled in between.
- **Tests:** the image's configs keep their ledgers in the volume and
  `ledgerPath` outside them; a future holding a span across an await (as
  iroh's bind does) leaks it into no other task, and real binds through
  `bind_endpoint` leave none. The production template test sets a local
  `ledgersDir` beside its local `ledgerPath`.
- **Rehearsal** (compose stack, built from this tree): `mesh-init.sh`, `up`,
  `--ledger acme` (UDP 4434) and `--ledger beta` (4435); a transaction
  written on node-0's acme is on node-1 and node-2 within 12 s, verifying,
  and not in their default ledgers; `--ledger acme` again is refused
  (`LEDGER_EXISTS`) and changes nothing; a bad name is refused; with a stray
  `gamma` folder on node-1 only, `--ledger gamma` adds it on node-0, is
  refused on node-1 and takes it off node-0 again (to `.removed/`); after a
  stop (1 s) and start, both companies serve and replicate. Before the bind
  fix several of node-0's lines sat under another ledger's endpoint; after it,
  0 of 283 lines across the three nodes. `mesh-init.sh --ledger` has no
  automated test: it needs Docker. After the review's changes, again on a
  rebuilt stack: `--ledger acme` (4434), `LEDGER_PORT=4440 --ledger beta`, a
  refused `LEDGER_PORT=010`, a transaction on node-1's beta on node-0 and
  verifying, and 0 lines under another ledger or any endpoint span.
- **Gate:** `scripts/gate.sh` — 1,618 passed, 0 failed, 0 ignored (7 min 2 s), on the final tree.
- **Review round** (reviewer subagent; nothing Important): the span test's
  fixed half could not fail — the blocking thread had no subscriber, so its
  spans were never recorded; the caller's dispatcher now goes with the work
  (also what keeps the bind's own logs), and the test checks its span is
  recorded there (L-R54). OPERATIONS' upgrade notes set the new keys at each
  node's swap, as the generic procedure does (a node whose `ledgerPath` is in
  `./data/ledgers` must), and say `gl-node ledger`, `user` and `--node-id`
  are new since 0.1.0. The script disarms its undo once every node is done,
  says which node still holds the ledger if an undo fails, and takes the
  port from `LEDGER_PORT` (not `PORT`, which other tools set), refusing a
  leading zero (octal to bash, decimal to jq). The README names `.removed/`
  in the node's own `ledgersDir`; L-R55 covers `gl-node.docker.json`.
- **Revert checks:** `ledgers.json` — L-R52 and L-R55 (an image config's
  `ledgersDir` outside `/data`), L-R53 (the future polled on the caller's
  thread) and L-R54 (the bind thread without the caller's subscriber) bite.
  A first L-R53 that called iroh's bind directly did not bite: on macOS the
  bind finishes without yielding, so the test uses a future that leaks as
  iroh's does.
- **Departures from the plan:** recorded in `plan.md` step 5 (*As built*):
  `--ledger` works on the running stack through the runtime commands; the
  bind fix.
- **Commit:** acbce10
