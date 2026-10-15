# Plan: several company ledgers on one node (from intent.md, 2026-10-13; approved 2026-10-14)

## Design

**A node is a host for ledgers.** The node owns what is shared — the HTTP
listener, TLS/proxy settings, CORS and allowed hosts, connection limits, the
rate limiter, and the operator key. Each ledger owns everything else, exactly
as a node does today: its `.bean`, commit journal and lock; its node key and
P2P endpoint (own UDP port, own `meshId`, relay, allowlist, peer addresses);
signing, Format, the file watcher; its access list and `auth.adminNodes`.

- **Settings.** `NodeConfig` splits into the node part and a `LedgerConfig`
  (`ledgerPath`, `watchLedgerFile`, `signing`, `format`, `p2p`,
  `auth.adminNodes`). The config file reads as today: its own ledger fields,
  when `ledgerPath` is set, are the ledger named **`default`**. Other ledgers
  live under **`ledgersDir`** (default `./data/ledgers`), one folder each:
  `<name>/ledger.json` (a `LedgerConfig`) beside that ledger's files, paths
  relative to the folder, folder 0700, files 0600. Boot starts `default` and
  every folder.
- **Names:** 1–40 characters of `a-z`, `0-9`, `-`, not starting with `-`;
  `default` is reserved for the config file's ledger. A name is a folder and a
  URL segment, so nothing else is accepted.
- **Requests name their ledger in the path:** `/ledgers/<name>/graphql` and
  `/ledgers/<name>/health`. `/graphql` and `/health` stay, as the `default`
  ledger, so a single-ledger node and its clients change nothing.
- **Auth per ledger:** a request is checked against the operator key and *that*
  ledger's access list only, so a key from ledger A gets 401 on ledger B. An
  unknown ledger name answers exactly like a wrong key (401) unless the caller
  holds the operator key (404), so names cannot be probed.
- **Starting and stopping one ledger** is the boot sequence `main` runs today
  — load the key, set the author, signer and verifier, finalise operator
  input, compact, then P2P and the watcher (H-13, L-04, T80) — moved, in the
  same order, into `ledger_runtime::start`, with `stop` doing the shutdown half
  (watcher, compaction, P2P router). `main` sets up the node, starts each
  ledger, serves, and stops them all.
- **Failure stays per ledger:** a ledger that fails to start is logged, listed
  as failed with its reason, and not served; the others start. Every
  per-ledger log line carries the ledger name.
- **At runtime** an operator-only node endpoint (`/node/graphql`:
  `ledgers`, `addLedger`, `removeLedger`) and `gl-node ledger add | list |
  remove` (a client of it, like `gl-node user`). `add` writes the folder and
  `ledger.json` atomically, creates the ledger's key, starts it and prints its
  node id for the other nodes' allowlists. `remove` stops it — in-flight
  requests finish, the journal is compacted — and moves the folder to
  `<ledgersDir>/.removed/<name>-<UTC time>/`; nothing is deleted.
- **Fairness:** each ledger already has its own write permit, caches and P2P
  limits. Added: an in-flight request cap per ledger (a hot ledger answers
  503 past it; the others are unaffected), and the client rate limit stays
  per client across ledgers. Boot refuses two ledgers with the same `meshId`,
  listen port, key path or ledger path, and more than `maxLedgers` (100).

## Order of work

1. **Carve out one ledger** — no behaviour change. `LedgerConfig`, and
   `ledger_runtime::{start, stop}` holding the sequence `main` runs today, in
   the same order; `main` calls it for the one ledger. Proof: every existing
   test, the shipped binary's boot, restart, upgrade and rollback tests; the
   ordering comments move with the code.
2. **Ledgers from `ledgersDir`, routed by path.** The registry, the routes,
   auth per ledger, the unknown-name rule, per-ledger failure, the cross-ledger
   checks, per-ledger `/health`, `--ledger <name>` on `gl-node user` and
   `--node-id`. README (*Several ledgers*), CHANGELOG. (As built: `/health`
   stays the `default` ledger's; a named ledger's `/health` needs a key it
   accepts, so it cannot be used to probe names; GraphiQL is the `default`
   ledger's only, since its page posts to `/graphql`; the node summary moves
   to step 4's `ledgers` query.) Step 4 inherits from the step 2 review: a
   full stop of one ledger must also end its address-refresh task, which a
   ledger refused after building its endpoint leaves running.
   Once a failed ledger no longer ends the process, `start` must undo what it
   began: validate everything (`adminNodes`) before spawning a task, and on a
   later failure stop the P2P tasks, the watcher and the endpoint before
   releasing the lock; and `build_signature_provider` must return an error
   instead of exiting (step 1 review).
3. **Fairness and scale.** The in-flight cap; a 100-ledger boot (P2P off) and
   a 10-ledger mesh on loopback, measured (boot time, memory, open files) into
   `notes/`; parallel compaction at shutdown, with the time it needs written
   into OPERATIONS (`docker stop` waits 10 s by default).
4. **Add and remove at runtime.** The node endpoint, `gl-node ledger …`,
   atomic folder creation, stop-and-move on remove, restart picks up what was
   added and not what was removed. README, OPERATIONS (*Adding a company*,
   backups per folder), CHANGELOG.
5. **Packaging.** The production template and compose stack with `ledgersDir`;
   `deploy/mesh-init.sh` for a named ledger; OPERATIONS upgrade notes.

## Risks

- **Step 1 can break boot ordering** that the audits fixed (identity before
  the first write, one key read, author set before signing). It is its own
  unit with no new behaviour, so any test change in it is a red flag.
- **Isolation by mistake:** a handler resolving the wrong ledger, or a cache
  keyed without the ledger. Every request-scoped piece is reached through the
  ledger's own handle; tests run two ledgers and check each answer, key and
  record stays on its side.
- **Name probing and path tricks:** the name rule and the 401-for-unknown rule.
- **Memory:** every ledger's DAG lives in memory; 100 ledgers near the 64 MiB
  cap would not fit a small server. Step 3 measures it and OPERATIONS states
  the budget; `maxLedgers` caps the count.
- **Shutdown time:** compacting 100 journals; done in parallel, and measured.
- **A runtime add racing a restart** leaves a half-written folder: written
  under a temporary name and renamed into place, so boot sees all or nothing.

## Alternatives rejected

- One process per ledger under a supervisor: exactly the operating burden the
  intent removes.
- The ledger in a header: proxies, caches and GraphiQL handle paths better,
  and a path shows up in access logs.
- One P2P endpoint shared by all ledgers: links the meshes (decision 1).
- Ledgers listed in the config file with a restart: decision 3.
- People's keys across ledgers: decision 2.

## Proof

- Tests per step as above; revert checks in `scripts/revert_specs/ledgers.json`
  for routing to the right ledger, auth per ledger, the unknown-name rule, the
  name rule, a failed ledger staying out while the rest serve, the
  cross-ledger refusals, the in-flight cap, remove keeping files, and restart
  loading what was added.
- Docs: README, OPERATIONS, CHANGELOG (*Added*; nothing in *Breaking*).
