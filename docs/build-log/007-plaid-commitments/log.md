# Log: keep what we told Plaid

Status: in progress.

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-11-10 — The secret store (step 3)

- **What changed:** `crates/gl-node/src/secret_store.rs`, a per-ledger
  encrypted store for values that never leave the node (Plaid access tokens
  from step 5). `secrets.json` in the ledger folder, opened through
  `open_checked` as `NodePrivate` (no symlink, owner, one link, 0600) and
  written through a fresh node-private temp file, fsync and rename. Each value
  is sealed with AES-256-GCM under `GL_NODE_SECRETS_KEY` (64 hex characters),
  with associated data binding it to its name (not the ledger: a removed
  ledger moved back under a new name keeps its store); `open` deletes temp
  files a crashed write left, then opens every value, so a wrong key or a
  moved value is refused there; writes refuse a file larger than `open`
  reads. `Secret` and `StoreKey` print `[redacted]`.
  `access_list::random_bytes` is now `pub(crate)`, the one random source for
  nonces. `aes-gcm` 0.10 is a new
  direct dependency of gl-node, already compiled in through iroh
  (`Cargo.lock` gains two dependency lines, no new crate). Intent approved
  with the maintainer's decisions; `plan.md` updated for them.
- **Not user-visible yet:** nothing calls the store until step 5, which wires
  the key into boot and the installer — so no README or CHANGELOG entry in
  this unit, and the module carries `#![allow(dead_code)]` until then.
- **Gate:** `scripts/gate.sh` — 1656 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/secret_store.json` — 12 of 12 bite.
- **Review:** no important findings. Fixed: binding values to the ledger's
  name would strand a removed ledger moved back under a new name (now bound
  to the name only, SS-R2 inverted); a crashed write's temp file outlived
  removals (now swept at open, SS-R9); no write-side size cap (SS-R10); the
  associated-data prefix renamed `openledger/secret-store/v1` before any
  store exists; distinct `Seal` and `TooLarge` errors, temp-file errors name
  the temp file; the `random_bytes` doc; revert checks for the round trip,
  version and name checks. Noted for step 5 in `plan.md` Risks: one store
  instance per ledger.
- **Departures from the plan:** the ledger binding above (`plan.md` updated).
- **Commit:** c24b376

## 2026-11-13 — Plaid connect and disconnect, in the node (step 5)

- **What changed:** bank connections through Plaid on the one node per
  company with `plaid.enabled` (new `PlaidConfig` in a ledger's config:
  `enabled`, `environment` — `sandbox` or `production`, never an address —
  and `clientName`). `crates/gl-node/src/plaid.rs`: `PlaidEnv` (credentials
  and store key from `GL_NODE_PLAID_CLIENT_ID`, `GL_NODE_PLAID_SECRET`,
  `GL_NODE_SECRETS_KEY`, read once in `main`; a half-set pair or a bad key
  stops the node), `PlaidClient` (reqwest on rustls/ring with Mozilla's
  roots, no proxy, 30 s timeout; errors keep Plaid's code, type and request
  id, never its message), `PlaidService` (the ledger's one `SecretStore`
  behind a mutex; token stored before Plaid is asked anything else;
  `/item/remove` before deleting, token kept when Plaid refuses).
  `ledger_runtime` starts the service under the ledger's lock or does not
  serve the ledger; `RunningLedger::stop` closes it first. `graphql/plaid.rs`: `createPlaidLinkToken`,
  `connectBank`, `disconnectBank` (added to `ADMIN_FIELDS`) and
  `connectedBanks`. `ledger_admin::remove` refuses `BANKS_CONNECTED` from the
  store's names (`SecretStore::stored_names`, no key). `reqwest`, `rustls`,
  `webpki-roots` are new direct dependencies, already compiled in through
  iroh with these features (`Cargo.lock` gains three dependency lines, no
  new crate). README *Bank connections (Plaid)* and three config rows;
  CHANGELOG *Security* and *Added*.
- **Review:** four important findings, all fixed: a connect cut short
  (`http.requestTimeoutSeconds`) could drop the token Plaid had just issued —
  connect and disconnect now run on tasks of their own, and the store lock is
  never held across a Plaid call; `INVALID_ACCESS_TOKEN` was taken for "gone"
  — only `ITEM_NOT_FOUND` is, and a token of another environment than
  `plaid.environment` is refused before it is sent (`PLAID_ENVIRONMENT`);
  Plaid's answers were read uncapped — capped at 1 MiB; a connect finishing
  during a removal could slip a token past the guard — `PlaidService::close`
  waits for connects and disconnects under way and refuses new ones, and
  removal (and every stop) closes first, reopening on a refusal. Nits fixed:
  no redirects and HTTPS only; transport errors with their causes; an empty
  `GL_NODE_SECRETS_KEY` is unset; the description deleted before the token; a
  bank description ignores unknown fields, one bad description no longer
  fails the list, `connectedOn` nullable; store errors reach callers without
  paths; README on a ledger with Plaid turned off but a store left. Deferred
  to step 6: the same bank linked twice (`plan.md` Risks). Clippy:
  `too_many_arguments` on `build_schema_with_access` allowed (precedent in
  `anti_entropy_alpn`).
- **Second review:** no code bugs; the four fixes hold (lock order, RwLock
  fairness, remove against restart checked). Fixed: the removal's close and
  reopen, `RunningLedger::stop`'s close and the disconnect's own task had no
  test — now `a_removal_waits_for_a_connect_and_reopens_on_refusal`,
  `a_restart_waits_for_a_connect_under_way` (a mock behind
  `PlaidEnv::base_url`, which `from_env` never sets) and
  `a_disconnect_cut_short_still_finishes`, PL-R24..R27; README and CHANGELOG
  overclaimed ("never dropped", "no bank left live") — softened, and the
  lost-key / other-account procedure written (Plaid Dashboard, then move
  `secrets.json` aside); the spawned tasks keep the request's `ledger` span;
  the after-failure warning names the item; `close`'s bound (three calls, ~90
  s) in its doc and the README; an id Plaid should not send is
  `PLAID_UNEXPECTED`; the off-node test covers `disconnectBank`. Not pinned:
  deleting the description before the token (a cut-short disconnect is
  retryable either way).
- **Gate:** `scripts/gate.sh` — 1679 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/plaid.json` — 27 of 27 bite;
  `secret_store.json` — 12 of 12 (SS-R6 re-anchored: the read moved into
  `read_store_file`); `users.json` U-R30 and U-R31 re-anchored on the
  multi-line `ADMIN_FIELDS` — 2 of 2 bite.
- **Departures from the plan:** company removal is refused while banks are
  connected instead of removing them itself (a refusal is safe whatever Plaid
  answers); the installer's key file is split off as step 5b; the log half of
  `no_response_carries_the_access_token` is best effort (tracing's global
  interest cache under parallel tests), the response half strict. `plan.md`
  updated.
- **Commit:** —

## 2026-11-13 — The store key on installed servers (step 5b)

- **What changed:** `deploy/install/install.sh` writes
  `/opt/openledger/secrets.env` (0600, root) when there is none: a generated
  `GL_NODE_SECRETS_KEY` (32 bytes from `/dev/urandom`, as the operator key)
  and commented `GL_NODE_PLAID_CLIENT_ID` / `GL_NODE_PLAID_SECRET` lines; an
  existing one is kept. The node's service reads it as a second `env_file`.
  The backup archive names `data`, `settings` and `env` only, so `secrets.env`
  was never in it; a comment there now says why it must stay out. A restore
  puts back `data` only, so a restore on the same server keeps its key. The
  install summary names the file. OPERATIONS: the file in *What it leaves on
  the server*, and *Bank connections (Plaid)* — turning Plaid on for a
  company, keeping a copy of `secrets.env` off the server, restoring onto a
  new server (the file first), the lost-key path, and a forced stop during a
  connect. README *Installing on a server* names the file; CHANGELOG *Added*.
- **Checks:** `bash -n` on the installer and both rehearsal scripts.
  `scripts/rehearse_install.sh` checks the file is `600 root`, holds a
  64-hex key, and that the node's container has it;
  `scripts/rehearse_backup.sh` checks a backup does not hold it. **Not run
  here:** the rehearsals install Docker and pull images inside Lima VMs, which
  leaves loopback (LuLu); run them before relying on this unit. The gate does
  not exercise the installer, so no revert check is added (the installer's
  other mechanisms are pinned by the rehearsals the same way).
  Also unexercised by them: an existing install upgraded onto this installer
  (no `secrets.env`, a one-entry `env_file`) and a rollback to a release
  whose `compose.yml` has none — both read right in review, neither run.
- **Review:** nothing important. Fixed: a restore or rollback moves aside the
  token of a bank connected since its backup or upgrade — OPERATIONS now says
  to disconnect such banks first (restore, rollback, Plaid section); restoring
  onto a new server copies `env` and `secrets.env` into `/opt/openledger/`
  before installing (one order, in both places); `secrets.json` in *What a
  node keeps*; the CHANGELOG's upgrade claim limited to `--version` and
  `--installer`; the `ledger.json` path; an edited `compose.yml` keeps the node
  from reading `secrets.env` (said); an empty `secrets.env` left readable is
  written anew.- **Gate:** `scripts/gate.sh --quick` — fmt, clippy, anchors, guard pass; no
  Rust changed since step 5's full gate (1679 passed, 0 failed, 0 ignored).
- **Departures from the plan:** none.
- **Commit:** —
