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
- **Commit:** —
