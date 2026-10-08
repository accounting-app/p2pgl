# openledger-v2

A peer-to-peer double-entry ledger in Rust. Crates: `ledger` (Beancount
parsing, the DAG, boot and file reconcile, accounts and reports), `p2p` (wire
protocol, union merge, orphan buffer), `gl-node` (the node binary: GraphQL over
HTTP, iroh P2P, config), `security` (signing). Design and audit history live in
`docs/` and `docs/audits/`.

## Commands

- `scripts/gate.sh` — fmt check, clippy `-D warnings`, every test. The bar for
  "ready to commit". `--quick` skips the tests. Logs in `target/gate/`.
- `cargo test -p ledger --lib -- <filter>`, `cargo test -p gl-node --bin gl-node -- <filter>`,
  `cargo test -p p2p --test <file> -- <filter>` — one test or area.
- `scripts/revert_check.py scripts/revert_specs/<file>.json [NAME…]` — revert
  checks (below). `--check` validates anchors without building.
- `crates/gl-node/tests/shipped_binary.rs` starts the built binary and drives
  it over loopback HTTP; with `GL_NODE_PREVIOUS_BINARY` it also rehearses an
  upgrade and rollback. `scripts/release.sh` builds and checks a release of the
  committed tree (`docs/RELEASE.md`); operators follow `docs/OPERATIONS.md`.
- The `verifier` subagent runs the gate and revert checks and only reports; the
  `reviewer` subagent reviews the uncommitted diff against `REVIEW.md`. Both run
  before "ready to commit".
- A feature starts as `docs/features/<name>/intent.md` then `plan.md`
  (templates and the flow in `docs/features/README.md`), before any code.
- `.github/workflows/weekly-health.yml` runs the gate and `cargo audit` every
  Monday and opens an issue on failure.

## Working agreement

- **Only the maintainer stages, commits and pushes.** Never run `git add`,
  `git mv`, `git rm`, `git commit` or `git push` (a hook denies them all).
  Move or delete files with plain `mv`/`rm`. Finish a unit,
  say plainly that it is ready to commit and what is in it, then stop. Do not
  start the next unit on top of uncommitted work.
- One commit-sized unit at a time. Before "ready": `scripts/gate.sh` passes,
  each new mechanism has a revert check that bites, and the docs are updated.
- Report failures with their output. If something is not ready, say so.

## Conventions

- Comments and test names carry finding and task IDs (`H-01`, `M-74`, `L-23`,
  `T98`, decision `(54)`). Trackers (`docs/audits/OUTSTANDING_TASKS*.md`) are
  living documents; the dated reports (`docs/audits/SECURITY_AUDIT_*.md`) are
  records — add to them only when asked (a hook asks first).
- A new test's doc comment ends with `Bug-catch:` — the revert it catches. Add
  that revert to a file in `scripts/revert_specs/`.
- A behaviour change updates the README and the CHANGELOG (*Breaking*,
  *Added*, *Security*) in the same unit.
- Network tests build endpoints with `loopback_endpoint_builder()` and dial
  `loopback_addr(&endpoint)` (gl-node `anti_entropy_alpn` tests) — never
  `endpoint.addr()` or a default builder. The dev machine runs LuLu, an
  outbound firewall whose prompts stall anything that leaves loopback.
- Record formats: the `ledger` library defaults to v1; `gl-node`'s config
  defaults to Format v2 (`format.wire2`, `format.idv2`).
- Hooks rustfmt `.rs` files edited with Edit/Write. Files changed from Bash
  or a script are not formatted: run `cargo fmt --all`.

## Revert checks

A check undoes one mechanism in a scratch copy and runs the tests meant to catch
it. If nothing fails, look for a second check covering the same case before
calling the mechanism unpinned. Known overlaps: T98 R4 (`unservable_history` and
the copy chooser both apply the data rule) and LH-R6 (boot's fragment check and
the served-set rule). Anchors must match rustfmt'ed code exactly once.

## Things Claude gets wrong here

- `cargo test … | head` stops the run when `head` exits. Redirect to a file
  and grep it.
- `cargo test --workspace -p X` runs the whole workspace, not X.
- zsh aborts a command on a glob that matches nothing (`rm -f ledger.bean*`).
- Do not run a smoke test or a second build while the gate runs; the QUIC
  tests' time limits fail on a loaded machine.
