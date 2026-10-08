# Review instructions

How Claude reviews a change in this repo — usually the uncommitted working
tree, before the maintainer commits (the `reviewer` subagent, or `/code-review`).
Findings advise; the maintainer decides what to fix and commits.

## Passes

Run three passes over the diff and the code it touches:

1. **Bugs** — logic errors, broken edge cases, regressions. In this codebase
   look hardest at:
   - order dependence: does every replica, every arrival order and every
     restart reach the same records, balances and file bytes?
   - boot and reconcile: is a record held back, kept in the file, and counted
     in the clock exactly as before? Does anything get dropped by a compaction?
   - the lamport clock, signatures and content ids: does any path compute them
     differently from the others (wire, file, API, boot)?
2. **Security** — the audit rules still hold: input bounded before it is
   buffered, nothing secret logged (keys, the swarm topic), files opened through
   the checked helpers, peers allowlisted, refusals fail closed. A change to a
   guard named after a finding (`H-xx`, `M-xx`, `L-xx`) needs its revert check
   to still fail its test.
3. **Compliance** — matches `docs/build-log/NNN-<name>/plan.md` (or the tracker task
   it implements) and `CLAUDE.md`: tests carry `Bug-catch:`, each new mechanism
   has a revert spec, README and CHANGELOG describe any behaviour change, network
   tests stay on loopback.

## What "Important" means

Reserve it for findings that break behaviour, lose or misstate ledger data,
split replicas, leak a secret, or breach an audit rule. Style and naming are
nits.

## Cap the nits

At most five nits per review; summarise the rest as a count.

## Do not report

- Anything `scripts/gate.sh` already enforces (formatting, clippy lints,
  failing tests — say only whether the gate was run and passed).
- The dated audit reports in `docs/audits/SECURITY_AUDIT_*.md` (records, not
  code), and `Cargo.lock` churn that matches a `Cargo.toml` change.
