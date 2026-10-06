# Plan: <feature name> (from intent.md, <date>)

## Files that change
crates/…, README.md, CHANGELOG.md, …

## Order of work
1. … (each step a commit-sized unit that passes `scripts/gate.sh`)
2. …

## Risks
What could break, which step is riskiest, and why. Note anything that touches
replication, boot, signatures or the file format — those need a test across a
restart and across two nodes.

## Alternatives rejected
What else was considered, and why not.

## Proof
- Tests that show it works (names, what each asserts).
- Revert checks to add to `scripts/revert_specs/` (what is reverted, which test
  must then fail).
- Docs: README sections, CHANGELOG entries.
