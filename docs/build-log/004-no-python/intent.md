# Intent: no Python in the repo

Author: Claude, with the maintainer. Status: **approved** (2026-10-15).

## Problem

Three tools are Python: `scripts/revert_check.py` (the revert checks every unit
relies on), `scripts/measure_ledgers.py` (003's measurements) and
`.claude/hooks/guard_git.py` (the hook that keeps staging, committing and
pushing the maintainer's). The maintainer does not want Python in the project:
one more language and runtime to keep, outside the toolchain everything else
uses.

## Proposed outcome

- **The revert checks and the measurements are Rust**, in a small workspace
  crate, `xtask`: `cargo xtask revert-check …` and `cargo xtask
  measure-ledgers …`, with `scripts/revert_check.sh` and
  `scripts/measure_ledgers.sh` running them, so the commands read as before.
- **The git guard is a shell hook**, `.claude/hooks/guard_git.sh`, blocking
  exactly what the Python one blocks and nothing it lets through.
- **No `.py` file is left**, and the docs, CLAUDE.md and the verifier agent name
  the new commands.

## Who it is for

The maintainer, and every unit after this one (the revert checks and the guard
run in each).

## Constraints

- The revert-spec format is unchanged: every file in `scripts/revert_specs/`
  works as it is, and each check gives the verdict it gives today.
- The revert checks still never touch the repo: they work on a scratch copy.
- The guard fails closed: input it cannot read is refused, never waved through.
- Nothing ships differently: `xtask` is a tool, never part of the release
  binary.

## How we will know it worked

- Every revert check in every spec file bites with the Rust tool, as with the
  Python one.
- The shell guard and the Python guard give the same verdict on a list of
  commands covering every form the guard is documented to block or allow; the
  list stays, as a test the gate runs.
- `cargo xtask measure-ledgers` reproduces 003's measurements.
- `git ls-files '*.py'` is empty.

## Decisions (maintainer, 2026-10-15)

1. The two scripts become a Rust `xtask` crate with `.sh` wrappers.
2. The git guard becomes plain `.sh`, tested against the Python one first.
3. This is done now, before 003 step 4.

## Not in this work

- Any change to what the revert checks or the guard decide.
- Other tooling (the `.sh` scripts that exist stay as they are).
