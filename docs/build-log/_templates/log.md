# Log: <feature name>

Status: in progress | done (<date>, last commit <hash>).

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## <date> — <unit title>

- **What changed:** the behaviour, in a sentence or two; the files.
- **Gate:** `scripts/gate.sh` — N passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/<file>.json` — n of n bite.
- **Departures from the plan:** none, or what changed and why (`plan.md`
  updated in the same unit).
- **Commit:** <hash>
