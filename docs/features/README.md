# Features: intent → plan → code

Each feature gets a folder `docs/features/<short-name>/` with two short files,
written before any code and committed with it:

1. **`intent.md`** — what problem, for whom, and how we will know it worked.
   Written in plain language with Claude from a conversation; the maintainer
   corrects it and approves it. Template: [`TEMPLATE-intent.md`](TEMPLATE-intent.md).
2. **`plan.md`** — how: the files that change, the order of work, the risks,
   and the tests (and revert checks) that will prove it. Claude drafts it in
   plan mode from the intent; the maintainer questions it ("what could break?
   which step is riskiest? what did you reject?") until someone new could build
   from it. Template: [`TEMPLATE-plan.md`](TEMPLATE-plan.md).

Then Claude implements the plan as one or more commit-sized units, each passing
`scripts/gate.sh` with its revert checks. If the work departs from the plan,
`plan.md` is updated in the same unit, so the merged code and the plan agree.

Keep both files to a page. A change too small to need either (a typo, a
one-line fix) does not get a folder. Security findings keep their own
trackers in `docs/audits/`.
