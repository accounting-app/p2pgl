# Build log

Every piece of work bigger than a one-line fix gets an entry here: why it is
being built, how, and how each step went. The entry is written before any code
and committed with it, so the history of the code can be read alongside the
reasons for it. Security findings keep their own trackers in `docs/audits/`.

## Layout

```
docs/build-log/
├── README.md            this file: the flow, the layout, the index below
├── _templates/          intent.md, plan.md, log.md
└── NNN-short-name/      one folder per piece of work, e.g. 001-peer-discovery/
    ├── intent.md        what and why
    ├── plan.md          how
    ├── log.md           one entry per commit-sized unit
    └── notes/           optional: research the plan relies on
```

Folders are numbered with three digits in the order the work starts, and never
renumbered; a dropped piece of work keeps its folder with its reason in
`log.md`. Copy the files from `_templates/` to start one.

## The flow: intent → plan → code → log

1. **`intent.md`** — what problem, for whom, and how we will know it worked.
   Written in plain language with Claude from a conversation; the maintainer
   corrects it and approves it (its status line then reads *approved* with the
   date).
2. **`plan.md`** — how: the files that change, the order of work, the risks,
   and the tests (and revert checks) that will prove it. Claude drafts it from
   the intent; the maintainer questions it ("what could break? which step is
   riskiest? what did you reject?") until someone new could build from it.
3. **Code**, as one or more commit-sized units, each passing `scripts/gate.sh`
   with its revert checks. If the work departs from the plan, `plan.md` is
   updated in the same unit, so the code and the plan agree.
4. **`log.md`** — each unit adds an entry when it is ready to commit: what
   changed, the gate result, the revert checks, any departure from the plan,
   and the commit hash once the maintainer has committed.

**`notes/`** holds what the plan was built on and someone later would want to
check: a library's API as read at the time, a measurement, a spike's result.

Keep `intent.md` and `plan.md` to about a page each. A change too small to need
them (a typo, a one-line fix) gets no entry.

## Index

| # | Work | Status |
|---|---|---|
| [001](001-peer-discovery/) | Peer discovery without a third party: own relay + direct addresses | done (d84083a) |
| [002](002-users-and-roles/) | People, keys and roles: a key per person, admin / write / read, who entered each write | done (4 of 4, cd51455) |
| [003](003-multi-ledger-node/) | Several company ledgers on one node, isolated, added at runtime | step 4 of 5 (add and remove at runtime) in progress |
| [004](004-no-python/) | No Python in the repo: revert checks and measurements in Rust, the git guard in shell | done (aa0415b) |
| — | Relay with a company's own certificate authority (`relayCaCert`) | planned (decision C, 2026-10-09) |
