# Log: list a ledger's accounts

Status: done (2026-10-21, ready to commit; commit pending).

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-10-21 — The `accounts` query

- **What changed:** a read-only GraphQL query, `accounts`, lists every account
  with an `open`, sorted by name, with `openedOn`, `closedOn` and
  `currencies`, whether or not it holds a posting. It reads
  `AccountState::summaries()` (new, `crates/ledger/src/accounts.rs`), so its
  fields are answers the write rules already give; it carries the reports'
  complexity weight. Files: `crates/ledger/src/accounts.rs`,
  `crates/ledger/src/service/tests/lifecycle.rs`,
  `crates/gl-node/src/graphql/{types,query,mod}.rs`,
  `scripts/revert_specs/list_accounts.json`, README *List Accounts*,
  CHANGELOG *Added*.
- **Gate:** `scripts/gate.sh` — 1634 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/list_accounts.json` — 5 of 5 bite.
- **Review:** the reviewer found an encoding fault (a Perl edit had
  double-encoded every older non-ASCII character of the README and two lines
  of `plan.md`; the README was rebuilt from HEAD plus the new section), a
  gl-node fixture typing a second hand `open` that boot refuses (L-77),
  wording that claimed more than `currencies` and `closedOn` give for a
  transaction dated before a future-dated `open` or `close`, and a
  `Bug-catch:` with no revert (now LA-R5). All fixed before the gate above.
  Left as is: the flat weight whatever the selection, which decision 2
  accepted; the list includes a staged write not yet committed, as
  `journal` does (documented).
- **Departures from the plan:** the quarantine test sits with the ledger's
  boot tests; one gl-node test covers the query and the read role; a test of
  the complexity weight and LA-R5 were added; there is no revert for the bare
  `close` (held by construction) or for reading balances (the design). All
  recorded in `plan.md`'s *Proof*.
- **Commit:** pending.
