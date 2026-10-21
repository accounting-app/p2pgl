# Plan: list a ledger's accounts (from intent.md, 2026-10-21)

## Design

**Source: `AccountState`, not the read model.** `LedgerService::accounts()`
holds every `open` and `close` of the served DAG, in the order-insensitive
event model of M-09. Boot builds it from the history it loads, and the
signature quarantine rebuilds it from the DAG it keeps
(`service/quarantine.rs`), so it never holds a quarantined record. The read
model's balances (what `trialBalance` uses) know only accounts with postings.

**Ledger side** — one new method in `crates/ledger/src/accounts.rs`:

```rust
pub struct AccountSummary {
    pub name: String,
    pub opened_on: NaiveDate,          // earliest open (CurrencyIndex::first_open)
    pub closed_on: Option<NaiveDate>,  // date of the last event, when it is a close
    pub currencies: Vec<String>,       // Self::currencies(): the union, empty = any
}
pub fn summaries(&self) -> Vec<AccountSummary> // accounts with an open, sorted by name
```

Each field reuses an answer the write rules already compute (`has_open`,
`currencies`, the last event of `deciding_overall`), so the list cannot drift
from them. `events` is a `HashMap`: the result is sorted by name explicitly.

**API side** — in `crates/gl-node/src/graphql/`:

```graphql
type Account { name: String!  openedOn: Date!  closedOn: Date  currencies: [String!]! }
accounts: [Account!]!
```

The resolver takes the ledger's read lock and maps `summaries()`, like
`account(name:)`. It carries `HEAVY_RESOLVER_COMPLEXITY`, which rations
aliased copies to eight per request (M-45). Per-ledger routes already give
each schema its own `SharedLedger`, so entry 003 needs nothing new.

## Order of work

One commit-sized unit:

1. `AccountSummary` and `summaries()`, with unit tests in `accounts.rs`.
2. The `Account` type and the `accounts` query, with gl-node tests.
3. README (a *List Accounts* section under *Queries*), CHANGELOG (*Added*),
   revert checks, `log.md`.

## Risks

- **Disagreeing with the write rules.** If the list computed "open" or
  "currencies" its own way, it could show an account as open that
  `appendTransaction` refuses. Mitigated by reusing `AccountState`'s own
  methods; the tests pin reopen, union and any-currency cases.
- **T98 inert closes.** `closedOn` is set while a `close` is the last event,
  even when a later posting makes that `close` inert for writes (intent,
  decision 3). Documented in the field's description.
- **Size.** A peer can open many accounts. The weight bounds aliases, not one
  long list; the response grows with the ledger like `journal` without a limit
  does. Accepted: decision 2, no paging.
- **A full dashboard request.** `verify` (2,048) plus the four reports (512
  each) already fill the 4,096 budget, so `accounts` cannot join that one
  request; a client sends it separately. Weighing it lighter would open the
  M-45 alias class on a planted chart of accounts. Accepted, and stated in
  the README and CHANGELOG.
- Nothing here touches replication, boot, signatures or the file format. The
  quarantine test still crosses a restart, since boot is where the
  quarantine is decided.

## Alternatives rejected

- **Rows of `trialBalance`:** misses unused accounts, the case that motivates
  this.
- **Scanning the DAG for `open` directives per request:** a second copy of the
  lifecycle rules that could drift from `AccountState`, and a full scan.
- **Adding opened accounts to the read model:** a second index of what
  `AccountState` already holds.

## Proof

As built (2026-10-21); departures from the draft are marked.

- Each test's doc comment starts with `006:` (the convention of entries
  002–005).
- Ledger, `accounts.rs`: `summaries_list_every_opened_account_sorted_by_name`
  (unposted accounts listed, earliest `open` date, sorted),
  `summaries_show_a_reopened_account_open_and_a_closed_one_closed` (with
  every arrival order of the records giving the same list),
  `summaries_list_the_union_of_currencies`, `summaries_leave_out_a_bare_close`.
- Ledger, `service/tests/lifecycle.rs`:
  `a_quarantined_open_is_not_in_the_chart_of_accounts` — a hand-edited signed
  `open` is quarantined and not listed, at boot and after the compaction
  and restart a starting node goes through.
  *Departure:* planned as a gl-node test; boot decides the quarantine, so it
  sits with the boot tests.
- gl-node, `graphql/mod.rs`: `accounts_lists_every_opened_account_to_a_read_caller`
  — the full query as a read caller, every field, unposted and closed
  accounts included. It types one `open` per account: boot refuses a second
  hand `open` of an open account (L-77). *Departure:* one test for the
  planned query and read-role tests, beside the 002 role tests that build a
  ledger-backed schema.
- gl-node, `graphql/query.rs`: `accounts_is_rationed_like_the_other_reports`
  — eight aliased copies admitted, nine refused. *Added* to pin the weight.
- Revert checks, `scripts/revert_specs/list_accounts.json`, 5 of 5 bite:
  LA-R1 the sort removed; LA-R2 the latest `open`'s list for the union;
  LA-R3 `closed_on` from any `close`; LA-R4 the complexity weight removed;
  LA-R5 the quarantine's rebuild keeping the old account state (added on
  review).
  *Departures:* no check for the bare `close` — the list is read off the
  currency index, which only an `open` creates, so there is no filter to
  undo (its test pins it); none for building the list from balances, which
  is the design and not a switch — the gl-node test pins it.
- Docs: README *Queries → List Accounts*; CHANGELOG *Added*.
