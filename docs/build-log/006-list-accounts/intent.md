# Intent: list a ledger's accounts

Author: Claude, with the maintainer. Status: **approved** (2026-10-21).

## Problem

The API cannot say which accounts a ledger has. `account(name:)` answers for
one account the caller already knows, and `trialBalance` lists only accounts
that hold a posting — an account opened and not yet used, which is every
account of a new company, is invisible. A client building an account picker, a
chart of accounts, or a check before posting has to read the `.bean` file by
hand or guess names until `openAccount` stops refusing them.

## Proposed outcome

- **One query returns every account of the ledger**, sorted by name, whether
  or not it has postings: `{ accounts { name openedOn closedOn currencies } }`.
- For each account: its name, the date of its earliest `open`, the date of its
  `close` when the account is closed now (its last lifecycle record is a
  `close`), and the currencies a transaction dated on or after its latest
  `open` may use (empty = any).
- **The answer is the same on every node of a mesh** holding the same records,
  whatever order they arrived in, and it never names an account whose only
  `open` is quarantined or not served.
- On a node with several ledgers (entry 003), each ledger's route lists its own
  accounts and no other's.

## Who it is for

Clients of the API: a web UI or script that needs the chart of accounts, an
accountant setting up a company, and anyone at a terminal or in Insomnia
checking what exists before posting.

## Constraints

- Read-only. No change to records, the file format, the wire format, the DAG
  or replication; nothing a peer sees changes.
- The figures come from the state the write rules already use (the account
  lifecycle model, M-09 / T91 / T97 / T98), so the list cannot disagree with
  what `openAccount`, `closeAccount` and `appendTransaction` accept.
- A **read** key may call it (deny by default puts every query at read; entry
  002). It reveals nothing a read key cannot already reach through the journal.
- It must not become a cheap way to pin the CPU through aliases (M-45): it
  carries a complexity weight like the other report queries.

## How we will know it worked

- A new ledger with four `open`s and no transactions lists all four.
- An account opened, closed and opened again lists as open, with no
  `closedOn`; one opened then closed lists its `closedOn`.
- An account opened twice with `USD` and then `EUR` lists both currencies; one
  `open` with no list makes it list none (any currency).
- Two nodes fed the same records in different orders return identical lists.
- An `open` boot quarantined does not appear, before and after a restart.
- A read key gets the list; a request without a key is refused as today.

## Decisions (maintainer, 2026-10-21)

The three open questions of the draft, each settled as proposed:

1. **A `close` with no `open`** (a peer's or a hand-typed bare `close`) is
   left out of the list: it names no account a transaction can use.
2. **No paging.** `accounts` returns every account; a chart of accounts is
   small, and a picker wants all of it.
3. **"Closed" under T98.** `closedOn` reports the record as it stands: the
   date of the account's last lifecycle record when that is a `close`, even
   when a posting dated after it makes it inert for this node's writes. The
   field's description says so. A field for "this node will accept a write
   dated D" is left for later.
