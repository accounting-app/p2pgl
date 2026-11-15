# Intent: Bank-feed inbox

Author: Hector Garcia, with Claude. Status: approved (2026-11-14).

## Problem
A bank sync (007 step 6) writes every new transaction straight into the
books, flagged `!`, against one suspense account (`Expenses:Uncategorized`,
a "to be decided" account); the bookkeeper then edits each entry. Accountants
want to see what the bank sent and decide how each transaction is booked
before anything is written — and the endpoint they use must never fetch and
write in one go.

## Proposed outcome
Fetching and booking are two steps, done by different people:

- **Fetching into the inbox** — `fetchBankTransactions(itemId)` (an admin) or
  a Plaid webhook (automatic) puts a company's new posted bank transactions in
  its **inbox**. Nothing is written to the books.
- **Booking** — a bookkeeper lists the inbox (`bankInbox`) and classifies
  transactions, one or many in a call (`classifyBankTransactions`): each to
  one ledger account, with the payee and narration they want. Only then is an
  entry written — the bank's ledger account against that account, flag `*`,
  link `^plaid-<transaction id>`, entered by that person — and the
  transaction leaves the inbox. A transaction the books hold some other way
  (a transfer entered by hand) can be **ignored** instead: it leaves the inbox
  with an optional reason, kept for the record, and nothing is written.
- **Fetching and writing at once stays** — `syncBank` (admin only) works as
  today: `!` entries against the suspense account.

Decided with the maintainer (2026-11-14):

1. **The write role books.** `bankInbox`, classifying and ignoring need a
   write key (bookkeepers); connecting banks, mapping accounts and both fetches
   stay admin or automatic. A read key sees nothing of the inbox.
2. **Both endpoints, always.** `syncBank` and `fetchBankTransactions` both
   exist for every company. They share Plaid's place-marker for a bank, so
   each new transaction goes to whichever runs first — into the books or into
   the inbox — never both. Webhooks fill the inbox, unless the company sets
   `plaid.webhookImport` to `"entries"`, when they run `syncBank`'s import.
   Entries imported so far stay as they are.
3. **One account per transaction** in the first version, plus **ignore**.
   Splitting a transaction across accounts and matching it to an entry
   already in the books come later.
4. **Several at once:** one call classifies or ignores a list; each
   transaction succeeds or fails on its own, with a result for each.
5. **The inbox lives on the bank node only** — the node that holds the
   company's banks, which the client app calls — in a plain file the node
   alone can read, backed up like the `.bean` (which holds the same data once
   booked). It is not part of the ledger and does not replicate; a
   transaction reaches other nodes only once it is booked.

Proposed (the maintainer to confirm): only **posted** transactions enter the
inbox, as today (007 decision 8), and only for **mapped** accounts from their
`importFrom` on. A transaction Plaid changes or removes while still in the
inbox is updated or dropped there; one already booked is reported for review,
never changed by the node. Plaid's own category is shown as a hint, never
used to book.

## Who it is for
Bookkeepers and accountants, through the client app with their write key; the
operator (admin) who connects banks, maps accounts and fetches; Plaid's
webhooks.

## Constraints
- Every entry goes through the ledger's usual write path and checks
  (`appendTransaction`).
- No transaction is booked twice: classifying refuses one whose
  `^plaid-<id>` the books already hold, and both fetches skip those.
- 007's rules stand: the bank node alone holds tokens and calls Plaid; no raw
  Plaid response is kept; the inbox keeps only the fields it shows.
- `syncBank` behaves exactly as today; its tests pass unchanged.

## How we will know it worked
- `fetchBankTransactions` returns what it added to the inbox, and the journal
  is unchanged.
- `bankInbox` (write key) lists those transactions; a read key is refused.
- `classifyBankTransactions` writes one `*` entry per transaction with the
  person's `enteredBy`, each leaving the inbox; classifying one again is
  refused; one bad item in a list does not stop the others.
- An ignored transaction leaves the inbox, writes nothing, and is not fetched
  again.
- A fetch after a restart adds nothing already in the inbox, ignored or
  booked; `syncBank` after a fetch writes nothing the inbox holds.
- A webhook fills the inbox; with `plaid.webhookImport: "entries"` it writes
  entries as in 007 step 6d.

## Open questions
None left for the intent; the plan says how Plaid's place-marker is shared
safely between the two fetches, and the inbox file's format and limits.
