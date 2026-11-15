# Plan: Bank-feed inbox (from intent.md, 2026-11-14)

## Files that change
- `crates/gl-node/src/bank_inbox.rs` (new): the inbox file — `bank-inbox.json`
  in the ledger's folder, format version 1, opened node-private like the
  secret store (no symlink, owned by the node, mode 0600), written whole
  through a temp file, fsync and rename; size-capped. Holds waiting
  transactions by Plaid transaction id and the ignored ones (when, by whom,
  why).
- `crates/gl-node/src/plaid.rs`: `PlaidService` opens and holds the ledger's
  one inbox behind a mutex; `Page` also carries Plaid's *modified* posted
  transactions (whole) and *removed* ids; a transaction's Plaid category is
  read as a hint.
- `crates/gl-node/src/graphql/plaid.rs`, `mutation.rs`, `query.rs`:
  `fetchBankTransactions` (admin), `bankInbox` (write),
  `classifyBankTransactions` and `ignoreBankTransactions` (write, a list, a
  result for each); `syncBank` skips transactions the inbox holds or ignored.
- `crates/gl-node/src/access_control.rs`: `WRITE_QUERY_FIELDS` — query
  fields that need a write key (`bankInbox`), beside `ADMIN_FIELDS`.
- `crates/gl-node/src/config.rs`, `plaid_webhook.rs`: `plaid.webhookImport`
  (`"inbox"` default, `"entries"`); a webhook runs the matching fetch.
- README *Bank connections (Plaid)*, OPERATIONS, CHANGELOG; revert specs in
  `scripts/revert_specs/bank_inbox.json`.

## Order of work
1. **The inbox and fetching into it.** `bank_inbox.rs`; `Page`'s modified and
   removed; `fetchBankTransactions(itemId)` → what it added, updated and
   dropped, what was already booked, in the inbox or ignored, the skipped
   counts, `needsReview`, `stoppedBy`; `bankInbox(itemId)` (write);
   `WRITE_QUERY_FIELDS`; `syncBank` skips inbox and ignored transactions.
2. **Booking and ignoring.** `classifyBankTransactions([{transactionId,
   account, payee, narration}])`: under the inbox lock for the whole call,
   the books and mappings read once it is held — refused if not in the inbox, if the books hold its `^plaid-<id>` already (then
   dropped from the inbox), or if its bank account is no longer mapped; else
   one `*` entry (the account's mapping now vs `account`, the inbox's date
   and amount) through `appendTransaction`'s path, `enteredBy` the caller,
   then removed. `ignoreBankTransactions([{transactionId, reason}])`.
3. **Webhooks and docs.** `plaid.webhookImport`; README, OPERATIONS,
   CHANGELOG.

## Risks
- **Two fetches, one cursor** (riskiest). `syncBank` and
  `fetchBankTransactions` share the bank's cursor. Both take the bank's sync
  guard (`begin_sync`: one at a time, `SYNC_IN_PROGRESS`), and each stores a
  page's cursor only once that page is written — to the books or durably to
  the inbox — so a crash between the two fetches the page again, and both
  skip what the books, the inbox or the ignored list hold.
- **Booked twice.** Two bookkeepers classifying one transaction to different
  accounts make entries with different content ids, which the ledger would
  both take. The inbox lock is held from the link check to the removal, and
  `syncBank` checks the inbox under the same lock before it writes.
- **A bad inbox file** stops the ledger's Plaid service from starting (the
  ledger is not served), as a bad secret store does; the log names the file.
  A crash mid-write leaves the old file whole (rename).
- **Growth.** Waiting and ignored transactions are capped; a fetch that would
  pass the cap stops with `stoppedBy` before storing that page's cursor.
- **Nothing replicates:** the inbox is node-local; only booked entries go
  through the ledger. No change to the wire format, signatures or boot order.

## Alternatives rejected
- **The inbox in the secret store:** capped at 1 MiB for a handful of tokens,
  and encrypted where the intent chose plain (decision 5).
- **The inbox in the ledger** (entries with a status): replicates bank data
  to every node and turns an undecided transaction into a record.
- **Booking with the mapping stored at fetch time:** an account remapped
  meanwhile would book to the old account; the mapping at booking time is
  used, and an unmapped account is refused.
- **A per-company mode** (the first draft): the maintainer chose both
  endpoints for every company (decision 2).

## Proof
- Tests (`Bug-catch:` each, revert checks in `bank_inbox.json`): the inbox
  file round-trips and refuses a foreign or oversized file; a fetch fills the
  inbox, leaves the journal unchanged and is not repeated after a restart; a
  modified transaction is updated and a removed one dropped in the inbox; a
  read key cannot list the inbox; classify writes one `*` entry with the
  caller's `enteredBy` and empties its slot, a second classify is refused, a
  bad item does not stop the others; ignore writes nothing and is not
  fetched again; `syncBank` after a fetch writes nothing the inbox holds; a
  webhook fills the inbox, or writes entries with `"entries"`.
- Docs: README (*The bank-feed inbox*), OPERATIONS (the inbox file in the
  ledger folder and backups), CHANGELOG *Added*.
