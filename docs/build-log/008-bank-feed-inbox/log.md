# Log: Bank-feed inbox

Status: in progress.

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-11-14 — The inbox and fetching into it (unit 1)

- **What changed:** new `crates/gl-node/src/bank_inbox.rs` — the inbox file
  `bank-inbox.json` in the ledger's folder (version 1, node-private, written
  whole through temp file, fsync and rename; 20,000 waiting and 50,000
  ignored at most, a change past the cap refused and changing nothing), plus
  the bookings since start kept in memory (`booked_lately`) for a fetch that
  read the books before them. `plaid.rs`: `PlaidService` opens the ledger's
  one inbox at start (a bad file and the ledger is not served, as for the
  secret store) and lends it through `open_inbox` with the `closed` gate held
  open; `Page` carries Plaid's modified posted transactions whole and the
  removed ids; Plaid's `personal_finance_category.primary` read as a hint;
  `PlaidError::Inbox` (`BANK_INBOX`, `BANK_INBOX_FULL`). New
  `graphql/bank_inbox.rs`: `fetchBankTransactions(itemId)` (admin) — under
  the bank's sync guard, page by page, the inbox written before the page's
  cursor is stored; skips what the books, the inbox (waiting or ignored) or
  a booking since the fetch began hold; takes Plaid's changes to what still
  waits, drops what Plaid removed, reports changes to what is booked —
  and `bankInbox(itemId, first, offset)` (write). `access_control.rs`:
  `WRITE_QUERY_FIELDS` (`bankInbox`). `syncBank` checks the inbox under its
  lock before each entry and leaves what it holds (`inInbox`). README *The
  bank-feed inbox*, OPERATIONS (the file in the ledger folder, backups),
  CHANGELOG *Added*.
- **Tests:** `the_inbox_survives_a_reopen`,
  `a_foreign_file_or_a_full_inbox_is_refused`,
  `the_bank_inbox_needs_a_write_key`,
  `a_fetch_fills_the_inbox_and_writes_nothing`,
  `plaids_changes_reach_what_still_waits`,
  `the_inbox_is_a_bookkeepers_and_fetching_an_admins`,
  `sync_bank_leaves_the_inbox_alone`,
  `sync_bank_takes_plaids_changes_to_what_waits`,
  `a_transaction_sent_again_is_taken_as_it_is_now`,
  `a_page_is_not_passed_until_the_inbox_holds_it`.
- **Review:** two important findings, fixed. (1) `syncBank` read Plaid's
  corrections and removals of transactions waiting in the inbox and stored
  the page's cursor without taking them — the bookkeeper would book what the
  bank had corrected or reversed: `InboxContents::take_plaid_changes`, used by
  both fetches, `syncBank` before it stores the cursor. (2) A transaction
  Plaid sends again with other values (a restart of its pages) was skipped
  without a look: one waiting is taken as it is now, and one booked is
  compared with the books, a difference reported as `syncBank` does. Also:
  `disconnectBank` drops the bank's waiting transactions; the role table and
  the access-control doc name the inbox; the README says a full inbox gives
  `BANK_INBOX_FULL` or, once a page was stored, `stoppedBy`; OPERATIONS says
  what to do when the inbox file cannot be read; `SYNC_IN_PROGRESS` says
  "synced or fetched"; 007's step 6e commit filled in. Found while adding
  the checks: a fetch took Plaid's changes after adding the page's new
  transactions, so a wrong sign on insert was mended by the same page — the
  changes are now taken first, and the insert is the one place a new
  transaction is written. Left: a modified transaction without a currency,
  or one that no longer reads, leaves the waiting one unchanged without a
  note; the temp-file sweep and `failed()`'s hiding of file paths have no
  test of their own (as in the secret store).
- **Gate:** `scripts/gate.sh` — passed (fmt, clippy, anchors, guard; 1747
  tests passed, 0 failed).
- **Revert checks:** `scripts/revert_specs/bank_inbox.json` BI-R1..R16 — 16
  of 16 bite (BI-R5, R6 re-anchored when the change-taking moved into
  `take_plaid_changes`; BI-R13 first used `false && a || b`, which did not
  switch the check off). 407 anchors in 17 files, each once.
- **Departures from the plan:** `booked_lately` (in memory) added: a fetch or
  `syncBank` reads the books once at its start, so a transaction booked from
  the inbox while it runs, and sent again by Plaid, would otherwise be taken
  a second time. `note_booked` waits for unit 2 (booking), with a dead-code
  allowance until then.
- **Commit:** —
