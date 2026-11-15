# Log: Bank-feed inbox

Status: done (2026-11-15, last commit fcec9e2).

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
- **Commit:** 25bfc1d

## 2026-11-15 — Booking and ignoring (unit 2)

- **What changed:** `graphql/bank_inbox.rs`: `classifyBankTransactions(items:
  [{transactionId, account, payee, narration}])` and
  `ignoreBankTransactions(items: [{transactionId, reason}])`, a write key
  (mutations' default), up to 200 a call, each item done or refused on its
  own (`BankBooking { transactionId ok txid code message }`). Classifying,
  under the inbox lock from the check to the removal: refused when not
  waiting (`NOT_IN_INBOX`; ignored: `BANK_TRANSACTION_IGNORED`), when the
  books hold its link — read once a call, plus the bookings since (`booked_lately`)
  — (`ALREADY_BOOKED`, and it leaves the inbox), when its bank account is
  not mapped now (`ACCOUNT_NOT_MAPPED`), or for the bank's own account
  (`INVALID_INPUT`); else one entry through `appendTransaction`'s path —
  the mapping now with the inbox's amount, `account` elided, flag `*`, link
  `^plaid-<id>`, the caller's `enteredBy`, Plaid's payee and description
  unless given (empty leaves out) — then `note_booked` and removal; a ledger
  refusal leaves it waiting. Ignoring moves it to `ignored` with the caller,
  time and reason (500 characters, no control characters). The unit-1
  dead-code allowance on `note_booked` is gone. README *Booking from the
  inbox*, CHANGELOG *Added*.
- **Tests:** `classifying_books_one_entry_and_empties_its_slot`,
  `a_bad_item_does_not_stop_the_others`,
  `an_ignored_transaction_is_gone_for_good`,
  `what_the_books_hold_is_not_booked_again`,
  `one_transaction_twice_in_a_call_is_booked_once`,
  `a_transaction_booked_while_a_fetch_runs_is_not_fetched_back`,
  `booking_checks_the_mapping_and_the_text`.
- **Review:** one important finding, fixed. A classify call took the inbox
  per item but read the books once, before it: a call cut short by the
  request timeout after its entry was staged (H-11 commits it detached) left
  the transaction booked and still waiting, unknown to `booked_lately`, and
  a second bookkeeper's call that had read the books earlier would book it
  again under another account. Now a call holds the inbox for its whole list
  and reads the books and the mappings only once it does, so a call after a
  cut-short one finds the entry and drops the transaction; the transactions
  booked leave the inbox in one write at the end, and an ignore call writes
  the inbox once (it rewrote the file per item). Also: an append that finds
  the very entry in the books answers `ALREADY_BOOKED` with its txid, not a
  new booking; README lists `LEDGER_BUSY`, the reason's control characters,
  the 200 cap refused whole, and that calls take turns on the inbox; a test
  pins `booked_lately` against a fetch running while a booking is made (the
  mock delays Plaid's answer), and one the mapping and text checks. Left:
  an `unmapBankAccount` during a call still books to the mapping read at the
  call's start; the inbox writes are blocking file I/O on the async runtime,
  as the secret store's are; `syncBank`'s own `booked_lately` check has no
  test.
- **Gate:** `scripts/gate.sh` — passed (fmt, clippy, anchors, guard; 1754
  tests passed, 0 failed).
- **Revert checks:** `scripts/revert_specs/bank_inbox.json` BI-R17..R26 — 10
  of 10 bite (R17, R18, R19, R24 re-anchored after the rewrite; R25, R26
  new).
- **Departures from the plan:** the inbox is held for a whole call rather
  than per item (the review's finding); `plan.md` updated.
- **Commit:** 58901f0

## 2026-11-15 — Webhooks fill the inbox (unit 3)

- **What changed:** `plaid.webhookImport` (`config.rs`, `WebhookImport`:
  `"inbox"` the default, `"entries"`), kept by `PlaidService`
  (`webhook_import`). `plaid_webhook::sync` runs `fetchBankTransactions` for
  `inbox` and `syncBank` for `entries`, as the operator through the ledger's
  schema as before (same queueing, same retry while one runs). Test
  fixtures take a Plaid config (`fixture_with`, `mapped_with`). The
  descriptions of `createPlaidLinkToken` and `lastNotice` say to pass the
  update-mode public token to `connectBank` (left from 007 step 6d). README
  (config row, *Webhooks* table, the inbox section), CHANGELOG *Added*.
- **Tests:** `a_webhook_fills_the_inbox_by_default`;
  `a_webhook_syncs_the_bank_on_its_own` now runs with `"entries"`;
  `a_ledgers_plaid_section_is_checked` takes `webhookImport`.
- **Review:** nothing important. The CHANGELOG had a *Breaking* entry for
  the webhook default, but webhooks were never released (they came after
  v0.3.0): the 007 step 6d entry now says what the webhook does, and the
  *Breaking* entry is gone. The README says a full inbox stops webhook
  fetches quietly (watch `bankInbox { total }`); `fireSandboxWebhook` and
  the webhook log line say "fetch". OPERATIONS has no webhook text, so the
  plan's mention of it needed nothing. Left: a full inbox shows in the log
  only, not in `connectedBanks`.
- **Gate:** `scripts/gate.sh` — passed (fmt, clippy, anchors, guard; 1755
  tests passed, 0 failed); a first run failed fmt on an unformatted test
  edit, fixed.
- **Revert checks:** `scripts/revert_specs/bank_inbox.json` BI-R27, R28 — 2 of
  2 bite; `plaid.json` PL-R85 and PL-R90 (on the `"entries"` test) still
  bite.
- **Departures from the plan:** none.
- **Commit:** fcec9e2 (with 007 step 6f)
