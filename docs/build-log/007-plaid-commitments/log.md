# Log: keep what we told Plaid

Status: in progress.

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-11-10 — The secret store (step 3)

- **What changed:** `crates/gl-node/src/secret_store.rs`, a per-ledger
  encrypted store for values that never leave the node (Plaid access tokens
  from step 5). `secrets.json` in the ledger folder, opened through
  `open_checked` as `NodePrivate` (no symlink, owner, one link, 0600) and
  written through a fresh node-private temp file, fsync and rename. Each value
  is sealed with AES-256-GCM under `GL_NODE_SECRETS_KEY` (64 hex characters),
  with associated data binding it to its name (not the ledger: a removed
  ledger moved back under a new name keeps its store); `open` deletes temp
  files a crashed write left, then opens every value, so a wrong key or a
  moved value is refused there; writes refuse a file larger than `open`
  reads. `Secret` and `StoreKey` print `[redacted]`.
  `access_list::random_bytes` is now `pub(crate)`, the one random source for
  nonces. `aes-gcm` 0.10 is a new
  direct dependency of gl-node, already compiled in through iroh
  (`Cargo.lock` gains two dependency lines, no new crate). Intent approved
  with the maintainer's decisions; `plan.md` updated for them.
- **Not user-visible yet:** nothing calls the store until step 5, which wires
  the key into boot and the installer — so no README or CHANGELOG entry in
  this unit, and the module carries `#![allow(dead_code)]` until then.
- **Gate:** `scripts/gate.sh` — 1656 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/secret_store.json` — 12 of 12 bite.
- **Review:** no important findings. Fixed: binding values to the ledger's
  name would strand a removed ledger moved back under a new name (now bound
  to the name only, SS-R2 inverted); a crashed write's temp file outlived
  removals (now swept at open, SS-R9); no write-side size cap (SS-R10); the
  associated-data prefix renamed `openledger/secret-store/v1` before any
  store exists; distinct `Seal` and `TooLarge` errors, temp-file errors name
  the temp file; the `random_bytes` doc; revert checks for the round trip,
  version and name checks. Noted for step 5 in `plan.md` Risks: one store
  instance per ledger.
- **Departures from the plan:** the ledger binding above (`plan.md` updated).
- **Commit:** e331ebd

## 2026-11-13 — Plaid connect and disconnect, in the node (step 5)

- **What changed:** bank connections through Plaid on the one node per
  company with `plaid.enabled` (new `PlaidConfig` in a ledger's config:
  `enabled`, `environment` — `sandbox` or `production`, never an address —
  and `clientName`). `crates/gl-node/src/plaid.rs`: `PlaidEnv` (credentials
  and store key from `GL_NODE_PLAID_CLIENT_ID`, `GL_NODE_PLAID_SECRET`,
  `GL_NODE_SECRETS_KEY`, read once in `main`; a half-set pair or a bad key
  stops the node), `PlaidClient` (reqwest on rustls/ring with Mozilla's
  roots, no proxy, 30 s timeout; errors keep Plaid's code, type and request
  id, never its message), `PlaidService` (the ledger's one `SecretStore`
  behind a mutex; token stored before Plaid is asked anything else;
  `/item/remove` before deleting, token kept when Plaid refuses).
  `ledger_runtime` starts the service under the ledger's lock or does not
  serve the ledger; `RunningLedger::stop` closes it first. `graphql/plaid.rs`: `createPlaidLinkToken`,
  `connectBank`, `disconnectBank` (added to `ADMIN_FIELDS`) and
  `connectedBanks`. `ledger_admin::remove` refuses `BANKS_CONNECTED` from the
  store's names (`SecretStore::stored_names`, no key). `reqwest`, `rustls`,
  `webpki-roots` are new direct dependencies, already compiled in through
  iroh with these features (`Cargo.lock` gains three dependency lines, no
  new crate). README *Bank connections (Plaid)* and three config rows;
  CHANGELOG *Security* and *Added*.
- **Review:** four important findings, all fixed: a connect cut short
  (`http.requestTimeoutSeconds`) could drop the token Plaid had just issued —
  connect and disconnect now run on tasks of their own, and the store lock is
  never held across a Plaid call; `INVALID_ACCESS_TOKEN` was taken for "gone"
  — only `ITEM_NOT_FOUND` is, and a token of another environment than
  `plaid.environment` is refused before it is sent (`PLAID_ENVIRONMENT`);
  Plaid's answers were read uncapped — capped at 1 MiB; a connect finishing
  during a removal could slip a token past the guard — `PlaidService::close`
  waits for connects and disconnects under way and refuses new ones, and
  removal (and every stop) closes first, reopening on a refusal. Nits fixed:
  no redirects and HTTPS only; transport errors with their causes; an empty
  `GL_NODE_SECRETS_KEY` is unset; the description deleted before the token; a
  bank description ignores unknown fields, one bad description no longer
  fails the list, `connectedOn` nullable; store errors reach callers without
  paths; README on a ledger with Plaid turned off but a store left. Deferred
  to step 6: the same bank linked twice (`plan.md` Risks). Clippy:
  `too_many_arguments` on `build_schema_with_access` allowed (precedent in
  `anti_entropy_alpn`).
- **Second review:** no code bugs; the four fixes hold (lock order, RwLock
  fairness, remove against restart checked). Fixed: the removal's close and
  reopen, `RunningLedger::stop`'s close and the disconnect's own task had no
  test — now `a_removal_waits_for_a_connect_and_reopens_on_refusal`,
  `a_restart_waits_for_a_connect_under_way` (a mock behind
  `PlaidEnv::base_url`, which `from_env` never sets) and
  `a_disconnect_cut_short_still_finishes`, PL-R24..R27; README and CHANGELOG
  overclaimed ("never dropped", "no bank left live") — softened, and the
  lost-key / other-account procedure written (Plaid Dashboard, then move
  `secrets.json` aside); the spawned tasks keep the request's `ledger` span;
  the after-failure warning names the item; `close`'s bound (three calls, ~90
  s) in its doc and the README; an id Plaid should not send is
  `PLAID_UNEXPECTED`; the off-node test covers `disconnectBank`. Not pinned:
  deleting the description before the token (a cut-short disconnect is
  retryable either way).
- **Gate:** `scripts/gate.sh` — 1679 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/plaid.json` — 27 of 27 bite;
  `secret_store.json` — 12 of 12 (SS-R6 re-anchored: the read moved into
  `read_store_file`); `users.json` U-R30 and U-R31 re-anchored on the
  multi-line `ADMIN_FIELDS` — 2 of 2 bite.
- **Departures from the plan:** company removal is refused while banks are
  connected instead of removing them itself (a refusal is safe whatever Plaid
  answers); the installer's key file is split off as step 5b; the log half of
  `no_response_carries_the_access_token` is best effort (tracing's global
  interest cache under parallel tests), the response half strict. `plan.md`
  updated.
- **Commit:** baf7068

## 2026-11-13 — The store key on installed servers (step 5b)

- **What changed:** `deploy/install/install.sh` writes
  `/opt/openledger/secrets.env` (0600, root) when there is none: a generated
  `GL_NODE_SECRETS_KEY` (32 bytes from `/dev/urandom`, as the operator key)
  and commented `GL_NODE_PLAID_CLIENT_ID` / `GL_NODE_PLAID_SECRET` lines; an
  existing one is kept. The node's service reads it as a second `env_file`.
  The backup archive names `data`, `settings` and `env` only, so `secrets.env`
  was never in it; a comment there now says why it must stay out. A restore
  puts back `data` only, so a restore on the same server keeps its key. The
  install summary names the file. OPERATIONS: the file in *What it leaves on
  the server*, and *Bank connections (Plaid)* — turning Plaid on for a
  company, keeping a copy of `secrets.env` off the server, restoring onto a
  new server (the file first), the lost-key path, and a forced stop during a
  connect. README *Installing on a server* names the file; CHANGELOG *Added*.
- **Checks:** `bash -n` on the installer and both rehearsal scripts.
  `scripts/rehearse_install.sh` checks the file is `600 root`, holds a
  64-hex key, and that the node's container has it;
  `scripts/rehearse_backup.sh` checks a backup does not hold it. **Not run
  here:** the rehearsals install Docker and pull images inside Lima VMs, which
  leaves loopback (LuLu); run them before relying on this unit. The gate does
  not exercise the installer, so no revert check is added (the installer's
  other mechanisms are pinned by the rehearsals the same way).
  Also unexercised by them: an existing install upgraded onto this installer
  (no `secrets.env`, a one-entry `env_file`) and a rollback to a release
  whose `compose.yml` has none — both read right in review, neither run.
- **Review:** nothing important. Fixed: a restore or rollback moves aside the
  token of a bank connected since its backup or upgrade — OPERATIONS now says
  to disconnect such banks first (restore, rollback, Plaid section); restoring
  onto a new server copies `env` and `secrets.env` into `/opt/openledger/`
  before installing (one order, in both places); `secrets.json` in *What a
  node keeps*; the CHANGELOG's upgrade claim limited to `--version` and
  `--installer`; the `ledger.json` path; an edited `compose.yml` keeps the node
  from reading `secrets.env` (said); an empty `secrets.env` left readable is
  written anew.- **Gate:** `scripts/gate.sh --quick` — fmt, clippy, anchors, guard pass; no
  Rust changed since step 5's full gate (1679 passed, 0 failed, 0 ignored).
- **Departures from the plan:** none.
- **Commit:** baf7068

## 2026-11-13 — Importing bank transactions (step 6)

- **What changed:** decisions 6–9 (intent.md). `plaid.suspenseAccount`
  (default `Expenses:Uncategorized`) in a ledger's `plaid` section.
  `crate::plaid`: a bank account's `ledger_account` in its stored
  description; `map_account` (a new mapping forgets the item's cursor);
  `fetch` pages `/transactions/sync` from the stored cursor (since the
  second review `begin_fetch` / `next_page` / `commit_page`, 100 a page, up
  to 1000 pages; started again on `TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION`, as
  Plaid asks), skipping pending, collecting changed and removed ids, storing
  nothing; `commit_page` (since the third review it also keeps a finished
  series' cursor apart, for restarts); connect refuses the same bank linked twice (same
  institution, same account names and masks: `BANK_ALREADY_CONNECTED`, the
  new item removed at Plaid). `graphql/plaid.rs`: `mapBankAccount` (the
  ledger account must be open) and `syncBank` (the suspense account must be
  open; one entry per posted transaction of a mapped account, flag `!`, link
  `^plaid-<id>`, the mapped account `-amount`, the suspense account
  balancing; a link the books hold is skipped; the cursor stored page by page
  once that page's entries are written; `needsReview` lists, with ids and
  reasons, what the accountant should look at; `stoppedBy` once a stored page
  precedes a stop). Both admin only. The entries go
  through `append_transaction_input`, `appendTransaction`'s body moved out of
  the resolver unchanged (re-indented), so they are refused, signed,
  journaled, published and gossiped alike. README *Importing transactions*
  and the config row; CHANGELOG *Added*.
- **Review:** four important findings, all fixed. (1) A disconnect left the
  cursor, so a bare bank stayed listed and `BANKS_CONNECTED` blocked removal
  for good — the cursor goes too (PL-R40). (2) One refused entry stopped every
  later sync of the bank, and the README's remedy could not work —
  maintainer's choice: `mapBankAccount` takes `importFrom` (default the
  ledger account's open date; earlier transactions skipped,
  `skippedBeforeStart`), and an entry the ledger refuses for what it says
  (`ENTRY_REFUSALS`) is noted in `needsReview` with its id and the reason
  while the sync goes on; any other refusal stops it with the cursor kept;
  unreadable transactions and zero amounts are noted too (PL-R30, R43, R45,
  R46). (3) A reconnect imports the history again (new ids) — the README now
  says so and gives the remedy, a later `importFrom`; `BANK_ALREADY_CONNECTED`
  claims no more than "while it is connected". (4) Pages of 500 may pass the
  1 MiB cap — 100 a page (Plaid's default), up to 1000 pages. Also fixed: a
  mapping made during a sync is no longer overwritten (a page's cursor stored only
  over the one the session last stored, PL-R41); one sync of a bank at a time
  (`SYNC_IN_PROGRESS`, PL-R42); an append that found the entry already is
  counted `alreadyImported`; `needsReview` lists ids and reasons and the log
  names them; changed ids counted once (PL-R44); the deposit test checks the
  sign; README on the close gate and the request timeout bounding a sync; an
  account the bank adds after connect is documented as unknown to the node.
  Not pinned by a test: a sync stopped by a node failure keeping its cursor
  (no way to inject an I/O error here); `SYNC_PAGE_SIZE` (the mock's pages
  are small). The `appendTransaction` move was checked byte-identical.
- **Gate:** `scripts/gate.sh` — 1702 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/plaid.json` — 58 of 58 bite
  (PL-R28..R58 for step 6; R55 rewritten after `false && a || b` left the
  amount test standing, R44 moved to the per-note de-duplication, the
  per-page one removed as redundant; PL-R3 and PL-R17 re-anchored; PL-R29 bites through
  a second admin's sync, the content id catching the same caller alone); `users.json` U-R54
  re-anchored on the moved append — 1 of 1 bite.
- **Second review:** no new code bugs in the first round's fixes; two
  important gaps, fixed. (1) A mapping made during a bank's first sync (no
  cursor stored, so the compare-and-set saw `None` = `None`) was lost —
  `mapBankAccount` is now refused while its bank syncs (`SYNC_IN_PROGRESS`,
  judged under the store lock; PL-R49), the compare-and-set kept as a second
  guard. (2) A fetch longer than `http.requestTimeoutSeconds` never got
  anywhere, every page fetched before any was written — the sync now goes
  page by page (`begin_fetch` / `next_page` / `commit_page`), each page's
  cursor stored once its entries are written (PL-R47). Also: nothing imported
  from before the suspense account was opened (PL-R48); a bank account cannot
  be mapped to the suspense account (PL-R50); payee and narration cut to the
  ledger's 1,000 and 10,000 bytes instead of refused for size (PL-R51); a
  transaction with a field that does not read is noted, not a failed page
  (PL-R45); docs: the README's timeout claim now true, CHANGELOG's refusal
  wording, the plan's proof list, this log's page size.
- **Third review:** two important findings from the page-by-page change,
  fixed. (1) A sync failing after a page was stored lost that page's notes
  for good — every note is now logged as it is made, and once a page is
  stored a stopped sync answers `Ok` with `stoppedBy` (PL-R54). (2) After
  Plaid restarts the pages, a transaction written before the restart comes
  back in `added` with any change folded in — an already-imported
  transaction whose date or bank amount differs from the books is now noted
  (PL-R55). And a possible one: Plaid keeps only a finished series' cursor
  valid for long, so the last page's cursor (`has_more` false) is stored
  apart and a restart goes back to it, not to a page cursor a cut-short sync
  stored (PL-R56, R58). Also: a test storing two pages in one sync
  (PL-R53); the cut test now cuts inside a character (PL-R57) and the payee
  cut has its check (PL-R52); changes read as id and pending only; an
  unreadable transaction's note keeps its id when it is valid; notes kept
  once each; the ledger's own text limits used; a poisoned sync lock counts
  as syncing. Known and left: a request dropped mid-append frees the sync
  mark while its commit may still run; a second sync could then skip that
  entry by its staged link, and lose it if that commit is rolled back —
  narrow, and the entry's absence would show at the next reconciliation.
- **Final review:** nothing important. Left as follow-ups (none loses an
  entry): another entry carrying the same `^plaid-…` link (a hand-linked
  follow-up) can draw a false "changed" note on a resend — keep the first
  entry per link; `stoppedBy` carries the message only, not the code or
  `plaidCode`; a sync ended by a disconnect or a moved cursor answers with
  `stoppedBy` null; `map_account` stores the mapping before removing the two
  cursors, so a disk error between them can leave a stale finished-series
  cursor — remove them first; two unreadable transactions without an id and
  with the same fault share one note.
- **Departures from the plan:** changed and removed posted transactions are
  counted for review instead of reversed (a reversing entry for a bank's
  correction is the accountant's call); the plan's two-node proof is not a
  test of its own — the entries are ordinary records, replicated as any.
  `plan.md` updated.
- **Commit:** 44c7d16

## 2026-11-13 — Logging in again to a connected bank (step 6b)

- **What changed:** `createPlaidLinkToken` takes an optional `itemId`. With
  it, `PlaidService::create_link_token` asks `/link/token/create` in Plaid's
  update mode: the bank's access token (`token_for_update`: a bank this
  ledger holds, a token of `plaid.environment`, read under the close gate;
  the Plaid call itself changes nothing and runs outside it) and no
  `products`. Link then logs the person in again on the same item — an
  expired password, a new multi-factor step, `ITEM_LOGIN_REQUIRED`. Its
  `onSuccess` still hands back a public token; `connectBank` given one for a
  held item now answers with the bank as stored and changes nothing
  (`held_connection`), where it used to store over its description and lose
  its mappings. Without `itemId`,
  as before. Admin only (already in `ADMIN_FIELDS`). README *Logging in
  again* (and the *Connected again* bullet points to it); CHANGELOG *Added*.
  The maintainer put the client app's MFA on hold.
- **Review:** one important finding, fixed: the docs said Link returns no
  public token in update mode — it does, and passed to `connectBank` it
  reset the bank's mappings (now a no-op, PL-R63). Also: the update-mode
  close check pinned (PL-R64); the update-mode body's required fields
  asserted; this entry's close-gate wording. Left: the caller's `itemId` is
  echoed in `NO_SUCH_BANK` unbounded (admin only, as `syncBank` does).
- **Gate:** `scripts/gate.sh` — 1706 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/plaid.json` PL-R59..R64 — 6 of 6
  bite (the token sent, no products in update mode, the environment check,
  an unknown bank refused before Plaid is asked, a held bank left as it is,
  the close check); the connect checks R2, R9, R16, R18, R22, R34 rerun
  after the change to `connect` — 6 of 6 bite.
- **Departures from the plan:** none (step 6b added to `plan.md`).
- **Commit:** fe12038

## 2026-11-13 — Endpoints for a proof of concept (step 6c)

- **What changed:** decision 11. A bank's stored description gains
  `last_synced_at` and `last_error_code`; `PlaidService::note_health` sets
  them (best effort) — `syncBank` clears the code and notes the time when it
  finishes, and keeps Plaid's code when `/transactions/sync` refuses.
  `connectedBanks` shows `lastSyncedAt` and `lastErrorCode`.
  `refreshBankAccounts(itemId)` (`refresh_accounts`: the bank's token as for
  update mode, `/accounts/get` again, new accounts added unmapped, known ones
  renamed with their mappings kept, accounts Plaid no longer lists kept).
  `unmapBankAccount(itemId, accountId)` (`unmap_account`: mapping and start
  cleared, refused while the bank syncs). Sandbox only, refused with
  `PLAID_SANDBOX_ONLY` and nothing sent elsewhere:
  `connectSandboxBank(institutionId = "ins_109508")`
  (`/sandbox/public_token/create`, then the usual `connect`) and
  `resetSandboxLogin(itemId)` (`/sandbox/item/reset_login`). All four
  mutations admin only. README *How each bank is doing*, *Accounts*, *A demo
  in Plaid's sandbox*; CHANGELOG *Added*.
- **Review:** one important finding, fixed: a refresh racing a disconnect
  wrote a bare description back for a bank whose token was gone — listed,
  uncountable down, blocking removal for good; the refresh now re-checks the
  token under the store lock and writes nothing then (PL-R75). Also: only a
  sync that read Plaid to the end clears the error code (`finished`); the
  README no longer claims `PRODUCT_NOT_READY` from `/transactions/sync`;
  revert checks for `a_banks_health_is_kept`, the sandbox connect and the
  demo test (R76–R78); an error code kept to 64 characters, an empty one as
  `UNKNOWN`; the sandbox connect refused once the ledger is closing; the
  module and `closed` docs name the new operations. These fixes were not
  reviewed again; each has its test and revert check.
- **Gate:** `scripts/gate.sh` — 1714 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/plaid.json` PL-R65..R78 — 14 of 14
  bite; PL-R49 re-anchored (its line now also in `unmap_account`) — bites.
- **Departures from the plan:** none (step 6c added to `plan.md`).
- **Commit:** 866868e

## 2026-11-13 — Plaid webhooks (step 6d)

- **What changed:** decision 12. New module `crates/gl-node/src/plaid_webhook.rs`:
  `verify` (the `Plaid-Verification` JWT: ES256 only, the key by its id from
  `PlaidService::verification_key` — `/webhook_verification_key/get`, its
  `kid`, `alg`, `crv`, `kty` and expiry checked, fetched in the background
  and never while the call waits, cached and asked about again hourly — the
  signature with `ring`, issued within five minutes either way, the body's
  SHA-256 compared in constant time) and `handle` (verify first, 401
  otherwise, and 401 for a webhook about no bank the ledger holds; then act
  as one of the ledger's tasks and answer 200 at once: a `syncBank` through
  the ledger's schema as the operator for `SYNC_UPDATES_AVAILABLE` and
  `LOGIN_REPAIRED`, one queued a bank at a time, retried three times 30 s
  apart when one already runs; `note_health` for `ERROR`; `note_notice`
  (`lastNotice`, `lastNoticeAt`) for the consent codes; `refresh_accounts`
  for `NEW_ACCOUNTS_AVAILABLE`; nothing for the older update codes). Routes
  `POST /ledgers/{name}/plaid/webhook` and `/plaid/webhook`
  (`Ledgers::plaid_webhook`: 401 for a name not served or without Plaid,
  413 past 64 KiB for any name), behind the request guard and a rate limit
  of their own, no API key. `plaid.webhookUrl` (https only, 2,000
  characters) carried by new link tokens; `updateBankWebhooks`
  (`/item/webhook/update` for each bank; `PLAID_NO_WEBHOOK_URL` while
  unset); sandbox `fireSandboxWebhook` (`/sandbox/item/fire_webhook`). Both
  admin only. An update-mode public token passed to `connectBank` clears
  the notice. `ring` 0.17 a direct dependency (already compiled in through
  rustls, these features). README *Webhooks*, *Logging in again* and the
  config row; CHANGELOG *Security* and *Added*.
- **Review:** the verification itself sound; four important findings, fixed.
  (1) The webhook's work ran outside the ledger's tasks, so a restart could
  leave the stopped ledger's sync appending beside the new one — it is now
  one of the ledger's tasks (`RunningLedger::tasks`, `track`), which `stop`
  aborts before compacting, and one webhook sync of a bank is queued at a
  time (`queue_webhook_sync`). (2) 404 for a name not served or without
  Plaid told strangers which companies the node serves — 401 for every name,
  the body cap met before the lookup. (3) A made-up key id cost a Plaid call
  each — key fetches are one at a time, ten a minute, a refused id remembered
  five minutes. (4) Consent codes were kept as `lastErrorCode`, which the
  next sync clears — kept as `lastNotice` / `lastNoticeAt`, cleared by
  `LOGIN_REPAIRED`. Nits: a key with any `expired_at` refused (as Plaid's
  samples); the older update codes ignored; a doc comment moved back; the
  body cap pinned. Left: `update_webhooks` stops at the first Plaid refusal
  without a count; no replay cache inside the five minutes (a replayed call
  only repeats an idempotent action); the route's rate limit has no test of
  its own.
- **Second review:** five findings, fixed. (1) A consent notice was never
  cleared by a login renewed in update mode (Plaid sends no webhook for it) —
  the update-mode public token passed to `connectBank` clears it (README
  *Logging in again* now says to pass it); it is cleared under the `closed`
  gate connect already holds (`change_info_open`), as a second read of the
  gate would wait behind a queued stop forever. (2) `LOGIN_REPAIRED` with a
  sync already queued was dropped, notice and all — the notice is cleared
  before the queue is asked. (3) One key-fetch budget for everyone let a
  stranger's made-up key ids block real fetches — ten a minute for each
  caller's address (`RateLimiter::client_of` on `Ledgers::strangers`), under
  sixty in all. (4) A call for a key not cached waited on Plaid, so timing
  told which companies have Plaid — `verification_key` answers at once
  (`KeyLookup::Pending`, 401) and fetches in the background; Plaid's
  redelivery is taken. Only Plaid's own refusal of a key id is remembered; a
  timeout or a 5xx is asked again. (5) A webhook arriving while a bank's
  sync ran was dropped, leaving what Plaid had since at Plaid — it marks the
  sync to go once more (`QueuedSync::go_again`). Found while testing (5): the
  ended guard's `Drop` removed the next sync's mark; it no longer does. Nit:
  `DEFAULT_UPDATE` and the other older codes do nothing (as Plaid asks of
  `/transactions/sync` clients). Left: the two-reads deadlock in (1) has no
  test (it needs a stop queued between connect's two reads); PL-R109 pins
  the clearing, not where it is done.
- **Third review:** two important findings, fixed. (1) The per-client key
  budget counted each IPv6 address apart, so one /64 rotating addresses could
  spend the sixty — keyed with `rate_limit::bucket_key` (M-04b), the /64 one
  client. (2) A webhook Plaid sent another customer, replayed, verified and
  was answered 200 by any ledger with Plaid — so it told which names have
  Plaid on (as L-R31 closed for names) — one about no bank the ledger holds,
  or that does not read, is 401 now. Should-fix: a cached key was never
  checked for expiry again — each key keeps its fetch time and is asked
  about again after an hour, in the background, used meanwhile and dropped
  once Plaid refuses it or sets it to expire; the dead second run of PL-R83
  removed; this entry's *What changed* brought up to date. Nits: `client_of`
  moved out of `sibling`'s doc comment; the passing-failure test waits for
  the fetch (`key_fetch_under_way`) rather than starting another; a key
  fetch of a stopped ledger asks Plaid nothing. Left: a caller with several
  addresses can still spend the sixty a minute (README says so); a consent
  notice redelivered after `LOGIN_REPAIRED` sets a notice already answered
  (Plaid's order is not kept; the JWT's `iat` could order them later); a
  cached key's signature check takes some tens of µs a ledger without Plaid
  does not spend — not measurable across the internet under the route's
  rate limit, and the README no longer says "as fast".
- **Fourth review:** nothing important. Medium, fixed: a stale key's
  re-check was paid from the callers' budgets, so made-up key ids spending
  the sixty kept it from ever being asked, and a key Plaid rotated out was
  trusted without end — a stale key is asked about outside both budgets, at
  most once a minute (`CachedKey::asked`; only keys Plaid gave are cached),
  and one not confirmed for a day (`KEY_TRUSTED_UNCONFIRMED`) is refused
  until Plaid answers. Minor, fixed: the 401 for a signed body about no bank
  had no test — the route test sends one (PL-R115). Nits: "ignored" comments
  now say refused; long comment lines wrapped; the README says a key is
  dropped on any refusal Plaid gives, not only an expiry.
- **Gate:** `scripts/gate.sh` — passed (fmt, clippy, anchors, guard; 1733
  tests passed, 0 failed).
- **Revert checks:** `scripts/revert_specs/plaid.json` PL-R79..R118 and the
  re-anchored PL-R63 — 41 of 41 bite (PL-R63, R83, R85, R95, R96, R99, R101
  re-anchored through the reviews; PL-R83's dead second run removed; 385
  anchors in 16 files, each once).
- **Departures from the plan:** none (step 6d added to `plan.md`).
- **Commit:** 65371da
