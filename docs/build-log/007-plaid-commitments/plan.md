# Plan: keep what we told Plaid (from intent.md, 2026-11-09)

Updated 2026-11-10 for the decisions in intent.md: Plaid runs in the node; the
client app does MFA (the node requires an admin key); no raw responses on disk.
Updated 2026-11-13 for the step 5 decisions (maintainer): the store key in its
own root-only file, left out of backups; the importing node chosen by
`plaid.enabled` in one node's ledger config; step 5 includes `connectedBanks`.

## Files that change

- `deploy/install/install.sh` — log retention, purge of `.removed/`, off-server
  backup copies; `docs/OPERATIONS.md`.
- `crates/gl-node/src/` — new `secret_store.rs` (encrypted token store),
  `plaid.rs` (client, service, sync), `graphql/plaid.rs`; `config.rs`
  (`plaid.enabled`, `plaid.environment`, `plaid.clientName`);
  `ledger_runtime.rs` (starts the service), `main.rs` (the environment);
  `ledger_admin.rs` (removal refused while banks are connected).
- `README.md`, `CHANGELOG.md`, `scripts/revert_specs/secret_store.json` (step
  3), `scripts/revert_specs/plaid.json`.
- The two policy docs (status column), outside the repo.

## Order of work

1. **Retention in the installer.** Logs: journald driver with 90-day
   retention, or a daily job deleting older rotated files. `.removed/` folders
   older than 30 days deleted by the nightly timer, plus
   `openledger company purge NAME` for a deletion request. No Plaid needed;
   ships first.
2. **Off-server encrypted backups** (needs open question 3): encrypt each
   backup before it leaves (`age` to a recipient key not on the server), copy
   it, delete remote copies older than 30 days; `openledger status` fails when
   the newest remote copy is over two days old.
3. **Secret store.** `secrets.json` per ledger folder, opened as the node key
   is (`open_checked`, `NodePrivate`: no symlink, owner, one link, 0600); each
   value sealed with AES-256-GCM under `GL_NODE_SECRETS_KEY` (outside the data
   folder; 5b), bound to its name by the associated data (not to the ledger,
   so a removed ledger moved back under a new name keeps its store); every value opened at `open`, so a wrong key is
   refused then, and temp files a crashed write left are deleted there. Writes
   refuse a file larger than `open` reads. A `Secret` type whose
   `Debug`/`Display` print `[redacted]`, so a token cannot reach a log by
   formatting. Done (e331ebd).
4. **MFA** is the client app's, at login (decision 2); nothing in the node.
5. **Plaid connect and disconnect (node).** `plaid.enabled` (one node per
   company; others refuse with `PLAID_NOT_ENABLED`), `plaid.environment`
   (sandbox or production, never an address), `plaid.clientName`; credentials
   and store key from the environment, read once at boot. The ledger's
   `PlaidService` starts under its lock (the one store instance, behind a
   mutex) or the ledger is not served. `createPlaidLinkToken`,
   `connectBank(publicToken)`, `disconnectBank(itemId)` (admin) and
   `connectedBanks` (read). Connect stores the token before asking Plaid
   anything else; disconnect calls `/item/remove` first and keeps the token
   when Plaid refuses (deletes it when Plaid says the item is gone). Company
   removal is refused while banks are connected (`BANKS_CONNECTED`), read
   from the store's names without the key, rather than removing them itself:
   a refusal is safe whatever Plaid answers.
5b. **The store key on installed servers.** `/opt/openledger/secrets.env`
   (root-only, `GL_NODE_SECRETS_KEY`, and the Plaid credentials the operator
   adds), a second `env_file` of the container, left out of backups; a
   restore onto a new server without it means connecting the banks again.
   OPERATIONS documents it. Checked by the rehearsals (`rehearse_install`,
   `rehearse_backup`), not the gate.
6. **Transaction import** (decisions 6–9). `mapBankAccount(itemId, accountId,
   ledgerAccount)` (admin) maps a Plaid account to an open ledger account and
   resets the item's cursor, so its earlier transactions arrive at the next
   sync. `syncBank(itemId)` (admin) pages `/transactions/sync` from the stored
   cursor; each **posted** transaction of a mapped account becomes one entry:
   its date, payee and narration from Plaid, flag `!`, link
   `^plaid-<transaction_id>`, the mapped account `-amount` (Plaid counts money
   out as positive) and `plaid.suspenseAccount` balancing it. An entry whose
   link the ledger already holds is skipped, so a repeated sync imports
   nothing twice; the cursor is stored page by page, once that page's
   entries are written.
   Modified and removed posted transactions, and entries the ledger refuses,
   are listed for review, never reversed (a departure from the first plan,
   which reversed them); `importFrom` on the mapping (default the account's
   open date) skips the history before it, and is the remedy after a
   reconnect, and nothing before the suspense account's open date is
   imported. One sync of a bank at a time, and no mapping during one; a
   page's cursor stored only over the one the sync last stored, the last
   page's kept apart for restarts; a sync that stops after storing a page
   answers with what it did and `stoppedBy`, and an already-imported
   transaction sent again with another date or amount is noted. Entries go through `appendTransaction`'s own path (signed,
   journaled, gossiped; `enteredBy` the admin). Connect refuses the same bank
   linked twice (`BANK_ALREADY_CONNECTED`; the new item removed at Plaid).
   Raw responses only in memory.
6b. **Logging in again** (maintainer, 2026-11-13: the next Plaid endpoint;
   MFA in the client app on hold). `createPlaidLinkToken(itemId)` asks Plaid
   for a link token in update mode — the bank's access token, no `products`
   — so an expired login is fixed on the same item; nothing to exchange
   after. Refused for a bank this ledger does not hold or a token of another
   environment, before anything is sent.
6c. **Endpoints for a proof of concept** (decision 11). `connectedBanks`
   shows each bank's `lastSyncedAt` and `lastErrorCode` (recorded by
   `syncBank`: a finished sync clears the code, a Plaid refusal sets it).
   `refreshBankAccounts(itemId)` reads the bank's accounts again and adds new
   ones, mappings kept. `unmapBankAccount(itemId, accountId)` stops an
   account's import (refused while its bank syncs). Sandbox only (refused
   with `PLAID_SANDBOX_ONLY` elsewhere, nothing sent):
   `connectSandboxBank(institutionId)` (`/sandbox/public_token/create`, then
   the usual connect) and `resetSandboxLogin(itemId)`
   (`/sandbox/item/reset_login`). All admin only.
6d. **Webhooks** (decision 12). `POST /ledgers/<name>/plaid/webhook` (and
   `/plaid/webhook`), no API key, behind the Host guard and a rate limit,
   body capped at 64 KiB, 401 alike for every name not served with Plaid
   and for a signed webhook about a bank the ledger does not hold;
   `plaid_webhook::verify` checks Plaid's ES256 JWT (key by id from
   `/webhook_verification_key/get`, fetched in the background — never while
   the call waits — at most ten a minute for one address (an IPv6 /64) and
   sixty in all, cached and asked about again hourly, its id and expiry
   checked; five minutes; the body's SHA-256) before anything is done. Then,
   for a bank the ledger holds, as one of the ledger's tasks: a sync
   (through the ledger's schema as the operator) for new transactions or a
   repaired login, one queued at a time, going once more for a webhook that
   came meanwhile; `lastErrorCode` for an error; `lastNotice` for an
   expiring consent, cleared by a repaired login or an update-mode
   `connectBank`; an accounts refresh for new accounts.
   `plaid.webhookUrl` (https only) in new link tokens;
   `updateBankWebhooks` (`/item/webhook/update`); sandbox
   `fireSandboxWebhook` (`/sandbox/item/fire_webhook`). `ring` (already in
   the build) verifies.
6e. **One Plaid account, many companies** (decision 13). (a) The webhook key
   cache, the refused key ids and the key-fetch budgets move from each
   ledger's `PlaidService` to one per node (through `PlaidEnv`): a key is
   fetched once for every company, and a stranger cannot spend sixty fetches
   a minute of the account's rate limit for each company served. (b) One
   Plaid environment per node: the node holds one secret, which is one
   environment's, so a ledger whose `plaid.environment` differs from another
   Plaid-enabled ledger on the node is refused at boot, `addLedger` and
   `restartLedger`, naming the ledger it clashes with (one not served now
   counts too, as its port does). (c) OPERATIONS *Bank connections (Plaid)*,
   README and the installer's `secrets.env` comment: the maintainer's
   credentials go only on servers the maintainer runs; an operator with a
   Plaid account of their own may put theirs on their own node; any other
   node leaves `plaid` off and the Plaid lines empty.
7. **Operations checklist** (no code; the maintainer, dated records in a
   private folder): MFA on GitHub, hosting, registrar, email and the Plaid
   Dashboard; disk encryption on servers and workstations; first quarterly
   access review, risk register, and restore test; incident tabletop; vendor
   file; policy acknowledgments. Flip each policy row to *In place* when done.

Steps 1–2 and 7 can start now; 3 → 5 → 5b → 6 depend in order. Link ships to
users only once the client app's MFA is live.

## Risks

- **Two nodes importing** posts transactions twice. Only a ledger with
  `plaid.enabled` holds connections, and an invitation never carries the
  setting; nothing stops an operator setting it on two nodes, which step 6
  must still guard (a Plaid `transaction_id` already posted is skipped).
- **The same bank linked twice** (two items, each with its own transaction
  ids) imports every transaction twice, and the `transaction_id` check cannot
  see it. Step 6 detects it at connect (same institution and account masks as
  a connected bank: the new item is removed at Plaid) before importing.
- **Token leakage through a log or error message** — the riskiest step (5): a
  Plaid error body can echo request fields. Error paths log Plaid's
  `error_code` only.
- **Removal order:** deleting the token before `/item/remove` succeeds leaves
  a live item at Plaid we can no longer remove. Remove at Plaid first; on
  failure keep the token and retry.
- **Pending and modified transactions:** pending ones are skipped (decision
  8); a posted one Plaid changes or removes after its import is counted in
  `needsReview` for the accountant, never reversed by the node.
- **One store instance per ledger:** each write replaces the whole file, so
  two instances on one folder lose each other's writes (a token lost, its
  item live at Plaid). Step 5 keeps one per ledger behind a mutex, opened
  under the ledger's lock.
- **Backups hold the secret store**: a backup archives the data and
  `/opt/openledger/env`. Decided (2026-11-13): the key goes in its own file
  that backups leave out (5b), so a stolen backup holds ciphertext only; the
  cost is reconnecting banks after a restore onto a new server.

## Alternatives rejected

- **Plaid in the client app's backend**: a second server holding bank tokens,
  outside this repo's audits and tests, and it would still need to write to
  the ledger.
- **Tokens in access-style records**: replication would copy them to every
  node, desk machines included — the opposite of "server-side only".
- **TOTP checked by the node**: rejected by the maintainer (decision 2) for
  simplicity; the accepted risk is in intent.md.

## Proof

- Step 5, against a loopback Plaid mock (`crate::plaid::tests::MockPlaid`):
  connect keeps the token and describes the bank; every call carries the
  credentials; disconnect removes at Plaid then here, keeps the token when
  Plaid refuses, deletes an item Plaid no longer has; Plaid errors carry its
  code, never its message; a bank Plaid cannot describe is still kept; a write
  key is refused on the three mutations, a read key lists banks; a node
  without Plaid refuses every field; no response of the whole flow carries
  the token (logs scanned, best effort); a ledger with `plaid.enabled` and no
  credentials is not served; a ledger with banks is not removed; a connect or
  disconnect cut short still finishes; a removal waits for a connect under way
  and reopens on a refusal; a restart waits for it too; a token of another
  environment is never sent there; Plaid's answers are capped.
- Step 6: every page read, nothing stored at fetch; started again when Plaid
  says the history moved; a mapping restarts the bank; the same bank linked
  twice refused; one entry per posted mapped transaction, sign turned; a
  repeated sync imports nothing twice; a sync cut short goes on from its
  last page; changed imported ones counted; no sync without the suspense
  account; the five admin fields refused to a write key.
- Revert checks: `scripts/revert_specs/secret_store.json` (step 3);
  `plaid.json` (step 5: admin-only, token stored, delete only on success or
  "gone", no Plaid message, credentials sent and not printed, id check,
  undescribed bank kept, removal guard, start refusal, `clientName` check).
- Docs: README (Plaid section, MFA), OPERATIONS (purge, off-server backups,
  logs), CHANGELOG *Added* and *Security*.
