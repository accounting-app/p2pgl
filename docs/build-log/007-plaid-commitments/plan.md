# Plan: keep what we told Plaid (from intent.md, 2026-11-09)

Updated 2026-11-10 for the decisions in intent.md: Plaid runs in the node; the
client app does MFA (the node requires an admin key); no raw responses on disk.

## Files that change

- `deploy/install/install.sh` — log retention, purge of `.removed/`, off-server
  backup copies; `docs/OPERATIONS.md`.
- `crates/gl-node/src/` — new `secret_store.rs` (encrypted token store),
  `plaid/` (client, link, sync, removal), GraphQL mutations in `graphql/`;
  `config.rs` (`plaid.*`: environment, the designated import node);
  `ledger_admin.rs` (removal calls Plaid first).
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
   value sealed with AES-256-GCM under `GL_NODE_SECRETS_KEY` (kept in
   `/opt/openledger/env`, not the data folder), bound to its name by the
   associated data (not to the ledger, so a removed ledger moved back under a
   new name keeps its store); every value opened at `open`, so a wrong key is
   refused then, and temp files a crashed write left are deleted there. Writes
   refuse a file larger than `open` reads. A `Secret` type whose
   `Debug`/`Display` print `[redacted]`, so a token cannot reach a log by
   formatting. Unused until step 5, which wires the key into boot and the
   installer.
4. **MFA** is the client app's, at login (decision 2); nothing in the node.
5. **Plaid connect and disconnect.** `createPlaidLinkToken`,
   `connectBank(publicToken)`, `disconnectBank(itemId)`: admin role,
   designated node only. Exchange the public token, store the access token;
   disconnect calls `/item/remove`, then deletes it. Company removal does the
   same for each item.
6. **Transaction sync.** `/transactions/sync` with a stored cursor, on a timer
   and on demand; each Plaid transaction becomes one entry carrying its
   Plaid `transaction_id` in metadata, skipped when already posted; posted to
   a mapped bank account. Raw responses only in memory.
7. **Operations checklist** (no code; the maintainer, dated records in a
   private folder): MFA on GitHub, hosting, registrar, email and the Plaid
   Dashboard; disk encryption on servers and workstations; first quarterly
   access review, risk register, and restore test; incident tabletop; vendor
   file; policy acknowledgments. Flip each policy row to *In place* when done.

Steps 1–2 and 7 can start now; 3 → 5 → 6 depend in order. Link ships to
users only once the client app's MFA is live.

## Risks

- **Two nodes importing** posts transactions twice. The designated-node
  setting is refused on a non-designated node at boot; a test with two nodes.
- **Token leakage through a log or error message** — the riskiest step (5): a
  Plaid error body can echo request fields. Error paths log Plaid's
  `error_code` only.
- **Removal order:** deleting the token before `/item/remove` succeeds leaves
  a live item at Plaid we can no longer remove. Remove at Plaid first; on
  failure keep the token and retry.
- **Pending and modified transactions:** Plaid revises them; a revision is
  posted as a reversing entry plus the new one, as the ledger cannot edit.
- **One store instance per ledger:** each write replaces the whole file, so
  two instances on one folder lose each other's writes (a token lost, its
  item live at Plaid). Step 5 keeps one per ledger behind the ledger's lock.
- **Backups hold the secret store and, today, the key with it**: a backup
  archives `/opt/openledger/env` with the data. Step 5 decides: keep
  `GL_NODE_SECRETS_KEY` out of the archive (then a restore on a new server
  needs it supplied), or rely on step 2's encryption of every copy that
  leaves the server.

## Alternatives rejected

- **Plaid in the client app's backend**: a second server holding bank tokens,
  outside this repo's audits and tests, and it would still need to write to
  the ledger.
- **Tokens in access-style records**: replication would copy them to every
  node, desk machines included — the opposite of "server-side only".
- **TOTP checked by the node**: rejected by the maintainer (decision 2) for
  simplicity; the accepted risk is in intent.md.

## Proof

- Tests against a loopback Plaid mock: connect → sync → disconnect; a second
  node receives the entries; the token is searched for and absent in the
  `.bean` files, records, GraphQL responses and captured logs of both nodes.
- Tests: a read or write key refused on Plaid mutations; a non-designated
  node refuses; a duplicate sync posts nothing; an `/item/remove` failure
  keeps the token; purge after 30 days. The store's own tests are in
  `secret_store.rs` (step 3).
- Revert checks: `scripts/revert_specs/secret_store.json` (step 3: redaction,
  ledger and name binding, fresh nonce, open-time check, mode check, removal
  on disk); `plaid.json` (skip `/item/remove`, drop the duplicate check, drop
  the admin-role check, drop the designated-node check).
- Docs: README (Plaid section, MFA), OPERATIONS (purge, off-server backups,
  logs), CHANGELOG *Added* and *Security*.
