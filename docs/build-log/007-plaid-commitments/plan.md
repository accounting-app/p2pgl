# Plan: keep what we told Plaid (from intent.md, 2026-11-09)

Draft: written with the intent, assuming the proposed answers to its open
questions (Plaid in the node; the node checks TOTP; no raw responses kept).
Revisit once the intent is approved.

## Files that change

- `deploy/install/install.sh` — log retention, purge of `.removed/`, off-server
  backup copies; `docs/OPERATIONS.md`.
- `crates/gl-node/src/` — new `secret_store.rs` (encrypted token store),
  `plaid/` (client, link, sync, removal), `mfa.rs` (TOTP), GraphQL mutations in
  `graphql/`; `config.rs` (`plaid.*`: environment, the designated import
  node); `ledger_admin.rs` (removal calls Plaid first).
- `README.md`, `CHANGELOG.md`, `scripts/revert_specs/plaid.json`.
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
3. **Secret store.** One file per ledger, owner-only (`0600`, the same checks
   as `p2p.secretKeyPath`), each value encrypted with an AEAD under a key in
   `/opt/openledger/env`, not in the data folder. A `Secret` type whose
   `Debug`/`Display` print `[redacted]`, so a token cannot reach a log by
   formatting.
4. **TOTP MFA.** An admin enrolls (`openledger person mfa NAME` prints a QR
   code once); the secret lives in the Plaid node's secret store. Plaid
   mutations take a `totp` argument; a wrong or missing code is refused, rate
   limited, logged without the code.
5. **Plaid connect and disconnect.** `createPlaidLinkToken`,
   `connectBank(publicToken, totp)`, `disconnectBank(itemId)`: admin role,
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

Steps 1–2 and 7 can start now; 3 → 4 → 5 → 6 depend in order. Link ships to
users only after 4.

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
- **Backups contain the secret store** (encrypted, key not in the backup) — a
  restore on a new server needs the key from `/opt/openledger/env` too.

## Alternatives rejected

- **Plaid in the client app's backend**: a second server holding bank tokens,
  outside this repo's audits and tests, and it would still need to write to
  the ledger.
- **Tokens in access-style records**: replication would copy them to every
  node, desk machines included — the opposite of "server-side only".
- **Trusting the client app for MFA**: any holder of an admin key could open
  Link without MFA.

## Proof

- Tests against a loopback Plaid mock: connect → sync → disconnect; a second
  node receives the entries; the token is searched for and absent in the
  `.bean` files, records, GraphQL responses and captured logs of both nodes.
- Tests: missing/wrong TOTP refused; non-designated node refuses; duplicate
  sync posts nothing; `/item/remove` failure keeps the token; purge after 30
  days; secret file with group-read refused.
- Revert checks in `scripts/revert_specs/plaid.json`: drop the `Secret`
  redaction (log test fails); skip `/item/remove` (disconnect test fails);
  drop the duplicate check (sync test fails); drop the TOTP check (MFA test
  fails); drop the designated-node check (two-node test fails).
- Docs: README (Plaid section, MFA), OPERATIONS (purge, off-server backups,
  logs), CHANGELOG *Added* and *Security*.
