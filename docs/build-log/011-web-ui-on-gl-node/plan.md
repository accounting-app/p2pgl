# Plan: gl-node's API for a web UI (draft from intent.md, 2026-11-17)

Status: **draft — decisions 2–4, 6 and 7 are open.** The design assumes the
recommended answer to each; where another answer changes it, the section
says how. All work here is gl-node's. The new UI (own repo, Vercel) is a
consumer, built afterwards against the published schema.

## Design

The UI's ~110 calls collapse into a few ledger operations; the schema is
shaped by the ledger, and `notes/ui-api-inventory.md` is the checklist that
every screen is covered.

- **Published schema.** `docs/api/schema.graphql`, the SDL of the ledger
  endpoint, committed; a test fails when it differs from the running
  schema, and says how to regenerate it (an xtask). The UI generates its
  client from this file.
- **Accounts.** The account's name is its id. Code, category, subtype and
  "allows manual entries" are metadata on the `open` directive, under a
  reserved `ui-` key prefix; `openledger-` (envelope) keys are refused.
  `openAccount` takes metadata, `Account` returns it. Changing it later is
  a correction, not an edit.
- **Entries.** `TransactionInput` and `Transaction` gain metadata: type
  (expense, check, deposit, transfer, sales receipt, journal entry), reference
  number, due date, source account. Memo is the narration. Deposit, transfer
  and the other forms are all `appendTransaction`; there is no draft state
  in the ledger.
- **Register.** `register(account, from, to, limit, offset)`: rows with
  running balances computed on the node and a stable row id (`txid` plus the
  posting's index), so a client never pages the whole journal to add up.
- **Reports.** Trial balance, balance sheet and income statement exist.
  Added: P&L detail (entries by account over a period), aging (open
  receivables and payables by due date, from the due-date metadata) and by
  payee.
- **Who am I.** A `me` query: the caller's name and role on this ledger, and
  the ledger's name and label, so a UI can sign in with a key and show the
  company. A company label set when an operator adds a ledger.
- **Corrections (decision 2a: entry 012).** A correction reverses the
  original and names it (a link or a metadata key, settled in 012). The read
  model hides replaced entries from the register and reports, and the
  journal keeps both. Void is a reversal; delete is a reversal hidden from
  the register. Reconciling a statement writes a `balance` assertion on the
  ending date plus a record of the entries cleared; undo is a later record.
  Replacing the `.bean` wholesale is not offered; adding entries from a file
  already works (T35).
- **Records that are not ledger entries (decision 3a: entry 013).** A store
  per ledger beside its folder, under the same keys and roles, served
  through the same endpoint. It does not replicate — deliberate for
  personal data. Receipts and attachments are files there, optionally
  linked from the ledger by a `document` directive naming the file's hash.
- **Bank feed.** The 008 inbox already serves a UI. Bank rules apply when
  the node classifies, once decision 3 places them.
- **Reaching the node from Vercel (decision 7a).** The browser calls
  `https://<node>/ledgers/<name>/graphql` directly. The node lists the UI's
  production origin, and a fixed preview origin, in `cors.allowedOrigins`;
  Vercel's per-deploy preview URLs cannot be listed one by one.

## Order of work

Each step is a commit-sized unit: tests written as a screen's calls, revert
checks, README and CHANGELOG (*Added*), and the schema file updated.

1. **Schema file** and the test that keeps it current.
2. **Account metadata** in and out, with the key rules.
3. **Entry metadata** in and out, the key rules, and the size cap counting
   metadata.
4. **`register` query.**
5. **`me` query** and the ledger label.
6. **Reports:** P&L detail, then aging, then by payee.
7. **Entry 012, corrections** — its own intent and plan.
8. **Entry 013, the store for records that are not ledger entries**, then
   one unit per area: contacts, products, bills and invoices (these post
   entries), estimates, employees, mileage, receipts, recurring templates,
   reconciliations, bank rules.

**The UI runs in parallel, when the maintainer starts it** (2026-11-17), in
its own repo on Vercel. Nothing here waits for it. Steps 1–4 are enough for
its first screens (chart of accounts, register, reports, create-only forms);
from then on it follows each step. Its first page tests the path from Vercel:
one example call per area against a real node, over HTTPS, with CORS and a key.

## Risks

- **Corrections are the riskiest step:** they touch the read model,
  replication, boot and signatures; tests must cover a restart, two nodes,
  and a correction arriving before the entry it replaces (the orphan buffer).
- **Metadata is part of the signed record and its hash** in both formats.
  Old entries without it must read as before; the size cap must count it.
- **Personal data in the ledger can never be removed** from any node — the
  reason for decision 3.
- **Unbounded lists:** every list query is paged and weighed for M-45; a
  screen that wants everything gets refused on a real ledger.
- **Browsers and nodes on desk machines:** an HTTPS page on Vercel cannot
  call a plain-HTTP node except on localhost, and browsers increasingly
  gate a public site's calls to private addresses (Chrome's local-network
  access permission). Server nodes with the installer's HTTPS (005) are
  fine; desk machines need checking before we promise them.
- **One key per person per ledger** makes signing in clumsy for an
  accountant with many companies; solving it must not weaken 003.

## Alternatives rejected

- **Copy `newgl-api`'s 110 REST paths, as REST or as GraphQL fields one for
  one:** QuickBooks-shaped, and its edit and delete calls cannot be honoured
  by an append-only ledger.
- **Rework `newgl-ui` in place:** its screens assume Supabase logins,
  tenants, a server-side active company, UUIDs, edits in place and reports
  in the browser; there are no users to keep. Its look is kept instead.
- **Edit the `.bean` in place for corrections:** rewrites signed history
  that other nodes hold.
- **Supabase tokens on the node (4b):** every node would need Supabase.
- **Proxy through Vercel (7b):** keys pass through a third party, and the
  node must face the internet.

## Proof

- **Screen tests stand in for the UI:** `crates/gl-node/tests/web_ui_screens.rs`,
  one test per screen, each sending the query that screen will send to the
  shipped binary over loopback HTTP and checking the answer holds what the
  screen shows. Each step adds or extends the screens it serves; the new UI
  later sends the same queries.
- Per step: GraphQL tests for the new fields, the refusal of reserved keys
  and oversize records, and a two-node test that metadata replicates and
  verifies; revert checks for each new rule.
- Per step: the calls added to `docs/api/curl/` and the Insomnia collection,
  so the maintainer can try them in GraphiQL or Insomnia against a local
  node.
- Once, early: a cross-origin call from an allowed origin to
  `/ledgers/<name>/graphql` — preflight, then the call with a key — passes,
  and one from an unlisted origin is refused.
- The schema test fails if a field changes without the file.
- Register and reports agree with `account` balances to the cent on a test
  ledger.
- Docs: README (*An API for web UIs*), CHANGELOG, OPERATIONS (CORS origins
  for a Vercel UI; later, what the store does not replicate).
