# What the web UI calls, and what gl-node has (2026-11-17)

Read from the UI's code (`accounting-app/newgl-ui`, checked out locally under
`.do_not_commit_please_ignore/newgl-ui`, which this repo ignores) and from
gl-node at `b83fb6a`. The UI's TypeScript types (`src/lib/services/*`,
`src/modules/accounting/domain/models.ts`) are the contract; no other
description of `newgl-api` was used.

## How the UI talks to its API today

- One REST API, `newgl-api` (Bun + Hono over Supabase Postgres and Auth), at
  `BASE_API_URL` (`https://newgl-api.fly.dev/api` in production,
  `NEXT_PUBLIC_API_URL` overrides). The second Fly service, `newgl-ai`, is
  reached only through `newgl-api`'s `/api/ai/*`.
- Every call goes through `request()` in `src/lib/services/http-service-container.ts`:
  JSON, `Authorization: Bearer <Supabase access token>`, a 401 sends the
  browser to `/login`, a 409 `RECONCILED_TRANSACTION` asks the user and
  repeats the call with `X-Confirm-Reconciled: true`. Uploads and downloads
  (receipts, attachments, `.bean` files) call `fetch` directly.
- The calls sit in `src/lib/services/*` and a few providers and pages, behind
  a `ServiceContainer` interface (`src/modules/accounting/application/contracts.ts`).
  Swapping the transport touches those files, not the screens.
- About 110 method-and-path pairs across the areas below.

## By area

| Area | UI calls | gl-node today |
|---|---|---|
| Session, tenant | `POST /tenants/bootstrap`, `PATCH /tenants/onboarding`, `PATCH /tenants/ai-enabled`; Supabase login | Operator key and per-person keys with roles (002); no tenants |
| Companies | `GET/POST /companies`, `PATCH/DELETE /companies/{name}`, `POST /companies/{name}/switch`, `GET /company-templates` | Ledgers on one node (003): `/ledgers/{name}/graphql`; `ledgers`, `addLedger`, `removeLedger` on `/node/graphql`, operator key only; no labels or templates |
| Ledger file | `/ledgers/{name}/download`, `/upload`, `/versions`, `/versions/{v}/restore`; `/ledger-files/*` (extra `.bean` files: list, create, label, delete, download, upload, versions, restore) | Hand edits to the `.bean` are adopted and signed (T35); no download, upload or versions over HTTP |
| Accounts | `GET/POST /accounts`, `GET/PATCH/DELETE /accounts/{id}` | `accounts`, `account`, `openAccount(name, date, currencies)`, `closeAccount` |
| Transactions | `POST /transactions`, `GET /transactions?status&sourceAccountId`, `GET /transactions/{id}`, `/detail`, `POST …/post`, `…/void`, `…/reverse`, `POST /deposits`, `POST /transfers`, `POST /transactions/import` | `appendTransaction`, `journal(account, from, to, limit = 100, offset)`, `transaction(txid)` |
| Postings | `GET /ledger/postings` (every posting), `GET /ledger/transactions/{id}/postings` | Postings inside `journal` and `transaction`; no flat list |
| Register | `GET /accounts/{id}/register`, `PATCH/DELETE /register/{id}`, `POST /register/{id}/reconcile`, `POST /register/batch-update`, `/batch-delete` | None |
| Reports | Built in the browser from accounts + all postings + all posted transactions: P&L, P&L Detail, Balance Sheet, Trial Balance, Aging, By Payee, report builder, dashboard | `trialBalance(at)`, `balanceSheet(at)`, `incomeStatement(from, to)` |
| Reconciliation | setup, finish, list (per account and all), detail, undo, discrepancies, draft (get, put, delete), attachments (list, upload, download, delete) — 14 calls | None |
| Bank feed | Pending rows kept in **localStorage** (`pending-bank-txns`); `/bank-rules` (4), `/excluded-feed-rows` (3) | Bank-feed inbox (008): fetch, `bankInbox`, classify, ignore; Plaid connect, map, sync |
| Recurring | `/recurring-templates` list, create, update, delete, `advance`, `run` | None |
| Sales | `/customers` (4), `/invoices` (5, with `pay`), `/estimates` (4), `/products-services` (4) | None |
| Expenses | `/vendors` (4), `/bills` (5, with `pay`), `/mileage-entries` (3), `/receipts` (5, multipart upload, file download) | None |
| Team | `/employees` (4) | None |
| AI | `/ai/status`, `/ai/usage`, `PUT/DELETE /ai/key`, `/ai/column-mapping`, `/ai/categorize`, `/ai/rules/learn` | None |

## Mismatches that matter more than the count

1. **Edits and deletes.** The UI edits register rows, voids, reverses,
   deletes in batches, edits bills and invoices, flips cleared/reconciled
   flags, overwrites the `.bean` and restores old versions. gl-node's ledger
   is signed, append-only and replicated: no mutation amends, voids or removes
   a transaction. The bank page's Undo also voids what it posted.
2. **Account shape.** The UI's `Account` has a UUID id, `code`, one of 13
   QuickBooks categories, `subtype`, `status`, `allowManualEntries`, an opening
   and a current balance; its zod schema requires `id` to be a UUID. gl-node's
   `Account` has `name`, `opened_on`, `closed_on`, `currencies`.
3. **Transaction shape.** The UI's `Transaction` has a UUID id, a `type`
   (CHECK, DEPOSIT, EXPENSE, TRANSFER, JOURNAL_ENTRY…), a `status` (DRAFT,
   POSTED, VOIDED, DELETED), `referenceNumber`, `dueDate`, `sourceAccountId`,
   and each register row has its own id. gl-node's has a content-hash `txid`,
   `flag`, `payee`, `narration`, tags, links, postings, author, signature.
4. **Metadata is stored but not exposed.** `ledger::model` keeps metadata on
   transactions, postings and `open` directives, but `TransactionInput`,
   `openAccount` and the GraphQL `Account` and `Transaction` types carry none.
   There is no `custom` directive.
5. **Records that are not ledger entries.** Vendors, customers, employees,
   products, estimates, drafts, rules, recurring templates, receipts and
   attachments live in Postgres and Supabase Storage today.
6. **Logins.** Supabase access tokens versus gl-node's API keys, one per
   person per ledger (003 decision 2).
7. **Loading everything.** The reports read every posting; `journal` pages at
   100 and the query-cost limit (M-45) refuses large selections.

## What already fits

- Companies ↔ ledgers: the UI would choose a ledger URL instead of asking the
  server to remember an active company, so one company's data cannot show
  while another is active.
- The bank-transactions page's local queue ↔ the 008 inbox.
- gl-node's reports already compute with exact decimals (T76).
- Beancount has a `document` directive (an account, a date, a file path),
  which gl-node's model parses — a possible home for receipt links.
- gl-node serves browsers already: `cors.allowedOrigins` (explicit origins).

## Local-only state in the UI

Besides the bank queue: next check, journal and sales-receipt numbers
(should come from the ledger), extra fields on the contact detail page, and
list and column preferences (fine to keep in the browser).
