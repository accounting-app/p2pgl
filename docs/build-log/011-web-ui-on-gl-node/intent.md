# Intent: gl-node's API for a web UI

Author: Claude, with the maintainer. Status: draft (2026-11-17; decisions 1
and 5 made, 2–4 and 6–7 open).

## Problem

The only web UI we have (`accounting-app/newgl-ui`, Next.js) works against
`newgl-api` on Fly.io: a REST API over Supabase Postgres and Auth, which also
fronts `newgl-ai`. We want a web UI on gl-node, so the books it shows are a
signed, replicated `.bean` that the company owns. gl-node cannot serve one
today: the UI needs about 110 REST calls across about 20 areas, and gl-node's
GraphQL covers the ledger core only. The bigger gap is the model, not the
count: that UI edits and deletes entries in place, and gl-node's ledger is
append-only. Findings: `notes/ui-api-inventory.md`.

## Proposed outcome

- **gl-node's GraphQL API covers what an accounting web UI needs**, designed
  around the ledger, not copied from `newgl-api`: accounts with their codes
  and categories, entries with their type and reference, a paged register
  with running balances, the reports, corrections, the bank feed, and then
  the areas that are not ledger entries (contacts, bills, invoices,
  products, employees, receipts, recurring templates, reconciliations).
- **gl-node publishes its schema** as a file in the repo, so a UI generates
  a typed client from it.
- **A new web UI**, in its own repo and deployed on Vercel, is built against
  that API afterwards. It carries over the existing UI's look — components,
  theme, `DESIGN.md`, the app shell — and gains a screen as gl-node gains
  the queries behind it, so nothing on screen is a stub.
- A correction (edit, void, delete, un-reconcile) is a new record in the
  ledger, never a rewrite, and the register and reports show the books as
  corrected.
- A company is a ledger: choosing one chooses its URL and key.

## Who it is for

Small-business owners keeping their own books, and accountants serving
several companies (product direction), using the web UI against one node —
their own desk machine or a server — with other nodes of the mesh holding
copies. There are no real users of `newgl-ui` or `newgl-api` yet, so nothing
needs to stay compatible with them; both can be retired.

## Constraints

- The ledger's rules stay: signed, append-only, replicated, record formats
  v1 and v2, the wire format. A correction record is new ledger design and
  gets its own entry with tests across a restart and two nodes.
- Isolation between ledgers (003): a key from one ledger is refused by every
  other, and unknown ledger names cannot be probed.
- Nothing in gl-node may need a hosted service to run: any computer can be a
  node. The UI on Vercel is a client of the node, not part of it.
- The audit rules hold: query-cost limits (M-45), explicit CORS origins (no
  `*`), no secrets in responses, every write attributed to the person who
  entered it (002).
- Existing nodes and their clients keep working unchanged; new fields are
  additions.
- This repo stays Rust and shell; the new UI's code lives in its own repo.

## How we will know it worked

- Each gl-node unit's tests make the calls a screen would make, over
  loopback HTTP against the shipped binary.
- For a test ledger: the register's last running balance equals the
  `account` query's balance, and the reports add up to the cent with the
  register.
- An entry written through the API is in the `.bean`, signed, attributed,
  and on a second node; a correction leaves the original in the ledger, and
  both nodes show the corrected books before and after a restart.
- The committed schema file matches the running node's schema (a test).
- Later, in the UI repo: the new UI on Vercel signs in to a node, lists a
  company's accounts, shows a register and the reports, and posts an entry.

## Decisions

Made (maintainer, 2026-11-17):

1. **The API is gl-node GraphQL, built first;** the UI adapts to it
   afterwards. No REST layer copying `newgl-api`, no go-between.
5. **A new UI codebase**, its own repo, on Vercel, keeping the existing
   UI's styling. This entry covers gl-node; the UI repo has its own plan.

Open:

2. **Corrections.** (a) *Recommended:* design correction records (a reversal
   plus a record naming the entry it replaces) as their own entry, 012.
   (b) Create-only until later.
3. **Records that are not ledger entries.** (a) *Recommended:* a store on
   each node for personal data and drafts (contacts, employees, drafts),
   with what every node must agree on (bank rules, recurring templates,
   reconciliations) in the ledger. (b) Everything in the ledger — personal
   data can then never be deleted.
4. **Logins.** (a) *Recommended:* gl-node's keys and roles; the UI holds a
   key per ledger. (b) gl-node accepts Supabase tokens, which ties every
   node to Supabase.
6. **AI.** (a) *Recommended:* out of this entry; `newgl-ai` stays a separate
   service the UI may call. (b) gl-node calls a model itself.
7. **How the Vercel UI reaches a node.** (a) *Recommended:* the browser
   calls the node directly, over HTTPS, with the UI's origin in the node's
   `cors.allowedOrigins`. (b) The UI's server routes on Vercel forward calls
   to the node — keys then pass through Vercel, and the node must be
   reachable from the internet.
