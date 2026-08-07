# General Ledger API — Spec-Driven Development Document

> Single-tenant, peer-to-peer, append-only General Ledger API.
> `.bean` (Beancount) is the source of truth. GraphQL is the interface.
> Stack: **Rust + Axum + async-graphql + Iroh**, deployable on any host that meets §3.10.

**Status:** Draft · **Version:** 1.0.0 · **Method:** Spec-Driven Development (SDD) · **License target:** open source

This document is the complete specification and plan for building an interoperable `gl-node`. All normative rules needed to implement the system are contained here.

---

## 0. How to use this document

This is a *spec-first* project. The order of authority is:

```
Constitution  →  Specification (WHAT/WHY)  →  Plan (HOW)  →  Tasks  →  Code
```

Rules of engagement for every contributor and every AI agent working on this repo:

1. **No code without a spec section it satisfies.** If you're about to write something not traceable to §2 (Specification) or §3 (Plan), stop and amend the spec first in the same PR.
2. **The Constitution (§1) is non-negotiable.** A change that violates it is rejected on principle, not on taste.
3. **Invariants (§2.4) are tested, not assumed.** Every invariant has at least one property-based test.
4. **Specs change via PR.** This file is versioned with the code. A behavior change and its spec change land together.
5. **Full-word identifiers (C8).** No single-letter names, no abbreviations. Lint enforces it; a PR that adds one doesn't merge.

---

## 1. Constitution — non-negotiable principles

| # | Principle | Why it's load-bearing |
|---|-----------|----------------------|
| C1 | **`.bean` is the single source of truth.** All state is derivable from **one** Beancount ledger file per node (`ledgerPath`). Everything else (indices, DAG, caches) is a deterministic projection. | If state lived anywhere else, peers could diverge with no canonical reconciliation. |
| C2 | **Append-only.** Transactions are never mutated or deleted in place. Corrections are new transactions (reversing/adjusting entries). | This is what makes the ledger auditable and makes P2P merge commutative. |
| C3 | **Double-entry is enforced at write time.** No transaction is accepted unless its postings balance to zero per currency. | A GraphQL API has no ACID of its own; balance is *our* invariant to guard. |
| C4 | **Deterministic canonical serialization.** Given the same set of transactions, every peer renders a byte-identical `.bean`. | This is what lets union-merge converge and keeps the file git-friendly across nodes. |
| C5 | **Eventual consistency with a verifiable audit trail.** No global lock, no consensus quorum on the write path. Order is established by a content-addressed DAG. | Matches the CAP trade we chose: availability + partition tolerance + tamper-evidence over linearizability. |
| C6 | **Single tenant per instance.** One running instance serves exactly one company's ledger. No tenant-routing logic exists. | Simplifies auth, isolation, and the entire data model. Isolation is a deployment boundary, not application code. |
| C7 | **Offline-tolerant.** A node accepts writes while partitioned and reconciles on reconnect. | "Guaranteed redundancy" is meaningless if a partitioned node is read-only. |
| C8 | **Full-word identifiers.** Every identifier in code — variables, parameters, functions, types, files — is spelled out in full words. **No single-letter names and no abbreviations.** Write `transaction`, not `txn` or `t`; `account`, not `acct` or `a`; `currency`, not `cur` or `c`; `index`, not `idx` or `i`. | In an accounting system, code that reads as plain English is its own audit control — a reviewer who can't read the variable can't verify the money. Clarity outranks brevity, always. |

**The one bounded exception to C8:** the established domain nouns defined as ubiquitous language in §2.3 may be used verbatim because they *are* the full names of those concepts in this project — specifically `txid` (the content-hash identifier), `txn` (Beancount’s synonym for transaction, used only where the on-disk dialect requires it), `DAG`, and `P2P`, plus GraphQL/HTTP/QUIC/TLS/ALPN/CBOR/SSE proper nouns and Iroh type names (`EndpointId`, `SecretKey`, `TopicId`). Nothing else is exempt. When in doubt, spell it out.

---

## 2. Specification — WHAT and WHY

### 2.1 Problem & goals

Provide a programmable, replicated General Ledger over a Beancount file, so that:

- An organization can run **N redundant nodes** of its ledger with no central coordinator.
- Each node exposes a **GraphQL API** for reads (reports) and writes (journal entries).
- The ledger remains a **plaintext `.bean` file** that humans can read, edit, and version in git.
- History is **tamper-evident**. Authorship is recorded on every entry (`author`); **cryptographic** attribution is available when signing is enabled (§3.8).

### 2.2 Non-goals

- Multi-tenant SaaS, per-tenant routing, or row-level isolation. (See C6.)
- Strong/linearizable consistency or Raft consensus.
- **Any interactive presentation layer** (web UI, mobile app, desktop client). The GraphQL API is the sole supported client interface in this repository.
- Built-in issue trackers, ticketing, workflow engines, chat panels, or other adjacent product domains.
- A general-purpose database (SQLite/Postgres/etc.) as ledger or product state. Persistence is the `.bean` file plus the node's Iroh key on disk.
- Currency conversion engine beyond Beancount's native cost/price handling (§3.5.1).
- Mutable/deletable transactions.
- Multi-file ledgers / Beancount `include` (see §3.3.2).
- Using iroh-docs, iroh-blobs, or a general-purpose CRDT document store as the ledger of record. Merge is a native content-addressed G-Set over ledger directives (see §3.4).

### 2.3 Domain model & ubiquitous language

Aligned 1:1 with Beancount directives so the file stays canonical.

- **Ledger** — the full set of directives = the company's books. Materialized as **exactly one** `.bean` file per node.
- **Account** — a colon-delimited name under one of five roots: `Assets`, `Liabilities`, `Equity`, `Income`, `Expenses`. Each segment must match `[A-Z][a-zA-Z0-9-]*`. Opened with an `open` directive, optionally `close`d. An `open` with a currency list constrains the account to those currencies (I9).
- **Transaction (`txn`)** — a dated event with a flag (`*` complete / `!` incomplete), optional payee + narration, tags, links, and ≥2 **postings**. Tags match `#[a-zA-Z0-9_-]+`; links match `^[a-zA-Z0-9_-]+`.
- **Posting** — an `Account` + an `Amount` (or an elided amount to be auto-computed), optional `cost` and `price`.
- **Amount** — a decimal `number` + a `currency` (commodity). Currency names must match `[A-Z][A-Z0-9'._-]{0,22}[A-Z0-9]` (minimum 1 character for single-letter currencies like `$` is not allowed; use `USD`). Decimals only; never floats (see C3 / I4). All dates are validated as real calendar dates; `2024-02-30` or `2024-13-01` → structured parse error `INVALID_DATE`.
- **Balance assertion (`balance`)** — asserts an account equals an amount at a date. Treated as a **checkpoint**, not a write gate (§3.6).
- **Pad (`pad`)** — inserts a balancing transaction against a source account to satisfy a following `balance`. Also checkpoint-time (§3.6).
- **Commodity / Price / Note / Document / Event** — pass-through Beancount directives, preserved verbatim when present in the supported subset.
- **Transaction ID (`txid`)** — `SHA-256` of the transaction's **economic canonical form** (§3.3.1–§3.3.2). The primary key of the transaction DAG. Envelope metadata never enters this hash.
- **Directive ID (`directiveId`)** — `SHA-256` of a non-transaction directive's economic canonical form (same exclusion rules). Primary key for union-merge of opens, closes, and pass-through directives.
- **Head** — a transaction with no children in the current DAG; the frontier a peer has observed.
- **Genesis transaction** — a transaction whose `parents` set is empty. Legal only when the authoring node had zero heads at write time (empty ledger or first concurrent root). All other transactions reference ≥1 existing parent (§2.4 I8).
- **Peer identity** — the node's Iroh `EndpointId` (stable across restarts via a persisted `SecretKey`). Used as `author` on locally authored and adopted directives.
- **Envelope metadata** — reserved Beancount metadata keys prefixed `openledger-` that carry replication/audit fields inside the `.bean` file (§3.3.1). They are part of the durable SoT (C1) and **excluded** from content hashes (I5).

**Supported directive types (closed set):** `open`, `close`, `commodity`, `pad`, `balance`, `transaction` (`txn` / `*`), `note`, `document`, `event`, `price`.

**Unsupported (hard fail):** `include`, `option`, `plugin`, `pushtag`/`poptag`, `pushmeta`/`popmeta`, `custom`, and any unrecognized directive keyword. On parse or boot: refuse to load the file with a structured error naming the directive and line. GraphQL writes never emit these.

> **Usability note:** virtually every Beancount file in the wild contains `option` directives (e.g., `option "title" "..."`, `option "operating_currency" "USD"`). These must be stripped before a `.bean` file can be loaded by `gl-node`. This is intentional — options are process-level settings that have no meaning in a multi-node replicated system. A future import/migration tool may automate this stripping, but it is out of scope for the core node.

### 2.4 Invariants — the laws (each must have a test)

| ID | Invariant |
|----|-----------|
| I1 | For every transaction, the sum of posting weights is zero **per currency** (after cost/price conversion per §3.5.1). Applies to **local and remote** acceptance. |
| I2 | At most **one** posting per transaction may have an elided amount; it is computed so I1 holds. |
| I3 | A posting's account must have an `open` directive dated on or before the transaction, and no `close` dated **strictly before** the transaction date. A transaction on the same date as a `close` is **allowed** (because `close` has sort priority 9, placing it after all same-day transactions in canonical order). Applies to **local and remote** acceptance. |
| I4 | All amounts are arbitrary-precision **decimals**. No floating-point arithmetic touches money. |
| I5 | `txid = SHA-256(economic_canonical_serialize(transaction))` is stable across peers and runs (C4). Envelope keys (`openledger-*`) never enter the digest. Digest input is UTF-8 bytes per §3.3.2. |
| I6 | Union of two peers' **directive** sets, deduped by `txid` / `directiveId`, yields **identical aggregate balances** regardless of merge order (commutativity). |
| I7 | The materialized `.bean` re-parses to the exact same directive set (including envelope metadata) it was rendered from (round-trip stability). |
| I8 | The transaction DAG is acyclic. Every non-genesis transaction references ≥1 parent `txid` that exists in the DAG (after anti-entropy closes gaps). |
| I9 | If an `open` directive specifies a currency list, postings to that account must use only those currencies. A posting in an unlisted currency is rejected with `ACCOUNT_CURRENCY_MISMATCH`. An `open` with no currency list accepts any currency. |

### 2.5 Functional requirements (user stories + acceptance criteria)

**FR-1 — Append a balanced journal entry**
*As a* client, *I want* to submit a transaction, *so that* it joins the ledger on all reachable peers.
- AC1: A balanced transaction returns its `txid` and is appended to `.bean`.
- AC2: An unbalanced transaction (violates I1) is rejected with a structured error naming the imbalance and currency (§2.8).
- AC3: A posting to an unopened/closed account (I3) is rejected.
- AC4: The same logical entry submitted twice yields the same `txid` and is stored once (idempotent by content).

**FR-2 — Read core financial reports**
- AC1: `trialBalance(at: Date)` returns every account's debit/credit balance; total debits == total credits.
- AC2: `balanceSheet(at: Date)` returns Assets, Liabilities, Equity. **Report closing rule (§3.7.1):** net Income − Expenses from the earliest ledger date through `at` is included as a synthetic Equity line `Equity:Net-Income` (or folded into existing Equity totals). After that closing, Assets = Liabilities + Equity. The raw open P&L slice alone is not required to satisfy that equation.
- AC3: `incomeStatement(from, to)` returns Income and Expenses and net result for the period (`net = income − expenses` per currency).
- AC4: `journal(account?, from?, to?)` returns transactions in deterministic display order (§3.4).
- AC5: All reports read from the in-memory index; no per-request file parse (perf gate in §6).

**FR-3 — Open / close accounts**
- AC1: `openAccount` appends an `open` directive; opening an already-open account errors.
- AC2: `closeAccount` appends a `close`; closing an account with a later transaction errors.

**FR-4 — Peer replication**
- AC1: A new transaction on node A is observable on a connected node B within one gossip + anti-entropy interval (§3.11).
- AC2: A node partitioned for a period and reconnected converges to the same DAG via anti-entropy.
- AC3: After convergence, `.bean` files on A and B are **byte-identical** (C4 / I7).

**FR-5 — Audit & verification**
- AC1: `verify()` walks the DAG and confirms every `txid` matches its content and every parent link resolves (I8).
- AC2: Each transaction records the authoring peer's identity and (optionally) a signature.

**FR-6 — Health & peers**
- AC1: `health` reports node status, head count, and connected peer count.
- AC2: `peers` lists connected peer IDs and their advertised heads.
- AC3: `GET /health` returns the same counts as GraphQL `health` (§2.9).

### 2.6 GraphQL contract (the public surface)

Code-first via **async-graphql**; this SDL is the agreed shape. It is part of the spec — schema changes require a spec PR.

```graphql
scalar Date          # ISO-8601 calendar date
scalar Decimal       # arbitrary precision; serialized as string
scalar TxId          # content hash (hex)

type Amount { number: Decimal!, currency: String! }

type Posting {
  account: String!
  amount: Amount!
  cost: Amount
  price: Amount
}

type Transaction {
  txid: TxId!
  date: Date!
  flag: String!              # "*" or "!"
  payee: String
  narration: String
  tags: [String!]!
  links: [String!]!
  postings: [Posting!]!
  author: String!            # openledger-author (Iroh EndpointId)
  signature: String          # openledger-signature; optional non-repudiation
  parents: [TxId!]!          # openledger-parents (DAG edges; empty = genesis)
}

type AccountBalance { account: String!, balances: [Amount!]! }

type TrialBalanceRow { account: String!, debit: Decimal!, credit: Decimal! }
type TrialBalance { at: Date!, rows: [TrialBalanceRow!]!, totalDebit: Decimal!, totalCredit: Decimal! }

type BalanceSheet { at: Date!, assets: [AccountBalance!]!, liabilities: [AccountBalance!]!, equity: [AccountBalance!]! }
type IncomeStatement { from: Date!, to: Date!, income: [AccountBalance!]!, expenses: [AccountBalance!]!, net: [Amount!]! }

type VerifyResult { ok: Boolean!, nodesChecked: Int!, errors: [String!]! }
type Health { status: String!, heads: Int!, peers: Int!, version: String! }
type Peer { id: String!, heads: [TxId!]! }

input AmountInput { number: Decimal!, currency: String! }
input PostingInput { account: String!, amount: AmountInput, cost: AmountInput, price: AmountInput }
input TransactionInput {
  date: Date!
  flag: String = "*"
  payee: String
  narration: String
  tags: [String!] = []
  links: [String!] = []
  postings: [PostingInput!]!   # exactly one posting may omit amount (I2)
}

type Query {
  trialBalance(at: Date!): TrialBalance!
  balanceSheet(at: Date!): BalanceSheet!
  incomeStatement(from: Date!, to: Date!): IncomeStatement!
  journal(account: String, from: Date, to: Date, limit: Int = 100, offset: Int = 0): [Transaction!]!
  transaction(txid: TxId!): Transaction
  account(name: String!, at: Date): AccountBalance
  verify: VerifyResult!
  health: Health!
  peers: [Peer!]!
}

type Mutation {
  appendTransaction(input: TransactionInput!): Transaction!   # FR-1, enforces I1–I3
  openAccount(name: String!, date: Date!, currencies: [String!]): Boolean!
  closeAccount(name: String!, date: Date!): Boolean!
}

type Subscription {
  transactionAppended: Transaction!   # fires for ALL appends: local, remote/gossip, and adopted
}
```

**Subscription transport (M5):** both **GraphQL over WebSocket** (default; `graphql-transport-ws` / async-graphql Axum WS) and **SSE** are supported. Clients that do not negotiate WebSocket may use SSE. When `auth.enabled`, the same credential rules apply as for queries/mutations (§3.8).

### 2.7 Conformance suite — invariants as runnable obligations

The invariants in §2.4 are only real if they execute on every commit. This section turns each into a **named, runnable test obligation**. Prose claims ("balances converge") are not accepted as evidence; a passing property test is.

**Test method:** property-based testing (`proptest`) over generated transactions, plus a golden `.bean` corpus for parser fidelity. Each obligation runs under `cargo test`. Status tracks delivery through milestones — nothing is claimed green until its milestone lands.

| Obligation | Invariant | What the property asserts | Status |
|------------|-----------|---------------------------|--------|
| **CT-1** | I1 | For generated balanced transactions, per-currency posting sums are zero; perturbing any amount is detected as an imbalance. | ⏳ M2 |
| **CT-2** | I2 | A transaction with one elided posting resolves to a balanced transaction; two elided postings are rejected. | ⏳ M2 |
| **CT-3** | I5 | `txid` is stable across runs and identical for structurally identical transactions; matches §3.3.3 fixture. | ⏳ M2 |
| **CT-4** | I6 | Union-merge by `txid` / `directiveId` yields identical aggregate balances regardless of order; a duplicate never double-counts. | ⏳ M4 |
| **CT-5** | I7 | `parse(serialize(t))` round-trips; re-serialization is byte-identical (the C4 promise). | ⏳ M1 |
| **CT-6** | I7 | Round-trip holds against a **golden corpus** (§5.1), not just generated ones. | ⏳ M1 |
| **CT-7** | I3 | Postings to unopened/closed accounts are rejected. | ⏳ M2 |
| **CT-8** | I8 | `verify()` detects a tampered `txid` and a dangling parent link. | ⏳ M5 |
| **CT-9** | FR-4 | Partition-and-converge harness: two nodes, one partitioned then reconnected, end byte-identical. | ⏳ M4 |
| **CT-10** | §3.8 | With signing **off**, `txid`/round-trip are unaffected; with signing **on**, `verify` accepts a valid `openledger-signature` and rejects a forged one — and envelope keys never enter economic canonical serialize (toggling signing leaves every `txid` unchanged). | ⏳ M5 |
| **CT-11** | §3.3 | With `"externalFileEdits": "disabled"`, an out-of-band `.bean` change is detected at boot (file hash vs. last write) and the node refuses to start. | ⏳ M2 |
| **CT-12** | §3.3 | With external edits **enabled**, hand-appending a balanced transaction is adopted via union-merge (same result as if a peer had gossiped it); a hand-"edit" yields a new `txid` with the original retained; a hand-"delete" does not remove the transaction. | ⏳ M4 |
| **CT-13** | §3.3.1 | Two economically identical transactions with different `openledger-parents` / author / Lamport produce the **same** `txid`; full-file serialize still persists distinct envelopes for the first accepted entry only (duplicate id is a no-op). | ⏳ M1 |
| **CT-14** | §3.5 | A gossiped transaction that violates I1 or I3 is rejected and never appears in the local G-Set or `.bean`. | ⏳ M4 |
| **CT-15** | §2.3 | A file containing `include` / `option` / `plugin` / `custom` / unknown directive fails boot with a structured parse error. | ⏳ M1 |

**Gating rule:** a milestone is not "done" (§6) until its conformance obligations are ✅. The three load-bearing ones — **CT-1 (balance), CT-4 (merge commutativity), CT-5 (round-trip)** — are the properties no amount of prose can substitute for, and they exist as executable tests early in the build.

### 2.8 GraphQL error shape (normative)

Failed mutations/queries that violate ledger rules return GraphQL errors with:

| Field | Rule |
|-------|------|
| `message` | Human-readable summary |
| `extensions.code` | Machine code from the table below |
| `extensions.*` | Code-specific fields (always JSON-safe strings/numbers) |

| `extensions.code` | When | Extra fields |
|-------------------|------|--------------|
| `UNBALANCED_TRANSACTION` | I1 failure | `currency`, `imbalance` (Decimal string) |
| `ELIDED_POSTING_INVALID` | I2 failure (0 or >1 elided, or cannot resolve) | — |
| `ACCOUNT_NOT_OPEN` | I3 — no open / closed | `account`, `date` |
| `ACCOUNT_ALREADY_OPEN` | FR-3 open duplicate | `account` |
| `ACCOUNT_CLOSE_CONFLICT` | FR-3 close with later activity | `account`, `date` |
| `UNAUTHORIZED` | Missing/invalid API key when auth on | — |
| `UNSUPPORTED_DIRECTIVE` | Parse/boot of forbidden directive | `directive`, `line` |
| `INVALID_POSTING` | Illegal posting shape (e.g. both `{cost}` and `@`/`@@`) | `account` |
| `EXTERNAL_EDIT_REJECTED` | File changed while edits disabled | — |
| `INVALID_DATE` | Unparseable or impossible calendar date (e.g. `2024-02-30`) | `date` |
| `INVALID_ACCOUNT_NAME` | Account name violates `[A-Z][a-zA-Z0-9-]*` segment rule or unknown root | `account` |
| `INVALID_CURRENCY` | Currency name violates `[A-Z][A-Z0-9'._-]{0,22}[A-Z0-9]` | `currency` |
| `ACCOUNT_CURRENCY_MISMATCH` | Posting currency not in `open` directive's currency list (I9) | `account`, `currency`, `allowed` |
| `RESOURCE_LIMIT_EXCEEDED` | Transaction exceeds a §3.12 resource limit | `limit`, `actual` |
| `INTERNAL` | Unexpected server failure | — |

HTTP status for GraphQL remains 200 with `errors` array except auth failures may use **401** when the entire request is rejected before GraphQL execution.

### 2.9 REST health alias

`GET /health` (no auth required even when `auth.enabled`, so orchestrators can probe):

```json
{
  "status": "ok",
  "heads": 0,
  "peers": 0,
  "version": "<crate version>"
}
```

Field meanings match GraphQL `Health`. Non-ok process state uses `"status": "degraded"` or `"status": "error"` with HTTP 503 when the node cannot serve reads.

---

## 3. Technical Plan — HOW

### 3.1 Stack (locked)

| Layer | Choice | Note |
|-------|--------|------|
| Language / runtime | **Rust** on **Tokio** | One async runtime shared by HTTP and P2P. |
| HTTP framework | **Axum** | Composes cleanly with Tokio/Hyper; same runtime as Iroh. |
| GraphQL server | **async-graphql** + `async-graphql-axum` | Code-first schema matching §2.6. |
| Decimals | **`rust_decimal`** | Enforces I4; GraphQL `Decimal` is a string on the wire. |
| P2P | **Iroh** (`Endpoint` + `Router`) | QUIC transport, relay / hole-punch for NAT. |
| Gossip | **iroh-gossip** | Announce new ids on a shared `TopicId`. |
| Anti-entropy | Custom protocol over Iroh ALPN `openledger/anti-entropy/1` | Length-prefixed CBOR (§3.4.1). |
| Merge | Native **G-Set union by `txid`** | No external CRDT document store; see §3.4. |
| Hashing / DAG | SHA-256 + Merkle parent links | Content addressing for merge and `verify`. |
| CBOR | `ciborium` or equivalent | Deterministic encode of wire messages. |
| Binary | `gl-node` | Single statically linked (or thin-container) node. |

**Version pinning:** at M0, pin `iroh` + `iroh-gossip` (and other deps) in `Cargo.lock`. Upgrades are deliberate PRs that re-run CT-9.

### 3.2 Architecture & layers

```
┌──────────────────────────────────────────────┐
│ GraphQL (async-graphql)  ← Axum HTTP / WS/SSE │  interface
├──────────────────────────────────────────────┤
│ Ledger service                                │  domain
│  • validate (I1–I3)  • append  • report       │
├──────────────────────────────────────────────┤
│ Read model (in-memory indices)                │  projection
│  • account tree  • running balances           │
│  • postings-by-account  • by-date journal      │
├──────────────────────────────────────────────┤
│ Transaction DAG (content-addressed)           │  core state
│  • txid hashing  • parents  • topo order      │
├──────────────────────────────────────────────┤
│ Persistence: canonical .bean serializer       │  source of truth (C1)
├──────────────────────────────────────────────┤
│ Replication: Iroh gossip + ALPN anti-entropy  │  P2P
└──────────────────────────────────────────────┘
```

Dependencies point **downward only**. The GraphQL layer never touches `.bean` or Iroh directly — it calls the Ledger service. The P2P layer calls into the ledger only through a narrow insert / head-query surface.

**Workspace layout:**

```
crates/
  gl-node/          # binary: config, boot, Axum, Iroh Router
  ledger/           # parse, serialize, hash, dag, validate, read_model, service
  p2p/              # gossip, anti_entropy, wire protocol, union_merge
  security/         # auth, identity, sign, verify, checkpoint helpers
```

Root `Cargo.toml` is a workspace. Client tooling is out of scope for this repository.

### 3.3 Source of truth & the derived DAG (the key design decision)

`.bean` is the source of truth (C1), **and** we need content addressing for P2P merge. We reconcile this as follows:

- On **boot**: if `ledgerPath` does not exist, create an empty file (the ledger starts with zero directives; the first `openAccount` / `appendTransaction` will be genesis). Then parse `.bean` → for each directive compute its content id (`txid` or `directiveId`) from the **economic** canonical form (§3.3.1) → rebuild the transaction DAG from **persisted envelope metadata** (parents, author, Lamport, signature) → build the read model. The file is authoritative; the DAG is derived and reproducible **without inventing parent edges**.
- On **append/merge**: update the G-Set and DAG, then **re-render** the full ledger to `.bean` via the canonical serializer (C4) and write atomically (temp file + rename). Envelope metadata is written into the file with every directive that needs it.
- Because serialization is deterministic, two peers with the same directive set produce **byte-identical** `.bean` (I7).

This makes `.bean` simultaneously the durable truth *and* a clean replication artifact — effectively "git's content-addressed merge, automated."

#### 3.3.1 Economic hash vs envelope metadata (C1 + I5)

**Problem:** Parent links, authorship, Lamport clocks, and signatures are required for replication and audit, but must not redefine economic identity (FR-1 AC4: same journal body → same `txid`).

**Rule:** Split every directive into two layers that both live in the `.bean` file:

| Layer | What it contains | In `.bean`? | In content hash? |
|-------|------------------|-------------|------------------|
| **Economic body** | Date, flag, payee, narration, tags, links, postings (transactions); account/currencies/etc. for other directives; plus any **non-reserved** Beancount metadata | Yes | **Yes** — this is `economic_canonical_serialize` |
| **Envelope** | Reserved metadata keys prefixed `openledger-` | Yes (C1) | **No** — never enters `txid` / `directiveId` |

**Reserved envelope keys (transactions):**

| Key | Value | Notes |
|-----|-------|-------|
| `openledger-parents` | Comma-separated list of parent `txid`s, **sorted ascending**, or empty string for genesis | Rebuilds Merkle edges on boot |
| `openledger-author` | Iroh `EndpointId` string | Authorship record |
| `openledger-lamport` | Decimal integer (Lamport clock at authoring) | Display-order tie-break (§3.4.2) |
| `openledger-signature` | Signature bytes as lowercase hex, or absent when signing off | Side metadata; toggling signing must not change any `txid` |

**Reserved envelope keys (non-transaction directives):** `openledger-author`, `openledger-lamport`, and optional `openledger-signature`. Parents apply only to the **transaction DAG**.

**Hash formulas:**

```
txid        = lowercase_hex( SHA-256( UTF-8( economic_canonical_serialize(transaction) ) ) )
directiveId = lowercase_hex( SHA-256( UTF-8( economic_canonical_serialize(non_transaction_directive) ) ) )
```

Economic serialization **strips** every metadata key with prefix `openledger-` before hashing. Full-file serialization for persistence **includes** those keys (sorted among metadata per §3.3.2) so boot can restore the DAG.

**Idempotency (FR-1 AC4):** Two submissions with the same economic body yield the same `txid` even if parents/author/Lamport differ. Store once (G-Set). If a duplicate arrives with different envelope data, keep the **first-accepted** envelope; log a metric `duplicate_envelope_ignored`; do not fork the economic entry. (Property test: CT-3 / CT-4 / CT-13.)

**Two write paths, switchable by config.** Both the API *and* direct human/git edits to `.bean` are supported. Config key `"externalFileEdits": "enabled" | "disabled"` — `"disabled"` collapses the system to API-sole-writer mode (file is an owned projection; unexpected on-disk modification → refuse boot with `EXTERNAL_EDIT_REJECTED`). Default is `"enabled"`.

When `"enabled"`, external edits reconcile through the **same union-merge used for peer gossip**. A file watcher (debounce **250ms**; coalesce bursts) plus a boot-time content-hash check detects change, re-parses, content-addresses each directive, and unions into the G-Set / DAG. Concurrent API append and watcher: API takes a ledger write lock; watcher waits; both end with a full re-serialize so the file matches the G-Set. *An external edit and a peer's gossip are the identical operation.*

Hand-appended transactions that lack envelope keys are adopted by stamping `openledger-author` / `openledger-lamport` locally and setting `openledger-parents` to the adopter's current heads (or empty if genesis). They are signed if signing is on. Economic body is unchanged, so `txid` remains content-defined.

The consequence you must understand before enabling it — **because the ledger is append-only (C2), a `.bean` file does not behave like an ordinary text file:**
- **Adding** a balanced transaction by hand → adopted into the DAG and gossiped.
- **Editing** an existing transaction's **economic** text → changes its `txid`, so it becomes a *new* transaction; the original is **not** removed. To truly correct, write a reversing/adjusting entry.
- **Deleting** a line → is **not** a delete. The directive still exists in the G-Set and on every peer; anti-entropy will re-materialize it. Retraction must be an explicit reversing entry.

#### 3.3.2 Canonical `.bean` format (normative)

Hand-written recursive-descent parser + matching serializer. Only the §2.3 closed directive set is accepted.

##### Directive ordering (full-file serialize)

Directives are sorted by a three-level key:

1. **Date** (ascending, lexicographic `YYYY-MM-DD`)
2. **Type priority** (numeric, lower = earlier):
   - `open` (0), `commodity` (1), `pad` (2), `balance` (3), `transaction` (4), `note` (5), `document` (6), `event` (7), `price` (8), `close` (9)
3. **Stable sort key** (type-specific, lexicographic):
   - Transaction: `narration|payee` (empty string if absent)
   - Open/Close: `account`
   - Balance: `account|amount`
   - Pad: `account|sourceAccount`
   - Commodity: `currency`
   - Price: `currency|amount`
   - Note: `account|comment`
   - Document: `account|path`
   - Event: `name|value`

##### Transaction header

```
YYYY-MM-DD FLAG "payee" "narration" #tag1 #tag2 ^link1
```

- `FLAG` is `*` or `!`
- Payee and narration are double-quoted when present
- If only narration (no payee): `YYYY-MM-DD FLAG "narration"`
- If neither payee nor narration: `YYYY-MM-DD FLAG`
- Tags prefixed `#`, links prefixed `^`; both lists **sorted lexicographically** before emit
- Metadata lines (if any) follow the header, then postings

##### Posting lines

```
  Account                                     NUMBER CURRENCY
```

- Exactly **2** spaces of indentation
- Amount **number** starts at **column 52** (1-based). If `len("  " + account) ≥ 51`, use a minimum **2**-space gap before the amount
- Cost: `{NUMBER CURRENCY}` after amount (single space before `{`)
- Unit price: `@ NUMBER CURRENCY`; total price: `@@ NUMBER CURRENCY`
- Elided amount: account only (no number/currency); used only when I2 applies

##### Amount formatting

- Emit the decimal with its stored scale (no scientific notation, no thousands separators)
- Negative amounts: leading `-` with no space (`-1000.00`)
- Currency: one space after the number

##### Strings & metadata

- Strings double-quoted; escape `\"` and `\\` only
- Metadata: `  key: "value"` — 2-space indent; keys **sorted alphabetically**; values are **strings only** (always quoted). Non-string metadata values (bare numbers, dates, amounts, booleans) are **not supported** — the parser rejects them with a structured parse error. This is a deliberate simplification from Beancount's full metadata value types.
- Envelope keys sort among all metadata by the same alphabetical rule

##### Whitespace & comments

- Line endings: `\n` only (never `\r\n`)
- Exactly one blank line between top-level directives
- File ends with exactly one `\n`
- Top-level `;` comments preserved at the **beginning** of the file (order preserved); inline comments are dropped on canonicalize

##### Economic vs full-file serialize

- **`economic_canonical_serialize(directive)`:** serialize that directive alone per the rules above, **omitting** every `openledger-*` metadata key; **include** a trailing `\n` after the last line of the directive; **do not** include the inter-directive blank line. Hash the UTF-8 bytes of that string.
- **`full_file_serialize(ledger)`:** optional leading comments, then all directives in order with one blank line between, envelope metadata included, file ends with `\n`.

##### Non-transaction directive shapes (canonical)

```
YYYY-MM-DD open Account [CURRENCY ...]
YYYY-MM-DD close Account
YYYY-MM-DD commodity CURRENCY
YYYY-MM-DD pad Account SourceAccount
YYYY-MM-DD balance Account NUMBER CURRENCY
YYYY-MM-DD price CURRENCY NUMBER OTHERCURRENCY
YYYY-MM-DD note Account "comment"
YYYY-MM-DD document Account "path"
YYYY-MM-DD event "name" "value"
```

Optional metadata blocks follow the first line the same way as transactions.

#### 3.3.3 Worked `txid` fixture (normative)

Economic body (UTF-8, note spacing to column 52):

```
2024-01-15 * "Acme Corp" "Initial funding"
  Assets:Cash                                      1000.00 USD
  Equity:Opening-Balances                          -1000.00 USD
```

(The amount `1` of `1000.00` begins at column 52 on each posting line; the string ends with `\n` after the second posting.)

```
txid = dd4a9ec5ec298be6edaa02c4408c0b1cb1b25eb51426599b7eda600cfc5fa88f
```

Full-file form may add envelope metadata without changing `txid`, e.g.:

```
2024-01-15 * "Acme Corp" "Initial funding"
  openledger-author: "<EndpointId>"
  openledger-lamport: "1"
  openledger-parents: ""
  Assets:Cash                                      1000.00 USD
  Equity:Opening-Balances                          -1000.00 USD
```

CT-3 must assert this fixture’s `txid` matches.

### 3.4 Consistency & replication protocol

- **Identity:** transactions are content-addressed (`txid`); other directives by `directiveId`. Transaction parents = the set of heads the author observed at write time → a Merkle-DAG. Genesis = empty parents (§2.3).
- **G-Set union:** Merge = union of all directives keyed by `txid` / `directiveId`, deduped. Commutative for balances (I6) because each transaction is internally balanced (I1) and non-transaction directives are immutable facts.
- **Gossip:** new ids (payload may be id-only or full envelope) via **iroh-gossip** on `TopicId` from §3.4.3.
- **Anti-entropy:** on connect and every `p2p.antiEntropyIntervalMilliseconds`, peers exchange heads + non-transaction id digests over ALPN; lagging peer pulls until closed.
- **Display order:** topological sort of the **transaction** DAG, tie-broken by `(date, openledger-lamport, txid)`. Non-transaction directives interleave by §3.3.2 file order.
- **No write blocks on peers.** Append locally and gossip; convergence on reconnect (FR-4 AC2).

#### 3.4.1 Wire protocol (normative)

- **ALPN:** `openledger/anti-entropy/1`
- **Framing:** each message is `uint32_be length || cbor_body` (length = CBOR body byte count; max **16 MiB**)
- **CBOR map** (keys are ASCII strings). Every message includes `"v": 1`. Unknown `v` → close the stream and increment metric `wire_version_rejected`.

| `type` | Fields | Purpose |
|--------|--------|---------|
| `announce` | `id` (string hex), `kind` (string: `transaction`\|`open`\|`close`\|`commodity`\|`pad`\|`balance`\|`note`\|`document`\|`event`\|`price`) | Gossip/push hint |
| `have_heads` | `head_txids` ([string]), `directive_ids` ([string], optional compact set) | Advertise frontier |
| `want` | `ids` ([string]) | Request missing |
| `supply` | `entries` ([object]) | Each entry: `id`, `kind`, `economic_bean` (string, economic canonical text without envelope), `envelope` (map of `openledger-*` → string) |

Peers MUST verify `id == hash(economic_bean)` before accept (§3.5).

#### 3.4.2 Lamport clocks

Each node keeps a monotonic integer `lamport_clock` (u64), persisted beside the Iroh key (or derived on boot as `max(openledger-lamport)+1` over the ledger).

- **Local write:** `lamport_clock := lamport_clock + 1`; stamp `openledger-lamport` with that value.
- **Remote adopt:** let `remote =` parsed Lamport; `lamport_clock := max(lamport_clock, remote) + 1` (standard Lamport receive). Do **not** rewrite the remote entry’s stamped Lamport.
- Display tie-break uses the **stamped** value on the directive, not the live clock.

#### 3.4.3 TopicId derivation

```
topic_preimage = UTF-8( p2p.swarmTopic )           # default "openledger/transactions"
TopicId        = first 32 bytes of SHA-256( topic_preimage )
```

(Iroh `TopicId` is 32 bytes; use that digest directly.)

#### 3.4.4 Orphan buffer & cycles

- If a remote transaction’s parents are missing: buffer up to **10_000** orphans or **1 hour** (whichever first); enqueue parent ids on `want`.
- On parent arrival: re-attempt insert.
- Before insert: reject if adding the edge would create a cycle (I8); emit metric `cycle_rejected`.
- Genesis (`parents` empty) accepted only if valid economically; multiple concurrent genesis roots are allowed when authored under empty heads.

### 3.5 Double-entry validation (write path)

**Concurrency:** all write operations (local mutations, file-watcher reconciliation, and remote gossip inserts) are serialized through a single **write lock** on the ledger state. Concurrent `appendTransaction` calls are queued; the second caller's `openledger-parents` will reflect the first caller's `txid` if it completes first. This lock is the consistency boundary — reads (queries, reports) use a read lock and proceed concurrently with each other but wait for any active write.

On `appendTransaction` (local client write):

1. Validate input against §3.12 resource limits; reject with `RESOURCE_LIMIT_EXCEEDED` if exceeded.
2. Validate account names (segment rule), currency names, date validity; reject with the appropriate error code (§2.8).
3. Resolve elided posting (I2): at most one; compute it so per-currency **weights** (§3.5.1) sum to zero.
4. Sum weights per currency using decimals (I4).
5. Reject if any currency's sum ≠ 0 (I1) with `UNBALANCED_TRANSACTION` (§2.8).
6. Check account `open`/`close` validity (I3) and currency constraints (I9).
7. Compute `txid` from the economic body only (§3.3.1). Set `openledger-parents` to current heads (empty iff genesis). Set `openledger-author` to local `EndpointId`, assign Lamport (§3.4.2), optionally sign (§3.8.1).
8. Insert into DAG / G-Set → update read model → re-serialize `.bean` (including envelope) → gossip → publish subscription (to all subscribers, including for remote/adopted appends).

**Genesis flow:** a fresh empty ledger has no accounts. The client must call `openAccount` before `appendTransaction` — I3 requires each posting's account to be open. The first `openAccount` on an empty ledger is the first directive; the first `appendTransaction` after that is the genesis transaction (empty parents).

On `openAccount` / `closeAccount` (and when adopting other non-transaction directives):

1. Validate account lifecycle rules (FR-3).
2. Compute `directiveId` from the economic body; stamp envelope author / Lamport / optional signature.
3. Union into the G-Set → re-serialize → gossip.

**Remote inserts (gossip / anti-entropy) — same acceptance laws as local writes:**

1. Verify content hash matches claimed `txid` / `directiveId` (I5).
2. For transactions: enforce I1, I2, and I3 on the economic body. An unbalanced or account-invalid remote transaction is **rejected** and must not enter the G-Set (C3).
3. Validate envelope shape (sorted parents, parseable Lamport, author present). Apply §3.4.4 for missing parents / cycles.
4. If signing is enabled, verify `openledger-signature` per §3.8.1; if signing is disabled, unsigned entries are accepted.
5. Skip GraphQL client auth (peer transport is separately authenticated via Iroh); never skip ledger invariants.

Duplicate id → no-op (idempotent G-Set add); first-accepted envelope wins (§3.3.1).

#### 3.5.1 Posting weights (cost / price)

Weights are the amounts that must sum to zero **per currency** (I1). Use `rust_decimal` only. **Every posting contributes exactly one weight** under these rules:

| Posting form | Weight for I1 |
|--------------|---------------|
| `NUMBER CURRENCY` (no cost, no price) | `NUMBER` in `CURRENCY` |
| `NUMBER CURRENCY {COST_NUMBER COST_CURRENCY}` (no `@`/`@@`) | `NUMBER × COST_NUMBER` in `COST_CURRENCY` (sign of `NUMBER` preserved) |
| `NUMBER CURRENCY @ PRICE_NUMBER PRICE_CURRENCY` | `NUMBER × PRICE_NUMBER` in `PRICE_CURRENCY` |
| `NUMBER CURRENCY @@ TOTAL_NUMBER TOTAL_CURRENCY` | `TOTAL_NUMBER` in `TOTAL_CURRENCY` |

- When `@` / `@@` / `{cost}` convert into another currency, the commodity **units** may be retained for display/inventory metadata but **do not** enter the I1 sum.
- If both `{cost}` and `@`/`@@` appear on one posting: **reject** with `INVALID_POSTING`.
- Elided posting: choose the unique amount that makes all per-currency weight sums zero; if not unique → `ELIDED_POSTING_INVALID`.

Inventory lot tracking / booking methods beyond these weights are **out of scope**. Cash-style ledgers need not emit cost/price.

### 3.6 Balance assertions & pad as checkpoints

`balance`/`pad` can't be per-write gates in an eventually-consistent system (a peer may not yet have all prior transactions). Therefore:

- **Quiescence:** a date range `[from, to]` is quiescent when the anti-entropy want-queue has no ids whose economic date ≤ `to`, and no orphan buffer entries dated ≤ `to`, for **≥ 1 anti-entropy interval**.
- Assertions are evaluated at **checkpoint** boundaries when the range covering the assertion date is quiescent.
- A failed assertion is **reported** (via `verify` and logs), never used to reject incoming transactions.
- **Pad generation (deterministic):** pad transactions are generated **only when the assertion date range is quiescent** (see above). This ensures all peers that have converged to the same directive set compute the same pad `txid`. A peer that generates a pad before convergence would produce a different `txid` than peers that have more transactions — the quiescence gate prevents this divergence.

  When evaluating `YYYY-MM-DD pad Account SourceAccount` followed by a `balance` on `Account` for amount `B` in currency `C` at date `D`:
  1. Let `current` = account balance of `Account` in `C` after all transactions with date `< D` (and same-day transactions that sort before the balance per §3.3.2).
  2. Let `delta = B − current`.
  3. If `delta = 0`, no pad transaction.
  4. Else synthesize a transaction:
     - date = pad directive date
     - flag `*`
     - payee absent; narration exactly `Pad Account`
     - postings: `Account  delta C` and `SourceAccount  -delta C`
     - envelope: author = local node; parents = current heads; Lamport per §3.4.2; sign if enabled
  5. Insert via the normal union path (so `txid` is content-defined). All peers with the same directive set produce the same pad `txid`.

### 3.7 Read model & indices

Built on boot, updated incrementally on append:

- **Account tree** — hierarchy + open/close state.
- **Running balances** — per account, per currency; supports `at: Date`.
- **Postings-by-account** — for `journal(account)` and `account()`.
- **By-date index** — for period reports and journal pagination.

Reports never re-parse the file (FR-2 AC5; perf gate §6).

#### 3.7.1 Balance sheet closing

For `balanceSheet(at)`:

1. Sum Assets / Liabilities / Equity account balances as of `at`.
2. Compute `net_income` = sum(Income) − sum(Expenses) for dates ≤ `at`.
3. Add `net_income` into Equity as account `Equity:Net-Income` (per currency).
4. Assert in tests: Assets = Liabilities + Equity (per currency).

### 3.8 Security & peer identity

- **Instance auth:** single-tenant → one instance-scoped API key (and optional mTLS later) on the GraphQL endpoint. Middleware from **M0** (disabled by default). Production Go/No-Go before public bind: `auth.enabled=true`, non-empty `auth.apiKey`, TLS terminated in-process or by the host (§3.9).
- **API key header:** when `auth.enabled`, require header `X-Api-Key: <auth.apiKey>` on GraphQL HTTP, WebSocket upgrade, and SSE. Missing/mismatch → `UNAUTHORIZED` / HTTP 401. `GET /health` is exempt (§2.9).
- **Peer identity:** Iroh `SecretKey` persisted on disk (CAP-4). Transactions carry `author` via `openledger-author` = `EndpointId`. Hand-adopted directives are stamped with the adopting node's identity.
- **Non-repudiation — optional, pluggable.** Signing **off by default**. Trait `SignatureProvider` with `NoopSignatureProvider` and `PeerKeySignatureProvider`. Config `signing.enabled` selects. Signatures are envelope-only (§3.3.1).

  **Integrity vs attribution:**
  - *Tamper-evidence* from content addressing and the Merkle-DAG (CT-8 / I8).
  - *Attribution:* unsigned → self-asserted author among trusted peers; signed → cryptographic proof (§3.8.1).

- **Transport:** Iroh QUIC between peers; TLS on the public GraphQL endpoint (in-process or host-terminated).

#### 3.8.1 Signature scheme (when `signing.enabled`)

- **Key:** the node's Iroh `SecretKey` (Ed25519).
- **Message (domain-separated UTF-8):**
  - Transaction: `openledger-sig-v1|txid|<64-hex-txid>`
  - Other directive: `openledger-sig-v1|directiveId|<64-hex-directiveId>`
- **Signature:** Ed25519 over the UTF-8 message bytes; store **lowercase hex** of the raw 64-byte signature in `openledger-signature`.
- **Verify:** recompute id from economic body; rebuild message; verify with author’s public key derived from `openledger-author` (`EndpointId`). Failure → reject remote insert; `verify` query reports error.
- Signing **off:** omit `openledger-signature`; verifiers treat unsigned as acceptable.

### 3.9 Deployment topology

- One long-lived process per node (`gl-node`), each with a **persistent volume** for `.bean` + Iroh key material.
- **Addressability:** public IP / IPv6 where available; otherwise Iroh relay + hole-punch (CAP-3).
- **Discovery — static bootstrap + tickets (with optional relay).** Configured bootstrap `EndpointId`s (and optional connection tickets) suffice for small fixed meshes. Relay / hole-punch are additive. Local-network convenience discovery may be used in development only.
- Container image: multi-stage Rust build → slim or distroless runtime; expose HTTP and the Iroh QUIC ports as required.
- **Graceful shutdown:** on `SIGTERM` / `SIGINT`, the node (1) stops accepting new GraphQL requests, (2) completes in-flight requests (with a **10-second** drain timeout), (3) flushes any pending `.bean` write via the normal atomic temp-file + rename, (4) closes Iroh gossip/anti-entropy connections, and (5) exits. No data is lost because every accepted mutation has already been atomically persisted before its response was sent.

### 3.10 Host capability contract (the agnosticism boundary)

The architecture is **host-agnostic but not paradigm-agnostic**: it runs on any infrastructure that satisfies the capability contract below, and on none that can't. A cloud provider (Fly.io, bare metal, VPS, etc.) is a **reference deployment**, not a dependency. To claim "we support host H," verify H against this contract.

**Required capabilities (hard floors — derived from the Constitution):**

| Cap | Requirement | Spec origin | Why it's non-negotiable |
|-----|-------------|-------------|-------------------------|
| **CAP-1** | Persistent local filesystem with atomic rename (POSIX `rename(2)`), surviving restarts | C1, §3.3 | `.bean` is the durable source of truth; writes are temp-file + atomic swap. |
| **CAP-2** | Long-lived process: lifetime not bounded per-request; enough RAM to hold the read model | §3.7 | The in-memory index is rebuilt on boot and updated incrementally; per-request cold starts forbid it. |
| **CAP-3** | One inbound-reachable address (public IPv6/IPv4, or relay / hole-punch) | §3.4, §3.9 | Peers must be dialable; egress-only / locked-NAT silently breaks redundancy. |
| **CAP-4** | Stable peer identity across restarts (persist the Iroh `SecretKey` on CAP-1 disk) | §3.8 | Peer ID continuity keeps the DAG's `author` attribution and discovery stable. |
| **CAP-5** | Outbound QUIC/UDP (and TCP if used for HTTP egress) to other peers + the bootstrap / relay set | §3.4 | Anti-entropy and gossip need to dial out. |

**Optional / nice-to-have (improve ops, never required):**

- Anycast or multi-region (geo-spread peers) — performance, not correctness.
- Managed TLS termination — else terminate in-process.
- Local-network discovery — convenient in development only.

**Portability matrix** — same domain code, deploy config differs:

| Host | CAP-1 disk | CAP-2 process | CAP-3 address | Verdict |
|------|-----------|---------------|---------------|---------|
| **Bare metal** | Native disk | systemd unit | Public IP | ✅ |
| **VPS** (Hetzner / DO / Vultr / etc.) | Block volume | VM process | Public IP | ✅ |
| **Fly.io** | Volumes | Machines | Public IPv6 / relay | ✅ |
| **AWS/GCP VM** | EBS / PD | VM/container | Elastic / public IP | ✅ |
| **Kubernetes** | PVC | StatefulSet | LoadBalancer / NodePort + relay care | ✅ With care |
| **Serverless request/response only** | ✗ | ✗ | ✗ | ❌ Disqualified |
| **Object-store-only + coordinator** | different SoT | different model | via vendor edge | ⚠️ Different architecture — not this design |

**Rule:** a host that fails any of CAP-1…CAP-5 is not "harder to support" — it's a **different architecture**. Don't weaken the caps to fit it.

### 3.11 Configuration surface (normative keys)

`gl-node.config.json` (path overridable by env `GL_NODE_CONFIG`). Nested objects use JSON nesting (not dotted keys on disk).

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `ledgerPath` | string | **required** | Path to the single `.bean` file (created if missing — see §3.3) |
| `bindAddress` | string | `"127.0.0.1"` | HTTP listen address. Use `"0.0.0.0"` for container/remote access. |
| `port` | number | `4000` | HTTP listen port |
| `externalFileEdits` | `"enabled"` \| `"disabled"` | `"enabled"` | §3.3 external write path |
| `auth.enabled` | boolean | `false` | Require `X-Api-Key` |
| `auth.apiKey` | string | — | Required when `auth.enabled` |
| `signing.enabled` | boolean | `false` | §3.8.1 |
| `p2p.enabled` | boolean | `false` | Iroh mesh |
| `p2p.secretKeyPath` | string | beside ledger | Persisted Iroh `SecretKey` |
| `p2p.bootstrapEndpointIds` | string[] | `[]` | Bootstrap peers |
| `p2p.gossipIntervalMilliseconds` | number | `5000` | iroh-gossip announce cadence |
| `p2p.antiEntropyIntervalMilliseconds` | number | `5000` | ALPN head-exchange cadence |
| `p2p.swarmTopic` | string | `openledger/transactions` | TopicId preimage (§3.4.3) |

Unknown keys are rejected at boot (fail closed). When `auth.enabled` and `auth.apiKey` missing/empty → boot fail. When `p2p.enabled` and secret key path unreadable → boot fail.

**Example:**

```json
{
  "ledgerPath": "./data/ledger.bean",
  "bindAddress": "127.0.0.1",
  "port": 4000,
  "externalFileEdits": "enabled",
  "auth": { "enabled": false, "apiKey": "" },
  "signing": { "enabled": false },
  "p2p": {
    "enabled": false,
    "secretKeyPath": "./data/iroh.secret",
    "bootstrapEndpointIds": [],
    "gossipIntervalMilliseconds": 5000,
    "antiEntropyIntervalMilliseconds": 5000,
    "swarmTopic": "openledger/transactions"
  }
}
```

### 3.12 Resource limits (normative defaults)

To bound memory and prevent abuse, the following limits are enforced on write. Each produces `RESOURCE_LIMIT_EXCEEDED` (§2.8) when exceeded.

| Limit | Default | Applies to |
|-------|---------|------------|
| Max postings per transaction | **1000** | `appendTransaction` input validation |
| Max narration length | **10 000** UTF-8 bytes | `appendTransaction` |
| Max payee length | **1 000** UTF-8 bytes | `appendTransaction` |
| Max tags per transaction | **100** | `appendTransaction` |
| Max links per transaction | **100** | `appendTransaction` |
| Max metadata keys per directive | **100** | Any directive (parse + API) |

These limits are not configurable in V1. They exist as named constants in the codebase so they can be promoted to config keys later without a spec change.

---

## 4. Implementation plan — milestones → tasks

Each milestone ends with passing tests for its acceptance criteria and is independently demoable.

**M0 — Scaffold & contracts**
- [ ] Cargo workspace (`gl-node`, `ledger`, `p2p`, `security`); lint/format (`clippy`, `rustfmt`); CI (`cargo test`); pin deps in `Cargo.lock`.
- [ ] async-graphql schema matching §2.6; mounted on Axum; resolvers stubbed.
- [ ] `Decimal`, `Date`, `TxId` scalars (Decimal as string).
- [ ] Config loader for §3.11; auth middleware (`X-Api-Key`) present (disabled by default).
- [ ] `GET /health` and GraphQL `health` both return the same head/peer counts (§2.9).
- *Done when:* schema introspects and stubs return typed placeholders; `/health` responds.

**M1 — Beancount parse & canonical serialize (C1, C4)**
- [ ] Parser for the directive subset in §2.3, including `openledger-*` envelope metadata round-trip; hard-fail unsupported directives (CT-15).
- [ ] Deterministic economic + full-file serializers per §3.3.2 (hash exclusions pinned).
- [ ] `txid` / `directiveId` hashing (I5); golden corpus (§5.1); fixture CT-3 / CT-5 / CT-6.
- *Done when:* parse → serialize → parse is stable and byte-identical across runs; envelope survives round-trip; economic hash ignores envelope; §3.3.3 fixture matches.

**M2 — Ledger core & double-entry (C2, C3, I1–I4)**
- [ ] DAG structure from envelope parents; genesis; topo order (§3.4).
- [ ] Validation pipeline (§3.5 / §3.5.1) with property tests for I1/I2 (CT-1, CT-2); I3 (CT-7); external-edit boot check (CT-11).
- [ ] `appendTransaction`, `openAccount`, `closeAccount` wired to real logic; error codes §2.8.
- *Done when:* FR-1, FR-3 acceptance criteria pass.

**M3 — Read model & reports (FR-2)**
- [ ] Indices (§3.7); incremental update on append; balance-sheet closing (§3.7.1).
- [ ] `trialBalance`, `balanceSheet`, `incomeStatement`, `journal`, `account`.
- [ ] Perf gate: report from index, not file (§6).
- *Done when:* FR-2 AC1–AC5 pass.

**M4 — Replication (FR-4, I6)**
- [ ] Iroh `Endpoint` + `Router`; bootstrap / tickets; optional relay; TopicId §3.4.3.
- [ ] iroh-gossip announces; ALPN anti-entropy with length-prefixed CBOR (§3.4.1).
- [ ] Native union-merge; remote path enforces I1–I3; orphan buffer (§3.4.4); byte-identical convergence (CT-4, CT-9, CT-12).
- *Done when:* two nodes converge after a simulated partition; unbalanced remote gossip is rejected.

**M5 — Audit, checkpoints, subscriptions, security (FR-5, §3.6, §3.8)**
- [ ] `verify` walks DAG (I8) + signature checks (CT-8, CT-10).
- [ ] Balance/pad checkpoint evaluation (§3.6).
- [ ] Peer signing via Iroh key (§3.8.1); production auth checklist.
- [ ] GraphQL `transactionAppended`: **WebSocket default + SSE**; authenticated like queries when auth is on.
- *Done when:* FR-5, FR-6 pass; tampering is detected; subscription delivers local appends.

**M6 — Deploy (§3.9)**
- [ ] Release binary / multi-stage container; volume + QUIC/HTTP ports.
- [ ] Multi-node smoke test; verify peer addressability (with and without relay).
- *Done when:* a 3-node cluster converges in production-like topology.

---

## 5. Build instructions (concrete)

```bash
# 0. Prereqs: Rust stable toolchain (rustup)
rustc --version
cargo --version

# 1. From the repo root — build the node
cargo build -p gl-node

# 2. Run (dev)
cargo run -p gl-node

# 3. Test
cargo test
cargo test -p ledger
cargo test -p p2p

# 4. Release binary
cargo build -p gl-node --release
# → target/release/gl-node
```

Suggested layout:

```
openledger/
├─ SPEC.md                  ← this document
├─ Cargo.toml               ← workspace
├─ crates/
│  ├─ gl-node/              ← Axum + Iroh bootstrap
│  ├─ ledger/
│  │  ├─ parse.rs
│  │  ├─ serialize.rs
│  │  ├─ dag.rs
│  │  ├─ validate.rs
│  │  ├─ read_model.rs
│  │  └─ service.rs
│  ├─ p2p/
│  │  ├─ gossip.rs
│  │  ├─ anti_entropy.rs
│  │  └─ union_merge.rs
│  └─ security/
│     ├─ auth.rs
│     ├─ identity.rs
│     └─ sign.rs
├─ testfixtures/            ← golden .bean corpus (§5.1)
└─ deploy/                  ← container + compose / unit files
```

### 5.1 Golden corpus contract (`testfixtures/`)

Minimum fixtures for CT-5 / CT-6:

| File | Must exercise |
|------|----------------|
| `fixture-simple.bean` | §3.3.3 transaction + opens; envelope round-trip |
| `fixture-multicurrency.bean` | ≥2 commodities; I1 per currency |
| `fixture-cost-price.bean` | `@` and `{cost}` weight paths (§3.5.1) |
| `fixture-pad-balance.bean` | `pad` + `balance` checkpoint path |
| `fixture-unsupported-include.bean` | Expects boot/parse failure (CT-15) |

---

## 6. Definition of Done — acceptance gates

A change is "done" only when:

1. Every touched invariant (I1–I8) has a passing property-based test.
2. Functional ACs for the relevant FR pass in `cargo test`.
3. **Convergence test:** two nodes, one partitioned then reconnected, end with byte-identical `.bean` (I7 / FR-4 AC3).
4. **Perf gate:** report queries (FR-2) resolve from the index; a benchmark asserts **zero** calls into the `.bean` parser on the read path. Soft latency target: p99 `< 50ms` for trial balance on a ledger with ≤10k transactions on a reference laptop-class CPU (informational, not a merge blocker until M6).
5. **Verify gate:** `verify` passes on the result, and a deliberately tampered transaction is detected (FR-5 AC1).
6. Spec sections changed by the PR are updated in the same PR.
7. **Naming gate (C8):** lint passes with the full-word-identifier rule on — no single-letter names, no abbreviations outside the §2.3 exception.

---

## 7. Risks & open questions

| Risk | Impact | Mitigation / decision needed |
|------|--------|------------------------------|
| **Peer addressability behind NAT** | "Guaranteed redundancy" silently fails | Prefer Iroh relay / hole-punch early; verify bootstrap-only path still works without public relay. |
| Beancount parser fidelity | Wrong balances; round-trip break | Golden corpus §5.1; canonical rules locked in §3.3.2. |
| Canonical serialization drift | Peers diverge on `.bean` bytes | Lock serializer; golden-file tests; version this document. |
| Iroh crate version skew (`iroh` vs `iroh-gossip`) | Broken builds / protocol drift | Pin a known-good pair early in M4; upgrade as a deliberate PR. |
| `balance`/`pad` under eventual consistency | False assertion failures | Checkpoint model (§3.6); assertions advisory, never gating. |
| External edits to `.bean` | Append-only semantics surprise users | Supported and switchable (§3.3). `"externalFileEdits": "disabled"` for API-sole-writer mode. |
| Large ledgers in memory | Boot time / RAM | Snapshot the read model; lazy-load cold periods if needed. |
| Cost/price booking vs full Beancount | Exotic lot methods diverge | Weight rules §3.5.1 are the interoperability floor; expand later via spec PR. |

**Resolved decisions:**
1. **`.bean` write path → both supported, switchable by config (see §3.3).**
2. **Transaction signing → optional, off by default, domain-separated Ed25519 over Iroh key (see §3.8.1).**
3. **Discovery → bootstrap EndpointIds / tickets, with relay additive (see §3.9).**
4. **Merge → native G-Set union by `txid` / `directiveId`.** No iroh-docs as ledger state.
5. **Envelope in `.bean` (see §3.3.1).** Excluded from content hashes.
6. **Remote path enforces I1–I3 (see §3.5).**
7. **Single-file ledger; `include` and other unsupported directives hard-fail (§2.3, §3.3.2).**
8. **Wire codec → length-prefixed CBOR on ALPN `openledger/anti-entropy/1` (§3.4.1).**
9. **Auth header → `X-Api-Key` (§3.8).**
10. **Subscriptions → WebSocket default + SSE (§2.6).**
