# OpenLedger v2

A **peer-to-peer, append-only, double-entry accounting engine** built in Rust. It stores all journal entries in a content-addressed DAG, syncs between nodes via [Iroh](https://iroh.computer/), and exposes a GraphQL API for querying and writing.

All data lives in a single **`.bean` file** (plain-text, beancount-compatible). Every mutation is validated against double-entry invariants before being committed.

---

## Quick Start

### Prerequisites

- **Rust 1.87+** — [install via rustup](https://rustup.rs/)
- **curl** (for testing the API) or a browser (for GraphiQL)

### 1. Clone & Build

```bash
git clone <repo-url> openledger-v2
cd openledger-v2
cargo build --release
```

### 2. Create a Config File

Create `gl-node.config.json` in the project root:

```json
{
  "ledgerPath": "my-ledger.bean"
}
```

That's the minimum config. The server will create `my-ledger.bean` if it doesn't exist.

### 3. Start the Server

```bash
cargo run --release
```

The server starts on **http://127.0.0.1:4000** by default.

You'll see:

```
INFO  loading configuration path="gl-node.config.json"
INFO  gl-node listening addr=127.0.0.1:4000
```

### 4. Open GraphiQL

Visit **http://127.0.0.1:4000/graphql**. The playground is on by default, including when the node binds a public address. Hide it with `"graphiql": false`.

---

## API Reference — curl Examples

All examples assume the server is running at `http://127.0.0.1:4000`. Pipe through `| python3 -m json.tool` for pretty output.

### Health Check

```bash
curl -s http://127.0.0.1:4000/health | python3 -m json.tool
```

Response:
```json
{
  "status": "ok",
  "heads": 0,
  "peers": 0,
  "version": "0.1.0"
}
```

---

### Mutations (Writing Data)

#### Open an Account

Before you can post transactions, you need to open accounts. This enforces the account lifecycle invariant (I3).

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { openAccount(name: \"Assets:Cash\", date: \"2024-01-01\", currencies: [\"USD\"]) }"
  }'
```

**Customize it:**

| Part | What to change | Example |
|------|---------------|---------|
| `name` | The account name. Must use `Type:Sub:Path` format. Types: `Assets`, `Liabilities`, `Equity`, `Income`, `Expenses` | `"Assets:Bank:Checking"`, `"Expenses:Food:Groceries"` |
| `date` | When the account is opened. Format: `YYYY-MM-DD` | `"2025-01-01"` |
| `currencies` | Optional list of allowed currencies. Omit to allow any. | `["USD", "EUR"]`, or remove entirely |

**More examples:**

```bash
# Open a checking account that accepts USD only
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { openAccount(name: \"Assets:Bank:Checking\", date: \"2025-01-01\", currencies: [\"USD\"]) }"
  }'

# Open an expense account (no currency restriction)
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { openAccount(name: \"Expenses:Food\", date: \"2025-01-01\") }"
  }'

# Open multiple accounts at once using GraphQL aliases
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { a1: openAccount(name: \"Assets:Cash\", date: \"2024-01-01\", currencies: [\"USD\"]) a2: openAccount(name: \"Equity:Opening\", date: \"2024-01-01\") a3: openAccount(name: \"Expenses:Food\", date: \"2024-01-01\") a4: openAccount(name: \"Income:Salary\", date: \"2024-01-01\") }"
  }'
```

---

#### Append a Transaction (Journal Entry)

Every transaction **must balance** — the sum of all posting amounts must equal zero (I1). You can omit the amount on exactly one posting and the system will auto-calculate it (I2).

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { appendTransaction(input: { date: \"2024-02-01\", narration: \"Salary deposit\", postings: [{ account: \"Assets:Cash\", amount: { number: \"5000\", currency: \"USD\" } }, { account: \"Income:Salary\", amount: { number: \"-5000\", currency: \"USD\" } }] }) { txid date narration postings { account amount { number currency } } } }"
  }'
```

**Customize it:**

| Part | What to change | Example |
|------|---------------|---------|
| `date` | Transaction date (`YYYY-MM-DD`) | `"2025-07-25"` |
| `flag` | `"*"` (complete/default) or `"!"` (incomplete/pending) | `flag: \"!\"` |
| `payee` | Optional counterparty name | `payee: \"Amazon\"` |
| `narration` | Description of what happened | `"Monthly rent"` |
| `tags` | Optional tags for categorization | `tags: [\"recurring\", \"q3\"]` |
| `links` | Optional reference links | `links: [\"invoice-2024-001\"]` |
| `postings` | At least 2 lines. Each needs `account` + `amount` (one may omit amount) | See examples below |
| `amount.number` | Decimal string — positive = debit, negative = credit | `"100.50"`, `"-100.50"` |
| `amount.currency` | 3-letter currency code | `"USD"`, `"EUR"`, `"BTC"` |

**Return fields you can request:** `txid`, `date`, `flag`, `payee`, `narration`, `tags`, `links`, `author`, `signature`, `parents`, `postings { account amount { number currency } }`

**More examples:**

```bash
# Buy groceries (with payee, tags, and auto-calculated equity posting)
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { appendTransaction(input: { date: \"2024-03-15\", payee: \"Whole Foods\", narration: \"Weekly groceries\", tags: [\"food\", \"weekly\"], postings: [{ account: \"Expenses:Food\", amount: { number: \"89.50\", currency: \"USD\" } }, { account: \"Assets:Cash\", amount: { number: \"-89.50\", currency: \"USD\" } }] }) { txid narration } }"
  }'

# Pending transaction (flag = "!")
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { appendTransaction(input: { date: \"2024-03-20\", flag: \"!\", narration: \"Pending refund\", postings: [{ account: \"Assets:Cash\", amount: { number: \"50\", currency: \"USD\" } }, { account: \"Expenses:Food\", amount: { number: \"-50\", currency: \"USD\" } }] }) { txid flag narration } }"
  }'

# Multi-posting transaction (3+ legs)
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { appendTransaction(input: { date: \"2024-04-01\", narration: \"Split deposit across accounts\", postings: [{ account: \"Assets:Cash\", amount: { number: \"300\", currency: \"USD\" } }, { account: \"Assets:Bank:Checking\", amount: { number: \"700\", currency: \"USD\" } }, { account: \"Income:Salary\", amount: { number: \"-1000\", currency: \"USD\" } }] }) { txid narration } }"
  }'

# With an elided posting (system auto-calculates the missing amount)
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { appendTransaction(input: { date: \"2024-04-15\", narration: \"Rent payment\", postings: [{ account: \"Expenses:Rent\", amount: { number: \"1500\", currency: \"USD\" } }, { account: \"Assets:Cash\" }] }) { txid postings { account amount { number currency } } } }"
  }'
```

> **Sign convention:** Assets and Expenses are **debit-normal** (positive = increase). Income, Equity, and Liabilities are **credit-normal** (negative = increase). The sum of all postings must always equal zero.

---

#### Close an Account

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { closeAccount(name: \"Assets:Cash\", date: \"2024-12-31\") }"
  }'
```

**Customize it:** Change `name` to any open account and `date` to the closing date. The account must have no transactions after the close date.

---

### Queries (Reading Data)

#### Trial Balance

Shows debit/credit totals for every account as of a given date.

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ trialBalance(at: \"2024-12-31\") { rows { account debit credit } totalDebit totalCredit } }"
  }'
```

**Customize it:** Change `at` to any date (`YYYY-MM-DD`). Only transactions on or before that date are included.

---

#### Balance Sheet

Shows assets, liabilities, and equity as of a given date.

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ balanceSheet(at: \"2024-12-31\") { assets { account balances { number currency } } liabilities { account balances { number currency } } equity { account balances { number currency } } } }"
  }'
```

---

#### Income Statement

Shows income, expenses, and net for a date range.

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ incomeStatement(from: \"2024-01-01\", to: \"2024-12-31\") { income { account balances { number currency } } expenses { account balances { number currency } } net { number currency } } }"
  }'
```

**Customize it:** Change `from` and `to` to any date range.

---

#### Journal (Transaction Log)

List transactions with optional filters.

```bash
# All transactions (default limit: 100)
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ journal { txid date narration postings { account amount { number currency } } } }"
  }'

# Filter by account
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ journal(account: \"Assets:Cash\") { txid date narration postings { account amount { number currency } } } }"
  }'

# Filter by date range with pagination
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ journal(from: \"2024-01-01\", to: \"2024-06-30\", limit: 10, offset: 0) { txid date narration } }"
  }'
```

**Customize it:**

| Parameter | What it does | Example |
|-----------|-------------|---------|
| `account` | Filter to transactions touching this account | `account: \"Expenses:Food\"` |
| `from` | Start date (inclusive) | `from: \"2024-01-01\"` |
| `to` | End date (inclusive) | `to: \"2024-12-31\"` |
| `limit` | Max results (default: 100) | `limit: 50` |
| `offset` | Skip N results (for pagination) | `offset: 20` |

---

#### Look Up a Single Transaction

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ transaction(txid: \"YOUR_TXID_HERE\") { txid date payee narration tags links author postings { account amount { number currency } } } }"
  }'
```

Replace `YOUR_TXID_HERE` with the `txid` returned from `appendTransaction`.

---

#### Look Up an Account Balance

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ account(name: \"Assets:Cash\") { account balances { number currency } } }"
  }'

# Balance as of a specific date
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ account(name: \"Assets:Cash\", at: \"2024-06-30\") { account balances { number currency } } }"
  }'
```

---

#### Verify DAG Integrity

Checks that all content hashes and parent links are valid.

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ verify { ok nodesChecked errors } }"
  }'
```

---

#### Node Health (GraphQL)

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ health { status heads peers version } }"
  }'
```

---

## Configuration

The config file is loaded from `gl-node.config.json` (or set `GL_NODE_CONFIG` env var).

### Minimal Config

```json
{
  "ledgerPath": "my-ledger.bean"
}
```

### Full Config (All Options)

```json
{
  "ledgerPath": "./data/company.bean",
  "bindAddress": "0.0.0.0",
  "port": 4000,
  "externalFileEdits": "disabled",
  "graphiql": true,
  "cors": { "allowedOrigins": [] },
  "auth": {
    "enabled": true,
    "apiKey": "my-secret-key-here"
  },
  "signing": {
    "enabled": false
  },
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

| Field | Default | Description |
|-------|---------|-------------|
| `ledgerPath` | **(required)** | Path to the `.bean` file |
| `bindAddress` | `"127.0.0.1"` | HTTP listen address |
| `port` | `4000` | HTTP listen port |
| `externalFileEdits` | `"disabled"` | Accept hand-edits to the `.bean` file |
| `graphiql` | `true` | GraphiQL playground; set `false` to hide it |
| `cors.allowedOrigins` | `[]` | Browser origin allowlist; `"*"` is rejected |
| `auth.enabled` | `false` | Require `X-Api-Key` header on GraphQL |
| `auth.apiKey` | `""` | The API key value (required if auth enabled) |
| `signing.enabled` | `false` | Sign transactions with Ed25519 |
| `p2p.enabled` | `false` | Enable Iroh mesh replication |

### Using Auth

When `auth.enabled` is `true`, add the header to all requests:

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: my-secret-key-here" \
  -d '{"query": "{ health { status } }"}'
```

The `/health` endpoint is always unauthenticated.

---

## Docker

### Build

```bash
docker build -t openledger .
```

### Run

```bash
# Create a config file for Docker
echo '{"ledgerPath": "/data/ledger.bean", "bindAddress": "0.0.0.0"}' > docker-config.json

# Run with persistent data
docker run -d \
  -p 4000:4000 \
  -v $(pwd)/docker-config.json:/data/gl-node.config.json \
  -v $(pwd)/data:/data \
  openledger
```

Then access GraphiQL at `http://localhost:4000/graphql` (or set `"graphiql": false` to hide it).

---

## Running Tests

```bash
# Run all 294 tests
cargo test

# Run a specific crate's tests
cargo test -p ledger
cargo test -p p2p
cargo test -p security
cargo test -p gl-node

# Run a specific test by name
cargo test -p ledger -- ct9_

# Check formatting + linting
cargo fmt --all -- --check
cargo clippy --all-targets
```

---

## Project Structure

```
openledger-v2/
├── Cargo.toml                # Workspace root
├── Dockerfile                # Multi-stage Docker build
├── gl-node.config.json       # Config file (create this)
├── SPEC.md                   # Full specification
├── crates/
│   ├── gl-node/              # HTTP server (Axum + GraphQL)
│   │   ├── src/main.rs       # Entrypoint, boot, graceful shutdown
│   │   ├── src/config.rs     # Config loader + validation
│   │   ├── src/graphql/      # GraphQL schema (queries, mutations, subscriptions)
│   │   ├── src/auth.rs       # API key middleware
│   │   └── src/health.rs     # GET /health handler
│   ├── ledger/               # Core accounting engine
│   │   ├── src/parse.rs      # Beancount parser
│   │   ├── src/serialize.rs  # Canonical serializer (I7 round-trip)
│   │   ├── src/dag.rs        # Content-addressed DAG (G-Set CRDT)
│   │   ├── src/validate.rs   # I1–I3, I9 validation + account state
│   │   ├── src/service.rs    # LedgerService (mutations, reconcile)
│   │   ├── src/hash.rs       # SHA-256 content hashing (I5)
│   │   ├── src/verify.rs     # DAG integrity verification
│   │   ├── src/read_model.rs # Reports (trial balance, balance sheet, etc.)
│   │   ├── src/checkpoint.rs # DAG checkpointing
│   │   └── src/file_watcher.rs # External edit detection
│   ├── p2p/                  # Peer-to-peer sync (Iroh)
│   │   ├── src/gossip.rs     # Gossip announcements
│   │   ├── src/anti_entropy.rs # Head exchange protocol
│   │   └── src/union_merge.rs  # CRDT merge logic
│   └── security/             # Signing + verification
│       └── src/signing.rs    # Ed25519 signing provider
└── testfixtures/             # Beancount fixture files for tests
```

---

## Double-Entry Accounting Quick Reference

Every transaction must have postings that sum to zero. The sign convention:

| Account Type | Normal Balance | Increase | Decrease | In Beancount |
|-------------|---------------|----------|----------|--------------|
| **Assets** | Debit | `+100` | `-100` | Positive = increase |
| **Expenses** | Debit | `+50` | `-50` | Positive = increase |
| **Income** | Credit | `-1000` | `+1000` | Negative = increase |
| **Equity** | Credit | `-500` | `+500` | Negative = increase |
| **Liabilities** | Credit | `-200` | `+200` | Negative = increase |

**Example:** You earn $5000 salary and deposit it:
```
Assets:Cash         +5000 USD    ← asset increases (debit)
Income:Salary       -5000 USD    ← income increases (credit)
                    ─────────
                    Sum = 0  ✓
```

---

## License

See repository for license terms.
