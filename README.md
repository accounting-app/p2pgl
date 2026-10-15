# OpenLedger v2

A **peer-to-peer, append-only, double-entry accounting engine** built in Rust. It stores all journal entries in a content-addressed DAG, syncs between nodes via [Iroh](https://iroh.computer/), and exposes a GraphQL API for querying and writing.

All data lives in a single **`.bean` file** (plain-text, beancount-compatible). Every mutation is validated against double-entry invariants before being committed.

---

## Quick Start

### Prerequisites

- **Rust 1.91+** (the workspace's `rust-version`) — [install via rustup](https://rustup.rs/)
- **curl** (for testing the API) or a browser (for GraphiQL)

### 1. Clone & Build

```bash
git clone <repo-url> openledger-v2
cd openledger-v2
cargo build --release
```

### 2. Create a Config File

The repository ships a minimal `gl-node.config.json` in the project root
with GraphiQL off. Edit it, or replace it with:

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
INFO  loading configuration path=gl-node.config.json
INFO  generated a new API key; clients send the file's contents as the X-Api-Key header (H-01) path=./data/api.key
INFO  gl-node starting address=127.0.0.1:4000 version=0.1.0 ledger=my-ledger.bean auth_enabled=true p2p_enabled=false graphiql=false
```

Every `/graphql` request needs that key in an `X-Api-Key` header — see [Using Auth](#using-auth). The first boot writes it to `./data/api.key` (readable by your account only); later boots read it back.

### 4. Open GraphiQL

The playground is **off** by default. Turn it on with `"graphiql": true` and visit **http://127.0.0.1:4000/graphql**. It is only available on a loopback bind — a non-loopback `bindAddress` with `graphiql` enabled is refused at boot, not silently downgraded. Its queries need the API key like any other client: open the **Headers** panel and paste `{"X-Api-Key": "<the contents of data/api.key>"}`. The node never puts the key into the page itself.

### Upgrading

The step-by-step procedure — backups, upgrade, rollback, what to watch — is in [`docs/OPERATIONS.md`](docs/OPERATIONS.md); start a production node from [`deploy/gl-node.production.json`](deploy/gl-node.production.json). Read [`CHANGELOG.md`](CHANGELOG.md) before upgrading, starting with *Breaking*. Config files are parsed strictly, so an **older binary refuses a config that uses a key added in a newer one**: upgrade the binary before editing the config, and remove new keys before rolling back. A newer node holds what it **writes** to tighter limits than what it **takes as history**, so that history an older build wrote keeps replicating: an `open` may list up to 64 currencies and a transaction's postings up to 100 metadata keys when this node authors them, but a peer's record or an existing file is held only to 4,096 of each. One case still cannot replicate: an amount past 10^21 in a history written before T65 (a ledger kept in base units, such as wei). Boot keeps that record in the file, names it, and quarantines it together with every record that depends on it, so the node serves only what a fresh replica can hold; `verify` lists what is quarantined. Restating such an amount in a larger unit gives the record a new id, so its descendants (whose parents name the old id) stay quarantined: restate the chain on **one** node only (the record without its own `openledger-*` lines, and each descendant without its `openledger-*` lines, so it is re-adopted under its own id with parents that node serves; every other node adopts the restated records and must not restate, or the deposit is counted twice — see *What no peer could hold is not served*), or join nodes by bootstrap (§Mesh identity). If the account's `open` accepts only the smaller unit (an `open … WEI`, say), the restated amount is refused there too: add the larger unit to that `open` in the same edit (delete its `openledger-*` lines so it is re-adopted as your own). The CHANGELOG lists each case. **Upgrade every node of a mesh, not some:** a node on a build from T75 to T80 refuses a history record over 64 currencies or 100 posting metadata keys that this build accepts, and then every record this node writes afterwards names a parent that node lacks — it buffers them all until it is upgraded, and nothing on this node says so. The same holds for the lifecycle rules: a node older than T91 judges a currency by the latest `open` alone, one older than T98 refuses a peer's `close` when it holds a later posting and refuses a peer's posting dated after a `close` — each refuses records this build accepts, and a node older than T90 refuses a restated record for good until it restarts on the new build. A hand-typed entry's metadata keys are counted as the record will be stored with a signature (96 on a transaction, 97 on anything else), also on a node with signing off, so enabling signing later never pushes a record over the cap.

---

## API Reference — curl Examples

All examples assume the server is running at `http://127.0.0.1:4000`. Pipe through `| python3 -m json.tool` for pretty output. Every `/graphql` example sends the API key from `$GL_NODE_API_KEY`; on a local node with the default config, load it from the key file first:

```bash
export GL_NODE_API_KEY="$(cat data/api.key)"
```

### Health Check

```bash
curl -s http://127.0.0.1:4000/health | python3 -m json.tool
```

Response (loopback bind, or any bind with a valid `X-Api-Key`):
```json
{
  "status": "ok",
  "heads": 0,
  "peers": 0,
  "version": "0.1.0"
}
```

`/health` sits behind the same Host guard as `/graphql`: a request whose `Host`
header is not in `allowedHosts` gets `403` (loopback names are always allowed,
so the local probe above and the Docker `HEALTHCHECK` are unaffected). This is
what stops a DNS-rebinding page from reading it. It also has its own rate
limit — 120 requests per minute per client, separate from the GraphQL budget so
a busy API client cannot fail your health probe — and answers `429` past it.
Point monitors at a listed host name, not a raw IP that is not in `allowedHosts`.

On a **non-loopback** `bindAddress`, an unauthenticated request gets the
liveness answer and nothing else:
```json
{
  "status": "ok"
}
```
Version, head count and peer count are reconnaissance for anyone who can reach
the port, so they are disclosed only to a caller holding the API key — the same
key `/graphql` requires. The status code is `200` in every case, which is all a
container health check or load-balancer probe reads.

**A bare `{"status":"ok"}` is a healthy node, not a broken one.** The three
detail fields are *absent* rather than null or zero, precisely so an empty
`peers` cannot be misread as "this node has lost its mesh" — if you need the
detail from a public bind, send the `X-Api-Key` header. The split keys off the
**bind address**, not the caller's: behind the TLS terminator a public bind
requires, every request arrives from the proxy, so a caller-address rule would
hand the loopback treatment to the whole internet. The shipped compose stack
publishes on host loopback but still binds `0.0.0.0` inside the container, so
its nodes answer with the minimal body.

---

### Mutations (Writing Data)

#### Open an Account

Before you can post transactions, you need to open accounts. This enforces the account lifecycle invariant (I3).

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
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

An account can end up with more than one `open` on a mesh — another node opened it too, or it was closed and opened again. A transaction on such an account may use any currency listed by **any** `open` dated on or before it, and any currency at all once one of those `open`s lists none, so an `open` that arrives later never makes a transaction every node already accepted unacceptable. A `close` stops **this node's own** writes: the API refuses a transaction dated after the account's latest `close` (with no `open` after it), and refuses to close an account that has a transaction after the close date. What a peer sends and what the `.bean` holds is data: a peer's or a hand-typed `close` is always accepted, and a transaction from a peer or the file is accepted whenever an `open` of its account is dated on or before it (a same-day `open` counts), whatever `close` sits in between. A `balance` assertion from a peer or the file is held to the same rule: an `open` of its account dated on or before it (a peer's waits for that `open`, a hand-typed one without it is refused, and one in the history — or pasted with its full envelope — whose account no `open` dated on or before it opens is kept in the file but not served). Every node therefore holds the same records whatever order they arrive in. A `close` with such a transaction dated after it (before the next `open`) no longer stops anything in that stretch, this node's own writes included; a `close` with nothing after it still does. To stop writes to an account again after a peer posted past its `close`, close it again at a later date.

**More examples:**

```bash
# Open a checking account that accepts USD only
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { openAccount(name: \"Assets:Bank:Checking\", date: \"2025-01-01\", currencies: [\"USD\"]) }"
  }'

# Open an expense account (no currency restriction)
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { openAccount(name: \"Expenses:Food\", date: \"2025-01-01\") }"
  }'

# Open multiple accounts at once using GraphQL aliases
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
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
  -H "X-Api-Key: $GL_NODE_API_KEY" \
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
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { appendTransaction(input: { date: \"2024-03-15\", payee: \"Whole Foods\", narration: \"Weekly groceries\", tags: [\"food\", \"weekly\"], postings: [{ account: \"Expenses:Food\", amount: { number: \"89.50\", currency: \"USD\" } }, { account: \"Assets:Cash\", amount: { number: \"-89.50\", currency: \"USD\" } }] }) { txid narration } }"
  }'

# Pending transaction (flag = "!")
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { appendTransaction(input: { date: \"2024-03-20\", flag: \"!\", narration: \"Pending refund\", postings: [{ account: \"Assets:Cash\", amount: { number: \"50\", currency: \"USD\" } }, { account: \"Expenses:Food\", amount: { number: \"-50\", currency: \"USD\" } }] }) { txid flag narration } }"
  }'

# Multi-posting transaction (3+ legs)
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { appendTransaction(input: { date: \"2024-04-01\", narration: \"Split deposit across accounts\", postings: [{ account: \"Assets:Cash\", amount: { number: \"300\", currency: \"USD\" } }, { account: \"Assets:Bank:Checking\", amount: { number: \"700\", currency: \"USD\" } }, { account: \"Income:Salary\", amount: { number: \"-1000\", currency: \"USD\" } }] }) { txid narration } }"
  }'

# With an elided posting (system auto-calculates the missing amount)
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
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
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { closeAccount(name: \"Assets:Cash\", date: \"2024-12-31\") }"
  }'
```

**Customize it:** Change `name` to any open account and `date` to the closing date. The account must have no transactions after the close date.

---

#### Amounts and precision

Any amount that is added into a balance (posting units, `{cost}`, `@`/`@@` price, and the auto-calculated
elided amount) must have magnitude at most **10^21** (`1000000000000000000000`). The limit includes 10^21
itself and allows up to 28 fractional digits; trailing zeros do not count against the 10^21 limit, but
they do count as digits: a stored amount holds at most 28 significant digits in all (29 below about
7.9 × 10^28), so 10^21 admits at most 7 decimal places, and a longer spelling is refused with a message
that says so. The API, peers
and the `.bean` file all apply the same rule. `balance` and `price` directive amounts are not limited.
A history record past the limit (written before T65) is held in the file and quarantined at boot with
everything that descends from it — see Upgrading above.

Every balance is kept as its exact sum. A reported figure is that exact sum whenever it fits a
`Decimal`'s 96-bit mantissa at the scale its amounts are written in. If it does not fit, which only
happens when amounts of very different scales are mixed (such as `1000` and
`0.0000000000000000000000000001`), the figure is rounded once, half to even, to the finest scale that
fits, and the report says so with `exact: false`. `balance` assertions and `verify` always compare
against the exact sum. With the 10^21 limit, no total in a ledger of any size the node accepts can be
too large to report. An inexact figure is within half a unit in its last
printed place of the exact sum.

### Queries (Reading Data)

#### Trial Balance

Shows debit/credit totals for every account as of a given date.

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
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
  -H "X-Api-Key: $GL_NODE_API_KEY" \
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
  -H "X-Api-Key: $GL_NODE_API_KEY" \
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
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ journal { txid date narration postings { account amount { number currency } } } }"
  }'

# Filter by account
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ journal(account: \"Assets:Cash\") { txid date narration postings { account amount { number currency } } } }"
  }'

# Filter by date range with pagination
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
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
  -H "X-Api-Key: $GL_NODE_API_KEY" \
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
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ account(name: \"Assets:Cash\") { account balances { number currency } } }"
  }'

# Balance as of a specific date
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
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
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ verify { ok nodesChecked errors truncated } }"
  }'
```

`errors` lists at most the first 1,000 problems, one per offending node;
`truncated` is how many more were found and not listed (`0` means `errors` is
complete). Three more fields describe what the node holds back: `quarantined`
lists the ids of records kept in the file but not served (at most 1,000),
`quarantinedTotal` counts all of them, and `unparsableBlocks` counts blocks of
the file held as text because they do not parse — request them as
`{ verify { ok quarantined quarantinedTotal unparsableBlocks } }`.

---

#### Node Health (GraphQL)

```bash
curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ health { status heads peers version } }"
  }'
```

---

## Configuration

The config file is loaded from `gl-node.config.json` (or set `GL_NODE_CONFIG` env var).

The config file must be a regular file of at most 1 MiB. A symlink to one is followed (a mounted ConfigMap works), but a FIFO, directory, device or dangling link is refused at startup, and by `--health-check`, rather than waited on. Its owner and mode are not checked; if it carries `auth.apiKey`, keep it `0600` or use `GL_NODE_API_KEY`.

### Minimal Config

```json
{
  "ledgerPath": "my-ledger.bean"
}
```

### Full Config (All Options)

This block is a **public-bind** example, so it carries everything a
non-loopback `bindAddress` requires: `auth.enabled`, `tls.mode: "terminated"`,
a populated `allowedHosts`, and `graphiql: false`. Each of those is refused at
boot if it is missing — the node will not start half-hardened.

```json
{
  "ledgerPath": "./data/company.bean",
  "bindAddress": "0.0.0.0",
  "port": 4000,
  "watchLedgerFile": false,
  "graphiql": false,
  "cors": { "allowedOrigins": [] },
  "allowedHosts": ["ledger.example.com"],
  "trustedProxies": ["10.0.0.1"],
  "tls": { "mode": "terminated" },
  "auth": {
    "enabled": true,
    "apiKey": "change-me"
  },
  "signing": {
    "enabled": false
  },
  "http": {
    "headerReadTimeoutSeconds": 30,
    "requestTimeoutSeconds": 30,
    "maxConnections": 1024,
    "maxConnectionsPerIp": 64
  },
  "p2p": {
    "enabled": false,
    "secretKeyPath": "./data/iroh.secret",
    "bootstrapEndpointIds": [],
    "gossipIntervalMilliseconds": 5000,
    "antiEntropyIntervalMilliseconds": 5000,
    "swarmTopic": "openledger/transactions",
    "relayMode": "n0"
  }
}
```

`p2p.meshId` is the one option deliberately left out of the block, because the
right value depends on whether the mesh already exists: on an **existing** mesh,
set it to your current `swarmTopic` verbatim — any other value invalidates every
signature already in the mesh. Read [Mesh identity](#mesh-identity-p2pmeshid)
before you set one. It is **required** whenever `signing.enabled` is true: a
signing node without it refuses to boot, and the refusal names that remedy.

> `"apiKey": "change-me"` above is a **placeholder that this node refuses to
> boot with**, on purpose — see [API keys](#api-keys) before you copy the block.

| Field | Default | Description |
|-------|---------|-------------|
| `ledgerPath` | **(required)** | Path to the `.bean` file |
| `ledgersDir` | `./data/ledgers` | Folder of this node's other ledgers, one folder each (see [Several ledgers](#several-ledgers)); missing = none. Under the working directory, and `ledgerPath` may not be inside it |
| `maxLedgers` | `100` | The most ledgers the node serves, its own included. `1`–`100` |
| `bindAddress` | `"127.0.0.1"` | HTTP listen address |
| `port` | `4000` | HTTP listen port |
| `watchLedgerFile` | `false` | Poll the `.bean` every 250 ms and fold a hand edit in promptly. It does **not** control whether a hand edit is accepted — nothing does — see [Editing the `.bean` file](#editing-the-bean-file-by-hand) |
| `graphiql` | `false` | GraphiQL playground; refused outright on a non-loopback bind. The page loads GraphiQL 4.1.2 and React 18.3.1 production builds from `unpkg.com`, each pinned by a Subresource Integrity hash — see below |
| `cors.allowedOrigins` | `[]` | Browser origin allowlist; `"*"` is rejected |
| `allowedHosts` | `[]` | Extra `Host` header values accepted, beyond loopback and the bind address. **Required (non-empty) on a non-loopback bind** — see below |
| `trustedProxies` | `[]` | Reverse-proxy IPs whose `X-Forwarded-For` the rate limiter believes — see below |
| `tls.mode` | `"disabled"` | `"disabled"` (loopback only) or `"terminated"` (TLS at a host/proxy). A non-loopback bind must be `"terminated"`; in-process TLS is not implemented |
| `auth.enabled` | `true` | Require `X-Api-Key` header on GraphQL. May be turned off only on a loopback bind, and boot then WARNs that anything on the machine can write the ledger |
| `auth.apiKey` | `""` | The API key value. Required on a non-loopback bind; on a loopback bind, empty means the key file below. Minimum 16 bytes; published placeholders are refused — see [API keys](#api-keys) |
| `auth.adminNodes` | unset | EndpointIds of the nodes whose access records (people's keys, roles, revocations) count; unset, every node the mesh admits. Needs `signing.enabled` (people's keys are honoured only on a signing node); an empty list is refused |
| `auth.apiKeyPath` | `"./data/api.key"` | Where a loopback node with no `apiKey` keeps the key it generates on its first boot (0600, owned by the node's user) — see [Using Auth](#using-auth) |
| `http.headerReadTimeoutSeconds` | `30` | Time a client gets to send a complete request head; also bounds idle keep-alive. `1`–`300` |
| `http.requestTimeoutSeconds` | `30` | Whole-request ceiling, body read and GraphQL execution included (`408` on expiry). `1`–`300` |
| `http.maxConnections` | `1024` | Concurrently served connections; excess stays in the kernel backlog. `8`–`65536` |
| `http.maxConnectionsPerIp` | `64` | Concurrent connections one client may hold (keyed per IPv4 address or IPv6 /64, like the rate limiter), so one address cannot take every slot. **It bounds one address or one /64, not one network:** a routed IPv6 /48 is 65,536 /64 keys, far past the global cap, so per-prefix limits wider than a /64 belong in your proxy or firewall. Addresses listed in `trustedProxies` are exempt — list your reverse proxy there, or every client behind it shares this cap. Clamped to `maxConnections`. `8`–`65536` |
| `http.maxRequestsPerLedger` | `64` | GraphQL requests one ledger serves at once; past it the ledger answers `503 LEDGER_BUSY` with `Retry-After`, and the node's other ledgers are unaffected. Counted after the key check, so only callers the ledger accepts take a slot. `1`–`65536` |
| `signing.enabled` | `false` | Sign transactions with Ed25519. Forced on when `p2p.enabled`. When on, the node's author id is its key's public half, P2P on or off |
| `signing.allowWritesWhenEverySignatureFails` | `false` | Accept API writes even when every signature in the history failed at boot (a wrong `meshId` or key); by default they are refused with `EVERY_SIGNATURE_FAILED` (§Mesh identity) |
| `p2p.enabled` | `false` | Enable Iroh mesh replication |
| `p2p.secretKeyPath` | `./data/iroh.secret` | The node's Ed25519 key — its QUIC identity **and** its signing key. Created `0600` if absent. An existing file is refused unless it is a regular file (not a symlink), owned by the uid the node runs as, and not readable by group or other |
| `p2p.bootstrapEndpointIds` | `[]` | Allowlisted peer EndpointIds; empty drops inbound `Supply` |
| `format.wire2` | `true` | Dial anti-entropy and gossip in the wire-v2 encoding (§Format v2). Both encodings are always served; `false` only to talk to a node on a build from before Format v2 |
| `format.idv2` | `true` | Write records in Format v2 — an id that covers the author, signed in signature v4 (§Format v2). Both formats are always accepted; `false` only to write for a node on a build from before Format v2 |
| `p2p.joinFrom` | unset | One of `bootstrapEndpointIds` that a node which has written nothing joins from: its history is adopted past the adoption ratchet until the node holds all of it (§Mesh identity, *Joining a mesh*) |
| `p2p.gossipIntervalMilliseconds` | `5000` | Accepted but currently unused (reserved for gossip pacing) |
| `p2p.antiEntropyIntervalMilliseconds` | `5000` | ALPN head-exchange cadence; minimum `100` |
| `p2p.antiEntropySessionSeconds` | `300` | Wall-clock cap on one anti-entropy session, inbound and outbound; the server closes an expired connection with code 5 `session-deadline`. `30`–`3600` |
| `p2p.antiEntropyMaxAdvertPages` | `512` | Pages one peer's `HaveHeads` advert may span. `256`–`1024` |
| `p2p.antiEntropyMaxAdvertIdBytes` | `67108864` | Distinct advertised id bytes one exchange may hold (64 MiB). Lower it to trade catch-up headroom for memory. `16777216`–`67108864` |
| `p2p.antiEntropyMaxSessionFrames` | `100000` | Frames one anti-entropy connection may cost, on either side. `10000`–`1000000` |
| `p2p.antiEntropyAcceptBurst` | `8` | New inbound anti-entropy connections one peer may open back to back; beyond it, one per refill interval (refusals close with code 6 `accept-rate-limit`). `2`–`256` |
| `p2p.antiEntropyAcceptRefillMilliseconds` | `2000` | One accept token back per this interval. `100`–`30000` |
| `p2p.antiEntropyMaxConcurrentExchanges` | `8` | Outbound anti-entropy exchanges this node runs at once, across all peers; past it, peers wait their turn in order. Each exchange against a hostile peer can hold ~130–150 MiB at worst. `1`–`64` |
| `p2p.antiEntropySupplyBackoffSeconds` | `60` | When a peer's batch would not fit under the 64 MiB ledger cap, that peer's `Supply` is not applied again for this long (one warning per deferral). `5`–`3600` |
| `p2p.listenPort` | `0` | UDP port the P2P endpoint listens on. `0` picks a new random port at every boot; set a fixed port on any node whose address other nodes list in `peerAddresses`, and open it (UDP) in the firewall |
| `p2p.peerAddresses` | `{}` | Where allowlisted peers listen: `{ "<EndpointId>": ["host:port", …] }`, 1–16 addresses each, every key one of `bootstrapEndpointIds`; names re-resolved every 5 minutes (every 10 s until each has first resolved) — see [Relay mode](#relay-mode-p2prelaymode) |
| `p2p.relayMode` | `"n0"` | `"n0"` (public Iroh relays and discovery), `"disabled"` (direct addresses only) or `"custom"` (the mesh's own relay, `relayUrl`, plus direct addresses; nothing goes to n0). Anything else is refused at boot — see [Relay mode](#relay-mode-p2prelaymode) |
| `p2p.relayUrl` | unset | The mesh's own relay for `relayMode: "custom"`: `https://host[:port]` of an `iroh-relay` server, the same on every node; no user info, query or path. Refused with any other mode |
| `p2p.swarmTopic` | `openledger/transactions` | Gossip topic (and, before `meshId` existed, the signature domain); required unique on a public bind. Same form as `meshId`: non-empty, no surrounding whitespace, ASCII letters, digits and `- _ . : /`, up to 128 bytes |
| `p2p.meshId` | *(unset)* | Mesh identity bound into every signature. **Required when `signing.enabled`** — a signing node without it refuses to boot. **Existing mesh: your current `swarmTopic`, verbatim** — any other value invalidates every signature already in the mesh. New mesh: a random UUID — see below |

**`allowedHosts`.** The request guard checks the `Host` header on every
GraphQL request, which is what stops a DNS-rebinding page in a browser from
driving your node. Loopback names (`localhost`, `127.0.0.1`, `::1`) and a
non-wildcard `bindAddress` are always accepted; everything else has to be
listed. A wildcard bind such as `0.0.0.0` names no host a client could send,
so on a non-loopback bind an **empty `allowedHosts` is refused at boot** rather
than left to reject every request with a `403` at runtime. Entries are bare
hostnames or IP literals — no scheme, no port, no path, no IPv6 brackets and no
trailing dot. The guard strips the port and brackets from every `Host` header
before the lookup, so an entry spelled `ledger.example.com:443` or `[::1]` could
never match; each of those is refused at boot with the spelling to use instead.

Two things the guard deliberately does not hide:

- **`OPTIONS` is answered for any `Host`.** The CORS layer short-circuits every
  `OPTIONS` request before the Host guard, and the response carries the route's
  `Allow` header (`GET,HEAD,POST` on `/graphql` with GraphiQL on, `GET,HEAD`
  with it off or on `/health`). A rebinding page can read that much — "a
  gl-node is here, GraphiQL on or off" — and nothing else: no data, no
  mutation, no version.
- **Loopback names are interchangeable in `Origin`.** Same-origin is judged as
  "the `Origin` host is an allowed host and its port equals the request's", so
  a page at `http://localhost:4000` is accepted by a request sent to
  `127.0.0.1:4000`, and vice versa. That matters only if a *different* service
  on another loopback address shares the node's port; CORS preflight still
  blocks cross-origin JSON `POST`s.

**`trustedProxies`.** Behind a TLS terminator every request arrives from the
same socket address, so without this list the whole internet shares a single
rate-limit bucket and one client can starve everybody. List the **exact IP
addresses of the proxies themselves**; when the TCP peer is one of them, the
client is identified by the rightmost `X-Forwarded-For` entry that is not
itself a trusted proxy (the standard anti-spoof parse — entries further left
were supplied by the client and are ignored).

Three limits are deliberate, not omissions:

- **Exact IP literals only.** No CIDR ranges, no hostnames, no ports. A range
  is a promise about addresses you do not control today; an entry that fails to
  parse is refused at boot rather than silently dropped from the trust set.
- **`X-Forwarded-For` only.** RFC 7239 `Forwarded:` is not read.
- **Empty means trust nothing**, and every client is keyed by its TCP peer
  address. That is the fail-closed default; a node with `tls.mode:
  "terminated"` and an empty list logs a warning at boot saying so.

Listing an address an untrusted client can reach lets that client choose its
own rate-limit identity, so list the terminator and nothing else.

**`http`.** These are the node's own connection-level backstops (header-read
timeout, whole-request timeout, connection ceiling). Omit the section entirely
and you get the values in the table, which is what the node has always applied.
The bounds in the table are enforced at boot in both directions: `0` does not
mean "no limit", it means the server answers nothing, and a value large enough
to be "effectively unlimited" simply re-opens the attack the limit exists to
close.

A public bind sits behind a TLS-terminating reverse proxy, and **that proxy
must enforce equivalent header, body, request and connection limits of its
own.** Nothing here relieves it of that: by the time a request reaches this
node, the proxy has already accepted the connection and is holding it. Treat
these values as the floor under a misconfigured or bypassed proxy, not as the
deployment's limits.

**GraphiQL's assets come from a CDN.** With `graphiql: true` the page at
`GET /graphql` loads GraphiQL **4.1.2** and React/React-DOM **18.3.1**
production builds from `unpkg.com`. Each tag carries a SHA-384 `integrity`
hash, so a CDN that serves anything else is refused by the browser and the page
stays blank rather than running it. No other origin is contacted. The tab is
still a same-origin session on the node, which is why GraphiQL is off by
default and refused on any non-loopback bind.

### Log volume on a public bind

A node bound to a public address accepts QUIC handshakes from anyone. Refusals are logged at bounded rates:

- one line per 10 s for every peer not on the allowlist, taken together;
- one per 10 s per allowlisted peer and reason;
- one per 10 s per HTTP client for requests the Host/Origin/Content-Type guard refuses.

Each window's suppressed count is logged when the window closes. iroh's own per-handshake warnings (unknown ALPN, a handshake aborted by the peer) are silenced by the default filter, `info,iroh::protocol=error`. **If you set `RUST_LOG`, it replaces that default: keep `iroh::protocol=error` in it**, or any dialer can write ~300–700 bytes of log per handshake. Put the same log-volume controls (rotation, rate limits in your log shipper) on the QUIC port as on the HTTP edge.

### API keys

`auth.apiKey` is the only credential in front of the writable GraphQL
mutations, so generate one — do not invent one by hand:

```bash
openssl rand -hex 32
```

Two boot rules back that up, and both apply whenever `auth.enabled` is true —
to a key typed into the key file by hand too —
including on a loopback bind (`bindAddress` is one edit away from `0.0.0.0`,
and a key that was never secret does not become one):

- **Minimum 16 bytes.** Shorter keys are refused, naming the field and the
  length found.
- **A denylist of published placeholders.** Every sample value that appears in
  this repository — this README's `"change-me"` included — plus the usual
  stand-ins (`changeme`, `password`, `secret`, `test`, …) is refused outright.
  Matching is exact and case-insensitive on the trimmed value, so a real
  32-byte key that happens to contain the word "secret" still boots. A test
  parses every `"apiKey"` published in this file and asserts it is on that
  list, so the samples here are guaranteed non-bootable by construction.

The key can also come from the **`GL_NODE_API_KEY` environment variable**,
which is the better place for it: the config file tends to be committed, baked
into an image, or mounted read-only, and a secret in any of those is a secret
that leaks. When both are set, **the environment wins** and the node logs a
warning naming the winner — so rotate by changing the environment variable and
restarting. (Do not rely on the file value being the one in use.) Setting
`GL_NODE_API_KEY` does **not** turn authentication on: with `auth.enabled:
false` the key is ignored, and the node logs a warning at boot saying so
(without printing the key). On Unix, a
config file that carries a non-empty `apiKey` and is readable by group or other
also draws a warning at boot; `chmod 600` it, or move the key to the
environment.

### Relay mode (`p2p.relayMode`)

With the default, `"n0"`, the node's endpoint uses the public relay and
discovery infrastructure run by n0 (the Iroh maintainers): it publishes a
record under its EndpointId to n0's discovery service saying how to reach it,
so peers can find it by id alone, and it falls back to n0's public relay
servers when a direct connection cannot be made. Peer traffic stays end-to-end encrypted, so a relay
cannot read directives, but it is **not private**: the operator of that
infrastructure can see that your node exists and is online, its IP address,
which EndpointIds it talks to, and when and how much. That is why a node on
`"n0"` logs a warning at every boot.

`"disabled"` builds the endpoint with no relay and no discovery, so nothing
about the node is published anywhere. Peers then connect on direct addresses
only, and a node learns them from **`p2p.peerAddresses`**: each allowlisted
peer's EndpointId mapped to where it listens —

```json
"peerAddresses": {
  "<peer EndpointId>": ["ledger.acme.com:4433", "203.0.113.7:4433"]
}
```

Each key must be one of `bootstrapEndpointIds` (an address says where an
admitted peer is; it never admits one), with 1 to 16 addresses written
`host:port` or `[v6]:port` (an incomplete IP such as `203.0.113:4433` is
refused — the system resolver would read it as another host). Host names are
resolved at boot and every five minutes after, so a server whose IP changes is
followed — every 10 seconds instead while an address has never resolved, so a
node started before its peers finds them within seconds; a name that does not
resolve is logged and retried, and that address's last known IPs are kept
meanwhile. With `"disabled"`, a bootstrap peer
that has no `peerAddresses` entry cannot be reached, and boot names it. The
port in an address is the peer's **`p2p.listenPort`** (UDP): by default a node
listens on a new random port at every boot, so set a fixed one on every node
others reach by address, and open it in the firewall. The peer must accept connections at that
address: a server with a public address and an open port, or a machine on the
same network. `peerAddresses` also works beside `"n0"`: its addresses are tried
along with whatever n0's discovery finds.

`"custom"` uses **the mesh's own relay** instead of n0's: an `iroh-relay`
server you (or your provider) run, named by **`p2p.relayUrl`** —

```json
"relayMode": "custom",
"relayUrl": "https://relay.example.com"
```

Every node registers at that relay, and every bootstrap peer is looked up
there as well as at its `peerAddresses`, so nodes behind office routers reach
each other with no address of their own to give. Traffic through the relay
stays end-to-end encrypted; the relay's operator — you — sees which nodes talk
to each other, n0 sees nothing (no n0 relay, no n0 discovery). Use **one relay
per mesh**, the same `relayUrl` on every node: a node registers at exactly one
relay, and that is where its peers look for it. The URL must be `https` with
nothing but a host and port, and the relay's certificate must come from a
public certificate authority (for example Let's Encrypt, which `iroh-relay`
can obtain itself): nodes verify it against the standard public roots, and a
self-signed or private-CA certificate leaves them unable to connect.
`"custom"` with neither `relayUrl` nor `peerAddresses` is refused, since it
would reach no peer. Configure the relay to admit only the mesh's own nodes —
an allowlist of their EndpointIds in the relay's own config.

### Mesh identity (`p2p.meshId`)

> **On an existing mesh: set `p2p.meshId` to your current `swarmTopic`
> verbatim — any other value invalidates every signature already in the mesh.**
> Copy it byte for byte, on every node. `meshId` is **required** on any node
> with `signing.enabled`: one without it refuses to boot with an error that
> says exactly this (it never prints the topic).

The swarm topic is a *reachability* string: anyone holding it
plus one member EndpointId can join the gossip overlay. Using it as the
signature domain too meant two meshes that happened to pick the same custom
topic accepted each other's signed directives. Setting `meshId` separates the
two; any identifier of ASCII letters, digits and `- _ . : /` up to 128 bytes is
accepted.

Because a mesh that signed before `meshId` existed signed under its topic — and
keeps that domain by copying the topic into `meshId` — **`swarmTopic` is held to
exactly the same form rules** — non-empty, no
leading or trailing whitespace, ASCII letters, digits and `- _ . : /`, at most
128 bytes — and a value that breaks them is refused at boot rather than
trimmed. The refusal names the field, the value's length and the byte offset of
the stray whitespace, never the value itself (it is the join credential). A
topic differing by one space between two nodes is not a cosmetic difference: it
is a different gossip overlay *and* a different signature domain, and it would
otherwise surface much later as `InvalidSignature`.

Before this release a signing node could leave it unset, and its domain was
then `swarmTopic`. A signature is checked by reconstructing the signed message
with the verifier's own domain, so **changing the resolved domain invalidates
every signature already persisted and every signature peers hold** — which is
why the only safe `meshId` for an existing mesh is the string it already signs
with. A node with signing off may still leave `meshId` out; it signs nothing.

A node started with the wrong domain (or the wrong key) says so: at boot every
signature in its history fails, it logs *"EVERY signature this node checked
failed"*, and it **refuses API writes** (`EVERY_SIGNATURE_FAILED`) until it is
restarted with the right `meshId` and key — the history is quarantined, not
lost, and loads again then. A line typed into the `.bean` meanwhile is held in
the file as written, not signed, and adopted at that boot. A write made
meanwhile would be signed under the wrong domain, and at the next boot it would
verify and hide the warning. To write anyway, set
`signing.allowWritesWhenEverySignatureFails: true`.

**New mesh.** Generate a random UUID (`uuidgen`) and a unique `swarmTopic`, set
both on every node before the first directive is written, and there is nothing
else to think about.

**Existing mesh — the required step when you upgrade.** Set `meshId` to the
current `swarmTopic`, byte for byte, on each node. The resolved domain does not
change, so no signature is invalidated and no maintenance window is needed:
nodes can be switched one at a time, before or as each one is upgraded. What it buys is that the two are now separate
settings — from then on you can rotate `swarmTopic` (the join credential)
without touching the signature domain. The shipped
`deploy/gl-node.docker.json` does exactly this (`"meshId":
"openledger/docker-dev"`, its own topic).

**Existing mesh — moving to a *different* domain** (for example, two meshes
that share a topic string and must stop accepting each other's directives) is
a coordinated, all-at-once change, and every directive signed before it stops
verifying. Do it only if you need it:

1. **Pick one new value** and use that same string on every node. It is
   compared byte for byte, so leading or trailing whitespace is refused at boot
   rather than silently trimmed — a value that differs by one character between
   two nodes is a mesh-wide verification failure that presents as "the other
   node's key is wrong".
2. **Take a maintenance window and switch every node together.** During the
   window the mesh is partitioned by domain: a node on the new `meshId` cannot
   verify anything signed by a node still on the old domain, and vice versa.
   Anti-entropy will keep retrying, so a short split heals once every node is
   over, but a node left behind stays permanently unable to accept its peers'
   directives.
3. **Expect already-persisted signatures not to re-verify.** Directives written
   before the switch were signed under the old domain. They stay in the ledger
   and their content ids are unchanged — the content hash does not include the
   signature envelope — but a signature check against the new domain will not
   pass for them. Verify the mesh has converged *before* the switch, so nothing
   is still in flight that needs its signature checked afterwards.

**Confirm the boot log** either way. Each node logs the domain's `source`
with its length and a four-character prefix — never the value itself, because a
`meshId` copied from the topic *is* the gossip join credential. All nodes must
report `source="p2p.meshId"` and the same length and prefix.

Rolling back is the same procedure in reverse, with the same window.

#### Joining a mesh / removing a peer

Replication has one bound it applies to *this node's own clock*: a directive
whose `openledger-lamport` would move the node's clock by 2^32 or more in one
step is refused (`LAMPORT_ADVANCE`, the adoption ratchet) until the node has
caught up through the directives in between. On a dense history a fresh node
therefore joins by anti-entropy alone, in any delivery order: each round adopts
what is within reach, the clock rises, the next round adopts the rest. That
stops holding the moment the history carries **one gap of the size the ratchet
permits** — a single legal directive at `clock + 2^32 − 1`, adopted by every
node at the time, or a jump of any size in a history written before the ratchet
existed (a hand-typed `openledger-lamport`, say). Every node that adopted the
jump carries on normally, and its own writes are accepted everywhere. But a
node that joins **later**, or is **rebuilt from an empty disk**, climbs to the
clock just below the jump and finds the first honest directive after it a full
step away. The only bridge is the jumping directive itself — and if its author
has since been **removed from the allowlist** (the remedy the `LAMPORT_CEILING`
text prescribes), that bridge is refused at intake, permanently. The same holds
without any lamport rule when the removed author's directive is a
*transaction*: everything authored on top of it names it as a parent, and a
node that refuses the parent buffers all of it as orphans forever
(`MISSING_PARENT`).

The node **tells you** when it is in this state: at boot, and when an adoption
opens one, it logs *"the ledger history carries a lamport gap no honest mesh
makes"* (or *"an adopted directive opened a lamport gap"*). It is judged on the
history the node serves — two consecutive lamport values at least 2^28 apart,
which honest traffic never produces (each event moves the highest clock by one)
— so honest meshes, however many nodes join them, never see it, and a record
the same boot quarantines (an edited lamport line, say) does not trigger it.
The line names the author at the top of the gap: the node that jumped the
clock, or — on a node that no longer holds the jumping directive (its author
removed, or the directive deleted) — the first honest record stamped above it;
the node cannot tell which, and says so. A gap under 2^32 is only *diagnosed*:
anti-entropy still crosses it, and nothing needs doing. A gap of 2^32 or more
is the one later joiners cannot cross, and the line then gives the bootstrap
join below. A `LAMPORT_ADVANCE` refusal that
repeats tick after tick on a fresh node is the same state seen from the other
side.

**Removing a peer from the allowlist** is therefore a two-part decision. Its
directives already in the history stay there (the mesh keeps what it accepted,
and peers keep re-supplying anything you delete), and from then on **every
later joiner must be joined by bootstrap, not by anti-entropy alone**:

1. **Pick a current peer** — any node that already holds the whole history —
   and stop it cleanly. A node folds its `<ledgerPath>.journal` into the `.bean`
   at shutdown (and at startup and every full rewrite), so a stopped node's
   `.bean` is complete and canonical. Do not copy a live node's file (its latest
   writes may still be in the journal), and do not copy the journal itself: it
   is that node's own crash-recovery sidecar, and the compacted `.bean` already
   holds everything it did.
2. **Copy that peer's compacted `.bean`** to the joiner's `ledgerPath`. Copy
   only the `.bean`; the joiner creates its own `.lock`, `.journal` and key.
3. **Boot the joiner under its own key and its own author id** — its own
   `p2p.secretKeyPath`, the same `meshId`, its own EndpointId on everyone's allowlist
   as for any new node. Nothing in the copied file belongs to the joiner: boot
   loads every enveloped record as *history* (author, lamport, parents and
   signature verified as they were written, whoever wrote them) and the
   joiner's clock **resumes above the highest lamport in the file**, so the gap
   is behind it. The removed author's records load too, exactly as they sit in
   every other node, because a file is history, not intake — the allowlist
   governs what a peer may *send*, not what a node already holds.
4. **Start the peer again and let anti-entropy finish the join.** Everything
   authored since the copy is within one ratchet step of the joiner's clock and
   arrives normally; the joiner's own writes are accepted by every node. The
   boot warning above fires on the joiner at every boot, naming the jump's
   author; that is expected — the gap is in the history it now serves — and it
   is your confirmation that the copy carried the gap.

This is the join the test `h19_fresh_node_bootstrapped_from_a_peers_file_converges`
performs (`crates/p2p/tests/convergence.rs`): the copy boots with the peer's
whole history, the removed author's directive included, every node authors on
top, and the mesh converges — equal DAGs, heads and balances — with the joiner's
own directive accepted everywhere.

**Joining over the wire instead (`p2p.joinFrom`).** When the history's problem
is a gap alone — a removed author's jump that was an `open`, or a history
written before the ratchet — the joiner can skip the copy: set `p2p.joinFrom`
on it to a current peer's EndpointId (one of its `bootstrapEndpointIds`) and
start it with an empty ledger. While the joiner holds no record of its own it
adopts what that peer serves past the ratchet — the trust you would give that
peer by copying its `.bean` — and every other check still applies (the
ceiling, the allowlist, signatures, content). Once the peer has nothing left
the joiner lacks, the window closes (*"joined: this node holds everything its
join peer serves"*) and the ratchet applies to it like any peer. Records from
any other peer are ratcheted throughout. A removed author's *transaction* is
still refused by the allowlist, so a history built on one needs the copy above.
Once joined you can remove the setting; a node that has written ignores it and
says so at startup. The tests `h19_fresh_node_converges_after_a_maximal_legal_jump_and_allowlist_removal`
and `h19_pre_t63_history_with_one_large_jump_is_joinable` perform this join.
There is no exemption for "first contact" with an unnamed peer: that would be
exactly the unbounded jump the ratchet exists to remove, on the nodes least
able to notice.

Two related rules that do **not** change: a transaction's parents are chosen
so that no author's heads can crowd out another's (at most `max(1, 256 /
authors)` per author, then smallest id — so a peer that grinds content ids cannot keep an
honest head unmerged), and a peer's transaction is never refused for the number
of heads its author holds on this node (that bound made DAG membership depend on
which subset a peer chose to serve first; frontier size is a cost every replica
pays alike, divergence is not).

### Format v2 (`format.wire2`, `format.idv2`)

Format v2 is the one coordinated change to what nodes put on the wire and in
the ledger (the design is `docs/FORMAT_V2_DESIGN.md`). Both switches are **on by
default**, so a new mesh is in Format v2 from its first record. Every node on
this build **accepts** both formats; the switches decide only what a node
**emits**. A node on a build from before Format v2 reads neither: upgrade every
node to this build, or set both switches to `false` on every node until the
older ones are upgraded, then remove them (one node at a time is fine — a mesh
holding both formats converges).

**`format.wire2` — the wire encoding.** Frames are sent externally tagged
(`{"supply": {...}}`), so a node decodes a frame straight into its message
instead of buffering it whole first; the size and count checks of the old
encoding still run in front of it. A switched node dials the
`openledger/anti-entropy/2` protocol and gossips on `<swarmTopic>/2`; every node
serves both protocols, so anti-entropy works across a mixed mesh, while
announcements reach only the nodes on the same topic until everyone has
switched (anti-entropy still delivers everything). It changes nothing stored
and can be switched back. On a mesh moving from `false` to the default, switch it
first.

**`format.idv2` — record identity and signatures.** A record written through
the API carries `openledger-format: "2"`. Its id then covers its author as well
as its body, so another peer that publishes the same body first owns only its
own copy — not yours (before, the first copy of a body held the id, whoever
signed it). And it is signed over a length-prefixed message, which no field
value can shift across a field boundary. Two consequences to know:

- **The same body from two different authors is two records**, both counted.
  The same author writing the same body twice is still one record.
- **Existing records keep their v1 ids and signatures forever** — nothing is
  rewritten — and a node that switches still verifies its own v1 history. A
  ledger written before this default keeps its v1 records; the node's new
  writes are v2.

A line typed into the `.bean` keeps v1 identity on a switched node, so every
repair this README prescribes ("delete its `openledger-*` lines so it is
re-adopted under the same id") still gives the record back its id; a typed line
that spells `openledger-format: "2"` itself (with its `openledger-author`) stays
v2. On a mesh moving from `false` to the default, switch it mesh-wide in one
window, like `meshId`, so the mesh does not write the same transaction under
both formats.

### Using Auth

Auth is **on by default**, on every bind. Every `/graphql` request carries a
key in an `X-Api-Key` header. A node accepts two kinds:

- **The operator key**: the node's own (`auth.apiKey`, `GL_NODE_API_KEY` or
  the generated key file, below). It may do everything on this node, and it
  is never replicated: each node has its own. Use it to run the node and to
  issue the first people's keys.
- **People's keys**: one per person, with a role, issued by an admin and
  honoured by every node of the mesh (below, *People and keys*).

Each request is checked against the caller's role **before anything runs**:

| Role | May |
|---|---|
| `read` | Every query: reports, balances, the journal, `verify` |
| `write` | Also every mutation: transactions, opening and closing accounts |
| `admin` | Also manage people: `grantAccess`, `revokeAccess`, `renameUser`, `accessList` |

The rule goes by operation type, so a mutation added later needs `write`
without anyone guarding it. A request mixing several operations, aliases or
fragments is held to the strictest thing in it. A missing or unknown key gets
**HTTP 401**; a known key whose role is too low gets HTTP 200 with a GraphQL
error coded **`FORBIDDEN`**, and nothing runs.

**A local node needs no setup.** With a loopback `bindAddress` and no
`auth.apiKey` (and no `GL_NODE_API_KEY`), the first boot generates a random
32-byte key and writes it, hex-encoded, to `auth.apiKeyPath` (default
`./data/api.key`): a regular file, mode 0600, owned by the account the node runs
as. Later boots read the same key back; the node never logs it. The file is
held to the node's secret-key rules — a symlink at the path, a file another
account owns or can read, or one with more than one link is refused at boot
rather than used — and an empty file (a crash mid-write) is replaced by a new
key. To rotate the key, stop the node, delete the file and start it. Read it
into your client's environment:

```bash
export GL_NODE_API_KEY="$(cat data/api.key)"
```

Before this release a loopback node served its mutations to anything that could
reach the port, with no key: another program or another account on the machine,
or a web page that got past the browser checks (H-01). To keep that, set
`"auth": { "enabled": false }` — allowed on a loopback bind only, and the node
WARNs about it at every boot. Such a node has no people: everything on the
machine is its operator, so it accepts no people's keys and refuses the admin
API (`NO_ACCESS_LIST`) — otherwise any local program could issue keys the
whole mesh honours.

**A public bind needs a key you set**, so its clients are given it on purpose:
`auth.apiKey` or, better, the environment. Keep the key in the environment
rather than pasting it into a shell history or a script:

```bash
export GL_NODE_API_KEY="$(openssl rand -hex 32)"   # and restart the node

curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -d '{"query": "{ health { status } }"}'
```

The `/health` endpoint never *requires* authentication. On a non-loopback bind it discloses its version/heads/peers detail only to a request carrying a valid `X-Api-Key`. It is not unconditional, though: like `/graphql`, it answers `403` to a request whose `Host` is not in `allowedHosts`, and `429` past its own rate limit — see [Health Check](#health-check).

### People and keys

Besides the operator key, each person can have a key of their own, with a role:
**read** (reports, balances, the journal), **write** (also enter transactions
and manage accounts) or **admin** (also manage people). Grants live in the
ledger as access records and replicate like any record, so a key works on every
node of the mesh. People's keys need a signing node (`signing.enabled`; every
mesh signs). `auth.adminNodes` limits which nodes may change who has access.

Manage people from the node's machine, as the node's user (in Docker,
`docker exec <container> gl-node user …`). The commands read the node's config
from `GL_NODE_CONFIG` and use its operator key:

```bash
gl-node user add --name "Ana Ruiz" --role write --expires 2026-12-31
gl-node user list
gl-node user rename u_7f3a9c21d4e8b605 --name "Ana Ruiz-Soto"
gl-node user add --user u_7f3a9c21d4e8b605 --role read   # new role and key; the old key stops working
gl-node user revoke u_7f3a9c21d4e8b605
```

`user add` prints the person's id and key **once**. The node keeps only the
key's SHA-256, so a lost key is replaced with a new `user add --user`. If
`user add` fails without an answer (a timeout), run `user list` before trying
again: the person may already be there, and a second `add --name` makes a
second person. The
person sends the key as `X-Api-Key`. `--expires` is the last day the key works.
A revocation reaches each node as fast as replication does; a node cut off
from the mesh accepts the key until it hears of it.

**Who entered it.** A person's writes (transactions, opening and closing an
account) carry their user id in the record, `entered-by: "u_…"`, signed with
it. The journal shows it as `enteredBy`, with `enteredByName`: their latest
name, kept after their access is revoked. Writes made with the operator key
carry none, exactly as before people had keys, so `enteredBy` is empty for
the operator, for lines typed into the `.bean`, and for history from before.
An entry typed into the `.bean` with an `entered-by` line is refused: the node
would sign someone's name to an entry they did not make. `entered-by` is part
of a record's identity: one person entering the same entry twice through the
same node makes one record (`alreadyExisted`), and two people entering it make
two. With Format v2 (the default) the node is in the id too, so the same entry
retried through *another* node is a second record — retry through the node
that timed out. Another node of the mesh can write any `entered-by` it likes,
as it can write any record: it names who entered a record, it does not prove
it.

The same operations are in the API, for an admin key: `grantAccess(name, role,
expires, userId)` (returns `userId` and `key`), `revokeAccess(userId)`,
`renameUser(userId, name)` and the query `accessList`. A refused change comes
back with a code: `INVALID_INPUT` (someone not on the list, a blank name, a
past expiry), `NO_ACCESS_LIST` (signing or auth is off) or `NOT_AN_ADMIN_NODE` (this
node is outside `auth.adminNodes`). Names, roles, expiry dates and key hashes
are part of the books: anyone given the `.bean` sees them, never a key.

### Several ledgers

One node can serve several companies' ledgers, each kept apart: its own
`.bean`, its own mesh and node key, its own people and keys. The config file's
ledger is the one named **`default`**, served at `/graphql` as before. Every
other ledger is a folder in `ledgersDir`, named for the ledger (1 to 40 of
`a-z`, `0-9` and `-`), holding a `ledger.json` beside its files:

```
data/ledgers/acme/ledger.json      the ledger's settings
data/ledgers/acme/ledger.bean      its books (created on first boot)
data/ledgers/acme/iroh.secret      its node key (created on first boot with P2P on)
```

`ledger.json` takes the ledger's own sections of the config file —
`watchLedgerFile`, `signing`, `format`, `p2p` and `auth.adminNodes` — with the
same defaults and the same checks; the ledger's file and key are always in its
folder, so `ledgerPath` and `p2p.secretKeyPath` are not set there:

```json
{
  "signing": { "enabled": true },
  "p2p": {
    "enabled": true,
    "meshId": "<a fresh uuidgen for Acme's mesh>",
    "swarmTopic": "openledger/<another uuid>",
    "relayMode": "custom",
    "relayUrl": "https://relay.example.com",
    "bootstrapEndpointIds": ["<the other nodes of Acme's mesh>"]
  }
}
```

A client names the ledger in the path: **`/ledgers/acme/graphql`** (POST; the
GraphiQL page is the `default` ledger's) and `/ledgers/acme/health`. A key is
checked against that ledger's people only, so a key issued in one ledger gets
`401` from every other; the operator key works on every ledger. A name the node
does not serve answers like a wrong key (`401`, the same body), so a name's
status says nothing about it; with the operator key it is `404`
(`NO_SUCH_LEDGER`), or `503` (`LEDGER_NOT_SERVED`) for a ledger refused at
boot. (The answer for a ledger that is served can take longer — its key check
does more work — so names are not hidden from timing; the rate limit bounds
how fast anyone can try.) A named ledger's `/health`
needs a key that ledger accepts; `/health` stays the `default` ledger's and open.

The command-line tools take `--ledger`:

```bash
gl-node --node-id --ledger acme            # acme's node id, for the other nodes' allowlists
gl-node user --ledger acme add --name "Ana Ruiz" --role write
```

At boot the node starts the `default` ledger and then each folder. A folder
whose `ledger.json` does not load, that repeats another ledger's `meshId`,
`swarmTopic` or fixed `listenPort`, or whose node key is another ledger's (a
copied folder: one node id in two meshes would tie them together), is logged
and not served; the others are. A folder named `default` is ignored, and files
in `ledgersDir` are not ledgers.
The node stops only if it can serve no ledger at all. Each ledger's log lines
carry its name (`ledger="acme"`). Adding or removing a ledger takes a restart
for now.

### Editing the `.bean` file by hand

**Editing a `.bean` file while the node that owns it is running is not
supported. Stop the node, edit the file, start it again.**

**Never edit an existing record. Append a reversing entry instead.** History is
append-only across the whole mesh: every peer holds the record the node wrote,
under its content id, with its signature. A line you change is a *different*
record (the content id covers the economic body) still carrying the *old*
signature, and no peer will ever accept it. Since T73, boot verifies the
signature of every record that carries an envelope — with this node's own key
for its own records, and with the author's key for everyone's once signing is
enabled — and a record that does not verify is **quarantined**: kept in the
file exactly as it is, kept out of the ledger, not served, not in any balance,
named in the boot banner as *"quarantined: signature does not verify — was this
record edited? (H-20)"*. To repair it, restore the original line from a peer's
copy of the ledger (or from the node's `.journal`/backup); then append a new
transaction that reverses the mistake. If no peer holds the original (a node
that ran with P2P off, or wrote the record while offline) and only an
`openledger-*` line was edited, delete that block's `openledger-*` lines instead:
the content id is unchanged, so the record is re-adopted as this node's own and
everything that names it resolves again. A record you **delete** from the file
is not gone either: peers re-supply it on the next anti-entropy round, because
the mesh keeps what it accepted. Adoption is one-way: the file is how records
get *into* this node, never how they leave it.

**What no peer could hold is not served.** A peer adopts a transaction only when
every parent it names is already in its ledger and the accounts it posts to are
open, on its date, for its currencies. A record this node holds that fails either
test — its parent was edited, deleted, restated or held as unparsable text; the
`open` it relies on was removed, or is dated after it; a posting whose amount was
deleted (a peer takes history only with every amount written) — would be refused
by every replica that lacks it, and so would everything this node writes afterwards. Boot
quarantines such records together with what descends from them, names each one
and why in the log (*"quarantining a ledger record no fresh replica could hold"*,
H-23), and keeps them in the file. On a mesh they come back when a peer holds
them: it re-supplies the missing parent and then them; a held record no peer
holds (written while offline, say) stays held until the node restarts or the
record is restored another way. On a node no peer
can help, restore the missing record from a backup, strip the `openledger-*`
lines as above, or add the missing `open` dated no later than the first
transaction on the account and listing its currencies, and restart — boot judges
the history after it has adopted what you typed, so an `open` that admits the
transactions frees them in that same boot. Restating a record in a different form
(a larger unit, a corrected body) gives it a new id, so what named the old id
stays held; restate the chain **on one node only** — type the record again
without its own `openledger-*` lines (an edited body under its old envelope is
held for its signature), and delete the `openledger-*` lines of each record that
descends from it, so each is re-adopted under its own id with parents that node
serves — or join nodes by bootstrap (§Mesh identity). Every other node adopts the
restated records from that one and must **not** restate: each node's log names
the same held records, but a second restatement is a second record that every
replica serves and counts. Once a node holds the restatement, its next boot says
the old block can be deleted (*"delete this block"*).

Three edits an editor makes by accident are caught the same way: a stray
dedent, a byte-order mark glued to a posting, or a stray word inside a
node-written transaction used to load the parsable head as a *shorter*
transaction (one posting, its counter-posting dropped). Such a block is now held
whole, as unparsable text, and written back byte-for-byte until you repair it.

That stop → edit → start path is the supported one, and this is what it does.
At boot, a directive that lacks `openledger-author` **or** `openledger-lamport`
was not written by a node, so it is treated as **operator input** rather than
history: it goes through the same checks a live hand edit goes through
(lifecycle, balance, body size, envelope keys), is stamped with this node's
author id, Lamport value and parents, is **signed with this node's key once the
key is loaded** — which happens before the startup compaction and before any
peer is served — and the startup compaction writes it to the file in canonical
form. From then on it replicates like any other local write. A hand-typed entry
the checks refuse is **quarantined**: kept in the file exactly as you wrote it,
kept out of the ledger, named in the boot banner with its reason, until you
repair it and restart (boot never drops what it read). The same rule adopts,
once, the envelope-less `open`/`close` lines a very old build wrote before it
stamped non-transaction directives.

The half-envelope cases follow from "lacks either": an entry with only an
`openledger-lamport` line is operator input — the lamport is not a clock value
this node issued, so it is re-stamped, this node's author is stamped, and any
`openledger-signature` on it is discarded (a signature under a fresh lamport
verifies nowhere). An entry with only an `openledger-author` line is re-stamped
the same way; if that author is **this node**, it is signed and replicates, and
if it names **another node** it is refused — quarantined at boot, dropped by a
live reconcile — because this node cannot sign for it, every signing peer
refuses it unsigned, and adopted it would become the parent of this node's next
write, so everything written after it would be refused too. Drop the author line
to adopt it as your own, or restore that node's complete signed record from a
peer's copy. A hand-typed `openledger-parents` line must name records this node
**serves**; one that names a parent that exists nowhere, or one held in the
quarantine (a quarantined record is never served), is refused, because a signed
record with a parent nobody can resolve orphans everything written after it. A
hand-typed `open` of an account that is already open is refused exactly as the
API refuses it. "Already open" is judged against what this node serves: when
its own `open` of the account is held (you edited it, say, so its signature no
longer verifies), a hand-typed `open` is adopted — at boot as well as under a
running node — and is the remedy the quarantine warning names. If a peer later
re-supplies the original `open`, the account carries both, which changes
nothing: a transaction may use any currency listed by any `open` dated on or
before it.

Fixing a node-written record **and** appending new lines in the same edit is
safe. Boot stamps your new lines' parents before it has checked the signatures
of the history under them, so the edited record (quarantined a moment later) can
be what they were first stamped against; the quarantine re-chooses the parents
of every line not yet signed from what survives, and refuses — as written — a
new line that can no longer stand without the quarantined record (one whose
hand-typed parent it was, or a transaction on an account only it opened). The
new lines' `openledger-lamport` is stamped only after every signature has been
checked, so an edited lamport line can no longer lift them above a value the
mesh accepts. And a
node that **enables signing over a history it wrote unsigned** finds that
history quarantined at the first signing boot; delete the `openledger-*` lines
from those blocks to re-adopt them as this node's own, signed, operator input.
If the mesh ran with signing off, other nodes hold copies of those records too,
and each would re-adopt them under its own key if it applied the same remedy —
the records would then carry a different author on each node. Apply the remedy
on **one** node (the one that wrote them), and on every other node delete those
blocks instead; the peers re-supply the re-signed copies.

An edit that changes a node-written record **and** removes one of its
`openledger-*` lines is not refused as an edit: without its full envelope the
record is operator input, so it is adopted as a **new** record beside the
original (which peers still hold and re-supply). To correct a record, append a
reversing entry; never edit the record itself.

A node that signs is always its key. Its author id — the `openledger-author` it
writes — is the node key's public half, the same value its P2P endpoint id would
be, whether or not P2P is enabled. So a single signing node can join a mesh
later by turning P2P on, and its history verifies as it is. Builds before T80
set the author only when P2P booted, so a node that signed with P2P off wrote
`openledger-author: "local"` over a real signature; this build re-attributes
every such record whose signature verifies under the node's own key (the
signature does not cover the author, so it stays valid), logs it once, and the
next compaction writes the real author. Nothing to do by hand. A `"local"` record
whose signature does **not** verify as this node's is quarantined like any
edited record.

The node treats its ledger file as something it writes, and a persist is a
full-file atomic rewrite. Two mechanisms make a concurrent hand edit *less*
likely to be lost, and neither of them makes it safe:

- **A `<ledgerPath>.lock` sidecar.** The node takes an exclusive lock on it at
  startup, so a second `gl-node` pointed at the same file fails closed with a
  message naming it. This excludes other **node processes**, not editors — your
  text editor knows nothing about it.
- **Adopt-before-persist.** The node records a hash of the exact text it last
  wrote or read. Before any write it re-reads the file, and on a mismatch it
  reconciles the hand edit *in* before performing the write that would otherwise
  have erased it unseen.

Adopt-before-persist is a **mitigation, not a lock**, and it says so at the call
site: an edit that lands between the hash check and the atomic rename is still
lost, and so is one made by an editor that replaces the file's inode rather than
writing through it. There is no window in which concurrent editing is correct —
only a window that is now smaller.

**There is no setting that turns adoption off, and there never was.** This
README used to say adoption required `"externalFileEdits": "enabled"`; that
setting gated the 250 ms file watcher and nothing else, so an operator who set
the documented opt-out — which was also the default — got no control at all.
The key is gone (a config that still carries it is refused at boot, by name,
with the replacement spelled out), and what it really gated is now
`watchLedgerFile`.

Adoption itself is not configurable, on purpose. Adopt-before-persist runs
*inside* the write that is about to replace the whole file, so "off" could not
mean "ignore the edit" — only "destroy it silently", which is the bug the
mechanism exists to fix. Refusing the write instead would wedge every write on
a node whose file was edited at all. Both readings also strand the quarantine:
a record the node refused at boot, or a block it could not parse, is held
verbatim and leaves only by being repaired **in the file** and re-read by this
same path.

So `watchLedgerFile: false` (the default) does not mean hand edits are ignored.
It means they are adopted at the node's next full rewrite rather than within
250 ms, and that the node does not read the ledger file four times a second to
find out.

When an edit is adopted it is treated exactly as a local API write by the same
operator, because that is the authority it carries — same machine, same file,
same trust boundary:

- Entries are canonicalized and re-ordered the way boot orders them, so where
  you pasted something in the file does not change the result.
- An entry with no signature is signed as this node's own before the first
  persist, so it replicates like any other local write. Two exceptions: an entry
  that carries a **full** envelope (author, lamport and signature) is adopted
  untouched if its signature verifies and refused if it does not (it came from
  a peer, or it was edited), and an entry *without* a full envelope whose
  author names a different node is refused (signing it here would produce a
  signature that verifies nowhere, and unsigned it would orphan every later
  write). A signature on a half envelope is discarded and a new one made, as
  described under the stop → edit → start path above.
- Entries that fail validation are dropped, each logged with its content id and
  the reason, before the canonical rewrite removes them from the file — and that
  rewrite runs even when *every* entry in the edit was refused, so a refused
  line does not linger on disk to be loaded raw at the next boot. (At boot the
  same refusal quarantines instead of dropping; see above.) An entry with a
  full envelope is history, not a typed line, and is kept when boot would keep
  it: one over a limit peers hold history to or over the 1 MiB body cap, one the
  accounts do not admit, and one whose parent this node does not serve are held
  in the quarantine and written back, as at boot. One refusal is the running
  node's alone: a full envelope whose lamport would move this node's clock by
  more than 2^32 in one step (the adoption ratchet, `LAMPORT_ADVANCE`) is refused
  and dropped by the rewrite, while boot loads the same bytes as history — to
  keep such a record, stop the node, put it back in the file and start it (the
  refusal's log line says so). A line this node adopts
  from the file is not offered to peers until the rewrite that spells it
  canonically has succeeded, so a failed rewrite followed by a restart (which
  stamps the line again) never leaves the mesh holding two envelopes for it.
- A file that no longer **parses** blocks writes until a human fixes it, rather
  than being canonicalized on top of a half-saved edit. The refusal records
  nothing about the broken file — not its hash, not its size — so every later
  write re-reads it and refuses again until it is repaired; a broken file is
  never mistaken for "what the node last read" and then overwritten. A line the
  parser cannot read *in full* counts as not parsing: trailing tokens it does
  not understand are refused, naming the text it could not read, rather than
  being dropped so that the shorter line left over is adopted and written back
  in place of what you typed. Comments and trailing whitespace are still fine
  everywhere they were before.
- Removing or renaming the `.bean` under a running node does not lose anything:
  the next write recreates it from memory with every directive in it, and a
  failed write never replaces what is in memory with a file that lacks a record
  the node already wrote. That includes a backup copied over the live file, and
  lines you added by hand once the node has stamped them — at startup, or as
  soon as a running node adopts them — whether or not signing is enabled. A
  line the node has stamped is its record: deleting it from the file does not
  retract it (append a reversing entry). A backup taken before the node
  rewrote your hand-added lines keeps the envelope the node gave them, not a
  fresh one, and when that envelope names a record the backup does not hold,
  the node keeps memory and rewrites both rather than install a ledger whose
  records name a parent it lacks.
- The 64 MiB limit applies to the file as the node writes it. Hand-typed
  directives gain an envelope of several hundred bytes each, so a file just
  under the limit can grow past it; boot then warns, and **every write fails**
  until the file is made smaller — refused before staging, with no reload, so
  the node stays responsive (the compaction the node attempts at startup and at
  shutdown is refused the same way, without a reload). Stop the node, shrink the file, restart. Near the
  limit, a mutation whose record would
  not fit is refused before anything changes (`RESOURCE_LIMIT_EXCEEDED`,
  "refused before staging"), and a peer's batch that would not fit is deferred
  and that peer paused for `p2p.antiEntropySupplyBackoffSeconds`. What
  shrinking can mean on a mesh is limited: records you delete from the file
  come back from peers (they keep what they accepted), so only comments and
  hand lines the node has not yet adopted really go away. The lasting remedy
  is to start a new ledger — carry the closing balances forward as opening
  entries in a fresh `.bean` under a new `meshId` for every node, and keep the
  old file read-only as the archive of the years it covers.

### The commit journal (`<ledgerPath>.journal`)

Between full rewrites the node appends each write to a sidecar,
`<ledgerPath>.journal`, and folds it back into the `.bean` at startup, at
shutdown and on the next full rewrite. You normally never see it; these are the
cases where you might:

- **It must be the node's own file.** The journal, the `.lock` and the key file
  must be regular files (not a FIFO, directory or symlink), owned by the uid the
  node runs as, with a single hard link; the lock and key must be `0600`, and a
  journal writable by group or other is refused (one merely readable by others
  loads with a warning and is compacted away). The node appends only to a
  journal with no group or other permission bits (0600 or stricter). A FIFO,
  directory or dangling symlink at the `.bean` or the journal refuses boot.
- **A `.bean` that is a symbolic link** you created as the node's user is
  followed: the node reads, journals, locks and rewrites at the link's target,
  so the journal, `.lock` and temporary files sit beside the target and the
  link is kept (a ledger on another volume works). A link owned by any other
  user refuses boot — otherwise whoever can write the ledger's directory could
  point it at any file the node's user owns and have it overwritten. For the
  same reason the link must sit in a directory owned by the node's user that
  group and others cannot write (not `/tmp`, not a shared directory, and on
  macOS not one whose access control list lets another account add or remove
  entries — `ls -le` shows it, `chmod -a` removes that entry; macOS's own
  `deny delete` on the home folders is fine), and it is followed **one link
  deep**: a link to another link refuses boot. A data directory created under a
  group-writable umask (002, mode 0775) is refused with its mode named;
  `chmod g-w,o-w <directory>` fixes it. The checks and the follow are made
  through one open handle on the link's directory, and the path the node then
  uses must be the file the link names in the directory it names, so swapping
  a directory above the link cannot redirect the node while it starts. After
  that the node works at the target by path: whoever can write a directory
  above the TARGET controls the ledger, as for any `.bean`. A directory in the
  path may itself be a link. If the ledger was converted to a link
  after an unclean stop, its journal is still beside the link, where the node
  no longer looks: boot refuses and names it. Move it beside the target (as
  `<target>.journal`), or put the ledger back, start the node once so it folds
  the journal in, stop it cleanly, and then make the link. The link is resolved
  once, when the node starts: turning the path into a link while it runs is
  not followed (a recovery after a failed write refuses it, and rolls that
  write back) — stop the node first. If you did not, the node's next write
  rewrites the file at the path, replacing your link with a regular file, and
  the file the link pointed to stops receiving writes: stop the node, move
  the path's file where the link pointed, and make the link again.
- **A `.bean` missing beside a journal refuses boot** rather than starting an
  empty ledger with the journal's writes on top.
- **A torn final record** — a crash mid-append — is dropped with a warning. On
  some filesystems the crashed record reads back at full length but with zeros
  (XFS) or old disk contents (ext4 `data=writeback`); a final record that fails
  its checksum is treated the same way, unless another record follows inside it
  — an intact one, or a torn one behind a record whose own bytes still verify
  (a damaged length field on a record that was acknowledged), which refuses
  boot instead. A final record damaged on disk after its write succeeded looks
  torn too: it is dropped loudly, and on a single node that has no peer to
  re-supply it, the sidecar below is where it is. The same applies to a journal whose recovery reload after a failed write
  could not read the files. The journal is kept as
  `<ledgerPath>.journal.torn-<unix-seconds>` instead of being deleted. No boot
  reads it; inspect it, then remove it.
- **Reserved names.** `<ledgerPath>.tmp` and `<ledgerPath>.tmp.<pid>.<16 hex
  digits>` are the node's temporary files; a stale one is deleted at startup. Do
  not name your own files that way. Anything else, `ledger.bean.tmp.backup`
  included, is left alone.
- **Damage anywhere else refuses boot**, naming the byte offset. It cannot be a
  crash, so the node will not guess which records to keep.
- **The per-record checksum is unkeyed.** It catches bit rot and accidents, not
  tampering: anyone who can write the journal can rewrite a record and its
  checksum together. The ownership and mode rules above are what protect it.
- **"Error but durable."** If a full rewrite installs the new `.bean` and then
  cannot delete the old journal (a sticky directory, a journal owned by someone
  else, an immutable attribute), the write is **reported as failed but is on
  disk**, and the node's reload shows it. Before retrying a failed mutation,
  look for it (`journal`, or `transaction(txid:)` if you have the id) — a blind
  retry can book it twice.
- **A failed write may already have been seen by a peer.** Between staging a
  write and the reload that follows a failed commit, a peer can fetch it. A
  retry of the same entry has the same content id (the body is the same) but a
  new lamport, parents and signature, and every node keeps whichever envelope
  it got first. Balances and membership still agree everywhere; only that
  record's parents, and so the head sets, differ between the nodes that took
  one copy and those that took the other. It is the same property as two
  nodes entering the same body independently.

---

## Docker

### Build

```bash
docker build -t openledger .
```

The base images are pinned by digest as well as tag, and the release build runs
`--locked`, so the same source commit produces the same image with the same
dependency versions. Refresh a pin deliberately, in its own commit; the exact
`docker manifest inspect` commands are in the `Dockerfile`.

### Run

The container binds `0.0.0.0` inside its own network namespace — that is how a
container is reachable at all — so the config below carries everything a
non-loopback bind requires, and the **published** port is pinned to the host's
loopback interface:

```bash
# Create a config file for Docker. A public bind needs auth, terminated TLS
# and a Host allowlist; the node refuses to start without them.
cat > docker-config.json <<'JSON'
{
  "ledgerPath": "/data/ledger.bean",
  "bindAddress": "0.0.0.0",
  "graphiql": false,
  "allowedHosts": ["localhost"],
  "tls": { "mode": "terminated" },
  "auth": { "enabled": true, "apiKey": "" }
}
JSON

# The image runs as uid 1000 (`glnode`). Create the data directory yourself
# and hand it to that uid first: if `docker run` has to create it, it is
# created root-owned and the node cannot write its ledger. (Docker Desktop on
# macOS/Windows maps ownership for you; the `chown` is for a Linux host.)
mkdir -p data
sudo chown 1000:1000 data

# Run with persistent data. The key comes from the environment, not the file.
docker run -d \
  -p 127.0.0.1:4000:4000 \
  -e GL_NODE_API_KEY="$(openssl rand -hex 32)" \
  -v $(pwd)/data:/data \
  -v $(pwd)/docker-config.json:/data/gl-node.config.json:ro \
  openledger
```

`-p 127.0.0.1:4000:4000` rather than `-p 4000:4000`: the plain form publishes on
every host interface, and since `tls.mode` is `"terminated"` while nothing here
terminates TLS, that would serve the writable GraphQL API — API key and all — as
plaintext to anything that can route to the host. Put a real TLS terminator in
front and point it at the loopback port; only the terminator gets a public
listener, and its address then belongs in `trustedProxies`.

GraphiQL is off: it is refused outright on a non-loopback bind. Query the node
with `curl` and the `X-Api-Key` header as shown under [Using Auth](#using-auth),
or run a second loopback-bound node for interactive exploration.

**One node per ledger file.** A node takes an exclusive lock on a
`<ledgerPath>.lock` sidecar at startup, so pointing two containers at the same
data volume makes the second one exit with an error naming the file. That is
the exclusivity check working: two nodes sharing one `.bean` each rewrite the
whole file and silently discard the other's directives. Give every node its own
volume.

### Multi-node stack

`deploy/docker-compose.yml` brings up three nodes on one bridge network that
**replicate with each other**, over direct addresses on that network, with
nothing going to n0. Prepare the mesh once, then start it:

```bash
deploy/mesh-init.sh
docker compose -f deploy/docker-compose.yml up -d    # or docker-compose
```

`mesh-init.sh` creates `deploy/.env` with a fresh API key per node (if it does
not exist), picks a new `meshId` and topic, asks each node for its EndpointId
(`gl-node --node-id`, which creates the node's key in its volume and starts
nothing), and writes `deploy/mesh/node-{0,1,2}.json`: `relayMode: "custom"`
without a relay, `listenPort` 4433, and each peer's id and address
(`node-1:4433`, …). Both `deploy/.env` and `deploy/mesh/` are gitignored —
they belong to this installation.

**A stack that already holds history** keeps its records verifying only under
the `meshId` they were signed with, so the script refuses to pick a fresh one
when any node's volume holds a ledger. Stacks from before `mesh-init.sh` signed
under `openledger/docker-dev`: run `MESH_ID=openledger/docker-dev
deploy/mesh-init.sh`, keeping the volumes. Only for a new mesh with no history
to keep: `down -v`, delete `deploy/mesh/`, run it again.

One shared API key would mean compromising any single node grants write access
to all of them, and rotating it is an all-or-nothing outage; the placeholders in
`deploy/.env.example` are too short to boot, so a stack started with them fails
instead of coming up with a guessable credential. Ports are published on
`127.0.0.1` only, for the reason above; the file's header comment covers the TLS
terminator and `trustedProxies` decisions for a real deployment, and
`docs/OPERATIONS.md` how nodes on different machines find each other (*Running
a relay*).

---

## Running Tests

```bash
# Everything a change must pass before it is committed: fmt, clippy, all tests
scripts/gate.sh

# Prove a test catches the bug its fix closes (see CLAUDE.md, "Revert checks")
scripts/revert_check.py scripts/revert_specs/h01_l23.json

# The gl-node binary itself, end to end on loopback (part of the gate); with
# GL_NODE_PREVIOUS_BINARY set, also an upgrade and rollback from that binary
cargo test -p gl-node --test shipped_binary
GL_NODE_PREVIOUS_BINARY=/path/to/old/gl-node cargo test --release -p gl-node --test shipped_binary

# Build and check a release of the committed tree (docs/RELEASE.md)
scripts/release.sh

# Run the full workspace suite
cargo test --workspace

# Run a specific crate's tests
cargo test -p ledger
cargo test -p p2p
cargo test -p security
cargo test -p gl-node

# Run a specific test by name
cargo test -p ledger -- ct9_

# Check formatting + linting
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

---

## Project Structure

```
openledger-v2/
├── Cargo.toml                # Workspace root
├── Dockerfile                # Multi-stage Docker build
├── gl-node.config.json       # Minimal local config (edit or replace)
├── deploy/                   # Docker Compose stack; gl-node.production.json, the production template
├── scripts/                  # gate.sh, revert checks, smoke test, upgrade rehearsal, release.sh
├── docs/                     # OPERATIONS.md, RELEASE.md, Format v2 design
│   └── audits/               # Security audit reports (latest: SECURITY_AUDIT_0927.md) and their task trackers
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
│   │   ├── src/service/      # LedgerService, one module per concern:
│   │   │   ├── mod.rs        #   the struct and its re-exports
│   │   │   ├── boot.rs       #   boot and operator input
│   │   │   ├── verify.rs     #   signature pass, served-set rule
│   │   │   ├── quarantine.rs #   held records, closure, copy chooser
│   │   │   ├── authoring.rs  #   this node's writes, envelope stamping
│   │   │   ├── commit.rs     #   two-phase commit, compaction
│   │   │   ├── recovery.rs   #   failed-commit recovery, reload
│   │   │   ├── reconcile.rs  #   live hand-edit reconcile
│   │   │   ├── remote.rs     #   directives from peers
│   │   │   ├── access.rs     #   accessors, served views
│   │   │   ├── lamport.rs, envelope.rs, resource_limits.rs,
│   │   │   │   blocks.rs, file_io.rs, error.rs  # shared rules and I/O
│   │   │   └── tests/        #   unit tests, one file per concern
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
