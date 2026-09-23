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
INFO  gl-node starting address=127.0.0.1:4000 version=0.1.0 ledger=my-ledger.bean auth_enabled=false p2p_enabled=false graphiql=false
```

### 4. Open GraphiQL

The playground is **off** by default. Turn it on with `"graphiql": true` and visit **http://127.0.0.1:4000/graphql**. It is only available on a loopback bind — a non-loopback `bindAddress` with `graphiql` enabled is refused at boot, not silently downgraded.

---

## API Reference — curl Examples

All examples assume the server is running at `http://127.0.0.1:4000`. Pipe through `| python3 -m json.tool` for pretty output.

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

#### Amounts and precision

Any amount that is added into a balance (posting units, `{cost}`, `@`/`@@` price, and the auto-calculated
elided amount) must have magnitude at most **10^21** (`1000000000000000000000`). The limit includes 10^21
itself and allows any precision up to 28 fractional digits, and trailing zeros are free. The API, peers
and the `.bean` file all apply the same rule. `balance` and `price` directive amounts are not limited.

Every balance is kept as its exact sum. A reported figure is that exact sum whenever it fits a
`Decimal`'s 96-bit mantissa at the scale its amounts are written in. If it does not fit, which only
happens when amounts of very different scales are mixed (such as `1000` and
`0.0000000000000000000000000001`), the figure is rounded once, half to even, to the finest scale that
fits, and the report says so with `exact: false`. `balance` assertions and `verify` always compare
against the exact sum. With the 10^21 limit, no total in a ledger of any size the node accepts can be
too large to report.

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
    "query": "{ verify { ok nodesChecked errors truncated } }"
  }'
```

`errors` lists at most the first 1,000 problems, one per offending node;
`truncated` is how many more were found and not listed (`0` means `errors` is
complete).

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
before you set one. A signing node with no `meshId` logs a warning at every
boot saying so; `meshId` becomes required in a later release.

> `"apiKey": "change-me"` above is a **placeholder that this node refuses to
> boot with**, on purpose — see [API keys](#api-keys) before you copy the block.

| Field | Default | Description |
|-------|---------|-------------|
| `ledgerPath` | **(required)** | Path to the `.bean` file |
| `bindAddress` | `"127.0.0.1"` | HTTP listen address |
| `port` | `4000` | HTTP listen port |
| `watchLedgerFile` | `false` | Poll the `.bean` every 250 ms and fold a hand edit in promptly. It does **not** control whether a hand edit is accepted — nothing does — see [Editing the `.bean` file](#editing-the-bean-file-by-hand) |
| `graphiql` | `false` | GraphiQL playground; refused outright on a non-loopback bind. The page loads GraphiQL 4.1.2 (pinned) and React 18 from `unpkg.com` — see below |
| `cors.allowedOrigins` | `[]` | Browser origin allowlist; `"*"` is rejected |
| `allowedHosts` | `[]` | Extra `Host` header values accepted, beyond loopback and the bind address. **Required (non-empty) on a non-loopback bind** — see below |
| `trustedProxies` | `[]` | Reverse-proxy IPs whose `X-Forwarded-For` the rate limiter believes — see below |
| `tls.mode` | `"disabled"` | `"disabled"` (loopback only) or `"terminated"` (TLS at a host/proxy). A non-loopback bind must be `"terminated"`; in-process TLS is not implemented |
| `auth.enabled` | `false` | Require `X-Api-Key` header on GraphQL. Forced on for a non-loopback bind |
| `auth.apiKey` | `""` | The API key value (required if auth enabled). Minimum 16 bytes; published placeholders are refused — see [API keys](#api-keys) |
| `http.headerReadTimeoutSeconds` | `30` | Time a client gets to send a complete request head; also bounds idle keep-alive. `1`–`300` |
| `http.requestTimeoutSeconds` | `30` | Whole-request ceiling, body read and GraphQL execution included (`408` on expiry). `1`–`300` |
| `http.maxConnections` | `1024` | Concurrently served connections; excess stays in the kernel backlog. `8`–`65536` |
| `http.maxConnectionsPerIp` | `64` | Concurrent connections one client may hold (keyed per IPv4 address or IPv6 /64, like the rate limiter), so one address cannot take every slot. **It bounds one address or one /64, not one network:** a routed IPv6 /48 is 65,536 /64 keys, far past the global cap, so per-prefix limits wider than a /64 belong in your proxy or firewall. Addresses listed in `trustedProxies` are exempt — list your reverse proxy there, or every client behind it shares this cap. Clamped to `maxConnections`. `8`–`65536` |
| `signing.enabled` | `false` | Sign transactions with Ed25519. Forced on when `p2p.enabled` |
| `p2p.enabled` | `false` | Enable Iroh mesh replication |
| `p2p.secretKeyPath` | `./data/iroh.secret` | The node's Ed25519 key — its QUIC identity **and** its signing key. Created `0600` if absent. An existing file is refused unless it is a regular file (not a symlink), owned by the uid the node runs as, and not readable by group or other |
| `p2p.bootstrapEndpointIds` | `[]` | Allowlisted peer EndpointIds; empty drops inbound `Supply` |
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
| `p2p.relayMode` | `"n0"` | `"n0"` (public Iroh relays and discovery) or `"disabled"` (direct addresses only). Anything else is refused at boot — see [Relay mode](#relay-mode-p2prelaymode) |
| `p2p.swarmTopic` | `openledger/transactions` | Gossip topic, and the signature domain while `meshId` is unset; required unique on a public bind. Same form as `meshId`: non-empty, no surrounding whitespace, ASCII letters, digits and `- _ . : /`, up to 128 bytes |
| `p2p.meshId` | *(unset)* | Mesh identity bound into every signature. **Existing mesh: your current `swarmTopic`, verbatim** — any other value invalidates every signature already in the mesh. New mesh: a random UUID. Unset falls back to `swarmTopic` and draws a boot warning on a signing node — see below |

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
`GET /graphql` loads GraphiQL **4.1.2** (an exact version, not the floating
`4`) and React 18 development builds from `unpkg.com`, without subresource
integrity — the async-graphql page builder offers no way to add it. The tab is
a same-origin session on the node, so whoever controls those CDN responses
controls what it sends. That is why GraphiQL is off by default and refused on
any non-loopback bind; leave it off unless you are exploring a local node.

### API keys

`auth.apiKey` is the only credential in front of the writable GraphQL
mutations, so generate one — do not invent one by hand:

```bash
openssl rand -hex 32
```

Two boot rules back that up, and both apply whenever `auth.enabled` is true,
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
about the node is published anywhere. The cost is reachability: peers connect
on direct addresses only, and nothing in the config supplies those addresses,
so check that your peers can actually connect before relying on it.

### Mesh identity (`p2p.meshId`)

> **On an existing mesh: set `p2p.meshId` to your current `swarmTopic`
> verbatim — any other value invalidates every signature already in the mesh.**
> Copy it byte for byte, on every node. A signing node with `meshId` unset logs
> a boot warning that says exactly this, and `meshId` becomes **required** in a
> later release.

The swarm topic is a *reachability* string: anyone holding it
plus one member EndpointId can join the gossip overlay. Using it as the
signature domain too meant two meshes that happened to pick the same custom
topic accepted each other's signed directives. Setting `meshId` separates the
two; any identifier of ASCII letters, digits and `- _ . : /` up to 128 bytes is
accepted.

Because leaving `meshId` unset is the default and the topic then *is* the
domain, **`swarmTopic` is held to exactly the same form rules** — non-empty, no
leading or trailing whitespace, ASCII letters, digits and `- _ . : /`, at most
128 bytes — and a value that breaks them is refused at boot rather than
trimmed. The refusal names the field, the value's length and the byte offset of
the stray whitespace, never the value itself (it is the join credential). A
topic differing by one space between two nodes is not a cosmetic difference: it
is a different gossip overlay *and* a different signature domain, and it would
otherwise surface much later as `InvalidSignature`.

Leaving it unset keeps the pre-existing behaviour exactly: the domain is
`swarmTopic`. A signature is checked by reconstructing the signed message with
the verifier's own domain, so **changing the resolved domain invalidates every
signature already persisted and every signature peers hold** — which is why the
only safe `meshId` for an existing mesh is the string it already signs with.

**New mesh.** Generate a random UUID (`uuidgen`) and a unique `swarmTopic`, set
both on every node before the first directive is written, and there is nothing
else to think about.

**Existing mesh — the recommended step.** Set `meshId` to the current
`swarmTopic`, byte for byte, on each node. The resolved domain does not change,
so no signature is invalidated and no maintenance window is needed: nodes can
be switched one at a time. What it buys is that the two are now separate
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
(`p2p.meshId` or `p2p.swarmTopic (meshId unset)`) with its length and a
four-character prefix — never the value itself, because on the fallback path
the domain *is* the gossip join credential. All nodes must report
`source="p2p.meshId"` and the same length and prefix.

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

The node **tells you** when it is in this state: at boot, and after an
adoption, it logs *"ledger clock is far above the number of directives this
node holds"* naming the author whose directive carried the clock there (a
clock is bounded by the events it has folded; a clock of 5 × 10⁹ over a few
thousand directives is a jump). A `LAMPORT_ADVANCE` refusal that repeats tick
after tick on a fresh node is the same state seen from the other side.

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
   boot warning above fires on the joiner once, naming the jump's author; that
   is expected, and it is your confirmation that the copy carried the gap.

This is the join the test `h19_fresh_node_bootstrapped_from_a_peers_file_converges`
performs (`crates/p2p/tests/convergence.rs`): the copy boots with the peer's
whole history, the removed author's directive included, every node authors on
top, and the mesh converges — equal DAGs, heads and balances — with the joiner's
own directive accepted everywhere. The anti-entropy-only join of the same mesh
is the ignored case beside it, a documented limitation rather than a defect to
be fixed by a looser bound: any exemption from the ratchet for a "first
contact" is exactly the unbounded jump the ratchet exists to remove, on the
nodes least able to notice.

Two related rules that do **not** change: a transaction's parents are chosen
so that no author's heads can crowd out another's (at most `256 / authors` per
author, then smallest id — so a peer that grinds content ids cannot keep an
honest head unmerged), and a peer's transaction is never refused for the number
of heads its author holds on this node (that bound made DAG membership depend on
which subset a peer chose to serve first; frontier size is a cost every replica
pays alike, divergence is not).

### Using Auth

When `auth.enabled` is `true`, add the header to all requests. Keep the key in
the environment rather than pasting it into a shell history or a script:

```bash
export GL_NODE_API_KEY="$(openssl rand -hex 32)"   # and restart the node

curl -s -X POST http://127.0.0.1:4000/graphql \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $GL_NODE_API_KEY" \
  -d '{"query": "{ health { status } }"}'
```

The `/health` endpoint never *requires* authentication. On a non-loopback bind it discloses its version/heads/peers detail only to a request carrying a valid `X-Api-Key`. It is not unconditional, though: like `/graphql`, it answers `403` to a request whose `Host` is not in `allowedHosts`, and `429` past its own rate limit — see [Health Check](#health-check).

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
copy of the ledger (or from the node's `.journal`/backup), or delete the edited
block; then append a new transaction that reverses the mistake. A record you
**delete** from the file is not gone either: peers re-supply it on the next
anti-entropy round, because the mesh keeps what it accepted. Adoption is
one-way: the file is how records get *into* this node, never how they leave it.

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
if it names **another node** it is adopted unsigned with a warning (this node
cannot sign for it — drop the author line to adopt it as your own). A hand-typed
`openledger-parents` line must name records this ledger holds; one that names a
parent that exists nowhere is refused, because a signed record with a parent
nobody can resolve orphans everything written after it. A hand-typed `open` of
an account that is already open is refused exactly as the API refuses it. And a
node that **enables signing over a history it wrote unsigned** finds that
history quarantined at the first signing boot — it never replicated to a signing
mesh anyway; delete the `openledger-*` lines from those blocks to re-adopt them
as this node's own, signed, operator input.

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
  a peer, or it was edited), and one whose author names a different node is
  adopted unsigned with a warning (signing it here would produce a signature
  that verifies nowhere). A signature on a half envelope is discarded and a new
  one made, as described under the stop → edit → start path above.
- Entries that fail validation are dropped, each logged with its content id and
  the reason, before the canonical rewrite removes them from the file — and that
  rewrite runs even when *every* entry in the edit was refused, so a refused
  line does not linger on disk to be loaded raw at the next boot. (At boot the
  same refusal quarantines instead of dropping; see above.)
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
  the node already wrote. That includes a backup copied over the live file. Only
  lines you added since the node last rewrote the file may be dropped by that
  recovery.

### The commit journal (`<ledgerPath>.journal`)

Between full rewrites the node appends each write to a sidecar,
`<ledgerPath>.journal`, and folds it back into the `.bean` at startup, at
shutdown and on the next full rewrite. You normally never see it; these are the
cases where you might:

- **It must be the node's own file.** The journal, the `.lock` and the key file
  must be regular files (not a FIFO, directory or symlink), owned by the uid the
  node runs as, with a single hard link; the lock and key must be `0600`, and a
  journal writable by group or other is refused (one merely readable by others
  loads with a warning and is compacted away). A FIFO, directory or dangling
  symlink at the `.bean` or the journal refuses boot.
- **A `.bean` missing beside a journal refuses boot** rather than starting an
  empty ledger with the journal's writes on top.
- **A torn final record** — a crash mid-append — is dropped with a warning, and
  so is a journal whose recovery reload after a failed write could not read the
  files; the journal is kept as `<ledgerPath>.journal.torn-<unix-seconds>` instead of
  being deleted. No boot reads it; inspect it, then remove it.
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

`deploy/docker-compose.yml` brings up three nodes on one bridge network. Each
needs its own API key:

```bash
GL_NODE_0_API_KEY="$(openssl rand -hex 32)" \
GL_NODE_1_API_KEY="$(openssl rand -hex 32)" \
GL_NODE_2_API_KEY="$(openssl rand -hex 32)" \
  docker compose -f deploy/docker-compose.yml up --build
```

To keep the keys out of your shell history, copy `deploy/.env.example` to
`deploy/.env`, put the three values there, and run the plain `docker compose -f
deploy/docker-compose.yml up --build` — Compose reads a `.env` beside the
compose file automatically. `deploy/.env` is gitignored; `deploy/.env.example`
is the committed template and holds no secret.

One shared key would mean compromising any single node grants write access to
all of them, and rotating it is an all-or-nothing outage. The defaults for those
three variables are unusable placeholders shorter than the 16-byte minimum, so a
stack started without them fails to boot instead of coming up with a guessable
credential. Ports are published on `127.0.0.1` only, for the reason above; the
file's header comment covers the TLS terminator, `trustedProxies` and `meshId`
decisions for a real deployment.

---

## Running Tests

```bash
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
cargo clippy --all-targets
```

---

## Project Structure

```
openledger-v2/
├── Cargo.toml                # Workspace root
├── Dockerfile                # Multi-stage Docker build
├── gl-node.config.json       # Minimal local config (edit or replace)
├── SECURITY_AUDIT_0922.md    # Current security audit register
├── docs/                     # Task trackers, Format v2 design
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
