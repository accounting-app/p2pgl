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

This block is a **public-bind** example, so it carries everything a
non-loopback `bindAddress` requires: `auth.enabled`, `tls.mode: "terminated"`,
a populated `allowedHosts`, and `graphiql: false`. Each of those is refused at
boot if it is missing — the node will not start half-hardened.

```json
{
  "ledgerPath": "./data/company.bean",
  "bindAddress": "0.0.0.0",
  "port": 4000,
  "externalFileEdits": "disabled",
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
    "maxConnections": 1024
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

> `"apiKey": "change-me"` above is a **placeholder that this node refuses to
> boot with**, on purpose — see [API keys](#api-keys) before you copy the block.

| Field | Default | Description |
|-------|---------|-------------|
| `ledgerPath` | **(required)** | Path to the `.bean` file |
| `bindAddress` | `"127.0.0.1"` | HTTP listen address |
| `port` | `4000` | HTTP listen port |
| `externalFileEdits` | `"disabled"` | Accept hand-edits to the `.bean` file — see [Editing the `.bean` file](#editing-the-bean-file-by-hand) |
| `graphiql` | `false` | GraphiQL playground; refused outright on a non-loopback bind |
| `cors.allowedOrigins` | `[]` | Browser origin allowlist; `"*"` is rejected |
| `allowedHosts` | `[]` | Extra `Host` header values accepted, beyond loopback and the bind address. **Required (non-empty) on a non-loopback bind** — see below |
| `trustedProxies` | `[]` | Reverse-proxy IPs whose `X-Forwarded-For` the rate limiter believes — see below |
| `tls.mode` | `"disabled"` | `"disabled"` (loopback only) or `"terminated"` (TLS at a host/proxy). A non-loopback bind must be `"terminated"`; in-process TLS is not implemented |
| `auth.enabled` | `false` | Require `X-Api-Key` header on GraphQL. Forced on for a non-loopback bind |
| `auth.apiKey` | `""` | The API key value (required if auth enabled). Minimum 16 bytes; published placeholders are refused — see [API keys](#api-keys) |
| `http.headerReadTimeoutSeconds` | `30` | Time a client gets to send a complete request head; also bounds idle keep-alive. `1`–`300` |
| `http.requestTimeoutSeconds` | `30` | Whole-request ceiling, body read and GraphQL execution included (`408` on expiry). `1`–`300` |
| `http.maxConnections` | `1024` | Concurrently served connections; excess stays in the kernel backlog. `8`–`65536` |
| `signing.enabled` | `false` | Sign transactions with Ed25519. Forced on when `p2p.enabled` |
| `p2p.enabled` | `false` | Enable Iroh mesh replication |
| `p2p.bootstrapEndpointIds` | `[]` | Allowlisted peer EndpointIds; empty drops inbound `Supply` |
| `p2p.antiEntropyIntervalMilliseconds` | `5000` | ALPN head-exchange cadence; minimum `100` |
| `p2p.swarmTopic` | `openledger/transactions` | Gossip topic; required unique on a public bind |
| `p2p.meshId` | *(unset)* | Mesh identity bound into every signature. Use a random UUID. Unset falls back to `swarmTopic` — see below |

**`allowedHosts`.** The request guard checks the `Host` header on every
GraphQL request, which is what stops a DNS-rebinding page in a browser from
driving your node. Loopback names (`localhost`, `127.0.0.1`, `::1`) and a
non-wildcard `bindAddress` are always accepted; everything else has to be
listed. A wildcard bind such as `0.0.0.0` names no host a client could send,
so on a non-loopback bind an **empty `allowedHosts` is refused at boot** rather
than left to reject every request with a `403` at runtime. Entries are bare
hostnames or IP literals — no scheme, no port, no path.

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
restarting. (Do not rely on the file value being the one in use.) On Unix, a
config file that carries a non-empty `apiKey` and is readable by group or other
also draws a warning at boot; `chmod 600` it, or move the key to the
environment.

### Mesh identity (`p2p.meshId`)

The swarm topic is a *reachability* string: anyone holding it
plus one member EndpointId can join the gossip overlay. Using it as the
signature domain too meant two meshes that happened to pick the same custom
topic accepted each other's signed directives. Setting `meshId` separates the
two — a random UUID (`uuidgen`) is the recommendation, though any identifier of
ASCII letters, digits and `- _ . : /` up to 128 bytes is accepted.

Leaving it unset keeps the pre-existing behaviour exactly: the domain is
`swarmTopic`. That matters on an existing deployment, because a signature is
checked by reconstructing the signed message with the verifier's own domain —
so **changing the resolved domain invalidates every signature already persisted
and every signature peers hold**.

On a **new** mesh, set `meshId` on every node before the first directive is
written and there is nothing else to think about.

**Rolling one out on an existing mesh** is a coordinated, all-at-once change,
because the fallback rule means an existing mesh keeps verifying under
`swarmTopic` until you deliberately migrate it:

1. **Decide you want it.** An existing mesh is not broken by leaving `meshId`
   unset — it keeps using `swarmTopic` as its domain, exactly as it always has.
   Migrate only if you need identity separated from reachability (for example,
   two meshes that share a topic string, or a topic you intend to rotate).
2. **Generate one value** (`uuidgen`) and use that same string on every node.
   It is compared byte for byte, so leading or trailing whitespace is refused
   at boot rather than silently trimmed — a value that differs by one character
   between two nodes is a mesh-wide verification failure that presents as "the
   other node's key is wrong".
3. **Take a maintenance window and switch every node together.** During the
   window the mesh is partitioned by domain: a node on the new `meshId` cannot
   verify anything signed by a node still on the old domain, and vice versa.
   Anti-entropy will keep retrying, so a short split heals once every node is
   over, but a node left behind stays permanently unable to accept its peers'
   directives.
4. **Expect already-persisted signatures not to re-verify.** Directives written
   before the switch were signed under the old domain. They stay in the ledger
   and their content ids are unchanged — the content hash does not include the
   signature envelope — but a signature check against the new domain will not
   pass for them. Verify the mesh has converged *before* the switch, so nothing
   is still in flight that needs its signature checked afterwards.
5. **Confirm the boot log.** Each node logs the domain's `source`
   (`p2p.meshId` or `p2p.swarmTopic (meshId unset)`) with its length and a
   four-character prefix — never the value itself, because on the fallback path
   the domain *is* the gossip join credential. All nodes must report
   `source="p2p.meshId"` and the same length and prefix.

Rolling back is the same procedure in reverse, with the same window.

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

The `/health` endpoint never *requires* authentication — it always answers `200` so probes keep working. On a non-loopback bind it discloses its version/heads/peers detail only to a request carrying a valid `X-Api-Key`; see [Health Check](#health-check).

### Editing the `.bean` file by hand

**Editing a `.bean` file while the node that owns it is running is not
supported. Stop the node, edit the file, start it again.**

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

When an edit *is* adopted (which requires `"externalFileEdits": "enabled"`), it
is treated exactly as a local API write by the same operator, because that is
the authority it carries — same machine, same file, same trust boundary:

- Entries are canonicalized and re-ordered the way boot orders them, so where
  you pasted something in the file does not change the result.
- An entry with no signature is signed as this node's own before the first
  persist, so it replicates like any other local write. Two exceptions: an entry
  that already carries a signature is adopted untouched (it came from a peer),
  and one whose author names a different node is adopted unsigned with a warning
  (signing it here would produce a signature that verifies nowhere).
- Entries that fail validation are dropped, each logged with its content id and
  the reason, before the canonical rewrite removes them from the file.
- A file that no longer **parses** blocks writes until a human fixes it, rather
  than being canonicalized on top of a half-saved edit.

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

# Run with persistent data. The key comes from the environment, not the file.
docker run -d \
  -p 127.0.0.1:4000:4000 \
  -e GL_NODE_API_KEY="$(openssl rand -hex 32)" \
  -v $(pwd)/docker-config.json:/data/gl-node.config.json \
  -v $(pwd)/data:/data \
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
