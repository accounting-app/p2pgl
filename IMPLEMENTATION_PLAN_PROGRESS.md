# OpenLedger Build Progress

> **Spec:** [SPEC.md](SPEC.md) (940 lines, v1.0.0)
> **Stack:** Rust + Axum + async-graphql + Iroh
> **Method:** 12 passes, one-at-a-time, each compilable and tested

---

## Overall Status

| Pass | Milestone | Scope | Status | Tests |
|------|-----------|-------|--------|-------|
| **1** | M0 | Cargo workspace, config, Axum, `/health` | ✅ Done | 7 |
| **2** | M0 | GraphQL schema, scalars, auth middleware | ✅ Done | 27 |
| **3** | M1 | Beancount parser (10 directive types) | ✅ Done | 68 |
| **4** | M1 | Canonical serializer + `txid` hashing | ⏳ Next | — |
| **5** | M2 | DAG + validation (I1–I3, weights) | 🔲 | — |
| **6** | M2 | Ledger service + live mutations | 🔲 | — |
| **7** | M3 | Read model + all report queries | 🔲 | — |
| **8** | M4 | Iroh P2P + gossip + Lamport clocks | 🔲 | — |
| **9** | M4 | Anti-entropy + union merge | 🔲 | — |
| **10** | M5 | Verify + checkpoints + pad generation | 🔲 | — |
| **11** | M5 | Signing + subscriptions + file watcher | 🔲 | — |
| **12** | M6 | Deploy + integration testing | 🔲 | — |

**Current totals:** 68 tests passing · 4 crates compiling · clippy clean

---

## ✅ Pass 1 — Workspace + Config + Health (M0)

**Spec sections covered:** §2.9, §3.2, §3.3 (boot), §3.9 (shutdown), §3.11 (config)

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `Cargo.toml` | 28 | Workspace root, 4 members, shared deps |
| `rustfmt.toml` | 2 | Format config |
| `.gitignore` | 9 | Rust artifacts, .bean data, IDE |
| `crates/gl-node/Cargo.toml` | 34 | Binary crate deps |
| `crates/gl-node/src/main.rs` | 136 | Boot, Axum, graceful shutdown |
| `crates/gl-node/src/config.rs` | 241 | §3.11 config loader + validation |
| `crates/gl-node/src/health.rs` | 64 | `GET /health` (§2.9) |
| `crates/ledger/*` | — | Stub lib crate |
| `crates/p2p/*` | — | Stub lib crate |
| `crates/security/*` | — | Stub lib crate |

### Tests (7)

| Test | Verifies |
|------|----------|
| `test_minimal_config_loads` | Defaults applied (port 4000, bind 127.0.0.1, etc.) |
| `test_full_config_loads` | All §3.11 keys parse correctly |
| `test_unknown_key_rejected` | `deny_unknown_fields` → boot fail |
| `test_empty_ledger_path_rejected` | Validation: ledgerPath required |
| `test_auth_enabled_without_key_rejected` | Validation: auth.apiKey required when enabled |
| `test_invalid_external_file_edits_rejected` | Validation: enum must be "enabled"/"disabled" |
| `test_health_returns_ok` | REST /health JSON shape + status |

### Key Design Decisions
- Config: `serde(deny_unknown_fields)` rejects unknown JSON keys at boot
- Boot: creates empty `.bean` + parent dirs if `ledgerPath` is missing (§3.3)
- Shutdown: SIGTERM/SIGINT → graceful drain (§3.9)

---

## ✅ Pass 2 — GraphQL Schema + Auth (M0)

**Spec sections covered:** §2.6 (SDL), §2.8 (error shape), §3.8 (auth)

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `crates/gl-node/src/graphql/scalars.rs` | 140 | `Date`, `Decimal`, `TxId` custom scalars |
| `crates/gl-node/src/graphql/types.rs` | 109 | 12 output types (Amount, Transaction, TrialBalance, etc.) |
| `crates/gl-node/src/graphql/inputs.rs` | 41 | AmountInput, PostingInput, TransactionInput |
| `crates/gl-node/src/graphql/query.rs` | 93 | 9 query resolvers (stubbed) |
| `crates/gl-node/src/graphql/mutation.rs` | 36 | 3 mutation resolvers (return INTERNAL error) |
| `crates/gl-node/src/graphql/subscription.rs` | 17 | `transactionAppended` (pending stream) |
| `crates/gl-node/src/graphql/mod.rs` | 158 | Schema builder, handlers, 8 integration tests |
| `crates/gl-node/src/auth.rs` | 109 | `X-Api-Key` middleware + 4 tests |

### Tests (20 new, 27 total)

| Test | Verifies |
|------|----------|
| `test_date_scalar_round_trip` | Date parse ↔ serialize |
| `test_date_scalar_rejects_invalid` | `2024-13-01` → error |
| `test_decimal_scalar_round_trip` | Decimal as string wire format |
| `test_decimal_scalar_negative` | `-500.25` serializes correctly |
| `test_transaction_id_valid` | 64-char hex accepted |
| `test_transaction_id_rejects_short` | Short hex rejected |
| `test_transaction_id_rejects_non_hex` | Non-hex chars rejected |
| `test_transaction_id_normalizes_to_lowercase` | Uppercase → lowercase |
| `test_schema_introspection` | Schema builds and introspects |
| `test_health_query` | GraphQL `health` returns correct shape |
| `test_trial_balance_stub` | Returns empty rows, zero totals |
| `test_journal_stub_empty` | Returns `[]` |
| `test_append_transaction_returns_error` | Returns INTERNAL error code |
| `test_all_query_fields_present` | All 9 query fields in schema |
| `test_all_mutation_fields_present` | All 3 mutation fields in schema |
| `test_scalars_registered` | Date, Decimal, TxId are SCALAR kind |
| `test_auth_disabled_passes_through` | No auth check when disabled |
| `test_auth_enabled_valid_key` | Correct key → 200 |
| `test_auth_enabled_missing_key` | No header → 401 + UNAUTHORIZED |
| `test_auth_enabled_wrong_key` | Wrong key → 401 |

### Routing Table

| Route | Method | Auth | Handler |
|-------|--------|------|---------|
| `/health` | GET | **Exempt** | REST JSON (§2.9) |
| `/graphql` | GET | Protected | GraphiQL playground |
| `/graphql` | POST | Protected | GraphQL execution |

### M0 Milestone Checklist (from §4)

- [x] Cargo workspace (`gl-node`, `ledger`, `p2p`, `security`); lint/format; pin deps
- [x] async-graphql schema matching §2.6; mounted on Axum; resolvers stubbed
- [x] `Decimal`, `Date`, `TxId` scalars (Decimal as string)
- [x] Config loader for §3.11; auth middleware (`X-Api-Key`) present (disabled by default)
- [x] `GET /health` and GraphQL `health` both return same head/peer counts
- [x] **Done when:** schema introspects and stubs return typed placeholders; `/health` responds ✅

---

## ✅ Pass 3 — Beancount Parser (M1, part 1)

**Spec sections covered:** §2.3 (directive types), §3.3.2 (format)

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `crates/ledger/src/model.rs` | 258 | Domain types: 10 directive structs, Amount, CostSpec, PriceSpec, Posting, envelope helpers |
| `crates/ledger/src/error.rs` | 66 | ParseError with line/column, 11 ParseErrorKind variants |
| `crates/ledger/src/parse.rs` | 1760 | Hand-written recursive-descent parser + Scanner + 41 tests |
| `testfixtures/fixture-simple.bean` | 45 | Golden corpus: all 10 directive types with envelope metadata |

### Tests (41 new, 68 total)

| Test | Verifies |
|------|----------|
| `test_parse_empty_file` | Empty input → no directives |
| `test_parse_comment_only_file` | Comments skipped |
| `test_parse_open_simple` | Open without currencies |
| `test_parse_open_with_currencies` | Open with USD, EUR |
| `test_parse_open_with_metadata` | Open + metadata key/value |
| `test_parse_close` | Close directive |
| `test_parse_commodity` | Commodity directive |
| `test_parse_balance` | Balance with amount |
| `test_parse_negative_balance` | Negative decimal parsing |
| `test_parse_comma_separated_number` | 1,000,000.00 → 1000000.00 |
| `test_parse_pad` | Pad with two accounts |
| `test_parse_note` | Note with quoted comment |
| `test_parse_document` | Document with path |
| `test_parse_event` | Event with type + description |
| `test_parse_price` | Price with currency + amount |
| `test_parse_simple_transaction` | Full transaction with payee + narration |
| `test_parse_transaction_narration_only` | Single quoted string = narration |
| `test_parse_transaction_no_strings` | Flag-only transaction |
| `test_parse_transaction_with_tags_and_links` | #tag and ^link parsing |
| `test_parse_transaction_incomplete_flag` | `!` = Incomplete |
| `test_parse_transaction_txn_keyword` | `txn` keyword defaults to Complete |
| `test_parse_elided_posting` | Account-only posting (I2) |
| `test_parse_posting_with_cost` | `{150.00 USD}` cost spec |
| `test_parse_posting_with_cost_and_date` | `{150.00 USD, 2024-01-01}` |
| `test_parse_posting_with_unit_price` | `@ 1.10 USD` |
| `test_parse_posting_with_total_price` | `@@ 110.00 USD` |
| `test_parse_transaction_metadata` | openledger-* envelope keys |
| `test_parse_posting_metadata` | Posting-level metadata |
| `test_parse_multi_directive_file` | 6 directives in one file |
| `test_unsupported_directive_option` | CT-15: option → error |
| `test_unsupported_directive_include` | CT-15: include → error |
| `test_unsupported_directive_plugin` | CT-15: plugin → error |
| `test_unsupported_directive_custom` | CT-15: custom → error |
| `test_invalid_date` | 2024-13-01 → INVALID_DATE |
| `test_invalid_account_root` | Foo:Cash → error |
| `test_invalid_account_lowercase_segment` | Assets:cash → error |
| `test_invalid_metadata_non_string` | `key: 42` → error |
| `test_inline_comment_ignored` | `;` comment stripped |
| `test_directive_type_priority` | Canonical ordering values |
| `test_envelope_parent_ids_parsing` | Comma-split parent list |
| `test_golden_fixture_file` | Full fixture parse: 16 directives, envelope, cost spec |

### Design Decisions
- **Line-oriented scanner:** Character-level `Scanner` struct for each line, recursive-descent dispatch at directive level
- **Strict validation:** Account roots, currency regex, and metadata types enforced during parse (not deferred)
- **Metadata-only strings:** Non-quoted metadata values rejected per §3.3.2
- **Unsupported = hard-fail:** Includes `custom`, `option`, `include`, `plugin`, `pushtag`/`poptag`, `pushmeta`/`popmeta`, and unknown keywords

---

## ⏳ Pass 4 — Canonical Serializer + Hashing (M1, part 2) — NEXT

---

## 🔲 Passes 4–12 — Remaining

### Pass 4 — Canonical Serializer + Hashing (M1, part 2)
Economic + full-file serializers (§3.3.2), `txid`/`directiveId` hashing (I5), golden fixtures, CT-3/CT-5/CT-6/CT-13

### Pass 5 — DAG + Validation (M2, part 1)
Transaction DAG, topological order, balance validation (I1 + §3.5.1 weights), elided posting (I2), account lifecycle (I3/I9), CT-1/CT-2/CT-7

### Pass 6 — Ledger Service + Mutations (M2, part 2)
Wire parse→validate→serialize, `appendTransaction`/`openAccount`/`closeAccount` live, error codes (§2.8), external edit boot check (CT-11)

### Pass 7 — Read Model + Reports (M3)
Account tree, running balances, postings-by-account, by-date index; all 5 report queries; balance sheet closing (§3.7.1). FR-2 AC1–AC5.

### Pass 8 — Iroh P2P + Gossip (M4, part 1)
Iroh Endpoint + Router, SecretKey persistence, bootstrap/tickets, TopicId (§3.4.3), iroh-gossip announces, Lamport clocks (§3.4.2)

### Pass 9 — Anti-entropy + Union Merge (M4, part 2)
ALPN anti-entropy (§3.4.1), CBOR wire messages, G-Set union merge, remote I1–I3 enforcement, orphan buffer (§3.4.4), CT-4/CT-9/CT-12/CT-14

### Pass 10 — Verify + Checkpoints (M5, part 1)
`verify()` DAG walk (I8), balance/pad checkpoint evaluation (§3.6), deterministic pad generation, CT-8

### Pass 11 — Signing + Subscriptions + File Watcher (M5, part 2)
SignatureProvider trait (§3.8.1), `transactionAppended` subscription (WS + SSE), file watcher for external edits, CT-10

### Pass 12 — Deploy + Integration (M6)
Multi-stage Dockerfile, release binary, multi-node smoke test, peer addressability verification

---

## Workspace Structure (current)

```
openledger-v2/
├── SPEC.md                           ← 940-line spec
├── IMPLEMENTATION_PLAN_PROGRESS.md   ← this document
├── Cargo.toml                        ← workspace root
├── rustfmt.toml
├── .gitignore
├── testfixtures/
│   └── fixture-simple.bean           ← golden corpus (all 10 directive types)
└── crates/
    ├── gl-node/                      ← binary (Axum + GraphQL)
    │   └── src/
    │       ├── main.rs               ← boot, routing, shutdown
    │       ├── config.rs             ← §3.11 config loader
    │       ├── health.rs             ← GET /health
    │       ├── auth.rs               ← X-Api-Key middleware
    │       └── graphql/
    │           ├── mod.rs            ← schema builder + handlers
    │           ├── scalars.rs        ← Date, Decimal, TxId
    │           ├── types.rs          ← 12 output types
    │           ├── inputs.rs         ← 3 input types
    │           ├── query.rs          ← 9 query resolvers
    │           ├── mutation.rs       ← 3 mutation resolvers
    │           └── subscription.rs   ← transactionAppended
    ├── ledger/                       ← library (parse, model, error)
    │   └── src/
    │       ├── lib.rs                ← module declarations
    │       ├── model.rs              ← domain types (10 directives)
    │       ├── error.rs              ← structured parse errors
    │       └── parse.rs              ← recursive-descent parser
    ├── p2p/                          ← library (stub — Passes 8–9)
    │   └── src/lib.rs
    └── security/                     ← library (stub — Passes 10–11)
        └── src/lib.rs
```

## Conformance Test Tracker (§2.7)

| Obligation | Invariant | Target Pass | Status |
|------------|-----------|-------------|--------|
| CT-1 | I1 (balance) | Pass 5 | 🔲 |
| CT-2 | I2 (elided posting) | Pass 5 | 🔲 |
| CT-3 | I5 (txid stable) | Pass 4 | 🔲 |
| CT-4 | I6 (merge commutativity) | Pass 9 | 🔲 |
| CT-5 | I7 (round-trip) | Pass 4 | 🔲 |
| CT-6 | I7 (golden corpus) | Pass 4 | 🔲 |
| CT-7 | I3 (account lifecycle) | Pass 5 | 🔲 |
| CT-8 | I8 (verify detects tamper) | Pass 10 | 🔲 |
| CT-9 | FR-4 (partition converge) | Pass 9 | 🔲 |
| CT-10 | §3.8 (signing toggle) | Pass 11 | 🔲 |
| CT-11 | §3.3 (external edit disabled) | Pass 6 | 🔲 |
| CT-12 | §3.3 (external edit enabled) | Pass 9 | 🔲 |
| CT-13 | §3.3.1 (envelope idempotency) | Pass 4 | 🔲 |
| CT-14 | §3.5 (remote validation) | Pass 9 | 🔲 |
| CT-15 | §2.3 (unsupported directive) | Pass 3 | 🔲 |
