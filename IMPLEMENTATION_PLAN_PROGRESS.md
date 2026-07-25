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
| **4** | M1 | Canonical serializer + `txid` hashing | ✅ Done | 93 |
| **5** | M2 | DAG + validation (I1–I3, weights) | ✅ Done | 133 |
| **6** | M2 | Ledger service + live mutations | ✅ Done | 155 |
| **7** | M3 | Read model + all report queries | ✅ Done | 180 |
| **8** | M4 | Iroh P2P + gossip + Lamport clocks | ✅ Done | 200 |
| **9** | M4 | Anti-entropy + union merge | ⏳ Next | — |
| **10** | M5 | Verify + checkpoints + pad generation | 🔲 | — |
| **11** | M5 | Signing + subscriptions + file watcher | 🔲 | — |
| **12** | M6 | Deploy + integration testing | 🔲 | — |

**Current totals:** 200 tests passing · 4 crates compiling · clippy clean

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

## ✅ Pass 4 — Canonical Serializer + Hashing (M1, part 2)

**Spec sections covered:** §3.3.1 (economic hash vs envelope), §3.3.2 (canonical format), §3.3.3 (worked fixture)

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `crates/ledger/src/serialize.rs` | 520 | Economic + full-file serializers with column 52 alignment, tag/link/metadata sorting |
| `crates/ledger/src/hash.rs` | 155 | SHA-256 content ID computation (txid / directiveId) |

### Tests (25 new, 93 total)

| Test | Verifies |
|------|----------|
| `test_posting_column_52_alignment` | Number starts at column 52 |
| `test_posting_long_account_minimum_gap` | 2-space minimum for long accounts |
| `test_economic_serialize_worked_fixture` | Exact byte output matches §3.3.3 |
| `test_economic_serialize_excludes_envelope` | openledger-* stripped, regular metadata kept |
| `test_full_serialize_includes_envelope` | Envelope present in full-file mode |
| `test_tags_and_links_sorted` | Lexicographic sort before emit |
| `test_full_file_ordering` | date → type_priority → stable_sort_key |
| `test_serialize_open_with_currencies` | `USD, EUR` format |
| `test_serialize_balance` | balance amount on header line |
| `test_serialize_event` | Quoted type + description |
| `test_serialize_price_directive` | `CURRENCY NUMBER OTHERCURRENCY` |
| `test_serialize_posting_with_cost` | `{150.00 USD}` |
| `test_serialize_posting_with_price` | `@ 1.10 USD` |
| `test_serialize_elided_posting` | Account-only, no amount |
| `test_quote_string_escaping` | `\"` and `\\` escapes |
| `test_full_file_with_leading_comments` | Comments preserved at top |
| `test_round_trip_serialize_parse` | **CT-5**: serialize → parse → equal |
| `test_golden_fixture_round_trip` | **CT-6**: fixture parse → serialize → re-parse → equal |
| `test_metadata_sorted_alphabetically` | BTreeMap order = alphabetical |
| `test_ct13_envelope_idempotency` | **CT-13**: different envelope → same economic form |
| `test_ct3_worked_fixture_txid` | **CT-3**: txid = `dd4a9ec5...` |
| `test_ct3_envelope_does_not_change_txid` | Envelope metadata doesn't change hash |
| `test_content_id_is_64_char_hex` | Format: 64-char lowercase hex |
| `test_different_directives_different_ids` | Different bodies → different IDs |
| `test_content_id_stable_across_calls` | Deterministic across invocations |

### M1 Milestone Checklist (from §4)

- [x] Parser for the directive subset in §2.3, including openledger-* envelope metadata round-trip
- [x] Matching canonical serializer (§3.3.2)
- [x] `txid` / `directiveId` hash formulas (§3.3.1)
- [x] Golden-file fixture test for the §3.3.3 worked example (CT-3)
- [x] **Done when:** parse → serialize → re-parse round-trips perfectly; `txid` of worked example matches ✅

---

## ✅ Pass 5 — DAG + Validation (M2, part 1)

**Spec sections covered:** §2.4 (I1–I3, I8, I9), §3.3 (G-Set/DAG), §3.4 (consistency), §3.5.1 (posting weights)

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `crates/ledger/src/weights.rs` | 285 | Posting weight computation per §3.5.1 (plain, cost, unit/total price, elision resolution) |
| `crates/ledger/src/validate.rs` | 485 | Transaction validation (I1 balance, I2 elision, I3 lifecycle, I9 currency), AccountState tracker |
| `crates/ledger/src/dag.rs` | 310 | Merkle-DAG + G-Set: content-addressed insert, head tracking, cycle detection (I8), dedup |

### Tests (40 new, 133 total)

| Category | Tests | Verifies |
|----------|-------|----------|
| Weights | 13 | Plain, cost, unit price, total price weight computation; sign preservation; cost+price rejection; elision resolution; multi-currency sum |
| Validation | 15 | **CT-1** (I1 balance), **CT-2** (I2 elision), **CT-7** (I3 lifecycle), I9 currency constraint, same-day close, cost+price rejection |
| DAG | 12 | G-Set dedup, genesis insert, parent→child edges, head tracking, merge reduces heads, missing parent (strict/lenient), accessors |

### Key Design Decisions
- **Weight computation decoupled:** `weights.rs` is a pure function library used by both `validate.rs` and future report queries
- **AccountState is a separate tracker:** Can be built from directives on boot and updated incrementally
- **DAG has strict/lenient modes:** `require_parents=true` for runtime inserts; `false` for boot (file order may not match DAG order)
- **Cycle detection:** DFS walk of ancestors before insert (I8)
- **Elision resolution in validate:** Returns the resolved transaction with the elided posting filled in

---

## ✅ Pass 6 — Ledger Service + Live Mutations (M2, part 2)

**Spec sections covered:** §3.5 (write path), §3.3.1 (envelope stamping), §3.4.2 (Lamport clocks), FR-1 (append), FR-3 (open/close)

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `crates/ledger/src/service.rs` | 660 | `LedgerService`: boot from `.bean`, `append_transaction`, `open_account`, `close_account`, file persistence |

### Files Modified

| File | Change |
|------|--------|
| `crates/ledger/src/validate.rs` | Added `is_open()` accessor to `AccountState` |

### Tests (22 new, 155 total)

| Test | Verifies |
|------|----------|
| `test_boot_creates_empty_file` | Creates file + parent dirs if missing |
| `test_boot_from_existing_file` | Parses and builds AccountState on boot |
| `test_boot_from_golden_fixture` | Boots from fixture-simple.bean (16 directives) |
| `test_open_account` | FR-3 AC1: creates directive, updates state, persists |
| `test_open_already_open_rejected` | FR-3 AC1: ACCOUNT_ALREADY_OPEN |
| `test_close_account` | FR-3 AC2: closes account, updates state |
| `test_close_not_open_rejected` | ACCOUNT_NOT_OPEN error |
| `test_close_with_later_transactions_rejected` | FR-3 AC2: ACCOUNT_HAS_LATER_TRANSACTIONS |
| `test_append_balanced_transaction` | FR-1 AC1: returns txid, updates DAG |
| `test_append_unbalanced_rejected` | FR-1 AC2: UNBALANCED_TRANSACTION |
| `test_append_unopened_account_rejected` | FR-1 AC3: ACCOUNT_NOT_OPEN |
| `test_append_currency_mismatch_rejected` | I9: ACCOUNT_CURRENCY_MISMATCH |
| `test_append_with_elided_posting` | I2: elided posting resolved, txid returned |
| `test_append_idempotent_by_content` | FR-1 AC4: same body → same txid |
| `test_lamport_increments` | §3.4.2: monotonic increment per write |
| `test_genesis_has_empty_parents` | §3.3.1: first txn has empty parents |
| `test_second_txn_references_first_as_parent` | DAG edges: parent = previous head |
| `test_persist_and_reboot` | Full round-trip: write → reboot → same state |
| `test_file_round_trip_stable` | I7: re-serialize produces identical bytes |
| `test_extract_leading_comments` | Comment preservation on boot |
| `test_extract_no_comments` | No comments = empty vec |
| `test_full_genesis_flow` | End-to-end: open → genesis txn → verify file |

### M2 Milestone Checklist (from §4)

- [x] Invariant checks I1–I4 on the write path (validate.rs)
- [x] `LedgerService` that boots from `.bean`, validates + appends, re-serializes
- [x] `openAccount` / `closeAccount` with FR-3 lifecycle rules
- [x] Lamport clock stamping (§3.4.2)
- [x] Parent head tracking for DAG edges
- [x] File persistence (write-back after every mutation)
- [x] **Done when:** can open accounts, append balanced transactions, reject invalid ones, and reboot from the file with identical state ✅

---

## ✅ Pass 7 — Read Model + All Report Queries (M3)

**Spec sections covered:** §3.7 (read model), §3.7.1 (balance sheet closing), FR-2 (all report queries)

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `crates/ledger/src/read_model.rs` | 460 | In-memory read model: account balances, transaction index, postings-by-account; report methods |

### Files Modified

| File | Change |
|------|--------|
| `crates/ledger/src/service.rs` | Added `ReadModel` field, built on boot, updated incrementally on append |

### Tests (25 new, 180 total)

| Test | Verifies |
|------|----------|
| `test_build_empty` | Empty model from no directives |
| `test_build_indexes_transactions` | Transaction count |
| `test_build_running_balances` | Running balance accumulation |
| `test_build_skips_non_transactions` | Only transactions indexed |
| `test_trial_balance_totals_equal` | FR-2 AC1: total debits == total credits |
| `test_trial_balance_at_date` | Date-filtered trial balance |
| `test_trial_balance_rows_sorted` | Alphabetical row ordering |
| `test_balance_sheet_closing_rule` | §3.7.1: Net-Income closing, accounting equation |
| `test_balance_sheet_at_date` | Date-filtered balance sheet |
| `test_income_statement` | FR-2 AC3: income, expenses, net |
| `test_income_statement_date_range` | Period-filtered income statement |
| `test_journal_all` | FR-2 AC4: all transactions |
| `test_journal_by_account` | Account-filtered journal |
| `test_journal_date_range` | Date-filtered journal |
| `test_journal_pagination` | Limit/offset pagination |
| `test_transaction_lookup` | Lookup by txid |
| `test_transaction_not_found` | Missing txid returns None |
| `test_account_balance_current` | Current running balance |
| `test_account_balance_at_date` | Point-in-time balance |
| `test_account_balance_unknown` | Unknown account returns None |
| `test_multi_currency_balances` | Multi-currency support |
| `test_incremental_update` | Incremental indexing |
| `test_incremental_dedup` | Duplicate rejection |
| `test_account_root` | Account root extraction |
| `test_golden_fixture_read_model` | Golden fixture: 3 txns, cash balance, journal |

### M3 Milestone Checklist (from §4)

- [x] `trialBalance(at)` — per-account debit/credit; totals balanced
- [x] `balanceSheet(at)` — Assets, Liabilities, Equity with §3.7.1 Net-Income closing
- [x] `incomeStatement(from, to)` — Income, Expenses, net per currency
- [x] `journal(account?, from?, to?)` — filtered, paginated
- [x] `transaction(txid)` — single lookup
- [x] `account(name, at?)` — per-currency balances
- [x] Read model built on boot, updated incrementally (FR-2 AC5)
- [x] **Done when:** all 6 report queries return correct results from the in-memory model ✅

---

## ✅ Pass 8 — Iroh P2P + Gossip + Lamport Clocks (M4, part 1)

**Spec sections covered:** §3.4.1 (wire protocol), §3.4.2 (Lamport clocks), §3.4.3 (TopicId derivation), §3.4 (gossip)

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `crates/p2p/src/protocol.rs` | 240 | Wire protocol types: `WireMessage` (Announce/HaveHeads/Want/Supply), CBOR serialization, length-prefixed framing, version check |
| `crates/p2p/src/topic.rs` | 50 | `TopicId` derivation from swarm topic string via SHA-256 (§3.4.3) |
| `crates/p2p/src/gossip.rs` | 165 | Gossip handler: announce/supply creation, broadcast encode/decode, envelope extraction |
| `crates/p2p/src/node.rs` | 180 | `PeerNode` (Iroh endpoint + gossip handles), `PeerRegistry` (thread-safe peer tracking) |

### Dependencies Added

| Crate | Version | Purpose |
|-------|---------|---------|
| `iroh` | 1 | QUIC endpoint + peer identity |
| `iroh-gossip` | 0.101 | Gossip broadcast trees |
| `serde_cbor` | 0.11 | CBOR wire encoding (§3.4.1) |
| `bytes` | 1 | Zero-copy byte buffers |
| `anyhow` | 1 | Error handling |

### Tests (20 new, 200 total)

| Category | Tests | Verifies |
|----------|-------|----------|
| Protocol | 10 | CBOR roundtrip (all 4 message types), wire framing, version rejection, insufficient data, oversized message, directive kind mapping |
| Topic | 3 | TopicId stability, different topics differ, 32-byte output |
| Gossip | 4 | Announce creation, supply entry with envelope extraction, broadcast roundtrip, content ID verification |
| Node | 3 | PeerRegistry CRUD, remote heads aggregation, default config |

### Key Design Decisions
- **Wire protocol is CBOR** per §3.4.1; length-prefixed framing (`uint32_be || cbor_body`)
- **PeerRegistry is thread-safe** via `Arc<RwLock<HashMap>>` for concurrent reads from GraphQL queries
- **TopicId derived deterministically** from `p2p.swarmTopic` config string
- **Envelope extraction filters** to only `openledger-*` keys (non-openledger metadata stays local)
- **PeerNode wraps** Iroh `Endpoint` + `Gossip` handles; actual event loop deferred to gl-node integration

---

## ⏳ Pass 9 — Anti-Entropy + Union Merge (M4, part 2) — NEXT

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
    ├── ledger/                       ← library (parse, serialize, hash, DAG, validate, service, read model)
    │   └── src/
    │       ├── lib.rs                ← module declarations
    │       ├── model.rs              ← domain types (10 directives)
    │       ├── error.rs              ← structured parse errors
    │       ├── parse.rs              ← recursive-descent parser
    │       ├── serialize.rs          ← canonical serializer
    │       ├── hash.rs               ← SHA-256 content IDs
    │       ├── weights.rs            ← posting weight computation
    │       ├── validate.rs           ← invariant validation + AccountState
    │       ├── dag.rs                ← Merkle-DAG + G-Set
    │       ├── service.rs            ← LedgerService (boot, mutate, persist)
    │       └── read_model.rs         ← in-memory read model + report queries
    ├── p2p/                          ← library (wire protocol, gossip, topic, peer management)
    │   └── src/
    │       ├── lib.rs                ← module declarations
    │       ├── protocol.rs           ← §3.4.1 wire types (CBOR)
    │       ├── topic.rs              ← §3.4.3 TopicId derivation
    │       ├── gossip.rs             ← broadcast/receive handler
    │       └── node.rs               ← PeerNode + PeerRegistry
    └── security/                     ← library (stub — Passes 10–11)
        └── src/lib.rs
```

## Conformance Test Tracker (§2.7)

| Obligation | Invariant | Target Pass | Status |
|------------|-----------|-------------|--------|
| CT-1 | I1 (balance) | Pass 5 | ✅ |
| CT-2 | I2 (elided posting) | Pass 5 | ✅ |
| CT-3 | I5 (txid stable) | Pass 4 | ✅ |
| CT-4 | I6 (merge commutativity) | Pass 9 | 🔲 |
| CT-5 | I7 (round-trip) | Pass 4 | ✅ |
| CT-6 | I7 (golden corpus) | Pass 4 | ✅ |
| CT-7 | I3 (account lifecycle) | Pass 5 | ✅ |
| CT-8 | I8 (verify detects tamper) | Pass 10 | 🔲 |
| CT-9 | FR-4 (partition converge) | Pass 9 | 🔲 |
| CT-10 | §3.8 (signing toggle) | Pass 11 | 🔲 |
| CT-11 | §3.3 (external edit disabled) | Pass 6 | 🔲 |
| CT-12 | §3.3 (external edit enabled) | Pass 9 | 🔲 |
| CT-13 | §3.3.1 (envelope idempotency) | Pass 4 | ✅ |
| CT-14 | §3.5 (remote validation) | Pass 9 | 🔲 |
| CT-15 | §2.3 (unsupported directive) | Pass 3 | ✅ |
