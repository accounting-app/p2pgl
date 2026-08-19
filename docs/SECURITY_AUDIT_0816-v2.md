# Security Audit — OpenLedger v2 (pass 2)

**Date:** 2026-08-16  
**Report:** `SECURITY_AUDIT_0816-v2.md`  
**Scope:** Full source review of workspace crates `gl-node`, `ledger`, `p2p`, `security`, plus `deploy/`, `config/`, `Dockerfile`, and `docs/SPEC.md` as the security contract  
**Methodology:** Manual review of every Rust module, config, and deploy artifact; SPEC §3.8 / §3.4 / §3.12 cross-check; lockfile dependency notes. No dynamic exploitation, no `cargo-audit` run in CI (none exists).  
**Prior reports:** [SECURITY_AUDIT_0808.md](./SECURITY_AUDIT_0808.md) · [SECURITY_AUDIT_0816.md](./SECURITY_AUDIT_0816.md)

---

## What’s new in this pass

The 2026-08-08 and earlier 2026-08-16 audits remain valid: **none of those 15 original findings have been remediated in source**. This v2 pass:

1. **Reconfirmed** every prior finding against current line numbers.
2. **Corrected** one factual error in `SECURITY_AUDIT_0816.md`: external file edits are **enabled by default**, not off.
3. **Added** findings the first 0816 pass did not cover: unauthenticated P2P write path on a well-known swarm topic, Beancount serialization injection from GraphQL, public-relay confidentiality, non-atomic ledger persistence, GraphQL-vs-parser validation gap, and related issues.
4. **Mapped** live code against SPEC security rules that the implementation claims to satisfy but does not.

---

## Executive Summary

OpenLedger v2 is a P2P-replicated double-entry ledger with a GraphQL API. Cryptographic *building blocks* are sound (SHA-256 content addressing, Ed25519 via `ed25519-dalek` v2, domain-separated sign messages, I1–I3/I9 on the local write path, no `unsafe` in workspace crates). Operational and protocol *enforcement* is not.

The node can be run as an unauthenticated, CORS-open GraphQL server that also **accepts full ledger `Supply` messages over gossip** from any Iroh neighbor on a **public default topic**, while signatures are off by default and **never verified on receive even when enabled**. That combination is not safe for any network-exposed or multi-tenant-adjacent deployment.

| Severity | Count | Change vs 0816 |
|----------|------:|----------------|
| Critical | 4 | +1 (`C-4` swarm write path) |
| High | 10 | +3 (injection, relay confidentiality, non-atomic persist) |
| Medium | 13 | +5 |
| Low | 10 | +5 |
| Informational | 5 | +3 |

**Production Go/No-Go (SPEC §3.8):** **No-Go.** Auth, signing verification, peer admission, CORS, GraphiQL, and secret-key permissions all fail the spec’s own production checklist.

---

## Status of prior findings

| ID | Finding | 0808 | 0816 | This pass |
|----|---------|------|------|-----------|
| C-1 | Non-constant-time API key compare | Open | Open | **Open** |
| C-2 | Secret key file world-readable | Open | Open | **Open** |
| C-3 / was M-4 | No signature verify on remote Supply | Medium | Elevated to Critical | **Open** (still Critical) |
| H-1 | Permissive CORS | Open | Open | **Open** |
| H-2 | No rate limiting | Open | Open | **Open** |
| H-3 | GraphiQL always on | Open | Open | **Open** |
| H-4 | Signing silent noop fallback | Open | Open | **Open** |
| H-5 / was I-1 | Docker `0.0.0.0` + auth off | Info | Elevated to High | **Open** |
| H-6 | Lenient remote parents / dead orphan path | — | New | **Open** |
| H-7 | Gossip bypasses wire size/version | — | New | **Open** |
| M-1 | `PeerRegistry` `RwLock` `.unwrap()` | Open | Open | **Open** |
| M-2 | `ledgerPath` traversal | Open | Open | **Open** |
| M-3 | Orphan buffer no per-peer limit | Open | Open | **Open** |
| M-5 | Unmaintained `serde_cbor` | Open | Open | **Open** |
| L-1 | Health info disclosure | Open | Open | **Open** |
| L-2 | Docker HEALTHCHECK / missing `curl` | Open | Open | **Open** |
| L-3 | Negative `limit`/`offset` cast | Open | Folded into H-2 | **Open** |

---

## Threat model (this codebase)

| Actor | Access | Realistic goals |
|-------|--------|-----------------|
| Browser / website | Victim has `gl-node` reachable (localhost or published Docker port) | CSRF-style `appendTransaction` via permissive CORS + auth off |
| Local user / container sibling | Filesystem read/write | Steal `identity.secret`; rewrite `.bean`; impersonate node via file-watcher adoption |
| Swarm peer | Iroh gossip neighbor on same `TopicId` | Inject balanced transactions, open accounts, forge `openledger-author` |
| Network observer | Path to n0 relay or LAN | Read gossiped economic bodies (no application-layer encryption beyond QUIC to relay) |
| Operator misconfig | `signing.enabled=true` with bad key path | Believe the ledger is signed; it is not |

Trust boundary that the code does **not** enforce: “only my org’s nodes may write my ledger.” SPEC §3.9 requires bootstrap `EndpointId`s / tickets; `bootstrapEndpointIds` is parsed and **never used** to admit peers (`docs/OUTSTANDING_TASKS.md` R2). Gossip `subscribe` is called with an empty peer list.

---

## Attack surface inventory

| Surface | Auth | Notes |
|---------|------|-------|
| `POST /graphql` | Optional `X-Api-Key` (off by default) | Mutations: `appendTransaction`, `openAccount`, `closeAccount` |
| `GET /graphql` | Same middleware | Always serves GraphiQL |
| `GET /health` | **None** (SPEC §2.9) | Heads, peer count, version |
| GraphQL `health` / `peers` / `verify` / reports | Same as GraphQL | Full financial reports when auth off |
| `/graphql/ws` | Advertised, **not routed** | Dead endpoint today |
| Iroh QUIC + `iroh-gossip` | Iroh identity only; **no org allowlist** | Incoming `Supply` merged into `.bean` |
| `.bean` file | OS permissions | Watcher adopts unsigned edits by default |
| `p2p.secretKeyPath` | OS permissions | Hex-encoded Ed25519 seed; default mode `0644` |

---

## Critical findings

### C-1: API key compared with non-constant-time equality

**File:** [crates/gl-node/src/auth.rs](crates/gl-node/src/auth.rs) line 40  
**Prior:** 0808 C-1, 0816 C-1 — unfixed

```rust
Some(key) if key == auth_state.api_key => next.run(request).await,
```

Rust `==` on `&str` short-circuits on the first mismatched byte. OPTIONS is also exempt (correct for CORS preflight, dangerous with H-1).

**Impact:** With `auth.enabled`, a low-latency attacker can recover `auth.apiKey` byte-by-byte. That key is the only GraphQL credential.

**Recommendation:** Compare with `subtle::ConstantTimeEq` on equal-length byte slices; treat length mismatch as failure without leaking which. `subtle` is already in the tree via `ed25519-dalek`.

---

### C-2: Iroh secret key written with default (world-readable) permissions

**File:** [crates/gl-node/src/p2p_service.rs](crates/gl-node/src/p2p_service.rs) lines 314–340  
**Prior:** 0808 C-2, 0816 C-2 — unfixed

```rust
std::fs::write(path, hex::encode(key.to_bytes()))?;
```

No `0o600` on create; no permission check on load. The same file is the signing seed when `signing.enabled` is true (`main.rs` 183–195).

**Impact:** Any local user who can read the file can impersonate the node on the mesh **and** forge signatures.

**Recommendation:** `OpenOptions` create with `0o600`; refuse to load if group/other bits are set; consider locking the file.

---

### C-3: Remote / gossiped directives never have signatures verified

**Files:**  
- [crates/p2p/src/union_merge.rs](crates/p2p/src/union_merge.rs) `validate_supply_entry` (lines 73–113)  
- [crates/gl-node/src/p2p_service.rs](crates/gl-node/src/p2p_service.rs) gossip `Supply` handler (lines 140–175)  
- [crates/ledger/src/service.rs](crates/ledger/src/service.rs) `insert_remote_directive` (lines 738–823)

**Prior:** 0808 M-4, 0816 C-3 — unfixed  
**SPEC:** §3.5 step 4 and §3.8.1 — *“If signing is enabled, verify `openledger-signature` … Failure → reject remote insert.”* Tracked as outstanding **R4**.

`validate_supply_entry` checks content hash (I5) and presence of `openledger-author` / `openledger-lamport`. It never calls `security::signing::verify_signature`. Envelope values are opaque strings. `NoopSignatureProvider::verify` returns `Ok(())` for any input.

**Impact:** Authorship on a financial ledger is self-asserted. Enabling signing does not produce non-repudiation on the receive path. Combined with C-4, any neighbor can write under any author string.

**Recommendation:** When `signing.enabled`, require a signature, verify against the author’s public key (bound to Iroh `EndpointId`), and reject missing/invalid signatures. Do not use the noop provider on the receive path.

---

### C-4: Unauthenticated P2P ledger writes on a well-known public swarm topic

**Files:**  
- [crates/p2p/src/topic.rs](crates/p2p/src/topic.rs) — default `"openledger/transactions"`  
- [crates/gl-node/src/p2p_service.rs](crates/gl-node/src/p2p_service.rs) lines 42–46 (`presets::N0`), 94 (`subscribe(topic_id, vec![])`), 140–175 (apply `Supply`)  
- [deploy/gl-node.docker.json](deploy/gl-node.docker.json) — P2P on, empty bootstrap, default topic  
- [docs/OUTSTANDING_TASKS.md](docs/OUTSTANDING_TASKS.md) R2 — bootstrap IDs never joined

**SPEC:** §3.9 — discovery is **static bootstrap + tickets**; “Local-network convenience discovery may be used in **development only**.”

This is the highest-impact *new* finding in v2.

1. `TopicId` is `SHA-256("openledger/transactions")` — enumerable by anyone who reads the spec or the default config.
2. The endpoint is built with **Iroh N0** (public relay + holepunch + n0 discovery), not a bootstrap-only private mesh.
3. `bootstrapEndpointIds` is stored on `PeerNodeConfig` and **never used** to restrict neighbors.
4. Gossip accepts `WireMessage::Supply` (full economic bodies), not merely `Announce` hints, and immediately `insert_remote_directive`.
5. Signing is off by default and unverified when on (C-3).
6. Remote transactions still only need to balance (I1) against accounts the attacker can also `Open` over the same path.

**Impact:** A node with `p2p.enabled` (including the shipped Docker compose stack) will merge attacker-authored journal entries, account opens, notes, and other directives into the canonical `.bean` if the attacker can become a gossip neighbor. On a shared LAN, shared Docker bridge, or any environment where N0/mDNS discovery introduces strangers, that is a **cross-deployment ledger injection** risk. Economic hash integrity does not stop insertion of *new* valid-looking entries.

**Recommendation:**

- Require a unique, high-entropy `swarmTopic` per organization; refuse to boot on the default string in production.
- Admit only configured bootstrap `EndpointId`s (allowlist); drop `Supply` from unknown senders.
- Treat gossip as announce-only until the sender is allowlisted; fetch bodies over authenticated ALPN.
- Do not use public N0 discovery for production meshes (SPEC already says this).

---

## High findings

### H-1: CORS is fully permissive

**File:** [crates/gl-node/src/main.rs](crates/gl-node/src/main.rs) line 247  
**Prior:** unfixed

```rust
.layer(CorsLayer::permissive())
```

`Access-Control-Allow-Origin: *`, all methods, all headers. Combined with auth off (default) and C-1 if auth is on but the key is stolen.

**Impact:** Any website can mutate a reachable node (classic localhost CSRF against a developer or a published Docker port).

**Recommendation:** Configurable origin allowlist; default deny or localhost-only.

---

### H-2: No rate limiting; journal `limit`/`offset` wrap to `usize::MAX`

**Files:** HTTP stack (no limiter); [crates/gl-node/src/graphql/query.rs](crates/gl-node/src/graphql/query.rs) lines 145–156; [crates/ledger/src/read_model.rs](crates/ledger/src/read_model.rs) `journal` (lines 335–374)

**Prior:** 0808 H-2 + L-3

```rust
limit as usize,
offset as usize,
```

`limit: -1` becomes `usize::MAX`. `journal` **materializes every matching row** into a `Vec` before `skip`/`take`, so even a “sane” limit still scans/allocates the full filter set.

Mutations persist the entire ledger file and may gossip; there is no per-IP or per-key throttle.

**Impact:** Memory/CPU/disk DoS; unbounded GraphQL responses.

**Recommendation:** Clamp `limit` to `[1, 10_000]`, `offset` to `≥ 0`; paginate without collecting the full set; add `governor` / `tower` rate limits on `/graphql`.

---

### H-3: GraphiQL playground always exposed

**Files:** [crates/gl-node/src/main.rs](crates/gl-node/src/main.rs) line 228; [crates/gl-node/src/graphql/mod.rs](crates/gl-node/src/graphql/mod.rs) lines 68–75

`GET /graphql` always returns GraphiQL, including a subscription URL `/graphql/ws` that is not implemented. Introspection is on (async-graphql default).

**Impact:** Interactive schema + mutation console for anyone who can hit the port (or who passes the API key).

**Recommendation:** Config flag, default **off**; disable introspection when GraphiQL is off.

---

### H-4: Signing enabled but key failure silently degrades to noop

**File:** [crates/gl-node/src/main.rs](crates/gl-node/src/main.rs) lines 183–215  
**SPEC:** §3.11 — fail closed on required secrets.

Missing, unreadable, or wrong-length key → `warn!` + `NoopSignatureProvider`. That provider’s `verify` accepts anything.

**Impact:** Operators think signing is on. Local writes are unsigned; any future verify call on this provider is a no-op.

**Recommendation:** Exit non-zero if `signing.enabled` and the key cannot be loaded. Never attach noop when the config promised signing.

---

### H-5: Shipped Docker config binds `0.0.0.0` with auth and signing disabled

**File:** [deploy/gl-node.docker.json](deploy/gl-node.docker.json)  
**Compose:** [deploy/docker-compose.yml](deploy/docker-compose.yml) publishes `3000–3002`

```json
"bindAddress": "0.0.0.0",
"auth": { "enabled": false },
"signing": { "enabled": false },
"p2p": { "enabled": true, "swarmTopic": "openledger/transactions", "bootstrapEndpointIds": [] }
```

Code default bind is `127.0.0.1` (good). The **deployable** config undoes it and turns on P2P with C-4 defaults.

**Impact:** `docker compose up` is an unauthenticated, world-listenable GraphQL ledger with gossip merge enabled.

**Recommendation:** Production sample: auth on, unique topic, bootstrap IDs, loopback or private bind, GraphiQL off. Boot-time warning when bind is non-loopback and `auth.enabled` is false.

---

### H-6: Remote DAG inserts ignore missing parents; orphan buffer is unused

**Files:** [crates/ledger/src/service.rs](crates/ledger/src/service.rs) line 779 (`dag.insert(..., false)`); [crates/p2p/src/orphan_buffer.rs](crates/p2p/src/orphan_buffer.rs); gossip handler never calls `OrphanBuffer::insert`

**SPEC:** §3.4.4 orphan buffer; I8 parent links.

`require_parents=false` admits transactions whose parents are not in the G-Set. `verify` then reports missing parents. `drain_orphans` only runs if something was buffered — nothing is.

**Impact:** Divergent, unverifiable DAGs; specified anti-entropy/`want` path is dead. An attacker can inject genesis-shaped transactions into a non-empty ledger (empty `openledger-parents`).

**Recommendation:** Remote insert with `require_parents=true`; on `MissingParent`, buffer with per-peer quotas; emit `want`.

---

### H-7: Gossip decode skips wire version and 16 MiB cap

**Files:** [crates/p2p/src/gossip.rs](crates/p2p/src/gossip.rs) lines 45–48; [crates/p2p/src/protocol.rs](crates/p2p/src/protocol.rs) `from_wire` vs `from_cbor`

```rust
pub fn decode_broadcast(data: &[u8]) -> Result<WireMessage, String> {
    WireMessage::from_cbor(data).map_err(|e| format!("CBOR decode error: {e}"))
}
```

`from_wire` enforces `MAX_MESSAGE_SIZE` and `v == 1`. Gossip does not. Combined with unmaintained `serde_cbor` (M-5).

**Impact:** Oversized or future-version CBOR is parsed with no application cap; decoder DoS and protocol confusion.

**Recommendation:** Decode gossip with the same gates as `from_wire` (or shared `decode_checked`).

---

### H-8: Beancount injection via GraphQL fields that skip parser validation

**Files:**  
- [crates/gl-node/src/graphql/mutation.rs](crates/gl-node/src/graphql/mutation.rs) `open_account` / `append_transaction`  
- [crates/ledger/src/service.rs](crates/ledger/src/service.rs) `open_account` / `append_transaction` — no `validate_account_name` / `validate_currency`  
- [crates/ledger/src/parse.rs](crates/ledger/src/parse.rs) lines 267–338 — validation exists **only** on parse  
- [crates/ledger/src/serialize.rs](crates/ledger/src/serialize.rs) — account, currency, tags, links are **unquoted**; `quote_string` only escapes `"` and `\`

Parser enforces `Root:Segment` and currency charset. GraphQL accepts arbitrary strings. Serializer then emits:

```text
{date} open {account}
  {account}                 {number} {currency}
#{tag}  ^{link}
```

A newline (or additional directive text) inside `account`, `currency`, `tag`, or `link` becomes extra `.bean` lines. After persist + reboot/reconcile, those lines parse as **new directives** that were never validated as a single GraphQL write.

Example shape (account name):

```text
2024-01-01 open Assets:Cash
2024-01-02 open Liabilities:Injected USD
```

**Impact:** Authenticated (or unauthenticated, if auth is off) clients can smuggle extra opens/transactions into the file, break canonical round-trip, and desynchronize in-memory DAG vs on-disk parse. Remote peers that re-parse the file inherit the injected directives.

**Recommendation:** Run the same `validate_account_name` / `validate_currency` / tag / link regexes on all write paths. Reject control characters. Quote or escape every free-form field. Add tests that `openAccount` / `appendTransaction` reject `\n` in names.

---

### H-9: Ledger bodies traverse the public Iroh relay network

**File:** [crates/gl-node/src/p2p_service.rs](crates/gl-node/src/p2p_service.rs) lines 42–46, 109–116, 140–175

`presets::N0` enables n0 relays. Gossip `Supply.economic_bean` is the plaintext journal body. There is no extra application encryption or topic secrecy.

**Impact:** Financial transactions (payees, narrations, amounts, accounts) may be visible to the relay operator and to anyone who joins the topic (C-4). This is a **confidentiality** failure for a general ledger, even if hashes later detect tampering.

**Recommendation:** Private relays or direct-only meshes for production; unique topics; treat gossip as metadata-only; encrypt application payloads if relays are required.

---

### H-10: Ledger persist is a non-atomic truncate-write

**File:** [crates/ledger/src/service.rs](crates/ledger/src/service.rs) lines 496–500

```rust
fn persist(&self) -> Result<(), ServiceError> {
    let content = full_file_serialize(&directives, &self.leading_comments);
    std::fs::write(&self.file_path, content)?;
    Ok(())
}
```

`std::fs::write` truncates, then writes. A crash or kill mid-write leaves a truncated `.bean`. Every local mutation, remote merge, signature stamp, and reconcile rewrites the **entire** file (disk amplification / DoS).

**Impact:** Source of truth (C1) can be destroyed; node may fail to boot (`parse` error) after a crash. Remote flood of inserts maximizes this window.

**Recommendation:** Write to `ledger.bean.tmp` + `fsync` + atomic rename; fsync directory. Consider append-only log + periodic canonical rewrite.

---

## Medium findings

### M-1: `PeerRegistry` panics on poisoned `std::sync::RwLock`

**File:** [crates/p2p/src/node.rs](crates/p2p/src/node.rs) lines 41–65  

Every `upsert` / `remove` / `list` / `count` / `all_remote_heads` uses `.unwrap()`. Health and GraphQL `peers` hit this.

**Impact:** One panic while holding the lock takes down subsequent requests (including `/health`).

**Recommendation:** `unwrap_or_else(|e| e.into_inner())` or `tokio::sync::RwLock`.

---

### M-2: `ledgerPath` is not jailed

**File:** [crates/gl-node/src/config.rs](crates/gl-node/src/config.rs) lines 181–185; [crates/gl-node/src/main.rs](crates/gl-node/src/main.rs) lines 50–65

Only non-empty is required. `create_dir_all` + `write` follow `..` and absolute paths.

**Impact:** Malicious config writes a ledger anywhere the process can write.

**Recommendation:** Resolve against a data root; reject `..` after canonicalize.

---

### M-3: Orphan buffer has no per-peer quota

**File:** [crates/p2p/src/orphan_buffer.rs](crates/p2p/src/orphan_buffer.rs) — global `MAX_ORPHANS = 10_000`

Once H-6 is fixed, one peer can fill the buffer with never-arriving parents.

**Recommendation:** Per-peer cap + LRU under the global cap (TTL already exists).

---

### M-4: §3.12 resource limits apply only to local `append_transaction`

**File:** [crates/ledger/src/service.rs](crates/ledger/src/service.rs) lines 267–316 vs 738+

Remote `insert_remote_directive` and file reconcile do not enforce posting/narration/tag/metadata caps. `economic_bean` size is unbounded at merge.

**Impact:** Peers (or a crafted `.bean`) can insert oversized directives GraphQL clients cannot submit.

**Recommendation:** One limiter for local, remote, and reconcile; cap CBOR/`economic_bean` length in `validate_supply_entry`.

---

### M-5: `serde_cbor` is unmaintained

**File:** [Cargo.toml](Cargo.toml) line 31 — `serde_cbor = "0.11"` (lockfile 0.11.2)

RUSTSEC-2021-0127; SPEC text already points at `ciborium`.

**Impact:** CBOR parser bugs will not be patched upstream.

**Recommendation:** Migrate to `ciborium`.

---

### M-6: P2P boot failure continues without replication

**File:** [crates/gl-node/src/main.rs](crates/gl-node/src/main.rs) lines 128–132  
**SPEC:** §3.11 — when `p2p.enabled` and the key path is unusable, boot should fail.

```rust
error!(%error, "failed to boot P2P — continuing without replication");
```

**Impact:** Operator believes the node is in the mesh; it is a silent singleton. Partition from the org’s books with no hard failure.

**Recommendation:** Fail boot, or require explicit `p2p.optional`.

---

### M-7: No GraphQL depth/complexity or HTTP body limits

**Files:** [crates/gl-node/src/graphql/mod.rs](crates/gl-node/src/graphql/mod.rs); [crates/gl-node/src/main.rs](crates/gl-node/src/main.rs)

No `limit_depth` / `limit_complexity`. Axum default body limit (2 MiB) may apply, but is not configured or tested. `verify` walks the whole DAG.

**Impact:** Nested introspection/query CPU exhaustion.

**Recommendation:** Set async-graphql limits; explicit `DefaultBodyLimit`; time-bound `verify`.

---

### M-8: Envelope and Lamport under-validated

**Files:** [crates/p2p/src/union_merge.rs](crates/p2p/src/union_merge.rs) lines 95–110; [crates/ledger/src/service.rs](crates/ledger/src/service.rs) lines 762–767

Any envelope keys are copied onto the directive (not only `openledger-*`). `kind` is not checked against the parsed body. Lamport is parsed with `parse::<u64>()` then `max + 1` (wraps at `u64::MAX`). Extra directives in `economic_bean` after the first are dropped (`next().unwrap()`).

**Impact:** Metadata pollution, kind confusion, Lamport collapse, hidden extra bodies in the wire payload.

**Recommendation:** Allowlist envelope keys; require kind match; `checked_add`; reject multi-directive bodies; reject unparseable Lamport.

---

### M-9: External file edits enabled by default (auth bypass)

**Files:** [crates/gl-node/src/config.rs](crates/gl-node/src/config.rs) lines 121–123; [crates/gl-node/src/main.rs](crates/gl-node/src/main.rs) lines 141–176; [deploy/gl-node.docker.json](deploy/gl-node.docker.json)

```rust
fn default_external_file_edits() -> String {
    "enabled".to_owned()
}
```

**Correction vs 0816:** that report’s positive table said the watcher is off by default. **It is on.** (`FileWatcherConfig::default()` is unused.)

Anyone who can write `ledgerPath` can insert directives **without** `X-Api-Key`. Reconcile then persists canonical form. Combined with H-8, a local writer can inject extra directives.

**Impact:** GraphQL auth is not the real write ACL; the file is.

**Recommendation:** Default `disabled` except in documented dev configs; require auth *or* explicit opt-in for adoption.

---

### M-10: File watcher stamps missing envelopes with the **local** author

**File:** [crates/ledger/src/service.rs](crates/ledger/src/service.rs) lines 528–574

Unsigned hand-edits get `openledger-author = local EndpointId`. SPEC allows adoption, but that means a filesystem attacker **impersonates this node** on every later gossip/anti-entropy supply (once R1/R3 land).

**Impact:** Forged local authorship without the secret key.

**Recommendation:** Distinct adopted-author marker; never sign adopted bodies with the node key unless a human confirms; verify signatures when present.

---

### M-11: Signature stamp is a second persist that ignores errors

**Files:** [crates/gl-node/src/graphql/mutation.rs](crates/gl-node/src/graphql/mutation.rs) lines 75–81; [crates/ledger/src/service.rs](crates/ledger/src/service.rs) lines 830–850

Flow: `append_transaction` persists **unsigned** → `stamp_signature` mutates DAG → `let _ = self.persist()`. Crash between the two writes leaves an unsigned SoT. Persist failure after stamp is swallowed.

**Impact:** Signing looks successful in the GraphQL response while disk has no signature.

**Recommendation:** Sign before first persist; fail the mutation if persist fails; do not ignore `persist()` errors.

---

### M-12: Unbounded peer registry

**File:** [crates/p2p/src/node.rs](crates/p2p/src/node.rs)

Every `NeighborUp` `upsert`s with no cap. Gossip `Lagged` is only logged.

**Impact:** Memory growth from neighbor churn.

**Recommendation:** Cap registry size; LRU unknown peers.

---

### M-13: GraphQL HTTP has no TLS

**SPEC:** §3.8 production checklist — TLS in-process or at the host.

Axum binds plaintext TCP. Docker publishes that port. API keys and ledger JSON travel in the clear on the HTTP hop.

**Impact:** Network sniffing of `X-Api-Key` and reports.

**Recommendation:** Document mandatory TLS terminator; or rustls in-process for production profiles.

---

## Low findings

### L-1: Unauthenticated `/health` leaks heads, peers, version

**File:** [crates/gl-node/src/health.rs](crates/gl-node/src/health.rs) lines 29–37  

Useful for recon (version → known bugs; peer count → mesh health). SPEC allows a health endpoint; it does not require these fields to be public.

**Recommendation:** `{ "status": "ok" }` without auth; details behind auth or an admin port.

---

### L-2: Docker HEALTHCHECK does not probe HTTP; compose needs `curl`

**Files:** [Dockerfile](Dockerfile) lines 47–48; [deploy/docker-compose.yml](deploy/docker-compose.yml)

Image `HEALTHCHECK` runs `gl-node --version`. Compose uses `curl`, not installed in `debian:bookworm-slim`.

**Impact:** False healthy / false unhealthy.

**Recommendation:** Install a probe binary or use a tiny HTTP check built into `gl-node`.

---

### L-3: Invalid mutation `flag` silently becomes `*`

**File:** [crates/gl-node/src/graphql/mutation.rs](crates/gl-node/src/graphql/mutation.rs) lines 31–34

**Recommendation:** Accept only `"*"` and `"!"`.

---

### L-4: `.gitignore` does not ignore secret key files

**File:** [.gitignore](.gitignore)

Ignores `.env` and `*.bean`, not `*.secret` / `identity.secret` / `iroh.secret`.

**Recommendation:** Add those globs.

---

### L-5: Remote `Open`/`Close` ignore account-state errors

**File:** [crates/ledger/src/service.rs](crates/ledger/src/service.rs) lines 788–809

```rust
let _ = self.accounts.open_account(...);
```

Directive still enters the G-Set. I3 on later transactions uses stale account state.

**Recommendation:** Reject the insert if account-state update fails.

---

### L-6: `Decimal` scalar accepts JSON numbers

**File:** [crates/gl-node/src/graphql/scalars.rs](crates/gl-node/src/graphql/scalars.rs) lines 41–46  

SPEC I4 / §3.1: decimals as strings. JSON numbers can round.

**Recommendation:** Accept strings only.

---

### L-7: `sign` / `verify_signature` always use the `txid` domain prefix

**File:** [crates/security/src/signing.rs](crates/security/src/signing.rs) lines 129–131, 173–174

`build_sign_message(..., true)` is hardcoded. Non-transaction directives would be signed/verified under `txid` rather than `directiveId`.

**Impact:** Latent cross-kind verification bug when opens/closes are signed.

**Recommendation:** Pass the real kind into `sign`/`verify`.

---

### L-8: Ed25519 verify is not `verify_strict`

**File:** [crates/security/src/signing.rs](crates/security/src/signing.rs) `Verifier::verify`

Dalek’s default verify is more permissive than `verify_strict` (small-order / canonical encoding).

**Recommendation:** Use `verify_strict` for ledger signatures.

---

### L-9: No CI, no `cargo-audit` / `cargo-deny`

No `.github/workflows`. Workspace Clippy is `deny(all)` locally but nothing enforces advisory scanning.

**Recommendation:** CI job: `cargo audit`, `cargo deny`, tests, clippy.

---

### L-10: `quote_string` does not escape control characters

**File:** [crates/ledger/src/serialize.rs](crates/ledger/src/serialize.rs) lines 350–361

Even quoted payee/narration can embed raw newlines/CR. Parser’s `read_quoted_string` will consume them as string data (not a new directive), but files become non-portable and harder to audit. Unquoted fields are H-8.

**Recommendation:** Reject or `\n`-escape controls in all serialized strings.

---

## Informational

### I-1: Auth and signing default off

Code defaults: `auth.enabled=false`, `signing.enabled=false`, bind `127.0.0.1`. Docker (H-5) is the dangerous override. Boot does not warn when bind is public and auth is off.

---

### I-2: GraphQL WebSocket advertised but not implemented

GraphiQL points at `/graphql/ws`. SPEC also requires SSE (outstanding R5). When WS is added, it must sit behind the same auth middleware (upgrade is easy to forget).

---

### I-3: Local mutations are not gossiped (`_gossip_sender` unused)

**File:** [crates/gl-node/src/main.rs](crates/gl-node/src/main.rs) line 100; outstanding **R1**.

Inbound `Supply` is still applied (C-4). Outbound lag is an availability issue; it does **not** mitigate inbound injection.

---

### I-4: Anti-entropy ALPN exchange is not implemented

**File:** [crates/gl-node/src/p2p_service.rs](crates/gl-node/src/p2p_service.rs) `spawn_anti_entropy_loop`; outstanding **R3**.

Loop compares heads and logs. Catch-up relies on gossip `Supply`. Security: fewer fetch paths today; once ALPN lands, authenticate and size-limit it.

---

### I-5: Two `ed25519-dalek` major versions in the lockfile

First-party signing: **2.2.0**. Iroh: **3.0.0**. Same 32-byte seed should interoperate, but key encoding (`EndpointId` Display vs `hex::encode(verifying_key)`) must be proven equal before receive-side verify (C-3) is implemented. Dual versions increase audit surface.

---

## Positive security observations

| Area | Assessment |
|------|------------|
| Content addressing | SHA-256 of economic canonical form; envelope keys excluded (I5 / CT-3 / CT-10) |
| Local I1–I3 / I9 | Enforced on GraphQL append and on remote *transactions* |
| Domain-separated signatures | `openledger-sig-v1\|txid\|…` prefix exists (kind always `txid` today — L-7) |
| No `unsafe` | Workspace crates |
| Config unknown keys | `deny_unknown_fields`; empty API key rejected when auth on |
| Unsupported Beancount | `include` / `plugin` / `option` hard-fail on **parse** (GraphQL bypass is H-8) |
| G-Set idempotency | Duplicate content IDs are no-ops |
| Cycle detection | Present when inserting transactions |
| Wire `from_wire` | Version + 16 MiB cap (gossip path does not use it — H-7) |
| Local §3.12 limits | Present on GraphQL `append_transaction` only (M-4) |
| Docker user | UID 1000 non-root |
| Graceful shutdown | SIGINT/SIGTERM |
| Default HTTP bind in code | `127.0.0.1` (deploy config overrides — H-5) |

---

## SPEC gaps (claimed vs implemented)

| SPEC rule | Code |
|-----------|------|
| §3.8.1 verify signature on remote insert when signing on | Not implemented (C-3, R4) |
| §3.9 bootstrap EndpointIds / tickets as discovery | Parsed, unused (C-4, R2) |
| §3.9 mDNS/convenience discovery dev-only | Production path uses `presets::N0` |
| §3.11 fail boot if P2P key unreadable | Continues without P2P (M-6) |
| §3.11 fail boot if signing required and key missing | Warn + noop (H-4) |
| §3.4.4 orphan buffer on missing parents | Buffer exists; remote insert never uses it (H-6) |
| §3.4.1 ALPN anti-entropy | Stub loop (I-4, R3) |
| §3.12 limits on all writes | Local append only (M-4) |
| §2.6 WS + SSE subscriptions | Schema has subscription; no WS/SSE routes (I-2) |
| Production: auth on before public bind | Docker sample does the opposite (H-5) |

---

## Recommended priority

1. **C-4 + C-3** — peer allowlist / unique topic; verify signatures on receive; stop applying unauthenticated `Supply`.  
2. **C-1 + C-2** — constant-time API key; `0o600` secret files.  
3. **H-4 + M-6** — fail boot instead of silent degrade.  
4. **H-8** — shared validation on GraphQL write path (cheap, high integrity).  
5. **H-2** — clamp journal pagination (one-liner) + rate limits.  
6. **H-1 + H-5 + H-3** — CORS, Docker defaults, GraphiQL off.  
7. **H-10** — atomic persist.  
8. **H-6 + H-7 + M-4** — strict parents, gossip framing, remote resource limits.  
9. **M-9** — default `externalFileEdits` to `disabled`.  
10. Remaining medium/low + CI `cargo-audit`.

---

## Appendix A: Dependency notes

| Crate | Notes |
|-------|--------|
| `serde_cbor 0.11.2` | Unmaintained (RUSTSEC-2021-0127) → `ciborium` |
| `ed25519-dalek` | Direct: 2.2.0 (OK). Transitive via iroh: 3.0.0 |
| `iroh 1.0.3` / `iroh-gossip 0.101` | N0 preset pulls public relay/discovery |
| `subtle` | Available transitively; not used in `auth.rs` |
| `tower-http` | CORS only; no rate-limit / trace / body features enabled |
| Advisories | This pass did not execute `cargo audit`; add it in CI (L-9) |

---

## Appendix B: Review coverage

| Path | Reviewed |
|------|----------|
| `crates/gl-node/src/**` | Yes (`main`, `auth`, `config`, `health`, `p2p_service`, GraphQL) |
| `crates/ledger/src/**` | Yes (service, parse, serialize, validate, dag, hash, weights, verify, file_watcher, read_model) |
| `crates/p2p/src/**` | Yes (protocol, gossip, union_merge, orphan_buffer, node, topic, anti_entropy) |
| `crates/security/src/**` | Yes |
| `deploy/`, `Dockerfile`, `config/`, `gl-node.config.json` | Yes |
| `docs/SPEC.md` security / P2P / limits | Yes |
| Integration tests | Skimmed; no adversarial tests for C-4 / H-8 |
| `unsafe` in workspace | None found |
| Third-party crate internals (iroh, async-graphql) | Not source-audited |

---

*End of SECURITY_AUDIT_0816-v2.md.*
