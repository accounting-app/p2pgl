# Security Audit — OpenLedger v2

**Date:** 2026-08-16  
**Scope:** Full codebase review of all 4 workspace crates (`gl-node`, `ledger`, `p2p`, `security`) plus deployment configs  
**Methodology:** Manual source code review, dependency analysis, architecture assessment  
**Prior audit:** [SECURITY_AUDIT_0808.md](./SECURITY_AUDIT_0808.md) — **0 of 15 findings fixed**

---

## Executive Summary

OpenLedger v2 retains solid cryptographic and integrity foundations (content-addressed hashing, Ed25519, domain-separated signatures, double-entry enforcement, no `unsafe` code). Since the 2026-08-08 audit, **no prior findings have been remediated**. This pass reconfirmed all 15 prior issues and identified **additional** gaps in the P2P merge path, wire-protocol validation on gossip, remote resource limits, and deploy defaults.

| Severity | Count |
|----------|------:|
| 🔴 Critical | 3 |
| 🟠 High | 7 |
| 🟡 Medium | 8 |
| 🔵 Low | 5 |
| ⚪ Informational | 2 |

---

## Status of 2026-08-08 Findings

| Prior ID | Finding | Status |
|----------|---------|--------|
| C-1 | Non-constant-time API key compare | **Still present** |
| C-2 | Secret key file world-readable | **Still present** |
| H-1 | Permissive CORS | **Still present** |
| H-2 | No rate limiting | **Still present** |
| H-3 | GraphiQL always on | **Still present** |
| H-4 | Signing silent noop fallback | **Still present** |
| M-1 | `PeerRegistry` RwLock `.unwrap()` | **Still present** |
| M-2 | `ledgerPath` path traversal | **Still present** |
| M-3 | Orphan buffer no per-peer limits | **Still present** |
| M-4 | No signature verify on remote Supply | **Still present** (elevated → **C-3**) |
| M-5 | Unmaintained `serde_cbor` | **Still present** |
| L-1 | Health info disclosure | **Still present** |
| L-2 | Docker HEALTHCHECK / missing curl | **Still present** |
| L-3 | Negative `limit`/`offset` cast | **Still present** |
| I-1 | Auth off by default / Docker insecure | **Still present** (partly elevated → **H-5**) |

---

## 🔴 Critical Findings

### C-1: API Key Compared with Non-Constant-Time Equality

**File:** [auth.rs](crates/gl-node/src/auth.rs)  
**Line:** 40  
**Prior:** C-1 (unfixed)

```rust
Some(key) if key == auth_state.api_key => next.run(request).await,
```

The API key is compared with Rust's short-circuiting `==`. An attacker with low-latency access can recover the key byte-by-byte via timing.

**Impact:** Full API compromise when auth is enabled.

**Recommendation:** Use `subtle::ConstantTimeEq` (already a transitive dependency via `ed25519-dalek`); reject mismatched lengths in constant time.

---

### C-2: Secret Key File Written with Default Permissions

**File:** [p2p_service.rs](crates/gl-node/src/p2p_service.rs)  
**Lines:** 318–338  
**Prior:** C-2 (unfixed)

```rust
std::fs::write(path, hex::encode(key.to_bytes()))?;
```

The Iroh `SecretKey` is written with default umask permissions (typically world-readable). There is also no permission check when reading an existing key.

**Impact:** Local users can steal the node's P2P identity (and signing key, when signing reuses this file).

**Recommendation:** Create with mode `0o600`; refuse to load if group/other bits are set.

---

### C-3: No Signature Verification on Remote / Gossiped Directives

**Files:**  
- [union_merge.rs](crates/p2p/src/union_merge.rs) lines 73–113  
- [p2p_service.rs](crates/gl-node/src/p2p_service.rs) lines 140–175  
- [service.rs](crates/ledger/src/service.rs) lines 738–823  

**Prior:** M-4 (elevated — author impersonation on a financial ledger)

`validate_supply_entry()` checks content hash and envelope key presence, but never calls `security::signing::verify_signature`. Envelope `openledger-author` / `openledger-signature` are accepted as opaque strings.

```rust
// 4. Validate required envelope fields for transactions.
//    (author + lamport presence only — no signature check)
```

SPEC §3.5 / §3.8.1 require verifying `openledger-signature` against `openledger-author` when signing is enabled.

**Impact:** Any swarm peer can forge authorship. Cryptographic non-repudiation is illusory even when operators enable signing. Content integrity (hash) still holds; attribution does not.

**Recommendation:** When signing is enabled, require and verify signatures before `insert_remote_directive`. Prefer binding `openledger-author` to the sending Iroh `EndpointId`. Fail closed if verification cannot run.

---

## 🟠 High Findings

### H-1: CORS Is Fully Permissive

**File:** [main.rs](crates/gl-node/src/main.rs)  
**Line:** 247  
**Prior:** H-1 (unfixed)

```rust
.layer(CorsLayer::permissive())
```

With auth disabled (default), any website can issue GraphQL mutations against a reachable node.

**Impact:** Drive-by ledger writes from a malicious page while `gl-node` runs locally or is network-exposed.

**Recommendation:** Configurable origin allowlist; default to localhost-only or deny.

---

### H-2: No Rate Limiting; Journal `limit`/`offset` Can Wrap

**Files:** HTTP stack (no rate-limit middleware); [query.rs](crates/gl-node/src/graphql/query.rs) lines 145–156  
**Prior:** H-2 + L-3 (combined)

No rate limiting on GraphQL, mutations, or health. Negative `limit`/`offset` cast via `as usize` becomes `usize::MAX`, returning the full journal.

**Impact:** Disk/gossip/CPU DoS; unbounded response sizes.

**Recommendation:** Add tower/`governor` rate limits; clamp `limit.max(0).min(10_000)` and `offset.max(0)`.

---

### H-3: GraphiQL Playground Always Exposed

**Files:** [main.rs](crates/gl-node/src/main.rs) line 228; [graphql/mod.rs](crates/gl-node/src/graphql/mod.rs) lines 68–75  
**Prior:** H-3 (unfixed)

`GET /graphql` always serves GraphiQL (including a `/graphql/ws` subscription endpoint that is **not** wired). With auth disabled, the full schema is public.

**Impact:** Schema reconnaissance and a convenient mutation console for attackers.

**Recommendation:** Gate GraphiQL behind a config flag (default off); disable introspection in production.

---

### H-4: Signing Silently Falls Back to Noop

**File:** [main.rs](crates/gl-node/src/main.rs)  
**Lines:** 183–215  
**Prior:** H-4 (unfixed)

When `signing.enabled = true` but the key is missing/corrupt/unreadable, the node warns and uses `NoopSignatureProvider` (whose `verify` always returns `Ok(())`).

**Impact:** Operators believe signing is on; transactions are unsigned and forged signatures would be accepted on any path that uses the noop verifier.

**Recommendation:** Abort boot when signing is enabled and the key cannot be loaded.

---

### H-5: Production Docker Config Binds `0.0.0.0` with Auth Disabled

**File:** [gl-node.docker.json](deploy/gl-node.docker.json)  
**Lines:** 3–9  
**Prior:** I-1 (elevated for shippable deploy risk)

```json
"bindAddress": "0.0.0.0",
"auth": { "enabled": false },
"signing": { "enabled": false }
```

Combined with compose publishing ports 3000–3002, permissive CORS, and GraphiQL.

**Impact:** Network-exposed unauthenticated GraphQL on a standard `docker compose up`.

**Recommendation:** Ship production configs with auth + signing enabled; warn at boot when bind is public and auth is off.

---

### H-6: Remote DAG Inserts Use Lenient Parents; Orphan Buffer Effectively Unused

**Files:**  
- [service.rs](crates/ledger/src/service.rs) line 779 (`dag.insert(..., false)`)  
- [orphan_buffer.rs](crates/p2p/src/orphan_buffer.rs)  
- [union_merge.rs](crates/p2p/src/union_merge.rs)  

SPEC §3.4.4 requires buffering orphans when parents are missing. Remote inserts use `require_parents=false`, so transactions with dangling parents enter the G-Set and the orphan buffer path is largely dead.

**Impact:** Incomplete DAG edges, `verify_dag` missing-parent failures, and divergence from the specified merge protocol.

**Recommendation:** Use `require_parents=true` on remote inserts; on `MissingParent`, buffer and emit `want`; re-insert when parents arrive.

---

### H-7: Gossip Decode Bypasses Wire Version and Size Limits

**Files:**  
- [gossip.rs](crates/p2p/src/gossip.rs) lines 45–48  
- [protocol.rs](crates/p2p/src/protocol.rs) lines 143–160  

`from_wire` enforces `MAX_MESSAGE_SIZE` (16 MiB) and `WIRE_VERSION == 1`. Gossip uses `from_cbor` directly with neither check.

```rust
pub fn decode_broadcast(data: &[u8]) -> Result<WireMessage, String> {
    WireMessage::from_cbor(data).map_err(|e| format!("CBOR decode error: {e}"))
}
```

**Impact:** Oversized or unknown-version gossip payloads rely solely on iroh-gossip framing — DoS and forward-compat risk.

**Recommendation:** Apply the same size + version gates as `from_wire` before accepting gossip messages.

---

## 🟡 Medium Findings

### M-1: `PeerRegistry` Panics on Poisoned `RwLock`

**File:** [node.rs](crates/p2p/src/node.rs)  
**Lines:** 41–65  
**Prior:** M-1 (unfixed)

```rust
let mut peers = self.peers.write().unwrap();
```

**Impact:** One panic while holding the lock can crash the node on every subsequent peer/health access.

**Recommendation:** `unwrap_or_else(|e| e.into_inner())` or `tokio::sync::RwLock`.

---

### M-2: No Validation on `ledgerPath` — Directory Traversal Possible

**File:** [config.rs](crates/gl-node/src/config.rs)  
**Lines:** 181–185  
**Prior:** M-2 (unfixed)

Only non-empty is checked. Malicious config can cause `create_dir_all` / writes anywhere the process can write.

**Recommendation:** Jail under a data root; reject `..` and unexpected absolute paths.

---

### M-3: Orphan Buffer Has No Per-Peer Limits

**File:** [orphan_buffer.rs](crates/p2p/src/orphan_buffer.rs)  
**Line:** 14  
**Prior:** M-3 (unfixed)

Global cap of 10,000 only. Once H-6 is fixed, one peer can fill the buffer with never-resolving parents.

**Recommendation:** Per-peer quotas + LRU/TTL eviction under pressure.

---

### M-4: §3.12 Resource Limits Not Enforced on Remote Inserts

**File:** [service.rs](crates/ledger/src/service.rs)  
**Lines:** 267–316 (local only); 738+ (remote — no equivalent)

Local `append_transaction` enforces narration/postings/tags limits. Remote `insert_remote_directive` does not.

**Impact:** A peer can inject oversized directives that GraphQL clients cannot submit, amplifying memory/disk/CPU on merge.

**Recommendation:** Share one resource-limit checker for local and remote paths; cap `economic_bean` size in `validate_supply_entry`.

---

### M-5: Unmaintained `serde_cbor`

**File:** [Cargo.toml](Cargo.toml)  
**Line:** 31  
**Prior:** M-5 (unfixed)

`serde_cbor = "0.11"` — unmaintained (RUSTSEC-2021-0127). SPEC suggests `ciborium`.

**Impact:** No future patches for CBOR parser vulnerabilities.

**Recommendation:** Migrate to `ciborium`.

---

### M-6: P2P Boot Failure Continues Without Replication

**File:** [main.rs](crates/gl-node/src/main.rs)  
**Lines:** 128–132

```rust
error!(%error, "failed to boot P2P — continuing without replication");
```

**Impact:** Silent loss of replication when `p2p.enabled` is true — availability/integrity expectation mismatch.

**Recommendation:** Fail boot when P2P is required, or add an explicit `p2p.optional` flag.

---

### M-7: No GraphQL Depth/Complexity or Request Body Limits

**Files:** [graphql/mod.rs](crates/gl-node/src/graphql/mod.rs), [main.rs](crates/gl-node/src/main.rs)

No `limit_depth` / `limit_complexity` / Axum `DefaultBodyLimit`.

**Impact:** Nested queries or large POST bodies can exhaust CPU/memory.

**Recommendation:** async-graphql cost limits + HTTP body size cap.

---

### M-8: Envelope / Kind Under-Validated; Lamport Can Wrap

**Files:**  
- [union_merge.rs](crates/p2p/src/union_merge.rs) lines 101–110  
- [service.rs](crates/ledger/src/service.rs) lines 762–767  

Envelope checks only key presence (not parseable Lamport, sorted parents, or `kind` matching body). Remote Lamport uses unchecked `+ 1` (crafted `u64::MAX` wraps).

**Impact:** Non-canonical envelopes, soft protocol confusion, Lamport clock collapse.

**Recommendation:** Strict Lamport parse; normalize parents; reject kind mismatch; use `checked_add`.

---

## 🔵 Low Findings

### L-1: Health Endpoint Leaks Internal Information

**File:** [health.rs](crates/gl-node/src/health.rs)  
**Lines:** 29–37  
**Prior:** L-1 (unfixed)

Unauthenticated `/health` returns heads, peers, and exact version.

**Recommendation:** Minimal unauth body (`status: ok`); detailed metrics behind auth.

---

### L-2: Docker HEALTHCHECK Does Not Check HTTP; Compose Uses Missing `curl`

**Files:** [Dockerfile](Dockerfile) lines 47–48; [docker-compose.yml](deploy/docker-compose.yml) lines 32–33  
**Prior:** L-2 (unfixed)

Dockerfile runs `gl-node --version`. Compose uses `curl`, which is not installed in `debian:bookworm-slim` runtime.

**Impact:** Unhealthy processes may look healthy; compose healthchecks fail.

**Recommendation:** Install `curl`/`wget` or embed an HTTP probe; HEALTHCHECK `GET /health`.

---

### L-3: Weak Mutation `flag` Validation

**File:** [mutation.rs](crates/gl-node/src/graphql/mutation.rs)  
**Lines:** 31–34

```rust
let flag = match input.flag.as_str() {
    "!" => Flag::Incomplete,
    _ => Flag::Complete,
};
```

Invalid flags silently coerce to `*`.

**Recommendation:** Accept only `"*"` / `"!"`; reject others.

---

### L-4: `.gitignore` Does Not Exclude Secret Key Files

**File:** [.gitignore](.gitignore)

Ignores `.env` and `*.bean`, but not `*.secret` / identity key paths.

**Impact:** Easy accidental commit of `identity.secret`.

**Recommendation:** Add `*.secret`, `**/identity.secret`, and data-dir globs.

---

### L-5: Remote `Open`/`Close` Account-State Errors Ignored

**File:** [service.rs](crates/ledger/src/service.rs)  
**Lines:** 788–809

```rust
let _ = self.accounts.open_account(...);
```

**Impact:** Lifecycle directives can enter the G-Set while account state does not update → inconsistent I3 views across peers.

**Recommendation:** Reject or quarantine on account-state errors; keep G-Set and account state consistent.

---

## ⚪ Informational

### I-1: Auth and Signing Disabled by Default

Code defaults: `auth.enabled=false`, `signing.enabled=false`, bind `127.0.0.1` (good for local). Docker overrides bind to `0.0.0.0` with auth off (see H-5).

**Recommendation:** Boot WARNING when bind ≠ loopback and auth is disabled.

---

### I-2: Subscription WebSocket Advertised but Not Routed

GraphiQL advertises `/graphql/ws`; no Axum route implements it. Future wiring without auth would leak live transactions.

**Recommendation:** Remove the advertisement until WS is implemented behind the same auth middleware.

---

## Positive Security Observations

| Area | Assessment |
|------|-----------|
| **Cryptographic signing** | Ed25519 via `ed25519-dalek` v2 — correct usage |
| **Domain separation** | `openledger-sig-v1\|…` prefix present (always uses `txid` path today) |
| **Content-addressed integrity** | SHA-256 content IDs; envelope excluded from hash (I5) |
| **Remote economic validation** | Remote transactions still run I1/I2/I3/I9 |
| **Config validation** | `deny_unknown_fields`; auth requires non-empty key when enabled |
| **No `unsafe` code** | Zero `unsafe` blocks in workspace crates |
| **G-Set idempotency** | Duplicate content IDs rejected |
| **DAG cycle detection** | Present on insert + `verify_dag` |
| **Wire framing (anti-entropy)** | Version gate + 16 MiB cap in `from_wire` |
| **Local write limits** | §3.12 resource limits on GraphQL append path |
| **Unsupported directives** | `include`/`plugin` hard-fail — reduces inclusion SSRF risk |
| **File watcher** | Off by default (`externalFileEdits`) |
| **Non-root Docker** | Runtime UID 1000 |
| **Graceful shutdown** | SIGTERM/SIGINT with drain |
| **`.gitignore`** | Excludes `.env` and `*.bean` |

---

## Recommended Priority Order

1. **C-1** + **C-2** — constant-time auth; `0o600` secret keys  
2. **C-3** — verify remote signatures when signing is enabled  
3. **H-4** — fail boot on signing key failure  
4. **H-2** — clamp journal `limit`/`offset` (quick win) + rate limits  
5. **H-1** + **H-5** + **I-1** — CORS allowlist; secure Docker defaults  
6. **H-6** + **H-7** — strict remote parents + gossip size/version checks  
7. **H-3** — GraphiQL off by default  
8. **M-4** / **M-5** / remaining medium–low — remote resource limits, `ciborium`, RwLock poison, path jail

---

## Appendix: Dependency Notes

| Dependency | Status |
|------------|--------|
| `serde_cbor 0.11.2` | Unmaintained (RUSTSEC-2021-0127) — migrate to `ciborium` |
| `ed25519-dalek` | First-party uses v2 (OK); lockfile also pulls v3 via iroh |
| `ring` / `rustls` | Transitive versions look current |
| `cargo-audit` | Not present in CI — recommend adding |

*This audit did not run automated `cargo-audit`; lockfile review was manual against known RustSec advisories.*
