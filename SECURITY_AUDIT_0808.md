# Security Audit — OpenLedger v2

**Date:** 2026-08-08  
**Scope:** Full codebase review of all 4 workspace crates (`gl-node`, `ledger`, `p2p`, `security`) plus deployment configs  
**Methodology:** Manual source code review, dependency analysis, architecture assessment

---

## Executive Summary

OpenLedger v2 is a P2P-replicated double-entry accounting ledger with a GraphQL API. The codebase demonstrates **solid foundational security** in several areas (content-addressed hashing, Ed25519 signing, domain-separated signatures, input validation). However, the audit identified **15 findings across 5 severity levels** that should be addressed before production deployment.

| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟠 High | 4 |
| 🟡 Medium | 5 |
| 🔵 Low | 3 |
| ⚪ Informational | 1 |

---

## 🔴 Critical Findings

### C-1: API Key Compared with Non-Constant-Time Equality

**File:** [auth.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/auth.rs#L40)  
**Line:** 40

```rust
Some(key) if key == auth_state.api_key => next.run(request).await,
```

The API key is compared using Rust's standard `==` operator, which short-circuits on the first mismatched byte. This is vulnerable to **timing side-channel attacks** — an attacker can determine the API key one byte at a time by measuring response latency.

**Impact:** An attacker on the same network (or with low-latency access) could extract the API key character by character.

**Recommendation:**  
Use a constant-time comparison. Add the `subtle` crate and use `ConstantTimeEq`:

```rust
use subtle::ConstantTimeEq;

let key_matches = key.as_bytes().ct_eq(auth_state.api_key.as_bytes());
if key_matches.into() {
    next.run(request).await
}
```

---

### C-2: Secret Key File Written with No Permission Restrictions

**File:** [p2p_service.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/p2p_service.rs#L337)  
**Line:** 337

```rust
std::fs::write(path, hex::encode(key.to_bytes()))?;
```

The Iroh `SecretKey` (Ed25519 private key) is written to disk with the default file permissions, which on most systems is **world-readable** (`0644`). Any user on the system can read the node's private identity key.

The same issue exists in how the key is **read** — there's no permission check on the file at [line 319](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/p2p_service.rs#L319).

**Impact:** Complete P2P identity theft. An attacker with local file access can impersonate the node.

**Recommendation:**
```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
}
```

---

## 🟠 High Findings

### H-1: CORS is Fully Permissive

**File:** [main.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/main.rs#L247)  
**Line:** 247

```rust
.layer(CorsLayer::permissive())
```

`CorsLayer::permissive()` sets `Access-Control-Allow-Origin: *`, allows all methods, and allows all headers. Combined with the fact that auth is **optional** (disabled by default), this means:

- Any website can make GraphQL mutations (including `appendTransaction`) to a running node
- A user visiting a malicious webpage while `gl-node` runs locally could have **transactions injected into their ledger**

**Impact:** Cross-origin write access to the ledger from any website if auth is disabled.

**Recommendation:**  
- Default to restrictive CORS with an explicit `allowedOrigins` configuration field
- At minimum, restrict to `http://localhost:*` and the configured bind address
- Make CORS configurable in `NodeConfig`

---

### H-2: No Rate Limiting on Any Endpoint

The HTTP server has **zero rate limiting** on any endpoint — GraphQL queries, mutations, the health endpoint, and even the GraphiQL playground.

**Impact:**
- Denial of service via high-rate mutation requests (each one writes to disk + potentially gossips)
- Resource exhaustion from expensive queries (e.g., `journal` with very large `limit`)
- The `journal` endpoint accepts a `limit: i32` parameter ([query.rs:145](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/graphql/query.rs#L145)) and casts it to `usize` with `limit as usize`. A negative `limit` will wrap to `usize::MAX` on cast, potentially requesting billions of entries.

**Recommendation:**
- Add `tower::limit::RateLimitLayer` or `governor` middleware
- Cap `limit` and `offset` parameters to sane maximums (e.g., 10,000)
- Validate that `limit` and `offset` are non-negative before casting

---

### H-3: GraphiQL Playground Exposed in Production

**File:** [main.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/main.rs#L228)  
**Line:** 228

```rust
.route("/graphql", get(graphiql_handler).post(graphql_handler))
```

The GraphiQL interactive IDE is unconditionally served on `GET /graphql` in **all environments**, including production Docker deployments. This:

- Reveals the entire schema to unauthenticated users
- Provides a convenient attack surface for crafting mutations
- May expose internal type names and field descriptions

**Impact:** Schema introspection + interactive query builder available to anyone, even when auth is enabled (GraphiQL is served on GET, auth only checks the header on subsequent POST requests, but the schema is fully visible).

**Recommendation:**
- Make GraphiQL conditional on a config flag (e.g., `graphiql: true` — disabled by default)
- Or restrict to `NODE_ENV=development` / a debug flag
- Consider disabling introspection in production as well

---

### H-4: Signing Silently Falls Back to Noop on Errors

**File:** [main.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/main.rs#L183-L215)

When `signing.enabled = true` in the config but the key file is unreadable, corrupted, or missing, the system **silently falls back** to `NoopSignatureProvider` with only a `warn!` log:

```rust
warn!("signing enabled but secret key unreadable — falling back to noop");
Arc::new(security::signing::NoopSignatureProvider)
```

This means the system **claims** signing is enabled but all transactions are actually unsigned. The `NoopSignatureProvider::verify()` returns `Ok(())` for **any** signature, meaning forged signatures would be accepted.

**Impact:** A configuration that promises signing integrity silently provides none. Unsigned or forged transactions will be accepted without any visible error.

**Recommendation:**
- When `signing.enabled = true` and the key cannot be loaded, **abort boot** (same pattern as config validation). Don't silently degrade.
- Alternatively, add a `signing.required` config option that makes the key mandatory

---

## 🟡 Medium Findings

### M-1: `PeerRegistry` Uses `std::sync::RwLock` with `.unwrap()` — Panics on Lock Poisoning

**File:** [node.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/p2p/src/node.rs#L41-L65)

The `PeerRegistry` uses `std::sync::RwLock` (not `tokio::sync::RwLock`) and calls `.unwrap()` on every lock acquisition:

```rust
let mut peers = self.peers.write().unwrap();
```

If any thread panics while holding the lock, the `RwLock` becomes **poisoned**, and every subsequent access will panic, taking down the entire node.

**Impact:** A single panic in the gossip loop can cascade into a full node crash.

**Recommendation:** Either:
- Use `tokio::sync::RwLock` (consistent with the rest of the codebase)
- Or handle the poison: `self.peers.write().unwrap_or_else(|e| e.into_inner())`

---

### M-2: No Validation on `ledgerPath` — Directory Traversal Possible

**File:** [config.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/config.rs#L181-L185)

Config validation only checks that `ledgerPath` is non-empty. There's no restriction on:
- Path traversal (`../../../etc/passwd`)
- Absolute paths outside the data directory
- Symlinks pointing elsewhere

At [main.rs:54](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/main.rs#L54), the node will `create_dir_all` for the parent directory, potentially creating directories anywhere on the filesystem.

**Impact:** A malicious config could write the ledger file to arbitrary filesystem locations.

**Recommendation:**
- Canonicalize the path and verify it's within an expected directory
- Reject paths containing `..` or leading `/` if a relative path is expected
- In Docker, this is mitigated by the non-root user, but not on bare-metal

---

### M-3: Orphan Buffer Has No Per-Peer Limits

**File:** [orphan_buffer.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/p2p/src/orphan_buffer.rs#L14)

The orphan buffer has a global limit of 10,000 entries but no **per-peer** limit. A single malicious peer could fill the entire buffer with invalid orphans (referencing fake parent IDs that will never arrive), effectively blocking legitimate orphan resolution.

**Impact:** A malicious peer can DoS the orphan resolution mechanism.

**Recommendation:**
- Add per-peer tracking and limits (e.g., max 100 orphans per peer)
- Consider a priority/LRU eviction policy

---

### M-4: No Signature Verification on Received Remote Directives

**File:** [p2p_service.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/p2p_service.rs#L140-L175)

When receiving `Supply` entries via gossip, the code calls `validate_supply_entry()` which checks the content hash and envelope fields, but **never verifies the `openledger-signature`** against the `openledger-author` public key.

In [union_merge.rs:validate_supply_entry()](file:///Users/samurai/code/edgar/openledger-v2/crates/p2p/src/union_merge.rs#L73-L113), envelope fields are attached but signature verification is not performed.

**Impact:** Any peer can claim to be any author. Signed transactions can have their signatures ignored, and unsigned transactions can claim any author identity.

**Recommendation:**
- When `signing.enabled`, verify `openledger-signature` against the `openledger-author` public key before accepting the directive
- Reject directives with missing/invalid signatures when signing is required

---

### M-5: `serde_cbor` is Unmaintained

**File:** [Cargo.toml](file:///Users/samurai/code/edgar/openledger-v2/Cargo.toml#L31)

```toml
serde_cbor = "0.11"
```

The `serde_cbor` crate has been **unmaintained since 2021** and has been superseded by `ciborium`. While no specific CVEs are known, unmaintained dependencies pose a risk for unpatched vulnerabilities.

**Impact:** Potential future vulnerabilities in CBOR parsing will not receive patches.

**Recommendation:** Migrate to `ciborium` (a maintained fork/successor)

---

## 🔵 Low Findings

### L-1: Health Endpoint Leaks Internal Information

**File:** [health.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/health.rs#L29-L37)

The `/health` endpoint is exempt from auth (by design, per §2.9) and exposes:
- Exact head count
- Exact peer count
- Exact build version

This is useful for attackers doing reconnaissance (knowing the exact version to find CVEs, or monitoring peer connectivity patterns).

**Impact:** Low — but provides useful reconnaissance data to attackers.

**Recommendation:**
- Consider a minimal health response for unauthenticated requests (just `"status": "ok"`)
- Expose detailed info only to authenticated users or on a separate admin port

---

### L-2: Docker HEALTHCHECK Doesn't Actually Check HTTP

**File:** [Dockerfile](file:///Users/samurai/code/edgar/openledger-v2/Dockerfile#L47-L48)

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/gl-node", "--version"] || exit 1
```

The Dockerfile's `HEALTHCHECK` just runs `gl-node --version`, which only verifies the binary exists — not that the service is actually listening. The `docker-compose.yml` correctly uses `curl` against `/health`, but the Dockerfile itself doesn't.

Additionally, `curl` is not installed in the runtime image, so the compose healthcheck will **always fail** (the runtime image is `debian:bookworm-slim` without curl).

**Impact:** Docker healthchecks may not detect an unresponsive service; compose healthchecks will fail silently.

**Recommendation:**
- Install `curl` in the runtime image or use a compiled-in health-check binary
- Fix the Dockerfile `HEALTHCHECK` to use `curl -sf http://localhost:3000/health`

---

### L-3: `i32` to `usize` Cast on GraphQL `limit`/`offset` Parameters

**File:** [query.rs](file:///Users/samurai/code/edgar/openledger-v2/crates/gl-node/src/graphql/query.rs#L145-L156)

```rust
#[graphql(default = 100)] limit: i32,
#[graphql(default = 0)] offset: i32,
```

These are cast with `limit as usize` and `offset as usize`. If a client sends `limit: -1`, this becomes `usize::MAX` (18,446,744,073,709,551,615), potentially causing the query to attempt to return all entries.

**Impact:** Potential denial of service or excessive memory allocation.

**Recommendation:**
```rust
let limit = limit.max(0).min(10_000) as usize;
let offset = offset.max(0) as usize;
```

---

## ⚪ Informational

### I-1: Auth Disabled by Default — Secure Defaults Not Enforced

By default, both `auth.enabled` and `signing.enabled` are `false`. The Docker deploy config ([gl-node.docker.json](file:///Users/samurai/code/edgar/openledger-v2/deploy/gl-node.docker.json#L5-L7)) also ships with auth disabled and bind address `0.0.0.0`, meaning the node listens on all interfaces with no authentication.

While this is convenient for development, it's an insecure default for production.

**Recommendation:**
- Default `bindAddress` to `127.0.0.1` (✅ already done in code defaults)
- Consider logging a WARNING at boot when auth is disabled and bind address is `0.0.0.0`
- Ship production Docker configs with auth enabled

---

## Positive Security Observations

The following security practices are well-implemented:

| Area | Assessment |
|------|-----------|
| **Cryptographic signing** | Ed25519 via `ed25519-dalek` v2 — industry standard, correct usage |
| **Domain separation** | `openledger-sig-v1\|kind\|id` prefix prevents cross-context signature reuse |
| **Content-addressed integrity** | SHA-256 content IDs with envelope exclusion — correct I5 implementation |
| **Config validation** | `deny_unknown_fields` rejects typos; boot-time validation catches misconfigs |
| **No `unsafe` code** | Zero `unsafe` blocks in the entire codebase |
| **Graceful shutdown** | SIGTERM/SIGINT handling with drain period |
| **Non-root Docker** | Runtime container runs as UID 1000 |
| **DAG integrity** | Cycle detection, content hash verification, parent link validation |
| **Wire protocol versioning** | `v: 1` field + unsupported version rejection + 16 MiB message size cap |
| **Idempotent merge** | G-Set semantics prevent duplicate insertion (I4) |
| **Test coverage** | Comprehensive test suite including CT-conformance tests |
| **`.gitignore`** | Correctly excludes `.env` files and `*.bean` ledger data |

---

## Recommended Priority Order

1. **C-1** (timing attack) + **C-2** (key permissions) — fix immediately
2. **H-2** (negative limit cast) — quick fix, high impact
3. **H-4** (silent noop fallback) — configuration integrity
4. **H-1** (CORS) — critical for any network-exposed deployment
5. **M-4** (no signature verification) — enables author impersonation
6. **M-1** (RwLock poisoning) — reliability issue
7. **Remaining medium/low findings** — can be addressed iteratively
