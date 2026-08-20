# Security Audit — openledger-v2

**Date:** 2026-08-20
**Scope:** Entire workspace — `gl-node`, `ledger`, `p2p`, `security` crates plus Docker/CI/config.
**Method:** Full source read of every crate, split across four reviewers (API surface, P2P/network, ledger engine, crypto + deployment). Top findings re-verified against source.

## Threat model

Two attacker classes matter here:

1. **Remote API caller** — anyone who can reach `POST /graphql`. Gated by API-key auth, but auth is **off by default** and only warn-enforced on a public bind.
2. **Malicious/compromised allowlisted peer** — the P2P allowlist is correctly and consistently enforced (inbound ALPN gated on the authenticated QUIC identity; gossip gated before decode; 16 MiB + cardinality caps on the wire). So there is **no anonymous-internet P2P attack surface**. The P2P findings below are integrity/DoS escalations *within* the trusted replica set — they matter because a single compromised replica should not be able to forge other peers' history or wedge the mesh.

Overall the codebase is unusually well-hardened: constant-time API-key compare, `0600` key files with permission checks at load, domain-separated Ed25519 signatures, boot-time refusal of sample keys / `cors:"*"` / public swarm topic / non-loopback bind without TLS. The issues below are what remains.

---

## High

### H1 — Decimal arithmetic panics on attacker-controlled amounts (remote DoS)
`crates/ledger/src/weights.rs:54,72,100`; same class in `read_model.rs:148,419`

Posting-weight summation and cost/price multiplication use `rust_decimal`'s `*`/`+`, which **panic** on overflow. Operands come straight from untrusted parsed amounts, and `Decimal::from_str` accepts values up to ~7.9e28. Two postings of `79228162514264337593543950335 USD`, or a single `10 AAPL {79228162514264337593543950335 USD}`, overflow inside `validate_transaction` before any balance check. Reachable from every write path — `appendTransaction`, remote gossip `insert_remote_directive`, and `reconcile_file`. In the async node this panic happens under the write lock, poisoning it and wedging all subsequent ledger operations. No `catch_unwind` anywhere in the crate.
**Fix:** use `checked_add`/`checked_mul` and map overflow to a validation error.

### H2 — Directive signatures do not cover the envelope; `parents`/`lamport` are malleable
`crates/security/src/signing.rs:64-71`, `crates/p2p/src/union_merge.rs:135-139,192-195`

The signed message is `openledger-sig-v1|<kind>|<content_id>`, and `content_id` is SHA-256 of the economic body only — envelope fields (`openledger-parents`, `openledger-lamport`) are authenticated by neither the hash nor the signature. An allowlisted relay can take another peer's validly-signed directive, rewrite its parents/Lamport clock, and deliver the tampered copy first; it verifies, is inserted, and the legitimate copy is then dropped as a duplicate by content ID. Consequences: strand a victim's transaction as a permanent orphan (censorship), or reorder transactions relative to balance assertions — corrupting causal ordering at the attacker's discretion. This directly undermines the stated goal of binding author identity.
**Fix:** include the envelope (or at least parents + lamport) in the signed message.

### H3 — Author is freely spoofable across the allowlist in the default (signing-off) config
`crates/gl-node/src/anti_entropy_alpn.rs:246`, `crates/p2p/src/union_merge.rs:180-221`; default `signing.enabled = false` (`config.rs:450`)

`signing.enabled` defaults false and **no config rule forces signing on when P2P is enabled** (the shipped `deploy/gl-node.docker.json` runs exactly this way). With signing off, `verify_remote_signature` returns `Ok(())` unconditionally, and the only origin check is that the *string* `openledger-author` is *somewhere* on the allowlist — it is never bound to the authenticated connection peer. One compromised node in the mesh can forge directives attributed to any other allowlisted peer, with arbitrary parents/lamport, and have them re-broadcast as that peer's history.
**Fix:** require signing when P2P is enabled (boot-time validation), and/or bind `openledger-author` to the connection's authenticated `EndpointId`.

---

## Medium

### M1 — GraphQL complexity budget allows amplification of expensive resolvers (DoS)
`crates/gl-node/src/graphql/mod.rs:34-44`, `query.rs:207-223`

Depth is capped at 16 and complexity at 4096, but every field has the default weight of 1, so one request can invoke a heavyweight resolver ~4096 times via aliases. `verify` runs a full DAG traversal under a read lock; `journal` returns up to 10,000 entries. A ~120 KB request of `{ a: verify{ok} b: verify{ok} … }` (~4000 aliases) is a single request that sails past the 60-req/min limiter and pins CPU on a large ledger.
**Fix:** annotate expensive resolvers with `#[graphql(complexity = …)]`.

### M2 — Unauthenticated mutations permitted on a public bind (warn-only)
`crates/gl-node/src/main.rs:287-292`, `config.rs:250-336`

With `auth.enabled` false (default) and a non-loopback bind, boot logs a warning and proceeds; `validate()` enforces TLS for a public bind but not auth. `bindAddress: "0.0.0.0"` + `tls.mode: "terminated"` + default auth yields an open, writable ledger (`appendTransaction`/`openAccount`/`closeAccount`) — a one-line misconfiguration.
**Fix:** refuse to boot on a non-loopback bind with auth disabled.

### M3 — Lamport-clock integer overflow on crafted `openledger-lamport`
`crates/ledger/src/service.rs:1080-1085` (via `anti_entropy_alpn.rs:267`)

`self.lamport_clock = self.lamport_clock.max(remote_lamport) + 1` with `remote_lamport` parsed from untrusted envelope metadata and no bound check. A peer sending `openledger-lamport: 18446744073709551615` overflows: debug builds panic (crash); release builds (no `[profile.release]` overflow-checks override — verified) wrap to 0, letting an attacker drive the node's logical clock arbitrarily and corrupt causal ordering.
**Fix:** reject out-of-range / use `saturating_add`.

### M4 — Orphan `waiting_on` index grows unbounded via oversized `openledger-parents`
`crates/p2p/src/orphan_buffer.rs:84-89`, `union_merge.rs:155-169` (no per-value length or parent-count cap)

Orphan *entry* count is capped, but each orphan may carry an unbounded parent list, and every parent inserts a distinct `waiting_on` key. One allowlisted peer sending `Supply` entries whose `openledger-parents` is a ~16 MiB comma-separated blob (~250k fake parents) injects ~250k map entries per single orphan; its 1,000-orphan quota yields ~10^8 cloned-string entries — tens of GB resident, none evictable for up to an hour.
**Fix:** cap parent count and envelope value length in `validate_supply_envelope`.

### M5 — Unbounded recursive DFS in cycle detection can overflow the stack
`crates/ledger/src/verify.rs:126-150`

`detect_cycles` walks the DAG with unbounded native recursion; depth = longest parent→child chain (attacker-controlled). A 64 MB file of chained transactions is ~600k frames deep — stack overflow aborts the process (unwind can't catch it) whenever verification runs.
**Fix:** convert to an explicit work-stack.

### M6 — Quadratic DAG insertion cost via ancestor walk
`crates/ledger/src/dag.rs:122,162`

Each insert walks the full ancestor set of every parent — O(N²) to load an N-long chain. A long parent chain via gossip or a crafted `.bean` makes boot/reconcile spend seconds-to-minutes of CPU; cheap asymmetric DoS.
**Fix:** memoize reachability or bound chain depth.

### M7 — CI actions pinned to mutable tags rather than commit SHAs
`.github/workflows/ci.yml:15,18,30`

`dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`, `rustsec/audit-check@v2.0.0` are moving refs. Compromise/force-push of any injects code into CI, which runs `cargo build`/`test` and holds `GITHUB_TOKEN`. Bounded (uses `pull_request` not `pull_request_target`; top-level `permissions: contents: read`), hence Medium.
**Fix:** pin to full commit SHAs.

---

## Low

- **L1** — `deploy/gl-node.docker.json` ships `signing.enabled: false` with P2P on → remote entries accepted with no signature check (this is the config that makes H3 live in the shipped deployment).
- **L2** — Signature domain omits ledger/mesh identity → cross-mesh replay if one node key is allowlisted on two meshes (`signing.rs:64-71`).
- **L3** — Filesystem paths leaked to GraphQL clients via `ServiceError::Io` error strings (`mutation.rs:81-84,136-139,165-168`).
- **L4** — API-key length leaked through early-return timing on length mismatch; the compare itself is constant-time (`auth.rs:58-66`).
- **L5** — `txid` not injective: payee-only vs narration-only transactions serialize identically → hash collision for programmatically-built directives (`serialize.rs:133-136`).
- **L6** — Atomic-persist temp file opened without `O_EXCL` → follows a pre-planted symlink; requires local same-dir write access (`service.rs:66-71`).
- **L7** — File-watcher change detection uses size+mtime only → edits preserving both within one mtime tick are silently dropped; bounded (`external_edits_enabled` defaults false) (`file_watcher.rs:76-88`).
- **L8** — Single allowlisted peer can pin ~1 GB of orphan memory for 1 h via max-size directives referencing nonexistent parents (`orphan_buffer.rs:14-19`); additive to M4.

---

## Checked and found sound
Allowlist enforcement on inbound connections and gossip; CBOR-bomb / unbounded-Vec on decode (16 MiB + cardinality caps before use); reachable wire-input panics (length-checked before slicing); content-hash verification; rate limiter keys on real TCP peer IP (not `X-Forwarded-For`) with bounded map growth; CORS rejects `"*"` and omits `allow_credentials`; `ledgerPath` rejects `..`/NUL/cwd-escape; GraphQL scalars validated, `.bean` injection escaped; introspection off unless loopback GraphiQL; no subscription route wired; constant-time API-key compare; `0600` key files with permission check at load; non-root container (uid 1000); no committed secrets in tree or git history.
