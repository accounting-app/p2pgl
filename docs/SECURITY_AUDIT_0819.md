# Security Audit — OpenLedger v2

**Date:** 2026-08-19  
**Report:** `SECURITY_AUDIT_0819.md`  
**Scope:** Full source review of workspace crates `gl-node`, `ledger`, `p2p`, `security`, plus `deploy/`, `config/`, `Dockerfile`, and `docs/SPEC.md` as the security contract. Working tree as of 2026-08-19 (includes uncommitted remediations).  
**Methodology:** Manual review of every Rust module, config, and deploy artifact; SPEC §3.8 / §3.4 / §3.12 cross-check; iroh-gossip 0.101 `delivered_from` semantics against the new allowlist; lockfile notes. No dynamic exploitation. `cargo-audit` was not run in CI (none exists).  
**Prior reports:** [SECURITY_AUDIT_0808.md](./SECURITY_AUDIT_0808.md) · [SECURITY_AUDIT_0816.md](./SECURITY_AUDIT_0816.md) · [SECURITY_AUDIT_0816-v2.md](./SECURITY_AUDIT_0816-v2.md)

---

## What’s new in this pass

The 2026-08-08 and 2026-08-16 audits found an unauthenticated, CORS-open GraphQL server that merged gossip `Supply` from any Iroh neighbor, with signatures never verified. **A large remediation set is now in the working tree.** This pass:

1. **Reconfirmed** every prior finding against current line numbers.
2. **Closed** twelve findings that are actually fixed in source (constant-time API key, `0600` secret files, restrictive CORS, fail-closed signing/P2P boot, gossip size/version gates, atomic persist, per-peer orphan quota, `ciborium`, file-watcher default off, journal flag/decimal clamps).
3. **Re-opened C-4 as still Critical:** the new bootstrap allowlist keys on iroh-gossip `delivered_from`, which is the **previous hop**, not the original publisher. Once any trusted peer is a gossip neighbor, a stranger on the same `TopicId` can inject `Supply` bodies.
4. **Added** findings the remediations introduced or left: envelope-key Beancount injection on the remote path, remote genesis on a non-empty DAG, committed Docker API key, HTTP loopback treated as P2P isolation, signature not bound to allowlist/sender, unbounded Supply batches, unbounded ledger file load.

---

## Executive summary

OpenLedger v2 is a P2P-replicated double-entry ledger with a GraphQL API. Cryptographic *building blocks* remain sound (SHA-256 content addressing, Ed25519 via `ed25519-dalek` v2, domain-separated sign messages, I1–I3/I9 on local and remote transactions, no `unsafe` in workspace crates). Operational *defaults* for a single loopback node are much safer than on 2026-08-16.

The remaining production blocker is the **mesh write path**. Gossip still applies full ledger `Supply` messages. Admission is “last hop is in `bootstrapEndpointIds`.” iroh-gossip documents that `delivered_from` is *not* the original author. Combined with `iroh::endpoint::presets::N0` (public relay + discovery) and signing off by default, a configured mesh does not enforce “only my org’s nodes may write my ledger.”

| Severity | Open | Fixed since 0816-v2 |
|----------|-----:|--------------------:|
| Critical | 1 | 2 (`C-1`, `C-2`) |
| High | 9 | 4 (`H-1`, `H-4`, `H-7`, `H-10`) |
| Medium | 12 | 3 (`M-3`, `M-5`, `M-6`; `M-9` also fixed) |
| Low | 10 | 2 (`L-3`, `L-6`) |
| Informational | 5 | — |

**Production Go/No-Go (SPEC §3.8):** **No-Go** for any deployment that enables P2P with a non-empty bootstrap list, or that publishes GraphQL without TLS and a unique API key. Loopback, `p2p.enabled=false`, auth optional: acceptable for local development.

---

## Status of prior findings

| ID | Finding | 0816-v2 | This pass |
|----|---------|---------|-----------|
| C-1 | Non-constant-time API key compare | Open | **Fixed** |
| C-2 | Secret key file world-readable | Open | **Fixed** |
| C-3 | No signature verify on remote Supply | Open | **Partial** (verify when signing on; author not bound to sender/allowlist) |
| C-4 | Unauthenticated P2P writes on public topic | Open | **Open** (allowlist is last-hop; still Critical) |
| H-1 | Permissive CORS | Open | **Fixed** |
| H-2 | No rate limiting; journal wrap | Open | **Partial** (limit/offset clamped; no rate limit) |
| H-3 | GraphiQL always on | Open | **Partial** (config flag; default still `true`) |
| H-4 | Signing silent noop fallback | Open | **Fixed** |
| H-5 | Docker `0.0.0.0` + auth off | Open | **Partial** (auth on; default key committed; GraphiQL on; signing off) |
| H-6 | Lenient remote parents / dead orphan path | Open | **Partial** (`require_parents=true` + buffer used; genesis still admitted) |
| H-7 | Gossip bypasses wire size/version | Open | **Fixed** |
| H-8 | Beancount injection via GraphQL | Open | **Partial** (GraphQL validated; remote envelope keys not) |
| H-9 | Public-relay confidentiality | Open | **Open** |
| H-10 | Non-atomic ledger persist | Open | **Fixed** |
| M-1 | `PeerRegistry` `RwLock` `.unwrap()` | Open | **Open** |
| M-2 | `ledgerPath` traversal | Open | **Open** |
| M-3 | Orphan buffer no per-peer limit | Open | **Fixed** |
| M-4 | §3.12 limits local-only | Open | **Mostly fixed** |
| M-5 | Unmaintained `serde_cbor` | Open | **Fixed** (`ciborium`) |
| M-6 | P2P boot failure continues | Open | **Fixed** |
| M-7 | No GraphQL depth/complexity limits | Open | **Open** |
| M-8 | Envelope / Lamport under-validated | Open | **Partial** |
| M-9 | External file edits default on | Open | **Fixed** |
| M-10 | Watcher stamps local author | Open | **Open** |
| M-11 | Signature stamp ignores persist errors | Open | **Open** |
| M-12 | Unbounded peer registry | Open | **Open** |
| M-13 | GraphQL HTTP has no TLS | Open | **Open** |
| L-1 | Health info disclosure | Open | **Open** |
| L-2 | Docker HEALTHCHECK / missing `curl` | Open | **Open** |
| L-3 | Invalid mutation `flag` silently `*` | Open | **Fixed** |
| L-4 | `.gitignore` omits secret key files | Open | **Open** |
| L-5 | Remote `Open`/`Close` ignore account errors | Open | **Open** |
| L-6 | `Decimal` scalar accepts JSON numbers | Open | **Fixed** |
| L-7 | `sign`/`verify` always `txid` domain | Open | **Partial** |
| L-8 | Ed25519 not `verify_strict` | Open | **Open** |
| L-9 | No CI / `cargo-audit` | Open | **Open** |
| L-10 | `quote_string` does not escape controls | Open | **Open** |

---

## Threat model

| Actor | Access | Realistic goals |
|-------|--------|-----------------|
| Browser / website | Victim has `gl-node` reachable | Weaker than 0816: CORS default-deny. Still works if operator lists the attacker origin, or if a non-browser client hits an unauthenticated bind. |
| Local user / container sibling | Filesystem read/write | Identity theft blocked if secret is `0600`. Ledger `.bean` still created with default umask. File-watcher adoption impersonates local author when enabled. |
| Swarm peer (allowlisted) | Iroh gossip neighbor | Intended writer. Can still inject genesis, unsigned bodies (if signing off), and envelope keys. |
| Swarm stranger on same `TopicId` | N0 discovery + gossip flood | **Inject `Supply` via last-hop allowlist** when the victim has any bootstrap neighbor (C-4). |
| Network observer | Path to n0 relay | Read gossip payloads (Announce ids always; `Supply` economic bodies when sent). |
| Operator with shipped Docker config | Published ports 3000–3002 | GraphQL with documented default API key `change-me-docker-api-key`. |

Trust boundary the code *claims* (SPEC §3.8): “only bootstrap `EndpointId`s may write.” Trust boundary the code *enforces*: “the previous gossip hop is in the bootstrap list.” Those are not the same.

---

## Attack surface inventory

| Surface | Auth | Notes |
|---------|------|-------|
| `POST /graphql` | Optional `X-Api-Key` (off by default; constant-time compare) | Mutations: `appendTransaction`, `openAccount`, `closeAccount` |
| `GET /graphql` | Same middleware | GraphiQL when `graphiql: true` (default) |
| `GET /health` | **None** (SPEC §2.9) | Heads, peer count, version |
| GraphQL reports / `verify` / `peers` | Same as GraphQL | Full financial reports when auth off |
| `/graphql/ws` | Advertised in spec/schema, **not routed** | Dead endpoint today |
| Iroh QUIC + `iroh-gossip` | Last-hop allowlist on `Supply` | `presets::N0`; inbound `Supply` merged |
| `.bean` file | OS permissions | Watcher off by default; adoption stamps local author |
| `p2p.secretKeyPath` | `0600` required on Unix | Hex-encoded Ed25519 seed; used for signing when enabled |

---

## Critical findings

### C-4: Gossip allowlist admits last hop, not origin — strangers can still write the ledger

**Files:**  
- [crates/gl-node/src/p2p_service.rs](../crates/gl-node/src/p2p_service.rs) lines 45–46 (`presets::N0`), 105 (`subscribe`), 146–230 (apply `Supply`)  
- [crates/p2p/src/allowlist.rs](../crates/p2p/src/allowlist.rs)  
- iroh-gossip 0.101 `Message.delivered_from`: *“The endpoint that delivered the message. This is not the same as the original author.”* (`DeliveryScope` is unused.)

**Prior:** 0816-v2 C-4 — *not fixed*; the new allowlist does not implement the stated policy.

Empty `bootstrapEndpointIds` now drops inbound `Supply` (fail-closed for a singleton). That is real progress, and it is why the shipped Docker sample (empty bootstrap) does not merge stranger writes *until* an operator fills the list.

A working mesh **must** list bootstrap peers. Then:

1. Victim V allowlists org node A.
2. V and A become gossip neighbors on `TopicId = SHA-256(swarmTopic)`.
3. Stranger T joins the same topic via N0 discovery (topic string is in config/spec; Docker uses `openledger/docker-dev`).
4. T broadcasts `WireMessage::Supply` with balanced transactions / `open` directives.
5. iroh-gossip floods the payload. A’s *application* may drop T, but the overlay still delivers the bytes to V.
6. V sees `Event::Received` with `delivered_from = A` (previous hop). `allowlist.admits(A)` is true.
7. V runs `validate_supply_entry` + `insert_remote_directive` and persists into `.bean`.

`msg.scope` (`DeliveryScope::Swarm(hops)` vs direct) is ignored, so V cannot even require “publisher is my direct neighbor.”

Signing does not save this when `signing.enabled` is false (default). When signing is on, T signs with T’s own key; verification checks `openledger-author` against that key, **not** membership in the allowlist (see H-14).

Honest nodes currently broadcast **Announce** only (`make_announce`); they still **accept Supply**. The attack message type is richer than the honest protocol.

**Impact:** Cross-deployment ledger injection into any node that has enabled P2P and listed at least one bootstrap peer. Economic hash integrity does not stop *new* valid-looking entries. Authorship is whatever T puts in the envelope.

**Recommendation:**

- Do not apply gossip `Supply`. Treat gossip as Announce-only; fetch bodies over ALPN from an authenticated peer, bound to that peer’s `EndpointId`.
- If gossip writes must stay: require `scope.is_direct()`, `delivered_from ∈ allowlist`, **and** `openledger-author == delivered_from` hex, **and** a valid signature when signing is on. Prefer restricting gossip membership to the allowlist (not only application drop).
- Do not use `presets::N0` for production meshes (SPEC §3.9 already says convenience discovery is dev-only).
- Refuse the public default topic in *all* `p2p.enabled` boots, not only when HTTP binds non-loopback (see H-15).

---

## High findings

### H-2: No rate limiting; journal still materializes the full filter set

**Files:** HTTP stack (no limiter); [crates/gl-node/src/graphql/query.rs](../crates/gl-node/src/graphql/query.rs) `clamp_journal_limit` / `clamp_journal_offset`; [crates/ledger/src/read_model.rs](../crates/ledger/src/read_model.rs) lines 343–373

Negative `limit`/`offset` no longer wrap to `usize::MAX` (fixed). `limit` is capped at 10_000. `journal` still **collects every matching row** into a `Vec` before `skip`/`take`. Mutations still rewrite the entire `.bean` (atomic, but expensive). No per-IP or per-key throttle.

Gossip `Supply { entries }` has **no entry-count cap**. Each `economic_bean` may be 1 MiB and the CBOR frame 16 MiB, so one allowlisted (or last-hop) message can force many parse/validate/persist cycles. `Want` ID lists are similarly uncapped on the (still stub) anti-entropy types.

**Impact:** Memory/CPU/disk DoS from `journal` scans, `verify` walks, mutation floods (each persist is O(ledger size)), and unbounded Supply batches.

**Recommendation:** Paginate without allocating the full filter set; `governor` / tower rate limits on `/graphql`; cap `entries.len()` (and Want IDs); time-bound `verify`.

---

### H-3: GraphiQL and introspection default on

**Files:** [crates/gl-node/src/config.rs](../crates/gl-node/src/config.rs) `default_graphiql() -> true`; [crates/gl-node/src/main.rs](../crates/gl-node/src/main.rs) lines 209–216; [crates/gl-node/src/graphql/mod.rs](../crates/gl-node/src/graphql/mod.rs) `Schema::build(...).finish()` with no `disable_introspection`

GraphiQL can be turned off. Default remains on, including when `bindAddress` is `0.0.0.0`. Auth (when enabled) does wrap `GET /graphql`, so the playground requires `X-Api-Key` — better than 0816. Introspection remains available on POST for anyone who can authenticate (or anyone, if auth is off).

**Impact:** Interactive schema + mutation console; reconnaissance.

**Recommendation:** Default `graphiql` to `false`; disable introspection when GraphiQL is off or when bind is non-loopback.

---

### H-5: Shipped Docker config publishes GraphQL with a committed default API key

**File:** [deploy/gl-node.docker.json](../deploy/gl-node.docker.json)  
**Compose:** [deploy/docker-compose.yml](../deploy/docker-compose.yml) publishes `3000–3002`

Improvements vs 0816: `auth.enabled: true`, unique-ish `swarmTopic` (`openledger/docker-dev`), empty bootstrap (inbound `Supply` dropped), CORS empty, file watcher off.

Remaining:

```json
"bindAddress": "0.0.0.0",
"auth": { "enabled": true, "apiKey": "change-me-docker-api-key" },
"signing": { "enabled": false }
```

`graphiql` is omitted → default `true`. Anyone who can reach the published port and who knows the key (it is in git) has full ledger read/write. Signing is off, so C-4/H-14 apply as soon as bootstrap IDs are added to make replication work.

**Impact:** `docker compose up` is an internet-reachable GraphQL ledger with a public credential.

**Recommendation:** Generate a per-deploy API key at first boot; do not commit a real-looking default. `graphiql: false`. Warn/fail if `apiKey` is the sample string. Enable signing for multi-node samples.

---

### H-6: Remote genesis is still legal on a non-empty DAG

**Files:** [crates/ledger/src/service.rs](../crates/ledger/src/service.rs) `insert_remote_directive` (`dag.insert(..., true)`); [crates/ledger/src/dag.rs](../crates/ledger/src/dag.rs) lines 108–117; [crates/ledger/src/model.rs](../crates/ledger/src/model.rs) `parent_ids()` filters empty strings

Remote transactions now use `require_parents=true` and missing parents go to `OrphanBuffer` (H-6 from 0816 is partly fixed). If `openledger-parents` is missing or empty, `parent_ids()` is empty, the parent loop does not run, and the transaction is inserted as a **second genesis**.

SPEC I8 / §2.3: genesis is legal only when the authoring node had zero heads.

**Impact:** An allowlisted hop (or C-4 stranger) can fork the DAG with a disconnected root, breaking a single audit trail and `verify` expectations.

**Recommendation:** Reject remote transactions with empty parents unless the local DAG has zero transactions. Keep buffering for *missing* (non-empty) parents.

---

### H-8: Remote envelope keys are copied and serialized unquoted (Beancount injection)

**Files:**  
- [crates/p2p/src/union_merge.rs](../crates/p2p/src/union_merge.rs) lines 111–115 (copy every envelope key)  
- [crates/ledger/src/serialize.rs](../crates/ledger/src/serialize.rs) line 345 (`{key}: {quoted value}`)

GraphQL `appendTransaction` / `openAccount` now run `validate_account_name`, `validate_currency`, tag/link regexes, and `reject_control_characters` on payee/narration. That closes the 0816 GraphQL injection.

The P2P path still attaches **arbitrary** envelope keys. Serializer writes metadata **keys unquoted**. A key containing a newline becomes extra `.bean` lines after persist — new directives that were never a single validated write. `extract_envelope` on *outbound* honest Supply filters `openledger-*`; inbound crafted Supply does not.

**Impact:** Ledger file injection, round-trip desync, extra opens/transactions after reboot.

**Recommendation:** Allowlist envelope keys to `openledger-author|lamport|parents|signature`. Reject control characters in keys and values. Quote or reject non-token keys.

---

### H-9: Ledger traffic traverses the public Iroh N0 relay network

**File:** [crates/gl-node/src/p2p_service.rs](../crates/gl-node/src/p2p_service.rs) lines 45–49

`Endpoint::builder(presets::N0)` enables n0 relays, holepunch, and public discovery. Gossip payloads are application plaintext (QUIC to the relay, not end-to-end at the ledger layer). Honest nodes send Announce (ids); `Supply` still carries `economic_bean` when used.

**Impact:** Financial metadata (and full journal bodies on Supply) may be visible to the relay operator and to topic participants (C-4).

**Recommendation:** Private relays or direct-only meshes; unique topics; Announce-only gossip; encrypt application payloads if relays are required.

---

### H-14: Signature verification does not bind author to the allowlist or the sender

**Files:** [crates/p2p/src/union_merge.rs](../crates/p2p/src/union_merge.rs) `verify_remote_signature` (lines 136–156); gossip handler passes `signing_enabled` only

When `signing.enabled` is true, missing/invalid signatures are rejected (C-3 from 0816 is implemented on that axis). The public key is `openledger-author`. There is no check that:

- `author` is in `bootstrapEndpointIds`, or
- `author` equals `delivered_from` hex.

A stranger who can get a `Supply` delivered (C-4) signs as themselves and is accepted as a new author. Signatures also cover only `openledger-sig-v1|{txid|directiveId}|{content_id}` — **not** parents, Lamport, or extra envelope keys (H-8 / M-17).

**Impact:** Non-repudiation is “this key signed this economic body,” not “this mesh member authored this DAG edge.”

**Recommendation:** Require `openledger-author` ∈ allowlist and equal to the authenticated sender. Extend the signed message to include parents + lamport, or treat those fields as untrusted until ALPN-authenticated fetch.

---

### H-15: HTTP loopback is treated as P2P isolation; default topic remains allowed

**File:** [crates/gl-node/src/config.rs](../crates/gl-node/src/config.rs) lines 232–242

Default `swarmTopic` `openledger/transactions` is rejected only when `bindAddress` is non-loopback. Iroh still uses N0. A node bound to `127.0.0.1` with `p2p.enabled` joins the **public** default topic. Empty allowlist drops `Supply`, but Announce of local txids still leaves the host, and adding bootstrap IDs later inherits C-4 on a well-known topic.

**Impact:** Operators think “localhost = private mesh.” P2P is not bound by `bindAddress`.

**Recommendation:** Unique `swarmTopic` required whenever `p2p.enabled`. Do not key P2P policy on HTTP bind.

---

## Medium findings

### M-1: `PeerRegistry` panics on poisoned `std::sync::RwLock`

**File:** [crates/p2p/src/node.rs](../crates/p2p/src/node.rs) lines 41–61  

Every `upsert` / `remove` / `list` / `count` uses `.unwrap()`. Health and GraphQL `peers` hit this.

**Recommendation:** `unwrap_or_else(|e| e.into_inner())` or `tokio::sync::RwLock`.

---

### M-2: `ledgerPath` is not jailed

**File:** [crates/gl-node/src/config.rs](../crates/gl-node/src/config.rs) lines 205–208; [crates/gl-node/src/main.rs](../crates/gl-node/src/main.rs) lines 50–65

Only non-empty is required. `create_dir_all` + writes follow `..` and absolute paths.

**Recommendation:** Resolve against a data root; reject `..` after canonicalize.

---

### M-7: No GraphQL depth/complexity or explicit HTTP body limit

**Files:** [crates/gl-node/src/graphql/mod.rs](../crates/gl-node/src/graphql/mod.rs); [crates/gl-node/src/main.rs](../crates/gl-node/src/main.rs)

No `limit_depth` / `limit_complexity`. Axum’s default body limit (~2 MiB) is not configured or tested. `verify` walks the whole DAG.

**Recommendation:** Set async-graphql limits; explicit `DefaultBodyLimit`.

---

### M-8: Envelope kind, extra bodies, Lamport wrap

**Files:** [crates/p2p/src/union_merge.rs](../crates/p2p/src/union_merge.rs) lines 100, 117–126; [crates/ledger/src/service.rs](../crates/ledger/src/service.rs) lines 968–972

- `SupplyEntry.kind` is not checked against the parsed body.  
- Extra directives after the first in `economic_bean` are dropped (`next().unwrap()`); the whole string is still parsed (CPU) up to 1 MiB.  
- Remote Lamport: `max(local, remote) + 1` wraps at `u64::MAX`.  
- Unparseable Lamport is silently skipped.

`economic_bean` length is now capped (`MAX_ECONOMIC_BEAN_LENGTH`).

**Recommendation:** Require kind match; reject multi-directive bodies; `checked_add`; reject unparseable Lamport.

---

### M-10: File watcher stamps missing envelopes with the local author

**File:** [crates/ledger/src/service.rs](../crates/ledger/src/service.rs) lines 727–732

Default `externalFileEdits` is now `disabled` (M-9 fixed). When enabled, unsigned hand-edits get `openledger-author = local EndpointId`. A filesystem attacker impersonates this node on later Supply (once R1 lands).

**Recommendation:** Distinct adopted-author marker; never sign adopted bodies with the node key unless confirmed.

---

### M-11: Signature stamp is a second persist that ignores errors

**Files:** [crates/gl-node/src/graphql/mutation.rs](../crates/gl-node/src/graphql/mutation.rs) lines 81–87; [crates/ledger/src/service.rs](../crates/ledger/src/service.rs) lines 1038–1055

Flow: `append_transaction` persists **unsigned** → `stamp_signature` mutates DAG → `let _ = self.persist()`. Crash between the two writes leaves an unsigned SoT. Persist failure after stamp is swallowed. GraphQL still returns success.

**Recommendation:** Sign before first persist; fail the mutation if persist fails.

---

### M-12: Unbounded peer registry

**File:** [crates/p2p/src/node.rs](../crates/p2p/src/node.rs)

`NeighborUp` upserts allowlisted peers with no cap. `Lagged` is only logged (message loss, not crash).

**Recommendation:** Cap registry size.

---

### M-13: GraphQL HTTP has no TLS

SPEC §3.8: TLS in-process or at the host. Axum binds plaintext TCP. Docker publishes that port. API keys and ledger JSON travel in the clear on the HTTP hop.

**Recommendation:** Document mandatory TLS terminator; or rustls in-process for production profiles. Fail boot if non-loopback bind and no TLS config.

---

### M-14: Orphan drain uses a stale DAG id set

**File:** [crates/gl-node/src/p2p_service.rs](../crates/gl-node/src/p2p_service.rs) `drain_orphans` lines 336–368

`dag_ids` is collected once. Newly inserted orphans are not added, so chains of orphans may remain buffered until a later Supply. Fills per-peer quota (DoS / stuck catch-up). Drain also calls `insert_remote_directive` **without** re-running `verify_remote_signature`. That is safe today only because the buffer is in-process and filled after verify; a later change that mutates buffered directives would skip the gate.

**Recommendation:** Update `dag_ids` after each successful insert; loop until fixpoint; re-verify signatures on drain.

---

### M-15: Atomic persist still creates world-readable `.bean` files

**File:** [crates/ledger/src/service.rs](../crates/ledger/src/service.rs) `persist_atomically` (`File::create` without mode)

Temp + `sync_all` + rename is correct for crash safety (H-10). `File::create` uses umask (typically `0644`). The source of truth is world-readable on multi-user hosts. Directory `sync_all` errors are ignored.

**Recommendation:** `OpenOptions` `0o600` on the temp file; fsync directory and fail closed if it errors (or log at error).

---

### M-16: `DeliveryScope` ignored

**File:** [crates/gl-node/src/p2p_service.rs](../crates/gl-node/src/p2p_service.rs) Received handler

iroh-gossip exposes `scope.is_direct()` (publisher is previous hop vs multi-hop swarm). Unused. Combined with C-4 this is the difference between “neighbor sent this” and “someone flooded this.”

**Recommendation:** Reject `Supply` unless `scope.is_direct()` (interim); long-term, do not apply gossip Supply.

---

### M-17: Ledger boot and reconcile read the entire `.bean` into memory

**File:** [crates/ledger/src/service.rs](../crates/ledger/src/service.rs) lines 311–312, 695 (`std::fs::read_to_string`)

There is no maximum file size. A huge ledger (local attacker, or remote flood of inserts that persist) can OOM the process on boot or on the 250ms file-watcher poll.

**Recommendation:** Cap file size at boot/reconcile; stream-parse; refuse persist above the cap.

---

## Low findings

### L-1: Unauthenticated `/health` leaks heads, peers, version

**File:** [crates/gl-node/src/health.rs](../crates/gl-node/src/health.rs) lines 29–37  

**Recommendation:** `{ "status": "ok" }` without auth; details behind auth.

---

### L-2: Docker HEALTHCHECK does not probe HTTP; compose needs `curl`

**Files:** [Dockerfile](../Dockerfile) lines 47–48; [deploy/docker-compose.yml](../deploy/docker-compose.yml)

Image `HEALTHCHECK` runs `gl-node --version`. The binary has **no CLI flags** — `main` always boots the node — so the Dockerfile probe does not mean what it says and may hang or fail depending on config. Compose uses `curl`, which is not installed in `debian:bookworm-slim`.

**Recommendation:** Add `gl-node --health-check` (or install a probe binary) that only hits `GET /health`. Do not invoke the full server as HEALTHCHECK.

---

### L-4: `.gitignore` does not ignore secret key files

**File:** [.gitignore](../.gitignore)

Ignores `.env` and `*.bean`, not `*.secret` / `identity.secret` / `iroh.secret`.

**Recommendation:** Add those globs.

---

### L-5: Remote `Open`/`Close` ignore account-state errors

**File:** [crates/ledger/src/service.rs](../crates/ledger/src/service.rs) lines 994–1008

```rust
let _ = self.accounts.open_account(...);
```

Directive still enters the G-Set. I3 on later transactions uses stale account state.

**Recommendation:** Reject the insert if account-state update fails.

---

### L-7: `PeerKeySignatureProvider::verify` always uses the `txid` domain

**File:** [crates/security/src/signing.rs](../crates/security/src/signing.rs) line 143 (`verify_signature(..., true)`)

Standalone `verify_signature` now takes `is_transaction` (union-merge uses it correctly). The provider method still hardcodes `true`. Any caller using the trait to verify opens/closes will accept the wrong domain.

**Recommendation:** Thread `is_transaction` through `SignatureProvider::verify`.

---

### L-8: Ed25519 verify is not `verify_strict`

**File:** [crates/security/src/signing.rs](../crates/security/src/signing.rs)

Dalek’s default verify is more permissive than `verify_strict` (small-order / canonical encoding).

**Recommendation:** Use `verify_strict` for ledger signatures.

---

### L-9: No CI, no `cargo-audit` / `cargo-deny`

No `.github/workflows`. Workspace Clippy is `deny(all)` locally but nothing enforces advisory scanning.

**Recommendation:** CI job: `cargo audit`, `cargo deny`, tests, clippy.

---

### L-10: `quote_string` does not escape control characters

**File:** [crates/ledger/src/serialize.rs](../crates/ledger/src/serialize.rs) lines 350–361

Quoted payee/narration can still embed raw newlines if they bypass GraphQL checks (reconcile / remote). Parser treats them as string data; files become non-portable.

**Recommendation:** Reject or `\n`-escape controls in all serialized strings.

---

### L-11: API key length is still an oracle

**File:** [crates/gl-node/src/auth.rs](../crates/gl-node/src/auth.rs) `api_key_matches`

Length mismatch dummy-compares `expected` to itself, then returns. Attackers learn key length from timing. Byte-by-byte recovery of the secret is fixed (C-1).

**Recommendation:** Compare against a fixed dummy buffer of `expected.len()` always; or HMAC-compare a keyed digest.

---

## Informational

### I-1: Auth and signing default off

Code defaults: `auth.enabled=false`, `signing.enabled=false`, bind `127.0.0.1`. Boot warns when bind is public and auth is off. Docker (H-5) is the dangerous override.

---

### I-2: GraphQL WebSocket advertised but not implemented

Schema has `transactionAppended`. No Axum WS/SSE route (outstanding **R5**). GraphiQL no longer hardcodes `/graphql/ws` in `graphiql_handler` (improvement). When WS is added, it must sit behind the same auth middleware.

---

### I-3: Local mutations are not gossiped (`_gossip_sender` unused)

**File:** [crates/gl-node/src/main.rs](../crates/gl-node/src/main.rs) line 99; outstanding **R1**.

Inbound `Supply` is still applied (C-4). Outbound lag is availability; it does **not** mitigate inbound injection. It does mean the working attack path (`Supply`) is not what honest nodes send (`Announce`).

---

### I-4: Anti-entropy ALPN exchange is not implemented

**File:** [crates/gl-node/src/p2p_service.rs](../crates/gl-node/src/p2p_service.rs) `spawn_anti_entropy_loop`; outstanding **R3**.

Loop compares heads and logs. Catch-up relies on gossip. Once ALPN lands, authenticate the peer `EndpointId`, size-limit frames (`from_wire` already exists), and do not skip the allowlist.

---

### I-5: Two `ed25519-dalek` major versions in the lockfile

First-party signing: **2.x**. Iroh: **3.x**. A unit test now asserts Iroh `EndpointId` Display equals dalek verifying-key hex (good for C-3). Dual versions still increase audit surface.

---

## Positive security observations

| Area | Assessment |
|------|------------|
| API key compare | `subtle::ConstantTimeEq` with tests (`C-1`) |
| Secret key files | Create `0600`; refuse group/other-readable (`C-2`) |
| CORS | Empty allowlist = no ACAO; `"*"` rejected at boot (`H-1`) |
| Signing boot | Missing key + `signing.enabled` → process exit (`H-4`) |
| P2P boot | Failure + `p2p.enabled` → process exit (`M-6`) |
| Gossip framing | `decode_checked`: 16 MiB + `v == 1` (`H-7`) |
| Persist | Temp file, `sync_all`, rename (`H-10`) |
| Orphan buffer | Global 10_000 + per-peer 1_000 + TTL (`M-3`) |
| CBOR | `ciborium` (`M-5`) |
| File watcher | Default `disabled` (`M-9`) |
| GraphQL writes | Account/currency/tag/link/control validation (`H-8` local) |
| Journal pagination | `limit`/`offset` clamped (`H-2` wrap) |
| Decimal scalar | Strings only (`L-6`) |
| Mutation flag | Only `*` / `!` (`L-3`) |
| Remote resource limits | Shared `enforce_resource_limits` + 1 MiB `economic_bean` (`M-4`) |
| Signature receive path | Implemented when signing on (`C-3` partial) |
| Content addressing | SHA-256 of economic canonical form; envelope excluded (I5) |
| Local I1–I3 / I9 | Enforced on GraphQL and remote transactions |
| Domain-separated signatures | `openledger-sig-v1\|txid\|…` / `directiveId` |
| No `unsafe` | Workspace crates |
| Config unknown keys | `deny_unknown_fields`; empty API key rejected when auth on |
| Unsupported Beancount | `include` / `plugin` / `option` hard-fail on parse |
| G-Set idempotency | Duplicate content IDs are no-ops |
| Cycle detection | Present when inserting transactions |
| Docker user | UID 1000 non-root |
| Default HTTP bind in code | `127.0.0.1` |

---

## SPEC gaps (claimed vs implemented)

| SPEC rule | Code |
|-----------|------|
| §3.8 peer admission = bootstrap EndpointIds | Last-hop `delivered_from` (C-4) |
| §3.8.1 verify signature on remote insert when signing on | Implemented; author not bound to mesh (H-14) |
| §3.9 mDNS/convenience discovery dev-only | Production path uses `presets::N0` |
| §3.8 genesis only when zero heads | Remote empty parents always insert (H-6) |
| §3.11 fail boot if P2P key unreadable | **Now implemented** |
| §3.11 fail boot if signing required and key missing | **Now implemented** |
| §3.4.4 orphan buffer on missing parents | **Now used**; drain bug M-14 |
| §3.4.1 ALPN anti-entropy | Stub loop (I-4, R3) |
| §3.12 limits on all writes | Largely shared now (M-4) |
| §2.6 WS + SSE subscriptions | Schema only (I-2, R5) |
| Production: unique topic | Only when HTTP bind is public (H-15) |
| Production: auth on before public bind | Docker auth on, but default key + GraphiQL (H-5) |

---

## Recommended priority

1. **C-4 + H-14 + M-16** — stop applying gossip `Supply`; or require direct scope + author == sender ∈ allowlist + signatures. Drop N0 for production.  
2. **H-8** — allowlist envelope keys; reject controls (cheap, high integrity).  
3. **H-6** — reject remote genesis unless DAG is empty.  
4. **H-5 + H-3 + H-15** — unique Docker API key, GraphiQL off, unique topic whenever P2P is on.  
5. **M-11** — sign before first persist.  
6. **H-2 + M-7** — rate limits, query complexity, journal pagination.  
7. **H-9 / M-13** — private mesh + TLS.  
8. **M-1 / M-2 / M-10 / M-14 / M-15** and remaining low + CI `cargo-audit`.

---

## Appendix A: Dependency notes

| Crate | Notes |
|-------|--------|
| `ciborium 0.2` | Replaces unmaintained `serde_cbor` (M-5 closed) |
| `ed25519-dalek` | Direct: 2.x (OK). Transitive via iroh: 3.x |
| `iroh` / `iroh-gossip 0.101` | N0 preset pulls public relay/discovery; `delivered_from` is last hop |
| `subtle` | Used in `auth.rs` |
| `tower-http` | CORS only; no rate-limit / body features enabled |
| Advisories | This pass did not execute `cargo audit`; add it in CI (L-9) |

---

## Appendix B: Review coverage

| Path | Reviewed |
|------|----------|
| `crates/gl-node/src/**` | Yes (`main`, `auth`, `config`, `health`, `p2p_service`, GraphQL) |
| `crates/ledger/src/**` | Yes (service, parse, serialize, validate, dag, hash, weights, verify, file_watcher, read_model) |
| `crates/p2p/src/**` | Yes (protocol, gossip, union_merge, orphan_buffer, node, topic, anti_entropy, allowlist) |
| `crates/security/src/**` | Yes |
| `deploy/`, `Dockerfile`, `config/`, `gl-node.config.json` | Yes |
| `docs/SPEC.md` security / P2P / limits | Yes |
| iroh-gossip 0.101 `Message` / `DeliveryScope` | Yes (registry source) |
| Integration tests | Skimmed; no adversarial tests for last-hop C-4 / envelope-key H-8 |
| `unsafe` in workspace | None found |
| Third-party crate internals (iroh, async-graphql) | Not source-audited beyond gossip delivery semantics |

---

*End of SECURITY_AUDIT_0819.md.*
