# Security Audit — openledger-v2

**Date:** 2026-09-01
**Scope:** Entire workspace — `gl-node`, `ledger`, `p2p`, `security` crates, plus Docker, docker-compose, CI, configs, scripts, committed fixtures, git history, and `Cargo.lock` dependencies.
**Method:** Full line-by-line source read split across four reviewers (HTTP/GraphQL API surface; P2P/network; ledger engine; crypto + deployment/supply-chain). Every High-severity finding below was independently re-verified against source by a second pass. Library-behavior claims were verified against the vendored registry sources (async-graphql 7.2.1, chrono 0.4.45, ed25519-dalek 2.2.0) rather than assumed. `cargo audit` 0.22.2 was run against the current RustSec advisory DB.
**Baseline:** [docs/audits/CLAUDE_SECURITY_AUDIT_0820.md](CLAUDE_SECURITY_AUDIT_0820.md) (previous audit) and [docs/audits/OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md), which marks all 17 remediation tasks ☑ done. A core goal of this audit was to adversarially verify those fixes, not just re-scan.

> **Update (2026-09-02):** a follow-up verification pass audited commit `e293a4f` (which remediated this report's partial verdicts), found and fixed one bypass in it, and confirmed **every 0820 finding is now closed** — see the [Addendum](#addendum--2026-09-02-verification-pass-0820-closure) at the end of this document. The status table below is the 09-01 snapshot.

---

## Executive summary

The 08/20 remediation round was largely real: **13 of 17 fixes are complete and correct**, including all three prior High-severity integrity issues (signature coverage of the envelope, mandatory signing under P2P, mesh-bound signature domain). The codebase remains unusually well-hardened at the boundaries that were previously reviewed: fail-closed boot validation, constant-time auth, strict allowlisting, size-capped decode, atomic persistence.

However, this audit found **4 new High-severity issues** — none of which is a regression; all are in territory the 08/20 audit did not reach:

1. **H-01** — In the default config (loopback bind, auth off), any website the operator visits can execute GraphQL mutations against the node via CSRF (no preflight fires), and DNS rebinding additionally makes the ledger readable. The default local setup is drive-by writable.
2. **H-02** — The anti-entropy protocol's *senders* violate their own *receivers'* caps. Once a ledger exceeds 4,096 directives — or any node falls more than 256 directives behind — sync deterministically and permanently wedges, mesh-wide, with no attacker required.
3. **H-03** — A malicious allowlisted peer can craft a directive with an elided posting whose content ID shifts on insert, planting state on a victim node that can never replicate: permanent replica divergence plus perpetual re-fetch churn.
4. **H-04** — One authorized GraphQL call with a signed-year date (e.g. `+10000-01-01`) is accepted, persisted, and then can never be re-parsed: the node bricks permanently at next boot.

In addition, **3 of the 17 remediations are incomplete in ways that matter** (Lamport bound check promised but absent → permanent clock poisoning by one peer; GraphQL complexity weights missing exactly where the prior attack still works; orphan buffer still allows ~1 GiB per malicious peer), and the P2P layer has a cluster of new Medium-severity availability issues (no I/O timeouts, serial sync loop, announce-flood spawning, un-gated gossip membership).

**Fix-first list:** H-02 (the mesh wedges itself organically — a ship-blocker independent of attackers), then H-01, H-04, H-03, then M-01 (Lamport bound) and M-02/M-03 (GraphQL weights + mutation batching).

---

## Threat model

Same three attacker classes as the prior audit, plus one it underweighted:

1. **Remote API caller** — anyone who can reach `POST /graphql`. Public binds now hard-require auth + TLS termination (fixed), but the *default* loopback deployment trusts the operator's browser, which H-01 shows is not a safe proxy for trusting the operator.
2. **Malicious or compromised allowlisted peer** — the interesting P2P class. Anonymous hosts still cost only a QUIC handshake (allowlist checked before any stream read). A single compromised replica should not be able to forge history (holds — signature fixes are sound), but it **can** still: pin every node's Lamport clock forever (M-01), plant divergent unservable state (H-03), close any account mesh-wide (M-09), pin ~1 GiB of orphan heap (M-05), and stall all replication (M-06/M-07).
3. **Supply chain** — CI is SHA-pinned (fixed); Docker base images and the build remain tag-mutable/unlocked (L-10).
4. **The protocol itself** — H-02 is not an attacker at all: the sync protocol violates its own limits at organic scale.

---

## 1. Status of the 2026-08-20 remediations

| 0820 finding | Task | Verdict | Evidence / residual |
|---|---|---|---|
| H1 — Decimal overflow panics | T1 | **Fixed** (reachable paths) | `checked_mul`/`checked_add` in [weights.rs:57-134](../../crates/ledger/src/weights.rs#L57-L134); saturating aggregation across `read_model.rs`. Latent: one bare `Decimal` subtraction survives in dead code, [checkpoint.rs:75](../../crates/ledger/src/checkpoint.rs#L75) — becomes High the day checkpoints are wired (see M-08). |
| H2 — Signature doesn't cover envelope | T4 | **Fixed** | Domain is now `openledger-sig-v3` covering kind, content id, parents, lamport, mesh id ([signing.rs:15,91-103](../../crates/security/src/signing.rs#L91-L103)); verify side reconstructs from stored envelope ([union_merge.rs:212-250](../../crates/p2p/src/union_merge.rs#L212-L250)); tamper tests present. v1/v2 implicitly rejected (no code path builds an old prefix). Hardening gap: `\|`-concatenation is not injective for adversarial values — see L-06. Doc rot: [signing.rs:17](../../crates/security/src/signing.rs#L17) and OUTSTANDING_TASKS.md still say "v2". |
| H3 — Author spoofable, signing off | T3 | **Fixed** | Boot refuses `p2p.enabled && !signing.enabled` ([config.rs:303-307](../../crates/gl-node/src/config.rs#L303-L307)); no env/reload bypass; missing signature is a rejection, not a skip ([union_merge.rs:212-250](../../crates/p2p/src/union_merge.rs#L212-L250)); orphans re-verified on drain ([anti_entropy_alpn.rs:316-324](../../crates/gl-node/src/anti_entropy_alpn.rs#L316-L324)). |
| M1 — GraphQL alias amplification | T7 | **Partial** | The five named resolvers now carry `complexity = 512` ([query.rs:20-219](../../crates/gl-node/src/graphql/query.rs#L20)) and the weight mechanism is effective (verified in async-graphql 7.2.1 source). But `account(name, at:)` — a full-ledger scan when `at` is set — got no weight, and **mutations got none at all**. The original attack survives intact through both. See M-02, M-03. |
| M2 — Unauth mutations on public bind | T8 | **Fixed** | Hard boot error ([config.rs:351-355](../../crates/gl-node/src/config.rs#L351-L355)); loopback detection is an exact-string allowlist (default-deny — `0.0.0.0`, `::`, `::ffff:127.0.0.1`, hostnames all treated as public); applies on every config load path. |
| M3 — Lamport overflow | T2 | **Partial** | The clock update saturates ([service.rs:1113](../../crates/ledger/src/service.rs#L1113)) — no panic/wrap. But the task's promised inbound bound check **does not exist**: `validate_supply_entry` checks key presence only. One peer still poisons every clock permanently. See M-01. |
| M4 — Orphan `waiting_on` blowup | T5 | **Fixed** | 32 KiB per envelope value, 256 parents max, closed key set, control chars rejected ([union_merge.rs:19-39,170-204](../../crates/p2p/src/union_merge.rs#L170-L204)); single validated path into the buffer; caps apply to body-embedded parents too. |
| M5 — Recursive DFS stack overflow | T6 | **Fixed** | Iterative explicit-stack DFS ([verify.rs:117-174](../../crates/ledger/src/verify.rs#L117-L174)); tested on a 1,500-deep chain under a 96 KiB stack. No other unbounded recursion found in the crate. |
| M6 — Quadratic DAG insertion | T9 | **Partial** | The `referenced_parent_ids` fast path ([dag.rs:35-39,177-199](../../crates/ledger/src/dag.rs#L177-L199)) is **provably exact** (no false negatives; cycles cannot slip in) and fixes the benign forward-append case. An adversarial `.bean` file can still force the O(N) walk on every insert → ~O(M·N) at boot/reconcile. See L-14. |
| M7 — CI actions on mutable tags | T10 | **Fixed** | All four `uses:` are 40-hex SHAs with tag comments ([ci.yml](/.github/workflows/ci.yml)). Not verified against GitHub (offline) — do a one-time `gh api` check that each SHA matches its claimed tag. |
| L1 — Docker config signing off | — | **Fixed** | `signing.enabled: true` in [deploy/gl-node.docker.json](../../deploy/gl-node.docker.json); regression now impossible anyway (boot rule above). Rest of that config is sound (auth on, key via env with sample value refused, GraphiQL off, relay disabled, non-default topic). |
| L2 — No mesh id in sig domain | T11 | **Fixed** | `mesh\|{mesh_id}` bound in; verifier substitutes its *own* topic (correct design — cross-mesh replay fails closed). |
| L3 — Path leak in GraphQL errors | T12 | **Fixed** | Single choke point maps `ServiceError::Io` → `"internal storage error"` ([mutation.rs:195-205](../../crates/gl-node/src/graphql/mutation.rs#L195-L205)); swept all other variants — only caller-supplied data reaches clients. |
| L4 — API-key length timing | T15 | **Fixed** | SHA-256 both sides, `subtle::ct_eq` on fixed 32-byte digests, no length branch ([auth.rs:62-69](../../crates/gl-node/src/auth.rs#L62-L69)). |
| L5 — Non-injective txid | T14 | **Fixed** | Payee-only emits an explicit empty narration slot ([serialize.rs:133-140](../../crates/ledger/src/serialize.rs#L133-L140)); tested. Two *latent* model-level injectivity holes remain, unreachable today — see L-15. |
| L6 — Temp-file symlink follow | T13 | **Fixed** | `create_new(true)` (O_EXCL) + 0600 + fsync file, rename, fsync dir; symlink pre-plant test passes ([service.rs:62-107](../../crates/ledger/src/service.rs#L62-L107)). |
| L7 — File-watcher missed change | T16 | **Fixed** | SHA-256 content hash authoritative in `detect_change` ([file_watcher.rs:56-111](../../crates/ledger/src/file_watcher.rs#L56-L111)). Nits: uncapped read in the poll loop; delete-then-recreate straddling a tick is never reconciled. |
| T17 — overflow-checks + harness | T17 | **Fixed** | `[profile.release] overflow-checks = true` in workspace [Cargo.toml](../../Cargo.toml); property harnesses exist in `ledger` and `p2p`. Note: covers integers only — `rust_decimal` panics are governed by T1's checked ops, which is why the checkpoint.rs remnant matters. |

**No regressions were found** in anything the 0820 audit listed as sound: allowlist-before-read on inbound ALPN, allowlist-before-decode on gossip, 16 MiB + cardinality caps on CBOR, rate limiter keyed on real TCP peer IP, CORS `"*"` rejection, `ledgerPath` traversal checks, GraphiQL/introspection gating, key-file permission checks, no committed secrets (re-verified across all 52 commits of history).

---

## 2. New findings — High

### H-01 — Drive-by CSRF (write) and DNS rebinding (read+write) against the default local node
**Where:** [main.rs:266-272](../../crates/gl-node/src/main.rs#L266-L272) (routes), [config.rs:60-71](../../crates/gl-node/src/config.rs#L60-L71) (`auth.enabled` defaults `false`), no content-type or Origin/Host validation anywhere in `gl-node` (verified by sweep).

Auth is off by default and the repo's own `gl-node.config.json` ships auth-off with GraphiQL on. async-graphql 7.2.1's body handling (verified in vendored source, `http/mod.rs` `receive_batch_body_no_multipart`) falls through to JSON parsing for **any** non-multipart content type — including `text/plain` and no header at all. Therefore:

```js
fetch("http://127.0.0.1:4000/graphql", {
  method: "POST", mode: "no-cors",
  headers: {"Content-Type": "text/plain"},
  body: '{"query":"mutation{appendTransaction(...){txid}}"}'
})
```

from **any web page** is a CORS *simple request*: no preflight, and the restrictive CORS layer only blocks reading the response — the mutation executes, persists to the operator's financial ledger, and gossips to the mesh. Nothing validates `Host` or `Origin`, so classic DNS rebinding (attacker domain re-resolving to 127.0.0.1) makes the browser same-origin with the node and allows **reading** the full journal as well. The 60/min rate limit is keyed to the victim's own IP and is no obstacle.

**Fix (layered):** reject `POST /graphql` unless `Content-Type` is exactly `application/json`; validate `Host` against the bind address and `Origin` against the CORS allowlist; consider generating and requiring an API key even for loopback binds by default.

### H-02 — Anti-entropy senders violate their own receive caps → deterministic, permanent mesh sync wedge at organic scale
**Where:** send sites [anti_entropy_alpn.rs:84-87, 223-233](../../crates/gl-node/src/anti_entropy_alpn.rs#L84-L87), [anti_entropy.rs:42-52](../../crates/p2p/src/anti_entropy.rs#L42-L52); receive caps [protocol.rs:16-157](../../crates/p2p/src/protocol.rs#L133-L157). Independently re-verified.

Three instances of the same bug — receive-side limits with no send-side chunking:

1. **Supply batches:** a `Want` may carry up to `MAX_WANT_IDS = 1024` ids, and `serve_anti_entropy` answers with **one** `WireMessage::supply(entries)` — but receivers reject any Supply over `MAX_SUPPLY_ENTRIES = 256`. A node more than 256 directives behind can never catch up: its Want elicits a reply its own decoder refuses, the session errors, repeat forever.
2. **Frame size:** `to_wire()` never checks `MAX_MESSAGE_SIZE` (16 MiB) on send; ~17 max-size (1 MiB) entries in one Supply exceed the receive cap → same wedge.
3. **HaveHeads:** `make_have_heads` advertises **all** directive ids, but receivers reject HaveHeads lists over `MAX_HAVE_HEADS = 4096`. **Once any ledger exceeds 4,096 directives, every head exchange it initiates or serves is rejected — anti-entropy dies mesh-wide, permanently.** Gossip announce/fetch partially masks this for online nodes until one restarts or misses an announce.

No attacker is needed; organic growth triggers it. A malicious peer can force it at will (e.g. by Want-ing 257+ ids).

**Fix:** chunk Supply replies to ≤256 entries and ≤16 MiB per frame; paginate or summarize HaveHeads (heads + digest, or windowed exchange). Add a property test asserting every encodable outbound message is decodable under the receive caps.

### H-03 — Elided-posting content-ID shift: a malicious peer plants permanently divergent, un-replicable state
**Where:** [union_merge.rs:110-146](../../crates/p2p/src/union_merge.rs#L110-L146) (entry id checked against hash of *as-sent* body), [service.rs:1117-1126](../../crates/ledger/src/service.rs#L1117-L1126) (insert stores *resolved* postings), [dag.rs:101](../../crates/ledger/src/dag.rs#L101) (id recomputed from stored body). Independently re-verified.

The canonical serializer supports elided postings (account with no amount) and `validate_transaction` fills the elided amount before insert. A crafted SupplyEntry whose `economic_bean` contains an elided posting: (1) passes `validate_supply_entry` — its claimed id X matches the hash of the elided body; (2) passes signature verification against X (the attacker signs with its own allowlisted key); (3) is **stored under a different id Y** = hash(resolved body), with a signature bound to X.

Consequences: when the victim later serves this directive, every other signing-enabled node recomputes Y, finds a signature bound to X, and rejects it. The directive sits in the victim's DAG, balances, and `.bean` file but **can never propagate** — permanent balance divergence between replicas — while nodes missing Y re-`Want` it on every anti-entropy round forever (receive → reject → still missing → re-want). The advertised X is never satisfiable either (dedup checks X, storage is Y), enabling endless re-fetch churn.

**Fix:** on the remote path, reject any entry that parses with `elided_count != 0` (honest senders always ship resolved postings — the local append path stores resolved form), or insert exactly the bytes as parsed with no posting rewrite.

### H-04 — Signed-year dates brick the node through one authorized API call
**Where:** [scalars.rs:12-21](../../crates/gl-node/src/graphql/scalars.rs#L12-L21) (no range check), 11 `%Y-%m-%d` format sites in [serialize.rs](../../crates/ledger/src/serialize.rs), [parse.rs:71-94](../../crates/ledger/src/parse.rs#L71-L94) (`read_date` requires digits only). Independently re-verified; chrono behavior confirmed in vendored 0.4.45 source.

chrono's `%Y` parser accepts explicitly signed years of unlimited digits (`+10000-01-01`, `-0001-01-01`; `NaiveDate` spans ±262142), and its formatter emits a **sign** for any year outside 0..=9999. The ledger's own `read_date` requires the first character to be an ASCII digit. `service.rs` performs no date-range validation on any mutation.

**Attack:** one call — `appendTransaction(input:{date:"+10000-01-01", …})` (or `openAccount`/`closeAccount`) — succeeds and persists. From then on every `LedgerService::boot` fails (`ServiceError::Parse` is all-or-nothing) and every `reconcile_file` fails. The node runs until its next restart, then is **permanently bricked** until someone hand-edits the file. If gossiped first, peers reject the entry (their parser refuses it), so the mesh also silently diverges from the originating node. Reachable by any authorized caller — or by any website via H-01 on default configs.

**Fix:** reject years outside 1..=9999 in `DateScalar::parse`, plus defense-in-depth range validation in `service.rs` on append/open/close/remote/reconcile. Add a serialize→parse round-trip property test over the full `NaiveDate` domain.

---

## 2. New findings — Medium

### M-01 — Lamport clock poisoning: the promised inbound bound was never implemented (completes 0820-M3)
[service.rs:1107-1113](../../crates/ledger/src/service.rs#L1107-L1113), [union_merge.rs:161-163](../../crates/p2p/src/union_merge.rs#L161-L163). One allowlisted peer signs a directive with `openledger-lamport: 18446744073709551615` (valid under its own key). Every merging node pins its clock at `u64::MAX` permanently — the saturating update codifies this — every subsequent local append stamps `u64::MAX`, the value persists to disk and re-adopts at boot, and Lamport ordering degenerates to all-ties mesh-wide, forever. Garbage (non-numeric) lamport strings are also silently accepted and persisted verbatim ([service.rs:1107-1109](../../crates/ledger/src/service.rs#L1107-L1109)). **Fix:** in `validate_supply_envelope`, require strict decimal-u64 and reject values greater than `local_clock + K` (plausibility window).

### M-02 — GraphQL amplification survives through the one heavy resolver that got no weight
[query.rs:193-216](../../crates/gl-node/src/graphql/query.rs#L193-L216). `account(name, at:)` with `at` set calls `balances_at`, which iterates **every transaction and posting** and clones all account balances — then discards all but one entry. Its cost is the default ~2, so ~2,000 aliases fit one 4,096-budget request: 2,000 full-ledger scans under the read lock, ×60 req/min. This is exactly the 0820-M1 attack. **Fix:** weight it 512 when `at` is provided (or index balances by date). Also: `journal`'s flat 512 ignores its `limit` arg — 8 aliased `journal(limit:10000)` still yield ~80k serialized transactions plus a SHA-256 each.

### M-03 — Mutation alias batching: ~2,000 writes per request → storage-exhaustion and permanent write outage
[mutation.rs:21,120,157](../../crates/gl-node/src/graphql/mutation.rs#L21) (no complexity weights). Each `appendTransaction` costs ~2 → ~2,000 sequential mutations per request; each rewrites and fsyncs the **entire** ledger file ([service.rs:806-811](../../crates/ledger/src/service.rs#L806-L811)) and may carry ~2 MiB of payload under the body cap. This quickly drives the file to the 64 MiB `MAX_LEDGER_FILE_BYTES` cap — after which **every write by anyone fails permanently** (no pruning path; see also L-13's cap-after-mutate wedge). Reachable by any authenticated caller, or unauthenticated via H-01 on default configs. **Fix:** weight mutations (≥256), cap mutation fields per request, append incrementally.

### M-04 — Rate limiting degenerates in exactly the deployments the config mandates; IPv6 rotation bypass
[rate_limit.rs:70-75](../../crates/gl-node/src/rate_limit.rs#L70-L75). (a) Public binds *require* `tls.mode:"terminated"` — i.e. a proxy in front — and behind an on-box/L7 proxy every client arrives as one IP: the whole world shares a single 60 req/min bucket (trivial starvation of legitimate users); there is no trusted-proxy `X-Forwarded-For` option. (b) A direct IPv6 attacker rotates addresses within their /64 for unlimited fresh buckets. **Fix:** configurable trusted-proxy support; key IPv6 by /64 prefix.

### M-05 — Orphan buffer still allows ~1 GiB of pinned heap per malicious peer (completes 0820-L8)
[orphan_buffer.rs:16](../../crates/p2p/src/orphan_buffer.rs#L16), [service.rs:38](../../crates/ledger/src/service.rs#L38). Entries are counted, not sized: 1,000 orphans/peer × 1 MiB max bean ≈ 1 GiB per peer (≈10 GiB at the global cap), evictable only after the 1 h TTL, refillable indefinitely. Parent-txid well-formedness is checked only *after* buffering, so orphans waiting on garbage parents that can never arrive sit the full hour. **Fix:** byte-budget the buffer; move `parent_txid_is_well_formed` into `validate_supply_entry`.

### M-06 — No I/O timeouts + serial anti-entropy loop: one hung peer stalls all replication
[anti_entropy_alpn.rs](../../crates/gl-node/src/anti_entropy_alpn.rs) (no `timeout` on connect/read/write anywhere), [p2p_service.rs:250-258](../../crates/gl-node/src/p2p_service.rs#L250-L258) (peers iterated sequentially in one task). A malicious peer that accepts and never responds stalls the entire loop indefinitely — replication with **all** peers stops. **Fix:** `tokio::time::timeout` per session; concurrent per-peer exchanges.

### M-07 — Announce flood spawns unbounded tasks and QUIC connections
[p2p_service.rs:176-182](../../crates/gl-node/src/p2p_service.rs#L176-L182). Every unknown gossip Announce id spawns a fresh task and a **new** QUIC connection (`fetch_want`), with no in-flight dedup, no concurrency cap, no connection reuse — duplicate announces of the same id race in parallel. **Fix:** in-flight id set, bounded semaphore, one reused ALPN connection per peer.

### M-08 — Balance assertions and pads are entirely unenforced; `checkpoint.rs` is dead code
[checkpoint.rs](../../crates/ledger/src/checkpoint.rs) has no production caller (only an integration test). `balance`/`pad` directives from files and peers are persisted via the unvalidated catch-all ([service.rs:1160-1171](../../crates/ledger/src/service.rs#L1160-L1171)) and never evaluated; GraphQL `verify` checks hashes/parents/cycles only. The checkpoint mechanism the file format advertises provides zero protection; an allowlisted peer can seed false, authoritative-looking assertions into everyone's file; beancount `pad` semantics silently differ. **Fix:** wire `evaluate_all_assertions` into `verify` — fixing the unchecked subtraction at [checkpoint.rs:75](../../crates/ledger/src/checkpoint.rs#L75) first (it panics on `MAX - (-MAX)` and would become remotely reachable the moment this code is wired).

### M-09 — Account lifecycle state is arrival-order dependent: replica divergence + one-directive per-account write DoS
[service.rs:1120,1150,926](../../crates/ledger/src/service.rs#L1150), [validate.rs:156-167](../../crates/ledger/src/validate.rs#L156-L167). Remote transactions are validated against the current mutable local `AccountState`; one arriving before its account's `Open` is rejected outright (the orphan buffer retries only on missing *parents*), so nodes with different arrival orders disagree permanently. Remote/reconcile `Close` is applied unconditionally with errors ignored — **one allowlisted peer sending `close` for `Assets:Cash` dated 1970 makes every subsequent local append to that account fail on every replica.** Conflicting opens/closes resolve first/last-arrival-wins per node. **Fix:** derive account state deterministically from the directive set (date-ordered, deterministic merge); buffer account-dependent remote transactions like parent-missing ones; apply the local path's "no later transactions" rule to remote closes.

### M-10 — Economic-hash dedup lets a peer squat authorship of predictable transactions
[serialize.rs:345-348](../../crates/ledger/src/serialize.rs#L345-L348) (content id excludes all `openledger-*` metadata), [service.rs:600-603](../../crates/ledger/src/service.rs#L600-L603). A peer who can predict a victim's exact economic content (recurring rent, salary) pre-publishes it under **its own** author/parents/lamport/signature; the victim's genuine append resolves as `Duplicate` everywhere and the mesh permanently records the attacker's authorship and causal position for the victim's economic event — the GraphQL caller sees success with no duplicate indication. Also collapses *legitimately distinct* identical events (two identical same-day coffees) into one posting. **Fix:** fold the author or a client uniqueness token into the hashed body; at minimum return a distinct "already existed" signal from `appendTransaction`.

### M-11 — Gossip overlay membership is not allowlisted; eclipse silences anti-entropy entirely
[p2p_service.rs:89-93,160-167,245-247](../../crates/gl-node/src/p2p_service.rs#L89-L93). The allowlist filters received messages and registry entries but not overlay membership: anyone knowing the swarm-topic string plus one member's EndpointId can join the topic, receive all Announce metadata (txid/kind/timing leak to strangers), and occupy neighbor slots. Because the anti-entropy loop iterates only the registry — populated exclusively by allowlisted `NeighborUp` events — an eclipsed node has an empty registry and **its anti-entropy loop does nothing**. **Fix:** seed the anti-entropy loop from `bootstrapEndpointIds` as well as live neighbors; treat the topic string as sensitive. (Exact iroh-gossip 0.101 join semantics inferred from API, not source-verified.)

---

## 2. New findings — Low

- **L-01 — Want amplification without ALPN rate limiting.** One ~70 KB Want of 1,024 ids materializes up to 1 GiB of SupplyEntry bodies in a `Vec` under the ledger read lock, then encodes it all again — repeatable in a tight loop on one connection; the HTTP rate limiter does not cover ALPN ([anti_entropy_alpn.rs:228-233](../../crates/gl-node/src/anti_entropy_alpn.rs#L228-L233)). Fix alongside H-02's chunking.
- **L-02 — Local append path skips the 1 MiB directive cap enforced on remote ingest.** Tags/links/account names have charset-only validation with no length cap; a local caller can append a directive whose serialized form exceeds `MAX_ECONOMIC_BEAN_LENGTH`, which every peer then rejects forever — the local head never converges and anti-entropy re-offers it indefinitely ([service.rs:461-560](../../crates/ledger/src/service.rs#L461-L560), [union_merge.rs:111](../../crates/p2p/src/union_merge.rs#L111)).
- **L-03 — docker-compose publishes cleartext GraphQL on all host interfaces** (`ports: "3000:3000"` etc.) with `tls.mode:"terminated"` but no terminator in the stack, and one shared `GL_NODE_API_KEY` across all three nodes — one on-path observation compromises write access to the whole mesh ([deploy/docker-compose.yml:29-79](../../deploy/docker-compose.yml#L29)). Publish as `"127.0.0.1:3000:3000"` and use per-node keys.
- **L-04 — Secret-key file TOCTOU + double read.** `exists()` → `metadata()` (perm check) → `read_to_string()` are three separate path lookups; the file checked is not provably the file read. The key is also read twice per boot (Iroh identity, then signer) — a swap in between yields a node whose author id doesn't match its signing key, making all its directives unverifiable ([p2p_service.rs:264-277](../../crates/gl-node/src/p2p_service.rs#L264-L277), [main.rs:352-360](../../crates/gl-node/src/main.rs#L352-L360)). Open once, `fstat` the handle, read from it, share the bytes. Hex/byte intermediates are not zeroized (the `SigningKey` itself is).
- **L-05 — Key-file permission check is a silent no-op on non-Unix** ([p2p_service.rs:313-316](../../crates/gl-node/src/p2p_service.rs#L313-L316)); at minimum warn.
- **L-06 — Signature message is `|`-concatenation of unvalidated field values.** Two different `(parents, lamport)` tuples can serialize to identical signed bytes when values contain `|`; honest values never do (hex/comma/decimal), so this is not presently forgeable against honest signers — but it becomes a vulnerability the moment any covered field can carry `|`. A malicious author can also sign the same economic content under *different* envelopes for different nodes (equivocation): dedup-by-content-id makes first-delivery-win permanent, so attacker-authored directives can carry divergent causal metadata across replicas ([signing.rs:91-103](../../crates/security/src/signing.rs#L91-L103)). **Fix:** reject non-canonical envelope values before verification (parents `^[0-9a-f]{64}(,[0-9a-f]{64})*$`, lamport decimal-u64 — same check as M-01); length-prefix fields on the next domain bump.
- **L-07 — `verify` instead of `verify_strict`** ([signing.rs:224-226](../../crates/security/src/signing.rs#L224-L226)): admits malleable/torsioned signature encodings other validators may reject; signatures are persisted and could later be compared across implementations. One-line fix.
- **L-08 — Sample-key boot refusal covers exactly one string.** README documents `"my-secret-key-here"`, which boots fine on a public bind ([config.rs:274-278](../../crates/gl-node/src/config.rs#L274-L278), [README.md:376](../../README.md#L376)). Extend the denylist and/or enforce minimum length.
- **L-09 — `/health` on public binds discloses version, head count, and peer count** unauthenticated and unrate-limited ([health.rs:32-41](../../crates/gl-node/src/health.rs#L32-L41)).
- **L-10 — Docker supply chain:** base images by mutable tag (`rust:1.91-slim`, `debian:bookworm-slim`) not digest, and `cargo build --release` without `--locked` ([Dockerfile:2,17,20](../../Dockerfile#L2)). Same issue class the CI pinning fix (T10) addressed.
- **L-11 — Externally-edited directives are adopted unsigned and silently never replicate** in a signing mesh (`reconcile_file` never invokes the signer; peers reject `EnvelopeMissing`) — permanent unreported divergence when `externalFileEdits` is enabled ([service.rs:820+](../../crates/ledger/src/service.rs#L820), [gossip.rs:23-37](../../crates/p2p/src/gossip.rs#L23-L37)). Sign at reconcile, or refuse reconcile when signing is on.
- **L-12 — `reconcile_file` silently destroys valid hand edits:** input is processed in file order (not canonical order like boot), so an appended `open`+transaction written transaction-first rejects the transaction, then the file is immediately re-persisted **without it** — the user's entry is deleted with only a log counter ([service.rs:829,913-948](../../crates/ledger/src/service.rs#L913-L948)).
- **L-13 — Whole-file persist per directive; the 64 MiB cap is enforced *after* the in-memory mutation.** Syncing K directives into an N-directive ledger costs O(K·N) IO with a full fsync each; once serialization crosses the cap, inserts succeed in memory while persist errors — reads serve state that no longer matches disk, and a restart silently drops those directives ([service.rs:44-52,598-610,806-811](../../crates/ledger/src/service.rs#L44-L52)). Check projected size before mutating or roll back on persist failure.
- **L-14 — Adversarial quadratic DAG load at boot/reconcile survives T9** (see status table): a crafted file forces the full ancestor walk per insert, ~O(M·N) CPU on a 64 MB file. Requires file write or booting a hostile file. Cap walk depth or keep a true reachability memo ([dag.rs:177-199](../../crates/ledger/src/dag.rs#L177-L199)).
- **L-15 — Latent serializer injectivity holes:** a posting with `amount: None` but `cost`/`price: Some` serializes identically to a plain elided posting (cost/price silently dropped); `CostSpec { amount: None, date: Some }` serializes as `{}`. Unreachable today (parser grammar and GraphQL can't produce them; elision is resolved before hashing) but one refactor away from being 0820-L5 again ([serialize.rs:175-215](../../crates/ledger/src/serialize.rs#L175-L215)).
- **L-16 — Zero/negative cost and price accepted:** `Assets:Broker 1000000 AAPL {0 USD}` is "balanced" with zero counterweight — unit minting for anyone with append rights; beancount proper warns/rejects these forms ([weights.rs:54-117](../../crates/ledger/src/weights.rs#L54-L117)).
- **L-17 — DAG `children`/`heads` not backfilled for out-of-order inserts:** `heads` can contain non-frontier nodes (extra parent edges on the next append) and cycle verification walks an incomplete children graph; a hand-edited in-file cycle bricks boot (`?` at [service.rs:424](../../crates/ledger/src/service.rs#L424)) — same availability class as H-04 but requiring file write ([dag.rs:149-159](../../crates/ledger/src/dag.rs#L149-L159)).
- **L-18 — `openAccount`/`closeAccount` gossip while holding the ledger write lock** — if the bounded gossip channel is full, mutations block holding the global lock; `appendTransaction` already drops the lock first — make the others match ([mutation.rs:152,183](../../crates/gl-node/src/graphql/mutation.rs#L152)).

### Informational

- Rate limiter is a fixed window (2× burst at boundaries), not sliding as commented; middleware fails open if its extensions are ever missing ([rate_limit.rs:46-80](../../crates/gl-node/src/rate_limit.rs#L46-L80)).
- `AuthState`/`NodeConfig` derive `Debug` including the API key (never printed today — verified); add a redacting impl.
- Subscriptions are **not wired** (no WebSocket route — good); `subscription.rs` uses `data_unchecked` and must go under auth + complexity limits if ever wired.
- No per-request GraphQL execution timeout; a max-budget query holds the read lock for its full duration.
- Local directives authored before signing/P2P was enabled have no signature and silently never replicate (fail-closed; document the migration).
- `relayMode` defaults `"n0"`: with P2P on and defaults, the node registers with public Iroh relays/discovery (presence leak; warning only). The shipped docker config disables it.
- One Ed25519 key serves as both QUIC identity and directive-signing key; the domain prefix mitigates cross-protocol confusion, but a derived subkey would be cleaner.
- Doc rot: [signing.rs:17](../../crates/security/src/signing.rs#L17) and OUTSTANDING_TASKS.md say "v2"; code is v3. `union_merge::extract_parents`/`extract_lamport` are production-dead with subtly different semantics than the used path — remove or align.
- Parser accepts trailing garbage after valid tokens (then reconcile canonicalizes it away — hand-edit typos silently rewritten); canonical sort tie-break (`date, type, narration|payee`) falls back to insertion order, so byte-identical-file determinism (I7) can be violated by tying transactions; trial balance sums across currencies ([read_model.rs:189-201](../../crates/ledger/src/read_model.rs#L189-L201)); file watcher reads the file uncapped every 250 ms and never reconciles a delete-then-recreate straddling a tick.
- CI: add `persist-credentials: false` to checkout; one-time verify the pinned SHAs match their claimed tags. Unused `rand = "0.8"` dep in gl-node; `libssl-dev` in the builder image appears vestigial (rustls stack); duplicate dalek/sha2/rand major versions in the lock (consider converging the security crate on dalek 3 to match iroh).

---

## 3. Dependencies and supply chain

`cargo audit` (advisory DB current as of this audit) on 499 locked crates:

| Crate | Advisory | Assessment |
|---|---|---|
| `h2` 0.4.15 | RUSTSEC-2026-0258 (unbounded empty DATA frames, DoS) — fix ≥0.4.16 | Enters only via `hickory-resolver` inside iroh (DNS-over-HTTPS client); **not** in the axum/hyper server path (verified via `cargo tree -i`). Upgrade opportunistically. |
| `rkyv` 0.7.46 | RUSTSEC-2026-0235 (OOB reads) | Lockfile-only — no path in the resolved dependency graph (`cargo tree -i` empty); not compiled in. |
| `lru` 0.18.1 | RUSTSEC-2026-0253 (unsound: potential UAF on panic in `pop()`) | Live in `iroh-relay`. Low practical risk; track iroh updates. |
| `chacha20` 0.10.1 | yanked | Via `rand` 0.10 in hickory. Cosmetic. |
| `paste` 1.0.15 | unmaintained | Transitive; cosmetic. |

Versions of the security-relevant direct stack are clean by current knowledge: `curve25519-dalek` 4.1.3 (post-RUSTSEC-2024-0344), `ring` 0.17.14, `chrono` 0.4.45, `idna` 1.1.0, `ed25519-dalek` 2.2.0/3.0.0. CI runs `rustsec/audit-check` on every push, which keeps this current.

---

## 4. Checked and found sound

- **Route/auth topology:** exactly three routes (`GET/POST /graphql`, `GET /health`); auth wraps both GraphQL methods; layer order CORS → 2 MiB body limit → rate limit → auth means key brute-force is throttled at 60/min/IP against a constant-time compare. JSON-array batch requests rejected (`UnsupportedBatch`). GET never executes queries (GraphiQL HTML only, loopback-gated). Introspection off unless GraphiQL.
- **Boot fail-closed set:** p2p→signing required; public bind→auth+TLS required; GraphiQL loopback-only; CORS `"*"` and malformed origins rejected; unknown config keys rejected (`deny_unknown_fields`); sample docker key refused; default swarm topic refused under P2P; signing-enabled-with-no-key aborts (never falls back to noop); `ledgerPath` NUL/`..`/cwd-escape rejected.
- **P2P gating order:** connection allowlist (before any stream read) → envelope validation → author allowlist → signature → orphan buffer/insert; orphans re-verify allowlist+signature on drain; gossip is Announce-only (bodies refused on the gossip path) and allowlist-gated before decode; 16 MiB + cardinality caps on all CBOR decode with length pre-checked before allocation; replay is idempotent by content id; envelope of an existing entry cannot be overwritten.
- **Signature scheme:** versioned domain prefix, kind separation (txid vs directiveId, tested), envelope + mesh id covered, author key = verification key (author binding is cryptographic), sign-before-first-persist on all three mutation paths, EndpointId-hex ≡ dalek key-hex pinned by test, deterministic Ed25519 (no nonce risk), CSPRNG-only key generation, test keys `#[cfg(test)]`-gated and unshippable.
- **Ledger invariants:** I1/I2 not bypassable via elision rounding or mixed currencies (exact re-sum from scratch including cost/price weights of the filled posting; no tolerance window; double-elision and cost+price rejected). `.bean` injection closed on all three entry paths (control-char rejection on GraphQL strings; remote text re-parsed by own grammar with hash re-verified; line-oriented parser makes raw newlines unrepresentable; `quote_string` escaping sufficient for the reachable charset — newline-injection tests present). Parser has no recursion, no include machinery (`include`/`option`/`plugin` rejected as unsupported), linear allocations, dates via `NaiveDate`, numbers via `Decimal::from_str`.
- **Persistence:** O_EXCL temp + fsync file + rename + fsync dir + 0600 — a crash leaves the old or new complete file, never a torn one. Boot/reconcile file size capped before read. tokio `RwLock` (no poisoning semantics), no `unsafe` in the ledger crate, remaining panic sites infallible or test-only.
- **Secrets:** no committed secrets in tree or across all git history (patterns + manual pass over historical adds); fixture hex strings are content hashes, not keys; `.gitignore` covers `*.secret`/`.env`; API key never logged (grepped); key files created 0600 and refused when group/other-readable (Unix).
- **CI:** SHA-pinned actions, least-privilege token (`contents: read`), `pull_request` not `pull_request_target`, `--locked` in CI builds, continuous `cargo audit`.

---

## 5. Prioritized remediation plan

| # | Finding | Why this order | Effort |
|---|---|---|---|
| 1 | **H-02** sender-side protocol caps | Mesh wedges itself at ~4k directives with no attacker; ship-blocker | S–M |
| 2 | **H-01** CSRF/rebinding on default config | Default local install is drive-by writable today | S |
| 3 | **H-04** date range validation | One API call bricks a node permanently; trivial fix | S |
| 4 | **H-03** reject elided postings on remote path | One peer plants permanent divergence | S |
| 5 | **M-01 + L-06** strict envelope canonicalization (lamport bound + parents/lamport syntax) before signature verify | Closes clock poisoning and the encoding-ambiguity class in one validator | S |
| 6 | **M-02, M-03** complexity weights on `account(at:)` + mutations; per-request mutation cap | Finishes 0820-M1 for real; blocks the write-outage path | S |
| 7 | **M-09** deterministic account lifecycle; guard remote closes | One-directive write-DoS within the trusted set; divergence | M |
| 8 | **M-05, M-06, M-07, L-01** P2P resource hardening (byte budgets, timeouts, concurrency caps, in-flight dedup) | One compromised replica must not stall or OOM the mesh | M |
| 9 | **M-08** wire checkpoint evaluation (fix `checkpoint.rs:75` first) | Advertised integrity feature currently does nothing | M |
| 10 | **M-04, M-10, M-11** + Lows/Info | As scheduled hardening | M |

Suggested regression tests to add with the fixes: an outbound-message-decodes-under-receive-caps property test (H-02); a serialize→parse date round-trip property over the `NaiveDate` domain (H-04); a `text/plain` POST rejection test (H-01); an elided-posting SupplyEntry rejection test (H-03); a `u64::MAX` and non-numeric lamport rejection test (M-01).

---

## Addendum — 2026-09-02 verification pass (0820 closure)

A dedicated re-audit verified every 0820 finding against current HEAD, including adversarial review of commit `e293a4f` (2026-09-02), which remediated the partial verdicts above. Method: line-by-line review of the remediation diff, direct source verification of each 0820 finding, full test run (400 tests green across all four crates), fmt + clippy clean.

### Commit `e293a4f` verification

The commit correctly closed three of this report's partial verdicts:

- **0820-M1 / M-02, M-03 — closed.** `account(name, at:)` now carries `HEAVY_RESOLVER_COMPLEXITY` (512) when `at` is set — the full-ledger-replay form — while keeping plain lookups cheap ([query.rs:191-193](../../crates/gl-node/src/graphql/query.rs#L191-L193)); all three mutations are weighted 512, capping alias batching at 8/request ([mutation.rs:23,125,166](../../crates/gl-node/src/graphql/mutation.rs#L23)). Regression tests cover mutation batching, `account(at:)` aliasing, and the cheap-path allowance ([graphql/mod.rs:153-218](../../crates/gl-node/src/graphql/mod.rs#L153-L218)).
- **0820-L8 / M-05 — closed.** The orphan buffer is byte-budgeted (64 MiB global, 16 MiB per peer) on top of entry counts, with correct accounting on insert, resolve, evict, and remove ([orphan_buffer.rs:18-26,105-124,210-231](../../crates/p2p/src/orphan_buffer.rs#L18-L26)); parent txids must be well-formed 64-hex *before* buffering, so garbage-parent orphans no longer squat the TTL.
- **0820-M3 / M-01 — closed with one bypass, found and fixed in this pass.** The commit added strict inbound Lamport validation (decimal-u64 only, capped at 2^53) — but only inside the `Directive::Transaction` branch of `validate_supply_entry`, while the clock-adoption site ([service.rs:1095-1114](../../crates/ledger/src/service.rs#L1095-L1114)) reads `openledger-lamport` from **every** directive kind. A malicious allowlisted peer could still pin every replica's clock at `u64::MAX` with one validly-signed `open`/`note`/`price` directive. **Fixed:** the strict parents + Lamport checks now run on the merged metadata of every directive kind ([union_merge.rs:167-233](../../crates/p2p/src/union_merge.rs#L167-L233)), with regression tests for the non-transaction paths. Side benefit: because these checks run *before* signature verification, the values entering the `|`-delimited signed message are now guaranteed canonical (64-hex CSV / decimal), substantially closing L-06's encoding-ambiguity concern for the remote path.
- Also in the commit: the `signing.rs` v2→v3 doc rot fixed; the rest is formatting churn (no functional change to `dag.rs` or `service.rs`).

### Fixed in this pass

- The non-transaction Lamport/parents bypass above ([union_merge.rs](../../crates/p2p/src/union_merge.rs)).
- The last bare `Decimal` op from 0820-H1's sweep: `checkpoint.rs:75`'s unchecked subtraction is now `checked_sub` (no pad synthesized on overflow instead of a panic) — closing H1 to the letter before checkpoint evaluation ever gets wired in (M-08) ([checkpoint.rs:74-79](../../crates/ledger/src/checkpoint.rs#L74-L79)).

### Final 0820 scorecard — all 18 items closed

| 0820 finding | Final status |
|---|---|
| H1 decimal panics | **Closed** — checked/saturating ops on every path; last latent op fixed this pass |
| H2 envelope not signed | **Closed** — sig-v3 covers parents+lamport+mesh; inputs now canonicalized pre-verify |
| H3 author spoofable | **Closed** — boot refuses P2P without signing; no bypass |
| M1 GraphQL amplification | **Closed** — all heavy resolvers + mutations weighted; tested |
| M2 unauth public bind | **Closed** — hard boot error, default-deny loopback detection |
| M3 lamport overflow | **Closed** — saturating clock + strict inbound bound on all directive kinds |
| M4 orphan `waiting_on` blowup | **Closed** — 32 KiB value / 256 parent caps on the single buffered path |
| M5 recursive DFS | **Closed** — iterative; no other unbounded recursion in the crate |
| M6 quadratic DAG insert | **Closed as specified** — long chains hit the exact-memo fast path. The offline-precomputed forward-reference variant (needs local file write) remains tracked as 0901 L-14 |
| M7 unpinned CI actions | **Closed** — 40-hex SHAs (one-time online SHA↔tag verification still recommended) |
| L1 docker signing off | **Closed** — enabled in config and boot-enforced |
| L2 no mesh id in domain | **Closed** — verifier-side mesh binding |
| L3 path leak | **Closed** — single masking choke point; all variants swept |
| L4 key-length timing | **Closed** — fixed-length digest compare via `subtle` |
| L5 txid injectivity | **Closed** — explicit empty slot; latent model-level holes tracked as 0901 L-15 |
| L6 temp-file symlink | **Closed** — `create_new` + fail-closed retry; tested |
| L7 watcher missed change | **Closed** — content hash authoritative |
| L8 orphan memory pinning | **Closed** — byte budgets + pre-buffer parent validation |

The 0820 audit's "checked and found sound" list was also re-verified: no regressions.

**Everything from the 0820 report is now addressed.** What remains open is exclusively this (0901) report's own new findings — H-01…H-04 and the Medium/Low items above — none of which were in the 0820 scope.
