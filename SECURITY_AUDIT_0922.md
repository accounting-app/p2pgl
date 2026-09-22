# Security Audit — openledger-v2

**Date:** 2026-09-22 · **Baseline:** HEAD `9f62435` (branch `main`, clean tree) · **Previous:** [SECURITY_AUDIT_0902.md](SECURITY_AUDIT_0902.md)

Scope: re-verification of **every** entry in the 09/02 consolidated register (§7 there) against
source at HEAD, plus fresh per-domain hunts over the ~28,000 lines that landed since. Method as
established: eight parallel passes (four re-verification, four fresh-hunt), library semantics
checked against vendored sources under `~/.cargo/registry`, `cargo audit` run, CI pins re-checked
online, and a per-task Change/Files/Verify backlog at the end.

This is the **Step-6 re-audit** that [docs/FORMAT_V2_DESIGN.md](docs/FORMAT_V2_DESIGN.md) recommends
before T45 wave C, so that Format v2 lands against a clean register.

---

## Executive summary

The remediation campaign worked. Of the 52 register entries carried into this audit, **42 are
fully closed** and verified closed by mechanism, not by tracker claim — five of the six Highs
(H-01 is partially closed), ten of fourteen Mediums, and 27 of the 31 Lows. Several fixes are better
than the backlog asked for (H-06's next-hop filter, T36's `fchmod`-not-chmod key writer, T29's
order-insensitive lifecycle model, T44's append-only commit path).

**But the fixes are now the least-audited code in the repo, and that is where this audit's findings
are.** Five new Highs, all in code written by T18–T44, none of them variants of anything previously
reported:

- **H-07** — one directive from an allowlisted peer permanently stops the victim authoring anything
  any peer will accept, survives reboot, and replicates: it poisons every node it reaches. An
  off-by-one between M-01's inbound lamport ceiling and the two `+1`s on either side of it.
- **H-08** — boot's cycle/fan-in *skip* (added to avoid bricking boot) combines with the unconditional
  startup compaction to **permanently delete** the skipped transactions from disk. One edited
  metadata line erases a whole transaction chain, with no content-id or signature change to betray it.
  Proven by execution: six appended transactions, zero left on disk after reboot.
- **H-09** — T43's `Supply` pre-scan returns at the first `entries` key and never walks the rest of
  the map, so a sibling key carries an unbounded array straight into serde's `Content` buffer.
  Measured: **805 MB peak for a 16 MB frame**, decoding *successfully* as an empty `Supply` — no
  error, no log.
- **H-10** — the `HaveHeads` `more`-page loop has no page, byte or time bound, and T41's dedup fix
  removed the only one it had. ~40 bytes per frame from one allowlisted peer kills **all**
  anti-entropy with **all** peers, permanently, for the process lifetime.
- **H-11** — `commit_in_flight` is set before an `await` and cleared only after it, with no `Drop`
  guard. Cancel a mutation in that window — the node's own 408 timeout will do it — and **every**
  ledger write path is permanently wedged: mutations, peer replication, reconcile, shutdown
  compaction. Reads keep working and `/health` keeps saying `ok`.

Four of these five are **availability-permanent and silent**: the node keeps answering, and nothing
in the logs says the ledger has stopped converging, stopped persisting, or lost records. That is the
through-line of this audit and the reason the backlog below leads with instrumentation as well as
fixes.

Two are regressions of previously-closed findings (H-09 re-opens M-16's amplification; H-10 was
introduced by T41's own dedup fix), which is the strongest argument in this report for the
adversarial-verification step the campaign already uses being applied to *follow-up* tasks too.

Also new since 09/02: a **new dependency advisory** (`rustls` RUSTSEC-2026-0285) and the discovery
that the GraphQL port serves **cleartext h2c**, which makes the `h2` advisory the register had
assessed as unreachable reachable pre-auth (M-22). The CI `cargo audit` job is **currently red**.

Nothing here changes the verdict that the campaign's direction is right. The Tier-1 items below are
small, local fixes — four of the five Highs are bounded by adding a limit that the surrounding code
already assumes exists.

---

## Threat model

Unchanged from 09/01 and [09/02](SECURITY_AUDIT_0902.md) (§Threat model). Actors: (a) a web page in
an operator's browser against a local node, (b) an API-key holder, (c) a **malicious or compromised
allowlisted peer**, (d) a network attacker on a public bind, (e) whoever can write the `.bean` file.
Availability impacts — boot bricking, OOM, wedging the mesh, silent loss of records — count as real
findings in this series, and this audit is dominated by them.

---

## 1. Status of the 09/02 register, re-verified at HEAD `9f62435`

Every entry was re-verified against source. Tracker claims in
[docs/OUTSTANDING_TASKS_09.md](docs/OUTSTANDING_TASKS_09.md) were treated as claims, not evidence:
each fix was confirmed to exist, to be reachable, and to be effective on **every** sibling ingest
path (local API / remote supply / reconcile / boot / orphan drain / gossip).

### 1.1 Closed — verified by mechanism (42)

**Highs — 5 of 6 fully closed:**

| ID | Verdict | Mechanism confirmed at HEAD |
|---|---|---|
| **H-02** | **Closed** | `paginate_have_heads` ([anti_entropy.rs:78-111](crates/p2p/src/anti_entropy.rs#L78-L111)) + `truncate_supply` (:135-150) on both production send sites; `make_have_heads` is now dead code; `to_wire` errors past 16 MiB ([protocol.rs:275-283](crates/p2p/src/protocol.rs#L275-L283)); client re-Want loop measures progress against what the peer actually served. Property tests assert every sender output survives `to_wire`→`decode_checked`. |
| **H-03** | **Closed** | Elision rejected pre-merge ([union_merge.rs:186-195](crates/p2p/src/union_merge.rs#L186-L195)) and again at [service.rs:3065-3076](crates/ledger/src/service.rs#L3065-L3076). Decisive detail: `validate_transaction` mutates postings **only** when `elided_count == 1` ([validate.rs:147-161](crates/ledger/src/validate.rs#L147-L161)), so zero-elision ⇒ stored id == accepted id. Orphan drain re-runs it; reconcile signs over `stored_id`. |
| **H-04** | **Closed** | Scalar clamp ([scalars.rs:31-37](crates/gl-node/src/graphql/scalars.rs#L31-L37)) plus `validate_ledger_date` on append/open/close and `validate_directive_dates` on remote (before the clock move) and reconcile. |
| **H-05** | **Closed** | `RequestBodyLimitLayer` at [main.rs:639](crates/gl-node/src/main.rs#L639). Verified in vendored `tower-http-0.6.11/src/limit/service.rs:47-62` and `axum-0.8.9/src/routing/route.rs:88-105` that the limit is carried into async-graphql's raw stream read — the exact thing `DefaultBodyLimit` failed to do. |
| **H-06** | **Closed (better than asked)** | `validate_body_envelope_keys(&directive, &[])` runs **pre-merge** ([union_merge.rs:196-201](crates/p2p/src/union_merge.rs#L196-L201)), so smuggled allowed-name keys cannot hide; `ENVELOPE_KEYS` single-sourced. The T40 follow-up **already landed**: [gossip.rs:69-88](crates/p2p/src/gossip.rs#L69-L88) filters `extract_envelope` to the closed set, so even a boot-adopted stray key cannot poison the next hop. |

**Mediums — 10 of 14:** M-04 (rightmost-untrusted XFF walk gated on `trusted_proxies`, /64 + v4-mapped keying, doubling-threshold prune — but see M-30), M-07 (`FetchCoordinator`: permit acquired last, in-flight insert undone on failure, RAII drop, 4096-cap TTL cache), M-08 (`verify.rs:158` → `evaluate_all_assertions`, surfaced additively — but see M-23), M-11 (targets = allowlist, pinned by `eclipsed_node_still_syncs_from_bootstrap_peers`), M-12 (closed **as mitigated**: the code no longer claims `delivered_from` authenticates origin, and the amplification it exposed is bounded by M-07's coordinator), M-13 (`TokioTimer` + `header_read_timeout`, outermost `TimeoutLayer`, permit-then-accept, bounded drain — but see M-33), M-14 (dedup before validate, pinned), M-17 (`ledger_lock.rs` sidecar `try_lock` taken in `main` before `boot`; per-peer `ledgerPath`s), M-18 (`Directive::lamport_clock()` scanned across all kinds over canonical ∪ journal; `test-ledger.bean` regenerated), plus M-15's stall (two-phase batch commit + journal + `spawn_blocking`, commit gate taken before the write lock, read guard dropped first — **no lock inversion**).

**Lows — 27 fully closed:** L-03, L-04, L-05, L-07, L-08, L-09, L-10, L-11, L-12, L-13, L-14, L-15, L-16, L-17, L-18 — all confirmed by mechanism, several surviving the T27/T44/T29 rewrites intact. Plus L-19, L-20, L-21, L-22, L-24, L-25, L-26, L-27, L-28, L-30, L-31, L-32 from the 09/02 batch.

Highlights worth recording because they exceeded the backlog: `verify_strict` is genuinely strict
(vendored `ed25519-dalek-2.2.0/src/verifying.rs:370` rejects small-order `R` **and** small-order
author key `A`; `legacy_compatibility` is not enabled and cannot be unified on). The key writer uses
`O_EXCL` + `sync_all` on file **and** parent directory + `fchmod` **on the handle, never by path**
([p2p_service.rs:754-786](crates/gl-node/src/p2p_service.rs#L754-L786)). `cbor_scan`'s header parser
is total and correct over all 256 initial bytes. `accounts.rs`'s `(date, priority, lamport,
content_id)` lifecycle key is genuinely total. There is **no `unsafe` in production code**.

### 1.2 Partially closed — the guard exists but not on every path (7)

| ID | What remains reachable at HEAD |
|---|---|
| **H-01** | Write CSRF and the rebinding *read of ledger data* are closed by `request_guard` ([request_guard.rs:48-126](crates/gl-node/src/request_guard.rs#L48-L126)), wired as the outermost GraphQL layer and pinned by 16 router-level tests. **`/health` is deliberately outside it** ([main.rs:634-637](crates/gl-node/src/main.rs#L634-L637)) and on a loopback bind serves version/head-count/peer-count to any `Host` — a rebinding page still reads it (→ **L-42**). Item (d), the loopback API key, remains deferred by decision. |
| **M-06** | Per-frame connect/IO timeouts and the concurrent `JoinSet` are real and correct. What is missing is a bound on **frames per session** — no session deadline, no client frame budget, no advert page cap, no `open_bi` timeout (→ **H-10**, **M-27**, **M-28**). |
| **M-09** | State is now order-insensitive (`accounts.rs` event model, verified total). **Admission** of a remote `close` is still arrival-order dependent — residual admitted in-source at [service.rs:2843-2858](crates/ledger/src/service.rs#L2843-L2858). Directive-set divergence remains possible; state divergence for a fixed set does not. |
| **M-10** | **Interim only, as tracked.** `AppendOutcome { already_existed }` makes the truth un-droppable at the type level, but the dedup-by-economic-hash primitive is unchanged. The real fix is T45 Facet A. |
| **M-16** | The peek gate, 64 KiB incremental reads and `ConnectionLimiter` are sound. The T43 `Supply` pre-scan is **bypassable** (→ **H-09**), and the limiter bounds connection *count*, not bytes (→ **L-39**). |
| **L-23** | `p2p.meshId` exists, is validated on four axes, and both quasi-credentials are redacted — but it is **opt-in** and no shipped config sets it. The default path still uses `swarmTopic` as the signature domain, with none of that validation (→ **M-31**) and logged in clear (→ **M-32**). |
| **L-29** | Lowercase-hex parent form is required on the wire ([union_merge.rs:256-265](crates/p2p/src/union_merge.rs#L256-L265)) and at `stage_remote_directive`, but **the reconcile and boot file paths have no form check at all** — `parent_txid_is_well_formed` has exactly one production call site (→ **M-20**). |

### 1.3 Still open — the file-ingest sibling path (2)

**L-01** and **L-02** are each half-closed, and both halves that remain live on the same path:

- **L-01** — the advert arm is closed; the **Want arm is not**. `collect_supply`
  ([anti_entropy_alpn.rs:706-718](crates/gl-node/src/anti_entropy_alpn.rs#L706-L718)) materializes
  every requested id under `ledger.read()` — each costing a SHA-256 plus a full canonical
  serialization — and only *then* does `truncate_supply` discard all but 256 / 15 MiB. With
  `MAX_WANT_IDS = 1024` that is ≥4× wasted work per Want (→ **L-33**). The 09/01 report's "1 GiB"
  figure is now wrong: the 64 MiB file cap bounds it.
- **L-02** — closed on the three local API paths and on `stage_remote_directive`; **absent on
  `reconcile_content`**, which never calls `enforce_economic_bean_limit` (→ **M-20**).

---

## 2. New findings — High

### H-07 — Lamport ceiling off-by-one: one directive permanently kills authoring on every node it reaches

**Where:** [union_merge.rs:50,278](crates/p2p/src/union_merge.rs#L278) (`MAX_REMOTE_LAMPORT = 1 << 53`, accepted with `value <= MAX_REMOTE_LAMPORT` — **inclusive**), [service.rs:3115](crates/ledger/src/service.rs#L3115) (adoption: `max(clock, remote).saturating_add(1)`), [service.rs:1856,1873](crates/ledger/src/service.rs#L1856) (`stamp_transaction_envelope` / `stamp_directive_envelope`: `saturating_add(1)`, **no ceiling**), [service.rs:1413-1416](crates/ledger/src/service.rs#L1413-L1416) (boot re-derives the clock as `max_lamport + 1`).

M-01 capped what a node will **accept**. Nothing caps what a node will **stamp**, and there is a `+1` on each side of the accept bound. `grep` confirms no lamport ceiling exists anywhere in the `ledger` crate — the constant lives only in `p2p`, as an inbound check.

**Attack.** An allowlisted peer sends one signed directive with `openledger-lamport: 9007199254740992` (= `1<<53`, which passes the inclusive bound). The victim's clock becomes `2^53 + 1`. Every directive the victim subsequently authors is stamped `> MAX_REMOTE_LAMPORT` and is **rejected by every peer, forever**, with `openledger-lamport must be a decimal u64 ≤ 9007199254740992`.

Four properties make this the most serious finding in this report:

1. **Permanent.** Boot re-derives the clock from the persisted maximum, so a restart does not clear it. There is no operator-facing way to lower it.
2. **Self-propagating.** The poison directive is itself perfectly valid, so it replicates by ordinary anti-entropy and poisons **every node that receives it** — the whole mesh from one message.
3. **Does not require acceptance.** The clock moves at `:3115` *before* `validate_transaction` at `:3121`. A directive that is ultimately rejected still poisons.
4. **Silent.** Local mutations keep returning `200` with a `txid`. Nothing logs that this node's output has stopped being replicable.

**Fix:** clamp at the stamp sites, not only at the accept site — refuse to author (or refuse to boot) above the ceiling, and treat an inbound lamport that would push the local clock past it as invalid rather than adopting it. Make the accept bound exclusive, or reserve headroom. This is the one place where the cap and the arithmetic around it must be reconciled as a single rule. **Regression test:** ingest `MAX_REMOTE_LAMPORT`, then assert a locally-authored directive still passes `validate_envelope`, across a restart.

### H-08 — Boot's cycle/fan-in skip plus the startup compaction permanently deletes the skipped transactions

**Where:** [service.rs:1311](crates/ledger/src/service.rs#L1311) (`cycle_blocked`), [service.rs:1355-1360](crates/ledger/src/service.rs#L1355-L1360) (`continue` past blocked directives), [main.rs:219](crates/gl-node/src/main.rs#L219) (unconditional `ledger_commit::compact` immediately after boot), [service.rs:2052-2056](crates/ledger/src/service.rs#L2052-L2056) (compaction serializes `self.dag.directives()` and rewrites the whole file).

T35 replaced the L-17 boot brick with a **skip**, and the code warns the operator to "repair or remove their `openledger-parents` metadata". The operator never gets the chance. Directives skipped at boot were never inserted into the DAG; the startup compaction rewrites the `.bean` from the DAG alone; `remove_journal` then takes the sidecar. **The records are gone from disk.**

`directives_blocked_by_parent_cycles` ([service.rs:263](crates/ledger/src/service.rs#L263)) is Kahn's algorithm and reports cycle members **plus all descendants**. A normal ledger is one parent chain, so pointing the *oldest* transaction's `openledger-parents` at the *newest* txid leaves nothing with zero in-file parents — **the entire chain is blocked**. Parents are envelope metadata, stripped by `economic_canonical_serialize`, so **no content id changes and no signature breaks**: nothing about the file looks tampered with.

**Proven by execution** — six real transactions appended through the public API, one `openledger-parents` line rewritten:

```
== directives after build: 8 ==
patched one openledger-parents line (envelope only — no content id changes)
== directives after reboot: 2 ==
== transactions left on disk: 0 ==
```

Only the two `open` directives survive. The same mechanism fires for the T41 fan-in skip ([service.rs:1377](crates/ledger/src/service.rs#L1377)) — which hits **pre-T41 files on upgrade**, no attacker at all — and for `dag.insert` refusals ([service.rs:1385](crates/ledger/src/service.rs#L1385)), which since L-14 include `CycleCheckExhausted`.

This is strictly worse than the brick it replaced: a brick is recoverable by editing the file back.

**Fix:** never let a lossy boot reach a rewrite. Carry skipped directives through boot in a quarantine set that compaction re-serializes verbatim, or refuse to compact when `cycle_blocked` (or any skip set) is non-empty and surface it as a fail-closed operator error. **Regression test:** the proof above, asserting the transactions are still on disk after reboot + compaction.

### H-09 — `supply_entry_count`'s early return bypasses the whole T43 pre-scan; ~50× amplification, silent

**Where:** [cbor_scan.rs:560-573](crates/p2p/src/cbor_scan.rs#L560-L573), routed from [protocol.rs:375-378](crates/p2p/src/protocol.rs#L375-L378).

```rust
for _ in 0..pairs {
    if scanner.map_key()? == ENTRIES_KEY {
        return match scanner.head()? { Head::Array(count) => Ok(count), ... };
    }
    scanner.skip_value()?;
}
```

It returns at the **first** `entries` key and never walks the rest of the top-level map. Put
`"entries": []` second and everything after it is invisible to the guard. `scan_bounded_arrays` —
the non-`Supply` arm — has no such hole: it walks all pairs under the visit budget. **The asymmetry
is the bug**: the one variant T26 deliberately admits at 16 MiB is the one whose scan short-circuits.

Verified in vendored `serde-1.0.229/src/private/de.rs:859-886` that `TaggedContentVisitor::visit_map`
buffers **every** pair into `Content`, unknown keys included. ciborium's only guard is a 256-level
*recursion* limit, not cardinality.

**Measured** with a standalone crate reproducing `Scanner`/`supply_entry_count` and the enum verbatim,
plus `decode_memory.rs`'s counting allocator:

```
frame = 16000032 bytes (MAX_MESSAGE_SIZE = 16777216)
T26 peek gate  carries_supply_discriminator = true
T43 pre-scan   supply_entry_count = Ok(0)   (cap 256)
serde decode   peak 805306633 bytes (50.33 x frame); result = Ok(Supply { v: 1, entries: [] })
```

805 MB for a 16 MB frame — the **same 50.33×** that `decode_memory.rs:155-161` records for the
unguarded path. Worse than the original M-16: it **decodes successfully** as an empty `Supply`. No
`BatchTooLarge`, no `FramePrescan`, no warning. One budget unit per frame (100k per connection), 32
concurrent connections per allowlisted peer → ~25 GB of transient heap from a single key.

**Fix:** walk every pair (as `scan_bounded_arrays` does) and bound every array in the frame, not just
the one behind `entries`; reject a `Supply` frame carrying unknown keys at all, since serde will
buffer them regardless. **Regression test:** the `{"type","entries":[],"z":[…]}` shape, asserting
both rejection *and* bounded peak allocation — `decode_memory.rs` currently measures only the two
shapes T43/T43b fixed.

### H-10 — Unbounded `HaveHeads` page loop kills all anti-entropy, permanently, for ~40 bytes

**Where:** [anti_entropy_alpn.rs:624-648](crates/gl-node/src/anti_entropy_alpn.rs#L624-L648) (`read_have_heads_advert`), [p2p_service.rs:435](crates/gl-node/src/p2p_service.rs#L435) (`while set.join_next().await.is_some() {}`).

The loop's only exits are `more == false`, a read error, and the **distinct**-id cap. `absorb_page`
dedups, so an allowlisted peer replying `HaveHeads { head_txids: [], directive_ids: [], more: true }`
— ~40 CBOR bytes, decoding cleanly because both fields are `#[serde(default)]` — never grows the
accumulators and the cap never fires. **Infinite loop.**

This is a **regression introduced by T41's own dedup fix**. Its rustdoc says so outright
([:606-612](crates/gl-node/src/anti_entropy_alpn.rs#L606-L612), and the test at `:2348-2360`: *"A peer
replaying one page 10,000 times advertises ONE id"*). Counting distinct ids removed the only bound
the loop had. `AntiEntropyTimeouts` does not rescue it: `io` is **per-frame** and every frame
refreshes it.

The blast radius is the whole subsystem, not one peer. `run_head_exchange` never returns → that
`JoinSet` task never finishes → the drain loop at `p2p_service.rs:435` never returns →
`interval.tick()` is never reached again. **All anti-entropy with all peers is dead for the process
lifetime** — and anti-entropy is the designated correctness backstop that makes dropped gossip hints
safe (T23). Silent: no error, no log, no health signal.

**Fix:** a session deadline around the whole exchange plus a page counter and a byte budget on the
advert loop; and make the tick drain resilient — `join_next` with a timeout, or abort the `JoinSet`
at the next tick, so one stuck peer cannot stop the scheduler. **Regression test:** a peer that
answers `more: true` with empty pages forever; assert the exchange aborts and that the *next* tick
still syncs a healthy peer.

### H-11 — A cancelled mutation permanently wedges every ledger write path

**Where:** [service.rs:2081](crates/ledger/src/service.rs#L2081) (`commit_in_flight = true`, set synchronously in `prepare`), [ledger_commit.rs:100](crates/gl-node/src/ledger_commit.rs#L100) (`spawn_blocking(...).await`), [service.rs:2145,2182](crates/ledger/src/service.rs#L2145) (the only two clears — `finish_commit` / `recover_failed_commit`, both **after** that await), [service.rs:2017](crates/ledger/src/service.rs#L2017) (`prepare` returns `CommitInFlight`), [ledger_commit.rs:155](crates/gl-node/src/ledger_commit.rs#L155) (`prepare_or_recover` deliberately **re-raises** `CommitInFlight` without recovering).

There is no `Drop` guard anywhere — `grep -rn "impl Drop"` over both files returns nothing. Drop the
caller's future during that await and the flag stays `true` **forever**. The `spawn_blocking` task is
not cancelled, so the write still lands; only the bookkeeping is lost. The `WritePermit` *is*
dropped, so the next writer walks into `prepare()` → `Err(CommitInFlight)` → re-raised, no recovery.

**All four write paths die permanently:** the three GraphQL mutations, the ALPN anti-entropy path
([anti_entropy_alpn.rs:930](crates/gl-node/src/anti_entropy_alpn.rs#L930)) — so **peer replication
stops being persisted** — the file-watcher reconcile, and the shutdown compaction. Reads keep
working and `/health` still returns `{"status":"ok"}`.

Three verified triggers: (1) **the node's own `TimeoutLayer`**, which returns `Poll::Ready(Ok(408))`
and drops `inner` (vendored `tower-http/src/timeout/service.rs:138`) — 30 s default, and
`requestTimeoutSeconds` is legal down to **1 s**; (2) **HTTP/2 `RST_STREAM`**, a precise repeatable
cancel primitive — and per M-22 the port serves cleartext h2c, so this needs no TLS; (3) any panic on
that path (release builds run `overflow-checks = true`).

Note the composition: M-23's quadratic `verify` is exactly the thing that pushes a concurrent
mutation past its timeout.

**Fix:** make the flag RAII — a guard that clears it on drop — or clear it on the cancellation path
explicitly. A wedged flag should also be recoverable rather than terminal. **Regression test:** issue
a mutation, cancel the future mid-commit, assert the next mutation succeeds.

---

## 3. New findings — Medium

### M-19 — `externalFileEdits: "disabled"` does not disable external-edit adoption, and the README says it does
[service.rs:2052](crates/ledger/src/service.rs#L2052) calls `adopt_external_edits()` **unconditionally** on the compaction branch. The only reader of the config value in the whole workspace is [main.rs:373](crates/gl-node/src/main.rs#L373), which gates the *file watcher* alone (`grep` confirms: `config.rs` definition, `main.rs:373`, and tests — nothing else). The compaction branch runs at boot, at shutdown, whenever the stat probe fires — which a hand edit itself causes — and on **every** write while the canonical file is under 64 KiB. [README.md:622](README.md#L622) states the opposite: *"which requires `"externalFileEdits": "enabled"`"*. `"disabled"` is the default and ships in `deploy/gl-node.docker.json`.

In fairness the README elsewhere argues that file-write authority *is* local-API-write authority ("same machine, same file, same trust boundary"), so this is not the privilege escalation it first appears. The defect is **false assurance** — the same class as H-05's misleading comment: an operator who sets the documented opt-out, which is also the default, gets no control whatsoever. Either honour the setting on both paths or delete it and correct the README.

### M-20 — Reconcile and boot apply a weaker check set than the wire and API paths, then **sign** and replicate the result
`reconcile_content` ([service.rs:2479-2704](crates/ledger/src/service.rs#L2479-L2704)) runs dates, envelope keys, control chars and parent fan-in, but **not**:
- `enforce_economic_bean_limit` (the open half of **L-02**) — nothing else bounds body length;
- **any parent-txid form check** — `parent_txid_is_well_formed` ([service.rs:224](crates/ledger/src/service.rs#L224)) has exactly **one** production call site, `:3082` in `stage_remote_directive`. Reconcile (`:2554`) and boot (`:1378`) call only `validate_parent_fan_in`, which is a *count* check ([service.rs:562-573](crates/ledger/src/service.rs#L562-L573)). `LedgerDag::insert` does not check form either. This is **L-29's rule, absent on the file path**;
- **any lamport format or range check** — `:2604-2607` silently ignores an unparseable value, and a file lamport of `u64::MAX` sets the boot clock to `u64::MAX`, destroying the `(author, lamport)` uniqueness T31 restored.

Each yields the same outcome, and it is the one the code itself names at [service.rs:396-399](crates/ledger/src/service.rs#L396-L399): the entry is adopted, **signed with this node's key** (L-11's fix), persisted and served — and then refused by every peer forever at [union_merge.rs:256-265](crates/p2p/src/union_merge.rs#L256-L265), while this node keeps advertising it. Permanent divergence plus perpetual re-Want churn: the H-03/H-06 shape reached through the file. **M-19 makes this reachable in every deployment.** Parents are envelope metadata, so a hand edit changes no content id.

### M-21 — The rate limiter's bucket cap is a sustainable total bypass
[rate_limit.rs:199-214](crates/gl-node/src/rate_limit.rs#L199-L214): at `MAX_BUCKETS` (65,536) a brand-new key is `return true`'d **and never inserted**. The in-code comment reasons only about incidental overflow and concludes "the table drains within one window" — but an attacker can *hold* the table at the cap by touching 65,536 keys once per 60 s window (~1,100 cheap requests/second, each well under the per-bucket limit), and the flood traffic from any further key then **never grows the table**. Stable, not self-limiting. A single routed IPv6 /48 supplies exactly 65,536 /64 keys. Distinct from M-04 (bucket *width*); this is an artifact T34 introduced. Fix: fail closed under a shared overflow budget, or evict expired-soonest rather than admitting free.

### M-22 — The GraphQL port serves cleartext h2c, making the `h2` advisory reachable pre-auth
[http_server.rs:126](crates/gl-node/src/http_server.rs#L126) uses hyper-util's sniffing `auto::Builder` and never restricts it; `:139-143` explicitly configures `.http2()` keep-alives. Verified in vendored `hyper-util-0.1.20/src/server/conn/auto/mod.rs:39,350-358`: the builder matches the `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` preface and serves HTTP/2 **over cleartext**, no TLS or ALPN needed. The `.http2()` call compiling proves the feature is on.

So RUSTSEC-2026-0258's frame decoder is reachable by **any unauthenticated client that can open a TCP connection** to the GraphQL port — below the axum stack, so the API key, Host guard and rate limiter do not gate it. **The register's assessment ("only via hickory/iroh DoH, not the server path") is stale and should be corrected.** This also hands H-11 its cleanest trigger (`RST_STREAM`). Fix: bump `h2` (a lockfile-only move to 0.4.19), and decide deliberately whether h2c should be served at all — `Builder::http1_only()` if not.

### M-23 — T32 made `verify` O(assertions × transactions × postings) under the read lock, with the old flat weight
[verify.rs:155](crates/ledger/src/verify.rs#L155) → [checkpoint.rs:55,152-166](crates/ledger/src/checkpoint.rs#L152-L166) → [read_model.rs:407,437-456](crates/ledger/src/read_model.rs#L437-L456): `account_balance(acct, Some(date))` rebuilds the **entire** balance map over every transaction and every posting — allocating a `String` per account and per currency — then keeps one entry. Once **per `balance` directive**.

Measured (release, perfect quadratic scaling):

```
1000 txns x 1000 assertions -> 171ms
2000 txns x 2000 assertions -> 656ms
4000 txns x 4000 assertions -> 2.61s
```

A `balance` directive is the cheapest thing a peer can plant: `stage_remote_directive` routes it through the `_ =>` catch-all ([service.rs:3163](crates/ledger/src/service.rs#L3163)) with no lifecycle check and no requirement that the account exist. At ~250 bytes each, >100k fit under the file cap; against a 78k-transaction ledger that is ~2×10¹⁰ posting visits — tens of minutes per call. It runs inside `ledger.read().await` ([query.rs:231](crates/gl-node/src/graphql/query.rs#L231)), blocking every writer, inline on a tokio worker, and the 408 drops the *response* but not the work.

This is **not** M-08 re-reported — M-08 was "assertions are never evaluated"; this is the cost of fixing it. Note the mitigation's model broke silently: `HEAVY_RESOLVER_COMPLEXITY = 512` was sized on "scan the ledger once" (its comment says so) against a 4096 budget, so **8 quadratic scans per request** are still allowed. Fix: a batched balances-at-date API (one pass for all assertions), re-weight, and move it off the read lock.

### M-24 — `full_file_serialize`'s tie-break is not total: replicas' `.bean` bytes diverge permanently
`stable_sort_key` ([serialize.rs:68](crates/ledger/src/serialize.rs#L68)) is `narration|payee` for transactions and `account` for opens — it omits postings, amounts and currency lists. `sort_by` is stable, so ties fall back to `LedgerDag::insertion_order`, i.e. **arrival order**. Proven for two "Starbucks/Coffee" transactions with different amounts — ordinary data, no attacker — and for two same-date `open Assets:Cash` with different currency lists. This directly violates the project's own assertion at [service.rs:6348](crates/ledger/src/service.rs#L6348): *"CT-9: After convergence, .bean files must be byte-identical (C4/I7)"*, and it is permanent, because a reboot re-derives insertion order from the file's own order. Fix: append the content id to the key — exactly as `accounts::LifecycleKey` already does.

### M-25 — The parser silently discards trailing tokens on every header and posting line
`at_eol` is called in only two places in all of `parse.rs`. Proven:

```
"2024-01-01 open Assets:Cash USD AND MORE JUNK"  -> "2024-01-01 open Assets:Cash USD"
"2024-01-01 close Assets:Cash 2020-01-01"        -> "2024-01-01 close Assets:Cash"
'* "p" "n" "third string dropped"'               -> '* "p" "n"'
"  Assets:Cash   1 USD this is dropped"          -> no trace of the dropped text
```

The `.bean` is the supported operator-edit interface. A half-finished edit is not rejected or logged — it is re-read as a *different* valid directive, adopted, signed with this node's key, and written back truncated. The rejection log at [service.rs:2695](crates/ledger/src/service.rs#L2695), which exists precisely so an operator "has a way to find out what they lost", never fires. Fix: `at_eol` after every line form.

### M-26 — The advert cap bounds id **count**, not bytes or time
`MAX_ACCUMULATED_HAVE_HEADS` is a count, and **nothing anywhere validates an advertised id's length or format** — unlike `openledger-parents`, which must be 64 lowercase hex. `absorb_page` stores each id twice (`seen.insert(id.clone())` + `into.push(id)`) and `compute_want` clones again. At 255-byte ids that is ~1.7 GB live per peer; pages of one ~1 MiB "id" under the 1 MiB `NON_SUPPLY_FRAME_CAP` cost ~2 MiB resident each, unbounded until ~2 TiB. The anti-entropy loop fans out **one concurrent exchange per allowlisted peer with no global bound** ([p2p_service.rs:424-434](crates/gl-node/src/p2p_service.rs#L424-L434)), so this multiplies. Introduced by T18's pagination: before it there was one bounded frame. Fix: require `^[0-9a-f]{64}$` on every advertised id (it is the same rule already applied to parents) and budget bytes, not just count.

### M-27 — `open_bi()` has no timeout: a second route to H-10's wedge, plus a coordinator permit leak
[anti_entropy_alpn.rs:422,451](crates/gl-node/src/anti_entropy_alpn.rs#L422) are bare. Verified in vendored `noq-1.1.0/src/connection.rs:1007-1046` that `poll_open` pends on `stream_budget_available[Bi]`; a peer advertising `initial_max_streams_bidi = 0` (the default is 100) plus keep-alive pends **forever**. `AntiEntropyTimeouts` covers `connect` and per-frame `io`, not stream opening. The same hang in the gossip task ([p2p_service.rs:313-324](crates/gl-node/src/p2p_service.rs#L313-L324)) never reaches `drop(guard)`, leaking a `FetchCoordinator` permit and in-flight entry — 16 such peers kill announce catch-up.

### M-28 — No client-side session deadline or frame budget
The server enforces `max_requests_per_connection = 100_000`; the client enforces nothing. A peer advertising 1M ids drives 4,096 Want chunks × up to 256 rounds ([anti_entropy_alpn.rs:579-581,658-699](crates/gl-node/src/anti_entropy_alpn.rs#L579-L581)), each bounded only by the refreshing 30 s per-operation timeout — days of held tick drain, with the H-10 consequence that the tick never comes round again. Existing tests only cover a peer that answers nothing at all.

### M-29 — The watcher permanently disables T44's append path and reparses the whole ledger under the write lock on every self-write
`reconcile_content` unconditionally sets `canonical_is_current = false` ([service.rs:2478](crates/ledger/src/service.rs#L2478)), which `prepare` turns into a forced rewrite (`:2027`). The watcher has no self-write suppression ([main.rs:380](crates/gl-node/src/main.rs#L380)), and `reconcile_file_staged` lacks the `last_file_hash` short-circuit that `adopt_external_edits` has — so it re-parses and re-hashes every directive under the **write** lock. That closes a self-sustaining loop. Proven on a 138 KB ledger:

```
commit kind (no watcher)          = Some(Append)   x4
watcher reconcile: new=0 dup=406 rejected=0
commit kind (after watcher tick)  = Some(Compact)  x4
```

On a 64 MiB ledger that is a full serialize + fsync plus a full parse and N SHA-256s per directive written, at up to 4 Hz. Also `FileState::from_path` ([file_watcher.rs:71](crates/ledger/src/file_watcher.rs#L71)) reads the file with **no size cap**, unlike `read_ledger_file`, on a tokio worker every 250 ms. Held to Medium only because `externalFileEdits` defaults to `"disabled"` — but see M-19 for how little that setting does.

### M-30 — `trustedProxies` silently misses a dual-stack peer
`bucket_key` normalizes IPv4-mapped IPv6 ([rate_limit.rs:267](crates/gl-node/src/rate_limit.rs#L267)); `client_ip` does not — `if !self.trusted_proxies.contains(&peer)` (`:135`). `bindAddress: "::"` is explicitly supported, and on Linux an IPv4 proxy then arrives as `::ffff:172.18.0.9`, which never equals `V4(172.18.0.9)`. XFF is discarded and **every client behind the terminator shares one 60/min bucket** — M-04's exact failure, re-created by a type mismatch. Silent in both directions: the M-04 boot warning fires only when the list is *empty*, and the operator instead sees the reassuring "X-Forwarded-For trusted" line. No test covers a v4-mapped peer against a v4 entry.

### M-31 — `swarmTopic` is the signature domain on the default path but gets none of `meshId`'s validation
[config.rs:326-332](crates/gl-node/src/config.rs#L326-L332) falls back to `swarm_topic` when `meshId` is unset — the default, and what `deploy/gl-node.docker.json` ships. `meshId` gets four hard boot checks ([config.rs:736-765](crates/gl-node/src/config.rs#L736-L765): non-empty, no leading/trailing whitespace — *"compared byte-for-byte on both sides of every signature"* — ≤128 bytes, restricted charset). `swarm_topic` gets exactly one, and it is about uniqueness. So on the default path a trailing space silently partitions the mesh and presents as `InvalidSignature`; `""` passes; there is no length cap; and `|` is allowed — which also falsifies the injectivity premise in [docs/FORMAT_V2_DESIGN.md:30-34](docs/FORMAT_V2_DESIGN.md#L30-L34), since `mesh_id` is the one interpolated field that is **not** constrained (see L-06). Fix: apply `meshId`'s validation to whatever resolves as the signature domain.

### M-32 — The swarm topic is logged verbatim at INFO, defeating the T39/T41 redaction
[p2p_service.rs:84-88](crates/gl-node/src/p2p_service.rs#L84-L88) does `info!(topic = %config.swarm_topic, …, "P2P node ready")`. Three other sites deliberately refuse to print it — [config.rs:286-294](crates/gl-node/src/config.rs#L286-L294) (*"the gossip join credential … prints source + length + a 4-character prefix rather than the value"*), `config.rs:312`, [main.rs:279-287](crates/gl-node/src/main.rs#L279-L287) (*"names its shape, never its value"*). The other half of the credential is 20 lines earlier. Impact is bounded — overlay membership yields Announce metadata, not bodies — but when `meshId` is unset this same string is the signature domain (M-31).

### M-33 — No per-IP HTTP connection cap; one client stops the accept loop
`accept_with_permit` takes the permit **before** `accept()` ([http_server.rs:223-233](crates/gl-node/src/http_server.rs#L223-L233)). That ordering is deliberate and correct against a flood, but the cap is **global only** — there is no per-IP analogue of the ALPN side's 32-per-peer limit. Once one client holds all 1024 slots the process stops accepting **at all**, upstream of the Host guard, the limiter and auth. 1024 idle sockets refreshed every 30 s locks out everyone including `/health`, which then fails the Docker `HEALTHCHECK`'s 3 s TCP connect and, via `depends_on: service_healthy`, the peers' startup.

### M-34 — New dependency advisory, and the CI audit job is red
`rustls` 0.23.42 → **RUSTSEC-2026-0285** (published 2026-09-14, after the last audit): "TLS 1.3 handshake messages incorrectly accepted across encryption level boundaries", CVSS 5.3. `cargo tree -i rustls -e normal` puts it **directly under `iroh v1.0.3`** and its `noq` QUIC layer — it is the TLS 1.3 under the node's own peer transport, not a DoH side-path. The advisory's own impact is genuinely limited (the transcript stays authenticated, so a handshake cannot be altered or completed by a network attacker). The Medium is for the operational consequence: [.github/workflows/ci.yml:40-53](.github/workflows/ci.yml#L40-L53) runs `rustsec/audit-check` with no `continue-on-error`, and `cargo audit` now exits `error: 3 vulnerabilities found!` — **CI is failing**, which is how future advisories get ignored. See §6 for the four one-line lockfile bumps that clear it.

---

## 4. New findings — Low

- **L-33 — `collect_supply` trims at the wrong end.** [anti_entropy_alpn.rs:706-718](crates/gl-node/src/anti_entropy_alpn.rs#L706-L718) serializes and hashes *every* matched directive for a Want of up to 1,024 ids (bounded by the 64 MiB file cap) under the ledger read lock, then `truncate_supply` discards all but 15 MiB. A ~68 KiB request frame costs up to ~64 MiB of allocation; 32 connections per peer sustain it concurrently. Budget while collecting. (This is L-01's open Want arm.)
- **L-34 — No refusal cache on the anti-entropy path.** `compute_want` just diffs, so any permanently-rejected directive — the M-09 backdated-close residual, anything in the M-20 class — is re-Wanted, re-transferred and re-validated **every tick forever**, and its orphans churn on the 1 h TTL.
- **L-35 — T27's incremental id index was never built.** `all_directive_ids()` ([service.rs:2971-2977](crates/ledger/src/service.rs#L2971-L2977)) is still a full O(N) `String` clone, called twice per peer per tick plus once per inbound advert; compaction still does a blocking whole-file read and O(N) serialize under the write lock.
- **L-36 — `client_ip` parses every XFF entry with no count cap** ([rate_limit.rs:140-155](crates/gl-node/src/rate_limit.rs#L140-L155)).
- **L-37 — The empty-`trustedProxies` warning fires only when `tls.mode == "terminated"`** ([main.rs:484-489](crates/gl-node/src/main.rs#L484-L489)); a node behind an ingress with the default `"disabled"` gets no warning and silently keeps one global bucket.
- **L-38 — `fetch_coordinator` panics on mutex poisoning.** `.expect()` at [fetch_coordinator.rs:149,158,177,222,230](crates/gl-node/src/fetch_coordinator.rs#L149) inside the gossip-loop task; everywhere else in the tree uses `unwrap_or_else(|p| p.into_inner())`.
- **L-39 — `ConnectionLimiter` bounds count, not bytes:** 256 connections × up to 16 MiB of in-flight frame body ≈ 4–8 GiB of legitimately-shaped buffers.
- **L-40 — A dangling `openledger-parents` naming a predictable future txid blocks that exact transaction.** Proven: the append is refused with `CYCLE_DETECTED` naming the victim's own new txid. The wire path is *not* exposed (`require_parents: true` routes to the orphan buffer — verified); reachable via hand edit and `reconcile_content`, and cleared by appending any other transaction first.
- **L-41 — Journal header length overflows instead of failing closed.** [journal.rs:246](crates/ledger/src/journal.rs#L246) parses an unbounded `usize`; `:214` does `cursor + payload_length`. Proven panic (`attempt to add with overflow`; `overflow-checks = true` in release too) against a module whose stated policy is `JournalError::Corrupt`. `read_journal` is the body of `recover_failed_commit`, so the panic can land in a live node holding the write lock.
- **L-42 — `/health` is outside the Host guard and the rate limiter.** [main.rs:634-640](crates/gl-node/src/main.rs#L634-L640) applies `request_guard` and `graphql_rate_limit` to `graphql_routes` only, and L-09's gate keys on `public_bind` — so a **loopback** node answers any `Host` with full detail. H-01's DNS-rebinding read, closed for `/graphql` by T19, is still open here. Also an unauthenticated, unmetered `ledger.read()` per request.
- **L-43 — The L-13 recovery path re-introduces a blocking whole-file rebuild under the write lock.** [ledger_commit.rs:108,115,157](crates/gl-node/src/ledger_commit.rs#L108) call `recover_failed_commit`, which runs `LedgerService::boot` synchronously ([service.rs:2184](crates/ledger/src/service.rs#L2184)) — up to 64 MiB read + parse + per-directive DAG insert + `ReadModel::build`, on a runtime worker with the **write** guard held. Exactly the stall `ledger_commit.rs:1-14` says T44 removed, repeated per failed commit.
- **L-44 — `persist_atomically` chmods the ledger by path after the rename.** [service.rs:174-182](crates/ledger/src/service.rs#L174-L182) uses `std::fs::metadata` + `set_permissions` (both symlink-following) post-rename, so a directory-writable attacker can have an arbitrary target chmod'd 0600 by the node — possibly root in the shipped container. Every other T36 site avoids precisely this; the key writer's own comment reads *"restore 0600 through the handle (`fchmod`), never by path"*. Set the mode on the temp file's handle before the rename.
- **L-45 — T37's charset tightening bricks boot on a pre-existing ledger.** Pre-T37 both parser and `validate_account_name` accepted Unicode alphanumerics, so `Assets:Cаsh` (Cyrillic а) was storable **and replicable**. At HEAD `parse_file` rejects it and boot propagates hard ([service.rs:1290-1294](crates/ledger/src/service.rs#L1290-L1294) → `main.rs` `exit(1)`). Any deployment that booked — or merely *received* — such a name cannot start after upgrade, with no targeted error. Same class as L-28/H-04, and it contradicts the tolerant-boot rule the same task family applied elsewhere. Fix is skip-and-warn at boot ingress, not loosening the charset.
- **L-46 — CI's `--locked` guarantee is defeated.** [ci.yml:36](.github/workflows/ci.yml#L36) runs `cargo clippy` *without* `--locked` before `:38`'s `cargo test --workspace --locked`. Clippy runs the resolver and regenerates `Cargo.lock`, so by the Test step it is consistent and `--locked` passes — defeating exactly the unreviewed-dependency-bump scenario the `Dockerfile:39` comment says the flag exists to catch.
- **L-47 — `README.md:13` says "Rust 1.87+"; `Cargo.toml:13` is `rust-version = "1.91"`.** Quick Start's `cargo build --release` hard-fails for anyone on 1.87–1.90.
- **L-48 — `p2p.relayMode` defaults to `"n0"` and appears nowhere in the README** ([config.rs:505-507](crates/gl-node/src/config.rs#L505-L507)) — absent from the block labelled "Full Config (All Options)" and from the options table. There is a boot `warn!`, which is why this is Low.
- **L-49 — The key-file check verifies mode but not owner, and the read path follows symlinks.** [p2p_service.rs:712-727](crates/gl-node/src/p2p_service.rs#L712-L727) checks `mode & 0o077` via `fstat` (correct — that is L-04) but never compares `st_uid` to `geteuid()`; `:615` uses plain `File::open` with no `O_NOFOLLOW`. The *write* path is hardened with `O_EXCL` against exactly this. Since one key is both QUIC identity and signing key, adopting a pre-planted 0600 key is full node impersonation.
- **L-50 — `auth.apiKey` is not validated for header-safety** while `allowedHosts` and `cors.allowedOrigins` are. [auth.rs:73](crates/gl-node/src/auth.rs#L73) gates on `HeaderValue::to_str().ok()`; [config.rs:701,724](crates/gl-node/src/config.rs#L701) already do `HeaderValue::from_str(...).is_err()` for the neighbouring fields. A non-ASCII key boots and then 401s everything forever with no signal.
- **L-51 — `origin_allowed` is scheme-blind.** [request_guard.rs:153-166](crates/gl-node/src/request_guard.rs#L153-L166) strips the scheme and compares host+port only, so behind the mandated TLS terminator a plaintext `http://<node-host>` page is treated as same-origin.
- **L-52 — `Origin: null` is accepted if configured**, contradicting the guard's own doc comment ("deliberately rejected"): `allowed_origins.contains(origin)` is checked first and config validation accepts the literal `"null"`. Any sandboxed iframe, `data:` or `file:` document then qualifies, and `cors_layer()` echoes `Access-Control-Allow-Origin: null`.
- **L-53 — `Announce.id` is unvalidated and used as a negative-cache key** (bounded to ~16 MB by iroh-gossip's 4096-byte frame default).
- **L-54 — `drain_orphans` re-runs an O(n) TTL sweep per re-buffer** under both write locks.

## 5. New informational

- **Test suite is green: 830 passed, 0 failed, 0 ignored** across the workspace on a quiet machine. **Correction to a first reading:** an initial run showed 4 failures (all T42 connection-pooling tests) — that run was made while eight audit agents loaded the machine, and the same suite passes in 14.4 s versus 168.3 s under load. The failures were a measurement artifact, not a defect. The residual observation is real though: these are wall-clock deadline tests, `NET_TEST_LOCK` serializes them only *within* the `gl-node` binary and nothing protects them from external load — so the replication regression signal degrades exactly when CI is busy. T18's `#[ignore]`d `two_node_catchup_beyond_have_heads_cap` is now running (0 ignored).
- **`OPTIONS` is a landmine.** tower-http short-circuits **every** `OPTIONS` with no `Access-Control-Request-Method` check (vendored `cors/mod.rs:678`) and it is the outermost layer, so OPTIONS never reaches the guard, limiter or auth; `auth.rs:88` waves it through independently. Harmless today (nothing routes OPTIONS). Unknown paths and `/health` sit outside the rate limiter entirely.
- An oversized **chunked** body returns 400 rather than 413 (RAM still bounded); only the `Content-Length` path is tested.
- **An unpinned cross-crate coupling.** `truncate_supply` emits an *empty* Supply for any entry over 15 MiB (pinned as intentional at `anti_entropy.rs:434-439`), which the client reads as `stalled` and abandons — permanent silent divergence. Unreachable today **only** because `MAX_ECONOMIC_BEAN_LENGTH` (1 MiB) is far below `SUPPLY_FRAME_BUDGET_BYTES` (15 MiB). Nothing documents or tests that dependency and the constants live in different crates — a Format-v2 bean-cap raise would silently re-create an H-03-class divergence.
- **Two Ed25519 stacks on one key:** `security` pins dalek 2.2.0 while iroh pulls 3.0.0; both curve25519-dalek 4.1.3 and 5.0.0 are built.
- `ledger_lock` keys on the **path spelling**, so a symlink or hard-link alias still gives two nodes one ledger — M-17's guarantee is nominal against a determined misconfiguration.
- `bootstrapEndpointIds` is not filtered against the node's own id, so the natural shared-config deployment **self-dials every tick** (one `SelfConnect` error per tick).
- `validate_body_names` re-checks accounts/tags/links for direct `stage_remote_directive` callers but **not currencies**, whose failure mode is worse — a spaced currency re-parses to a different content id via M-25.
- The I8 budget verdict depends on `HashSet` seed order (harmless once H-08 is fixed).
- Local writes never drain the orphan buffer (self-heals via re-Want).
- **A register informational is now fixed:** `GL_NODE_API_KEY` no longer loses to a stale file value — [config.rs:588-609](crates/gl-node/src/config.rs#L588-L609) gives the environment precedence with a warning, and README:524 / `.env.example:35-37` describe it correctly.
- README drift: `SPEC.md` does not exist; `gl-node.config.json` is tracked with `graphiql: true` while README:53 says off by default; the `docker run` example's `-v $(pwd)/data:/data` creates a root-owned directory that uid-1000 cannot write.

---

## 6. Dependencies, supply chain, and verification runs

**`cargo audit`** (v0.22.2, DB refreshed, 1,261 advisories, 499 locked crates) — **six hits, one new**:

| Crate | Advisory | Status vs 09/02 |
|---|---|---|
| `rustls` 0.23.42 | RUSTSEC-2026-0285 (CVSS 5.3) | **NEW** (published 09-14). Directly under `iroh`/`noq` — the QUIC transport's TLS 1.3. See M-34. |
| `h2` 0.4.15 | RUSTSEC-2026-0258 | **Assessment corrected** — reachable pre-auth via cleartext h2c on the GraphQL port, not only via DoH. See M-22. |
| `rkyv` 0.7.46 | RUSTSEC-2026-0235 | Confirmed lockfile-only: `cargo tree -i rkyv -e all --target all` prints *"nothing to print"*. |
| `lru` 0.18.1 | RUSTSEC-2026-0253 (unsound) | Confirmed live under `iroh-relay`. |
| `paste` 1.0.15 | RUSTSEC-2024-0436 (unmaintained) | Build-time proc-macro only, via `netdev`'s android-extra feature. |
| `chacha20` 0.10.1 | yanked | Reached via `rand 0.10.2` — i.e. it is the RNG behind `SecretKey::generate()`, the identity-keygen path. |

**All four actionable ones are semver-compatible lockfile bumps — no dependency upgrade, no code change.** Verified by `cargo update --dry-run` (lockfile confirmed unmodified afterwards):

```
chacha20 0.10.1 -> 0.10.2 · h2 0.4.15 -> 0.4.19 · lru 0.18.1 -> 0.18.4
rustls 0.23.42 -> 0.23.45 · rustls-webpki 0.103.13 -> 0.103.15
```

**CI action pins re-verified online** (`git ls-remote`; `gh` is not installed on this machine): `actions/checkout` `11d5960…` = `refs/tags/v4.4.0` ✔ · `Swatinem/rust-cache` `6323deb…` = `v2.9.2^{}` ✔ · `rustsec/audit-check` `69366f3…` = `refs/tags/v2.0.0` ✔ · `dtolnay/rust-toolchain` `4360b52…` no longer equals `refs/heads/stable` — **not a finding**, `ci.yml:25-27` documents it as "stable branch tip at pin time" and the pinned commit still exists upstream (verified by fetching it: 2026-08-04 "toolchain: stable"). No new job, action or step since 09/02; `permissions: contents: read` and `persist-credentials: false` still in place.

**Supply chain:** all 495 locked packages come from crates.io — **zero** git, path or vendored dependencies. 81 `build.rs` scripts, all ordinary crates.io packages, nothing anomalous. **No `unsafe` in production code** (the only hits are a test allocator and a `#[cfg(test)]` umask shim).

**Test suite at HEAD:** 830 passed, 0 failed, 0 ignored (see §5 for the load-sensitivity note).

---

## 7. Consolidated open-findings register

Everything open as of this audit. IDs are stable across the 09/01, 09/02 and 09/22 reports; new IDs
continue the numbering rather than restarting.

| ID | Sev | One-liner | Origin |
|---|---|---|---|
| **H-07** | High | Lamport ceiling off-by-one — one directive permanently kills authoring, mesh-wide | **09/22** |
| **H-08** | High | Boot skip + startup compaction permanently **deletes** the skipped transactions | **09/22** |
| **H-09** | High | `supply_entry_count` early return bypasses the T43 pre-scan — ~50×, silent | **09/22** |
| **H-10** | High | Unbounded `HaveHeads` `more` loop — all anti-entropy dies permanently | **09/22** |
| **H-11** | High | Cancelled mutation never clears `commit_in_flight` — every write path wedged | **09/22** |
| H-01 | High→Low | *Partially closed.* Write CSRF and the ledger-data rebinding read are closed; `/health` rebinding read remains (→ L-42); loopback API key deferred | 09/01 |
| M-06 | Med | *Partially closed.* Per-frame timeouts exist; no session deadline / frame budget / `open_bi` timeout | 09/01 |
| M-09 | Med | *Partially closed.* State is order-insensitive; remote-`close` **admission** is not | 09/01 |
| M-10 | Med | *Interim only.* Authorship squatting — real fix is T45 Facet A | 09/01 |
| M-16 | Med | *Partially closed.* Pre-scan bypassable (→ H-09); limiter bounds count not bytes (→ L-39) | 09/02 |
| **M-19** | Med | `externalFileEdits: "disabled"` does not disable adoption; README says it does | **09/22** |
| **M-20** | Med | Reconcile/boot apply a weaker check set, then **sign** and replicate the result | **09/22** |
| **M-21** | Med | Rate-limiter bucket cap is a sustainable total bypass | **09/22** |
| **M-22** | Med | Cleartext h2c on the GraphQL port makes the `h2` advisory reachable pre-auth | **09/22** |
| **M-23** | Med | `verify` is O(B×T×P) under the read lock; a peer supplies the multiplier | **09/22** |
| **M-24** | Med | `full_file_serialize` tie-break not total → replica `.bean` divergence (breaks I7) | **09/22** |
| **M-25** | Med | Parser silently discards trailing tokens on header/posting lines | **09/22** |
| **M-26** | Med | Advert cap bounds id count, not bytes or time; ids never format-checked | **09/22** |
| **M-27** | Med | `open_bi()` has no timeout — second wedge route + coordinator permit leak | **09/22** |
| **M-28** | Med | No client-side session deadline or frame budget | **09/22** |
| **M-29** | Med | Watcher disables T44's append path and reparses under the write lock per self-write | **09/22** |
| **M-30** | Med | `trustedProxies` misses a v4-mapped dual-stack peer → limiter collapses to one bucket | **09/22** |
| **M-31** | Med | `swarmTopic` is the signature domain by default but gets none of `meshId`'s validation | **09/22** |
| **M-32** | Med | Swarm topic logged verbatim at INFO, defeating the T39/T41 redaction | **09/22** |
| **M-33** | Med | No per-IP HTTP connection cap; one host stops the accept loop | **09/22** |
| **M-34** | Med | New `rustls` advisory; CI `cargo audit` job is red | **09/22** |
| L-01 | Low | *Partially closed.* Want arm still collect-then-truncate (→ L-33) | 09/01 |
| L-02 | Low | *Partially closed.* Absent on `reconcile_content` (→ M-20) | 09/01 |
| L-23 | Low | *Partially closed.* `meshId` is opt-in; default path unvalidated (→ M-31/M-32) | 09/02 |
| L-29 | Low | *Partially closed.* Parent form checked on the wire, not on the reconcile/boot file path (→ M-20) | 09/02 |
| **L-33…L-54** | Low | Twenty-two new Lows — see §4 | **09/22** |
| L-06 | Latent | `\|`-delimited sig message — `mesh_id` is now the one unconstrained field (M-31); length-prefix at T45 Facet B | 09/01 |

**Closed this audit (42):** H-02, H-03, H-04, H-05, H-06 · M-04, M-07, M-08, M-11, M-12, M-13, M-14,
M-15, M-17, M-18 · L-03, L-04, L-05, L-07, L-08, L-09, L-10, L-11, L-12, L-13, L-14, L-15, L-16,
L-17, L-18, L-19, L-20, L-21, L-22, L-24, L-25, L-26, L-27, L-28, L-30, L-31, L-32.

---

## 8. Remediation backlog

Task numbering continues from T45 (Format v2, design approved-pending — unchanged by this audit
except that **M-31 strengthens the case for Facet B**: `mesh_id` is now the only unconstrained field
in the v3 signature message). Effort: S = <½ day, M = ~1–2 days.

### Tier 1 — ship-blockers (all five new Highs; fix before any multi-node or exposed deployment)

**☐ T46 — Reconcile the lamport ceiling with the arithmetic around it (H-07) — S**
Change: clamp at the **stamp** sites, not only the accept site — refuse to author above the ceiling (or fail closed at boot); reject an inbound lamport that would push the local clock past it rather than adopting it; make the accept bound exclusive or reserve explicit headroom. Move the clock **after** validation, not before. Files: [union_merge.rs:50,278](crates/p2p/src/union_merge.rs#L278), [service.rs:3115,1856,1873,1413-1416](crates/ledger/src/service.rs#L3115). Verify: ingest `MAX_REMOTE_LAMPORT`, assert a locally-authored directive still passes `validate_envelope` — across a restart; property test that no reachable ingest can push the clock past the ceiling.

**☐ T47 — A lossy boot must never reach a rewrite (H-08) — S/M**
Change: carry skipped directives through boot in a quarantine set that compaction re-serializes verbatim, **or** refuse to compact when any skip set is non-empty and surface a fail-closed operator error. Covers all three skip sites (cycle, T41 fan-in, `dag.insert` refusal incl. `CycleCheckExhausted`). Files: [service.rs:1311,1355,1377,1385,2052](crates/ledger/src/service.rs#L1355), [main.rs:219](crates/gl-node/src/main.rs#L219). Verify: the §2 proof — append six transactions, patch one `openledger-parents` line, reboot, assert **all six are still on disk**; same for a pre-T41 over-fan-in file.

**☐ T48 — Complete the CBOR pre-scan (H-09) — S**
Change: walk every top-level pair and bound every array, as `scan_bounded_arrays` already does; reject `Supply` frames carrying unknown keys, since serde buffers them regardless. Files: [cbor_scan.rs:560-573](crates/p2p/src/cbor_scan.rs#L560-L573), [protocol.rs:375-378](crates/p2p/src/protocol.rs#L375-L378). Verify: extend `decode_memory.rs` with the `{"type","entries":[],"z":[…]}` shape, asserting **both** rejection and bounded peak allocation.

**☐ T49 — Session bounds on anti-entropy, and a tick drain that cannot be held hostage (H-10, M-26, M-27, M-28) — M**
Change: a deadline around the whole exchange; page counter + byte budget on the advert loop; `^[0-9a-f]{64}$` on every advertised id (the rule parents already have); timeout on `open_bi`; client-side frame budget mirroring the server's 100k; and make the drain resilient — `join_next` with a timeout or abort the `JoinSet` at the next tick. Files: [anti_entropy_alpn.rs:422,451,579,624-648,658-699](crates/gl-node/src/anti_entropy_alpn.rs#L624-L648), [p2p_service.rs:313-324,435](crates/gl-node/src/p2p_service.rs#L435). Verify: a peer answering `more:true` with empty pages forever — assert the exchange aborts **and the next tick still syncs a healthy peer**; a peer advertising `initial_max_streams_bidi = 0`.

**☐ T50 — Make `commit_in_flight` RAII (H-11) — S**
Change: a guard that clears the flag on drop, or an explicit clear on the cancellation path; make a wedged flag recoverable rather than terminal. Files: [service.rs:2081,2145,2182,2017](crates/ledger/src/service.rs#L2081), [ledger_commit.rs:100,155](crates/gl-node/src/ledger_commit.rs#L100). Verify: cancel a mutation mid-commit, assert the next mutation succeeds; repeat for the 408 path and an h2 `RST_STREAM`.

### Tier 2 — the file-ingest path (its guards diverged from the wire's, and it signs what it adopts)

**☐ T51 — Reconcile/boot check parity (M-20, L-02, L-45) — S/M** — Add `enforce_economic_bean_limit`, `parent_txid_is_well_formed` and a lamport format/range check to `reconcile_content` and boot; make boot's charset rejection skip-and-warn rather than fatal. Verify: a regression test per class asserting the entry is refused **before** it is signed.
**☐ T52 — File-interface honesty (M-19, M-25, M-29) — S/M** — Honour `externalFileEdits` on the compaction path or delete the setting and correct README:622; `at_eol` after every line form; self-write suppression + `last_file_hash` short-circuit in the watcher, and a size cap in `FileState::from_path`. Verify: the four M-25 truncation cases rejected-or-logged; the M-29 `Append`→`Compact` proof inverted.

### Tier 3 — cost, determinism, and the HTTP edge

**☐ T53 — Total serialization order (M-24) — S** — Append the content id to `stable_sort_key`, as `accounts::LifecycleKey` already does. Verify: the two proven tie cases produce byte-identical files under both arrival orders; strengthen CT-9.
**☐ T54 — Batched balances-at-date (M-23, L-35) — M** — One pass for all assertions; re-weight `verify`; move it off the read lock; build T27's incremental directive-id index. Verify: the 4000×4000 case stays sub-second; assert the weight matches measured cost.
**☐ T55 — HTTP edge hardening (M-21, M-30, M-33, L-36, L-37, L-42, L-50, L-51, L-52) — M** — Fail closed under a shared overflow budget at the bucket cap; normalize v4-mapped peers in `client_ip`; per-IP connection cap; XFF entry-count cap; widen the `trustedProxies` warning; put `/health` behind the Host guard and the limiter; validate `apiKey` header-safety; compare scheme in `origin_allowed`; reject literal `"null"` origins.
**☐ T56 — Dependency bumps and CI hygiene (M-34, M-22, L-46) — S** — `cargo update -p rustls -p h2 -p lru -p chacha20` (all semver-compatible, lockfile-only); decide deliberately whether to serve h2c at all (`http1_only()` if not); add `--locked` to the clippy step. Verify: `cargo audit` exits clean and CI is green.
**☐ T57 — Mesh identity and logging (M-31, M-32, L-23) — S** — Apply `meshId`'s four checks to whatever resolves as the signature domain; stop logging the topic verbatim; consider making `meshId` required. Feeds T45 Facet B.

### Tier 4 — scheduled hardening

**☐ T58 — P2P cost/robustness sweep (L-33, L-34, L-38, L-39, L-53, L-54) — M**
**☐ T59 — Ledger/commit robustness sweep (L-40, L-41, L-43, L-44) — S/M**
**☐ T60 — Docs, config and key hygiene sweep (L-47, L-48, L-49, plus §5's README drift and the unpinned `truncate_supply`/bean-cap coupling) — S**

### Finding → task coverage map

H-07→T46 · H-08→T47 · H-09→T48 · H-10→T49 · H-11→T50 · H-01(residual)→T55 · M-06→T49 · M-09→(open, revisit with T45) · M-10→T45 · M-16→T48/T58 · M-19→T52 · M-20→T51 · M-21→T55 · M-22→T56 · M-23→T54 · M-24→T53 · M-25→T52 · M-26→T49 · M-27→T49 · M-28→T49 · M-29→T52 · M-30→T55 · M-31→T57 · M-32→T57 · M-33→T55 · M-34→T56 · L-01→T58 · L-02→T51 · L-23→T57 · L-33/34/38/39/53/54→T58 · L-35→T54 · L-36/37/42/50/51/52→T55 · L-40/41/43/44→T59 · L-45→T51 · L-46→T56 · L-47/48/49→T60 · L-06→T45.

**Recommended order:** T46–T50 (Tier 1) → T56 (clears red CI, one command) → T51/T52 → T53/T54/T55/T57 → T58–T60. T45's wave C can proceed in parallel with Tier 1; **T45 waves A+B should wait for T46 and T51**, since both touch the envelope fields Format v2 re-specifies.

---

## 9. Checked and found sound (new this audit)

Beyond the 29 closures in §1.1, these were probed adversarially and held:

- **Crypto.** `verify_strict` is genuinely strict — vendored `ed25519-dalek-2.2.0/src/verifying.rs:370` rejects small-order `R` **and** small-order author key `A`; `signature.rs:91-96` uses `Scalar::from_canonical_bytes`; `legacy_compatibility` is not enabled and cannot be unified on (`security` is the sole consumer of 2.2.0). `zeroize` is a dalek default, so `SigningKey` really is `ZeroizeOnDrop`. RNG is OS-seeded ChaCha12. API-key compare is SHA-256 + `subtle::ConstantTimeEq` with no length branch. **No directive-insert path skips signature verification** — gossip is Announce-only, all three ALPN paths call `verify_remote_signature`, and `NoopSignatureProvider`'s always-`Ok` verify is unreachable for remote input because `config.rs:688-692` refuses `p2p.enabled && !signing.enabled`.
- **Wire.** `cbor_scan`'s header parser is **total and correct** over all 256 initial bytes (24/25/26/27 arg widths, 28–30 reserved, 31 indefinite, major-7 floats); `skip_value` is iterative with checked arithmetic and treats tags as same-level prefixes. The discriminator peek **cannot be spoofed into a different variant** — serde rejects a duplicate `"type"` as `duplicate_field` (H-09 needs no spoof). `ConnectionLimiter` releases on every path including the per-peer refusal, and reuse resets no server budget. `PeerConnectionCache`'s dial dedup, single connect timeout and `stable_id()` invalidation are correct. Verified from vendored quinn/noq that QUIC flow control gives no implicit per-stream total, so nothing rescues H-10.
- **Canonicalization.** Every `String` in `model.rs` was enumerated against `validate_body_strings` — **no field escapes the control-char sweep**. `union_merge`'s three checks all run **before** the envelope merge. No path reaches `stage_remote_directive` without canonicalization; `from_peer` is never `None`, so per-peer orphan budgets cannot be bypassed. `fetch_want_chunk`'s re-Want loop and `drain_orphans`' fixpoint both provably terminate; negative-cache poisoning is not exploitable into lost data.
- **Ledger.** `persist_atomically` is `O_EXCL` temp + fsync + rename + dir fsync + 0600 + cap-before-write (the one flaw is L-44's post-rename chmod). Journal framing and torn-tail policy are sound apart from L-41; compact-then-delete crash ordering is correct; `finish_commit`'s generation guard and the permit→write-lock ordering hold, including `adopt_reloaded`'s carry set. I1 is exact-zero with no tolerance window, with `checked_mul`/`checked_add` throughout `weights.rs`. L-27's determinism is real (`BTreeMap` sums; both ambiguous elision shapes refused). `check_no_cycle`'s early-`Ok` is a genuine proof and its `pending_children` invariant holds. Charset single-sourcing means `serialize_metadata`'s unquoted key cannot inject a line, and `quote_string`/`read_quoted_string` are a fixed point. `accounts.rs`'s `(date, priority, lamport, content_id)` key is genuinely total. `parse_file` never panics.
- **HTTP.** The Host guard covers all methods including the HTTP/2 `:authority` fallback, and every `split_authority` edge case fails **closed**. Content-Type parsing kills the simple-request CSRF. The XFF rightmost-untrusted walk resists client forgery (M-30 is a type mismatch, not a logic flaw). The connection permit releases on every path including panic and shutdown cancellation; h2 is not a cap escape (`max_concurrent_streams` defaults to 200). **Complexity expressions do see request variables** (vendored `validation/mod.rs:55` → `param_value`), so `account(at: $d)` cannot dodge its weight. Batch requests are refused; introspection is off on public binds; no WebSocket route exists, so nothing escapes the guard/timeout/cap. `ServiceError::Io` is collapsed so no paths leak. `deny_unknown_fields` on all seven config structs. The public-bind fail-closed set (TLS/auth/allowedHosts/graphiql) is complete and `binds_non_loopback` errs strict on every non-literal spelling. The deploy stack boots as documented, and the compose defaults are deliberately sub-16-byte so a stack started without keys fails to boot.

---

*Previous audits: [SECURITY_AUDIT_0902.md](SECURITY_AUDIT_0902.md) · [SECURITY_AUDIT_0901.md](SECURITY_AUDIT_0901.md) · [docs/CLAUDE_SECURITY_AUDIT_0820.md](docs/CLAUDE_SECURITY_AUDIT_0820.md). Remediation trackers: [docs/OUTSTANDING_TASKS_09.md](docs/OUTSTANDING_TASKS_09.md) (T18–T45) · [docs/OUTSTANDING_TASKS.md](docs/OUTSTANDING_TASKS.md) (T1–T17, all ☑). Format v2 design: [docs/FORMAT_V2_DESIGN.md](docs/FORMAT_V2_DESIGN.md).*
