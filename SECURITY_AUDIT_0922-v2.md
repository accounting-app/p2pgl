# Security Audit — openledger-v2 (0922 v2: re-audit of T46–T60)

**Date:** 2026-09-22 · **Baseline:** HEAD `3d5ff71` (branch `main`, clean tree) · **Previous:** [SECURITY_AUDIT_0922.md](SECURITY_AUDIT_0922.md) (HEAD `9f62435`)

Scope: re-verification of **every** open entry in the 09/22 register (§7 there) and of **every** residual
R-1…R-21 in [docs/OUTSTANDING_TASKS_09_22.md](docs/OUTSTANDING_TASKS_09_22.md) against source at HEAD,
plus fresh hunts over the ~14,900 lines T46–T60 added or changed (36 files, six commits after `9f62435`),
treated as unreviewed code. Priority went to the places where one fix touched another: the commit/recovery
path and the H-11 guard, the boot quarantine and compaction serializer, the refusal cache and anti-entropy
session bounds, and the connection, byte and rate budgets.

Method as established for the series: thirteen parallel passes (five re-verification, eight fresh-hunt),
each read-only on the repo with its own scratch crates; library semantics checked against vendored
sources under `~/.cargo/registry`; every mechanism an agent reported was re-read in source and every
executable proof re-run by the orchestrator before it appears below; `cargo audit`, lockfile sources
and CI pins re-checked; a per-task Change/Files/Verify backlog at the end. Test suite at HEAD before the
audit started, quiet machine: **987 passed, 0 failed, 0 ignored**. The repository was not modified except
to add this file.

---

## Executive summary

**T46–T60 closed what they set out to close.** Of the 0922 register's five new Highs, four are closed by
mechanism (H-08, H-09, H-10, H-11) and their regression tests assert the security property rather than a
proxy. Of the sixteen Mediums, fourteen are closed; of the twenty-two Lows, twenty are closed. Several
fixes are better than asked (T47's quarantine over refuse-to-compact, T48 finding the second hidden-payload
hole, T50 closing the permit-release durability bug, T55 catching the `http1_only()` no-op). `cargo audit`
is clean, CI is green, the lockfile is entirely crates.io.

**But the pattern the 0922 audit named has repeated, one level down.** That audit found its Highs inside
T18–T44's own code. This one finds its Highs inside T46–T60's code *and* in the pre-existing file-ingest
path that T47/T51/T52 built on top of without re-deriving its assumptions. Six new Highs:

- **H-12** — H-07 is only partially closed. The ceiling rule is applied to three different quantities
  (stamp: `clock+1`; wire: `value`; adoption: `max+1`), so `CEILING-1` is stamped and accepted on the wire
  but refused at adoption. One legal directive from an allowlisted peer still makes every node that adopts
  it author **one silently unreplicable record** and then brick authoring on restart; the boot warning T46
  added never fires for the reachable state; and the documented remedy is undone by the next anti-entropy
  tick. R-1 is re-rated High on this evidence.
- **H-13** — the README's only supported edit workflow — *stop the node, edit the file, start it* —
  produces records with **no envelope and no signature**. Boot loads them as history, the startup
  compaction writes them back as-is, and the node's next local transaction names one as a parent. Every
  peer refuses the record and orphans everything the node authors afterwards. L-11 was closed for the live
  path only.
- **H-14** — a failed reconcile records the broken file's hash as the new baseline **before** it parses.
  With `watchLedgerFile: true` the next commit's adopt-before-persist sees "nothing changed" and rewrites
  the file over the operator's edit, valid lines included, after having logged that the file was safe.
- **H-15** — removing or renaming the `.bean` under a running node makes the next write's L-13 recovery
  boot **create an empty ledger** and install it over the complete in-memory copy. Total loss, one I/O
  error to one client, nothing logged, `mv ledger.bean ledger.bak` is enough.
- **H-16** — an allowlisted peer sends 257 valid parentless transactions. The victim's next append names
  all 257 heads as parents (local stamping has no fan-in cap), is refused by every peer, and is quarantined
  out of the victim's **own** DAG at its next boot. Everything the victim authors afterwards is orphaned
  mesh-wide, and the head set re-inflates so it repeats.
- **H-17** — balance accumulation is not associative (`saturating_add`, no magnitude cap at any ingress).
  Two directives from a peer make a chosen replica's live `account()`/`trial_balance` drop an honest
  posting to zero while `verify` reports every assertion passing and the same directive set shows the
  right number on another replica and after a reboot.

Two of the six (H-14, H-15) are **silent loss of committed or operator-entered records**, the outcome
this series ranks highest. Three (H-12, H-13, H-16) are the H-03/H-06 divergence shape reached through a
door the campaign did not think of as an ingest path: the victim's *own* stamping and boot logic.

Eleven new Mediums follow the same lines: a compaction-crash boot brick from the journal budget (M-35);
the ledger-side file readers opening whatever is at the path — a FIFO parks the writer holding the permit
forever, unkillable by SIGTERM (M-36); reconcile-rejected and recovery-loaded hand edits becoming history
without any guard (M-37); a reconcile that leaks one cycle member and thereby quarantines the node's own
later transactions (M-38); a near-cap ledger reloading itself under the write lock once per tick per peer
(M-39); no server-side anti-entropy deadline (M-40); pre-limit log amplification on both the HTTP and the
ALPN edge (M-41); the watcher hashing the whole file four times a second (M-42); R-18 confirmed end to end
(M-43); a plausible crash-time boot refusal on zero-filled journal tails (M-44); and a GraphQL weight that
ignores its own `limit` (M-45).

The through-line is narrower than 0922's and more actionable: **the file is treated as history by boot,
as operator input by reconcile, and as this node's own bytes by the compaction — and the three disagree.**
Five of the six Highs and five of the Mediums are one consequence or another of that disagreement. The
Tier-1 backlog below is therefore organised around making the file path one path, not around six
unrelated patches.

---

## Threat model

Unchanged from [09/22](SECURITY_AUDIT_0922.md) (§Threat model). Actors: (a) a web page in an operator's
browser against a local node, (b) an API-key holder, (c) a **malicious or compromised allowlisted peer**,
(d) a network attacker on a public bind, (e) whoever can write the `.bean` file or its directory. This
audit adds the explicit no-attacker cases the fixes created: the operator following the README, an editor
autosave, a backup `mv`, a crash at the wrong instant, an upgrade over an old file.

---

## 1. Status of the 09/22 register, re-verified at HEAD `3d5ff71`

Every entry was re-verified in source; the tracker's "Done" paragraphs were treated as claims. Where the
09/22 report gave an executable proof, an equivalent proof was re-run at HEAD. Regression tests were read
for whether they pin the property or a proxy; the ones that do not are named.

### 1.1 Closed — verified by mechanism (44)

**Highs — 4 of 5:**

| ID | Verdict | Mechanism confirmed at HEAD |
|---|---|---|
| **H-08** | **Closed** | All three boot skip sites quarantine ([service.rs:2114](crates/ledger/src/service.rs#L2114) cycle, [:2176](crates/ledger/src/service.rs#L2176) fan-in/M-20 form, [:2202](crates/ledger/src/service.rs#L2202) DAG refusal) plus L-45's `quarantined_text` (:2004-2012); `compaction_text` (:3062-3075) = `full_file_serialize(DAG ∪ live_quarantine)` + raw blocks, and it is the only whole-file write (:2982). The 09/22 proof runs as `test_a_planted_parent_cycle_cannot_erase_the_ledger_at_the_next_compaction` and asserts six on disk after reboot + compaction; over-fan-in and `CycleCheckExhausted` have the same assertion. But see **M-38** and **H-13** for what reconcile and boot still do to records the quarantine does not see. |
| **H-09** | **Closed** | One `walk()` (cbor_scan.rs:838-897) visits every top-level pair; `scan_supply_frame` requires each bound's key and refuses unknown/duplicate keys; `entries` elements are judged at the header **and walked** (`ElementKind::Struct`). The only `ciborium::from_reader` in the workspace ([protocol.rs:336](crates/p2p/src/protocol.rs#L336)) sits behind `decode_checked` → `prescan_frame`. Re-measured with `decode_memory`'s counting allocator: hidden tail and hidden entry both **peak 0**; honest Supply 1.02×, honest Want 1.82×. R-4 re-measured at **4.05×** (was 5.00×). |
| **H-10** | **Closed** | `SessionBudget` built before the dial; `charge_frame()` is the only source of a frame timeout and returns `min(io, time left)`; page cap charged before the page is examined; byte budget over distinct ids; `is_content_id` on every advertised id; `open_bi_bounded` is the only production `open_bi`; drain is `timeout_at(tick, join_next())` with an RAII `InFlightGuard`. The money test drives the real loop and requires the healthy peer to converge **after** the flood starts. Server side is bounded by frame count, not wall-clock (→ **M-40**). |
| **H-11** | **Closed** | `CommitInFlightGuard::arm` is the only setter, called last in `prepare` (:3008); `Drop` is a generation-stamped `compare_exchange`; the guard is a private field of `PendingCommit`. `commit_pending` takes the `WritePermit` **by value** into `tokio::spawn` and awaits only the `JoinHandle` (vendored tokio 1.53.1 `task/join.rs:357-365`: drop detaches). All six call sites verified: none drops a `PendingCommit` after releasing the permit or holds the write guard across the await. Tests panic while *holding* the `PendingCommit` and assert the next write succeeds. |

**Mediums — 14 of 16:** M-19 (key deleted; `reject_removed_config_keys` runs before the typed parse; README:667-687 corrected), M-20/L-02/L-29 (four parity validators before the stamp and before `sign_adopted_entry`; second bean-cap on the I2-resolved body; boot at form parity), M-21 (shared overflow bucket; nothing admitted free — the residual is a new-client lockout under ~1,100 rps of key churn, documented), M-22 (`serve_connection` + `http1_only()` together; vendored hyper-util confirms the upgrades variant ignores the flag; head timer runs from accept; live: h2 preface closed with 0 bytes), M-23 (`balances_at_dates` one sweep; 2048 weight, 2 per request; the `const { assert! }` is inside a `#[test]`, so it guards the test build, not `cargo build`), M-24 (decorate-sort-undecorate; ties by `(content id, emitted bytes)`; CT-9 now carries a tied pair — R-11 closed), M-25 (`reject_trailing_content` at 12 sites; an eight-form scratch sweep found no gap), M-26/M-27/M-28 (client-side bounds all present; M-28's frame counter is unpinned by any test — G-1), M-29 (set-never-clear asymmetry; watcher suppression under a read lock), M-30 (`canonical_ip` on peer, XFF entries, configured list, per-IP table), M-31 (four rules on both fields; `debug_assert!` on the resolved domain, compiled out in release), M-32 (`redact` at the ready-log; workspace grep clean except **L-56**), M-33 (per-IP cap after the pre-accept permit; 70 slowloris sockets → #64–69 closed), M-34 (lockfile bumps present; `cargo audit` exit 0; ignore file names exactly RUSTSEC-2026-0235 with evidence), M-16 (pre-scan half by T48, byte half by T58 — R-4 is what remains).

**Lows — 20 of 22:** L-01/L-33 (`build_supply` budgets while collecting — the tracker cites the wrong test for byte-identity; the real one is p2p's `test_build_supply_is_identical_to_collect_then_truncate`), L-34 (`RefusalCache` keyed `(peer,id)`; both classifiers are exhaustive `match`es with no wildcard — but see **L-60**), L-36, L-37, L-38, L-39, L-40 (give-up yields a parentless append that backfills as a child, not a fork), L-41 (overflow-proof; the *policy* half is **M-43**), L-42, L-44 (handle `fchmod`; a stale/FIFO/symlink `.tmp` is unlinked and retried — but see **L-57**), L-45, L-46, L-47, L-48, L-49 (lstat → regular → open → (dev,ino) → owner, no root exemption), L-50, L-51, L-52, L-53, L-54.

Highlights that exceeded the backlog: T50's permit-by-value design makes cancellation change nothing about
the write; T48's `MAX_SUPPLY_ENTRY_ITEMS` is derived from `ENVELOPE_KEYS`; T53's tie-break is total up to
byte-indistinguishable output and *cheaper* than the comparator it replaced; T55 caught that hyper-util's
sniffing path parked silent sockets with no timer at all; T60's `const _: () = assert!` coupling is sound
per key for the largest legal entry.

### 1.2 Partially closed (6)

| ID | What remains reachable at HEAD |
|---|---|
| **H-07** | Stamp, wire and adoption apply `LAMPORT_CEILING` to three different quantities (→ **H-12**). `test_ingest_at_the_ceiling_cannot_brick_local_authoring` and `test_remote_lamport_at_the_ceiling_is_refused_not_adopted` pin *both halves of the contradiction* — one asserts `CEILING-1` is accepted on the wire, the other that it is refused at adoption. |
| **H-01** | `/health` is now behind the Host guard and its own limiter (closed). Item (d), the loopback API key, remains deferred by decision. `OPTIONS` still short-circuits every layer and returns the route's `Allow` header to a rebound page (§5). |
| **M-06** | Client side fully bounded. **No server-side wall-clock deadline** (→ **M-40**); no cross-peer cap on concurrent exchanges (R-5). |
| **L-23** | Validation half closed by T57. `meshId` remains opt-in; no boot `warn!` when unset; `deploy/gl-node.docker.json` does not set it; the README steers to `uuidgen`, which invalidates history (R-9, decision pending). |
| **L-35** | `contains_directive`, `is_head`, `sorted_directive_ids` exist with **zero production callers**; all three `all_directive_ids()` sites in `anti_entropy_alpn.rs` (:801, :1020, :1581) still clone O(N). The snapshot's invalidation is sound (the DAG is grow-only; a reload resets it). R-19 stands. |
| **L-43** | Commit-failure recovery is off-lock (L-43 shape verified). The prepare-failure arm still reloads synchronously under the caller's write guard (R-20) — and **M-39** shows a peer can drive it once per tick. |

### 1.3 Unchanged by decision (3)

M-09 (remote-close admission order-dependent; T45), M-10 (interim `already_existed`; T45 Facet A), L-06
(the `|`-delimited signature message; T57 has now constrained `mesh_id`, so the message is injective at the
verifier, and T45 Facet B can length-prefix it).

### 1.4 Residuals R-1 … R-21, dispositions at HEAD

| R-# | Disposition | Evidence |
|---|---|---|
| R-1 | **Still open and worse → re-rated High as H-12.** A peer at `CEILING-2` lands the receiver on `CEILING-1`; a peer at `CEILING-3` additionally makes the receiver author one unreplicable directive. Removing the offending line and restarting is undone by the next anti-entropy tick from any peer that holds it. Boot `warn!` tests `>= CEILING` and never fires for `CEILING-1`. | executed (five scratch tests, re-run) |
| R-2 | Still open, scope clarified: after **any** L-13 reload the next write is a forced compaction (boot sets `canonical_is_current = false`), so at the cap every write — appends that would fit included — is refused, and each attempt reloads. → **L-64** | executed |
| R-3 | Still open, and **escalated** → **M-38** (reconcile leaks a cycle member into the DAG, which then becomes a head). | executed |
| R-4 | Still open, improved: **4.05×** at HEAD (67,108,850 B on a 16,777,152 B frame), not 5×. A second shape of the same class: `entries:["<16 MiB text>"]`. Low → Info. | executed |
| R-5 | Still open. Per exchange ≈130–150 MiB resident worst case (1M ids × ~90 B in `Vec` + `HashSet` + `compute_want` clone, plus one 16 MiB Supply and its decode) × every admitted peer. | reasoned |
| R-6 | Not a finding (documented hand-off). | — |
| R-7 | Still open (no config surface for the new bounds). | — |
| R-8 | Still open (documented, shutdown-only). | — |
| R-9 | **Decision pending.** Step (b) not done: `main.rs:311` is `info!`, not `warn!`; docker config ships no `meshId`; README §Mesh identity recommends `uuidgen` and never states that `meshId := swarmTopic` byte-for-byte is the only history-preserving choice. Recommendation unchanged: warn, document the verbatim choice, ship it in the docker config, require it a release later. | reasoned |
| R-10 | Still open as described; should also name the lamport-ceiling case (a file value ≥ 2^53 is loaded and served — boot never signs). The L-34 cache **does** absorb the re-Want churn (one refused ≤1 MiB transfer per peer per 10 min). | reasoned |
| R-11 | **Closed** by T59 (CT-9 carries a tied pair delivered in opposite orders). | — |
| R-12 | **Closed** by T55 (banner lists all four reasons and explains id-less blocks). | — |
| R-13 | **Decision pending, partially documented.** README covers `watchLedgerFile`, `/health` 403/429, 64 conns/IP. **Not documented anywhere:** HTTP/1.1-only (zero hits for "h2c"/"HTTP/2"), the printable-ASCII `apiKey` rule, `"null"`-origin refusal, plain-`http` `Origin` refusal under `terminated`, and that an older binary rejects the new config key. No CHANGELOG exists. | reasoned |
| R-14 | Still open. `verify` measured 34 µs/directive debug, ≈3.4 µs release — matches the T54 table. | executed |
| R-15 | Still open: 20,000/20,000 remote `balance` directives on `Assets:Ghost` admitted, `first_err = None`. `verify.ok` deliberately excludes assertion failures. | executed |
| R-16 | Monitor; not a finding. | — |
| R-17 | **Decision pending.** `p2p_service.rs:1042` is the only non-test `unsafe`; `libc` 0.2.189 is already compiled into `gl-node` transitively. Recommendation unchanged: add it as a direct dependency — it also gives `O_NOFOLLOW`/`O_NONBLOCK`, which **M-36** needs. | reasoned |
| R-18 | **Decision pending; loss confirmed three times independently** → **M-43**. Three length spellings (`999999`, `10^23`, `u64::MAX`) all classify as torn; boot loads the prefix; the startup compaction unlinks the journal. Not reachable by a crash (executed: no `Append` is ever chosen while a torn tail is outstanding). Recommendation: fail closed. | executed |
| R-19 | Still open, fully: `drain_orphans` was **not** switched either. | grep |
| R-20 | Still open → composed into **M-39**. | executed |
| R-21 | Environment; harness `warm_up_loopback()` present. Not a register item. | — |

---
## 2. New findings — High

Every finding below was executed, not only reasoned, unless marked otherwise; the command and observed
output come from a scratch crate against the workspace crates at HEAD, re-run by the orchestrator.

### H-12 — H-07 is only partially closed: the ceiling is applied to three different quantities, and the reachable state is silent, persistent and re-infecting

**Where:** [service.rs:929-934](crates/ledger/src/service.rs#L929-L934) (`checked_lamport`: refuses `next >= LAMPORT_CEILING`), [service.rs:2737,2759](crates/ledger/src/service.rs#L2737) (stamp sites: `checked_lamport(clock + 1)`), [union_merge.rs:289-292](crates/p2p/src/union_merge.rs#L289-L292) (wire: `value < LAMPORT_CEILING`), [service.rs:4678-4681](crates/ledger/src/service.rs#L4678-L4681) (adoption: `checked_lamport(max(local, remote) + 1)`), [service.rs:2231](crates/ledger/src/service.rs#L2231) (boot warning: `lamport_clock >= LAMPORT_CEILING`), [service.rs:2088](crates/ledger/src/service.rs#L2088) (`max_lamport` scanned before every quarantine skip).

T46 single-sourced the constant and made every path refuse rather than clamp — both correct. But the
three checks bound *different* things against the *same* number: the stamp bounds the value it is
about to write, the wire bounds the value it reads, adoption bounds the value **plus one**. So
`CEILING-1` is a legal stamp, passes every peer's wire check, and is refused by every peer's adoption.
The repository's own tests pin both halves of the contradiction: `union_merge.rs:2160-2165` asserts
`CEILING-1` "is still accepted on the wire"; `service.rs:7337` asserts it is refused at adoption.

**Executed** (`A1-highs/h07proof`, re-run): node A adopts a peer directive at `CEILING-3`; its clock is
`CEILING-2`; its next mutation returns success stamped `CEILING-1`; node B refuses it with
`LAMPORT_CEILING`; A restarts, re-derives `clock = CEILING`, and refuses every further mutation.

```
A authored lamport = 9007199254740991 ; CEILING-1 = 9007199254740991
wire check (value < LAMPORT_CEILING): true
B REFUSED A's directive: code=LAMPORT_CEILING
A after restart: clock=9007199254740992 (CEILING) -> A refuses to author: code=LAMPORT_CEILING
```

Three more facts, each executed (`A5-residuals`, re-run), make this High rather than the Medium R-1
recorded:

1. **The reachable state is exactly the one the boot warning misses.** A file re-deriving `clock =
   CEILING-1` logs zero WARN lines (the test is `>= CEILING`; the stamp refuses from `CEILING-1`).
2. **The documented remedy is not durable.** Removing the offending line and restarting restores
   authoring — and one `stage_remote_directive` of the same, perfectly legal directive re-poisons it,
   which is what the next anti-entropy tick from any peer that holds it does. The real remedy is
   allowlist removal *plus* coordinated file surgery on every node.
3. **The quarantine writes the poison back forever.** A hand-edited transaction with `lamport =
   CEILING-2` and an uppercase-hex parent is quarantined (not in the DAG), still sets the clock, and is
   re-written by every compaction; the banner says "nothing is lost… repair", H-07 says "remove".

Net: one legal directive from an allowlisted peer still stops authoring on every node that adopts it,
survives restart, and — for the `CEILING-3` value — makes each victim emit one silently unreplicable
record first. Loud after that record, not silent; mesh-wide; the allowlist is the only control. That is
three of H-07's four properties.

**Fix (S):** state the rule once on the *adopted* value — stamp refuses when `next + 1 >= CEILING`
(largest stamp `CEILING-2`), wire requires `value + 1 < CEILING`, boot warns when `clock + 1 >= CEILING`;
count `max_lamport` only for inserted directives unless `openledger-author` is this node; name the
author id in `LamportCeiling` and state the mesh-wide remedy. **Decision:** the adoption ratchet
(bounded advance per directive) is the only thing that closes reachability; R-1's stated risk (a
long-offline replica refusing honest traffic) needs an explicit escape. **Regression:** feed the last
authored directive at the ceiling into a second service's `stage_remote_directive` and assert `Ok`;
extend the restart test to assert the warning fires at `CEILING-1`.

### H-13 — The README's supported edit workflow produces records with no envelope and no signature; the node's later history is orphaned on every peer

**Where:** [service.rs:1937-1946](crates/ledger/src/service.rs#L1937-L1946) (boot reads the file), [service.rs:2289](crates/ledger/src/service.rs#L2289) (`last_file_hash = hash(content)` of the file boot read), [service.rs:3526-3534](crates/ledger/src/service.rs#L3526-L3534) (`adopt_external_edits` returns on an equal hash), [main.rs:251](crates/gl-node/src/main.rs#L251) (startup compaction) vs [main.rs:392](crates/gl-node/src/main.rs#L392) (`set_signer`), [README.md:643-700](README.md#L643-L700).

The README says: *"Editing a `.bean` file while the node that owns it is running is not supported. Stop
the node, edit the file, start it again."* and, forty lines later, *"An entry with no signature is
signed as this node's own before the first persist, so it replicates like any other local write."* The
second sentence is true only for the *live* path (L-11's fix lives in `reconcile_content`). On the
supported path: boot parses the hand-typed block as history and inserts it with whatever metadata it
has — none; boot records the file's hash as the baseline; the startup compaction re-reads the same
bytes, finds no change, adopts nothing, and rewrites the directive **without an envelope**; the signer
is installed after all of that anyway.

**Executed** (`orch/offline-edit`, orchestrator's own probe): two node-authored opens, clean stop, one
hand-typed transaction appended, boot, `set_signer`, startup compaction:

```
hand-typed txn metadata after boot+startup compaction: {}
author=None lamport=None parents=None signature=None
file contains 'Offline edit': true ; envelope lines for it: 0
next local txn parents=Some("740d5285…"); names the envelope-less hand txn? true
```

Every peer's `validate_supply_entry` refuses the record at
[union_merge.rs:220-223](crates/p2p/src/union_merge.rs#L220-L223) (`EnvelopeMissing("openledger-author")`),
a content-determined refusal the L-34 cache holds for 10 minutes and repeats forever. The node's next
transaction names it as a parent, so every peer buffers *that* as an orphan, Wants the parent, gets it,
refuses it again. Everything this node authors from then on lives on this node alone, and the operator
did exactly what the README told them. Locally the record is in every report with no author. Pre-existing
(boot has never stamped), never registered; T51 added `validate_file_envelope_form` at boot, which checks
the form of envelope keys *that are present*.

**Fix (M, part of T61):** boot must distinguish history from operator input by the one signal it has —
a directive with no `openledger-author`/`-lamport` was never written by a node — and route such
directives through the reconcile adoption path (stamp, parents, sign) after the signer is installed,
before the startup compaction; alternatively quarantine them with a banner that says "unsigned, will not
replicate" until adopted. Either way `main.rs` must install the signer before the first compaction.
**Regression:** the probe above, asserting the record carries this node's author and signature after
boot and that a second service's `stage_remote_directive` accepts it.

### H-14 — A failed reconcile records the broken file's hash as the baseline; the next commit silently overwrites the operator's edit

**Where:** [service.rs:3760-3763](crates/ledger/src/service.rs#L3760-L3763) (`last_file_hash`, `canonical_bytes`, `canonical_marker` written **before** the parse), [service.rs:3785](crates/ledger/src/service.rs#L3785) (`canonical_is_current = false`), [service.rs:3826-3832](crates/ledger/src/service.rs#L3826-L3832) (`Err(Parse)` restores nothing; the log line says *"NOT reconciling and NOT persisting over it — repair the file (the in-memory ledger is unaffected)"*), [service.rs:3695-3712](crates/ledger/src/service.rs#L3695-L3712) (`reconcile_file_staged` restores nothing on `Err`), [main.rs:474-477](crates/gl-node/src/main.rs#L474-L477) (the watcher logs and continues), [service.rs:3532](crates/ledger/src/service.rs#L3532) (`adopt_external_edits` returns on an equal hash).

An editor autosaves a half-typed line. With `watchLedgerFile: true` the watcher reconciles within
250 ms, the parse fails, and the reconcile correctly refuses — but it has already recorded the broken
bytes as "what this service last read". The next commit of any kind — a GraphQL mutation, a peer's
routine anti-entropy delivery, the shutdown compaction — takes the compaction branch (the flag was
cleared), runs adopt-before-persist, sees the hash it recorded, adopts nothing, and rewrites the file
from memory. The operator's edit is gone, valid lines included, after two log lines said it was safe.
Because the flag was cleared, this is a full rewrite even on a ledger past the 64 KiB threshold where an
append would have left the file alone.

**Executed** (`B2-quarantine/probe`, `e1`, re-run): compact → hand edit = canonical + a valid `open` + a
half-typed `2024-03-03 open` → `reconcile_file_staged()` = `PARSE_ERROR` → `append_transaction(...)` =
`Ok` → the file contains neither line; `external_reconcile_count == 0`; no "adopting" line logged.

With the watcher **off** the same edit takes a different path — the first commit's `adopt_external_edits`
fails, `prepare_or_recover` reloads, and the L-45 salvage boot loads the valid line raw (→ **M-37**) — so
turning the watcher off converts loss into bypass, not into safety. The hash-before-parse ordering predates
the baseline (`git -S`); `reconcile_file_staged` is T44's; neither audit saw the composition. Tracker
R-13(b)'s "reconcile refuses the whole file until repaired … will block writes" is false.

**Fix (S, part of T61):** parse first; write `last_file_hash`/`canonical_bytes`/`canonical_marker`/
`canonical_is_current` only once `file_directives` exists (or snapshot and restore on the `Err` path).
Then a broken file is re-detected as foreign on every commit and blocks writes, as documented.
**Regression:** the `e1` shape, asserting the next write returns `PARSE_ERROR` and both hand-written lines
survive, at both sides of `COMPACTION_MIN_CANONICAL_BYTES`.

### H-15 — Removing or renaming the `.bean` under a running node installs an empty ledger over the complete in-memory copy

**Where:** [service.rs:3190-3205](crates/ledger/src/service.rs#L3190-L3205) (`FileMarker::of == None` ⇒ "changed on disk"), [service.rs:3526-3527](crates/ledger/src/service.rs#L3526-L3527) (`adopt_external_edits` → `read_ledger_file` → `NotFound`), [ledger_commit.rs:353-370](crates/gl-node/src/ledger_commit.rs#L353-L370) (`prepare_or_recover` → `recover_failed_commit`), [service.rs:1937-1946](crates/ledger/src/service.rs#L1937-L1946) (`boot`: *"Create parent dirs + empty file"* when the path is absent), [service.rs:3434-3453](crates/ledger/src/service.rs#L3434-L3453) (`adopt_reloaded`: `*self = reloaded`).

The next `prepare` after the file vanishes escalates to a compaction, whose adopt-before-persist fails
with `NotFound`; the prepare fails; the L-13 reload runs `boot`; `boot` finds no file, **creates an empty
one**, loads nothing (or the journal alone), and `adopt_reloaded` replaces the whole in-memory DAG with
it. Nothing is logged on the successful-reload path (`recover_failed_commit` logs only when the reload
itself fails). The caller sees one `IO: No such file or directory`; the next mutation succeeds and writes
a `.bean` holding only itself.

**Executed** (`B8-disk/probe rm-bean`, re-run):

```
before: directives=3 bean_bytes=254
--- rm ledger.bean; next write ---
write -> Err("IO: No such file or directory (os error 2)")
after : directives=0 bean_exists=true bean_bytes=Some(0)
next write -> Ok("ok"); directives=1
```

Reaching actor: anyone who can unlink or `mv` in the ledger directory (they need not read or write the
0600 file), and — the case that matters — an operator making a backup with `mv ledger.bean ledger.bak`
while the node runs. Total loss of committed, acked directives while the process held a complete copy.

**Fix (S, part of T62):** in `adopt_external_edits` and `reconcile_file_staged`, treat `NotFound` as
"nothing to adopt" and let the compaction recreate the file from memory (there is no edit to protect);
make `boot` refuse — or at least `warn!` — when the `.bean` is absent but a journal or `.lock` sidecar
exists; log every L-13 reload with before/after directive counts, and refuse to install a rebuild that
holds fewer directives than memory did unless the caller asked for exactly that. **Regression:** boot
three directives, `remove_file(.bean)`, `open_account` → `Ok`, `directive_count() == 4`, file holds four.

### H-16 — An allowlisted peer inflates the head set past `MAX_PARENTS`; the victim's own next append is refused everywhere and quarantined out of its own DAG at the next boot

**Where:** [service.rs:2746-2748](crates/ledger/src/service.rs#L2746-L2748) (`stamp_transaction_envelope` names **every** admissible head, no cap), [service.rs:2479](crates/ledger/src/service.rs#L2479) (local insert with no `validate_parent_fan_in`), [union_merge.rs:226](crates/p2p/src/union_merge.rs#L226) (*"openledger-parents may be empty string for genesis"* — accepted on a non-empty ledger), [service.rs:4636-4646](crates/ledger/src/service.rs#L4636-L4646) (remote path checks parent form only). Refusers: [union_merge.rs:246](crates/p2p/src/union_merge.rs#L246), [service.rs:940-950](crates/ledger/src/service.rs#L940-L950), boot quarantine [service.rs:2176](crates/ledger/src/service.rs#L2176).

Send 257 valid, signed, parentless transactions (~64 KB). Each passes I1/I3, inserts trivially, and
nothing points at them, so `heads` grows to 257+. The victim's next honest append names all of them —
the only fan-in check on the local path is the *file* one at boot — inserts locally, returns success,
and is refused by every peer with `openledger-parents has 257 entries (max 256)`. Every later victim
transaction descends from it, so peers orphan them forever. At the victim's next boot
`validate_parent_fan_in` quarantines the over-cap transaction — out of the DAG, out of the read model,
out of balances — while the 257 planted heads are heads again, so the next append is over-cap again.

**Executed** (`B6-semantics/proof heads_inflation_makes_local_append_over_cap`, re-run):
`victim parents = 257 · peer stage_remote_directive: openledger-parents has 257 entries (max 256) ·
after reboot: quarantined=1 victim_present=false · Assets:Cash after reboot = 251` (the victim's own −5
posting is gone from its own reports). Also reachable by (e).

**Fix (S, T64):** when admissible heads exceed `MAX_PARENTS`, name the `MAX_PARENTS` smallest sorted heads
and let the rest merge on later appends; run `validate_parent_fan_in` before the local insert as an
invariant. **Decision:** whether the remote path should bound unmerged heads per author (refuse a remote
transaction that names no current head while its author already owns ≥ N heads). **Regression:** stage
`MAX_PARENTS + 1` parentless remote transactions, append locally, assert the stored directive passes
`validate_parent_fan_in`, a second service accepts it, and reboot quarantines nothing.

### H-17 — Balance accumulation is order-dependent, so replicas, code paths and reboots disagree, and a peer can erase an honest posting from a chosen replica's live reports while `verify` passes

**Where:** [read_model.rs:182](crates/ledger/src/read_model.rs#L182) (`index_directive` running totals, `saturating_add` in arrival order), [read_model.rs:617](crates/ledger/src/read_model.rs#L617) (`balances_at`, arrival order), [read_model.rs:539](crates/ledger/src/read_model.rs#L539) (`balances_at_dates`, date order), every report at :232-360 and :643; no magnitude cap at [parse.rs:195](crates/ledger/src/parse.rs#L195), [scalars.rs:57](crates/gl-node/src/graphql/scalars.rs#L57) or `enforce_resource_limits`.

`saturating_add` is not associative (`MAX + 1 − MAX = 0`; `MAX − MAX + 1 = 1`) and plain `Decimal`
addition is not either when scales differ by more than 28 digits. I1 uses `checked_add` per transaction,
so a `+MAX` / `−MAX` pair is individually valid on every path. Live `account()`, `account(at:)`,
`trial_balance`, `balance_sheet`, `income_statement` fold in arrival order; `verify`'s batched sweep and
`ReadModel::build` at boot fold in date order; arrival order differs per replica.

**Executed** (`B6-semantics/proof`, re-run): honest local `+7`, then from a peer `+MAX` dated later and
`−MAX` dated earlier, both `Ok(Some)`:

```
victim live: account(Cash)=0  account(Cash, at)=0  trial_balance debit=0 | verify's batched sweep=7 (true 7)
victim after reboot: account(Cash)=7
replica1 live: 0 · replica2 live: 1 · balance Assets:A 1 USD -> ok on both
```

Two ~120-byte directives from an allowlisted peer (or two mutations from an API-key holder) zero any open
account's live balance on a replica of the attacker's choosing; `verify` says every assertion holds; a
reboot silently changes the number; two replicas holding the same directive set report different
financials. That breaks "same directive set ⇒ same state" (M-09's premise, C4/I7) at the layer operators
read. Not a panic — saturation is what T17 chose over `+=`. The precondition (amounts near 7.9 × 10²⁸,
visible in the journal) is why this is not rated higher, and why the user may re-rate it.

**Fix (M, T65):** either refuse at every ingress (local, remote, reconcile; quarantine at boot) any amount
whose mantissa exceeds ~10²² so every sum is exact, or accumulate in `i128` per `(account, currency,
scale)` and convert with checked arithmetic at read time, surfacing overflow as an error rather than a
number; fold the no-`at` path in canonical order. **Regression:** the proptest as written (random arrival
order vs `build` vs batched, with `±MAX` and mixed scales, checked at every prefix).

### H-18 — One 1 MiB body makes `validate_supply_entry` allocate ~195 MB and log ~55 MB: uncapped per-block `ParseError` accumulation on the wire path

**Where:** [union_merge.rs:152-154](crates/p2p/src/union_merge.rs#L152-L154) (`parse_file(&entry.economic_bean).map_err(|errors| … format!("{e:?}") … join("; "))`), [parse.rs:592-599](crates/ledger/src/parse.rs#L592-L599) (`errors.push` per block, no cap), [anti_entropy_alpn.rs:1156](crates/gl-node/src/anti_entropy_alpn.rs#L1156) (`warn!(%error, "invalid ALPN supply entry")`), [anti_entropy_alpn.rs:511](crates/gl-node/src/anti_entropy_alpn.rs#L511) (the serve loop's `Supply` arm applies *pushed* frames).

A body of `"x\n"` × 524,288 is 1 MiB, inside `MAX_ECONOMIC_BEAN_LENGTH`, and 524,288 directive blocks,
each failing `read_date`, each Debug-rendered at ~105 bytes into a `Vec<String>` that is then joined and
wrapped in `MergeError::ParseError` — after every frame cap, in the place T49's `BoundedSink` rationale
("a 16 MiB frame must not become a 16 MiB log line") stopped short of. `apply_supply_entries` logs the
whole string as one line. A fresh well-formed `id` per entry defeats the M-14 skip; the refusal cache
suppresses *Wants*, not pushes.

**Executed** (`B5-wire/fuzz merge`, release, counting allocator, re-run):

```
body = 'x\n'   x 512k (1 MiB)  peak 194,924,029 B (185.9x)  MergeError Display 55,463,434 B (52.9x)  246 ms
body = 'x\n\n' x 349k (1 MiB)  peak 138,356,367 B (131.9x)  Display 36,994,106 B (35.3x)
body = ' x\n'  x 349k (1 MiB)  peak 152,631,342 B (145.6x)  Display 44,278,581 B (42.2x)
```

Per 15 MiB Supply frame: 15 such entries ≈ 3 GB of sequential transient allocation and ~830 MB of log;
per peer, 32 connections × 32 MiB in-flight allow 32 such frames concurrently — ~6 GB transient peak and
32 × 55 MB log lines per round, repeatable to the 100k-request budget. 186× against the series' 4× bar,
from one allowlisted peer, unsolicited.

**Fix (S, T66):** at the wire boundary keep the first three errors plus a count, render each through a
`BoundedSink`-style 256-char truncation, and never `collect` the full vector (a `max_errors` variant of
`parse_file` for the remote path; the file loader legitimately wants all errors). Run the cheap refusals
(`is_content_id(entry.id)`, envelope key set, author allowlist, signature form) before the parse.
**Regression:** the `"x\n"` × 512k entry under `decode_memory.rs`'s counting allocator, asserting peak ≤ 4×
body and `error.to_string().len() < 1024`.

---
## 3. New findings — Medium

### M-35 — A crash between the compaction's rename and its journal removal bricks the next boot once `new canonical + old journal > 64 MiB`
[service.rs:1516-1517](crates/ledger/src/service.rs#L1516-L1517) (`persist_atomically` then `remove_journal`), [service.rs:1954-1955](crates/ledger/src/service.rs#L1954-L1955) (boot: `journal_budget = MAX − canonical_bytes`), [journal.rs:177-179](crates/ledger/src/journal.rs#L177-L179) (`length > budget` → `TooLarge` **before** parsing), [main.rs:190](crates/gl-node/src/main.rs#L190) (boot error → `exit(1)`). The append-path projection keeps `canonical + journal ≤ 64 MiB`, and the doc at :1503-1509 says the compact-then-delete window "is safe by construction because boot unions and dedups". But after the rename the new canonical is `≈ canonical + journal`, so the post-crash state is `canonical + 2·journal`, over the cap whenever `journal > (64 MiB − canonical)/2` — a ratio-triggered compaction on any canonical between ~32 and ~42 MiB, or the unconditional boot/shutdown compaction with any journal above that line. The window is the post-rename directory `sync_all`, exactly where a slow volume spends its time and where a container runtime's grace-period SIGKILL lands. **Executed** (`B1-commit/probe brick`, re-run): `pre-compaction: canonical=50100032 journal=10020780 (sum<=cap) · compaction OK · post-crash: canonical=60120032 journal=10020780 > cap · boot after crash: ERR ledger journal is 10020780 bytes (max 6988832) [LEDGER_JOURNAL] · boot with journal deleted: 60001 directives — journal was fully folded`. The same `TooLarge` fires on the runtime reload after a rename whose `remove_journal` failed (EPERM/EIO), so the caller is told the commit failed although it landed. **Fix:** boot's budget should be `MAX_LEDGER_FILE_BYTES` (the journal is already bounded at append time and the compacted file by `persist_atomically`); the message should say a journal older than the `.bean` may be a folded leftover. **Regression:** the `brick` fixture (`C + J > MAX`, `J ⊂ C`) must boot with `directive_count == boot(C alone)`.

### M-36 — The ledger-side file readers and the journal appender open whatever is at the path: a FIFO parks the writer holding the permit forever, unkillable by SIGTERM; a symlink is read through; a stream bypasses the cap
[journal.rs:291-306](crates/ledger/src/journal.rs#L291-L306) (`append_record`: `lstat` refuses only a **symlink**, then `open(O_WRONLY|O_APPEND|O_CREAT)` — on a FIFO with no reader this blocks *before* the post-open `is_file()` check can run), [journal.rs:168-184](crates/ledger/src/journal.rs#L168-L184) (`read_journal`: `metadata` then `std::fs::read`), [service.rs:218-226](crates/ledger/src/service.rs#L218-L226) (`read_ledger_file`: `metadata.len() == 0` passes the cap, `read_to_string` blocks or reads unbounded), [service.rs:1938](crates/ledger/src/service.rs#L1938) (`file_path.exists()` is true for a FIFO), [file_watcher.rs:108](crates/ledger/src/file_watcher.rs#L108) (sync `std::fs::read` on a runtime worker every 250 ms), [p2p_service.rs:898-926](crates/gl-node/src/p2p_service.rs#L898-L926) (key reader: `lstat` then `File::open` with neither `O_NOFOLLOW` nor `O_NONBLOCK` — a race, not a standing hole).

Four agents confirmed this independently, twice with the real binary. **Executed** (re-run): `append_record on FIFO journal: STILL BLOCKED after 3 s · boot with FIFO journal (isolated): STILL BLOCKED · boot with FIFO .bean: STILL BLOCKED · symlink journal (control): refused in 162 µs`; real `gl-node` with `mkfifo ledger.bean` → hangs after `ledger lock acquired`, lock held, no port bound, `rc=142`; `fifo-cap`: 73,482,240 bytes fed through a FIFO → `boot OK canonical_bytes=73482272 (cap 67108864)`; `symlink-bean`: the target's text is quarantined and the next compaction replaces the link with a regular `.bean` holding it.

Consequences: a FIFO at the journal on a ledger past `COMPACTION_MIN_CANONICAL_BYTES` parks the commit's blocking thread **holding the `WritePermit`** — every GraphQL mutation waits on the gate until its 408, every peer batch is never persisted, the watcher and the shutdown compaction hang, reads and `/health` stay green, SIGTERM's compaction waits forever (`BlockingPool::drop` has no timeout, vendored tokio `runtime/blocking/pool.rs:244-285`), and the restart parks in `read_journal` with no exit code for a supervisor. A FIFO at the `.bean` parks the next compaction-path `prepare` **under the ledger write lock**. T60 closed exactly this shape for the key file ("a FIFO can no longer block boot"); the ledger's two files and the watcher were not given the same rule. Actor (e) directory-writable — the class L-44/L-49 were fixed for — or a `mkfifo`/mount accident. Medium rather than High because it needs the same directory access L-44/L-49 rated Low; it is rated above them because the runtime consequence is a permanent, silent, un-terminable write wedge and a cap bypass. **Fix (T67):** one helper for every ledger-side open: `symlink_metadata` → require a regular file → `open` → `fstat` → require `is_file()` and `(dev, ino)` match; read through `handle.take(MAX + 1)`; with `libc` as a direct dependency (R-17) use `O_NOFOLLOW | O_NONBLOCK` and make the lstat/inode dance defence in depth. **Regression:** `mkfifo` at each of `.bean`, `.journal`, the key path; `boot`/`append_record`/`from_path` must return `Err` within the test's timeout; a 64 MiB + 1 stream → `ResourceLimitExceeded`.

### M-37 — Hand edits the reconcile refused, or never adopted, become loaded history by two routes, bypassing I3, H-06, L-26, L-02, the envelope stamp and L-11's signing
(a) **Recovery route, new with T51.** API-first ordering: `adopt_external_edits` → `reconcile_content` parse failure → `prepare` `Err` → `prepare_or_recover` → `recover_failed_commit` ([service.rs:3279](crates/ledger/src/service.rs#L3279)) → `boot`, which since L-45 **succeeds** on the unparsable file and loads every parseable block raw. Pre-L-45 that reload failed and memory was left as-is. **Executed** (`B2 e1b`, `e12`, re-run): a hand-typed transaction on never-opened `Assets:Vault` plus a broken line → first `append_transaction` = `PARSE_ERROR`; afterwards the DAG holds it with metadata `{}` (signer never called); the second write succeeds; the API transaction's `openledger-parents` names the raw one. A 1,200,530-byte body that `reconcile_file` had just rejected is in the DAG and on disk after the same sequence — the exact thing `validate_file_ingest_parity`'s doc says T51 closes. (b) **Rejected-only route, pre-existing.** `reconcile_file` ([:3668](crates/ledger/src/service.rs#L3668)), `reconcile_file_staged` (:3709) and the watcher ([main.rs:465](crates/gl-node/src/main.rs#L465)) re-persist only when `new_directives > 0`; the L-12 warning at :4159 says *"the canonical re-persist will drop them from the file"* but none runs. **Executed** (`e13`): watcher-path reconcile → `rejected=1`, warning printed, entry still on disk → restart → transaction on an unopened account loaded (boot applies no I3). Both are H-13's shape reached through a *refused* edit, and (a) also means **L-55** (a rejected entry's lamport moves the clock and stays on disk). **Fix (T61):** (a) falls out of H-14's fix (a parse failure then mutates nothing, so `prepare_or_recover` can return `Parse` without reloading); (b) set `force_compaction` when `rejected > 0`, or drop the claim in the warning. Tests: the `e1b`/`e12`/`e13` shapes.

### M-38 — Reconcile leaks one member of a planted cycle into the DAG; it becomes a head; the node's own later transactions are quarantined at the next boot (R-3, escalated)
`reconcile_content` uses only the DAG's I8 check ([dag.rs:304](crates/ledger/src/dag.rs#L304)), which passes the first cycle member because its partner is absent; `release_quarantined_now_in_dag` ([service.rs:4132](crates/ledger/src/service.rs#L4132)) then frees it from the quarantine; `heads_admissible_as_parents_of` ([dag.rs:411](crates/ledger/src/dag.rs#L411)) offers it to `stamp_transaction_envelope`; boot's Kahn scan ([service.rs:428](crates/ledger/src/service.rs#L428)) blocks it *and all its descendants*. **Executed** (`B2 e3`, re-run): planted A↔B → boot quarantines both → compact → an unrelated hand-added `open` → `reconcile_file`: `new=2 rejected=1`, quarantine now `[B]`, `heads = {A}` → `append_transaction(C)` → C's parents `[A]` → restart: quarantine `[A, B, C]`, C absent from the read model; C was signed and served in between. The node's own replicated transactions drop out of its balances on every restart until the cycle is hand-repaired, and peers holding C Want A, which this node no longer serves. R-3 said "no record is lost either way"; it covers file-resident descendants only. **Fix (S, T61):** run `directives_blocked_by_parent_cycles` over `file_directives ∪ quarantine` in `reconcile_content` and keep blocked ids quarantined (it is already O(N) hashes at boot). Test: the `e3` shape asserting the quarantine stays `{A, B}` and `heads` excludes A.

### M-39 — Near the 64 MiB cap, every remote batch that does not fit runs a full synchronous ledger reload **under the write lock**, once per tick per peer, forever (R-20 composed with anti-entropy)
[anti_entropy_alpn.rs:1281-1282](crates/gl-node/src/anti_entropy_alpn.rs#L1281-L1282) (`prepare_or_recover(&mut svc, false)` with `svc` the ledger **write guard**, dropped on the next line), [ledger_commit.rs:353-370](crates/gl-node/src/ledger_commit.rs#L353-L370) (every prepare error except `CommitInFlight` → inline `recover_failed_commit` = `boot`). The L-43 off-lock recovery was applied to the *commit*-failure arm only. Prepare fails deterministically on the append arm when `canonical + journal + record > MAX` ([service.rs:2989-2999](crates/ledger/src/service.rs#L2989-L2999)); a 256-entry batch is ~50 KB; the batch is rolled back, nothing is cached (`batch_durable = false`), and `compute_want` re-wants the identical ids next tick. **Executed** (`B3-antientropy/nearcap`, release): canonical 66,362,358 B + journal 733,787 B (headroom 12,719 B); 256 staged opens → `prepare_commit: Err(… would reach 67143471 bytes …) in 643 µs` → `recover_failed_commit took 3.65 s; directives 305714 → 305458` (11.7 s in a debug build). With a 5 s tick and N peers whose adverts contain anything the node lacks, the write lock is held ~3.6 s × N per 5 s; readers queue behind the write-preferring lock; CPU pinned. Actor (c), or organic end-of-life. **Fix (M, T69):** route prepare failures through the L-43 shape (the permit is already held); ask the service for its append headroom before staging and skip the batch with a `warn!` and a *transient* per-peer backoff (not the refusal cache). **Regression:** near-cap fixture, one 256-entry `apply_supply_entries`, assert the `RwLock` is never held > 100 ms and a second call does not re-stage.

### M-40 — No server-side anti-entropy session deadline: one connection may live 100,000 × `io`, so a few peers pin every inbound slot (M-06's server half)
`serve_anti_entropy` uses only the per-frame `io` ([anti_entropy_alpn.rs:353](crates/gl-node/src/anti_entropy_alpn.rs#L353), `accept_bi` :422, reads :478) and `max_requests_per_connection` (:464); `timeouts.session` is consumed solely by the client (`SessionBudget::new`, :245) — M-28's "client mirrors the server" was never mirrored back. A client sending one ~30 B `Announce` (ignored, 1 unit) every 29 s holds a serve task and an M-16 slot for 100,000 × 29 s ≈ 34 days; at 32 per peer of 256 global, one compromised peer pins 12.5% of the slots indefinitely and eight colluding peers pin all of them, after which every other peer is refused at `accept`. Separately, each 40 B `HaveHeads{more:false}` costs a full O(N) local advert under the read lock (~36 MB out on a 300k-directive ledger), bounded per connection by L-01's units but not across free reconnects. Reasoned; corroborated by three passes. **Fix (S/M, T70):** a server `SessionBudget` (deadline clamps `accept_bi` and every frame's `io`; close with a distinct code) and a per-peer accept token bucket in `ConnectionLimiter::try_acquire`. Test: a client sending `Announce` every `io/2` past `session` is closed.

### M-41 — Pre-limit and unbounded log echo on both edges: attacker-controlled header bytes are logged outside the rate limiter; attacker-chosen ids, keywords, envelope keys and whole frames are logged unbounded on the ALPN intake path
**HTTP:** [request_guard.rs:84,105-108,130](crates/gl-node/src/request_guard.rs#L84) (`warn!(%host …)`, `content_type = other`, `warn!(%origin …)`) and the layer order at [main.rs:719-744](crates/gl-node/src/main.rs#L719-L744) put the guard **outside** the rate limiter on both routes (deliberately, so a bad Host never reaches the schema). hyper's only header ceiling is the 417,792-byte default (`hyper-1.11.0 proto/h1/io.rs:23`); `serve_hardened` never sets `max_buf_size`. **Executed** against the real node: each foreign-Host / oversized-Content-Type / oversized-Origin request was correctly refused (403/415) and produced one warn line carrying the ~300 KB value; log growth 100–190 MB/s from one 8-connection client; ~13k small-header refusals/s at ~190 B/line. Behind a real terminator the per-line size is capped by the proxy (8–32 KB), the line rate is not. **ALPN:** [union_merge.rs:173-176](crates/p2p/src/union_merge.rs#L173-L176) (`ContentHashMismatch { claimed: entry.id.clone() }`, no length check), :305-307 (`"unsupported envelope key: {key}"`), [parse.rs:723,758](crates/ledger/src/parse.rs#L723) (`"Unsupported directive: '{keyword}'"` echoes the whole token), [anti_entropy_alpn.rs:996](crates/gl-node/src/anti_entropy_alpn.rs#L996) (`warn!(peer, ?other, …)` Debug-prints an entire non-Supply frame), all reaching `warn!(%error)` at :1156 and siblings. **Executed:** `ContentHashMismatch` Display 2,097,258 B for a 2 MiB id; 15 MiB id → 15,728,746 B; 15 MiB envelope key → 15,728,684 B; a `HaveHeads` page Debug 557,118 B. Compare `elide_decode_error`/`BoundedSink` (256 chars) and `check_advert_ids` (logs only the length) — the same threat, applied only there. Default logging is `tracing_subscriber::fmt` at `info` to stdout with no line cap ([main.rs:126-131](crates/gl-node/src/main.rs#L126-L131)); the compose file configures no log rotation. **Fix (S, T66):** throttle the pre-auth guard `warn!`s the way `PerIpConnections::should_log_refusal` does, truncate echoed header values, set `http1().max_buf_size()`; make `BoundedSink` a `pub` bounded formatter and use it at every `warn!(%error …)` on the intake/drain path; carry `claimed` only when `is_content_id`, else its length; replace `?other` with a variant name; excerpt the keyword as `reject_trailing_content` already does. Tests: `to_string().len() < 512` for each shape; N foreign-Host refusals emit ≤ K lines.

### M-42 — With `watchLedgerFile: true` the watcher reads and SHA-256s the entire `.bean` every 250 ms whether or not anything changed
[file_watcher.rs:90-112](crates/ledger/src/file_watcher.rs#L90-L112) (the `stat` gates only the cap; `std::fs::read` + `Sha256::digest` run on every call), [main.rs:412-422](crates/gl-node/src/main.rs#L412-L422) (`tokio::time::interval(250 ms)`, default `MissedTickBehavior::Burst`, `from_path` called on a runtime worker). **Executed** (`B8 watch-cost`, release, re-run): `file=59 MiB  FileState::from_path per tick = 215.8 ms → at 4 Hz 86% of one core, 240 MiB/s hashed, forever, with no change to the file`; debug 4.17 s/tick, at which point `Burst` runs ticks back to back — 100% of a blocking-in-async worker for the life of the process. T52's "stats before reading" describes the cap, not change gating. **Fix (S, T69):** keep the last `(len, mtime, ino)`; read+hash only when the tuple changed or every Nth tick (to preserve the same-size/same-mtime guarantee); run the read in `spawn_blocking`; `MissedTickBehavior::Delay`. Test: two consecutive polls of an unchanged file perform one read.

### M-43 — R-18 confirmed end to end: a mid-file journal header whose length exceeds the remainder silently drops every later record, the startup compaction erases them, and the warning blames a crash that did not happen
[journal.rs:224-233](crates/ledger/src/journal.rs#L224-L233) (over-long claim → torn tail, `break`), [service.rs:1957-1966](crates/ledger/src/service.rs#L1957-L1966) (warning: *"the node crashed mid-append; the torn record is DROPPED (its commit never reported success)"*), [service.rs:2308](crates/ledger/src/service.rs#L2308) (`force_compaction`), [main.rs:251](crates/gl-node/src/main.rs#L251) → `remove_journal`. **Executed three times independently** (A5, A4, B8; re-run): three appended, acked records; the second header's length rewritten (`999999`, `10^23`, `u64::MAX`, or simply `86 → 986`) → `read_journal = Ok { payloads: 1, torn_tail_bytes: … }`, no error; boot holds 903 of 905 directives; `compact()` writes a `.bean` without `Assets:Two`/`Assets:Three` and unlinks the journal — permanently, with no forensic trace. Control: the same header edited to a length that *fits* fails the SHA check → `Corrupt` → boot refuses. So the policy boundary is "does the bad length happen to overrun EOF", not "was this a crash". Not reachable by a crash (executed: no `Append` is ever chosen while a torn tail is outstanding — `force_compaction` is cleared only by that compaction's receipt); reachable by one flipped digit or anyone who can write the journal. **Decision (recommended: fail closed):** classify as torn only when the remainder contains no later `\n;;olj ` line and the claimed length is within the journal budget — a node-written payload can contain neither (control characters are refused in every string field); otherwise `Corrupt`, refuse boot, name the offset. And after any boot that saw a torn tail, have the compaction rename the journal to `<journal>.torn-<unix-ts>` instead of unlinking it, so bytes are never destroyed on the strength of a heuristic. Fix the warning text. Tests: the exact fixture → `Err(Corrupt)`; a real torn tail → `.torn-*` sidecar left behind.

### M-44 — A crash-time zero-filled journal tail is classified `Corrupt` and refuses boot (PLAUSIBLE — reasoned with a byte-level reproduction, not executed on a real filesystem)
[journal.rs:237-244](crates/ledger/src/journal.rs#L237-L244). Filesystems that journal metadata before data (XFS; ext4 `data=writeback`) can, after a power loss between `write_all` and `sync_all` ([journal.rs:330-331](crates/ledger/src/journal.rs#L330-L331)), expose the appended region as NUL bytes at the new length. If the header's block reached disk and the payload's did not: complete header, right length, wrong hash → `Corrupt` → boot `?` → `exit(1)`, on a file the node wrote, with no attacker. The module doc (`journal.rs:60-64`) states this "cannot be produced by a crash". Byte level: `probe zero-fill` → `read_journal -> Err: corrupt at byte 106`, `boot -> Err`; an all-zero record (header too) is correctly torn. **Fix (S, T68):** a **final** record whose payload contains a NUL byte (impossible in a node-written payload) is a torn tail, not corruption. Test: the `zero-fill` fixture boots with a torn warning.

### M-45 — The `journal` resolver is weighted as "one scan" but costs O(limit × postings) in CPU and materialized memory (PLAUSIBLE — reasoned with measured constants)
[query.rs:195-196](crates/gl-node/src/graphql/query.rs#L195-L196) (`complexity = HEAVY_RESOLVER_COMPLEXITY`, ignoring `limit` and `child_complexity`), [query.rs:11](crates/gl-node/src/graphql/query.rs#L11) (`MAX_JOURNAL_LIMIT = 10_000`), [query.rs:383-388](crates/gl-node/src/graphql/query.rs#L383-L388) (`domain_txn_to_graphql` clones the whole transaction and re-hashes it per row although `IndexedTransaction.txid` is at hand), `MAX_POSTINGS_PER_TRANSACTION = 1000`; async-graphql resolves Query root fields **concurrently**, so all aliases' `Value` trees are live at once. Eight aliases of `journal(limit: 10000) { postings { … } }` cost exactly 4096 and are admitted; against ~3,600 peer- or API-planted 1,000-posting transactions that is ~3.6M posting `Value` objects (~1.8 GB) per alias, ~14 GB per request, under the read lock, 60 requests/min. Honest ledgers are fine (~120 MB/request). **Fix (S, T69):** `complexity = "(clamp_journal_limit(limit) / 100).max(1) * (1 + child_complexity)"` or a per-request row cap across aliases; pass `txid` instead of re-hashing. **Regression:** eight aliased `journal(limit: 10000)` with a postings selection is refused.

---
## 4. New findings — Low

- **L-55 — Reconcile applies the adopted lamport before validation.** [service.rs:3991](crates/ledger/src/service.rs#L3991) `self.lamport_clock = next_lamport` precedes `enforce_resource_limits` (:4011), `validate_transaction`, the second bean-cap check and `dag.insert`, each of which `continue`s on failure with the clock moved. The ordering T46(d) fixed in `stage_remote_directive` (:4753-4757) was left unfixed on the third ingest path. **Executed:** a hand-appended unbalanced transaction with `openledger-lamport: "5000"` → `reconcile: new=0 rejected=1`, clock `3 → 5000`, next authored envelope `5001`, poison still on disk (M-37b). Bounded by `checked_lamport`; needs file write. Fix: assign only in the `Inserted` arm.
- **L-56 — The boot error for a padded signature domain echoes it verbatim.** [config.rs:1063-1065](crates/gl-node/src/config.rs#L1063-L1065) (`got "{value}"`), surfaced by `error!(%error)` at [main.rs:143](crates/gl-node/src/main.rs#L143). The padded value differs from the live join credential / signature domain by one byte; three other sites deliberately redact it (M-32) and L-50 applied "never echo" to `apiKey`. **Executed** live: `"swarmTopic": "acme/secret-join-topic-77 "` → `ERROR … got "acme/secret-join-topic-77 "`. Fix: `crate::auth::redact(value)` or the byte offset; assert non-echo in the existing test.
- **L-57 — A directory planted at the predictable `<ledger>.bean.tmp` wedges every full rewrite until an operator removes it.** [service.rs:160-167](crates/ledger/src/service.rs#L160-L167): `AlreadyExists` → `remove_file` → `EPERM`/`EISDIR` → every compaction, reconcile and the startup compaction fail (`IO: Operation not permitted`); appends still land until a forced compaction or the cap. A stale regular file, FIFO or symlink at `.tmp` **is** unlinked and retried (executed) — no crash-leftover brick. Fix: randomised temp name (`.tmp.<pid>.<nonce>`) and a boot-time sweep under the lock, or `remove_dir` on that arm.
- **L-58 — The journal's owner, mode and link count are never checked, so a pre-planted or hard-linked journal receives every appended commit in an attacker-readable file.** [journal.rs:291-328](crates/ledger/src/journal.rs#L291-L328): `mode(0o600)` applies only on create; the post-open check requires `is_file()` and the same `(dev, ino)`, which a regular file or a hard link satisfies. **Executed:** `append into pre-planted journal: mode now 644, contains record: true · hard-linked journal: elsewhere contains record: true (nlink=2)`. The shipped container runs as `glnode` with `/data` 755 owned by it, so the directory-writable class is thin there; on a shared host it is the L-44 class. Fix (T67): `fstat` → `uid == geteuid()`, `nlink == 1`, `mode & 0o077 == 0`, else `refuse_non_regular_journal`.
- **L-59 — `ledger_lock::acquire` follows a symlink at `<ledger>.bean.lock`.** [ledger_lock.rs:89-101](crates/gl-node/src/ledger_lock.rs#L89-L101): `create(true)` without `create_new`/`O_NOFOLLOW`, then `try_lock`. **Executed:** the flock landed on the symlink's target (a second flock on it → `WouldBlock`). Re-pointing the link between two starts admits two nodes onto one ledger — the M-17 silent-loss shape; a FIFO target defeats the intent. Fix (T67): `symlink_metadata` refusal + `fstat` `is_file()`/uid, or lock a directory fd.
- **L-60 — Unsolicited Supply entries let a peer fill its own refusal quota, and four peers evict everyone's.** [anti_entropy_alpn.rs:1140-1158](crates/gl-node/src/anti_entropy_alpn.rs#L1140-L1158) records an intake refusal for **every** entry with no check that `entry.id` was Wanted; `fetch_want_chunk` passes the whole reply (:1007). **Executed:** 16 frames × 256 junk ids → `record(P, real) = false` (P has opted out of L-34); four such peers reach the 16,384 global cap and `pop_oldest` FIFO-evicts honest peers' entries. Each unsolicited entry also costs a full parse/verify. Fix (T66): filter to the outstanding `remaining` set before `apply_supply_entries`.
- **L-61 — The per-IP cap keys on IPv6 /64 and its docs omit the caveat the rate-limiter module states; refused connections have no backoff.** [http_server.rs:73-79](crates/gl-node/src/http_server.rs#L73-L79), [README.md:462](README.md#L462) vs [rate_limit.rs:10-19](crates/gl-node/src/rate_limit.rs#L10-L19): a routed /48 is 65,536 keys × 64, far past the 1024 global cap, so the cap constrains a single-IPv4 or single-/64 attacker only. **Executed:** with 8 same-IP holders at cap, a 9th connection was accepted and reset with nothing read and the global permit released (correct); ~2,900 accept+refuse cycles/s cost the server ~0.15 CPU-s/s — cheap, but `ACCEPT_ERROR_BACKOFF` applies only to `accept()` errors. Fix: align the wording; optional short per-IP admission cooldown once over cap.
- **L-62 — A mid-file byte-order mark bricks boot, or admits what the whole-file parser refused.** `split_ledger_blocks` → `salvage_unparsable_blocks` ([service.rs:384](crates/ledger/src/service.rs#L384)) parses each block with `parse_file`, which strips a **per-block** BOM ([parse.rs:546](crates/ledger/src/parse.rs#L546)); the whole-file pass strips only offset 0. **Executed:** a `cat`-style concatenation with `U+FEFF` before a mid-file header → as the sole defect, whole-file fails, every block parses, `refused.is_empty()` → the L-45 fail-closed arm → boot `Err` → `exit(1)`; with any other bad block present, the BOM'd directive is loaded. Fix: salvage without BOM stripping, or refuse a block starting with `U+FEFF`.
- **L-63 — `VerifyReport.errors` is one entry per dangling *edge*.** [verify.rs:164](crates/ledger/src/verify.rs#L164), [query.rs:307](crates/gl-node/src/graphql/query.rs#L307). **Executed:** 4,000 transactions × 256 dangling parents → `errors = 1,024,000`, `to_string` 166 MiB, ×2 `verify` aliases per request. File-writer only (peers cannot create dangling parents — `require_parents: true`). Fix: cap at the first 1,000 plus a `truncated` count; report per node.
- **L-64 — After any L-13 reload every write is a forced compaction, so a file whose canonical spelling exceeds the cap wedges every write, reloading on each attempt (R-2, clarified; B1-C3).** Boot sets `canonical_is_current = false` ([service.rs:2300](crates/ledger/src/service.rs#L2300)), `prepare` turns that into `must_rewrite` (:2944-2947), the rewrite fails at `persist_atomically` (:119), the failure reloads — and the append-arm projection is never consulted again. **Executed:** a healthy 77 KB ledger writes `Append`; after one `recover_failed_commit()` the next prepare is `Compact`; canonical form is ~3% larger than a dense hand-written file (`10,000 open lines: 350,000 → 359,999 B`), so a 62.5–64 MiB dense file boots and never compacts. Loud, operator-only, no loss; each attempt is a full reload (R-20). Fix: keep a margin between the read cap and the write cap, or warn at boot when `compaction_text().len() > MAX`; do not force a compaction merely because a reload happened.
- **L-65 — The L-39 byte budget charges the frame body only.** `grow_to(capacity)` matches `reserve_exact` exactly (no 2× from the growth policy — verified against the doubling clamped to `len` at [anti_entropy_alpn.rs:1881-1888](crates/gl-node/src/anti_entropy_alpn.rs#L1881-L1888)), but the decoded `Vec<SupplyEntry>` (~1×), ciborium's `Content` tree (up to 4×, R-4) and the staged `Vec<Directive>` are uncharged while the reservation is alive, so the real ceiling under the 256 MiB budget is ≈ 0.5–1.5 GiB. Constant-factor; document or scale the budget by the measured multiple.
- **L-66 — The GraphiQL page loads unpinned CDN scripts.** [graphql/mod.rs:107](crates/gl-node/src/graphql/mod.rs#L107) → vendored `async-graphql-7.2.1/src/http/graphiql_v2_source.hbs:28-51`: `react@18` **development** builds and `graphiql@4` (floating major) from `unpkg.com`, `crossorigin` but no `integrity`. Loopback-only by config and off by default, but the operator's GraphiQL tab is a same-origin, unauthenticated session on the node; whoever controls that CDN response controls mutations. Pin a version or self-host.

## 5. New informational

- **`OPTIONS` bypasses every layer and returns the route's `Allow` header** (tower-http `cors/mod.rs:678-690` short-circuits any OPTIONS with no `Access-Control-Request-Method` check; axum sets `Allow` on the fallback). Live: `OPTIONS /graphql` with `Host: evil.example` → `200`, `allow: GET,HEAD,POST` with GraphiQL on, `GET,HEAD` for `/health`. A rebound page can read that: a fingerprint ("gl-node here, GraphiQL on/off"), nothing more. `auth.rs:93`'s OPTIONS branch is unreachable.
- **`allowedHosts` entries with a port or trailing dot pass validation and then reject every request** (`config.rs:849-871` checks `://`, `/`, whitespace; the error text and README say "no port"). Live: entry `ledger.example.com:443` → both spellings `403`, boot said nothing. Fail-closed misconfiguration; run entries through `split_authority`.
- **`GL_NODE_API_KEY` with `auth.enabled: false` is silently discarded** (`config.rs:713-725`); public binds are unaffected. Warn.
- **Host-side `/health` monitors behind the Docker bridge share one 120/min bucket** (all host traffic arrives from the gateway; `trustedProxies` ships empty). The in-container `HEALTHCHECK` dials `127.0.0.1` ([health.rs:99-104](crates/gl-node/src/health.rs#L99-L104)) and so has its own bucket — it cannot be starved by host-side tooling, contrary to a first reading.
- **`decode_checked` alone admits a 16 MiB non-Supply frame** (`{"type":"want","v":1,"ids":[],"z":"<16 MiB text>"}` decodes `Ok` at 1.57×); the 1 MiB `NON_SUPPLY_FRAME_CAP` lives only in ALPN `read_frame`. Unreachable in production — the gossip builder's `DEFAULT_MAX_MESSAGE_SIZE` is 4096 (`iroh-gossip-0.101.0/src/proto.rs:69`). Defence in depth.
- **Accepted, signed, non-canonical envelope spellings**: `"0007"` lamport, Unicode whitespace (U+2028/U+00A0/U+3000 — `trim` strips it, `is_control` does not cover it) around parent ids, unsorted/duplicated parents, uppercase signature hex. Executed: all `Ok`. Same content id and clock; envelope-byte divergence between replicas only. Optional canonical-form rule with a format bump.
- **`validate_supply_entry` orders expensive work first**: a 1 MiB body is parsed, re-serialised and hashed before the envelope key set, `is_content_id(entry.id)`, the author allowlist and the signature form are examined (`union_merge.rs:143-176` vs `:303-320`). CPU, not bypass; matters for H-18's fix.
- **`AccountClosed` drain churn** (pre-existing M-09 interplay): `has_open` is true for an opened-then-closed account, so every `drain_orphans` pass releases, re-validates and re-buffers every `AccountClosed` waiter, twice via the `attempted` set. Bounded by the 64 MiB orphan budget.
- **A parent may name a non-transaction directive id** (`dag.rs:183` checks `nodes`, not transaction nodes) — executed: an `open` gains a child. `0 AAPL @@ 100 USD` and zero-posting transactions are accepted (beancount refuses both). `trial_balance` nets currencies into one `Decimal` per account. `transaction(txid)` re-hashes per row like `journal`.
- **Boot order residual:** the startup compaction (`main.rs:251`) and the P2P tasks (`:358-365`) run before `set_signer` (`:392`) — H-13's fix must move the signer first regardless.
- **`Origin: http://localhost:p` is accepted with `Host: 127.0.0.1:p`** (any allowed host + equal port) — exploitable only if a different service on another loopback address shares the port; preflight still blocks JSON POSTs. Document rather than tighten.
- **`remove_journal` failure after a successful rename** (sticky dir, foreign-owned journal, `chattr +i`) → the commit reports `Err`, the reload from disk *includes* the write → "error but durable": a retrying client double-books. Worth a distinct log line. Both directory `fsync`s swallow errors (`service.rs:204`, `journal.rs:376`). `finish_recovery`'s reload-failure arm leaves `force_compaction` stale (cheap hardening: set it). The journal hash is an unkeyed checksum, not the integrity guarantee `journal.rs:66-69` describes.
- **Test-net notes:** M-28's client frame counter (`frames_left`) has no test (G-1); `h2c_upgrade_header_is_ignored` passes with M-22 reverted (the preface test is the discriminating one); the two async h11 tests pass with the `Drop` guard removed (claim 1 is pinned separately by `h11_dropping_a_prepared_commit_releases_the_in_flight_flag`); `finish_commit`'s generation-mismatch arm is unpinned; `l35_the_snapshot_does_not_survive_a_reload` passes on the size key alone; `LEGAL_ENVELOPE_VALUE_BYTES`/`LEGAL_SUPPLY_ENTRY_FRAMING_BYTES` in `protocol.rs` are restated, not aliased, and untested — a drift silently voids the coupling assert; the `const { assert! }` at `query.rs:514` guards the test build only; the tracker cites `batch_path_is_byte_identical_to_per_entry_path` for L-33's byte-identity but the proof is p2p's `test_build_supply_is_identical_to_collect_then_truncate`; `MergeError::CycleDetected` is never constructed in production.
- **`validate_body_names` still does not re-check currencies; local writes still do not drain the orphan buffer; the I8 budget's `HashSet` seed-order dependence is still present** — all harmless with the quarantine in place, all unchanged from 09/22 §5.
- **An unparsable journal payload is quarantined with a line number relative to the combined text and `file=<.bean>`**, and migrates into the canonical tail on compaction. No loss; cosmetic.

---

## 6. Dependencies, supply chain, and verification runs

**`cargo audit`** (v0.22.2, DB 1,264 advisories, 499 locked crates): **exit 0**; sole output is the allowed warning RUSTSEC-2024-0436 (`paste` 1.0.15, unmaintained; build-time proc-macro via `netdev`'s android-extra feature). `.cargo/audit.toml` ignores exactly RUSTSEC-2026-0235 (`rkyv` 0.7.46) with reachability evidence and a retire condition; `cargo tree -i rkyv -e all --target all` still prints nothing. Lockfile at HEAD: rustls **0.23.45**, rustls-webpki **0.103.15**, h2 **0.4.19**, lru **0.18.4**, chacha20 **0.10.2** — the four T56 bumps; `h2` remains compiled (hyper-util `server-auto`; iroh → hickory) but is unreachable on the port. No new advisory for any locked crate since 09/22.

**Lockfile provenance:** 499 packages — 495 `registry+https://github.com/rust-lang/crates.io-index`, 4 workspace path crates, **zero** git sources. Two Ed25519 stacks unchanged (`ed25519-dalek` 2.2.0 + 3.0.0). Toolchain rustc 1.97.1; `rust-version = "1.91"`; README says 1.91+.

**CI** (`.github/workflows/ci.yml`): `--locked` on both the Clippy and the Test step (L-46 closed); `permissions: contents: read`; `persist-credentials: false`. Pins re-verified online with `git ls-remote`: `actions/checkout` `11d5960…` = `refs/tags/v4.4.0` ✔ · `Swatinem/rust-cache` `6323deb…` = `v2.9.2^{}` ✔ · `rustsec/audit-check` `69366f3…` = `refs/tags/v2.0.0` ✔ · `dtolnay/rust-toolchain` `4360b52…` still not an advertised ref (stable head is now `6bed076`), still the 2026-08-04 "toolchain: stable" commit documented at `ci.yml:25-27` — not a finding.

**`unsafe`:** exactly one non-test occurrence in production code, the `geteuid` FFI declaration at `p2p_service.rs:1042` (R-17); `libc` 0.2.189 is compiled into `gl-node` transitively (tokio/mio; iroh → hickory → system-configuration) and not a direct dependency.

**Test suite at HEAD:** `cargo test --workspace --locked` — **987 passed, 0 failed, 0 ignored** on a quiet machine before the audit started (344 + 8 + 425 + 10 + 171 + 3 + 5 + 21; gl-node lib 54 s) and again after all passes completed (gl-node lib 108 s under the last agent's fuzz load; no failures). Every named regression test in §1 was additionally run in isolation by the re-verification passes (22 for the Highs; 105 for the HTTP tier; 23 + 27 + 17 for the Lows; 13 for M-23; all green). The repository is unchanged except for this file.

---

## 7. Consolidated open-findings register

Everything open as of this audit. IDs are stable across the 09/01, 09/02, 09/22 and 09/22-v2 reports; new IDs continue the numbering.

| ID | Sev | One-liner | Origin |
|---|---|---|---|
| **H-12** | High | H-07 residual: ceiling checked on three quantities; one peer directive → one silent unreplicable record per victim, then a restart brick; boot warning misses it; remedy undone by the next tick (R-1 re-rated) | **09/22-v2** |
| **H-13** | High | The supported stop-edit-start workflow loads hand edits as envelope-less, unsigned history; the node's later history is orphaned on every peer | **09/22-v2** |
| **H-14** | High | A failed reconcile records the broken file as the baseline; the next commit silently overwrites the operator's edit (watcher on) | **09/22-v2** |
| **H-15** | High | `rm`/`mv` of the `.bean` under a running node → recovery boot creates an empty ledger and installs it over memory | **09/22-v2** |
| **H-16** | High | A peer's 257 parentless transactions make the victim's own next append over-cap: refused everywhere, quarantined from its own DAG at reboot; repeats | **09/22-v2** |
| **H-17** | High | Order-dependent (saturating) balance accumulation: a peer erases an honest posting from a chosen replica's live reports; `verify` blind; replicas disagree | **09/22-v2** |
| **H-18** | High | Uncapped per-block parse-error accumulation on the wire: 186× allocation and a 55 MB log line per 1 MiB entry | **09/22-v2** |
| H-01 | High→Low | *Partially closed.* `/health` closed; loopback API key deferred; `OPTIONS` fingerprint (§5) | 09/01 |
| M-06 | Med | *Partially closed.* Client bounded; server half → M-40; cross-peer cap R-5 | 09/01 |
| M-09 | Med | *Partially closed.* Remote-close admission order-dependent (T45) | 09/01 |
| M-10 | Med | *Interim only.* T45 Facet A | 09/01 |
| **M-35** | Med | Compaction crash between rename and journal removal → boot refuses the journal as too large (`C + 2J > 64 MiB`) | **09/22-v2** |
| **M-36** | Med | Ledger-side readers/appender open whatever is at the path: FIFO wedge holding the permit, boot hang, cap bypass, symlink read-through | **09/22-v2** |
| **M-37** | Med | Refused / recovery-loaded hand edits become history without any guard (two routes) | **09/22-v2** |
| **M-38** | Med | Reconcile leaks a cycle member into the DAG; the node's own later transactions are quarantined at reboot (R-3 escalated) | **09/22-v2** |
| **M-39** | Med | Near the cap, every non-fitting peer batch reloads the ledger under the write lock, per tick per peer (R-20 composed) | **09/22-v2** |
| **M-40** | Med | No server-side anti-entropy session deadline; slot pinning by a few peers | **09/22-v2** |
| **M-41** | Med | Pre-limit / unbounded log echo on the HTTP guard and the ALPN intake path | **09/22-v2** |
| **M-42** | Med | Watcher reads + hashes the whole `.bean` every 250 ms regardless of change | **09/22-v2** |
| **M-43** | Med | R-18 confirmed: mid-file over-long journal header silently drops later records; compaction erases them; warning blames a crash | **09/22-v2** |
| **M-44** | Med | Crash-time zero-filled journal tail classified `Corrupt` → boot refusal (plausible) | **09/22-v2** |
| **M-45** | Med | `journal` resolver weight ignores `limit` and child complexity (plausible) | **09/22-v2** |
| L-23 | Low | *Partially closed.* `meshId` still opt-in (R-9) | 09/02 |
| L-35 | Low | *Partially closed.* New id APIs have zero callers (R-19) | 09/22 |
| L-43 | Low | *Partially closed.* Prepare-failure reload still under the lock (R-20 → M-39) | 09/22 |
| **L-55…L-66** | Low | Twelve new Lows — see §4 | **09/22-v2** |
| L-06 | Latent | `\|`-delimited signature message — injective at HEAD (T57); length-prefix at T45 Facet B | 09/01 |

**Closed this audit (44):** H-08, H-09, H-10, H-11 · M-16, M-19, M-20, M-21, M-22, M-23, M-24, M-25, M-26, M-27, M-28, M-29, M-30, M-31, M-32, M-33, M-34 · L-01, L-02, L-29, L-33, L-34, L-36, L-37, L-38, L-39, L-40, L-41, L-42, L-44, L-45, L-46, L-47, L-48, L-49, L-50, L-51, L-52, L-53, L-54. **Residuals closed:** R-11, R-12, R-21. **Residuals re-rated:** R-1 → H-12; R-3 → M-38; R-18 → M-43; R-20 → M-39; R-2 → L-64; R-4 → Info.

---

## 8. Remediation backlog

Task numbering continues from T60. Effort: S = <½ day, M = ~1–2 days. Every task keeps the campaign's
rule: revert the fix → the named test fails → restore, and record residuals in the tracker.

### Tier 1 — ship-blockers

**☐ T61 — One file path (H-13, H-14, M-37, M-38, L-55, L-62) — M**
Change: (a) `reconcile_content` parses first and commits `last_file_hash`/`canonical_bytes`/`canonical_marker`/`canonical_is_current` only on success; (b) `prepare_or_recover` returns `Parse` without reloading (nothing was mutated); (c) boot treats a directive with no `openledger-author`/`-lamport` as operator input, not history: route it through the adoption path (stamp, parents, sign) after the signer is installed and before the startup compaction — or quarantine it with an "unsigned, will not replicate" banner; (d) `main.rs` installs the signer before the first compaction and before the P2P tasks; (e) a reconcile with `rejected > 0` forces the compaction the warning promises; (f) run the Kahn pre-scan over `file_directives ∪ quarantine` in reconcile; (g) assign the reconcile lamport only in the `Inserted` arm; (h) salvage without per-block BOM stripping. Files: [service.rs](crates/ledger/src/service.rs) (`boot`, `reconcile_content`, `reconcile_file_staged`, `salvage_unparsable_blocks`), [ledger_commit.rs](crates/gl-node/src/ledger_commit.rs) (`prepare_or_recover`), [main.rs](crates/gl-node/src/main.rs), README §Editing. Verify: the H-13 probe asserts author + signature after boot and peer acceptance; the H-14 `e1` shape asserts the next write returns `PARSE_ERROR` and both hand lines survive; `e1b`/`e12`/`e13`/`e3`/`e7` shapes.

**☐ T62 — Recovery must never install an emptier ledger (H-15, M-35, L-64) — S**
Change: `adopt_external_edits`/`reconcile_file_staged` treat `NotFound` as nothing-to-adopt; `boot` refuses (or warns loudly) when the `.bean` is absent but a journal or `.lock` exists; every L-13 reload logs before/after counts and refuses to install a rebuild holding fewer directives than memory unless asked; boot's journal budget becomes `MAX_LEDGER_FILE_BYTES`; a reload does not by itself force a compaction. Files: [service.rs](crates/ledger/src/service.rs) (`boot`, `adopt_external_edits`, `finish_recovery`), [journal.rs](crates/ledger/src/journal.rs). Verify: `rm-bean` → `Ok`, four on disk; `brick` fixture boots; a dense 63 MiB file boots and compacts.

**☐ T63 — The ceiling as one rule (H-12) — S, plus a decision**
Change: stamp refuses `next + 1 >= CEILING`; wire requires `value + 1 < CEILING`; boot warns at `clock + 1 >= CEILING`; `max_lamport` counts inserted directives only unless authored by this node; `LamportCeiling` names the author and the mesh-wide remedy. **Decision:** the adoption ratchet (bound per-directive advance, with an explicit escape for a long-offline replica). Files: [service.rs:929-934,2231,2088,3969,4678](crates/ledger/src/service.rs#L929), [union_merge.rs:289-292](crates/p2p/src/union_merge.rs#L289). Verify: the `h07proof` shape ends in peer acceptance; the restart half asserts the warning at `CEILING-1`.

**☐ T64 — Bounded parent choice (H-16) — S, plus a decision**
Change: cap stamped parents at `MAX_PARENTS` (sorted prefix); `validate_parent_fan_in` before the local insert. **Decision:** per-author unmerged-head bound on the remote path. Files: [service.rs:2746-2748,2479](crates/ledger/src/service.rs#L2746). Verify: `heads_inflation` shape → local directive passes fan-in, peer accepts, reboot quarantines nothing.

**☐ T65 — Exact, order-independent balances (H-17) — M, plus a decision**
**Decision:** magnitude cap at every ingress (~10²² mantissa; quarantine at boot) versus `i128` accumulation per `(account, currency, scale)` with checked conversion at read time. Either way fold the no-`at` path in canonical order and make `verify` and live reports agree by construction. Files: [read_model.rs](crates/ledger/src/read_model.rs), [validate.rs](crates/ledger/src/validate.rs), [parse.rs:195](crates/ledger/src/parse.rs#L195), [scalars.rs:57](crates/gl-node/src/graphql/scalars.rs#L57). Verify: the proptest at every prefix, `±MAX` and mixed scales; `account()` == batched at all times.

**☐ T66 — Bounded errors and unsolicited input on the wire (H-18, M-41, L-60) — S/M**
Change: `parse_file` `max_errors` variant for the remote path (first three + count, each ≤ 256 chars); cheap refusals before the parse; a `pub` bounded formatter from `BoundedSink` at every intake/drain `warn!(%error)`; `ContentHashMismatch` carries `claimed` only when `is_content_id`; `?other` → variant name; keyword/envelope-key excerpts; guard `warn!` throttle + `max_buf_size` + truncated header echoes; filter Supply entries to the outstanding Want. Files: [union_merge.rs:143-176,305-307](crates/p2p/src/union_merge.rs#L143), [parse.rs:592-599,723,758](crates/ledger/src/parse.rs#L592), [anti_entropy_alpn.rs:996,1007,1140-1158](crates/gl-node/src/anti_entropy_alpn.rs#L996), [request_guard.rs:84,107,130](crates/gl-node/src/request_guard.rs#L84), [http_server.rs](crates/gl-node/src/http_server.rs). Verify: the `"x\n"` × 512k entry ≤ 4× under the counting allocator and `< 1024` chars; every echo shape `< 512`; N refusals ≤ K lines; an unwanted id records no refusal.

### Tier 2 — the filesystem boundary and the journal

**☐ T67 — File-type discipline for every ledger-side open (M-36, L-57, L-58, L-59, R-17) — S/M**
Change: add `libc` as a direct dependency (R-17); one helper: `symlink_metadata` → regular file → `open(O_NOFOLLOW | O_NONBLOCK)` → `fstat` `is_file`, `(dev, ino)`, `uid == geteuid`, `nlink == 1`, `mode & 0o077 == 0`; reads through `take(MAX + 1)`; the watcher's read in `spawn_blocking`; randomised `.tmp` name with a boot-time sweep; `ledger_lock` refuses symlinks. Files: [journal.rs](crates/ledger/src/journal.rs), [service.rs:118-240](crates/ledger/src/service.rs#L118), [file_watcher.rs](crates/ledger/src/file_watcher.rs), [ledger_lock.rs](crates/gl-node/src/ledger_lock.rs), [p2p_service.rs:895-950](crates/gl-node/src/p2p_service.rs#L895), `gl-node/Cargo.toml`. Verify: FIFO/symlink/directory/hard link at each path → `Err` within the timeout; a 64 MiB + 1 stream → `ResourceLimitExceeded`.

**☐ T68 — Journal policy (M-43, M-44) — S, plus the R-18 decision**
Change: a header whose length exceeds the remainder is `Corrupt` when a later `;;olj` line exists or the length exceeds the budget; a torn journal is renamed to `<journal>.torn-<ts>` at the next compaction, never unlinked; a final record whose payload contains NUL is torn; fix the warning text and the module doc's "cannot be produced by a crash" / "fails closed on its hash" claims. Files: [journal.rs:224-244](crates/ledger/src/journal.rs#L224), [service.rs:1957-1966,1516](crates/ledger/src/service.rs#L1957). Verify: the R-18 fixture → `Err(Corrupt)`; the zero-fill fixture boots torn; a real torn tail leaves a `.torn-*` sidecar.

**☐ T69 — Cost bounds on the read, watch and near-cap paths (M-39, M-42, M-45, L-63, L-65, R-19, R-20) — M**
Change: async `prepare_or_recover` that drops the guard and reuses `recover_off_lock`; headroom check before staging with a transient per-peer backoff; change-gated hashing in the watcher, `spawn_blocking`, `MissedTickBehavior::Delay`; `journal` complexity from `limit` and `child_complexity`, `txid` passed not re-hashed; `VerifyReport.errors` capped; the three `all_directive_ids()` callers switched to `contains_directive`/`sorted_directive_ids`; document the byte budget's real multiple. Files: [ledger_commit.rs:353-370](crates/gl-node/src/ledger_commit.rs#L353), [anti_entropy_alpn.rs:801,1020,1281,1581](crates/gl-node/src/anti_entropy_alpn.rs#L1281), [file_watcher.rs:90-112](crates/ledger/src/file_watcher.rs#L90), [main.rs:412-422](crates/gl-node/src/main.rs#L412), [query.rs:195,307,383](crates/gl-node/src/graphql/query.rs#L195), [verify.rs:164](crates/ledger/src/verify.rs#L164). Verify: near-cap fixture holds the lock < 100 ms; unchanged file → one read per N ticks; eight aliased `journal(limit:10000)` refused.

**☐ T70 — Server-side session deadline and cross-peer cap (M-40, R-5, R-7) — S/M**
Change: a server `SessionBudget` clamping `accept_bi` and every frame; per-peer accept token bucket; a semaphore across concurrent outbound exchanges sized against the allowlist; config surface for the T49/T58 bounds. Files: [anti_entropy_alpn.rs:348-546](crates/gl-node/src/anti_entropy_alpn.rs#L348), [connection_limiter.rs](crates/gl-node/src/connection_limiter.rs), [p2p_service.rs:426-632](crates/gl-node/src/p2p_service.rs#L426), [config.rs](crates/gl-node/src/config.rs). Verify: an `Announce`-every-`io/2` client is closed past `session`; N+1 outbound exchanges never run concurrently.

### Tier 3 — documentation, configuration and hygiene

**☐ T71 — Docs, config and small hygiene (L-56, L-61, L-66, R-9, R-13, §5 items) — S**
Redact the domain in `validate_signature_domain`'s whitespace arm; add the /48 caveat to the per-IP docs; pin or self-host GraphiQL; boot `warn!` when `meshId` is unset with the verbatim-`swarmTopic` guidance, ship `meshId` in `deploy/gl-node.docker.json`; a `CHANGELOG.md` covering every T52/T55 breaking change (h2c removal, apiKey ASCII rule, `null` origin, `http` Origin under `terminated`, `externalFileEdits`, new config keys vs older binaries); refuse ports/trailing dots in `allowedHosts`; warn when the env key is set with auth disabled; document `OPTIONS`, `Origin` localhost/127.0.0.1, "error but durable", and the unkeyed journal hash.

### Finding → task coverage map

H-12→T63 · H-13→T61 · H-14→T61 · H-15→T62 · H-16→T64 · H-17→T65 · H-18→T66 · H-01(residual)→deferred · M-06→T70 · M-09/M-10→T45 · M-35→T62 · M-36→T67 · M-37→T61 · M-38→T61 · M-39→T69 · M-40→T70 · M-41→T66 · M-42→T69 · M-43→T68 · M-44→T68 · M-45→T69 · L-23→T71 · L-35→T69 · L-43→T69 · L-55→T61 · L-56→T71 · L-57→T67 · L-58→T67 · L-59→T67 · L-60→T66 · L-61→T71 · L-62→T61 · L-63→T69 · L-64→T62 · L-65→T69 · L-66→T71 · L-06→T45.

**Decisions this audit puts to the user** (all recorded above): the H-12 adoption ratchet; H-13's policy for envelope-less file directives (adopt-and-sign at boot vs quarantine); H-16's per-author head bound; H-17's approach (magnitude cap vs exact accumulation); R-18/M-43 fail-closed vs silent-torn; R-9 `meshId`; R-13 release notes; R-17 `libc` (now recommended, because T67 needs it).

**Recommended order:** T61 and T62 first (they are the two silent-loss Highs and share `service.rs`), then T63–T66 as focused PRs, then T67/T68 together (both are the filesystem boundary), T69/T70, T71. T45 waves A+B should additionally wait for T61 and T63, since both touch the envelope fields Format v2 re-specifies; T57's prerequisite for Facet B is satisfied.

---

## 9. Checked and found sound (new this audit)

Beyond the 44 closures in §1.1, these were probed adversarially and held:

- **Commit choreography.** `CommitInFlightGuard::arm` is the only setter; `Drop` is a generation CAS; `release_commit_in_flight` is a clearer, not a setter; `commit_generation` is carried across reloads so `0` is never re-issued. `acquire_write_permit` and `ledger.write().await` are cancel-safe (vendored tokio `sync/mutex.rs:596-618`, `sync/rwlock.rs:761-780`); a spawn on a shutting-down runtime drops the `PendingCommit` and permit immediately; at process exit `BlockingPool::drop` waits for the in-flight write, so the bytes land. The fingerprint misses `last_file_hash`, `canonical_is_current`, `leading_comments` and a second `stamp_signature` — all unreachable at HEAD (`stamp_signature` has no production caller; `reconcile_file_staged` runs only under the permit; `set_author_id`/`set_signer` precede serving). The ALPN path is the one call site that yields between staging and `prepare` (`orphan_buffer.write().await`, `drain_orphans`); a drop there leaves memory ahead of disk with no `PendingCommit`, self-healed by the next writer's `pending_block`.
- **Quarantine fixed point.** `split_ledger_blocks` mirrors `parse_file`'s outer loop (blank/comment skip, body rule, one-line orphan rule, CRLF); the quarantine survives restart + compaction for indented-orphan, comment-only, whitespace-inside-block and journal-payload shapes. Dangling parents are **not** cycles (five transactions each naming an absent parent → 7 directives, 0 quarantined, 5 heads). Duplicate content id with good and broken envelopes: the DAG copy wins in both file orders. Quarantined `open`/`close` are outside `record_lifecycle`, consistently. A > 64 MiB file: stat-only watcher, every commit fails before any field update, reload fails on the cap, memory left as-is — fail-closed, no baseline poisoning.
- **Canonicalisation.** `-0`→`0`, `+5`→`5`, `1,000`→`1000`, scale kept, payee-only, `\"` escape, tag/link sorting, cost+date+price, `00012.3400` — all `ser(parse(ser(parse(x)))) == ser(parse(x))` with equal ids. `rust_decimal` silently rounds past 28 fractional digits: value-changing but deterministic. M-24's order is total up to indistinguishable output; boot's `(date, type_priority)` stable sort differs only in tie order and nothing observable depends on it.
- **Wire.** Scanner totality: exhaustive one- and two-byte frames (131,604) plus 293,907 mutated-honest and 301 large structured frames under `catch_unwind`: 0 panics, 0 calls > 2 ms. `head` charges before reading; widths 24–27 via `take_array` with `checked_add`; `usize::try_from` + `checked_add` in `take`; no `as` casts; iterative `skip_value` with a fixed stack. Scan-vs-serde on accepted Supply frames: honest 1.11×, 15 MiB body 1.60×, deep-nested 1.60×, `entries=[15 MiB text]`/`kind`/`v` text 4.07× (the R-4 class). The discriminator peek cannot be spoofed into a different variant; a Supply with `type` not first goes to the 1 MiB path and exhausts the visit budget. `to_wire`/`from_wire` are consistent at exactly 16 MiB; `from_wire` has no production caller. Gossip is bounded at 4096 bytes and inherits the prescan. `BoundedSink` cuts only at char boundaries; `CborScanError` carries no attacker bytes. **L-06 at the verifier:** nine `|`-separated fields, none able to spell `|` — `mesh_id` is validated unconditionally for both fields — so the v3 message is injective.
- **Anti-entropy.** `SessionBudget` is built before the dial and is the only source of a frame timeout; vendored noq `poll_open` takes no stream credit while pending and tokio `timeout` polls the inner future first, so a timed-out `open_bi` drops cleanly and the gossip path releases its coordinator permit. `RefusalCache` keying and classification enumerated over all 11 `MergeError` and every `ServiceError` variant: intake refusals are pure over served bytes + immutable config; account-waits, orphans and DAG verdicts never cached; refusals recorded only against committed state; `pop_oldest` is O(1). `build_supply` checks `is_open()` before `produce`. L-39's `grow_to` matches `reserve_exact` exactly; the reservation is released on every exit. L-54's bound can only be stale-low. Drain semantics: stragglers carried, ≤ |allowlist| tasks, healthy peers spawned every loop.
- **HTTP edge.** `header_read_timeout` is absolute from the first head read (a byte every 2 s is closed at ~30 s), so slowloris is bounded per connection; `TimeoutLayer` covers the body read. Over-cap per-IP connections are dropped with nothing read and the global permit released; freeing a holder lets a fresh connection through at once. `canonical_ip` is applied consistently across peer, XFF, trusted set and per-IP table; XFF keeps the rightmost 16 entries, so a client cannot push the proxy-appended entry out of the window. The Host matcher is fail-closed over twelve loopback-alias spellings (`localhost.`, `127.1`, `0x7f000001`, `2130706433`, `[::ffff:127.0.0.1]`, `[::1%lo0]`, `127.0.0.1:4000@evil`, …); absolute-form targets prefer the `Host` header; `GET /graphql?query=` returns the GraphiQL page, never executes; no WS route; a cross-site JSON `fetch` preflights against an empty allow-list and is blocked.
- **Config and keys.** Every field has a rule except `bindAddress` (anything non-loopback forces tls/auth/hosts — fail-closed), `port`, `watchLedgerFile`, and the unused gossip interval. `REMOVED_CONFIG_KEYS` runs on the raw object before serde. The key chain (`lstat` → regular → open → `(dev,ino)` → mode → owner, no root exemption) refused missing/0644/62-hex/symlink/FIFO/directory/empty and accepted padded and uppercase hex; `Zeroizing` on the hex string, the decoded vector and the 32-byte array; `SigningKey` zeroizes; iroh's `SecretKey` is `Debug → "SecretKey(..)"` and `ZeroizeOnDrop`. `serve_hardened` is the last step of `main`, after `set_author_id` and `set_signer`. `--health-check` probes `::1`/`127.0.0.1` with a Host the guard accepts.
- **Ledger semantics.** `balances_at_dates` agrees with `account_balance` over 1,500 random ledgers checked after every incremental append (unsorted vector, unknown account, same-date cuts, dates before the first transaction, multi-currency); assertions are exact-account, exact-currency, scale-insensitive, tolerance-free; `generate_pad_*` is unreachable from any resolver; `verify_dag` is O(N + E) and iterative; `check_no_cycle`'s proof holds in both dry-out cases; `heads_admissible`'s 8192 budget guarantees the insert's check completes; lifecycle is a total key with last-event-wins reopen; `reject_backdated_close` allows `latest == close.date` consistently on every path; `weights.rs` is `checked_*` throughout and rescales on scale overflow; the GraphQL model inlines fragments, counts aliases, ignores `@skip`/`@include` (conservative), refuses batches, and ties introspection to loopback-only GraphiQL.
- **On-disk formats.** Record grammar requires exactly two spaces, a saturating `usize`, 64 lowercase hex; CRLF → `Corrupt`; framing is length-delimited so a `;;olj` inside a payload cannot resync the scanner and would be a comment in `combined` anyway. `prepare`'s projection includes the header, so the node's own writes never exceed boot's budget. No `Append` is ever chosen while a torn tail is outstanding (executed). No compact-vs-journal resurrection path. `persist_atomically`: `O_EXCL` create, `fchmod` on the handle before `fsync`, rename replaces (never follows) a symlinked `.bean`, dir fsync after rename; stale `.tmp` unlinked and retried. Crash matrix for every step of `Compact` and `Append`: no acked directive can be lost or duplicated, and boot succeeds, except M-35 (journal budget) and M-44 (zero-fill).

---

*Previous audits: [SECURITY_AUDIT_0922.md](SECURITY_AUDIT_0922.md) · [SECURITY_AUDIT_0902.md](SECURITY_AUDIT_0902.md) · [SECURITY_AUDIT_0901.md](SECURITY_AUDIT_0901.md) · [docs/CLAUDE_SECURITY_AUDIT_0820.md](docs/CLAUDE_SECURITY_AUDIT_0820.md). Remediation trackers: [docs/OUTSTANDING_TASKS_09_22.md](docs/OUTSTANDING_TASKS_09_22.md) (T46–T60, R-1…R-21) · [docs/OUTSTANDING_TASKS_09.md](docs/OUTSTANDING_TASKS_09.md) (T18–T45) · [docs/OUTSTANDING_TASKS.md](docs/OUTSTANDING_TASKS.md) (T1–T17). Format v2 design: [docs/FORMAT_V2_DESIGN.md](docs/FORMAT_V2_DESIGN.md).*
