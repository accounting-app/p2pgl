# Security Audit — openledger-v2 (0924: re-audit of T72–T78)

**Date:** 2026-09-24 · **Baseline:** HEAD `3d64a16` (branch `main`, clean tree) · **Previous:** [SECURITY_AUDIT_0923.md](SECURITY_AUDIT_0923.md) (HEAD `af14603`)

Scope: re-verification of **every** claim and residual in the T72–T78 "Done" notes of
[docs/audits/OUTSTANDING_TASKS_09_23.md](OUTSTANDING_TASKS_09_23.md) against source at HEAD, plus fresh hunts over
the ~17,700 lines T72–T78 added or changed (34 files, four commits after `af14603`), treated as unreviewed code.
Priority went to the places where one fix runs inside another, as the 0923 backlog itself predicted: the boot
pipeline in gl-node's exact order (`boot("local")` → `set_author_id` → `set_signer` → `set_verifier` →
`finalize_operator_input` → `verify_own_history` → compaction) against the T73 quarantine, the T74 floor and the
T78 clock shift; the T72 parent choice and ratchet short-circuit against the T75 intake caps and the T77
chunking; the T76 magnitude cap on every ingress against the read-time arithmetic; the T77 cost bounds against
the L-64 state T78 diagnoses; and the four invariant test files as the standing specification of the mesh
invariant, the boot invariant and the balance invariant.

Method as established for the series: ten parallel passes (six per task group, each re-verifying then hunting,
three of them owning one invariant test file; three cross-cutting interaction hunters with named compositions;
one documentation, configuration and supply-chain pass), each read-only on the repo apart from its owned test
file, with its own scratch crates and target directory and a `git archive HEAD` copy for revert-proofs; every
mechanism a pass reported was re-read in source and **every executable proof was re-run by the orchestrator**
before it appears below (the re-run outputs are quoted, not the passes'). Test suite at HEAD before the audit,
quiet machine: **1,248 passed, 0 failed, 2 ignored** (412 + 8 + 549 + 16 + 10 + 185 + 23 + 10 + 7 + 2 + 5 + 21).
Loopback QUIC worked throughout. The repository was modified in exactly five files: this report and the four
invariant test files the brief asked to extend (§6).

---

## Executive summary

**T72–T78 closed what they set out to close.** Twenty of the twenty-three open register entries are closed by
mechanism (H-19 by the decided bootstrap join plus its diagnostic, H-20, H-21, M-46, M-48, M-49, L-64, L-66,
L-67, L-68, L-69, L-70, L-71, L-72, L-73, L-74, L-76, L-77, L-78, L-79) and three are partially closed (M-47,
M-50, L-75). Every regression test the Done notes name is green and every revert-proof a pass repeated failed the
named test (30 reverts across the ten passes). Several fixes are better than asked: the L-71 estimate never
under-counts across seven shapes and over-counts only above 256 heads; `resident_weight` is at or above real
residency on every shape tried and phase 1 never held more than its budget; the T76 arithmetic matches an
independent `num-bigint` oracle over 20,000 mixed-scale cases and the ingress round-trip is one verdict on
every path; the boot verifier and the wire verifier build the same message (1,000 random signed directives,
829 mutations, zero disagreements); all four GraphiQL SRI hashes match the CDN bytes; `cargo audit` is clean,
CI pins verified, lockfile unchanged, `clippy -D warnings` and `fmt --check` pass with the extended tests in.

**But the pattern has repeated a fourth time.** The 0923 audit's through-line was "the fix compares against
replica-local state where the property is a mesh property, and boot trusts a classification the file cannot
enforce". This audit finds the same shape in the *order* the fixes run, and in what they count:

- **H-22** — Boot stamps the parents of operator input from the heads it holds *before* the T73 signature
  pass runs, and `quarantine_out_of_dag` never re-parents. The README's supported edit — fix a narration in a
  node-written block **and** append one hand-typed transaction in the same stop → edit → start — signs the hand
  line over a parent that exists only in this node's quarantine. Every peer buffers it forever
  (`MissingParent` is not permanent, so it is re-Wanted forever), and with it every API append this node
  acknowledges afterwards and every bootstrap joiner's own writes. Restoring the original line does not
  repair it. Three passes reproduced it independently (X1, A2, A1), the last one through the README's bootstrap
  join. The same door opens by hand: T73's rule that a hand-spelled parent may resolve in "DAG ∪ quarantine"
  admits a parent no replica serves.
- **Five Mediums**, four of them the M-50 shape under another rule: the T75 cardinality caps got no upgrade
  path, so one pre-T75 record partitions every replica that lacks it from all later history (M-51); M-50 is
  closed only up to `10^21` — a pre-T65 amount past the cap still quarantines as text with dangling children
  and strands fresh replicas (M-52); a hand directive with 97 metadata keys passes the file-path cap before the
  signature is added and carries 101 at every peer (M-55); a foreign-author half envelope is still adopted
  unsigned, served as a head and named by the node's next write — M-47's consequence verbatim (M-54). The fifth
  is the placeholder author meeting the verifier: a node that signs with `p2p.enabled: false` writes
  `openledger-author: "local"` under a real signature, and the boot that turns P2P on quarantines its entire
  history, every boot, as a fixed point (M-53).
- **Sixteen Lows** (§4), the widest being that on a ledger whose canonical form exceeds the cap (the L-64 state
  T78 now diagnoses) every write path — not "writes that need a compaction" — stages, fails and pays a full
  reload, with no backoff for peers and no pre-stage refusal for mutations (L-80, found by three passes).

The through-line this time: **each new rule is applied at a moment when the state it reads is not yet the
state that will be served** — parents before verification, a metadata count before the signature, a clock
warning against a count the quarantine has since shrunk, a cap on writes but not on history — and the
operator-facing remedies assume the fixes ran in an order gl-node does not use. The backlog (§8) is organised
around moving each check to the point where its input is final.

---

## Threat model

Unchanged from [09/22](SECURITY_AUDIT_0922.md), [09/22-v2](SECURITY_AUDIT_0922-v2.md) and
[09/23](SECURITY_AUDIT_0923.md): (a) a web page in an operator's browser, (b) an API-key holder, (c) a
**malicious or compromised allowlisted peer**, (d) a network attacker on a public bind, (e) whoever can write
the `.bean` or its directory, plus the no-attacker cases (an operator following the README, an editor autosave,
a backup `cp`/`mv`, a crash, an upgrade over an old file, a long-offline or freshly restored replica, the
operator following a remedy the code prescribes). This audit adds three no-attacker cases that the new code
made reachable: **two supported edits made in one stop → edit → start**; **a signing single node that later
joins a mesh**; **an upgrade over a file that a T71–T75 build wrote**.

---

## 1. Status of the 09/23 register, re-verified at HEAD `3d64a16`

Every entry is re-verified by mechanism in source and by the named regression test; "revert-proof" means a pass
reverted the mechanism in a `git archive` copy and the named test failed.

### 1.1 Closed — verified by mechanism (20)

| ID | Task | Mechanism at HEAD | Pinned by | Revert-proof |
|---|---|---|---|---|
| H-19 | T72 | Ratchet unchanged ([service.rs:1429](../../crates/ledger/src/service.rs#L1429), byte-identical to `af14603`); bootstrap join documented and pinned; `clock_is_far_above_history` ([:1311](../../crates/ledger/src/service.rs#L1311)) at boot and the three adoption sites; one `BOOTSTRAP_JOIN_REMEDY` ([:1326](../../crates/ledger/src/service.rs#L1326)) on every remedy path; `highest_lamport_author` prefers the foreign author ([:4777](../../crates/ledger/src/service.rs#L4777)) | `h19_fresh_node_bootstrapped_from_a_peers_file_converges`, four `test_h19_*`, `test_h12_ceiling_diagnostics_name_the_peer…`; the two anti-entropy-only joins stay `#[ignore]`d for the documented reason | — (decision (1)); the README join executed on two real binaries (D1) |
| H-20 | T73 | `unverified_history` filled on every `Inserted` ([:3279](../../crates/ledger/src/service.rs#L3279), [:3491](../../crates/ledger/src/service.rs#L3491)); `verify_history_pass` from `set_signer` ([:7154](../../crates/ledger/src/service.rs#L7154)), `set_verifier` ([:7169](../../crates/ledger/src/service.rs#L7169)), `finalize_operator_input` ([:3997](../../crates/ledger/src/service.rs#L3997)), `finish_recovery` ([:5649](../../crates/ledger/src/service.rs#L5649)), [main.rs:510](../../crates/gl-node/src/main.rs#L510); verdicts [:4131-4193](../../crates/ledger/src/service.rs#L4131-L4193); `quarantine_out_of_dag` [:4208](../../crates/ledger/src/service.rs#L4208); salvage demotion [:629-643](../../crates/ledger/src/service.rs#L629-L643) | boot fuzzer `op_a/b/c/d/e/h`, five `h20_*`, `l45_*`; the live watcher path executed with a real key (edited amount refused, original restored) | yes: `verify_history_pass` no-op → 12 fuzzer cases fail; demotion dropped → `op_u` fails; verifier arm unreachable → `op_w` fails |
| H-21 | T72 | No `check_unmerged_head_bound`, `heads_authored_by`, `UnmergedHeadLimit` or `UNMERGED_HEAD_LIMIT` anywhere in code, schema or README (prose mentions only); `validate_parent_fan_in` on all four paths and `select_parents ≤ 256` still close H-16 | `h21_disjoint_subset_delivery…`, `single_subset_delivery…`, `test_h21_the_257th…`, `test_h16_parentless_flood…` | yes: bound re-inserted → both harness cases fail |
| M-46 | T74 | `adopted_from_file` ([:2918](../../crates/ledger/src/service.rs#L2918)) filled by both `Inserted` arms ([:6705](../../crates/ledger/src/service.rs#L6705), [:6776](../../crates/ledger/src/service.rs#L6776)), cleared on `Compact` ([:5416](../../crates/ledger/src/service.rs#L5416)), pruned ([:4261](../../crates/ledger/src/service.rs#L4261)), fingerprinted ([:5696](../../crates/ledger/src/service.rs#L5696)), not carried; per-id check `committed_ids_missing_from` ([:5675](../../crates/ledger/src/service.rs#L5675)) over `LedgerDag::ids()` | four `m46_*` | yes: per-id check dropped → two fail |
| M-48 | T75 | `enforce_resource_limits` right after the parse in `validate_supply_entry` ([union_merge.rs:258](../../crates/p2p/src/union_merge.rs#L258)); `ParseLimits` counted inside the block loop ([parse.rs:745-770](../../crates/ledger/src/parse.rs#L745-L770), sites :1017, :1182, :1192, :1275, :1622, :1640); lazy `Scanner` ([:33-90](../../crates/ledger/src/parse.rs#L33-L90)) | `decode_memory` 7/7 in release; nine unit tests; 35 uncounted shapes all ≤ 6.5× and nothing stages `Ok` above it; 40,000 fuzzed bodies, one-block gate 0 disagreements | yes: both mechanisms reverted → `a_frame_of_flood_bodies…` fails at 34.71× |
| M-49 | T74 | `Err` arm sets `force_compaction` and `journal_torn_at_boot` ([:5651-5655](../../crates/ledger/src/service.rs#L5651-L5655)); refusing arm ORs the rebuilt fact ([:5620](../../crates/ledger/src/service.rs#L5620)); rename never unlink after a failed reload | two `m49_*`; crash matrix A–D executed (A3 §4) | yes: `force_compaction = true` dropped → `m49_a_failed_reload…` fails |
| L-64 | T78 | `compaction_text_len()` ([:5208](../../crates/ledger/src/service.rs#L5208)) and the WARN at boot and at the end of `finalize_operator_input` ([:3725](../../crates/ledger/src/service.rs#L3725), [:4000](../../crates/ledger/src/service.rs#L4000)) | `l64_*`, `t78_compaction_text_len…`; WARN observed on a real 64 MiB-canonical file | — (but the text understates: L-80) |
| L-66 | T78 | `pin_page_assets` ([graphql/mod.rs:222](../../crates/gl-node/src/graphql/mod.rs#L222)); four pinned assets with `integrity` + `crossorigin`; favicon stripped | `test_graphiql_page_loads_only_pinned_assets_with_integrity`; all four SHA-384s re-fetched from unpkg by two passes and equal the constants; page served by the real binary has exactly four external tags, zero `graphql.org` | — |
| L-67 | T78 | `set_author_id` ([:7078](../../crates/ledger/src/service.rs#L7078)) resumes above `boot_outside_dag_lamports`, re-stamps unfinalised operator input uniformly, skips a shift past the ceiling with a WARN; text-held own pairs counted | two `l67_*`, `t78_an_own_envelope…`; probe: own junk pair at `2^53−3` raises the clock, foreign junk does not, `u64::MAX` no panic | yes: resume removed → `l67_set_author_id_resumes…` fails (7 vs 13) |
| L-68 | T72 | `select_parents` ([:1669](../../crates/ledger/src/service.rs#L1669)): sorted `(id, author)`, `max(1, 256/A)` per author then smallest id; maps only counted, never iterated | two `test_l68_*`; harness: every honest head named on every replica's append over an 800-head ground flood; identical head sets → identical parents | yes: diversity removed → `test_l68_*` and the harness flood case fail; replica-local choice → determinism case fails |
| L-69 | T72 | `defer_ratcheted` / `retain_not_ratcheted` ([anti_entropy_alpn.rs:249-285](../../crates/gl-node/src/anti_entropy_alpn.rs#L249-L285)); threshold `remote − MAX + 1`, both caps return early; recorded from stage and drain, cleared for pushed batches; warn throttle [:297-327](../../crates/gl-node/src/anti_entropy_alpn.rs#L297-L327) | `ratchet_deferral_…`, `ratchet_refused_…` (real ALPN), `stage_refusal_warn_…` | yes: `+1` dropped → `ratchet_deferral_…` fails |
| L-70 | T77 | `RecordEstimate` == `record_bytes(full_file_serialize)` ([anti_entropy.rs:283-345](../../crates/p2p/src/anti_entropy.rs#L283-L345)); per-orphan check before staging ([anti_entropy_alpn.rs:2503](../../crates/gl-node/src/anti_entropy_alpn.rs#L2503)); backoff on `ResourceLimitExceeded` ([:2221](../../crates/gl-node/src/anti_entropy_alpn.rs#L2221)); announce only after `commit_pending` `Ok` ([:2214](../../crates/gl-node/src/anti_entropy_alpn.rs#L2214)) | `l70_*` ×2, `t77_a_fitting_batch…`, `record_estimate_is_the_journal_record_length` | yes: per-orphan check removed → `l70_drained_orphans…` fails |
| L-71 | T77 | `refuse_if_local_write_cannot_fit` ([ledger_commit.rs:550](../../crates/gl-node/src/ledger_commit.rs#L550)) in all three mutations under the permit | `l71_*` ×2; estimate == staged record to the byte on seven shapes, over-counts 2,925 B at 301 heads | yes: call removed → four reloads, 5.1 s permit wait |
| L-72 | T77 | Not-allowlisted arm closes, throttles as a class, returns `Ok` ([anti_entropy_alpn.rs:597-616](../../crates/gl-node/src/anti_entropy_alpn.rs#L597-L616)); default filter [main.rs:64](../../crates/gl-node/src/main.rs#L64) | `l72_refused_dials…` (47 + 50 refusals, 917 filtered bytes, zero `protocol.rs:654` lines) | — |
| L-73 | T77 | `open_checked(OperatorConfig)` + `read_to_end_capped(1 MiB)` ([config.rs:931-960](../../crates/gl-node/src/config.rs#L931-L960)); shared by `--health-check` | `l73_*` ×3; real binary: FIFO, directory, `/dev/null`, `/dev/zero`, `/dev/stdin`, dangling link refused in ≤ 83 ms; 1 MiB accepted, 1 MiB + 1 refused | — |
| L-74 | T73 | `reindex_directive` from `finalize_operator_input` ([:3974](../../crates/ledger/src/service.rs#L3974)) | `l74_*`; `journal` and `transaction` agree on a real binary | — |
| L-76 | T73 | `quarantine_keeping_envelope` ([:3760](../../crates/ledger/src/service.rs#L3760)) at all five boot quarantine arms | `l76_*`, `op_l` | — |
| L-77 | T73 | `AccountAlreadyOpen` on both file paths ([:6740](../../crates/ledger/src/service.rs#L6740)) | `l77_*`, `op_j`; executed on the real binary | — |
| L-78 | T75 | `MAX_CURRENCIES_PER_OPEN = 64` ([limits.rs:30](../../crates/ledger/src/limits.rs#L30)) in the parser and `enforce_resource_limits` | three unit tests; real binary: 64 accepted, 65 → `RESOURCE_LIMIT_EXCEEDED`, nothing written | — |
| L-79 | T76 | `ExactAmount::equals` in `checkpoint.rs:101` shared by per-assertion and batched `verify`; half-ulp bound documented | `l79_*`, `m08_extreme…`; new assertion-scale property | yes: `equals` → `reported().value == claim` → five tests fail |

### 1.2 Partially closed (3)

- **M-47** (T73) — closed for the author-less half (lamport-only → stamped and signed) and for the lamport-less
  half when the author is this node. **Open for a foreign author** on such a line: adopted unsigned, served as a
  head, named by the node's next write → **M-54**.
- **M-50** (T76) — closed for every amount within `10^21`: the fixture boots whole, `verify` is clean, a fresh
  replica syncs it, `1.00000000 BTC @ 100000.00000000 USD` is accepted everywhere. **Open past `10^21`**: the
  block still quarantines as text with dangling children and strands fresh replicas → **M-52**.
- **L-75** (T73) — closed for a parent that exists nowhere. The "∪ quarantine" half of the rule admits a parent
  no replica serves → the second door of **H-22**.

### 1.3 Unchanged by decision (5)

H-01 (loopback API key), M-09, M-10, L-06 (T45 Format v2), L-23 (`meshId` required next release).

### 1.4 Done-note residuals, dispositions at HEAD

- T72 "the warning threshold `4 × count + 1024` cannot false-fire" — **wrong**: it fires on an honest mesh after
  repeated fresh joins (L-94) and after a signing boot that quarantined this node's own history (L-83). The
  ratchet is unaffected.
- T72 "frontier inflation bounded only by the file cap" — accurate and quantified: one honest append merges
  `256 − honest heads` flooded heads (405 → 150 → 1 across two appends); nothing is O(heads²).
- T72 "short-circuit keyed by peer" — accurate; the `ratcheted` and `refusal_log` maps are never pruned when a
  peer leaves the allowlist (bounded by `SUPPLY_BACKOFF_MAX_PEERS`, ≤ ~400 KiB per peer ever allowlisted; Info).
- T73 "a keyless node serves history as loaded with one WARN" — accurate, but not the relevant residual: the
  placeholder author (`"local"`) meeting the verifier is (M-53, L-82).
- T73 "the salvage joins only an unparsable tail to the block above" — accurate; a *parsable* tail (a hand
  header pasted inside a signed block) is H-22's door by accident (A2 `op_y`).
- T73 "a history written before signing was enabled never replicated" — false for a mesh that ran with signing
  off (L-88).
- T74 "floor (a)'s failure path obeys the operator's removal" — understated: a hand line re-adopted by the reload
  after a failed *startup compaction* is finalised, signed and served while still exempt from the floor (L-93).
- T74 "the `must_rewrite` term cannot be revert-proven through a public path" — accurate.
- T75 "existing history over these caps still loads at boot and is served, but upgraded peers refuse it (the T51
  residual class)" — **understated**: it is the M-50 partition for every replica that lacks the record (M-51).
- T75 "a single 1 MiB token ≤ 6.5×" — 6.65× (100 tags × 10 KiB, admitted) and 9.0× (a 1 MiB account name ending
  in U+0430, refused: [parse.rs:305-317](../../crates/ledger/src/parse.rs#L305-L317) formats the whole token before
  cutting it). Info.
- T76 "OutOfRange unreachable through any ingress" — accurate: `2^31 × (2^96 − 1) < 2^127`, the fold fits 256
  bits, the densest legal posting line is 16 B so a 64 MiB file holds `< 2^31 / 128` postings; quarantined and
  unparsable records are never indexed.
- T76 "an inexact trial-balance total may differ from the sum of its rows by that rounding" — bound is ½ ulp of
  the total plus ½ ulp per inexact row (2 units at scale 24 over 40 rows). Info.
- T77 "`append_headroom` does not see a hand edit that grew the `.bean` (mutations then still pay a reload)" —
  mis-described: a watcher-adopted edit *is* seen ([:6267](../../crates/ledger/src/service.rs#L6267)); the reload per
  attempt comes from the over-cap canonical state (L-80), reached also by a Fresh boot with no edit.
- T77 "one directive per connection uncharged when the budget is exhausted" — understated: the uncharged path
  also flushes a chunk per directive (L-90).
- T77 "calibrated 1.02–1.49×" — measured 1.00–1.15×, ≥ real on every shape. Fine.
- T78 "the L-64 check does not run on a reload" — inaccurate but harmless: `finish_recovery` → `finalize_operator_input`
  runs it whenever the rebuild re-adopted operator input.
- T78 "a length damaged to swallow intact later records stays `Corrupt`" — *intact* is load-bearing (L-85).
- T78 "a final record hit by bit rot after its commit boots without it, loudly (peers re-supply)" — right for a
  mesh; on a single node nothing re-supplies and the WARN still says "that commit never reported success". Info.
- T78 "`set_author_id` after `finalize_operator_input` only raises the clock (library misuse)" — accurate; gl-node
  order confirmed.

---

## 2. New findings — High

### H-22 — Boot chooses the parents of operator input before the signature pass removes what they name: an edited own record plus a hand-appended line in one edit signs the hand line over a parent that exists only in this node's quarantine, and every later write of this node is orphaned on every peer, permanently

**Severity: High** (permanent partition of this replica's authoring from the mesh, including acknowledged API
appends and every bootstrap joiner's writes, through the README's supported workflow with no attacker; the one
WARN names the *edited* record and its remedy does not repair it). **EXECUTED** — three independent
reproductions (X1 `c2`/`c2e`, A2 `composite`, A1 harness through the bootstrap-join pipeline), each re-run by
the orchestrator.

**Mechanism.** `boot_with` adopts the file's operator input at
[service.rs:3825](../../crates/ledger/src/service.rs#L3825) (`adopt_operator_input_at_boot` → `adopt_file_directive`),
which stamps `openledger-parents` with `choose_parents` over the *current* heads
([:6626](../../crates/ledger/src/service.rs#L6626), [:6662](../../crates/ledger/src/service.rs#L6662)). At that moment the DAG
holds every enveloped record on its envelope's word: the edited record (new content id, old envelope) is in and
is a head, because its children name the *original* id. Verification runs later — from `set_signer`
([:7154](../../crates/ledger/src/service.rs#L7154)) and `set_verifier` ([:7169](../../crates/ledger/src/service.rs#L7169)) in
gl-node's order ([main.rs:436](../../crates/gl-node/src/main.rs#L436), [:459](../../crates/gl-node/src/main.rs#L459)) — and
`quarantine_out_of_dag` ([:4208](../../crates/ledger/src/service.rs#L4208)) rebuilds the DAG from survivors by lenient
insertion, pruning ids from `unsigned_operator_input` ([:4262](../../crates/ledger/src/service.rs#L4262)) but never
re-parenting what stays in. `finalize_operator_input` ([:3919](../../crates/ledger/src/service.rs#L3919)) then signs the
hand line over exactly those parents (the signature verifies, so the pass it triggers at
[:3997](../../crates/ledger/src/service.rs#L3997) accepts it); the startup compaction persists it; P2P starts; every peer's
`stage_remote_directive` inserts with `require_parents: true` and the parent is held by no replica anywhere — a
quarantine is never served. `Dag(_)` refusals are not permanent
([anti_entropy_alpn.rs:2401](../../crates/gl-node/src/anti_entropy_alpn.rs#L2401)), so the id is re-Wanted forever.

**Second door, by hand.** T73's L-75 rule resolves a hand-spelled parent in "DAG ∪ quarantine"
([:6508](../../crates/ledger/src/service.rs#L6508)), so a hand line naming the id the boot banner printed for the edited
record is adopted and signed the same way (X1 `c2e`, A2 `op_z`). **Third door, by accident:** a hand header pasted
between a signed block's envelope and its postings makes a 0-posting head (quarantined by the pass) and a
parsable tail adopted with `parents = <the quarantined head>` (A2 `op_y`), re-authoring the original's postings
under the hand narration.

**Shape.** The README's stop → edit → start: correct a narration in a node-written block *and* append one
hand-typed transaction. The boot fuzzer applies one operator per case
([boot_fuzz.rs:1395](../../crates/p2p/tests/boot_fuzz.rs#L1395) at `af14603`), so the composition was not a covered shape.

**Proof** (orchestrator re-run, `X1_DIR=$P/runs2 RUST_LOG=warn x1 c2`):

```
[boot] directives=4 heads=1 quarantined=0 operator_input=1 clock=5
 WARN ledger directives QUARANTINED at signature verification: signature does not verify — was this record edited? … ids=35398e5a…
[finalize] finalized=1
[A] directives=3 heads=["290bd726"] quarantined=1 clock=5 cash={"USD": 7} dangling_parents=["txn[Hand]->[\"35398e5a\"]"]
[A] Hand 290bd726 author=f5f9a35a lamport=5 parents=["35398e5a"] sig=79010c88
[A] Hand's parent is the QUARANTINED edited record: true      [A] Hand's parent in DAG: false
[A] file after startup compaction has Hand signed: true
[A] Next 66b098b9 author=f5f9a35a lamport=6 parents=["290bd726"] sig=811d613d
[B<-A] STILL REFUSED at fixed point: txn[Hand] 290bd726 — stage: DAG: Missing parent: … references unknown parent 35398e5a…
[B<-A] STILL REFUSED at fixed point: txn[Next] 66b098b9 — stage: DAG: Missing parent: … references unknown parent 290bd726…
[A-after-restore] … dangling_parents=["txn[Hand]->[\"35398e5a\"]"]   [C<-A] STILL REFUSED at fixed point: txn[Hand] …
```

Through the README's bootstrap join (orchestrator re-run of the `#[ignore]`d harness case
`h20_operator_input_stamped_at_boot_must_not_name_a_record_the_h20_pass_quarantines`): A restarted in gl-node
order, joiner F bootstrapped from A's file with the real `verify_signature` verifier, all author, real
advert-order anti-entropy:

```
A1 / bootstrap: A restarted: GlNodeBoot { finalized: 1, quarantined_by_signature: 0 }, quarantined 1
A1 / bootstrap: hand line d2252c… parents ["a9a6d9…"]
A1 / bootstrap: anti-entropy ticks 2, counts [16, 13, 16], F's own write on A true on B false
DIVERGENT DAG membership: 3 id(s) differ; sizes ["R0=16 …", "R1=13 …", "F=16 …"]   R1: orphan buffer holds 3 waiting on parents [a9a6d9…, d2252c…]
```

Controls pass at HEAD: the hand line alone converges; the edit alone converges (B re-serves the original and A
re-adopts it, X2 `r2`). A2's `composite` and `op_x`/`op_y`/`op_z` reproduce the same three doors.

**Consequence.** From that boot on, nothing this node authors reaches any peer: the hand line and every
descendant are buffered on every replica until the 1 h TTL and re-Wanted forever; `verify` on this node reports
`MissingParent` forever; deleting the edited block later makes the hand line's parent resolve nowhere, so L-75
quarantines the hand line at the next boot and its descendants stay unadoptable. The recovery is a bootstrap
rebuild of this node from a peer's file, losing its post-edit writes — and nothing tells the operator.

**Fix** (S, T79): stamp operator-input parents *after* the verification passes — choose them in
`finalize_operator_input` (nothing is signed or served before it) or have `quarantine_out_of_dag` re-stamp
`openledger-parents` for every id still in `unsigned_operator_input` from the rebuilt DAG (the lamports are
already re-stamped that way by `set_author_id`); resolve hand-spelled parents in the DAG alone; on the
`finish_recovery` path run `verify_own_history` before `finalize_operator_input`
([:5645-5649](../../crates/ledger/src/service.rs#L5645-L5649)); quarantine any *signed* survivor whose parent is in
quarantine. Regression: the three `#[ignore]`d cases (`op_x`, `op_y`, `op_z` in the fuzzer; the harness bootstrap
case) un-ignored.

---

## 3. New findings — Medium

### M-51 — The T75 cardinality caps have no upgrade path: one pre-T75 record over a cap loads and is served by every holder, is refused for good by every replica that lacks it, and everything authored after it is orphaned there

**Severity: Medium** (M-50's rating for the same shape; High by the scale's letter — same available set,
permanently different committed DAGs and balances on honest replicas, no attacker; Medium because the
precondition is a file a T71–T75 build wrote). **EXECUTED** by three passes (X2 `r1_*`, A1 harness case, A5
`t75` and its `m50_wire` case).

**Mechanism.** Boot's history loop applies `validate_parent_fan_in`, `validate_file_envelope_form` and the amount
cap ([service.rs:3387-3400](../../crates/ledger/src/service.rs#L3387-L3400)) with `ParseLimits::UNLIMITED`;
`enforce_resource_limits` runs on the write paths only (:4360, :4542, :4645, :6632, :7318). The wire refuses the
record at intake ([union_merge.rs:258](../../crates/p2p/src/union_merge.rs#L258)) as `ResourceLimitExceeded`, permanent
([anti_entropy_alpn.rs:2349](../../crates/gl-node/src/anti_entropy_alpn.rs#L2349)); every transaction on the account waits
for an `open` that never arrives (`account_wait_target`), every descendant on a missing parent; each is evicted
after `MAX_ORPHAN_AGE` and re-fetched forever. A 65-currency `open` was a plain `openAccount` call before L-78.
T76 gave the amount cap exactly this upgrade path; the two T75 caps got none.

**Proof** (orchestrator re-run, X2 `r1_over_cap_open`; A on a file holding a signed 65-currency `open`, C a
pre-upgrade holder, B fresh, D bootstrap-joined):

```
R1(open65): A ids=5 heads=1 orphans=0 clock=6 permanent=[]     C ids=5 heads=1 …
R1(open65): B ids=1 heads=0 orphans=3 clock=4 permanent=["intake: Resource limit exceeded: Too many currencies in one open: more than 64 (max 64)…"]
DIVERGENT DAG membership: 4 id(s) differ; sizes ["A=5 @clock 6", "B=1 @clock 4", "C=5 @clock 7"]   balances differ: A Assets:Multi debit=7 / B total 0
R1(open65): bootstrap-joined D converges with A
R1(pm101): B ids=2 heads=0 orphans=1 … permanent=["intake: Resource limit exceeded: Too many posting metadata keys in one transaction…"]
```

The harness case `t75_over_cap_open_loaded_from_a_file_partitions_anti_entropy_joiners` (`#[ignore]`) shows the
same: `F holds 2 of 4, permanent {…: Too many currencies…}, orphans 1`.

**Consequence.** After an upgrade over any pre-T75 history holding one such record, every fresh joiner, every
node rebuilt from empty and every node that was offline when it was authored is partitioned from all history
touching that account; silent on the holders, one throttled line per 10 min on the victim; the bootstrap join
converges but nothing prescribes it. [CHANGELOG.md:59](../../CHANGELOG.md#L59) states the refusal with no remedy while
[README.md:58](../../README.md#L58) promises "the CHANGELOG lists each case and its remedy".

**Fix** (S–M, T81): the T76 pattern — either grandfather real history with a larger *legacy* ceiling on the wire
and at boot (the M-48 floods were 262k currencies and 74k keys; the local write cap stays 64/100), or run
`enforce_resource_limits` over loaded history at boot and quarantine the record *with its descendant closure*
naming the ids and `BOOTSTRAP_JOIN_REMEDY`; `verify` reports them; a CHANGELOG remedy under L-78/M-48.

### M-52 — M-50 is closed only up to `10^21`: a pre-T65 amount past the cap still boots as quarantined text with dangling children, silently changes balances, and strands every fresh replica

**Severity: Medium** (M-50's exact consequence and rating; narrower precondition — a base-unit token ledger
such as `50000000000000000000000 WEI`, or the `±Decimal::MAX` H-17's peer could plant before T65).
**EXECUTED** (A5 `m50wei`, `m50max`; pinned `#[ignore]`d in `exact_balances.rs`, re-run by the orchestrator).

**Mechanism.** The whole-file parse fails at [parse.rs:287](../../crates/ledger/src/parse.rs#L287), the block is
salvaged as *text* ([service.rs:3184-3230](../../crates/ledger/src/service.rs#L3184-L3230)) under L-45's Unicode-account
warning, so it has no id; children insert leniently with a dangling parent; the wire refuses the parent for good
(`ParseError`, permanent class) and every descendant gets `MISSING_PARENT`.

```
upgraded boot: unparsable_blocks=1 quarantined=1 has X? false has C? true has G? true
upgraded balance Assets:Cash = Some("14 exact=true")   (pre-upgrade nodes reported 50000000000000000000014)
verify: ok=false errors=[MissingParent { txid: "60987ad2…", parent: "f3ce5c6d…", missing: 1 }]
fresh: stage f3ce5c6d -> refused [INVALID_POSTING] … exceeds the amount cap … ; stage 60987ad2 -> refused [MISSING_PARENT]
```

**Fix** (S–M, T81): when boot quarantines a block for the cap, quarantine its descendant closure so the served
set is self-consistent, and name the cap and the ids in the warning (today it is L-45's text); or refuse boot
naming the id and a remedy; plus the interim items 0923 M-50 listed (`verify` reporting quarantine ids, a
release note for base-unit ledgers).

### M-53 — A node that signs with `p2p.enabled: false` writes `openledger-author: "local"` under a real signature; the boot that turns P2P on quarantines its entire history, every boot, as a fixed point

**Severity: Medium** (loud, every record, recoverable by the enable-signing remedy but undocumented for this
transition; the node boots and serves nothing it wrote). **EXECUTED** (X1 `k3`, re-run).

**Mechanism.** `signing.enabled: true` without `p2p.enabled` is a permitted config
([config.rs:1134](../../crates/gl-node/src/config.rs#L1134) forces signing on for P2P, not the converse). The key is
loaded ([main.rs:334](../../crates/gl-node/src/main.rs#L334)), the signer and verifier installed
([:436](../../crates/gl-node/src/main.rs#L436), [:459](../../crates/gl-node/src/main.rs#L459)), but `set_author_id` runs only
inside the P2P branch ([:379](../../crates/gl-node/src/main.rs#L379)), so every record such a node writes carries author
`"local"` and a signature by the key. While P2P stays off this verifies through the *signer* arm
([service.rs:4177](../../crates/ledger/src/service.rs#L4177): author == `"local"`, deterministic re-sign). With P2P on,
the author is the key hex and the verifier arm ([:4159](../../crates/ledger/src/service.rs#L4159)) is consulted first
with `author = "local"`, which is not a key → refused.

```
[single] directives=3 heads=["e0695777"] quarantined=0 clock=3 cash={"USD": 100}
=== operator enables p2p (same key) and restarts ===
 WARN … QUARANTINED at signature verification: signature does not verify — was this record edited? … (×3)
[p2p-on]   directives=0 heads=[] quarantined=3 clock=4 cash=(none)
[p2p-on-2] directives=0 heads=[] quarantined=3 clock=4 cash=(none)
```

The WARN's remedy ("restore the original line from a peer's copy") is wrong here; the enable-signing remedy
(delete the `openledger-*` lines) works but README §Editing describes only the unsigned → signed transition.

**Fix** (S, T80): derive the author id from the signing key whenever `signing.enabled` (the QUIC identity and
the signing key are the same 32 bytes), so `"local"` never reaches a signed envelope; and document the
single-node → mesh transition. This also closes L-82 and L-91.

### M-54 — A foreign-author half envelope is adopted unsigned as operator input, served as a head, and named by this node's next write: M-47's consequence survives for that half

**Severity: Medium** (M-47's rating and consequence — "served, refused by every peer, every later write descends
from it" — reached through M-47's own example, a block copied from another ledger with the lamport line dropped;
now loud where M-47 was silent, and the WARN says "will NOT replicate" but not "orphans everything after it").
**EXECUTED** (X2 `x_foreign`, A2 `foreign-half`, re-run).

**Mechanism.** `is_operator_input` ([:3747](../../crates/ledger/src/service.rs#L3747)) parks the block;
`adopt_file_directive` stamps lamport and parents and inserts the author only if absent
([:6599](../../crates/ledger/src/service.rs#L6599)); `finalize_operator_input` skips signing a file-spelled foreign author
([:3945-3953](../../crates/ledger/src/service.rs#L3945-L3953)); `choose_parents` ([:4740](../../crates/ledger/src/service.rs#L4740))
names it. The wire refuses it for good (`EnvelopeMissing signature`) and buffers every descendant. T41's
justification "inert outside this node" ([:6895-6899](../../crates/ledger/src/service.rs#L6895-L6899)) is false: it is a
parent. The stamp also issues `(author B, lamport n)`, a pair B never issued; at the next boot the block is a
full envelope without a signature and is H-20-quarantined — after the poisoned write is already signed.

```
X2: B holds pasted? true envelope=Some({"openledger-author": "f5f9…(A)", "openledger-lamport": "5", …}) heads={"5b9d…"}
X2: B's next append parents=Some("5b9d…")
    A: refused for good: intake: Missing required envelope field: openledger-signature; orphan buffer holds 1 waiting on parents ["5b9d…"]
```

**Fix** (S, T79): operator input may name no author but this node — quarantine at boot and reject live a
hand-spelled foreign `openledger-author` with the existing remedy text — or adopt it under this node's author
with an inverted T41 warning. README §Editing's "adopted unsigned with a warning" line changes.

### M-55 — A hand-typed directive with 97 (transaction) or 98 (other kinds) metadata keys passes the file-path cap before the signature is added, carries 101 keys at every peer, and is refused for good there; every later own write is orphaned

**Severity: Medium** (the 0923 through-line — a replica-local count where the property is a mesh property;
silent; within the documented cap of 100, so the operator cannot know). **EXECUTED** (A4 `history` cases E/F,
re-run).

**Mechanism.** `adopt_file_directive` stamps author, lamport and parents
([:6596-6629](../../crates/ledger/src/service.rs#L6596-L6629)) and then runs `enforce_resource_limits`
([:6632](../../crates/ledger/src/service.rs#L6632)), which counts `directive.metadata().len()` — body keys plus the three
envelope keys stamped so far; the signature is added afterwards by `sign_adopted_entry`
([:6867](../../crates/ledger/src/service.rs#L6867)) or `finalize_operator_input`. Peers count the parsed body at intake
(97, ok), merge the four envelope keys, and `stage_remote_directive` counts the merged map
([:7318](../../crates/ledger/src/service.rs#L7318)) → 101 → `ResourceLimitExceeded`, permanent. The local API cannot hit
it (`TransactionInput` has no metadata); both file paths can. Without a signer there is no gap.

```
Case E: hand-typed transaction with 97 metadata keys, boot-adopted and signed by A
  finalized=3; stored hand txn f52c0bc55732 has 101 metadata keys (envelope keys: [author, lamport, parents, signature])
  A's next own write a8702f9f5e33 names parents Some("f52c0bc55732")
  [E] fresh replica B: f52c0bc55732 stage REFUSED Resource limit exceeded: Too many metadata keys: 101 (max 100) → PERMANENT
                        a8702f9f5e33 stage ORPHAN: missing parents ["f52c0bc55732"] (buffered until TTL, re-Wanted forever)
```

**Fix** (S, T81): count the full envelope in the adoption check (run it after signing, or check
`body_keys + ENVELOPE_KEYS.len()`), or define the cap on body keys everywhere and subtract the envelope in
`stage_remote_directive`.

---

## 4. New findings — Low

- **L-80 — On a ledger whose canonical form exceeds the cap (the L-64 state), every write path fails — not "writes that need a compaction" — and each failure costs a full reload with the permit held; no backoff is armed for peers and no pre-stage refusal fires for mutations.** Found by three passes (A3 `hunt4b`, X3 `k1`/`k7`, A6 `l64loop`). `canonical_is_current` is `false` after every boot ([service.rs:3659](../../crates/ledger/src/service.rs#L3659)) and set only by a `Compact` receipt, so `must_rewrite` ([:5055](../../crates/ledger/src/service.rs#L5055)) is always true; the compaction arm's cap refusal is `Io(InvalidData)` from `persist_atomically` ([:264](../../crates/ledger/src/service.rs#L264)), not `ResourceLimitExceeded`, so the L-70 arm ([anti_entropy_alpn.rs:2221](../../crates/gl-node/src/anti_entropy_alpn.rs#L2221)) never arms and the log says "rolled back in memory, will re-pull"; `append_headroom()` ([:4944](../../crates/ledger/src/service.rs#L4944)) is the append projection, so both pre-stage checks admit. **Executed** (63.16 MiB file, canonical 65.5 MiB): `local write 0..2: staged → Err(Io(InvalidData …)) in 0.8–1.0 s` each with `L-13 reload installed`; `peer batch commit → Io(InvalidData …); is ResourceLimitExceeded? false`; a 230k-`open` fixture: 33–85 s per attempt. A peer cannot push a node into this state (headroom is judged against the file size); only a hand-written dense file or an adopted hand edit can. The WARN ([:3725](../../crates/ledger/src/service.rs#L3725)), README and [CHANGELOG.md:121](../../CHANGELOG.md#L121) say "compactions fail". Fix (T82): return `ResourceLimitExceeded` from the compaction arm via `compaction_text_len()`, and make `append_headroom` report 0 while the over-cap fact holds (set by `warn_if_canonical_exceeds_cap`, cleared by `Compact`, carried through `adopt_reloaded`); reword the three texts.
- **L-81 — The recovery floor checks id presence, not record identity: a backup taken before a hand line was canonicalised, restored after the record was acked, plus one failed commit re-stamps the acked record's envelope (new lamport, new signature) where the success path keeps it.** [service.rs:5675-5681](../../crates/ledger/src/service.rs#L5675-L5681) asks only `rebuilt.get(id).is_none()`; the rebuild reads the raw line as operator input under the same id, installs, and `finalize_operator_input` ([:5642](../../crates/ledger/src/service.rs#L5642)) stamps it. **Executed** (A3 `hunt7`, `hunt8`): `envelope A (acked): lamport 504 → now: lamport 902; equals A = false; next write ok; on disk after: 902` with `discarded_staged=0 discarded_file_adopted=0`; control (successful commit) keeps 504; an acked child keeps `lamport 505` below its re-stamped parent. Bodies, parents and balances unchanged; the mesh holds two envelopes for one id forever. Fix (T82): copy memory's enveloped directive over the rebuilt operator-input copy before finalising, or treat "present as operator input but acked with an envelope" as missing.
- **L-82 — On a signing single node (P2P off) a boot-adopted hand line is quarantined by the very pass that signed it and appears only after the next restart.** Same root as M-53: finalize stamps author `"local"` and signs, inserts the id into `unverified_history`, and the verifier arm cannot parse `"local"`. **Executed** (X1 `k2`): `[run2] Hand served: false quarantined ids=["290bd726"]` → after restart `directives=4 … cash={"USD": 107}`. The README's primary workflow omits the operator's line from every balance for one process lifetime with a WARN accusing them of editing a signed record. Closed by M-53's fix.
- **L-83 — The adoption-site clock warning is evaluated against the post-quarantine DAG size: after a first signing boot quarantined this node's own unsigned history, the first honest adoption trips it, names the honest peer and prescribes the bootstrap join.** Boot's copy ([:3565](../../crates/ledger/src/service.rs#L3565)) sees `dag.len()` before the pass; `warn_if_clock_far_above_history` ([:4800](../../crates/ledger/src/service.rs#L4800)) sees it after, with the clock left where boot put it. **Executed** (X1 `c6`): 2,002 own records, first signing boot → `quarantined=2002 clock=2003`; one `open` from peer B → `WARN … lamport_clock=2004 directive_count=1 author="3e0af306…"`. Fix (T83): count the quarantine (or the own out-of-DAG high) in the predicate.
- **L-84 — A symlinked `.bean` reads the target's bytes but never the target's journal, and the startup compaction replaces the link with a regular file, silently detaching the node from the target.** `journal_path_for` ([journal.rs:144](../../crates/ledger/src/journal.rs#L144)) and T78's `symlink_metadata` probe derive from the *link* path; `persist_atomically` renames over the link. **Executed** (X1 `c9`): `[via-link] directives=3 … InJournal served via link: false; link is still a symlink after the startup compaction: false; target's journal still present: true`; boot from the target: 4 directives. Zero WARN lines. Fix (T82): refuse a symlinked `.bean` (as the key file is), or canonicalise once at boot and derive journal, lock and temp names from the target.
- **L-85 — T78's torn rule drops an acknowledged non-final record when its length field is damaged and the node then crashes mid-append of the next record; the old rule refused boot.** `has_later_intact_record` ([journal.rs:437](../../crates/ledger/src/journal.rs#L437)) examines only the first `;;olj ` candidate; a torn successor's header parses but does not fit, so the damaged, long-acked record is classified torn with it. **Executed** (X3 `k4`): `c R1.len swallows TORN R2: OK intact=0 torn_tail_bytes=670` (acked R1 dropped, loudly, bytes in the sidecar) while `b`, `f`, `g`, `h` stay `Corrupt`. Two independent faults; recoverable from the sidecar. Fix (T82): treat a candidate whose header parses but whose claim runs past the region as evidence of a later record.
- **L-86 — A local record whose commit failed can already have been served in the prepare → commit → reload window; the caller's retry re-authors the same content id under a different envelope, so replicas hold one id with different parents and their head sets differ permanently.** **Executed** (X3 `k10`): `A retry: same id? true lamport 4 → 7 parents 1 → 1 signature same? false … ids equal? true | heads A=["6ddc69c3"] P=["6ddc69c3","c4d8c708"] equal? false`. Membership and balances converge; the harness's `Snapshot` compares heads, so this shape would fail `assert_converged`. The `(author, lamport)` pair is not reused. Document beside the "same body, two authors" property (T83).
- **L-87 — An own record whose lamport line is edited to ~2^32 is quarantined by the pass, but the clock boot folded from it stays; the node's next writes carry the jump and the mesh follows.** `lamport_high.note` on `Inserted` ([:3485](../../crates/ledger/src/service.rs#L3485)) runs before verification; `quarantine_out_of_dag` leaves the clock. **Executed** (A2 `env-edit`): `quarantined_total=1 … clock=4000000001` plus the T72 WARN on every later boot; peers accept it (under `MAX_LAMPORT_ADVANCE`). Fix (T83): re-derive the clock in `quarantine_out_of_dag` from survivors ∪ operator input ∪ own records quarantined for other reasons. Pinned `#[ignore]`d as `op_ab`.
- **L-88 — The enable-signing remedy is replica-local: on a mesh that ran with signing off, each replica re-authors the same ids under its own key and a fresh replica's attribution depends on which peer serves first.** The Done note and README say such history "never replicated"; it did. **Executed** (A2 `migration`): after the remedy `membership equal? true`, same heads, `10e57a05 A: author=26509cc6 … | B: author=6d791c3a …`, `C1: A then B → C carries A's authorship; C2: B then A → B's`. Forensic only. Fix (T83): README — run the remedy on one node, delete the blocks on the others.
- **L-89 — The boot history arm does not apply H-06's closed envelope-key set: a hand-added directive-level `openledger-*` key loads as verified history and is written back on every compaction.** [:3387-3399](../../crates/ledger/src/service.rs#L3387-L3399) runs fan-in, envelope form and the amount cap only. **Executed** (A2 `env-edit`): `on disk after compaction: openledger-note present? true; served metadata keys: [author, lamport, note, parents, signature]`; peers accept it (`extract_envelope` filters to the closed set), so local-only. Fix (T83): `validate_body_envelope_keys(directive, ENVELOPE_KEYS)` in the boot chain as `stage_remote_directive` has ([:7325](../../crates/ledger/src/service.rs#L7325)).
- **L-90 — When the inbound byte budget cannot cover the next directive, phase 1 flushes one-directive chunks: a peer that fills its own 32 MiB share turns each 256-entry frame into 256 commits and fsyncs under the write permit.** [anti_entropy_alpn.rs:1877-1907](../../crates/gl-node/src/anti_entropy_alpn.rs#L1877-L1907): a failed `grow_to` flushes the chunk whatever its weight and holds the directive uncharged; the next charge fails again. **Executed** (A4, gl-node level, real `apply_supply_entries`): `control frame → 4 journal records in 1.03 s; budget-exhausted frame → 256 journal records in 1.95 s; merged: 256`. Reachable with two of a peer's 32 connections each pushing a 16 MiB frame. Fix (T83): flush on the weight budget only; a failed charge keeps holding up to `PHASE_ONE_WEIGHT_BUDGET`.
- **L-91 — `set_author_id` can carry the clock to the Lamport ceiling with an INFO line only; the first refused write then names the wrong author and prescribes the mesh-wide remedy.** Boot WARNs when the next stamp will refuse ([:3515-3560](../../crates/ledger/src/service.rs#L3515-L3560)), but under the placeholder the planted own envelope (junk text, or a parsed own record outside the DAG) is folded only at `set_author_id`, which logs `info!` ([:7134](../../crates/ledger/src/service.rs#L7134)); `highest_lamport_author` ([:4777](../../crates/ledger/src/service.rs#L4777)) does not see text-held pairs. **Executed** (A6 `l67`): `clock at boot(local)=4 after set_author_id=9007199254740990 → open_account: Err(… past the last legal value … carried there by a directive from author local. Remedy, mesh-wide: remove that author from the allowlist …)`. Threat (e) only. Fix (T80): apply boot's ceiling predicate after the raise and include `boot_outside_dag_lamports` in the author lookup.
- **L-92 — README "Amounts and precision" and the T76 CHANGELOG bullet promise "any precision up to 28 fractional digits, trailing zeros are free", but every ingress refuses a spelling of more than 28–29 significant digits, trailing zeros included, with a non-cap error.** `Decimal::from_str_exact` runs before the cap ([scalars.rs:69](../../crates/gl-node/src/graphql/scalars.rs#L69), [parse.rs:240](../../crates/ledger/src/parse.rs#L240)); the true rule is ≤ 28 fractional digits and ≤ 28–29 total digits and `|value| ≤ 10^21` (`10^21` admits at most 7 decimals). **Executed** (D1, real binary): `1000000000000000000000.0000000` accepted; `1000000000000000000000.00000000` → `Invalid decimal string`; `10.0000000000000000000000000000` → `Invalid decimal string`; the same line in a hand block is quarantined as unparsable. One verdict on every path (A5). Fix (T83): state the mantissa bound; map the parse failure to a precision message.
- **L-93 — A hand line re-adopted by the reload that follows a failed startup compaction is finalised, signed and served while still exempt from the recovery floor; a backup copied over the live file plus one failed commit then drops it without `REFUSING`.** `adopted_from_file` is cleared only by a `Compact` receipt, and the first commit after any adoption is a Compact — but that Compact can fail. **Executed** (X1 `c1`): startup compaction `FAILED: Permission denied` → `L-13 reload installed … discarded_file_adopted=0`, `Hand … uncommitted_count=0`, served to B; then `cp` + failed commit → `before=5 after=3 discarded_staged=1 discarded_file_adopted=1`, `Hand still in memory: false`, on disk after the next commit: false; it came back only because B re-supplied it. Needs two disk failures plus a `cp`. Fix (T82): the T74 residual should say so, and the per-id check should exempt only ids not yet served (or L-81's identity check covers it).
- **L-94 — The clock-versus-history warning fires on an honest mesh: the "≤ 2 × count" derivation does not hold across repeated fresh joins.** Each below-clock adoption adds one, a joiner adopts in advert (hex) order, stamps its inflated clock into its own directive, and the next joiner climbs from there; compounds whenever the highest-lamport directive is parentless. **Executed** (A1 harness case, `#[ignore]`d): 300 accounts, 12 fresh joiners each opening one account, no jump anywhere → `R0 clock 2314, count 317, threshold 2292, fires true` (newest-first order: 4042). The WARN then names an honest author and prescribes bootstrap joins; the README calls the line "your confirmation that the copy carried the gap". Fix (T83): warn on a *gap* (largest difference between consecutive lamports in the DAG, a content property) or call the factor heuristic.
- **L-95 — A fresh anti-entropy join of a chain longer than `MAX_ORPHANS_PER_PEER` (1,000) progresses a few directives per tick.** Want is heads first then hex order, 256-entry chunks with a drain per chunk; the per-peer orphan cap refuses rather than evicts ([orphan_buffer.rs:357-366](../../crates/p2p/src/orphan_buffer.rs#L357-L366)), so a chain entry past the cap stages only if its parent is already present when it arrives. **Executed** (A1): `n=3000 advert order: F holds 83 of 3003 after 30 ticks, orphans 1000`; `n=1500 newest-first: 62 of 1503` (one per tick); an 800-chain joins in ≤ 3 ticks. At the 5 s default tick a 3,000-transaction chain takes hours, with ~500 "orphan buffer full" WARNs per tick. Fix (T83): Want in ascending-lamport order, or evict-oldest at the per-peer cap, or let the drain fetch a missing parent directly.

---

## 5. New informational

- **`main.rs:510` prints the H-20 banner from `verify_own_history()`'s return, which counts only the *last* pass**; the setters' passes already quarantined, so in gl-node's order the banner never prints (per-record WARNs do). Observed `quarantined_by_signature: 0` with one quarantined, and 0 with all 11 quarantined on a `meshId` mismatch — whose per-record WARN says "was this record edited?" (A1). Fold into T80.
- **A keyless boot logs `signer_installed=true`** in the UNVERIFIED warning: [main.rs:432](../../crates/gl-node/src/main.rs#L432) installs a provider unconditionally (D1).
- **The dangling-link config refusal says "is a symbolic link; refusing to follow it"** while a link to a regular file is followed by policy (D1).
- **`KeyedRefusalLog` at its 64-source bound:** a source that first refuses after the table filled is never named — 250 refusals folded into five overflow reports over five windows (A6). 64 fresh client addresses per 10 s keep every later client anonymous. Forensic only.
- **`health.rs:124`** reads the node's own `/health` response with a plain `read_to_string` (3 s socket timeout, no byte cap). Not pursued.
- **An edit that changes an amount *and* drops the lamport line** is adopted as a *second* signed transaction (`cash 230`), not refused (X1 `c5-ii`); by M-47's design, but README §Editing should say an edit that loses an envelope line becomes a duplicate.
- **A pasted block signed by a non-allowlisted same-mesh key** is verified at boot (signature, not allowlist), served, refused by peers via `verify_author_allowlisted`, and named by the node's next write (A2). Consistent with T72's "rules on content" and `BOOTSTRAP_JOIN_REMEDY`; no action.
- **A pasted foreign full envelope with a valid signature and an unknown parent** is adopted leniently on the live path with a dangling parent and the clock ratcheted to the pasted lamport (X1 `c5-iii`); pre-existing reconcile behaviour.
- **`ratcheted` / `refusal_log` maps are never pruned** when a peer leaves the allowlist (A1). Bounded.
- **HEAD's `non_fitting_totals_are_rounded_once_half_to_even_on_every_path` never hits an exact tie**: a ties-away-from-zero revert passed it; the new oracle properties catch it (A5).
- **`10^21` with 8 or 28 zeros** is refused by `from_str_exact` before any cap on every path — one verdict, but the message is "Invalid decimal string" (L-92).
- **Mixed-version notes** (X2, A1, reasoned from `af14603`): a pre-T72 replica keeps the head bound (H-21 divergence until it authors or upgrades); a pre-T75 replica's API can still author a 65-currency `open` (M-51's precondition, live); a T71-era node refuses a HEAD node's `10^21`-exact or trailing-zero body until upgraded, then converges; an author-less half envelope converges after upgrade, an author-bearing one is M-54.
- **Harness caveat:** the convergence harness's L-34 memory is per id where gl-node's is per `(peer, id)`, so a harness joiner that refuses one peer's copy never asks another (X2). Keep in mind when reading its divergence reports.
- **README nit:** "at most `256 / authors` per author" — the code is `max(1, 256 / A)` (D1).
- **Test-net notes:** the boot fuzzer applied one operator per case (H-22's shape) — now 25 operators plus composites; no test drove the GraphQL `exact`/`actualExact` fields end to end (D1 did by introspection only); `t77_phase_one_*` are calibrated for release and the multiples in the Done note are unverifiable here; the `.torn-*` sidecar `-N` collision arm is now executed (X3 `k9`).

---

## 6. Dependencies, supply chain, verification runs, and the four invariant test files

**`cargo audit`** (DB `1931a145`, 2026-09-23, 1,267 advisories, 499 locked crates): **exit 0**; sole output the
allowed RUSTSEC-2024-0436 (`paste`) warning. `.cargo/audit.toml` still ignores exactly RUSTSEC-2026-0235;
`cargo tree -i rkyv -e all --target all` prints nothing. **`Cargo.lock` unchanged since `af14603`**: 495
crates.io + 4 workspace crates, zero git sources. **CI pins** re-verified with `git ls-remote`: `actions/checkout`
`11d5960…` = `v4.4.0` ✔ · `Swatinem/rust-cache` `6323deb…` = `v2.9.2` ✔ · `rustsec/audit-check` `69366f3…` = `v2.0.0`
✔ · `dtolnay/rust-toolchain` `4360b52…` fetched by SHA, the 2026-08-04 "toolchain: stable" commit ✔. Toolchain
rustc 1.97.1; `rust-version = "1.91"`; Dockerfile digests unchanged. **`unsafe`:** one production occurrence
(`libc::geteuid()`, [journal.rs:956](../../crates/ledger/src/journal.rs#L956)). `cargo clippy --workspace --all-targets
--locked -- -D warnings` exit 0 and `cargo fmt --all -- --check` exit 0, both with the extended test files in.

**CHANGELOG vs code:** 55 bullets added or changed since `af14603` checked; 24 executed on the real binary or
over HTTP (config file rules, log filter, 64/65 currencies, `exact`/`actualExact` by introspection, the boot
WARN texts, the sweep, the dangling journal link, the H-20 quarantine and remedy, the M-47 stamps, L-74
agreement, GraphiQL SRI, the torn sidecar, journal modes), the rest by 57 named tests and source. **Every
statement is true except the T76 "any precision" claim (L-92) and the L-64 "compactions fail" wording (L-80).**
Omissions: the ledger-crate public API changes (`parse_file_bounded` gained a `ParseLimits` parameter — breaking
— with `ParseLimits`/`ParseLimitExceeded`; the `ledger::limits` and `ledger::wide` modules; `ExactAmount`,
`OutOfRange`, the `try_*` report forms, `reindex_directive`; `DirectiveVerifier`; the removed
`MAX_AMOUNT_SIGNIFICANT_DIGITS`/`MAX_AMOUNT_MANTISSA`; `p2p::anti_entropy::{RecordEstimate, record_bytes,
resident_weight, …}`), and four behaviour changes (the live reconcile refusing a non-verifying pasted envelope;
the cap error preceding the validation error at the cap; `account(at:)` summing one account; a bit-rotted final
journal record booting without it). **README:** every procedure executed worked, including the bootstrap join
on two real binaries (A wrote 6 records, stopped clean; B booted A's `.bean` under its own key, verified 6/6,
served A's history and authored above it). **Config:** all twelve keys parsed, validated at the documented
floors and ceilings (36 real-binary boundary boots), landed and consumed; `deny_unknown_fields` on all seven
sections; the docker config validates.

**The four invariant test files** (the brief asked for them to be extended; pure additions plus helper changes,
no existing test modified or removed; every new test that pins an existing mechanism was revert-proven in an
archive copy; every test that pins a new finding is `#[ignore = "<pass>-N: …"]` and fails for the stated reason
under `--ignored`):

| File | Before | After | New cases (pins) |
|---|---|---|---|
| [crates/p2p/tests/convergence.rs](../../crates/p2p/tests/convergence.rs) | 10 / 2 ign | **17 / 6 ign** | multi-author flood with local authoring on every replica; identical heads → identical parents; bootstrap join through gl-node's order with operator input, with a quarantined block, and with the wrong `meshId`; the H-19 warn under one join and under transaction-authoring joins; chain joins under the orphan cap; ignored: H-22 through the bootstrap join, M-51, L-94, L-95 |
| [crates/p2p/tests/boot_fuzz.rs](../../crates/p2p/tests/boot_fuzz.rs) | 23 / 0 | **32 / 5 ign** | the pipeline now installs the verifier as `main.rs` does; 12 new operators (parents-line edit, lamport-line edit, duplicated lamport line, journal-record edit with recomputed checksum, stray word after the header, pasted allowlisted-signed block, pasted forged block, and the composites); `boot_fuzz_all_operators_including_a2` over 25 operators; the crash-between-finalize-and-compaction fixed point; ignored: H-22's three doors (`op_x`, `op_y`, `op_z`), M-54 (`op_aa`), L-87 (`op_ab`) |
| [crates/ledger/tests/exact_balances.rs](../../crates/ledger/tests/exact_balances.rs) | 16 / 0 | **24 / 1 ign** | `I256` vs the base-10^9 oracle; Rule R vs the oracle beyond the cap (20,000 cases in release); every ingress gives one verdict and re-reads what it accepted; assertion claims at other scales and over cancelling partials on both paths; I1 on rounded weights (acceptance); inexact trial-balance total vs rows; the partial-count and 256-bit bounds; negative zero; ignored: M-52 |
| [crates/p2p/tests/m50_wire.rs](../../crates/p2p/tests/m50_wire.rs) | 2 / 0 | **6 / 0** | `±10^21` at scales 0–7 signed through the wire, one ulp past refused permanent; `balance`/`price` amounts above the cap cross signed; the M-50 fixture × the T75 caps (65-currency `open`, 1001-posting transaction: `["OK","WIRE_REFUSED","ACCOUNT_NOT_OPEN"]`); an over-cap parent strands its child on every fresh replica |

**Test suite:** `cargo test --workspace --locked` — **1,248 passed, 0 failed, 2 ignored** before the audit and
**1,276 passed, 0 failed, 12 ignored** (412 + 8 + 549 + 24 + 10 + 185 + 32 + 17 + 7 + 6 + 5 + 21; the 12 ignored are the two documented H-19 anti-entropy-only joins plus the ten new finding cases) after all passes completed with the four files extended. The 30 revert-proofs across the passes
(each in a `git archive` copy, each restored and diffed pristine afterwards): H-21 bound re-inserted; L-68
diversity removed and replica-local choice; L-69 threshold off by one; `verify_history_pass` no-op; `is_operator_input`
"lacks both"; salvage demotion dropped; verifier arm unreachable; M-46 per-id check; M-49 `force_compaction`;
T78 torn rule; T75 enforce + limits; T77 chunking; L-70 per-orphan check; L-71 pre-stage call; L-67 resume; T76
Decimal fold, double rounding, `actual == claim`, parser cap, ties-away, `balance` capped.

---

## 7. Consolidated open-findings register

Everything open as of this audit. IDs are stable across the 09/01 … 09/24 reports.

| ID | Sev | One-liner | Origin |
|---|---|---|---|
| **H-22** | High | Boot stamps operator-input parents before the signature pass; an edited own record + a hand line in one edit (or a hand parent resolving in quarantine) signs a record no peer can take and orphans every later write mesh-wide | **09/24** |
| H-01 | High→Low | *Partially closed.* Loopback API key deferred | 09/01 |
| M-09 | Med | *Partially closed.* Remote-close admission order-dependent (T45) | 09/01 |
| M-10 | Med | *Interim only.* T45 Facet A | 09/01 |
| M-47 | Med | *Partially closed.* Foreign-author half envelope → M-54 | 09/23 |
| M-50 | Med | *Partially closed.* Past `10^21` → M-52 | 09/23 |
| **M-51** | Med | T75 caps have no upgrade path: one pre-T75 record partitions every replica that lacks it (the M-50 shape) | **09/24** |
| **M-52** | Med | Pre-T65 amount past `10^21`: text quarantine, dangling children, balances change, fresh replicas stranded | **09/24** |
| **M-53** | Med | Signing with P2P off writes author `"local"`; enabling P2P quarantines the whole history every boot | **09/24** |
| **M-54** | Med | Foreign-author half envelope adopted unsigned, served as a head, named by the next write | **09/24** |
| **M-55** | Med | 97-key hand directive passes the file cap pre-signature, 101 at every peer, permanent refusal | **09/24** |
| L-23 | Low | *Partially closed.* `meshId` still opt-in | 09/02 |
| L-75 | Low | *Partially closed.* The "∪ quarantine" half is H-22's second door | 09/23 |
| **L-80 … L-95** | Low | Sixteen new Lows — see §4 | **09/24** |
| L-06 | Latent | `\|`-delimited signature message — injective at HEAD; T45 Facet B | 09/01 |

**Closed this audit (20):** H-19, H-20, H-21 · M-46, M-48, M-49 · L-64, L-66, L-67, L-68, L-69, L-70, L-71, L-72,
L-73, L-74, L-76, L-77, L-78, L-79. **Residuals re-rated:** T75 "loads but upgraded peers refuse" → M-51; T72
"cannot false-fire" → L-83/L-94; T77 "one directive uncharged" → L-90; T74 "floor (a)" → L-93; T78 "swallow
intact records" → L-85.

---

## 8. Remediation backlog

Tracked in [docs/audits/OUTSTANDING_TASKS_09_24.md](OUTSTANDING_TASKS_09_24.md). Task numbering continues from T78. Effort: S = < ½ day, M = ~1–2 days. Every task keeps the campaign's rule:
revert the fix → the named test fails → restore; residuals go in the tracker. The `#[ignore]`d cases in the four
invariant files are the acceptance tests: a task is done when its cases are un-ignored and green.

### Tier 1 — ship-blocker

**☐ T79 — Operator input after verification (H-22, M-54, L-75 remainder) — S–M**
Change: choose and stamp operator-input parents in `finalize_operator_input` (after the signer and verifier
passes; nothing is signed or served before it), or re-stamp `openledger-parents` of every `unsigned_operator_input`
id in `quarantine_out_of_dag` from the rebuilt DAG; on the `finish_recovery` path run `verify_own_history` before
`finalize_operator_input`; resolve hand-spelled parents in the DAG alone (a quarantined record is never served);
quarantine any signed survivor whose parent is in quarantine; operator input may name no author but this node
(boot quarantines, live rejects, with the existing remedy text). Files: [service.rs:3825-3870, 3919-4000,
4208-4270, 5645-5649, 6500-6520, 6596-6604, 6867-6899](../../crates/ledger/src/service.rs#L3825), README §Editing.
Verify: un-ignore `op_x`, `op_y`, `op_z`, `op_aa` (fuzzer) and
`h20_operator_input_stamped_at_boot_must_not_name_a_record_the_h20_pass_quarantines` (harness); the X1 `c2`,
`c2e` and X2 `x_foreign` probes converge; the controls still pass.

### Tier 2 — the upgrade paths and the placeholder author

**☐ T80 — The author id is the key (M-53, L-82, L-91, §5 banner) — S**
Change: derive the ledger author from the signing key whenever `signing.enabled` (before `set_signer`), so
`"local"` never reaches a signed envelope; document the single-node → mesh transition (the enable-signing
remedy applies); after the raise in `set_author_id` apply boot's ceiling predicate and WARN, and include
`boot_outside_dag_lamports` in `highest_lamport_author`; make `main.rs:510` report the total quarantined by
signature, not the last pass's; the per-record WARN should name a `meshId` mismatch when every record failed.
Verify: X1 `k3` boots with 3 served after enabling P2P; X1 `k2` serves the hand line in the same lifetime; A6
`l67` case 1 logs a ceiling WARN naming no author.

**☐ T81 — Upgrade paths for the T75 caps and the `10^21` remainder; count the envelope (M-51, M-52, M-55) — M, plus a decision**
Decision: grandfather real pre-T75 history with a legacy ceiling on the wire and at boot (recommended — the
M-48 floods were three orders of magnitude larger) vs quarantine-with-closure at boot. Change: apply the chosen
rule identically at boot, on the wire and in `stage_remote_directive`; when boot quarantines a block for the
amount cap, quarantine its descendant closure and name the cap and the ids (not L-45's text); `verify` reports
quarantine ids; count the full envelope in the adoption check (or define the cap on body keys everywhere);
CHANGELOG remedies under L-78/M-48 and M-50. Verify: un-ignore `t75_over_cap_open_loaded_from_a_file_partitions_anti_entropy_joiners`
and `over_cap_history_keeps_its_descendants_parents_resolvable_or_refuses_loudly`; X2 `r1_*`, A5 `m50wei`, A4
`history` case E converge or refuse loudly; a 97-key hand transaction adopted with a signer round-trips through
`validate_supply_entry` + `stage_remote_directive` on a second service.

### Tier 3 — recovery, journal, cost bounds and hygiene

**☐ T82 — The over-cap canonical state, the floor's identity check, the torn rule, the symlinked `.bean` (L-80, L-81, L-84, L-85, L-93) — S**
Change: a `canonical_over_cap` fact set by `warn_if_canonical_exceeds_cap`, cleared by `Compact`, carried through
`adopt_reloaded`, under which `append_headroom()` returns 0 and `prepare`'s compaction arm refuses with
`ResourceLimitExceeded` (arming the peer backoff, refusing mutations pre-stage, no reload); reword the WARN,
README and CHANGELOG to "every write fails until the file is made smaller"; in `finish_recovery`'s install arm
copy memory's enveloped directive over a rebuilt operator-input copy of the same id (closes L-81 and L-93's
served-record case); `has_later_intact_record` treats a parsing-but-overrunning candidate as a later record;
refuse a symlinked `.bean` or canonicalise the path once at boot; the torn-tail WARN mentions post-ack damage
and the sidecar. Verify: X3 `k1`/`k7` — zero reloads, backoff armed; A3 `hunt7` keeps lamport 504; X3 `k4` case c
→ `Corrupt`; X1 `c9` serves the target's journal record or refuses the link; X1 `c1` refuses the install.

**☐ T83 — Diagnostics and cost bounds (L-83, L-86, L-87, L-88, L-89, L-90, L-92, L-94, L-95, §5) — S**
Change: the clock warning judged on a lamport *gap* in the DAG (content), or the factor called heuristic and the
adoption-site copy counting the quarantine; re-derive the clock in `quarantine_out_of_dag`; the boot history
arm applies `validate_body_envelope_keys`; phase 1 flushes on the weight budget only; Want in ascending-lamport
order or evict-oldest at the per-peer orphan cap; README: the mantissa bound, the mesh-wide enable-signing
remedy ("run it on one node"), the failed-commit retry's two-envelope property, the edited-amount-plus-dropped-lamport
duplicate; the keyless `signer_installed` and dangling-link texts. Verify: un-ignore
`h19_clock_warning_is_silent_on_an_honest_mesh_with_repeated_fresh_joins`, `chain_over_the_orphan_cap_joins_within_thirty_ticks_in_advert_order`,
`op_ab`; A4 `a4_exhausted…` gives 4 records; A2 `env-edit` shows no `openledger-note` on disk.

### Finding → task coverage map

H-22→T79 · M-51→T81 · M-52→T81 · M-53→T80 · M-54→T79 · M-55→T81 · L-80→T82 · L-81→T82 · L-82→T80 · L-83→T83 ·
L-84→T82 · L-85→T82 · L-86→T83 · L-87→T83 · L-88→T83 · L-89→T83 · L-90→T83 · L-91→T80 · L-92→T83 · L-93→T82 ·
L-94→T83 · L-95→T83. **Deferred by design to T45:** M-09, M-10, L-06. **Deferred by decision:** H-01, L-23.
**Landing order:** T79 → T80 (both in `service.rs`'s boot pipeline and `main.rs`; T79 first because T80's author
change alters which arm verifies own records) → T81 (its own files: `union_merge.rs`, the boot history arm,
`limits.rs`) ∥ T82 (`finish_recovery`, `journal.rs`, `prepare`) → T83. The four invariant files are the
acceptance tests throughout; extend them before each task, as this audit did.

---

## 9. Checked and found sound (new this audit)

Beyond the 20 closures in §1.1, these were probed adversarially and held:

- **Signature coverage and the two verifiers.** `SignableMessage` covers the content id, the transaction flag,
  the parents and the lamport, bound to the mesh id, with the author as the key: a parents edit, a lamport edit
  (+1), a reordered or duplicated envelope line (last spelling wins, then verified) and a journal record edited
  under a recomputed checksum are all quarantined. The boot verifier built in `main.rs` and the wire's
  `verify_remote_signature` build the same message from the same mesh id: 1,000 random signed directives
  accepted by both, 829 mutations refused by both. A crash between `finalize_operator_input` and the compaction
  re-derives a byte-identical envelope with a quarantined own record beside it and T78's shift in force. A
  foreign record stays `Unverifiable` under the signer pass and is judged by the verifier pass; a block signed
  by another allowlisted peer is served untouched. The live watcher path refuses an edited own block (full
  envelope) with the H-20 reason and the rewrite restores the original, on a verifier node and a signer-only node.
- **Salvage.** Ten shapes — dedent, BOM before and after the indent, a stray word after the header, a corrupted
  date, two damaged lines, damaged + blank + good, CRLF + dedent, a blank line inside the envelope — all held whole
  or I1-quarantined, all fixed points, balances excluding every half.
- **The quarantine and the mesh (R2).** A's edited own record is quarantined; A serves its descendants naming
  the original id; anti-entropy re-fetches the original from B in two rounds; the compaction writes both blocks;
  the next boot quarantines the edited one again and holds the original; A == B throughout; no pair rule refuses
  the original. The enable-signing migration across two signing-off replicas plus a fresh third converges to
  equal ids, heads and balances (with L-88's attribution caveat).
- **Parents, heads, ratchet.** `select_parents` on identical head sets under different author ids names
  identical parents; an attacker holding all the smallest ids (ground to prefix `00`) plus N honest authors
  never starves an honest head; a 300-parent attacker transaction is refused identically everywhere (content
  rule); 5,000 parentless transactions from one peer are all admitted, the next honest append names 256 and the
  frontier drains ~255 per append; nothing O(heads²). The ratchet hold is monotone under a dropping clock
  (`adopt_reloaded`) and a `set_author_id` shift, released on the exact tick, never re-fetched early; pushed
  batches record nothing; a held parent of a buffered child is not re-Wanted through the drain (delay only).
  Under the 2^26 file cap `4 × count + 1024 ≪ 2^32`, so no peer can hide a partitioning jump below the warning.
- **Wire caps and chunks.** 35 uncounted parser shapes ≤ 6.5× and none stages `Ok` above it; `resident_weight`
  ≥ real on every shape; the pushed-Supply charge is released on refusal, on dedupe, on deferral and on a
  cancelled apply (`Drop`); a peer exhausts only its own 32 MiB share; a 256-entry parent chain across four
  chunks merges whole; a chunk refused at the cap backs the peer off once per frame; the refusal cache is keyed
  `(peer, id)` so an over-cap body under an honest id poisons one peer's slot only; 40,000 fuzzed bodies through
  the bounded and unbounded parsers — zero disagreements.
- **Commit, recovery, journal.** Crash matrix around the M-49 arms (A–D): no acked record lost, one sidecar per
  failed-reload → successful-compaction cycle, sidecars ≤ the bytes appended since the previous compaction; a
  reload never renames the journal, only a Compact after `persist_atomically` succeeded, so no boot can find
  records only in a sidecar; a Compact writes no journal bytes, so no crash inside it creates a checksum-failing
  final record; the `Parse` arm keeps peer and local staged records together through a reload with no missing
  parent; the L-71 estimate has no side effects (clock unmoved, signer stateless, 131 µs at 300 heads); an
  installed reload re-adopts hand lines as exempt operator input and keeps them across a second failure;
  shutdown ordering waits on the permit and a chunk committed between the compaction and router shutdown lands
  in the journal. The `(author, lamport)` pair is never reused after a rollback (4 → 7).
- **Balances.** `I256` matches `num-bigint` on every operation including exact ties in both signs and the sticky
  bit across the `10^19` step; Rule R matches the oracle digit for digit up to `±Decimal::MAX` at any scale;
  58,261 `(mantissa, scale)` round trips through `to_string`/`from_str_exact` with zero mismatches; an elided leg
  resolving to exactly `10^21` at scale 7 through a scale-8 product is accepted and re-parses, one ulp more is
  refused on every path; `@` and `@@` capped as stored, weights never summed; assertions at other scales, on
  cancelling partials, on never-posted accounts and at `Decimal::MAX` agree per-assertion and batched; no
  ingress can produce a negative zero.
- **Files and config.** The sweep leaves a reserved-name directory (WARN), removes a reserved-name symlink's
  link only, unlinks a hard link's name only; a dangling journal link beside an absent `.bean` refuses and
  creates nothing; the config loader refuses every non-regular shape before any read and a link to `/dev/stdin`
  redirected from a regular file as "replaced while being opened" (conservative); `KeyedRefusalLog` holds ≤ 65
  windows under 50,000 sources; the secret key, the `.bean`, the journal and the watcher all go through
  `open_checked`.
- **Docs.** Every README procedure executed worked; the bootstrap join on two real binaries; every config key
  at floor, floor−1, ceiling and ceiling+1; `deny_unknown_fields` on all seven sections; 29 error codes in code,
  none documented-but-gone.

---

*Previous audits: [SECURITY_AUDIT_0923.md](SECURITY_AUDIT_0923.md) · [SECURITY_AUDIT_0922-v2.md](SECURITY_AUDIT_0922-v2.md) · [SECURITY_AUDIT_0922.md](SECURITY_AUDIT_0922.md) · [SECURITY_AUDIT_0902.md](SECURITY_AUDIT_0902.md) · [SECURITY_AUDIT_0901.md](SECURITY_AUDIT_0901.md) · [docs/audits/CLAUDE_SECURITY_AUDIT_0820.md](CLAUDE_SECURITY_AUDIT_0820.md). Remediation trackers: [docs/audits/OUTSTANDING_TASKS_09_23.md](OUTSTANDING_TASKS_09_23.md) (T72–T78) · [docs/audits/OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md) (T61–T71) · [docs/audits/OUTSTANDING_TASKS_09_22.md](OUTSTANDING_TASKS_09_22.md) (T46–T60) · [docs/audits/OUTSTANDING_TASKS_09.md](OUTSTANDING_TASKS_09.md) (T18–T45) · [docs/audits/OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md) (T1–T17). Proof crates for every finding live in this session's scratchpad (`A1` … `A6`, `X1` … `X3`, `D1`); each pass's report §6 gives the re-run command, and the orchestrator's re-runs are under `orch/`.*
