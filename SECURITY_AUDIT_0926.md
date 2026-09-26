# Security Audit — openledger-v2 (0926: re-audit of T84–T89)

**Date:** 2026-09-26 · **Baseline:** HEAD `8c0a87e` (branch `main`, clean tree) · **Previous:** [SECURITY_AUDIT_0925.md](SECURITY_AUDIT_0925.md) (HEAD `45014e9`)

Scope: re-verification of **every** claim, revert-proof, existing-test change, behaviour change and residual in the
T84–T89 "Done" notes of [docs/OUTSTANDING_TASKS_09_25.md](docs/OUTSTANDING_TASKS_09_25.md) against source at HEAD,
plus fresh hunts over the ~3,400 lines T84–T89 added or changed (19 files, six commits after the 0925 audit commit
`c8364fe`; ~2,480 of them in `crates/ledger/src/service.rs`), treated as unreviewed code. Priority went to the one
rule T84 stated — `unservable_history`: every parent served, `validate_transaction` against the surviving
`AccountState`, with descendants — and its four call sites (boot after operator input, the signature pass,
finalize after M-54, the live reconcile); to the design the Done notes added without the tracker asking for it (T85's
live-path hold and `reconcile_batch_ids`, T86's REFUSING-arm consequence, T88's `retain_not_doomed` and per-peer hint
share, T89's `release_on_hold`); to the permanent wire refusal T85 introduced; to the symlink guard T87 rebuilt; and
to every WARN text T84–T89 reworded, **followed literally as the remedy an operator will apply**.

Method as established for the series: ten parallel passes — six per task (A1 T84 … A6 T89, re-verify then hunt,
four of them owning one invariant test file each), three cross-cutting interaction hunters with named compositions
(X1 the boot pipeline, X2 replication, X3 commit/recovery/file system), one documentation, configuration and
supply-chain pass that executes the CHANGELOG on the real binary — each read-only on the repo apart from its owned
test file, with its own scratch crates and target directory and a `git archive HEAD` copy for revert-proofs. Every
mechanism a pass reported was re-read in source and **every executable proof below was re-run by the orchestrator**
(the quoted outputs are the re-runs; where a timing differs from the pass's, the re-run's figure is given). Test
suite at HEAD before the audit, quiet machine: **1,374 passed, 0 failed, 2 ignored** (421 + 8 + 594 + 31 + 10 + 190
+ 48 + 28 + 7 + 11 + 5 + 21), matching T89's Done note. **Loopback QUIC for fresh binaries: still blocked** — the
repo's own test binary works (the control `happy_path_small_limits_converges` passed in the baseline and again at
22:03), a fresh build in a scratch target fails it ("client did not converge"), and the repo's *already-passing* test
binary copied byte-for-byte into the scratch directory fails identically: the block is keyed on the executable's
location (the machine's firewall), not on the code. Real-QUIC proofs and revert-proofs were therefore run in the
repo tree by the back-up / apply / run-with-control / restore / `cmp` procedure (A5 twice, the orchestrator once;
each restore compared identical, `git status` re-checked). The repository was modified in exactly six files: this
report, the new tracker, and the four invariant test files (§6).

---

## Executive summary

**T84–T89 closed what they set out to close.** All 26 register entries the 0925 backlog assigned are closed by
mechanism (H-23 · M-56 … M-62 · L-96 … L-113). Every regression test the Done notes name is green, and every
revert-proof a pass repeated (41 across the ten passes) failed the named test. Several claims were re-measured and
held:
- A fresh boot and an L-13 recovery reload of the same file derive the same served set, quarantine, closure,
  balances, envelopes and over-cap fact in 25 of 27 file shapes, and the compacted file is byte-identical in all 27.
- All seven 0925 X1 findings are closed on the probes that found them.
- A held record whose parent a peer re-supplies returns through `stage_remote_directive` with a correct clock.
- The per-peer hint share keys on the transport identity.
- `quarantinedTotal` agrees with the list.
- `cargo audit` is clean, the lockfile unchanged, and `clippy -D warnings` and `fmt --check` pass with the extended
  test files in.

**But the through-line has moved again, and the High is T85's.** The 0925 through-line was "each fix tests its own
symptom where the property is *what a fresh replica would hold*". T84 answered by stating that property once. What
0926 finds is that the rule and its neighbours **judge a snapshot where the property is a history**:

- **H-24** — T85's closure is a set of **content ids**, but membership is a property of **one copy's parents**. A
  content id hashes the economic body only, so the wire refuses — permanently, cached per `(peer, id)` — a copy of a
  held body whose parents are perfectly servable. The README's own "restate the chain" remedy, applied on one node of
  a pre-T65 mesh, is refused forever by every other node that still holds the originals (their balances differ
  across every restart; a T79–T83 node adopts the same records, so the mesh also splits by version). An API re-entry
  of a held record followed by a crash leaves a node refusing its **own acknowledged records** from every peer. T84
  had healed both shapes over the wire; T85 made them permanent. Found independently by A2 and X2; revert-proven;
  a fix that keeps every T85 pin green was validated in the archive.
- **Seven Mediums.**
  - M-63: the served-set rule judges admitted history against the *final* account state, which a later-arriving
    `open` can narrow. One peer's signed `open Assets:Cash EUR` makes every honest node stop serving an account's
    USD history — and through parenthood all later history — at its next restart. Found by A1 and A2.
  - M-64: the rule is not a fixpoint — the rebuild its own quarantine triggers creates a record served over a held
    parent, silently.
  - M-65: T86's M-59 refusal keeps a write whose call failed; near the cap it reopens M-58 through gl-node's own
    pre-stage gate.
  - M-66: T88's Want filter reads whichever peer's copy it finds, so one author's second envelope blocks an honest
    peer's copy (real QUIC).
  - M-67: the same filter is quadratic under the orphan-buffer lock.
  - M-68: the M-60 race survives one directory up.
  - M-69: gl-node's H-20 banner still prescribes the remedy T84 withdrew, and following it double-counts or empties
    the ledger.
- **The M-09 remainder is sharper than recorded.** Under the protocol's own Want order, an honest replica refuses an
  honest `close` for good when the account was re-opened and posted to later; replicas then disagree on balances and
  that replica's later writes are refused mesh-wide. It is not a T84–T89 regression; its rating is decision (38).
- **Twenty-three Lows** (§4). The widest:
  - the "EVERY signature failed" verdict suppressed by the node's own fresh signatures — a regression against T88,
    found by three passes;
  - the recovery reload re-issuing an `(author, lamport)` pair in 26 of 27 shapes, which also makes 0925 §9's "no
    executed shape re-issues a pair" wrong;
  - the H-23 remedy "add the missing open" refused as "already open";
  - L-105's five-byte gap surviving in the journal's sibling arm.

As in 0925, **the remedies the code prints create the shapes it then refuses**: "restate the chain" is H-24's
trigger, "add the missing open" is refused by L-77, gl-node's banner double-counts. The backlog (§8) is organised
around keying the closure on parenthood (T90), lifecycle verdicts that never retract (T91), the rule reaching a
fixpoint with every printed remedy working (T92), and the reload, symlink and Want-filter doors (T93–T95).

---

## Threat model

Unchanged from [09/22](SECURITY_AUDIT_0922.md) through [09/25](SECURITY_AUDIT_0925.md): (a) a web page in an
operator's browser, (b) an API-key holder, (c) a **malicious or compromised allowlisted peer**, (d) a network attacker
on a public bind, (e) whoever can write the `.bean` or its directory, plus the no-attacker cases (an operator
following the README, an editor autosave, a backup `cp`/`mv`, a crash, an upgrade over an old file, a long-offline or
freshly restored replica, a mixed-version mesh, the operator following a remedy the code prescribes). This audit
adds three cases the new code made reachable: **an account opened on two nodes with different currency lists** (a
partition, or a peer), **an equivocating author** (two envelopes of one body, which the signature over
`openledger-parents` permits), and **an account on the file system that can write an ancestor of the ledger link's
directory**.

---

## 1. Status of the 09/25 register, re-verified at HEAD `8c0a87e`

Every entry is re-verified by mechanism in source and by the named regression test; "revert-proof" means a pass
reverted the mechanism in a `git archive` copy (or, for real QUIC, in the repo tree with restore and `cmp`) and the
named test failed.

### 1.1 Closed — verified by mechanism (26)

| ID | Task | Mechanism at HEAD | Pinned by | Revert-proof |
|---|---|---|---|---|
| H-23 | T84 | `unservable_history` ([service.rs:4570-4618](crates/ledger/src/service.rs#L4570)): parents `:4582-4591`, `validate_transaction` `:4593`, `children_of` walk `:4600-4616`; `quarantine_unservable_history` `:4628` at boot `:4051`, pass `:4779`, finalize after M-54 `:4373`, live post-loop `:7642`; T79 (d) WARN gone | `h23_…`, fuzzer check 6, `a1_2`, `a4_2` ×2, `a4_3`, golden, `l40_*`; A1's new check 7 sweep (39 operators × 2 seeds × 2 positions) | yes (A1 R1: golden, `l40_*`, four `a4_`, `a1_2`, the new sweep) — **but the I3/I9 arm judges against the final account state (M-63), the rule is not a fixpoint (M-64), and the fuzzer is blind to its I3/I9 half (L-135)** |
| M-57 | T84 | `provisional_stamp` ([:7820](crates/ledger/src/service.rs#L7820)), clock untouched `:8134-8136`, `:8230-8232`; finalize stamp loop `:4386-4405`; `set_author_id` only raises the clock | `a1_1_…`, `l67_…` | yes (A1 R3) — ceiling arm lacks the rule (M-64) |
| L-97 | T84 | release excludes pending input (`:4880`), counts an edited lamport unless ≥ 2^28 above the survivors (`:4906-4911`) | `l87_the_clock_release…` ×2 (harness) | yes (Done note R4/R5; X1 `c6a/b/c` "RE-ISSUED = false") |
| M-56 | T85 | closure walks parenthood only ([:5244-5263](crates/ledger/src/service.rs#L5244)); the account question judged by the H-23 rule after operator input (`:4039` → `:4043` → `:4051`); the wire refuses closure members ([:8857-8881](crates/ledger/src/service.rs#L8857)), permanent in gl-node ([anti_entropy_alpn.rs:2473-2497](crates/gl-node/src/anti_entropy_alpn.rs#L2473)) | `m56_*` ×3, `a4_1_…`; X1 `c2d` (X served at boot 1, peer 7/7), `c8b` | yes (A2 R2) — **the wire check is keyed on content ids (H-24); its "names a closure parent" branch never fires on gl-node's path (X2)** |
| L-101 | T85 | body cap as a third content seed ([:3731-3744](crates/ledger/src/service.rs#L3731)) | `history_over_the_wire_body_cap_…`, `a2_the_closure_is_refused_…` | yes (A2 R3) |
| L-110 | T85 | clause on operator-input `open`s ([:8208-8226](crates/ledger/src/service.rs#L8208)) | `l110_…` | yes (A2 R4) — refuses its own remedy live (L-125) |
| M-58 | T86 | `prepare_refusal_needs_no_reload` ([:6056-6060](crates/ledger/src/service.rs#L6056)) in `commit_inline` (`:7321`) and gl-node ([ledger_commit.rs:466](crates/gl-node/src/ledger_commit.rs#L466)); re-measure after install (`:6825`); D1 on the real binary: 66,911,755 B, both mutations "refused before staging", 0 reloads | ledger and gl-node `m58_*`, A3 `a3_m58_…` | yes (A3 R1, R2) — **closed for its shape; M-65 reopens the symptom through the REFUSING arm** |
| M-59 | T86 | `keep_committed_envelopes_in` parent check ([:6926-6941](crates/ledger/src/service.rs#L6926)) → REFUSING arm (`:6759-6781`) | `m59_*`, A3 `a3_m59_…`, X3 `k1a` | yes (A3 R3) — **the refusal keeps the failed write (M-65)** |
| L-104 | T86 | floor keyed on `is_operator_input` ([:6877](crates/ledger/src/service.rs#L6877)) | `l104_*`, rewritten `m46_*`, A3 `a3_l104_…` | yes (A3 R4) — the exemption is dead code (L-124) |
| L-105 | T86 | no-candidate branch ([journal.rs:602-614](crates/ledger/src/journal.rs#L602)) | `l105_*`, A3 `a3_l105_…`; X3 `k8` no false positive | yes (A3 R5) — **the over-claim arm keeps the gap (L-122)** |
| M-60 | T87 | directory owned by this uid, `mode & 0o022 == 0` ([journal.rs:196-224](crates/ledger/src/journal.rs#L196)); one hop via `read_link` vs `canonicalize` (`:226-258`); real binary: 0775 → exit 1 "(M-60)" before the lock | `m60_*` ×2 | yes (A4 R1, R2) — **race-free for the link's own directory only (M-68); string compare (L-119); ACLs (L-120)** |
| M-61 | T87 | stray journal beside the link → `AlreadyExists` ([:259-277](crates/ledger/src/journal.rs#L259)); both remedies executed on the binary (D1 `case_journal`, A4) | `m61_*` ×2 | yes (A4 R3) — the sweep beside the link never runs on gl-node (L-118) |
| M-62 | T88 | `UNCHARGED_RESIDUE_CAP` ([anti_entropy_alpn.rs:1712](crates/gl-node/src/anti_entropy_alpn.rs#L1712), `:1953-1980`); `l90_*`: 64 commits, max uncharged 949,568 B | `l90_*` | yes (A5 R1: 16,617,440 B held) — the bound is `max(1 MiB, one directive)`, ≈1.9× the documented figure (L-132) |
| L-106 | T88 | `retain_not_doomed` ([orphan_buffer.rs:340-375](crates/p2p/src/orphan_buffer.rs#L340)), called at `anti_entropy_alpn.rs:1289` | p2p and gl-node `l106_*` | yes (A5 R2b; the call's removal flips A5-1) — **reads any peer's copy (M-66), quadratic under the lock (M-67), misses never-served roots (L-130)** |
| L-107 | T88 | per-peer share keyed on the transport `EndpointId` (`:2090`, `:2140-2145`), sweep in `evict_expired` | `l107_*` ×2, `l95_*` (harness, un-ignored) | yes (A5 R3, R4) |
| L-102 | T88 | 16× budget with a dense second control (14.40×) | `decode_memory` 7/7 | reasoned (14.40 > 8) — "densest" is not: 28.25× by ratio, 211 MB absolute (L-132) |
| L-103 | T88 | `quarantined_ids_capped` ([service.rs:6454-6464](crates/ledger/src/service.rs#L6454)), `quarantinedTotal: Int!`; D1 over HTTP: listed 1000, total 1005, schema diff exactly one field | `l103_*` | yes (A5 R6) |
| L-96 | T89 | `is_own_author` ([:1581](crates/ledger/src/service.rs#L1581)) in `BootLamportHigh` (`:1651`, `:1668`, `:1678`), the release floor (`:4891-4903`), `highest_lamport_author` (`:5856-5865`), `set_author_id` (`:8578-8650`); X1 `c5a` clock 9 = 9; X3 `unparsable-own` 52 on all arms | `l96_*` ×3, A6 `l96_a_placeholder_history_resumes…` (harness) | yes (A6 R1, R1b) |
| L-98 | T89 | totals and `every_checked_signature_failed` ([:4845-4849](crates/ledger/src/service.rs#L4845)) judged in `verify_own_history` (`:4519-4531`) | `l98_*` | Done note R2 — **counts finalize's own signatures (L-114)** |
| L-99 | T89 | `release_on_hold` (`:4732-4735`, `:4768-4774`); D1 `case_l99`: one WARN, lamports kept, the `meshId` fix restores 5/5 | `l99_*`, A6 `l99_a_wrong_mesh_id…` (harness) | yes (A6 R3, which also fails the reload half) — defeated by a hand line (L-114) |
| L-100 | T89 | gap check after the pass on the served DAG (`:4814-4838`), called by gl-node every boot ([main.rs:556](crates/gl-node/src/main.rs#L556)) | `l100_*` | Done note R4 |
| L-108 | T89 | `hand_parented_last` ([:9174-9203](crates/ledger/src/service.rs#L9174)) at boot `:4231` and live `:7587`; X1 `c7 order` fixed point | `l108_*`, A6 `l108_hand_lines_child_first…` | yes (A6 R5; **R5b — no topological sort — passes the unit test**, only the new harness case catches it, L-135) — keyed on the file-spelled id (L-128), quadratic (L-129) |
| L-109, L-112 | T89 | `strip_stray_envelope_keys` ([:1897-1926](crates/ledger/src/service.rs#L1897)) at boot `:3527` and live `:7784-7796`; posting-level keys are outside the hash ([serialize.rs:332](crates/ledger/src/serialize.rs#L332)) and the signature; a fresh node adopts the stripped records from A alone | `l109_*`, `l112_*`, A6 `l109_stray_keyed…` (harness) | yes (A6 R6, R7) |
| L-111, L-113 | T89 | `lamport_gap_verdict` ([:1434-1451](crates/ledger/src/service.rs#L1434)) at both WARN sites; module-level `const _` (`:1384`); D1 `case_gap`: 3·10^8 "diagnosed, not uncrossable", 5·10^9 "uncrossable" + join | `h19_the_gap_warning…` (harness, un-ignored), A6 `l113_…` | yes (A6 R8, R9) — **wrong after an author's removal (L-127)** |
| 0925 §5 | T89 | CI re-pin `6bed076` (reachable today, `refs/heads/stable` only — L-123), M-54 `"local"` text, `sign_adopted_entry` comment, summary WARN wording, README items | — | — |

### 1.2 Unchanged by decision (5)

H-01 (loopback API key), M-09, M-10, L-06 (T45 Format v2), L-23 (`meshId` required next release). **M-09's
remainder is re-opened for a decision** (§3, decision (38)).

### 1.3 Done-note residuals, existing-test changes and unrequested design — dispositions at HEAD

- **T84 (a) "judges what a fresh replica could hold"**: true for parents; for I9 the rule judges against the *final*
  account state, and a fresh replica that adopted the same set in lamport order holds what the rule quarantines
  (M-63).
- **T84 "pending operator input is exempt (the rebuild rebases it)"** is understated. The rebuild can also *refuse*
  it, and the exemption hides its history descendants from every site (M-64).
- **T84 (c) "a stamp past the ceiling quarantines the entry as written"**: true, without the rule after it (M-64).
- **T84 (e) "gl-node's quarantine banner reworded"** is wrong: only the H-08 banner was; the H-20 banner still
  prescribes deleting the edited block (M-69).
- **T84 "returns by itself once a peer re-supplies the parent"** holds only when a peer also holds the record itself
  (X2 `c2`: P and X return in one tick, Y — held by no peer — only at a restart), and never for I9-held records
  (L-136, M-63).
- **T84 existing-test changes (ten fuzzer cases, the harness case)** are weaker than decision (15) asked.
  `assert_refused_with_descendants` ([boot_fuzz.rs:1794](crates/p2p/tests/boot_fuzz.rs#L1794)) bounds a count and
  never checks dependence: holding every history transaction still passes 10 of the 11. `convergence.rs:3110`'s
  `>= 1` has no upper bound (L-135).
- **T85 "no later record can make it adoptable"** ([service.rs:8855](crates/ledger/src/service.rs#L8855)) is false for
  the own-id term (H-24).
- **T85 "a running node and a restarted one serve the same set"** is partial: the live check is by id, while boot
  re-derives membership from parenthood (H-24).
- **T85 "the live path's held records stay held until a restart or a peer's copy"** is slightly overstated: the next
  reconcile of any hand edit also re-adopts them (D1 `case_live89`, A2).
- **T85 "`close_account`'s own body-size check is now unreachable"** is **wrong**. An `open` with no currencies whose
  body is exactly 1,048,576 bytes is authored, crosses and stages; its `close` is one byte over and is refused on
  every path, so the account can never be closed (pinned passing: `a2_close_accounts_size_check_is_reachable…`).
  The edit to `test_close_rejects…` therefore loosened a real assertion (L-136).
- **T85 `m51_history_over_the_legacy_ceiling…` change** fails deterministically beside the new T85 tests (tracing's
  callsite-interest cache); green only alone or in the full `--lib` run (L-135).
- **T85 `m56_the_wire_refuses…`** pins the library entry point: on gl-node's path a record with a missing parent is
  buffered before staging ([anti_entropy_alpn.rs:2138-2160](crates/gl-node/src/anti_entropy_alpn.rs#L2138)), so the
  "names a closure parent" branch never fires (X2).
- **T86 "memory is exactly what a rebuild would derive"** is literally untrue (the refused prepare leaves stamped
  envelopes a rebuild would stamp afresh), but equal in effect through the L-81 keep (A3, executed: one balance
  running, restarted and on a fresh replica).
- **T86 "the REFUSING arm keeps a write whose call failed, as it always has"** is understated. T86 adds a trigger with
  no disk incident, the kept write is counted and served at once, and on the cap path it disables gl-node's
  pre-stage refusal (M-65).
- **T86 L-104 "exempt while not yet stamped"** describes an empty set (L-124).
- **T86 README:1038 "startup/shutdown compaction refused the same way, without a reload"** is wrong in M-65's shape.
- **T87 "race-free by construction"** holds for the link's own directory only (M-68).
- **T87 "whoever can write the directories above is already threat (e) for any ledger"** is understated. For a
  regular `.bean` an ancestor writer cannot make the node overwrite an arbitrary file (compaction renames onto the
  path; the journal is `O_NOFOLLOW`); through a link they can (M-68).
- **T87 "the sweep also clears `<link>.tmp.*`"** never runs on gl-node; R4's test boots the library with the link
  path (L-118).
- **T87 behaviour change "a directory group or others can write refuses boot"** is correct but silent on upgrades:
  under umask 002 (Debian/Ubuntu defaults), Kubernetes `fsGroup` (2775) and package state directories (0770), a
  T82-era symlinked ledger stops booting. The refusal is loud, pre-write and names the mode (Info; T94 adds the
  `chmod` remedy).
- **T88 "suppressed only for the peer whose copy of its root was refused" / "other peers are unaffected"** are wrong
  (M-66, L-133).
- **T88 "about its own 32 MiB budget"** is understated ≈1.9×, and "committed per ~1 MiB, never per directive" is wrong
  for dense content (L-132).
- **T88 "densest frame 14.4×, stated and bounded"** is wrong as a ratio (L-132).
- **T88 "`oldest_hint_at` keeps it O(1)"** holds per call; in steady state each expiring hint costs a full pass
  (L-134).
- **T89 (b)/(c) "judged once, over every pass"**: the passes include finalize's pass over records this node signed
  moments earlier (L-114).
- **T89 "a hand child placed before its hand parent is adopted in the same boot"** is overstated for an
  elided-posting parent (L-128), and the named test does not pin the topological order (L-135).
- **T89 "prescribes the bootstrap join only for a gap ≥ 2^32"** and README's "nothing needs doing" are wrong after an
  author's removal (L-127).
- **T89 "the one-slot clock step … does not re-issue a pair since T84"** holds for the boot pipeline; the recovery
  reload does re-issue one (L-115).
- **0925 §9 "no executed shape re-issues a pair" (the L-81 clock rule)** is **wrong at HEAD**: X3 `k1b` now logs
  `true` (it logged `false` at 0925); T84's provisional stamp is what turned it (L-115).
- **T29's residual "STATE divergence for a fixed set is not possible"** is wrong for a re-open posted to after the
  re-open (M-09 remainder, §3).
- **`release_on_hold` (T89's unrequested design)** is sound apart from L-114. It is reset and re-derived on a reload,
  the clock never falls while it is held, and a re-installed verifier re-judges only `unverified_history`.
- **`reconcile_batch_ids` (T85's unrequested design)** is sound. The set is filled after the parse and cleared with
  no early return in between, a forward same-file parent is honoured, and a later parent refused for another reason
  leaves the child held (A2, X3).

---

## 2. New findings — High

### H-24 — T85's closure check refuses by content id where membership is a property of one copy's parents: the README's "restate the chain" remedy, applied on one node, is refused forever by every other node that held the originals, and an API re-entry of a held record followed by a crash leaves a node refusing its own acknowledged records from every peer

Found independently by **A2** (A2-1) and **X2** (X2-1). **EXECUTED**, revert-proven, fix validated in the archive.

**Mechanism.** `refused_history_closure` is a set of content ids: the seeds this boot refused under a content rule
plus their descendants **in this file's copy** (`quarantine_descendants_of_refused_history`,
[service.rs:5244-5263](crates/ledger/src/service.rs#L5244)). A content id hashes the economic body only
([hash.rs:15-19](crates/ledger/src/hash.rs#L15)). The parents sit in the envelope, and the design relies on that
elsewhere: `live_quarantine`'s doc at `:6383` ("a peer serving the same economic body"), `RefusalCache`'s rationale
at [anti_entropy.rs:702-708](crates/p2p/src/anti_entropy.rs#L702).

The checks keyed on that set:
- `stage_remote_directive` refuses any record whose **own id** is in the closure, whatever the offered copy's parents
  ([:8857-8881](crates/ledger/src/service.rs#L8857)). The live file path does the same (`:7843-7870`).
- gl-node classifies `InvalidInput` as permanent and caches it per `(peer, id)`
  ([anti_entropy_alpn.rs:2473-2497](crates/gl-node/src/anti_entropy_alpn.rs#L2473)).
- The held block stays in the file (H-08), so the next boot re-seeds the same ids.
- The other branch — "names a parent in the closure" — never fires on gl-node's path: a record with a missing parent
  is buffered before staging ([anti_entropy_alpn.rs:2138-2160](crates/gl-node/src/anti_entropy_alpn.rs#L2138)), and a
  closure member is never in the DAG. So the only refusal that fires is the own-id one, and only for a copy whose
  parents all resolve — an **adoptable** record.

**Shape 1 — the prescribed remedy, mesh-wide.**
- A pre-T65 mesh replicated X (an amount of 5·10^22 or 10^22), its child C and grandchild G.
- After the upgrade, every node's closure holds C and G.
- On node A the operator follows §Upgrading and the M-52/closure WARN ("restate the chain"): restate X in a larger
  unit, strip C's and G's `openledger-*` lines. A re-adopts C and G under the same ids with parents it serves, and a
  fresh replica stages all three.
- Every other node refuses C and G for good, across restarts. Orchestrator re-runs:
  ```
  $ cargo test -p p2p --test m50_wire a2_a_restated_chain -- --ignored
  A2-1: B staged ["OK", "INVALID_INPUT", "INVALID_INPUT"], after a restart ["OK", "INVALID_INPUT", "INVALID_INPUT"]; A and a fresh replica serve C and G, B never will

  $ X2_DIR=… …/X2/target/release/x2 c1f          # A2 restarts after every round
    round 1: A2 has D REFUSED-for-good E buffered; DAG A1 7 A2 4 C 7; balances A1==C true A2==C false
    round 2: A2 has D REFUSED-for-good E buffered; DAG A1 9 A2 5 C 9; balances A1==C true A2==C false
    round 3: A2 has D REFUSED-for-good E buffered; DAG A1 11 A2 6 C 11; balances A1==C true A2==C false
  ```
- Variants:
  - X2 `c1e`: the chain restated on a node that never held it.
  - X2 `c1d`: the chain restated through the API. The node refuses its peers' children of the restated records until
    it restarts.
- **Mixed version** (X2 `xver.sh … s3`): a HEAD receiver refuses the restated copy; a `45014e9` receiver adopts it,
  whichever version serves.

**Shape 2 — a single node, no hand edit.**
- The closure holds C (a child of a pre-T65 X).
- The operator re-enters C's transaction through the API (same body, same id; accepted because the DAG lacks it) and
  writes Y on top. Both are acknowledged journal records.
- The process dies before its stop compaction. Boot reads the canonical file's old C (parent X) before the
  journal's C, and the first copy wins (the duplicate arm, `:3860`).
- The closure takes C by id and Y as its child:
  ```
  $ cargo test -p p2p --test m50_wire a2_a_record_reentered -- --ignored
  A2-1: after the crash the node serves neither its C nor its Y, held ["53aba2c0…d68e", "b60ba2f4…a309"], and refuses a peer's copies: ["INVALID_INPUT", "INVALID_INPUT"]
  ```

**Revert-proof.** With the check at `:8857` disabled (A2 R2, X2 `if false &&`), both m50_wire cases pass and X2
`c1f`/`c1e`/`c1d` converge (`round 1: A2 has D DAG E DAG; … A2==C true`).

**Consequence.** Two honest replicas with the same available set hold permanently different DAGs and balances
(shape 1). A node is permanently partitioned from its own acknowledged records and from everything the mesh writes
on top of them (shape 2). Nothing new is logged on the refusing nodes. It is triggered by a remedy the code itself
prints. Before T85 both shapes healed over the wire.

**Fix (T90, decision (36)).** Refuse on the wire and on the live file path only a copy that names a closure parent the
DAG lacks, drop the own-id term, and remove an id from the closure once a copy is adopted. Have boot's duplicate-body
arm prefer the copy whose parents are served. A2 (F1) and X2 (fix-sketch v2) validated this in the archive: both A2-1
tests and X2 `c1f`/`c1e`/`c1d` pass, and `m56_*`, `l110_*`, `l40_*`, `ct9_*` and `a2_the_closure_is_refused…` stay
green. The variant without the "DAG lacks it" test still refuses E until a restart. Pinned:
`a2_a_restated_chain_reaches_every_node_that_held_the_old_one`,
`a2_a_record_reentered_through_the_api_returns_from_a_peer_after_a_crash` (`m50_wire.rs`, ignored).

---

## 3. New findings — Medium

### M-63 — The served-set rule judges admitted history against the final account state, which a later-arriving `open` can narrow: one peer's signed `open` of an already-open account in another currency makes every honest node stop serving that account's later history, and through parenthood all later history on every account, at its next restart or hand edit

Found independently by **A1** (A1-1) and **A2** (A2-4). **EXECUTED.**

**Mechanism.**
- `stage_remote_directive` inserts a peer's `open` as data with no lifecycle check
  ([service.rs:9015-9027](crates/ledger/src/service.rs#L9015)); this is M-09's design (T29: a peer's `open` joins the
  lifecycle at its own date). L-77's "already open" exists only on the file path (`:8187`) and the API.
- I9 at date *d* is decided by the latest `open` dated ≤ *d*, so a later-arriving `open Assets:Cash 2024-01-04 EUR`
  retroactively refuses USD transactions dated after it that every replica admitted.
- `unservable_history` judges every served transaction against the **final** `self.accounts` (`:4593`) and walks
  descendants (`:4600-4616`). Transactions take every head as parents, so in practice that is all later history on
  every account.
- It runs at the next boot (`:4051`) and at the next live reconcile (`:7642`, T85). Before T84 boot applied no
  lifecycle rule to history, and the same `open` only refused new writes on that account.

**Proof** (A1 `a1p0926 i9`, re-run):
```
[N live, after B's open] directives=10 quarantined=0 served txns=["T1 cash","T2 cash","T3 cash","T4 bank (other account)"] Cash={"USD": -6.00} Bank={"USD": -4.00}
[fresh F synced from N in lamport order] directives=10 quarantined=0 … served txns=[T1,T2,T3,T4]
[N after restart] directives=7 quarantined=3 clock=11 served txns=["T1 cash"] Cash={"USD": -1.00} Bank=-
  N refuses 0851a0f6 from F: stage: Validation: Account Assets:Cash does not accept USD; allowed: EUR
[F after its restart] directives=7 quarantined=4 … served txns=["T1 cash"]      # F's own acknowledged write W is gone
[N after remedy] … quarantined=4                                               # hand "open Assets:Cash USD" → "already open"
```
- Live-path variant: one hand `note` under the running node → `quarantined=3`.
- A2's `a2_a_peer_open_never_unserves…` (re-run): `T1 served after the live reconcile false (2 held), after a restart
  false`. The held pair is T1 and the operator's next hand line, which was signed first and then held.
- Revert (boot and live rule off): N keeps T1–T4 and F's W survives.

**Consequence.**
- One signed directive, accepted mesh-wide by design, removes acknowledged records from every balance on every node
  as each restarts. Until then running and restarted nodes disagree, and a node that has not restarted keeps writing
  on top of records its restarted peers refuse, losing those writes at its own restart.
- None of the WARN's remedies works: the hand `open` is refused as already open, and a bootstrap join copies the same
  `open`. The real remedy — remove that `open` from every node's file and its author from every allowlist — is
  printed nowhere.
- Honest variant: two partitioned nodes opening one account with different currency lists. It is loud (every held id
  is named), so Medium by the series' scale.

**Fix (T91, decision (37)).** Make the verdict monotone in the directive set; the recommended form is the union of
currencies over every `open` dated ≤ *d*. The WARN also names the `open` whose arrival changed the verdict. Pinned:
`a1_0926_1_a_restart_with_nothing_edited_serves_what_the_running_node_served` (`boot_fuzz.rs`),
`a2_a_peer_open_never_unserves_history_this_node_already_serves` (`m50_wire.rs`).

### M-64 — The served-set rule is not a fixpoint: the rebuild its own quarantine triggers refuses pending hand-parented operator input whose history descendants the rule had exempted, and the finalize ceiling arm quarantines without the rule; a signed record is then served over a parent held in the quarantine, and every later write is unadoptable, with nothing naming it

Found by **X1** (X1-1, X1-2) and **A1** (A1-2). **EXECUTED**; fix-proofs executed.

**Mechanism.**
- `quarantine_unservable_history` exempts pending operator input ([service.rs:4629](crates/ledger/src/service.rs#L4629)),
  and the walk does not pass through it (`:4608`).
- `quarantine_out_of_dag` → `rebuild_dag` then refuses a pending **hand-parented** line (a half envelope — the
  operator deleted a record's `openledger-lamport` and `openledger-signature`, kept author and parents: M-47) whose
  hand parent the rule just held (`rebase_operator_input` `:5302`, `refused_now` `:5156`). That line's signed history
  child is re-inserted with a dangling parent (`:5163`).
- No site re-runs the rule: boot `:4051` is followed only by the measure, the pass site `:4779` is the pass's last
  step, and finalize returns at once with nothing pending (`:4334`).
- Separately, finalize's ceiling arm ([:4389-4412](crates/ledger/src/service.rs#L4389)) quarantines unstampable
  operator input and never calls the rule. The M-54 arm does (`:4373`).

**Proof** (X1 `n1`, re-run). Own chain T1←R←T←P←C; P half-enveloped; R's block deleted (`n1a`) or an `open`'s
lamport edited (`n1b`):
```
WARN … quarantining operator input adopted at boot, kept in the file as written: it depended on a record this boot has since quarantined (H-22, H-08) id=8ff3dd4b…
SERVED WITH A DANGLING PARENT: C(59f61e35) names P(8ff3dd4b) (held in this node's quarantine)
FRESH PEER [canonical] REFUSES C(59f61e35): stage_remote_directive: DAG: Missing parent: … unknown parent 8ff3dd4b…
the node's next write W: parents=[C(59f61e35),T1(9a729708)] … REFUSES W
FIXED POINT: file byte-identical after 2nd compaction = true
```
- The state is identical after a crash and after the L-13 reload.
- Ceiling arm (X1 `n2`, A1 `a1p0926 ceiling`): `X served = true; HandOpenNew served = false … FRESH PEER REFUSES X(on
  New): Account Assets:New not open`. The M-54 control holds X.
- Fix-proofs: `quarantine_out_of_dag(&ids)` followed by the rule (X1), and the rule after `:4411` (X1, A1). The
  fresh peer then accepts everything; boot_fuzz reaches 54 passed / 0 failed / 3 ignored.

**Consequence.** H-23's consequence — this node's later history is unadoptable mesh-wide, as a fixed point — reached
through a partial-envelope edit or a node near the lamport ceiling. P is named; C and the writes on top of it are not.
Following the H-23 summary literally (strip all of P's `openledger-*` lines) repairs it (peer 8/8).

**Fix (T92, decision (39)).** Run the rule to a fixpoint after every quarantine step. Pinned:
`a1_0926_2_a_ceiling_refused_hand_line_leaves_nothing_served_over_it` (`boot_fuzz.rs`).

### M-65 — T86's M-59 refusal rolls a failed write forward: a hand edit adopted inside a write's `prepare` names the staged write as its parent, the failed commit's reload is refused, and the write whose call returned an error is counted, served and kept; near the cap every later mutation rebuilds under the permit, M-58's symptom through gl-node's own pre-stage gate

Found by **A3** (A3-1). **EXECUTED** (library, and gl-node's GraphQL path in an archive copy).

**Mechanism.**
1. With the watcher off (the default), a running node adopts a hand edit inside the next write's `prepare`
   (`finalize` [service.rs:6182](crates/ledger/src/service.rs#L6182), `adopt_external_edits` `:6194`).
2. The adoption chooses the hand line's parents from every head, including the write staged in the same call
   (`:8003-8010`).
3. If that commit fails, `keep_committed_envelopes_in` finds a kept envelope naming the staged write and refuses the
   install (`:6939-6941` → REFUSING `:6761-6780`). Memory, with the failed write, is kept.
4. On a near-cap ledger the adopted envelopes push the canonical form over the cap (`:7698`), so the write can never
   be written.
5. `pending_ids` stays non-empty. So `prepare_refusal_needs_no_reload` stays false and every compaction reloads (and
   refuses) again. gl-node's `refuse_if_local_write_cannot_fit` also returns `Ok` whenever `uncommitted_count() > 0`
   ([ledger_commit.rs:561](crates/gl-node/src/ledger_commit.rs#L561)).

**Proof.**
- Orchestrator re-run:
  ```
  $ cargo test -p ledger --test exact_balances a3_1_a_write_whose -- --ignored
  assertion `left == right` failed: the failed call's 7 is in the balance (1 staged write kept)
    left: Some("112")
   right: Some("105")
  ```
- gl-node's GraphQL path (A3's probe; log re-read):
  ```
  mutation 0: RESOURCE_LIMIT_EXCEEDED in 41.6s; REFUSING so far 1; directives 46; uncommitted 1; headroom 0; cash -220
  mutation 1: RESOURCE_LIMIT_EXCEEDED in 46.4s; REFUSING so far 2; directives 47; uncommitted 2; headroom 0; cash -225
  mutation 2: RESOURCE_LIMIT_EXCEEDED in 25.3s; REFUSING so far 3; directives 48; uncommitted 3; headroom 0; cash -230
  cash running -230 after restart -215
  ```

**Consequence.**
- Each write is told `RESOURCE_LIMIT_EXCEEDED`, yet it is counted in balances and served (anti-entropy serves pending
  records).
- The writes vanish at restart, unless a peer pulled them, in which case they come back after the client was told
  they were refused.
- Every write after the first costs a full rebuild under the single-writer permit — the M-58 symptom T86 closed.
- The I/O flavour needs no cap: a hand edit plus any failed commit makes a failed call's write durable.
- README:1038 is wrong for this shape. It needs a running-node hand edit, which README:987 documents as adopted at
  the next write.

**Fix (T93, decision (43)).** Choose operator input's parents from committed records only, and have gl-node refuse
before staging whenever `canonical_over_cap`. Pinned: both `a3_1_…` cases (`exact_balances.rs`).

### M-66 — T88's `retain_not_doomed` judges a Want id by whichever peer's copy it finds, so an allowlisted author's second envelope of its own record keeps an honest peer's copy — and everything honest written on top of it — out of a replica's Want

Found by **A5** (A5-1). **EXECUTED over real QUIC in the repo tree** (gotcha-6 procedure; re-run by the orchestrator,
file restored and compared identical).

**Mechanism.**
- `retain_not_doomed(peer=H)` takes a Want id's parents from any buffered entry or hint
  ([orphan_buffer.rs:348-356](crates/p2p/src/orphan_buffer.rs#L348)). It ignores `entry.from_peer` and the hint's
  recorded peer, and asks only whether those parents are refused-for-good **for H** (`:362`).
- A content id covers the body, and the signature covers `openledger-parents`. So author M can sign a second
  envelope of its own record C with parents = K, a record V refused from H for good.
- M can create that refusal by delivery order: a back-dated `close` refused as `AccountHasLaterTransactions`,
  permanent — the M-09 shape.
- M pushes its envelope to V first, and V buffers it.

**Proof** (re-run, `a5_1_an_equivocating_author_suppresses_an_honest_peers_copy` + control):
```
A5-1 control: K wanted 1 (refused for H: true); C wanted 1 times, D wanted 1 times over 4 exchanges; C adopted true, D adopted true
A5-1 attacked: push of M's second envelope of C: SupplyOutcome { … buffered: 1 … }
A5-1 attacked: K wanted 1 (refused for H: true); C wanted 0 times, D wanted 1 times over 4 exchanges; C adopted false, D adopted false
test anti_entropy_alpn::tests::happy_path_small_limits_converges ... ok
```
With the call removed, the attacked case adopts C and D.

**Consequence.**
- V never Wants C from any honest peer, so everything written on top of C is withheld from V.
- Gossip does not rescue it: announces are for local writes only, and M does not announce C.
- The hold lasts the (H, K) refusal's TTL (10 min). M renews it with each new record, keeping V ~10 min behind
  indefinitely.
- T88 reopened what per-peer refusal keying ([anti_entropy.rs:702-708](crates/p2p/src/anti_entropy.rs#L702))
  prevents.

**Fix (T95, decision (48)).** Judge only copies and hints the asked peer itself delivered, and skip parents the DAG now
holds.

### M-67 — `retain_not_doomed` is quadratic in a peer-ordered Want and runs before the ancestors-first ordering, under the orphan-buffer lock that phase 2 of every batch waits for while holding the ledger write lock

Found by **A5** (A5-2). **EXECUTED** for the cost; the stall is **PLAUSIBLE**, from the lock order.

**Mechanism.** The fixpoint ([orphan_buffer.rs:342-370](crates/p2p/src/orphan_buffer.rs#L342)) re-walks the whole
Want for each newly doomed id. It runs at [anti_entropy_alpn.rs:1289](crates/gl-node/src/anti_entropy_alpn.rs#L1289)
under `orphan_buffer.read()`, before `order_want_ancestors_first` (`:1311`), so the Want is in the peer's advert
order.

**Proof** (re-run, release):
```
A5-7 parent-first: 1000 buffered + 8192 hinted = 9192 in the Want; dropped 9192 in 3.841542ms
A5-7 child-first:  1000 buffered + 8192 hinted = 9192 in the Want; dropped 9192 in 9.795337s      (A5: 14.6 s)
```

**Consequence.**
- A peer advertising its refused chain child-first costs ~10–15 s of CPU per exchange, and exchanges run every 5 s.
  The advert cap (1,048,576 ids) does not bind.
- Phase 2 of any peer's batch holds `ledger.write()` (`:2092`) while it waits for `orphan_buffer.write()` (`:2140`),
  so GraphQL queues behind the filter. That is a resource exhaustion beyond the documented budgets, reachable by an
  allowlisted peer.

**Fix (T95).** Order ancestors-first before filtering and compute the doomed set in one pass over a parent→children
index, on a snapshot outside the lock.

### M-68 — The M-60 race survives one directory up: an account that can write an ancestor of the link's directory swaps that whole directory between T87's check and the follow, and the next compaction rewrites any file the node's uid owns

Found by **A4** (A4-1). **EXECUTED** with a same-uid swapper; the other-uid step holds by construction, as in 0925 X3
`k4a`.

**Mechanism.** `resolve_ledger_path` re-resolves the link's directory **by path** at each step:
- `symlink_metadata(configured)` ([journal.rs:182](crates/ledger/src/journal.rs#L182))
- `metadata(&link_directory)` (`:208`)
- `canonicalize(configured)` (`:226`)
- `read_link` (`:231`)
- `canonicalize(target dir)` (`:244`)

An account that can write a non-sticky ancestor puts its own directory beside the operator's, holding
`ledger.bean -> /victim/file`. It exchanges the two atomically (`renamex_np(RENAME_SWAP)` / `renameat2(RENAME_EXCHANGE)`)
between `:208` and `:226`. The directory rule has already approved the operator's directory, while the follow and the
one-hop comparison both see the attacker's link and agree.

**Proof** (re-run):
```
[control: evil/ at node/ (0777)] Err(PermissionDenied): … a directory with mode 777, writable by group or others … (M-60)
race 5s: calls=109733 swaps=858 -> target=7176 VICTIM=276 unresolved=0 refused(dir rule)=102265 refused(one hop)=16 other_err=0 first_victim_call=Some(3)
```
`consequence`: `boot(victim)` + `compact()` → `compact: Ok(()); victim changed: true` (the victim gains `openledger-*`
lines).

**Scope.**
- A sticky ancestor (`/tmp`) blocks the swap.
- A relative `ledgerPath` whose link sits in the cwd itself is immune (reasoned).
- A plain-`rename` swapper gave 0 hits in 5 s; the exchange syscall is what makes it practical.
- For a regular `.bean` an ancestor writer cannot do this (compaction renames onto the path; the journal is
  `O_NOFOLLOW`), so T87's "already threat (e) for any ledger" residual is understated.

**Fix (T94, decision (46)).** Resolve through one directory handle (`openat` / `fstat` / `fstatat` / `readlinkat`,
compare `(dev, ino)`).

### M-69 — gl-node's H-20 boot banner still prescribes "delete the edited block and append a reversing entry" — the remedy T84 withdrew from the ledger's own WARN and the README; followed literally, the entry is counted twice, and after enabling signing over an unsigned history the operator empties the ledger

Found independently by **X1** (X1-5) and **D1** (D1-1). **EXECUTED** on the library and on the real binary.

**Mechanism.** The banner at [main.rs:560-572](crates/gl-node/src/main.rs#L560) predates T84. T84 reworded the
per-record WARN (service.rs `:4741-4749`: "deleting the block leaves what descends from it held (H-23)") and the
README; T89 rewrote the summary for pre-signing history ("Delete their openledger-* lines"). The banner — the last and
most visible line — was not reworded. T84's Done note (e) says "gl-node's quarantine banner" was; only the H-08
banner (`main.rs:285-300`) was.

**Proof.**
- X1 `n6a` (re-run): with T2 (lunch, Cash −10) edited, following the banner gives `served=["Rev(hand)", "T1", …]
  quarantined=["T3(child of T2)"]` and `Cash={"USD": 110.00}` where unedited Cash is 88.00.
- D1 `case_h23a` on the binary: journal `['reversal of T1']`, Cash −1 instead of 3.
- D1 `case_banner_b` (re-run): after enabling signing over an unsigned history, the banner prints right after the
  correct "delete their openledger-* lines" summary. Following the banner leaves `served journal [] nodesChecked 0`
  — the whole history gone from what the node serves.

**Consequence.** Incorrect balances, or an emptied ledger, reached by following the code's own remedy. It contradicts
the line printed just before it.

**Fix (T92, decision (40)).** Defer to the per-record reasons and name the working remedies; pin the text in a gl-node
test.

### The M-09 remainder, sharpened — re-rated High by decision (38) (not a new ID)

Found by **X1** (X1-3). **EXECUTED** at library level with the real `compute_want` order.

**Mechanism.**
- `reject_backdated_close` ([service.rs:8460](crates/ledger/src/service.rs#L8460)) refuses a `close` when any held
  posting is later — including postings after a later re-open, which the lifecycle fold
  ([accounts.rs:247-256](crates/ledger/src/accounts.rs#L247)) admits.
- `compute_want` puts remote heads first ([anti_entropy.rs:35](crates/p2p/src/anti_entropy.rs#L35)), and the latest
  transaction is a head.
- Arrival order is kept ([anti_entropy_alpn.rs:1980](crates/gl-node/src/anti_entropy_alpn.rs#L1980)), and
  `AccountHasLaterTransactions` is permanent (`:2483`).
- T29's permutation fixture re-opens Cash but posts nothing after the re-open, so it never meets this shape.

**Proof** (re-run, `x1 n3e`):
```
[R, back online] REFUSED FOR GOOD: closeF:Side(eef3f51c): Cannot close Assets:Side: has transactions as late as 2024-04-01
R's Assets:Side balance = Some({"USD": 8.00}); A's = Some({"USD": 7.00})
R open on Side at 02-15 = true; A open on Side at 02-15 = false
```
R's ordinary back-dated receipt (02-15) and every later write of R's are refused by every other replica
(`AccountClosed`, re-buffered forever).

**Consequence.** Two honest replicas with the same available set and permanently different balances — the scale's
High. T29's residual "state divergence for a fixed set is not possible" is wrong here. It predates this series and is
recorded as M-09 ("partially closed, remote-close admission order-dependent, T45").

**Decision (38), taken 2026-09-26:** re-rated **High** and fixed now in T91 — a `close` is refused only when, under
the fold, it would invalidate a held transaction.

---

## 4. New findings — Low

- **L-114 — The "EVERY signature failed / do not author" verdict counts this node's own fresh signatures, so a hand
  line in the same boot (or one write before the next boot) hides a `meshId`/key mismatch; a Fresh boot and a reload
  of the same file disagree.** Found by X1 (`n5`), X3 (`diff=sh:domain+handopen`) and A6 (`a6_2`).
  - `finalize_operator_input` puts what it just signed into `unverified_history` ([service.rs:4453](crates/ledger/src/service.rs#L4453)).
  - Its pass (`:4469`) counts it verified (`:4722`), so `every_checked_signature_failed` (`:4845`) is false and
    `release_on_hold` is released (`:4732`).
  - `finish_recovery` judges before finalize (`:6818-6819`), so the reload prints the WARN.
  - Re-runs: `EVERY-signature WARN lines = 1` (control) vs `= 0` (with one hand `open`); `DIFF A vs B(reload) WARN
    x0 vs x1: EVERY signature this node checked failed`; `A6-2: EVERY WARN with a hand line in the boot: false; at
    the boot after one write: false`.
  - A6's differential: `8bf3287` (T88) `EVERY_WARN=true`, HEAD `false` — a regression.
  - The hand line is signed under a domain every peer refuses, and the operator is told every record was edited.
  - Fix (T92, decision (41)). Pinned: `a6_2_…` (`convergence.rs`).
- **L-115 — The recovery reload lowers the clock below the lamport of the staged write it discards, so the next write
  re-issues that `(author, lamport)` pair.** Found by X3.
  - `finish_recovery`'s install takes the rebuild's `max + 1`; `keep_committed_envelopes_in` raises it only to kept
    records ([:6951-6957](crates/ledger/src/service.rs#L6951)), whose comment states the M-18 rule this breaks.
  - 26 of 27 shapes (`diff=all`), including `k7`, which needs no backup. Re-run: `next write … lamport=10 … same
    (author, lamport) as the served S? true`.
  - `k1b` (the 0925 backup shape): `false` at 0925, `true` now. T84's provisional stamp turned it (archive revert
    `X3_REVERT_PROVISIONAL=1` → `false`); the other shapes date from T44.
  - A peer that pulled S during the window (L-86) holds two records under one pair. Low by decision (17)'s rating of
    a re-issued pair.
  - Fix (T93, decision (44)), validated in the archive (`X3_FIX_CLOCK=1`: every shape ok).
- **L-116 — A hand line adopted live and served whose compaction then fails is re-stamped at the next restart: two
  envelopes for one id mesh-wide.** X3 `k9` (re-run): `lamport=10 sig=06f977d8 | same envelope as E1? false`; `node
  pairs == peer pairs? false`. Pre-T84 (the L-81 keep protects a reload, not a restart). Fix (T93, decision (45)).
- **L-117 — The recovery reload re-resolves the ledger path, so a ledger moved behind a link while the node runs is
  worked at the new target while gl-node's lock and watcher stay on the old path.** `boot_with` →
  `resolve_ledger_path` ([:3263](crates/ledger/src/service.rs#L3263)); `adopt_reloaded`'s doc (`:7041`) says the path
  is carried. X3 `k12` (re-run): `after the reload the node works at elsewhere/moved.bean … gl-node's lock and watcher
  stay on ledger.bean(.lock)`. A second node pointed at the new target is not excluded by the lock (PLAUSIBLE). Fix
  (T93).
- **L-118 — T87's sweep of `<link>.tmp.*` never runs on gl-node.** [service.rs:3297](crates/ledger/src/service.rs#L3297)
  sweeps only when `file_path != configured`, and gl-node passes `boot` the resolved path (`main.rs:216`, `:247`). The
  INFO "ledger path is a symbolic link (L-84)" never prints on the binary either. A4 `case_sweep_and_remedy.py`
  (re-run): `stale temp beside the LINK still there: True`. Fix (T94): a public sweep called by gl-node after the
  lock.
- **L-119 — The one-hop check compares path strings, so a valid single link whose target differs from the on-disk
  name in case or Unicode normalisation (macOS default APFS) is refused as "itself a symbolic link".**
  [journal.rs:237-250](crates/ledger/src/journal.rs#L237). A4 `hops` (re-run): `open through h.bean works: true`
  → `Err(PermissionDenied): … which is itself a symbolic link …`; the same for NFC vs NFD `café`; the real binary
  exits 1. Fix (T94): identity compare.
- **L-120 — The directory rule reads mode bits only; a macOS ACL granting everyone add/delete passes.** A4 `acl`, X3
  `k11`: `drwx------+ … 0: group:everyone allow add_file,add_subdirectory,delete_child` → `Ok(…)`. Linux POSIX ACLs
  show through the group mask. That another account could then race is PLAUSIBLE (no second account). Fix (T94,
  decision (47)).
- **L-121 — The H-23 remedy "add the missing open, dated no later than the first transaction" is refused at boot as
  "already open" whenever the node's own (edited or moved) `open` is still in the DAG at adoption.** L-77
  ([:8186-8195](crates/ledger/src/service.rs#L8186)); the L-110 text carrying the right remedy is reached only live.
  D1 `case_h23b` (re-run): `Account Assets:Cash is already open`, `"account": null`; A1 `dated_after` on signing and
  signing-off nodes; pinned `a1_0926_3_…` (`boot_fuzz.rs`). Nothing lost (restoring the `open`, or stripping its
  envelope, works). Fix (T92, decision (42)).
- **L-122 — L-105's five-byte gap survives in the journal's over-claim arm.** In the `payload_length > remaining` arm
  ([journal.rs:470-497](crates/ledger/src/journal.rs#L470)), boot fails closed only when `has_later_record_header`
  finds a complete `;;olj ` tag. T86's own-hash discriminator runs only in the exact-length arm. D1 `case_l105b`
  (re-run): a later append torn after 1, 3 or 5 bytes → `ready=True served=[]` (the acknowledged record dropped as a
  torn tail); after 6 or 9 → `journal is corrupt`. CHANGELOG:133/:188 say the opposite. Fix (T93).
- **L-123 — The CI re-pin recreates the unreachable-pin condition.** `dtolnay/rust-toolchain@6bed076` is a leaf
  reachable only from the regenerated `stable` branch (re-run: `git ls-remote … | grep 6bed0761` →
  `refs/heads/stable` only); its parent is on `master`, which has moved on; the next regeneration orphans it as it
  orphaned `4360b52`. Fix (T96, decision (51)).
- **L-124 — T86's L-104 exemption is dead code.** Boot adoption writes the author and a provisional lamport into the
  DAG copy (`:7976-7985`), so `is_operator_input(memory copy)` is never true (`:6873-6877`). A3's probe: `REFUSING …
  still unstamped … adopted_from_file=1`. The floor's log text (`:6745-6750`), `finish_recovery`'s doc
  (`:6644-6648`, "T62's floor (a) exactly as before") and CHANGELOG:124 describe an empty set. Fix (T93).
- **L-125 — T85's L-110 clause refuses the remedy its own WARN names when applied under a running node, and the
  compaction writes the edited envelope back.** Stripping the envelope gives an operator-input `open` with the held
  record's own id, which the clause (`:8208-8213`) finds in `live_quarantine`. A2 `a2_the_l110_remedy_followed…`
  (re-run): `open live false, the compaction wrote the edited envelope back true`. Stop → edit → start works (pinned
  passing). Fix (T92): exempt the same id.
- **L-126 — The live reconcile deletes from the file a pasted complete envelope the accounts refuse, where boot
  quarantines and keeps the same bytes.** T85's hold covers the missing-parent arm only (`:8082-8108`); a validation
  failure goes to `tally.refuse` (`:8164-8166`) and the re-persist drops it. A2 `a2_the_live_reconcile_keeps…`
  (re-run): `left: [("live", false, true), ("boot", true, true)]`. The served set is the same. Fix (T90).
- **L-127 — The gap verdict counts a removed author's own records, so two consecutive sub-2^32 jumps by that author
  are called crossable ("no bootstrap join is needed") while a fresh joiner is partitioned.**
  - The verdict ([:1434-1451](crates/ledger/src/service.rs#L1434)) is judged over the served DAG, which still holds
    the removed author's records: gl-node's verifier does not consult the allowlist.
  - A6 `a6_1` (re-run): `A's WARN says crossable: true; F after 2 rounds holds 4 of 9, clock 6`.
  - Seventeen or more sub-2^28 steps partition with no WARN at all (a blind spot since T83).
  - The verdict's `>=` at exactly 2^32 is one off against the ratchet (`:1562`) and adoption's `max + 1`: A6 `a6_4`
    `F's gap 4294967296 … F crossed it: true` (Info, folded in).
  - Before T89 the text prescribed the join for every gap ≥ 2^28, which was correct for this shape.
  - Fix (T96, decision (50)).
- **L-128 — `hand_parented_last` orders by the file-spelled id; a hand child names an elided-posting hand parent by
  its stored (I2-resolved) id, so the child keeps file order.** It is refused at boot 1 and served at boot 2; on the
  live path it is refused and deleted from the file ([:9185-9197](crates/ledger/src/service.rs#L9185)). A6 `a6_3`
  (re-run): `child served at boot 1 false, at boot 2 true; live reconcile … rejected: 1: child served false`. L-108's
  flip returns for this shape. Fix (T92).
- **L-129 — `hand_parented_last` is quadratic in hand-parented lines, re-sorted at every boot and live reconcile.**
  Each output element rescans with `position` and `Vec::remove` shifts the rest. A6 `$P/cost` (release): 20,000
  lines in a reversed chain boot in 58.18 s against 0.87 s without parents lines. Reachable by the operator or threat
  (e), not a peer. Fix (T92): Kahn's algorithm.
- **L-130 — `retain_not_doomed` covers only a root the same peer served and whose refusal is still cached.**
  - A root never served, or a peer past its 4,096-entry refusal share
    ([anti_entropy.rs:788-790](crates/p2p/src/anti_entropy.rs#L788)), costs a full parse + Ed25519 verify per
    buffered child per tick. X2 `c3` (re-run): `tick 2..4: wanted 50 validated(parse+Ed25519) 50 … buffer_dup 50`.
  - An honest T79–T83 node serving H-23's dangling records triggers it (`xver s1`).
  - Fix (T95): do not re-Want ids already buffered; Want their missing parents.
- **L-131 — A held descendant retyped beside its original in the file is silently dropped.** `unverified_history` is
  keyed by id (`:3854`, `:4672-4677`), so the hand copy is judged as history ("no openledger-signature"), and the
  startup compaction keeps the enveloped spelling. X2 `c1` (`c1b` case): A serves 3 records where the in-place restate
  serves 5. The same happens on `45014e9`; T84's reworded remedy is what leads operators there. Fix (T92).
- **L-132 — The uncharged phase-1 bound and the decode proxy are ≈2× what T88 documents.**
  - The bound is `max(1 MiB, one directive)` per connection ([anti_entropy_alpn.rs:1953-1980](crates/gl-node/src/anti_entropy_alpn.rs#L1953)).
    One admitted directive weighs 1.87–1.97 MB (X2 `c5` re-run: `body 957766 B … resident_weight 1960058 B`), so
    ≈60 MiB per peer and ≈480 MiB global, where `connection_limiter.rs:90-104` and CHANGELOG:118 say "about its own
    byte budget" (Found by X2, A5).
  - Dense content commits once per directive: A5 `a5_2`, 128 directives → 128 commits.
  - Decode ratio: the same caps admit 28.25× (211 MB absolute) where the "densest" control is 14.4× (A5
    `a5_densest_variants`).
  - Still far below the pre-T88 figures. Fix (T95, decision (49)).
- **L-133 — A stale parent hint keeps a record out of the Want after its parent arrived.** `parent_arrived(X)` forgets
  only the hint keyed X ([orphan_buffer.rs:582-585](crates/p2p/src/orphan_buffer.rs#L582)). A5 `a5_4` (re-run):
  `hint for C still names [X] … retain_not_doomed dropped 1; want now []`. It needs differing envelopes (an
  equivocating author, or a mixed-version mesh). Fix (T95, with M-66).
- **L-134 — The hint sweep is one full pass per distinct expiring hint time, under the orphan write lock.**
  `oldest_hint_at` ([:428-450](crates/p2p/src/orphan_buffer.rs#L428)). A5 `a5_6` (re-run): 0.37 ms per expiry at
  8,192 hints, 1.62 ms at 32,768 (A5 measured 2.7 / 9.3 ms under load). Better than before T88. Fix (T95): pop an
  insertion-ordered front.
- **L-135 — Proxies in the tests T84–T89 added or changed.**
  - The boot fuzzer is blind to T84's I3/I9 arm: with it disabled, boot_fuzz stays 48 / 0.
  - `assert_refused_with_descendants` ([boot_fuzz.rs:1794](crates/p2p/tests/boot_fuzz.rs#L1794)) is a count bound:
    holding every history transaction still passes 10 of the 11 T84-changed cases. `convergence.rs:3110`'s `>= 1` is
    unbounded (A1).
  - `l108_*` passes with the topological sort removed (A6 R5b).
  - `m56_the_wire_refuses…` pins the library entry, not gl-node's intake order (X2).
  - `l90_*`'s high-water mark runs with an uncharged frame body (A5).
  - The log check in `m51_history_over_the_legacy_ceiling…` fails whenever it runs beside the T85 tests (tracing's
    callsite-interest cache; `--test-threads=1` passes) (A2).
  - A1's check 7 (`Checks::EXACT`) closes the first two for new cases. Fix (T96, decision (52)).
- **L-136 — Texts that say more than the code does.**
  - README's live-path bullets (`README.md:999-1011`) omit T85's hold and T89's strip, and §Verify omits
    `quarantined`, `quarantinedTotal` and `unparsableBlocks` (D1).
  - "Returns by itself once a peer re-supplies the parent" (service.rs `:8103`, README:861, CHANGELOG:60) holds only
    if a peer also holds the record (X2 `c2`, `c6`).
  - The L-81 keep WARN (`:6800-6808`) blames a restored backup on ordinary failed-compaction reloads (X3).
  - The M-52 "restate" remedy is refused on a currency-constrained account (`open … WEI`), and the in-file path needs
    the `open` edited too (D1 `case_m52`).
  - T85's "`close_account`'s size check is unreachable" is wrong (§1.3).
  - Fix (T96).

---

## 5. New informational

- **Loopback QUIC is blocked for executables outside the repo's `target/`** on this machine (§ intro). The repo's
  own test binary, copied byte for byte to a scratch directory, fails the control too. Every real-QUIC proof in this
  audit ran in the repo tree with restore and `cmp`.
- **The reload's clock can sit one above a Fresh boot's** (X3 `lampP On`, 9 vs 8): the kept hand line is history
  when the L-87 release runs. This is the safe direction.
- **A sticky 1777 directory is refused** by T87's rule, although another account can neither rename over the
  operator's link nor plant one the owner check accepts. This is fine as policy ("not `/tmp`") (A4, X3).
- **Four colluding allowlisted transport ids fill the parent-hint table**, and by the same ¼ arithmetic the refusal
  cache. Evicting an honest peer's cached refusal lifts its `retain_not_doomed` suppression. This is by design for a
  single hostile peer (X2, A5).
- **`finalize_operator_input` re-stamps the DAG and the read model but not `self.accounts`' lifecycle keys**, so a
  hand `open`/`close` keeps its provisional lamport there until the next rebuild. Relative order is preserved.
  PLAUSIBLE only; not reproduced (A1).
- **The live `ReconcileResult` counts as new a record the post-loop rule then holds**, whose foreign lamport has
  already moved the clock (L-55); boot would not count it (A2).
- **The H-23 summary and the banners join every id into one line** (67 KB at 1,005 ids), and **the T85 live hold is
  logged under the "already quarantined" header** on first sight (D1).
- **A re-adopted parent's lamport can sit above its child's** after the strip remedy (6 over 4); no consumer checks
  parent < child (D1).
- **The §5 "no openledger-signature" summary wording** also covers M-47 "author but no lamport" refusals (A6).
- **Decision (17) as stated:** an edited lamport under 2^28 still lifts the next hand line and write (D1 `case_m57`:
  H stamped 1,000,002 at an edit to 10^6). Peers accept it; README's "can no longer lift them above a value the mesh
  accepts" can read as "no longer lifts them at all".

---

## 6. Dependencies, supply chain, verification runs, and the four invariant test files

**Supply chain.**
- **`cargo audit -n`** with the local DB (1,267 advisories) exits 0, and so does a fresh DB in scratch (1,271). The
  only output is the allowed RUSTSEC-2024-0436 (`paste`) warning. `cargo tree -i rkyv -e all --target all` prints
  nothing.
- **`Cargo.lock` and every manifest are unchanged since `45014e9`.**
- **CI pins**, checked with `git ls-remote`:
  - `actions/checkout` `11d5960…` = v4.4.0 ✔
  - `Swatinem/rust-cache` `6323deb…` = v2.9.2 ✔
  - `rustsec/audit-check` `69366f3…` = v2.0.0 ✔
  - `dtolnay/rust-toolchain` `6bed076…` is reachable today, from `refs/heads/stable` only (L-123).
- **Dockerfile** unchanged, with the same digests. `deny_unknown_fields` on 7 of 7 config structs. No error code was
  added. Zero `unsafe` lines were added in `c8364fe..HEAD`.
- **Lint and format:** `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo fmt --all --
  --check` exit 0 on the pristine archive (D1) and on the repo with the four extended test files in (orchestrator,
  after the gate).

**CHANGELOG vs code:** every bullet tagged T84–T89 was executed on the real binary (D1, 22 new scripts plus the
0925 re-runs) or pinned by a named test. They are true except for:
- L-105's "fails closed" (L-122);
- the L-110 remedy under a running node (L-125);
- "returns by itself" (L-136);
- the M-52 restate remedy on a constrained account (L-136);
- the 32 MiB bound (L-132);
- the banner (M-69).

**GraphQL:** the schema diff against the 0925 dump is exactly `VerifyResult.quarantinedTotal: Int!`.

**The four invariant test files.** They contain pure additions plus helpers; no existing test was modified or
removed. Every new test that pins an existing mechanism was revert-proven in an archive copy. Every test that pins a
new finding is `#[ignore = "<pass>-N: …"]` and fails for the stated reason under `--ignored` (orchestrator re-run of
all 14):

| File | Before | After | New cases (pins) |
|---|---|---|---|
| [crates/p2p/tests/convergence.rs](crates/p2p/tests/convergence.rs) | 28 / 2 ign | **33 / 6 ign** | placeholder history resumes at one clock on a boot and a real L-13 reload (R1); wrong `meshId` keeps the clock and warns once, boot and reload (R3); a single sub-2^32 jump crossable and crossed (R8); hand lines child-first served in one boot and replicated (R5, R5b); stray-keyed records stripped on both paths and adopted by a fresh node (R6, R7); ignored: A6-1 (L-127), A6-2 (L-114), A6-3 (L-128), A6-4 (L-127 Info) |
| [crates/p2p/tests/boot_fuzz.rs](crates/p2p/tests/boot_fuzz.rs) | 48 / 0 | **55 / 3 ign** | check 7 `fresh_peer_audit` (`Checks::EXACT`: the served set is exactly what an empty signing peer adopts in lamport order, and every held node-written record is one it refuses); operators (ai) open dated after its transactions, (aj) delete an open + hand open, (ak) strip a signed record's envelope; the 39-operator EXACT sweep (M1, M2, R1, R3 each fail it); check 7 detects a stranded transaction and an over-quarantine; a held child returns when a peer re-supplies its parent; ignored: A1-1 (M-63), A1-2 (M-64), A1-3 (L-121) |
| [crates/ledger/tests/exact_balances.rs](crates/ledger/tests/exact_balances.rs) | 31 / 0 | **35 / 2 ign** | M-59 one balance running/restarted/replicated (R3); L-104 at balance level on a signing-off node vs a synced replica (R4); L-105 never a quiet balance loss, cuts 1–5 (R5); M-58 in the watcher's order over the cap, no rebuild (R1); ignored: A3-1 ×2 (M-65, I/O and cap flavours) |
| [crates/p2p/tests/m50_wire.rs](crates/p2p/tests/m50_wire.rs) | 11 / 0 | **17 / 5 ign** | the closure refused on the wire where no fresh replica could hold it either, with real keys (R2, R3); a pasted record with an absent parent held live as at boot and returned by a peer (R5); `reconcile_batch_ids` forward parent (R6); post-loop rule, live = boot (R7); `close_account`'s size check reachable; the L-110 remedy with the node stopped; ignored: A2-1 ×2 (H-24), A2-2 (L-125), A2-3 (L-126), A2-4 (M-63) |

**Test suite:** `cargo test --workspace --locked --no-fail-fast` gave **1,374 passed, 0 failed, 2 ignored** before the
audit and **1,396 passed, 0 failed, 16 ignored** (421 + 8 + 594 + 35 + 10 + 190 + 55 + 33 + 7 + 17 + 5 + 21) after all passes completed, with the four files extended. The ignored cases are
the two documented H-19 anti-entropy-only joins plus the 14 new finding cases.

**Revert-proofs:** 41 across the passes. Each was done in a `git archive` copy, restored and compared equal
afterwards, except real-QUIC ones, which were done in the repo tree and `cmp`-restored:
- T84: R1, R3, M1, M2
- T85: R2–R7, F1, F2
- T86: R1–R5
- T87: R1–R4
- T88: R1, R2b, R3, R4, R6, the QUIC call removal
- T89: R1, R1b, R3, R5, R5b, R6, R7, R8
- plus X1's two fix-proofs, X3's three archive switches, and the new tests' own reverts

---

## 7. Consolidated open-findings register

Everything open as of this audit. IDs are stable across the 09/01 … 09/26 reports.

| ID | Sev | One-liner | Origin |
|---|---|---|---|
| **H-24** | High | T85's closure refuses by content id: the "restate the chain" remedy and an API re-entry after a crash partition replicas permanently | **09/26** |
| H-01 | High→Low | *Partially closed.* Loopback API key deferred | 09/01 |
| M-09 | **High** (re-rated, decision (38)) | *Partially closed.* Remote-close admission order-dependent; **state divergence executed between honest replicas under `compute_want`'s order (0926 X1)**; remainder pulled into T91 | 09/01 |
| M-10 | Med | *Interim only.* T45 Facet A | 09/01 |
| **M-63** | Med | A later peer `open` narrowing an account un-serves admitted history mesh-wide at each node's next restart | **09/26** |
| **M-64** | Med | The served-set rule is not a fixpoint: served over a held parent after the rebuild's refusal / the finalize ceiling arm | **09/26** |
| **M-65** | Med | M-59's refusal keeps the failed write; near the cap M-58's reload-per-write returns through gl-node's gate | **09/26** |
| **M-66** | Med | `retain_not_doomed` reads any peer's copy: an equivocating author blocks an honest copy and its subtree | **09/26** |
| **M-67** | Med | `retain_not_doomed` quadratic under the orphan lock; phase 2 holds the ledger write lock behind it | **09/26** |
| **M-68** | Med | The M-60 race one directory up: an ancestor writer swaps the link's directory | **09/26** |
| **M-69** | Med | gl-node's H-20 banner prescribes the withdrawn remedy: double count / emptied ledger | **09/26** |
| L-23 | Low | *Partially closed.* `meshId` still opt-in | 09/02 |
| **L-114 … L-136** | Low | Twenty-three new Lows — see §4 | **09/26** |
| L-06 | Latent | `\|`-delimited signature message — injective at HEAD; T45 Facet B | 09/01 |

**Closed this audit (26):** H-23 · M-56, M-57, M-58, M-59, M-60, M-61, M-62 · L-96 … L-113.

**Residuals re-rated:**

| Residual (task) | Now |
|---|---|
| T84 "pending input is exempt" | M-64 |
| T84 (e) "banner reworded" | M-69 |
| T84 "returns by itself" | L-136 / M-63 |
| T85 "no later record can make it adoptable" | H-24 |
| T85 "size check unreachable" | L-136 |
| T86 "the REFUSING arm keeps a write … as it always has" | M-65 |
| T87 "race-free by construction" | M-68 |
| T87 "the sweep beside the link" | L-118 |
| T88 "other peers are unaffected" | M-66 |
| T88 "about its own 32 MiB" | L-132 |
| T89 "judged once, over every pass" | L-114 |
| T89 "join only for ≥ 2^32" | L-127 |
| 0925 §9 "no executed shape re-issues a pair" | L-115 |
| T29 "state divergence … not possible" | M-09 (decision (38)) |

---

## 8. Remediation backlog

Tracked in [docs/OUTSTANDING_TASKS_09_26.md](docs/OUTSTANDING_TASKS_09_26.md). Task numbering continues from T89.
Effort: S = < ½ day, M = ~1–2 days. Every task keeps the campaign's rule: revert the fix → the named test fails →
restore; residuals go in the tracker. The `#[ignore]`d cases in the four invariant files are the acceptance tests.
Decisions (36)–(53) were taken on 2026-09-26 (the recommended option every time) and are recorded in the tracker's header.

### Tier 1 — ship-blocker

**☐ T90 — The closure keyed on parenthood; the live path holds what boot holds (H-24, L-126) — S, decision (36).**
- Change: refuse on the wire and live path only a copy naming a closure parent the DAG lacks, drop an id once
  adopted, and let the duplicate-body arm prefer the served-parent copy; quarantine what the live path refuses for a
  boot-hold reason.
- Verify: un-ignore `a2_a_restated_chain_…`, `a2_a_record_reentered_…`, `a2_the_live_reconcile_keeps_…`; X2
  `c1f`/`c1e`/`c1d` converge.

### Tier 2 — lifecycle, the rule's fixpoint, the recovery reload, the symlink guard, the Want filter

**☐ T91 — Lifecycle verdicts that never retract (M-63, M-09 remainder, re-rated High) — M, decisions (37), (38)**
**☐ T92 — The rule reaches a fixpoint; every remedy it prints works (M-64, M-69, L-114, L-121, L-125, L-128, L-129, L-131) — S–M, decisions (39)–(42)**
**☐ T93 — The recovery reload rolls back what failed and keeps the clock (M-65, L-115, L-116, L-117, L-122, L-124) — S–M, decisions (43)–(45)**
**☐ T94 — The symlink guard bound to one directory handle (M-68, L-118, L-119, L-120) — S, decisions (46), (47)**
**☐ T95 — The Want filter: own copies, linear, outside the lock; the stated bounds (M-66, M-67, L-130, L-132, L-133, L-134) — S–M, decisions (48), (49)**

### Tier 3 — texts, CI, proxies

**☐ T96 — The gap verdict, the CI pin, the proxies and the texts (L-123, L-127, L-135, L-136) — S, decisions (50)–(52)**

### Finding → task coverage map

H-24→T90 · L-126→T90 · M-63→T91 · M-09 (remainder)→T91 · M-64→T92 · M-69→T92 · L-114→T92 · L-121→T92 ·
L-125→T92 · L-128→T92 · L-129→T92 · L-131→T92 · M-65→T93 · L-115→T93 · L-116→T93 · L-117→T93 · L-122→T93 ·
L-124→T93 · M-68→T94 · L-118→T94 · L-119→T94 · L-120→T94 · M-66→T95 · M-67→T95 · L-130→T95 · L-132→T95 ·
L-133→T95 · L-134→T95 · L-123→T96 · L-127→T96 · L-135→T96 · L-136→T96.

**Deferred by design to T45:** M-10, L-06 (M-09's remainder is in T91 by decision (38)). **Deferred by decision:** H-01, L-23.

**Landing order:** T90 → T91 → T92 → T93 (`service.rs`; T90 first because T92's fixpoint and T93's reload re-run the
closure T90 re-keys) → T94 ∥ T95 (disjoint files) → T96.

---

## 9. Checked and found sound (new this audit)

Beyond the closures in §1.1, these were probed adversarially and held:

**The boot pipeline (X1).**
- gl-node's order at HEAD is `resolve_ledger_path` :216 → lock :223 → `boot("local")` :246 → `set_author_id` :373
  → signer :482 → verifier :505 → finalize :542 → `verify_own_history` :556 → compaction :586.
- A fresh peer built on the real wire path, fed the served set in canonical, reverse, transactions-first and
  `compute_want` order, agrees with the rule on:
  - a failing `balance` plus a `pad` (7/7);
  - a `close` served before a back-dated transaction (5/5);
  - a hand `open … EUR` against USD history (the rule holds X and its child; the peer accepts the 6 served);
  - an `open` deleted, moved or dated after its transactions — A1's check 7, 39 operators × 2 seeds × 2 positions.
- Auto-parented hand lines over an M-54-held `open` are rebased, stamped and signed; hand-parented ones are refused
  as written.
- Every rule-held shape is a boot → compaction → boot fixed point, and crash-and-reload differences are 0.
- The H-23 "strip the `openledger-*` lines" and "restate the chain" remedies work on a single node.
- Provisional lamports never move the clock, the release excludes pending input, and finalize stamps in adoption
  order.

**Fresh boot vs reload (X3).**
- On a 27-shape differential (clean, hand lines, edited narration and lamport, a deleted `open` with an early or late
  hand `open`, L-108, M-54 at finalize, stray keys at both levels, a planted dangling parent, a text-held `"local"`
  record, domain mismatch), the Fresh pipeline, the failed-commit reload and the failed-startup-compaction reload
  agree on the served set, quarantine, closure, text-held blocks, balances, pending input, envelopes, over-cap fact
  and WARN set — except L-114, and the one-slot Info.
- The compacted file is byte-identical in 27/27 shapes, and every shape is a fixed point.
- `reconcile_batch_ids` has no early return between fill and clear.
- The M-59 REFUSING arm cannot loop.
- An identical client retry after a REFUSING install is deduplicated (`already_existed=true`).
- `prepare_refusal_needs_no_reload` is exact: with nothing staged, memory equals what the reload installs.

**The closure and the wire (A2, X2).**
- Every closure seed is a rule every peer applies identically: the body cap, the history limits, the amount cap.
  T79–T80 refuse a superset, and T81–T83 are identical.
- A closure subtree served with its root is suppressed from tick 2.
- A hand `open` that frees a record in the same boot leaves no permanent refusal on peers (the peer's account wait
  adopts it).
- A lying peer's hash-mismatch copy refuses X only for the liar.
- A held record that a peer also holds returns in one tick, with no pair re-issued.
- The refusal cache costs at most one refetch per peer per TTL for a mixed-version peer re-offering closure members.
- Mixed-version H-23 records are adopted identically by both builds.

**Recovery and journal (A3, X3).**
- L-105's new branch has no false positive: stale payloads ending in `;`, `;;`, `;;o`, `;;ol` or `;;olj` at a line
  start read as torn; a `;;olj ` inside a narration is never at a line start; a strict prefix cannot hash to the full
  payload's hash.
- The M-59 check accepts kept-envelope parents, and the floor runs first.
- The re-measure after install uses the rebuild's comments.
- A failed-commit install re-captures the leading comments.

**The symlink guard (A4, X3).**
- Every T87 refusal comes before the lock and before any write.
- These resolve correctly:
  - `..` targets and `..` after a directory link;
  - a link directory reached through a directory link;
  - a target reached through a directory link;
  - a hard-link target.
- These are refused: a target whose own name is a link; a link to a directory (by T67); a self-loop and a missing
  directory (returned unresolved, then T67 refuses).
- `/tmp` → `/private/tmp` and `/var` → `/private/var` are compared as physical paths on both sides.
- Stray-journal variants:
  - a zero-byte stray is refused;
  - a stray that is itself a symlink is refused (`lstat`);
  - a `.torn-*` sidecar beside the link does not refuse;
  - a non-link ledger never checks.
- Directory modes: 0755, 0750, 0700 and 1755 resolve; 0775, 2775, 0770 and 1777 are refused, with the mode named.
- Root running the node: the checks compare against `geteuid`.
- The M-61 remedies A and B both work on the binary.

**Identity and diagnostics (A6).**
- `is_own_author` only raises the clock or changes naming. Signing and re-attribution do not use it, the wire refuses
  a non-allowlisted `"local"`, and it cannot re-issue a pair.
- `release_on_hold` is re-derived on a real reload, and the clock never falls while it is held.
- Stripped keys are covered by neither the content id nor the signed message, and a fresh node adopts the stripped
  records.
- The adoption-site gap WARN is always under 2^32, so only "diagnosed" is reachable there.
- A single-record node keeps the EVERY WARN off by design.

**Replication bounds (A5, X2).**
- The hint share keys on the transport `EndpointId`, and drained re-buffers keep `from_peer`.
- Three colluders leave room for an honest 300-chain.
- The over-share path is O(1) until expiry.
- The uncharged cap arithmetic is correct per connection.
- `quarantined_ids_capped` and `quarantinedTotal` use one predicate, in id order, and the i32 total saturates.
- Gossip announce fetches apply neither filter.
- A hint cycle terminates (88 µs).
- Every 0925 X2 case (`r1`–`r6`) behaves as before.

**On the real binary (D1).**
- The H-23 strip remedy and a backup restore both clear the quarantine.
- An edited lamport at 2^29 or 5·10^9 is released (H stamped 5).
- L-108, L-110 (stop → edit → start), the live hold and its return, M-56 back-dated vs late, and L-101 (1,256,134 B
  held with its child) behave as documented.
- L-96: a text-held `"local"` record at 1000 → next write 1002.
- L-98/L-99 behave as documented, and fixing the `meshId` restores 5/5; writes under the wrong domain are quarantined
  at the next correct boot with no pair re-issued.
- The gap verdicts at 3·10^8 and 5·10^9 are correct.
- The bootstrap join loads with `verify ok`.
- Stray keys are stripped live and at posting level.
- M-60/M-61 and both their remedies work.
- M-58 behaves as documented (66.9 MB, 0 reloads), and its remedy works.
- Deleting a stamped line does not retract it, on signing and signing-off nodes.
- The T89 summary's "delete their openledger-* lines" gives 0 quarantined and a fixed point.

---

*Previous audits: [SECURITY_AUDIT_0925.md](SECURITY_AUDIT_0925.md) · [SECURITY_AUDIT_0924.md](SECURITY_AUDIT_0924.md) · [SECURITY_AUDIT_0923.md](SECURITY_AUDIT_0923.md) · [SECURITY_AUDIT_0922-v2.md](SECURITY_AUDIT_0922-v2.md) · [SECURITY_AUDIT_0922.md](SECURITY_AUDIT_0922.md) · [SECURITY_AUDIT_0902.md](SECURITY_AUDIT_0902.md) · [SECURITY_AUDIT_0901.md](SECURITY_AUDIT_0901.md) · [docs/CLAUDE_SECURITY_AUDIT_0820.md](docs/CLAUDE_SECURITY_AUDIT_0820.md). Remediation trackers: [docs/OUTSTANDING_TASKS_09_26.md](docs/OUTSTANDING_TASKS_09_26.md) (T90–T96) · [docs/OUTSTANDING_TASKS_09_25.md](docs/OUTSTANDING_TASKS_09_25.md) (T84–T89) · [docs/OUTSTANDING_TASKS_09_24.md](docs/OUTSTANDING_TASKS_09_24.md) (T79–T83) · [docs/OUTSTANDING_TASKS_09_23.md](docs/OUTSTANDING_TASKS_09_23.md) (T72–T78).*
