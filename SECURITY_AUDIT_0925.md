# Security Audit — openledger-v2 (0925: re-audit of T79–T83)

**Date:** 2026-09-25 · **Baseline:** HEAD `45014e9` (branch `main`, clean tree) · **Previous:** [SECURITY_AUDIT_0924.md](SECURITY_AUDIT_0924.md) (HEAD `3d64a16`)

Scope: re-verification of **every** claim, revert-proof, accepted design deviation and residual in the T79–T83 "Done"
notes of [docs/OUTSTANDING_TASKS_09_24.md](docs/OUTSTANDING_TASKS_09_24.md) against source at HEAD, plus fresh hunts
over the ~4,080 lines T79–T83 added or changed (25 files, four commits after `4a3428f`; 2,861 of them in
`crates/ledger/src/service.rs`), treated as unreviewed code. Priority went to what T79–T83 moved and what they
added: the checks that now run **inside** `verify_history_pass` (the T80 re-attribution, the T79 rebase, the T83
clock release) and after it (the T79 served-child WARN), the T81 closure that runs before them and before operator
input, the new state each fix keeps (`operator_input_as_written`, `refused_history_closure`, `canonical_over_cap`,
`known_missing_parents`, `keep_committed_envelopes_in`'s replacements) and whether a reload, a live reconcile or a
second boot re-derives it; the two accepted design deviations (T79 (d) warns instead of quarantining, T83 drops the
stray key instead of quarantining); decision (11)'s symlink guard against threat (e); and the four invariant test
files as the standing specification.

Method as established for the series: ten parallel passes (six per task group, each re-verifying then hunting,
four of them owning one invariant test file; three cross-cutting interaction hunters with named compositions — X1
the boot pipeline, X2 replication, X3 commit/recovery/file system; one documentation, configuration and
supply-chain pass that executes the CHANGELOG on the real binary), each read-only on the repo apart from its owned
test file, with its own scratch crates and target directory and a `git archive HEAD` copy for revert-proofs; every
mechanism a pass reported was re-read in source and **every executable proof below was re-run by the
orchestrator** (the quoted outputs are the re-runs). Test suite at HEAD before the audit, quiet machine:
**1,319 passed, 0 failed, 2 ignored** (418 + 8 + 572 + 25 + 10 + 187 + 38 + 21 + 7 + 7 + 5 + 21). Loopback QUIC
worked throughout, on the freshly built binaries too. The repository was modified in exactly six files: this
report, the new tracker, and the four invariant test files (§6).

---

## Executive summary

**T79–T83 closed what they set out to close.** Every register entry the 0924 backlog assigned is closed by mechanism
(H-22 · M-51, M-52, M-53, M-54, M-55 · L-80 … L-95, with the remainders of M-47, M-50 and L-75), every regression
test the Done notes name is green, and every revert-proof a pass repeated (33 across the ten passes) failed the
named test. Several claims were re-measured and held: the boot fuzzer's pipeline still matches `main.rs`'s order
with the author now taken from the key; the re-attributed placeholder record crosses the wire and verifies under
the key on a second node; two keys cannot re-attribute each other's history; the wire's 4,096 ceilings are exact
at 4,096/4,097 with a real key; a journal record is never smaller than the canonical spelling of the same set, so
a peer cannot drive the canonical form over the cap while the file stays under it; the symlink resolution puts
journal, lock, temp files and sidecars beside the target; `cargo audit` is clean, the lockfile unchanged, CI pins
verified (one is unreachable, §5), `clippy -D warnings` and `fmt --check` pass with the extended tests in.

**But the pattern has repeated a fifth time, and this audit's High is a composition of the last three.** The
0924 through-line was "each check runs at a moment when its input is not yet the state that will be served".
T79–T83 moved the checks later and gave several of them the right input. What they did not do is state the
property those checks were approximating — *a served record must be one a fresh replica can hold* — so each
fix tests its own symptom and the doors between them stay open:

- **H-23** — A served record whose parent exists **nowhere** is named by no check. The T79 served-child WARN
  looks the parent up in the quarantine by id; a parent id that vanished under an edit, a text-held block that
  has no id, and a parent the operator deleted are in nobody's quarantine. Four doors, all executed: the T79
  rebase *builds on it* (a hand line is signed over a served signed child of the edited record, whose own parent
  is the edited record's original id — silent, and a fixed point); the two remedies the H-20 WARN prescribes for
  an edited record ("restore from a peer's copy … or delete the edited block") silence the WARN and leave the
  child stranded on a node no peer has a copy for; the M-52/M-51 remedies ("restate the amount", "repair the
  refused record") leave every descendant served with no seed, `verify` reporting `ok: true` for the deleted-`open`
  case; and a block held as text for any reason but the amount cap strands its children under L-45's own
  precondition. In each, this node's next write names the stranded record and every later write is orphaned on
  every peer, permanently, with nothing said.
- **Six Mediums.** The T81 closure's "orphaned account" term is date- and currency-blind and judged before the
  hand `open` that is the natural M-51 remedy, so one restart silently serves what every peer refuses and the
  wire path never checks the closure (M-56). A lamport edit plus a hand line in one edit defeats the L-87 clock
  release: the hand line is stamped above the edit and past 2^32 every peer refuses it and everything after
  (M-57). L-80 is not closed on gl-node's own boot path: the fact is lost by the reload the L-80 refusal itself
  triggers whenever the file holds hand lines — the L-64 shape — so every write on the real binary stages, fails
  and pays an ~80 s reload with the permit held, and the client gets a request timeout (M-58; found by four
  passes). The L-81 keep installs a committed envelope whose parent the rebuild lacks — the local write staged in
  the same failed commit — so the node's later history descends from a record no replica can resolve (M-59).
  Decision (11)'s uid guard is checked on one inode and the follow done on another, and only on the first hop
  (M-60). Converting a ledger to a symlinked one after an unclean stop silently strands its journal (M-61).
- **Lows** (§4), the widest being the placeholder author surviving in every outside-DAG "own" lookup after
  re-attribution (a re-issued `(author, lamport)` pair, L-91's wrong remedy verbatim), the L-87 release re-issuing
  a pair by boot's `+1` gap, the wire path re-verifying a doomed subtree every tick with no closure and no cache,
  and the one content rule (the 1 MiB body cap) the boot closure leaves out.

The through-line this time: **each fix tests its own symptom where the property is "what a fresh replica would
hold"**, and the operator-facing remedies create the shapes the fixes do not test. The backlog (§8) is organised
around stating that property once, at boot and on the wire, and rewording every remedy that contradicts it.

---

## Threat model

Unchanged from [09/22](SECURITY_AUDIT_0922.md) through [09/24](SECURITY_AUDIT_0924.md): (a) a web page in an
operator's browser, (b) an API-key holder, (c) a **malicious or compromised allowlisted peer**, (d) a network
attacker on a public bind, (e) whoever can write the `.bean` or its directory, plus the no-attacker cases (an
operator following the README, an editor autosave, a backup `cp`/`mv`, a crash, an upgrade over an old file, a
long-offline or freshly restored replica, the operator following a remedy the code prescribes). This audit adds
three no-attacker cases the new code made reachable: **the operator following the remedies T79–T83 added**
(delete the edited block; restate the amount; repair the refused record; hand-open the account); **an unclean
stop followed by the symlink conversion T82 documents**; **a signing node whose history never replicated**
(P2P off, or authored offline) editing one of its own records.

---

## 1. Status of the 09/24 register, re-verified at HEAD `45014e9`

Every entry is re-verified by mechanism in source and by the named regression test; "revert-proof" means a pass
reverted the mechanism in a `git archive` copy and the named test failed (33 reverts repeated this audit).

### 1.1 Closed — verified by mechanism (22)

| ID | Task | Mechanism at HEAD | Pinned by | Revert-proof |
|---|---|---|---|---|
| H-22 | T79 | `rebuild_dag` rebases every still-unsigned operator input over the rebuilt heads by `choose_parents_in` ([service.rs:4771-4870](crates/ledger/src/service.rs#L4771), pending gate `:4808`, `rebase_operator_input` `:4988-5024`, `content_ids()` is insertion order [dag.rs:519](crates/ledger/src/dag.rs#L519)); hand parents must survive (`:4995-5010`); a transaction re-validates (`:5018`); refused entries held as written (`operator_input_as_written` filled `:4127`, pruned `:4858`, cleared `:4247`); hand parents resolved in the DAG alone ([:7412-7440](crates/ledger/src/service.rs#L7412)); `finish_recovery` verifies before it finalises ([:6441-6442](crates/ledger/src/service.rs#L6441)) | four `h22_*`, `m54_*`, `op_x/y/z/aa`, the harness bootstrap case; every acceptance case un-ignored and green | yes, all eight (R1 no rebase → 8 tests; R2 "DAG ∪ quarantine" → live half of `h22_a_hand_parent…`; R3, R4, R5, R6, R7, R8 as the note states) — **but the rebase re-chooses parents, not the lamport (M-57), and builds on served heads whose parents exist nowhere (H-23)** |
| M-54 | T79 | `foreign_operator_input_reason` ([:4014](crates/ledger/src/service.rs#L4014)) at finalisation ([:4200-4236](crates/ledger/src/service.rs#L4200)) and on the live path ([:7373-7380](crates/ledger/src/service.rs#L7373)); executed on the real binary (boot and live) | `m54_*`, `m47_a_half_envelope…`, `test_reconcile_does_not_sign_for_another_author`, `op_aa`; two new fuzzer cases now fail under R4 where `op_aa` did not | yes (R4, R5) |
| L-75 | T79 | "exists nowhere" and "held in this node's quarantine" both refused, boot and live; executed on the real binary | `h22_a_hand_parent…`, `op_z` | yes (R2, R3) |
| M-53 | T80 | author from the key before signer, verifier and finalize ([main.rs:366-372](crates/gl-node/src/main.rs#L366), `:477`, `:502`, `:527`); `NodeSecretKey::author_id` ([p2p_service.rs:775](crates/gl-node/src/p2p_service.rs#L775)) is the `EndpointId` Display; mismatch aborts (`:411-418`); `reattributed_placeholder_record` ([service.rs:4609-4652](crates/ledger/src/service.rs#L4609)) first in the pass (`:4434`) and on both live full-envelope arms (`:7623`, `:7702`); executed on the real binary before/after | two `m53_*`, `t80_*`, fuzzer `op_ac`, gl-node `t80_*` | yes (R1, R2, R3) — **DAG entries only: outside-DAG placeholder entries stay `"local"` (L-96)** |
| L-82 | T80 | closed by M-53's mechanism (the hand line verifies under the key in the same lifetime; real binary) | `m53_*` | — |
| L-91 | T80 | `set_author_id` WARN ([:8098-8127](crates/ledger/src/service.rs#L8098)); `highest_lamport_author` reads `boot_outside_dag_lamports` (`:5535-5541`) | two `l91_*` | yes (R6, R7) — **keyed by the new author id; the pre-T80 shape (`"local"` in text) reproduces L-91's text verbatim (L-96)** |
| 0924 §5 banner | T80 | `signature_quarantined_total` ([:4537](crates/ledger/src/service.rs#L4537)) reported by [main.rs:557](crates/gl-node/src/main.rs#L557); total-failure WARN (`:4496-4511`); signer only with signing enabled (`main.rs:477-479`); executed on the real binary with a wrong `meshId` (3 per-record WARNs + banner `quarantined=3` + the domain WARN) | `t80_*` | yes (R4, R5) — heuristic is per pass (L-98) |
| M-51 | T81 | `*_LEGACY` = 4,096 ([limits.rs:69](crates/ledger/src/limits.rs#L69), `:76`); `ResourceRule`, `enforce_resource_limits_for` ([service.rs:797-866](crates/ledger/src/service.rs#L797)); wire ([union_merge.rs:236-270](crates/p2p/src/union_merge.rs#L236), `ParseLimits::WIRE` [parse.rs:713-722](crates/ledger/src/parse.rs#L713)), staging (`:8332`), boot's history arm with its own WARN (`:3597-3617`), complete envelopes on the file path (`:7562-7571`); body-line cap 5,196 (`parse.rs:748-752`); real binary: 65 loads and is served, 4,097 quarantined with dependants, API 65 refused | `t75_over_cap_open…` (harness), `m51_*` ×2, the changed wire/staging tests, m50_wire T75 case + three new cases | yes (R1, R2, R3) |
| M-52 | T81 | `ParseLimits::IDENTIFY` (`parse.rs:685-710`), `amount_cap_refused_block_ids` ([:690-700](crates/ledger/src/service.rs#L690)), WARN names cap and id (`:3363-3376`); closure `quarantine_descendants_of_refused_history` ([:4902-4967](crates/ledger/src/service.rs#L4902)) via `children_of`/`children_awaiting` ([dag.rs:494-511](crates/ledger/src/dag.rs#L494)); `refused_history_closure` reset every boot/reload (`:3887`, `:4949`); file-path guard (`:7386-7411`); GraphQL fields (`query.rs:293-300`, `types.rs:190-192`), executed over HTTP | `m52_*`, `over_cap_history…` (acceptance), `test_verify_lists_the_quarantine`, two new `exact_balances` cases | yes (R4, R5, R6, R7) — **the account term is date- and currency-blind and pre-operator-input (M-56); the closure is seeded only by what boot refuses (H-23) and only on the file path (L-106)** |
| M-55 | T81 | `enforce_resource_limits_as_stored` ([:834-849](crates/ledger/src/service.rs#L834)) on both file paths; a transaction always stores `openledger-parents` (`serialize.rs:1581`); real binary 96/97; the one "count, then sign" shape (own author + lamport, unsigned, 97 keys) is closed by the verifier refusing before `sign_adopted_entry` (`:7616` before `:7633`) | `m55_*`, m50_wire M-55 case + two new cases | yes (R8) |
| M-47 / M-50 remainders | T79 / T81 | M-54 and M-52 above | — | — |
| L-80 | T82 | `canonical_over_cap` ([:3012](crates/ledger/src/service.rs#L3012)) set at boot (`:3943`, only with no operator input pending), finalize (`:4299`), reconcile of foreign bytes (`:7262`), cleared by Compact (`:6198`); `append_headroom` 0 (`:5700`); pre-stage checks ([ledger_commit.rs:555-573](crates/gl-node/src/ledger_commit.rs#L555), [anti_entropy_alpn.rs:2029-2045](crates/gl-node/src/anti_entropy_alpn.rs#L2029)); `prepare`'s arm (`:5861-5871`) | `l80_*` ×2 | yes (R1, R2) — **closed only until the first refused compaction on a file with hand lines (M-58); both tests use comment-only fixtures** |
| L-81 | T82 | `keep_committed_envelopes_in` ([:6507-6538](crates/ledger/src/service.rs#L6507)) before `adopt_reloaded`; `rebuild_dag(refused, replacements)` | `l81_*` | yes (R3) — **no check that the kept envelope's parents survived the rebuild (M-59)** |
| L-93 | T82 | `committed_ids_missing_from` exempts a file-adopted id only while unsigned ([:6477-6490](crates/ledger/src/service.rs#L6477)) | `l93_*` | yes (R4) — **never expires on a signing-off node (L-104)** |
| L-85 | T82 | `has_later_intact_record(region, own_hash)` ([journal.rs:496-530](crates/ledger/src/journal.rs#L496)), prefix check `:512` | `l85_*` | yes (R5) — five-byte gap (L-105) |
| L-84 | T82 | `resolve_ledger_path` ([journal.rs:164-190](crates/ledger/src/journal.rs#L164)); `main.rs:216-232` resolves, locks and boots on the resolved path; watcher polls it (`main.rs:614`); journal/temp/sidecar/sweep beside the target; real binary: lock beside the target, write lands in the target, link survives | `l84_*`; D1 on the binary | yes (R6) — **the uid guard races and covers one hop (M-60); a journal beside the link is stranded (M-61)** |
| L-83 / L-94 | T83 | `largest_lamport_gap` counting from 0 ([service.rs:1382-1396](crates/ledger/src/service.rs#L1382)), `LAMPORT_GAP_WARN` (`:1376`), `lamport_gap()` (`:8173`); boot's third branch names the author at the top (`:3789-3823`); `warn_if_adoption_opens_a_lamport_gap` (`:5554-5575`) from the three adoption sites with the clock before; real binary: fires at every boot with `author=` | `test_h19_lamport_gap_predicate`, `test_h19_boot_warns_…`, `test_h19_adoption_warns_once_per_jump_…`, `l83_*`, the harness joins case + three new cases | yes (predicate → `(0,0)`, R1 old ratio, R4 old adoption predicate) — **judged before the pass and the closure (L-100); names an honest author after the remedy (L-111); the remedy text over-claims for [2^28, 2^32) (L-113); the `<` assertion is inside a unit test** |
| L-86, L-88, L-92 | T83 | documented (L-86, L-88); `explain_unrepresentable_amount` ([validate.rs:166](crates/ledger/src/validate.rs#L166)) in the scalar and the parser, executed over HTTP and in a hand block | `l92_*` ×2 | yes (R10) |
| L-87 | T83 | `release_clock_carried_by_edited_records` ([:4557-4595](crates/ledger/src/service.rs#L4557)) after `quarantine_out_of_dag`; real binary `from=4000000001 to=3` | `op_ab`, `l87` | yes (R5) — **defeated by a hand line in the same edit (M-57); re-issues a pair by boot's `+1` gap (L-97); walks the clock to 0 on a domain mismatch (L-99); drops placeholder outside-DAG records (L-96)** |
| L-89 | T83 | boot strips a stray `openledger-*` key from non-operator-input directives ([:3394-3432](crates/ledger/src/service.rs#L3394)); real binary | `l89_*` | yes (R6) — boot only; the live path deletes the block (L-109) |
| L-90 | T83 | phase 1 flushes on `PHASE_ONE_WEIGHT_BUDGET` alone | gl-node `l90_*` (269 s run) | yes (R7) |
| L-95 | T83 | `known_missing_parents` / `MAX_PARENT_HINT_IDS` ([orphan_buffer.rs:261-330](crates/p2p/src/orphan_buffer.rs#L261)); `order_want_ancestors_first` ([anti_entropy.rs:120](crates/p2p/src/anti_entropy.rs#L120)); gl-node's Want session and the harness call it | `l95_*` ×3, harness chain case, gl-node real-QUIC chain test | yes (R9) — the hint table is process-wide (L-107) |

### 1.2 Unchanged by decision (5)

H-01 (loopback API key), M-09, M-10, L-06 (T45 Format v2), L-23 (`meshId` required next release).

### 1.3 Done-note residuals and accepted deviations, dispositions at HEAD

- T79 (d) "a WARN, not a quarantine … since T79 boot never creates the shape" — **the premise is wrong**: editing
  any envelope line of a non-head own record creates it at HEAD (A1 `strand`), and the rebase *builds on* a
  served head whose parent vanished under a body edit (X1 `c3j`). The WARN checks the quarantine by id, so the
  latter is named nowhere (H-23). The WARN also fires when the parent *is* replicated and the child is fine
  (A1 `lamport`, control): "no peer can adopt them" is wrong there.
- T79 "exactly what boot would have adopted over a file without the refused records" — true for the parents
  (two passes rebase to what a boot without the refused blocks stamps, A1 `twopass`), **false for the lamport**,
  which is never re-stamped: +1 in the ordinary case, M-57 with an edited lamport.
- T79 "a hand `open` refused as already-open stays refused" — understated: any later live reconcile re-reads the
  file and adopts it against replica-local state (the history `open` is quarantined here, not on the mesh), with
  the transactions boot cascaded — two `open`s for one account mesh-wide (L-110).
- T79 "a library caller that installs the verifier after finalize" — accurate; no gl-node path does (A1, X1 c5).
- T80 "a signing-off node still boots and writes under `local`" — accurate on the binary; but re-attribution is
  DAG-only and the note does not say so (L-96).
- T81 "every other §3.12 cap … is the same for both" — true inside `enforce_resource_limits_for`; the 1 MiB body
  cap (wire-permanent, not applied at boot by T51's decision) and the 256-parent cap (record-only at boot) sit
  outside the rule and outside the closure (L-101; fan-in Info).
- T81 "a node on a T75–T80 build still refuses pre-T75 history over 64/100 until it upgrades" — accurate,
  quantified on the real `4a3428f` build: every later write of the HEAD node is `MISSING_PARENT` on that node
  for the rest of that build's life, silent on HEAD (Info).
- T81 "a past-10^21 amount has no path to replicate other than restating it in a larger unit" — **understated**:
  restating strands every descendant (H-23 door 3).
- T81 "the closure follows parents and account-opening only" — accurate, and "account-opening" is judged by
  account name alone (M-56); "what this node serves is the set a fresh replica can hold" holds only until a hand
  `open` re-opens the account.
- T82 "carried through `adopt_reloaded`" — **wrong as worded**: the flag is not carried ([:6636-6663](crates/ledger/src/service.rs#L6636)
  carries `canonical_is_current` only); it is re-measured by the reload's boot only when no operator input is
  pending, which on the L-64 shape it always is (M-58).
- T82 "prepare's compaction arm refuses … instead of failing in `persist_atomically`" — true, but that refusal is
  still answered by a full reload in both drivers (M-58's second mechanism).
- T82 "a hand-added line the node has not yet signed may still be dropped" — understated: on a signing-off node
  that is every hand line, forever, after it was served and written back (L-104).
- T82 "torn in its header or payload" — overstated by five bytes (L-105).
- T82 / decision (11) "a link owned by another uid refuses boot … another account cannot create a link this uid
  owns" — the premise is sound, the check is not atomic with the follow and covers the first hop only (M-60);
  README §The commit journal says where the journal lives but not that an existing one must move (M-61).
- T82 "the leading comments … never re-read" — accurate; a live comment deletion is not merely unseen but undone
  by the next rewrite (Info, pre-existing).
- T83 L-87 doc comment "the next stamp stays above it" — off by one when the edited record was the first stamp
  after a restart (L-97); the INFO says "an edited lamport line" for a body edit too.
- T83 L-95 "a hint table at `MAX_PARENT_HINT_IDS` records nothing more (one extra round per lost hint)" —
  understated: the table is process-wide, so one peer degrades another peer's chain join (L-107).
- T81 residuals list only the closure's file-path limits; the closure has no wire-intake counterpart (L-106).

---

## 2. New findings — High

### H-23 — A served record whose parent exists nowhere is named by no check: the T79 rebase signs a hand line over such a record, and every remedy the code prescribes for a refused record creates one; from then on every write of this node is orphaned on every peer, permanently and silently

**Severity: High** (permanent partition of this replica's authoring from the mesh — acknowledged API appends
included — reached through the README's edit workflow and through the remedies the code's own WARNs prescribe,
with no attacker; silent in three of the four doors, `verify` reporting `ok: true` in one; the recovery is a
bootstrap rebuild that loses the post-edit writes, and nothing says so). **EXECUTED** — four doors reproduced by
four passes (X1 `c3j`, A1 `strand`, A4 `P4`/`P6b`, A4 `P3`/`P7b`/`P7c`), each re-run by the orchestrator; five
`#[ignore]`d cases pin them (§6).

**The property.** T79 (d), T81 and the H-20/M-52 remedies each approximate one rule — *what this node serves must
be what a fresh replica can hold* — by a different symptom: T79's WARN asks "is the parent in my quarantine"
([service.rs:4377-4410](crates/ledger/src/service.rs#L4377), `self.quarantined.contains_key(parent)` at `:4389`);
T81's closure is seeded only by the ids boot refused *at this boot* (`content_rule_refused` `:3608`,
`amount_cap_refused` `:3375`) and walks their descendants; boot inserts everything else leniently
(`dag.insert(…, false)` `:3692`) with no lifecycle check (`:3494`). A parent that is in **neither** the DAG nor
the quarantine — because its id changed under an edit, because its block has no id, or because the operator
deleted it — is named by none of them, and `choose_parents_in` treats its served child as an ordinary head.

**Door 1 — the rebase builds on it (X1 `c3j`).** A node with P2P off (or a record that never gossiped) writes
T2 and a child J that lands in the journal; the operator fixes T2's narration and appends a hand line H in the
same edit. T2's new id is quarantined by the pass; J's envelope still verifies (parents are envelope, unchanged)
and J is inserted leniently with a parent that exists nowhere; the rebase re-chooses H's parents from the rebuilt
heads — J is one — and finalize signs H over `[T1, J]`. The (d) WARN does not fire: T2's original id is in
nobody's quarantine.

```
after boot       served=7 quarantined={} clock=8 pending=1 heads={H(e896f97a)}
    H(e896f97a)  author=local lamport=8 parents=[J(journal)(cc267242),E(T2 edited)(dd26ae93)] sig=<none>
after signer     served=6 quarantined={E(T2 edited)(dd26ae93)} clock=8 pending=1
    H(e896f97a)  author=local lamport=8 parents=[T1(ae82ae6f),J(journal)(cc267242)] sig=<none>
  [log INFO] … its parents were chosen again from what survives, before it is signed (H-22) rebased=1
after finalize   H(e896f97a)  author=ea4a6c63… lamport=8 parents=[T1(ae82ae6f),J(journal)(cc267242)] sig=0b5eb29e
    J(journal)(cc267242) author=ea4a6c63… lamport=6 parents=[T2(38f700d4)] sig=124400ef
  WIRE REFUSES J(journal)(cc267242): parent 38f700d4 not served
peer service (B, verifier installed) staged 4/6 ; refused: 2
  PEER REFUSES J: DAG: Missing parent: cc267242… references unknown parent 38f700d4…
  PEER REFUSES H: DAG: Missing parent: e896f97a… references unknown parent cc267242…
FIXED POINT: file byte-identical after 2nd compaction = true; served/quarantine/balance diffs = 0
```

No "name a parent that is only in its quarantine" line is logged. Where a peer holds the original T2 (0924 §9
R2) J and H resolve there and the mesh converges; where none does, J, H and every later write of this node are
refused by every peer for good, and the H-20 remedy ("restore the original line from a peer's copy … or delete
the edited block") cannot repair J's parent. The boot fuzzer's oracle takes `known_ids = served ∪ truth`
([boot_fuzz.rs:684-689](crates/p2p/tests/boot_fuzz.rs#L684)) — it assumes the mesh holds the original — so it
could not see this.

**Door 2 — the prescribed remedy silences the WARN (A1 `strand`).** The (d) shape itself is reachable at HEAD:
edit any envelope line (lamport, parents, or delete the signature) of a non-head own record and the record is
quarantined under the *same* id, so its served child names a quarantined parent and the WARN fires. The
per-record H-20 WARN prescribes "restore the original line from a peer's copy of the ledger, or delete the
edited block". On a node no peer has a copy for, the operator deletes the block:

```
--- boot 1: T2's lamport line edited 5 -> 6
  A quarantined=["3e10ebff"]
  fresh peer B adopted 4 of 7 served; refused: T5 API, T3, T4 (ORPHAN: missing parent …)
--- boot 2: the operator follows the per-record H-20 remedy: delete the edited block
  A quarantined=[] served=7            (no WARN line at all)
  fresh peer B adopted 4 of 7 served; refused 3
--- boot 3 (not named by any WARN): T2 put back with its openledger-* lines stripped
  A re-adopted T2 3e10ebff author=ea4a6c63 lamport=11 parents=[""] sig=7c2aae4b
  fresh peer B adopted 8 of 8 served; refused 0
```

After the remedy the parent is in neither the DAG nor the quarantine, the WARN stops, and the served child and
every later write stay unadoptable by every anti-entropy peer. The remedy that works — strip the `openledger-*`
lines so the record is re-adopted under the same id — is named nowhere.

**Door 3 — the M-52 / M-51 remedies (A4 `P4`, `P6b`).** The M-52 WARN says "restate the amounts in a larger
unit" ([:3363-3372](crates/ledger/src/service.rs#L3363)); the closure WARN says "repair the refused record"
(`:4962`); the H-08 banner says "stop the node and repair them"; README §Editing says "or delete the edited
block". After any of these nothing is refused at the next boot, so nothing seeds the closure; the descendants
load leniently (the signature covers `openledger-parents`, so they cannot be re-parented by hand):

```
[P4 before remedy] directives=2 quarantined=3 unparsable=1 heads=[] verify.ok=true qids=["30e7874f", "60987ad2"]
[P4 after remedy]  directives=5 quarantined=0 unparsable=0 heads=["f11e7f43", "30e7874f"] verify.ok=false errors=["Missing parent: 60987ad2… references unknown parent f3ce5c6d…"]
[P4 after] X' served? true C served? true G served? true Cash WEI=14 Cash ETH=50000
[P4 fresh] holds 3 of 5; refused=["60987ad2 never found its parent …", "30e7874f never found its parent …"]; Cash WEI=(none)
[P6b boot1] directives=2 quarantined=3 … qids=["264919d6", "98e92b9f", "c1d8bba9"]
[P6b boot2] directives=4 quarantined=0 unparsable=0 heads=["c1d8bba9"] verify.ok=true errors=[] qids=[]
[P6b fresh] holds 2 of 4; refused=["98e92b9f refused [ACCOUNT_NOT_OPEN]: … not open at 2024-01-05", "c1d8bba9 never found its parent …"]
```

G is a head after the remedy; the next own write names it. For the deleted-`open` shape `verify` is clean.

**Door 4 — a text-held block with no id (A4 `P3`, `P7b`, `P7c`).** `amount_cap_refused_block_ids` returns
`None` whenever `ParseLimits::IDENTIFY` cannot parse the block ([:695-699](crates/ledger/src/service.rs#L695)):
a pre-T37 Unicode account (L-45's own precondition, which the code calls real at `:3311-3316`), a past-cap block
glued to one (contiguous refusals merge into one raw block, `:617-622`), or an amount spelling `from_str_exact`
rejects (L-92). No seed; the children load leniently; the (d) WARN looks the parent up by an id the block never
had.

```
[P3 upgraded] directives=4 quarantined=1 unparsable=1 heads=["d15fa53b"] verify.ok=false errors=["Missing parent: bdc81027… references unknown parent 1111…"] qids=[]
[P3 upgraded] child served? true grandchild served? true Cash USD=11
[P3 fresh] holds 2 of 4; refused=["bdc81027 never found its parent …", "d15fa53b never found its parent …"]; Cash USD=(none)
[P7c] IDENTIFY parses the block? false     [P7c] child of X served? true     fresh holds 2 of 3
```

Only the L-45 WARN fires; nothing names the two served descendants.

**Consequence.** In every door the served record is a head and this node's next write names it (X1 `c3j`:
H over J; A4 `P4`: G; A1 `strand`: T3/T4 and the API append T5). Every anti-entropy peer buffers it on a parent
it can never obtain and re-Wants it forever (`MissingParent` is not permanent); a node bootstrapped from this
file serves the same stranded set, so later joiners differ from the bootstrapped replicas permanently (the M-51
shape). The recovery — strip the envelope lines of the vanished record so it is re-adopted under its old id, or
rebuild by bootstrap — is documented nowhere; the H-20 remedy makes it worse.

**Fix** (S–M, T84): state the property once — at boot, after the signature pass and the closure, quarantine (or
at least WARN about, extending T79 (d)) every served transaction whose parent is in neither the DAG nor the
quarantine, and every transaction that fails the peer's I3/I9 against the surviving `AccountState`; make the
rebase exclude heads whose ancestry does not resolve; reword the H-20, M-52, closure and H-08 remedies
(descendants go with the record; strip the envelope lines to re-adopt under the same id; or restate the chain /
rebuild by bootstrap); the boot-fuzzer oracle gets a single-node mode (`known_ids = served`). Regression: the
five `#[ignore]`d cases un-ignored (§6).

---

## 3. New findings — Medium

### M-56 — The T81 closure's "orphaned account" term is judged by account name alone, before the operator input that re-opens the account: a hand `open` — the natural M-51 remedy — un-strands the transactions every peer refuses, one restart later, silently; the wire path never checks the closure

**Severity: Medium** (incorrect balances reachable by an operator's supported edit; boot → compaction → boot
not a fixed point; a replica-local judgement of a mesh property). **EXECUTED** (X1 `c2d`, `c8b`; A4 `P2`,
`P5-late` / `P5-early`; pinned `#[ignore]`d in `exact_balances.rs`).

**Mechanism.** `quarantine_descendants_of_refused_history` runs at [service.rs:3928](crates/ledger/src/service.rs#L3928)
*before* `adopt_operator_input_at_boot` (`:3932`); its account term (`:4908-4919`) drops an account from
`orphaned_accounts` when *any* `Directive::Open` for it survives — no date, no currency list — while every peer
judges the transaction with `check_account_open(account, date)` ([accounts.rs:275-292](crates/ledger/src/accounts.rs#L275))
and `check_currency_constraint_at` ([validate.rs:397-401](crates/ledger/src/validate.rs#L397)). A hand `open` of
the account is adopted (L-77 sees the account closed: the flood `open` is in the quarantine), signed and written;
at the next boot it is history, the account is not orphaned, the transaction is served. `stage_remote_directive`
([:8316](crates/ledger/src/service.rs#L8316)) has no `refused_history_closure` check where `adopt_file_directive`
(`:7386`) has.

```
=== c2d: flood `open Assets:Flood` (4097 currencies) + own txn X on Assets:Flood + a hand `open Assets:Flood` ===
  DIFF: served after boot 2 but NOT after boot 1: X(on Flood)(d60f5944)
  c2d fixed point holds = false
  peer service (B, verifier installed) staged 7/7 ; refused: 0
--- c8b: boot 1: X served = false; live: stage_remote_directive(X) from a peer -> Ok("accepted"); X served now = true
[P5-late boot2] on_flood served? true child served? true Flood C0001=5 Cash USD=7
[P5-late fresh] holds 3 of 5; refused=["98e92b9f refused [ACCOUNT_NOT_OPEN]: … not open at 2024-01-05", "c1d8bba9 never found its parent …"]
[P5-early fresh] holds 5 of 5; refused=[]        (works only if the operator back-dates the open and lists the currency)
```

Boot 2 logs no line saying X left the quarantine (boot has no release diagnostic; `release_quarantined_now_in_dag`
is live-only). **Consequence:** M-51's partition with the closure believing it is closed (`ACCOUNT_NOT_OPEN` is
a permanent intake refusal); balances differ between the process that adopted the `open` and every later one.
**Fix** (S, T85): decide "orphaned" per transaction with the peer's predicate against the surviving DAG's
`AccountState`, after operator input is adopted (or refuse a hand `open` of a closure-orphaned account,
L-77-style); apply `refused_history_closure` on the wire path as on the file path.

### M-57 — A lamport edit of an own record plus a hand line in one edit defeats the L-87 clock release: the hand line is stamped above the edit, the rebase re-chooses its parents but not its lamport, and past 2^32 every peer refuses it and everything this node writes after it

**Severity: Medium** (H-22's consequence — this node's authoring permanently cut off from the mesh; the
trigger is the unsupported edit L-87 set out to neutralise plus the README's supported "fix a record and append
in one edit is safe"; below 2^32 the whole mesh clock follows the edit and every node's gap WARN names this node
from then on). **EXECUTED** (A1 `lamport`; pinned `#[ignore]`d in `boot_fuzz.rs`).

**Mechanism.** Boot stamps the hand line at `clock + 1` where the clock already includes the edited lamport
([:7466](crates/ledger/src/service.rs#L7466), `:7639`); `quarantine_out_of_dag` rebases parents only (`:5011`);
`release_clock_carried_by_edited_records` (`:4557-4595`) takes its floor from the DAG (`:4565`), which still holds
the hand line at edit+2, so nothing is released; `finalize_operator_input` signs at that lamport (`:4274-4281`).
`LamportAdvance` is not a permanent refusal ([anti_entropy_alpn.rs:2427](crates/gl-node/src/anti_entropy_alpn.rs#L2427)):
the id is deferred until the peer's clock climbs by 2^32, which never happens.

```
=== edited lamport of T2 -> 5000000000, hand line in the same edit: false
  A after gl-node boot: quarantined=["3e10ebff"] clock=7        (control: L-87 holds)   B accepted everything A serves
=== edited lamport of T2 -> 5000000000, hand line in the same edit: true
  A after gl-node boot: quarantined=["3e10ebff"] clock=5000000002
  A hand line 30097d4b author=ea4a6c63 lamport=5000000002 parents=["8085d66c", "836dd72d"] sig=f054c6ea
  A API append e426ae34 author=ea4a6c63 lamport=5000000003 parents=["30097d4b"]
  B REFUSES 30097d4b: stage: openledger-lamport 5000000002 … would advance this node's clock from 7 by more than 4294967296 in one step; refused (H-12 adoption ratchet) …
  B REFUSES e426ae34: ORPHAN: missing parent 30097d4b (buffered, re-Wanted)
  A reboot clock=5000000004 gap=4999999996
=== 4000000000 + hand: A clock=4000000002 … B accepted everything; B clock after sync: 4000000004
```

Boot prints the (d) WARN, an L-94 gap WARN naming this node with the allowlist-removal remedy, and the per-record
H-20 WARN; none says the hand line carries the jump. **Fix** (S, T84): operator input is unsigned and unserved
until finalize, so re-stamping it re-issues no pair — compute the release floor without pending operator input and
re-stamp those entries' lamports in insertion order from the released clock (as `set_author_id` does for L-67),
or stamp operator-input lamports in `finalize_operator_input`.

### M-58 — L-80 is not closed on gl-node's boot path: the over-cap fact is lost by the reload that the L-80 refusal itself triggers whenever the file holds hand lines — the L-64 shape — so every write stages, fails in `persist_atomically` and pays a full reload with the permit held, and the client gets a request timeout

**Severity: Medium** (new state derived once and not re-derived on a reload; cost beyond the documented budget,
reachable by any API-key holder per request and by an allowlisted peer's batch per tick; the CHANGELOG and README
now promise "refused before staging, with no reload, so the node stays responsive", which is false on exactly the
shape L-64 describes). **EXECUTED** by four passes independently (D1 on the real binary, A5 `a5_p7b`, X3 `k3y`/`k3x`/`k3r`,
X1 `c5b`), re-run by the orchestrator.

**Mechanism.** (1) `boot_with` measures the fact only when no operator input is pending
([service.rs:3939-3944](crates/ledger/src/service.rs#L3939)). (2) The startup compaction hits `prepare`'s L-80
refusal (`:5861-5871`), which `commit_inline` (`:6884-6905`, only `CommitInFlight`/`Parse` exempt) and gl-node's
`prepare_or_recover_with_reload` ([ledger_commit.rs:462-478](crates/gl-node/src/ledger_commit.rs#L462)) both answer
with the L-13 reload. (3) The reload re-reads the never-rewritten hand lines raw → pending → no measure;
`finish_recovery` then runs `keep_committed_envelopes_in` (`:6422`), which empties the rebuild's operator-input
sets, so `finalize_operator_input` (`:6442`) returns at `:4201` before its measure at `:4299`; `adopt_reloaded`
(`:6636-6663`) carries `canonical_is_current` but not `canonical_over_cap` — the Done note's "carried through
`adopt_reloaded`" has no code. (4) With the flag false, `append_headroom()` (`:5697-5706`) is positive, both
pre-stage checks admit, `prepare` builds the text, `persist_atomically` refuses it as `Io(InvalidData)` (`:264`),
the driver reloads; the peer arm sees `Io`, not `ResourceLimitExceeded`, so the M-39 backoff never arms.

Real binary (D1 `case_l80.py`; 66,911,755 B file, 1,502 hand transactions, signing on; `$P/D1/run/l80/node.log`):

```
18:38:03 WARN the canonical form of this ledger is larger than the ledger file cap … EVERY WRITE FAILS … canonical_bytes=67454128
18:39:25 WARN L-13 reload installed … before=1502 after=1502 discarded_staged=0     ← startup compaction (82 s)
18:39:26 WARN could not compact … at startup … error=Resource limit exceeded: the canonical form … (L-64, L-80)
18:40:35 WARN L-13 reload installed … before=1503 after=1502 discarded_staged=1     ← appendTransaction #1: STAGED; client timed out
18:41:57 WARN L-13 reload installed … before=1503 after=1502 discarded_staged=1     ← appendTransaction #2
18:42:57 WARN L-13 reload installed … before=1502 after=1502                         ← shutdown compaction
18:42:58 WARN could not compact … at shutdown … error=IO: ledger content is 67454128 bytes (max 67108864)   ← the pre-T82 text
```

`grep -c 'reload installed'` = 4; `grep -c 'refused before staging'` = 0. Library level (X3 `k3y`, 0.7 s per
attempt on the 0924 fixture):

```
[k3y] boot: headroom=888430 (boot skips the measure while operator input is pending) unsigned_operator_input=3
  finalize_operator_input → 3; headroom=0 (L-80 fact set)
  startup compaction → ResourceLimitExceeded(… 68721298 bytes, over the file cap …) in 653ms
  AFTER the startup compaction's reload: headroom=888430 (0 = fact kept; >0 = LOST) unsigned_operator_input=0
  first mutation: → Io(InvalidData: ledger content is 68721439 bytes (max 67108864)) in 725ms; observer=[(Compact, 68721439)]
```

Both `l80_*` tests use comment-only fixtures (no operator input, so the reload's boot measures) and never run a
compaction first. Without hand lines the fact survives; with them — the shape README:994-996 names as the usual
cause — it does not. **Fix** (S, T86): measure unconditionally at the end of `finish_recovery`'s install arm
(after `finalize_operator_input`), or carry the flag through `adopt_reloaded`; treat `ResourceLimitExceeded` from
`prepare_compaction` like `Parse` in `commit_inline` and `prepare_or_recover` (nothing was written, no reload —
this also removes the startup/shutdown reload X3 `k3r` measures); extend the gl-node `l80_*` test to compact
first (fails at HEAD).

### M-59 — `keep_committed_envelopes_in` installs a committed envelope whose parent the rebuild lacks: the local write staged in the same failed commit is discarded by the floor, the hand line it parented is kept with memory's envelope naming it, and the node's later history descends from a record no replica can ever resolve

**Severity: Medium** (the High shape — this node's later writes unresolvable on every peer — behind one failed
commit plus an edit adopted by the pre-persist reconcile (an editor autosave is in the threat model); the one log
line claims a backup was restored; **mitigated by accident** when the caller retries the identical body, since
the content id is the body and the parent then resolves). **EXECUTED** (A5 `a5_p2`; the signing-off floor (a)
variant X3 `k1a`).

**Mechanism.** The pre-persist reconcile (`adopt_external_edits` [:6755](crates/ledger/src/service.rs#L6755) →
`reconcile_content`) adopts a hand transaction H inside `prepare`'s compaction arm (`:5842-5856`) with parents from
the DAG heads (`:7597-7600`), which include the local write P staged in this very commit. If the persist fails,
`finish_recovery` reloads; H is raw on disk → operator input in the rebuild; `keep_committed_envelopes_in`
([:6507-6538](crates/ledger/src/service.rs#L6507)) replaces it with memory's copy (parents `[P]`) with no check that
those parents exist in `reloaded.dag`; `rebuild_dag` inserts with `require_parents = false` (`:4826`), so the
edge is parked, never refused; P is staged → floor-exempt (`:6477`) → discarded. The next local write names H;
the next compaction writes H with parent P to disk.

```
A5-P2 local write outcome: Some("IO: Permission denied (os error 13)")
A5-P2 P (staged local txn) still in memory after recovery: false
A5-P2 hand parents=["e0695777…9139"] signed=true lamport=Some("4")     parent e0695777…9139 in DAG: false
A5-P2 log has 'L-81': true | 'REFUSING': false | 'reload installed': true
A5-P2 next write parents=["ed5ae1a9…73b4"] (hand id ed5ae1a9…73b4)
A5-P2 ON DISK hand parents=["e0695777…9139"]  /  on-disk parent present: false   on-disk directives=4 quarantined=0
```

Control with R3 (pre-T82): `hand parents=[] … ON DISK hand parents=[]` — consistent history. The signing-off
variant (X3 `k1a`): floor (a) drops an unsigned own record A that memory's kept B names; B is served, written and
reloaded with `missing parents: ["3c9eabe7"]`, `quarantined=[]`, no WARN; with signing on the floor `REFUSING`s
(sound). **Fix** (S, T86): replace only when every parent of memory's envelope is in `reloaded.dag` or in
`replacements`; otherwise refuse the install (memory kept, P and H rewritten) or keep the rebuild's re-stamped
copy; log the parent ids; exclude from the floor's exemption any id a kept record names as a parent.

### M-60 — Decision (11)'s uid guard is checked on one inode and the follow is done on another, and only on the first hop: whoever can write the ledger's directory can swap their own link over the operator's between the two syscalls, or plant one further down the chain, and have the next compaction overwrite any file the node's uid owns

**Severity: Medium** (a stated security guard against threat (e) that "runs when its input is not yet final";
the consequence is the one the guard exists to prevent — the next compaction rewrites any node-uid-owned file,
the key file included; preconditions: a symlinked `.bean` in a directory another uid can write). **EXECUTED**
for the race window and the hop rule (X3 `k4a`, `k4b`; A5 `P5`); the uid half is **PLAUSIBLE** (no second uid on
this machine — the guard reads `uid()` from the same `symlink_metadata` result, so the observed inode mismatch is
the uid mismatch).

**Mechanism.** `resolve_ledger_path` ([journal.rs:164-190](crates/ledger/src/journal.rs#L164)): one
`symlink_metadata(configured)` (`:165`) reads the owner of the first hop, then `canonicalize` (`:189`) walks the
path again and follows every further link regardless of owner; a directory link in the path is never examined.
gl-node passes the *resolved* path to the lock, `boot` and the watcher (`main.rs:216-232`, `:614`), so the only
window is inside this function.

```
[k4a] 21902 resolves against 305 link swaps in 3 s → 113 times the inode the uid check inspected was NOT the link canonicalize followed (0.52%)
  first hit: checked ino 10859591 → …/k4a/a/real.bean ; followed → …/k4a/b/real.bean        (14.5% on a quiet machine)
A5-P5 chain a->b->target resolves to: Ok(".../real/target.bean")     dir-link path resolves to: Ok(".../dirlink/target.bean") (is_symlink final=false)
```

README:1019-1024 "a link owned by any other user refuses boot" is true of the first hop only. **Fix** (S, T87,
decision): follow a link only when its parent directory is owned by this uid and not group/world-writable (race-free
by construction), or resolve through an `O_PATH|O_NOFOLLOW` fd (`fstat` for the uid, `F_GETPATH`/`/proc/self/fd`
for the target); check every hop or refuse chains; document directory links as policy.

### M-61 — Converting a ledger to a symlinked one after an unclean stop silently strands its journal: the node derives the journal from the target, the acknowledged records in `<link>.journal` beside the link are never read, folded or renamed, and H-15's guard does not fire because the `.bean` is present through the link

**Severity: Medium** (acknowledged records silently absent from service, reached by an operator following
README §The commit journal's symlink support after a crash — the README never says to move the journal; the bytes
remain in the orphaned file, so recoverable by hand). **EXECUTED** (X3 `k4f`).

**Mechanism.** `boot_with` derives `journal_path_for(&file_path)` from the *resolved* path
([service.rs:3160](crates/ledger/src/service.rs#L3160), [journal.rs:193-201](crates/ledger/src/journal.rs#L193));
nothing looks for `journal_path_for(&configured)`; the H-15 check asks only whether the `.bean` is present.

```
[k4f] acked append → observer=[(Append, 157)] files=["ledger.bean.journal=157", "ledger.bean=118680"]
  boot through the link: acked record served? false | journal_path=…/k4f/vol/real.bean.journal | directives=401
  files beside the link: ["ledger.bean.journal=157", "ledger.bean.tmp.4242.0123456789abcdef=5", "ledger.bean@=132", "vol=96"]
  after the startup compaction: beside the link [same] — ledger.bean.journal (the acked record) is never read, never folded, never renamed
```

(The temp named after the link's stem is not swept either — the sweep matches the target's stem; Info.) The
reverse move strands `real.bean.journal` the same way. **Fix** (S, T87): when `file_path != configured`, refuse
boot on a journal beside the link (H-15's precedent: "a journal beside the link belongs to a ledger that was at
that path; move it beside the target, or start the node on the old path to fold it"), or at least WARN; README
§The commit journal: move `<name>.journal` with the file, or stop cleanly first.

### M-62 — The L-90 uncharged hold escapes both inbound byte budgets: what a peer's exhausted budget cannot cover is held uncharged up to the 16 MiB weight budget per connection, so one allowlisted peer can hold ~460 MiB of parsed directives across its 32 connections and the 256-connection cap admits 4 GiB

**Severity: Medium** (resource exhaustion beyond the documented budgets — 32 MiB per peer, 256 MiB global —
reachable by an allowlisted peer; before T83 the uncharged residue was one directive, so T83 turned a documented
one-directive residual into a per-connection 16 MiB one and multiplied it by the connection caps; Low if the
pre-T83 escape is judged to have accepted the class). **EXECUTED** at the gl-node level (A6, archive
instrumentation of the real `apply_supply_entries`; the orchestrator re-ran the weight probe).

**Mechanism.** Phase 1 flushes on `PHASE_ONE_WEIGHT_BUDGET` alone ([anti_entropy_alpn.rs:1894](crates/gl-node/src/anti_entropy_alpn.rs#L1894));
the byte-budget charge is best-effort (`let _ = weight.grow_to(..)`, `:1918`); nothing bounds the uncharged sum
across connections or peers (budgets [connection_limiter.rs:161-166](crates/gl-node/src/connection_limiter.rs#L161),
`grow_to` `:734-762`). Entry needs a charged body: 32 connections × a 1 MiB body each weighing ~14.4 MiB parsed.

```
A6-flush: chunk weight=16617361 directives=70 charged_beyond_base=0   (×3, plus a tail)
60.6 MB of parsed directives from a 4.36 MB frame passed uncharged; ~16.6 MB resident at once (13.9× text)
```

**Fix** (S, T88, decision): cap the uncharged residue per connection (e.g. 1 MiB, then flush) or give each
peer an uncharged allowance counted against its 32 MiB share; document the bound.

---

## 4. New findings — Low

- **L-96 — After T80's re-attribution, a placeholder-authored own record that is *outside* the DAG (held as text, or quarantined for another reason) stays `"local"` for every "own" lookup, so the L-87 release drops it from the clock floor and the node re-issues its lamport, the ceiling refusal names `author local` with the mesh-wide allowlist remedy (L-91's text verbatim), and a Fresh boot and a reload resume at different clocks.** Found by A2 (`s7`, `s5`, `s9`) and X1 (`c5a`). Boot under the placeholder folds a `"local"` envelope as own (`note_if_own` [service.rs:1613](crates/ledger/src/service.rs#L1613), `note_text_if_own` `:1626`); `reattributed_placeholder_record` rewrites DAG entries only (`:4434`); `release_clock_carried_by_edited_records` (`:4561`, `own = self.author_id`), `highest_lamport_author` (`:5526-5545`, `"local"` is *foreign*, so preferred) and `set_author_id` (`:8044`, returns early) all miss the `"local"` key. **Executed:** `[B/set_verifier] … clock=4` (was 6) → `new own write stamped lamport=Some(5)` → `DUPLICATE PAIR (8139770e, 5) on ids ["301f869f", "e82a4bbd"]`; `RESULT: LamportCeiling next=9007199254740991 author=Some("local") … Remedy, mesh-wide: remove that author from the allowlist`; `clock after Fresh pipeline = 9; after the L-13 reload of the same file = 6`. Threat (e) / editor damage for the pair; L-91's rating for the text. Fix (T85): treat `PLACEHOLDER_AUTHOR` as this node in the three lookups once `author_id` is set, or re-key `boot_outside_dag_lamports["local"]` in `set_author_id`.
- **L-97 — The L-87 clock release re-issues the `(author, lamport)` pair of an edited own record whenever that record sat more than one above the highest survivor: the first record stamped after any restart (boot's `+1` gap) and any own record written after an adoption (the clock is set to `max(local, remote) + 1`, a value nobody stamped).** Found by X1 (`c6a`, `c6b`) and A6 (harness). `release_clock_carried_by_edited_records` resumes at `highest_remaining + 1` ([:4577](crates/ledger/src/service.rs#L4577)) and excludes the edited record (`:4570`) on the doc's argument that its lamport "was stamped above what the node held then" — true only when nothing sat between. `edited` = "signature does not verify", which a narration fix with the lamport line intact satisfies, so the released value was issued and may be on every peer. **Executed:** `after signer … clock=5 … next record this node issues: (author=key, lamport=6); T2's original pair on the peer: (key, 6) → RE-ISSUED = true; peer now holds duplicated (author,lamport) pairs: ["(ea4a6c63…,6)x2"]`; harness: `A restarted at clock 9 (r3 issued at 10); r4 stamped 10; B's duplicate pairs [("f5f9a35a…", 10)]`. The INFO says "an edited lamport line" for a body edit. M-18's shape (two records under one pair on every replica, read-model order by txid tie-break, balances unaffected; the file invariant `assert_lamport_pairs_unique` broken); rated Low as L-67 was — the user may prefer M-18's Medium. Pinned `#[ignore]`d in `convergence.rs`. Fix (T84): count the edited record's own lamport unless it is implausible (≥ `LAMPORT_GAP_WARN` above the rest), i.e. resume at `max(highest_remaining + 1, edited_lamport)` below that bound.
- **L-98 — The "EVERY signature this node checked failed" WARN is judged per pass: two edited own records fire it in the signer's pass (foreign records are `Unverifiable` there) while every foreign record verifies in the verifier's pass.** A2 `s3`: `[A/set_signer] WARN … EVERY signature this node checked failed … [A/set_verifier] INFO ledger history verified … verified=3` — the WARN's remedy sends the operator to `meshId`/key "before repairing anything". [service.rs:4496-4499](crates/ledger/src/service.rs#L4496). The converse (one honest re-attributed record suppressing it on a real mismatch) is refuted: nothing verifies under a wrong domain. Fix (T85): judge once in `verify_own_history` over the summed passes.
- **L-99 — On the exact shape the T80 WARN calls "not an edit" (a domain or key mismatch), the L-87 release still treats every failure as an edited lamport line and walks the clock to 0.** A2 `s1(e)`: `[B/m2/set_verifier] WARN … EVERY signature … INFO … (L-87) … directives=0 quarantined=3 sig_total=3 clock=0` (was 4). [:4520](crates/ledger/src/service.rs#L4520) runs unconditionally after `:4496-4511`. The node then authors under a domain peers refuse anyway and re-issues pairs it signed in its own file. Fix (T85): skip the release when `every_checked_failed`; say in the WARN not to author until the domain/key is fixed.
- **L-100 — Boot's H-19 gap WARN is judged on the DAG as loaded — before the signature pass and the closure — so it fires for the record the same boot then quarantines, and prescribes the bootstrap join for a gap the served history does not have.** D1 on the real binary (`case_l87`): `WARN the ledger history carries a lamport gap no honest mesh makes … gap=3999999998 top=4000000000 author=<this node>` → `WARN quarantining … signature does not verify` → `INFO … (L-87) from=4000000001 to=3`. [:3798-3830](crates/ledger/src/service.rs#L3798); `lamport_gap()` (`:8173`) has no production caller. Contradicts README "judged on the history itself". Fix (T85): re-judge after `verify_history_pass` on the surviving DAG and print from gl-node after `verify_own_history`.
- **L-101 — The one content rule every peer holds history to that T81's history rule and closure leave out: a record over the wire's 1 MiB body cap (inside every count — 4,000 posting keys × 300 B) loads at boot, is served with its descendants, is refused for good by every peer and strands the descendants on every fresh replica — M-51's shape through the cap T51 decided not to apply at boot.** A3 `h2`: `big body: 1256134 bytes (cap 1048576) … boot: quarantined=0 … serves big=true serves child=true … wire on big: Resource limit exceeded: economic_bean is 1256134 bytes … fresh replica on child: MISSING_PARENT`. Wire [union_merge.rs:210-216](crates/p2p/src/union_merge.rs#L210); boot's arm never calls `enforce_economic_bean_limit` ([service.rs:1096-1115](crates/ledger/src/service.rs#L1096), by T51's decision), so it never seeds the closure. Precondition a pre-L-02 file or a pre-T51 hand edit. Pinned `#[ignore]`d in `m50_wire.rs`. Fix (T85, decision): a third seed of `content_rule_refused` (same WARN, same closure), or the H-23 rule's WARN naming it as served-but-unreplicable.
- **L-102 — `decode_memory`'s honest-frame budget (8×) is a proxy for one shape: the densest admitted frame parses at 14.4×, and T81's legacy posting-metadata ceiling tripled its absolute size (69 MB → 203 MB per 14 MB frame); the "≤ 0.08×" comment is stale (0.28×).** A3 `mem`: `T81 densest x256: frame 14083501 B (fits 16 MiB: true), phase-1 peak 202783694 B (14.40x frame), kept 202537984 B`. Per-byte multiple unchanged by T81; bounded by the frame cap and, resident, by the 64 MiB file cap. Fix (T88): add the densest admitted shape to the control and state ≈15×, or lower `MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY` to 1,024 (still covers any honest history); fix the comment.
- **L-103 — `VerifyResult.quarantined` is unbounded where `errors` is truncated: a 20,000-record closure costs 1.34 MB and 260 ms under the read lock per `verify`, twice per request.** A4 `P8`; [query.rs:293-299](crates/gl-node/src/graphql/query.rs#L293) vs `verify_dag`'s cap ([verify.rs:99-122](crates/ledger/src/verify.rs#L99)); `MAX_VERIFY_PER_REQUEST = 2`. Size set by the file, not the caller. Fix (T88): cap at 1,000 plus `quarantinedTotal: Int!` (schema addition).
- **L-104 — On a signing-off node the L-93 exemption never expires: a hand line finalised, served and written back is still "unsigned", so a restored backup plus one failed commit drops it without `REFUSING`; `keep_committed_envelopes_in` treats the same record as enveloped — T82's two rules disagree on "committed".** A5 `a5_p3`: `hand after finalize: author=Some("test-peer") lamport=Some("3") signature=None adopted_from_file=1 … REFUSING: false | discarded_file_adopted=1 … HandY still open in memory: false / on disk after the next commit: false`. [:6483-6486](crates/ledger/src/service.rs#L6483) keys on `ENVELOPE_KEY_SIGNATURE`; finalize stamps author+lamport only (`:4265-4277`). Fix (T86): exempt only while `is_operator_input(memory's copy)`.
- **L-105 — L-85's discriminator never runs when the later append was torn inside the first five bytes of its header: the acknowledged record is still dropped as torn.** A5 `a5_p4`: `R3 header cut at 3 bytes: OK intact=1 torn_tail_bytes=108; at 5 bytes: OK intact=1; at 6 bytes: Corrupt@105`. [journal.rs:496-506](crates/ledger/src/journal.rs#L496) needs a complete `;;olj ` before the prefix hash at `:512`. Every other asked shape (length shrunk 1/5/20, shrunk + torn, shrunk final, grown over intact/payload-torn, stale block) is `Corrupt` or torn as designed. Fix (T86): with no candidate, hash `region` minus any trailing proper prefix of `;;olj ` against `own_hash`.
- **L-106 — A peer serving the descendants of a wire-refused record makes the victim re-transfer, re-parse and re-Ed25519-verify that doomed subtree on every anti-entropy tick, forever: L-34 caches the refused parent but not its buffered children, `MissingParent` is buffered rather than refused, and the T81 closure has no wire-intake counterpart.** X2 `r3`: `tick 1: 51 validated, 1 refused (X cached), 50 buffered; ticks 2–5: 50 validated, 50 buffer_dup each; A holds 0 of X's 50 children`; after `MAX_ORPHAN_AGE` they age out and are re-fetched. `fetch_want_chunk` re-Wants by membership ([anti_entropy_alpn.rs:1459](crates/gl-node/src/anti_entropy_alpn.rs#L1459)); phase 1 validates before `missing_parents` is computed (`:2064`); `stage_refusal_is_permanent` (`:2404`) excludes `Dag(_)`. Cost `min(subtree, 1,000)` verifications per tick per peering victim; threat (c). Fix (T88, decision): suppress, per peer and transitively, buffered orphans whose only missing parent is in the `(peer, id)` refusal cache for a content reason.
- **L-107 — The parent-hint table is process-wide with no per-peer share, so one allowlisted peer serving ~33k signed orphans naming absent parents fills it and restores the pre-T83 crawl for every honest join; hints are aged out lazily only (`evict_expired` never touches them).** Found by X2 (`r1`) and A6 (harness): `hint table full (1000 buffered, 32768 refused by X): 1300-chain ticks Some(25)` vs 3 with a free table. [orphan_buffer.rs:271](crates/p2p/src/orphan_buffer.rs#L271), `:306-330`, `:607-640`. Pinned `#[ignore]`d in `convergence.rs`. Fix (T88): a per-remote hint budget (as orphan counts and the refusal cache have) or evict-oldest; sweep hints in `evict_expired`.
- **L-108 — Two hand lines in one edit where the child precedes its hand parent in the file (same date): boot 1 refuses the child as "exists nowhere in this ledger", boot 2 adopts it — served set, balances and file bytes change across boot → compaction → boot.** X1 `c7 order`: `refused=1 … openledger-parents names e896f97a…, which exists nowhere … FIXED POINT: file byte-identical = false; DIFF: served after boot 2 but NOT after boot 1: H2(parent=H1)`. Operator input is adopted in stable `(date, type)` order; the L-75 check resolves at that moment. Loud, self-healing, wrong text. Fix (T85): adopt hand-parented entries after the rest of the batch, or say a later hand line is adopted at the next restart.
- **L-109 — A pasted allowlisted-signed block carrying a stray `openledger-*` key has two fates for the same bytes: boot strips the key and serves the record (L-89); the live reconcile refuses it (H-06) and the re-persist deletes the block from the file.** X1 `c8a`: `BOOT: P served = true … file after compaction holds openledger-note = false; LIVE: reconcile_file -> Ok("new=0 dup=5 rejected=1") … the canonical re-persist will drop them from the file … P served = false; file after re-persist holds P's body = false`. The strip runs only in `boot_with` ([:3412](crates/ledger/src/service.rs#L3412)); the live path holds complete envelopes to `validate_body_envelope_keys` (`:7344`). The record is a peer's, re-suppliable where a peer exists. Fix (T85): strip on the live path too, or quarantine instead of drop; the T83 deviation should name the asymmetry.
- **L-110 — A hand `open` refused at boot as already-open (the history `open` it duplicates being quarantined by the signature pass) is adopted by any later live reconcile, judged against replica-local state, with the transactions boot cascaded: two `open`s for one account mesh-wide.** A1 `reopen`: `boot: quarantined=3 Food open? false hand txn served? false → live reconcile: new=3 rejected=1 Food open? true hand txn served? true quarantined=1; peer B (holds the original open) refused 0; B's Food opens: 2`. The M-09 fold is deterministic so replicas agree; the T79 residual "stays refused" is understated. Fix (T85, decision): accept and document, or have the live path refuse an `open` whose account has a quarantined `open`.
- **L-111 — On a node that does not hold the jumping directive (the author removed, or the directive deleted per the remedy), the gap WARN names the first honest author above the gap as the jumper, every boot, forever.** A6 (harness, pinned `#[ignore]`d): `assertion failed: the warning names an honest author as the jumper` (names B; X is the jumper). [:3796-3806](crates/ledger/src/service.rs#L3796) names the author at `top`. Fix (T85): reword ("the author at the top of the gap, which may be the first honest record above a removed one").
- **L-112 — The L-89 strip reads directive-level metadata only: a posting-level `openledger-*` key on an intact signed record is served with the key and written back by every compaction.** A6 `h6_strip` (d); [:3405-3413](crates/ledger/src/service.rs#L3405). Local-only (the economic bean drops posting metadata: `wire body carries openledger-foo? false`, `validate_supply_entry: Ok`). Fix (T85): strip posting-level keys in the same loop.
- **L-113 — `BOOTSTRAP_JOIN_REMEDY` claims un-joinability for every gap ≥ 2^28, but gaps in [2^28, 2^32) are crossed by anti-entropy: one peer record at `clock + 2^28` makes every node and every joiner WARN forever and prescribes a bootstrap join that is not needed.** A6 `h1_gap` and the new harness case (`h19_a_peers_2_28_jump_is_diagnosed_everywhere_yet_a_fresh_node_still_joins_by_anti_entropy` converges in 2 rounds with every node's gap ≥ 2^28). [:1417-1424](crates/ledger/src/service.rs#L1417) vs the ratchet at 2^32. Better than L-94 (no false fire without a jump) but cannot be silenced. Fix (T85): distinguish "diagnosed" (≥ 2^28) from "uncrossable" (≥ 2^32) in the text; raising the threshold would miss 2^32−1 jumps.

---

## 5. New informational

- **CI pins `dtolnay/rust-toolchain@4360b52…`, a commit unreachable from any branch or tag** (the `stable` branch was force-moved to `6bed076…` on 2026-09-03); GitHub keeps unreachable commits best-effort, so a GC fails `actions/checkout` of the action and CI stops (fail-closed). Pre-existing, unchanged since `4a3428f` (D1). Re-pin.
- **Stale code doc:** `FileTrust::OperatorLedger` ([journal.rs:697-706](crates/ledger/src/journal.rs#L697)) still says the first compaction replaces the link and to "symlink the data directory instead" (A5).
- **`enforce_resource_limits_as_stored` always counts a signature key**, so on a signing-off node 97 body keys are refused though the record would store at exactly 100; conservative, and what makes "enable signing later" safe (A3, D1).
- **Mixed-version window quantified on the real `4a3428f` build:** a 65-currency `open` HEAD stages is `WIRE REFUSED (permanent)` there, the transaction on it `ACCOUNT_NOT_OPEN`, and HEAD's every later own write `MISSING_PARENT` for the rest of that build's life; nothing on HEAD says so (A3).
- **The 256-parent cap is record-only at boot** (comment at [:3592-3595](crates/ledger/src/service.rs#L3592)): a pre-T41 file with a 257-head merge is quarantined and its child served (loud via the T79 (d) WARN). Belongs beside the M-51 residuals (A3).
- **A live comment deletion is not merely unseen but undone by the next rewrite**; on an over-cap file deleting every comment live leaves headroom 0 (X3 `k3a`; pre-existing, unsupported live edit).
- **README's shrink remedy has no archive/split procedure**, and README:838 says deleted blocks are re-supplied by peers, so on a mesh the only real shrink is comments and unreplicated hand lines (X3).
- **The summary H-20 WARN always reads "signature does not verify — was this record edited?"** even when every reason was "no openledger-signature" (A2; pre-existing text).
- **The M-54 refusal says "names another node (local)"** for a hand-spelled placeholder author on a signing node; the remedy still works (A1). `sign_adopted_entry`'s foreign-arm comment ([:7836-7845](crates/ledger/src/service.rs#L7836)) is stale since T80 (a signing-off gl-node installs no signer).
- **A `"local"` child closure-quarantined at boot stays `"local"` in the file forever** (re-attribution runs over DAG entries only); an edited descendant of an M-52 record is quarantined under the closure reason and never signature-checked, so the operator sees "descends from", not "was this record edited?" (X1 `c2b`, `c2c`).
- **The live reconcile re-refuses the whole closure on every hand edit** — 10,001 ids in one WARN, 3.5 s per edit (A3); **`signature_quarantined_total` restarts at 0 on a reload** (re-derived by `verify_own_history`; only the boot banner reads it) (A2); **later-refused boot adoptions leave the clock at their provisional stamps** for the process lifetime, not persisted (X1 `c7 i`).
- **A link re-pointed after boot is never followed** (L-44 as documented): the write lands in the old target, the watcher polls the resolved path, no WARN (X3 `k4d`). **The temp named after the link's stem is not swept** (the sweep matches the target's stem) (X3 `k4f`).
- **`probe_local_health` errors on a 64 KiB cut inside a multibyte character** (foreign server only; exit 1, fail-closed) (A6).
- **The `LAMPORT_GAP_WARN < MAX_LAMPORT_ADVANCE` "const assertion" lives inside a unit test** ([:12398](crates/ledger/src/service.rs#L12398)), not at module level (A6).

---

## 6. Dependencies, supply chain, verification runs, and the four invariant test files

**`cargo audit -n`** (online fetch failed; local DB of 2026-09-23, 499 locked crates): **exit 0**; sole output the
allowed RUSTSEC-2024-0436 (`paste`) warning. `.cargo/audit.toml` still ignores exactly RUSTSEC-2026-0235;
`cargo tree -i rkyv -e all --target all` prints nothing. **`Cargo.lock` unchanged since `4a3428f`** (`git diff
4a3428f..HEAD --stat -- Cargo.lock` empty). **CI pins** re-verified with `git ls-remote`: `actions/checkout`
`11d5960…` = v4.4.0 ✔ · `Swatinem/rust-cache` `6323deb…` = v2.9.2 ✔ · `rustsec/audit-check` `69366f3…` = v2.0.0 ✔ ·
`dtolnay/rust-toolchain` `4360b52…` **unreachable from any ref** (§5). Toolchain rustc 1.97.1; `rust-version =
"1.91"`; Dockerfile digests unchanged; `deny_unknown_fields` on all seven config structs; both shipped configs
parse under the binary. **`unsafe`:** 14 lines, one production expression (`libc::geteuid()`,
[journal.rs:1031](crates/ledger/src/journal.rs#L1031)), unchanged. `cargo clippy --workspace --all-targets
--locked -- -D warnings` exit 0 and `cargo fmt --all -- --check` exit 0, before the audit and with the four
extended test files in.

**CHANGELOG vs code:** every bullet tagged T79–T83 (25) executed on the real binary or pinned by a named test;
**true except** the L-80 wording ("refused before staging, with no reload, so the node stays responsive" —
README:994-999, CHANGELOG:135/:181; false on the hand-line shape, M-58) and two understatements (M-55 counts a
signature key on signing-off nodes; L-94 is judged before the pass, L-100). **README:** every procedure executed
worked; the symlinked `.bean` on the binary (lock beside the target, the write lands in the target, the link
survives); T80's author from the key with P2P off, the re-attribution and its fixed point, the `meshId`-mismatch
banner; T79's rebase INFO, the foreign-author and hand-parent refusals boot and live, the edit-plus-drop-a-line
duplicate; T81's 65/4,097/API-65; L-92's two messages; L-89, L-87, L-94 on the binary; the dangling-link text;
`--health-check` against an endless stream. **GraphQL:** `VerifyResult` gains exactly `quarantined: [String!]!`
and `unparsableBlocks: Int!`; introspection is off unless `graphiql: true`; the 38 error codes are identical at
`4a3428f` and HEAD (README names four, pre-existing).

**The four invariant test files** (pure additions plus helpers, no existing test modified or removed; every new
test that pins an existing mechanism was revert-proven in an archive copy; every test that pins a new finding is
`#[ignore = "<pass>-N: …"]` and fails for the stated reason under `--ignored`):

| File | Before | After | New cases (pins) |
|---|---|---|---|
| [crates/p2p/tests/convergence.rs](crates/p2p/tests/convergence.rs) | 21 / 2 ign | **25 / 5 ign** | ancestors-first join converges under a hostile peer's hints; the gap WARN silent across two bootstrap generations; a peer's 2^28 jump diagnosed everywhere yet a fresh node still joins by anti-entropy; an edit of a middle own record neither carries the clock nor re-issues a pair; ignored: L-97 (release re-issues a pair after an adoption), L-107 (hint table filled by one peer), L-111 (gap WARN names an honest author) |
| [crates/p2p/tests/boot_fuzz.rs](crates/p2p/tests/boot_fuzz.rs) | 38 / 0 | **46 / 2 ign** | operators (ad)–(ah) and a `capture_warnings` subscriber; a foreign line with a hand line stamped on top; the foreign half envelope refused, not re-attributed (closes the R4 gap `op_aa` left); two passes rebase to what a clean boot stamps; a hand-spelled placeholder author refused on a signing node; an edited `open` with a hand re-open and transaction held whole; the crash between finalize and compaction with a refused foreign line; the (d) WARN on a HEAD-reachable shape; the A1 operators under proptest; ignored: M-57 (`a1_1_…`), H-23 door 2 (`a1_2_…`) |
| [crates/ledger/tests/exact_balances.rs](crates/ledger/tests/exact_balances.rs) | 25 / 0 | **27 / 4 ign** | the closure leaves an upgraded node with a fresh replica's balances; two records glued into one text block are identified and closured together; ignored: M-56 (`a4_1_…`), H-23 doors 3 and 4 (`a4_2_…` ×2, `a4_3_…`) |
| [crates/p2p/tests/m50_wire.rs](crates/p2p/tests/m50_wire.rs) | 7 / 0 | **10 / 1 ign** | the posting-metadata legacy ceiling exact on the wire and at staging with a real key (4,096 crosses, 4,097 permanent, 101 crosses while authoring refuses); hand input adopted at boot carries the envelope every peer counts (96/97 at exactly 100, cross and stage; 97/98 quarantined); a pasted complete envelope counted as it arrives and an unsigned own one never signed past the cap; ignored: L-101 |

**Test suite:** `cargo test --workspace --locked --no-fail-fast` — **1,319 passed, 0 failed, 2 ignored** before
the audit and ****1,336 passed, 0 failed, 12 ignored** (418 + 8 + 572 + 27 + 10 + 187 + 46 + 25 + 7 + 10 + 5 + 21)** after all passes completed with the four files extended (the 12 ignored are the two
documented H-19 anti-entropy-only joins plus the ten new finding cases). The 33 revert-proofs across the passes
(each in a `git archive` copy, each restored and compared equal afterwards): T79 R1–R8; T80 R1–R3, R6, R7; T81
R1, R2, R4–R8; T82 R1–R6; T83 R1, R4–R7, R9, R10 and the gap predicate; plus the new tests' own reverts.

---

## 7. Consolidated open-findings register

Everything open as of this audit. IDs are stable across the 09/01 … 09/25 reports.

| ID | Sev | One-liner | Origin |
|---|---|---|---|
| **H-23** | High | A served record whose parent exists nowhere is named by no check: the rebase signs over it, the prescribed remedies create it, every later write orphaned mesh-wide, silently | **09/25** |
| H-01 | High→Low | *Partially closed.* Loopback API key deferred | 09/01 |
| M-09 | Med | *Partially closed.* Remote-close admission order-dependent (T45) | 09/01 |
| M-10 | Med | *Interim only.* T45 Facet A | 09/01 |
| **M-56** | Med | Closure's orphaned-account term is name-only and pre-operator-input; a hand `open` un-strands what peers refuse; no wire-path closure | **09/25** |
| **M-57** | Med | Lamport edit + hand line in one edit defeats L-87; past 2^32 every peer refuses the hand line and everything after | **09/25** |
| **M-58** | Med | L-80 fact lost by the reload the L-80 refusal triggers on the hand-line shape; every write reloads on the real binary | **09/25** |
| **M-59** | Med | L-81 keep installs a committed envelope whose parent the rebuild lacks (the staged write it discards) | **09/25** |
| **M-60** | Med | Decision (11)'s uid guard races the follow and covers the first hop only | **09/25** |
| **M-61** | Med | Symlink conversion after an unclean stop strands `<link>.journal` silently | **09/25** |
| **M-62** | Med | L-90's uncharged hold escapes both inbound budgets: 16 MiB per connection, 4 GiB across the global cap | **09/25** |
| L-23 | Low | *Partially closed.* `meshId` still opt-in | 09/02 |
| **L-96 … L-113** | Low | Eighteen new Lows — see §4 | **09/25** |
| L-06 | Latent | `\|`-delimited signature message — injective at HEAD; T45 Facet B | 09/01 |

**Closed this audit (22):** H-22 · M-51, M-52, M-53, M-54, M-55 · L-80 … L-95, plus the M-47, M-50 and L-75
remainders. **Residuals re-rated:** T79 (d) "boot never creates the shape" → H-23; T79 "exactly what boot would
have adopted" → M-57; T82 "carried through `adopt_reloaded`" → M-58; T83 "next stamp stays above it" → L-97;
T83 L-95 "one extra round per lost hint" → L-107; T83 L-90 "within `PHASE_ONE_WEIGHT_BUDGET`" → M-62; T81
"restating it in a larger unit" → H-23; T79 "stays refused" → L-110.

---

## 8. Remediation backlog

Tracked in [docs/OUTSTANDING_TASKS_09_25.md](docs/OUTSTANDING_TASKS_09_25.md). Task numbering continues from
T83. Effort: S = < ½ day, M = ~1–2 days. Every task keeps the campaign's rule: revert the fix → the named test
fails → restore; residuals go in the tracker. The `#[ignore]`d cases in the four invariant files are the
acceptance tests: a task is done when its cases are un-ignored and green.

### Tier 1 — ship-blocker

**☐ T84 — The served-set rule (H-23, M-57, L-97) — S–M, plus decisions**
Change: after the signature pass and the closure, judge every served transaction by what a fresh replica could
hold — parent in the DAG (not "not in the quarantine"), I3/I9 against the surviving `AccountState` — and
quarantine it (or WARN, extending T79 (d), by decision) with its descendants; the rebase excludes heads whose
ancestry does not resolve; re-stamp pending operator-input lamports from the released clock (or stamp them at
finalize); the release counts an edited record's own lamport unless implausible; reword the H-20, M-52, closure
and H-08 remedies; the fuzzer oracle gets a single-node mode. Verify: un-ignore `a1_1_…`, `a1_2_…` (fuzzer),
`a4_2_…` ×2, `a4_3_…` (`exact_balances`), `l87_the_clock_release_…` (harness); X1 `c3j` and `c6a`, A1 `strand`
and `lamport`, A4 `P4`/`P6b`/`P3` converge or refuse loudly.

### Tier 2 — the closure, the recovery reload, the symlinked ledger, the cost bounds

**☐ T85 — The closure judged as a peer would, on both paths (M-56, L-101, L-110) — S, decision**
**☐ T86 — The recovery reload keeps its facts and its parents (M-58, M-59, L-104, L-105) — S–M, decision**
**☐ T87 — The symlinked ledger: an atomic guard, every hop, the journal beside the link (M-60, M-61) — S, decision**
**☐ T88 — Replication cost bounds: the uncharged hold, the doomed subtree, the hint table, the proxies (M-62, L-106, L-107, L-102, L-103) — S–M, decisions**

### Tier 3 — diagnostics and texts

**☐ T89 — The placeholder in every own lookup, the WARNs judged once and after the pass, the texts (L-96, L-98, L-99, L-100, L-108, L-109, L-111, L-112, L-113, §5) — S**

### Finding → task coverage map

H-23→T84 · M-57→T84 · L-97→T84 · M-56→T85 · L-101→T85 · L-110→T85 · M-58→T86 · M-59→T86 · L-104→T86 · L-105→T86 ·
M-60→T87 · M-61→T87 · M-62→T88 · L-106→T88 · L-107→T88 · L-102→T88 · L-103→T88 · L-96→T89 · L-98→T89 · L-99→T89 ·
L-100→T89 · L-108→T89 · L-109→T89 · L-111→T89 · L-112→T89 · L-113→T89. **Deferred by design to T45:** M-09,
M-10, L-06. **Deferred by decision:** H-01, L-23. **Landing order:** T84 → T85 → T86 (all three in
`service.rs`'s boot pipeline and `finish_recovery`; T84 first because T85's per-transaction rule and T86's
kept-envelope check both reuse the served-set predicate T84 introduces) → T87 ∥ T88 (disjoint files) → T89.
The four invariant files are the acceptance tests throughout; extend them before each task, as this audit did.

---

## 9. Checked and found sound (new this audit)

Beyond the closures in §1.1, these were probed adversarially and held:

- **Identity and re-attribution.** Two real keys: B's placeholder history booted by A is not re-attributed
  (the verifier is keyed by `self.author_id`) and is quarantined with the total-failure WARN; booted by B it is
  re-attributed in the signer's pass, the compaction writes B's id, the second boot re-attributes nothing; forging
  is breaking Ed25519. A re-attributed record crosses the wire and verifies under the key on a second node
  (`verify_remote_signature` is the same call); under a changed `meshId` nothing verifies and the WARN names it.
  Two `"local"` histories bootstrap-copied into one node are both quarantined, loudly. A hand-spelled `"local"`
  author is refused on a signing node and adopted unsigned on a signing-off one (nothing is served there). One
  key path, one `EndpointId` Display; the P2P mismatch abort has no config that reaches it. The
  `signature_quarantined_total` is re-derived across a reload.
- **The rebase and the fuzzer.** The fuzzer's pipeline matches `main.rs` at HEAD, author from the key before the
  signer. Rebase order equals boot's adoption order on a Fresh boot, a reload and across the two passes (the
  second pass rebases again to what a clean boot without the refused blocks stamps). Hand-parented survivors are
  kept and re-validated; one naming refused operator input cascades with it; `openledger-parents: ""` is a root;
  a `close`/`note`/`balance` on a refused `open`'s account is kept and peers accept it as data; a foreign line
  consumes one clock value and a later hand line stamped on it is rebased at finalize; the crash between finalize
  and compaction re-derives byte-identical envelopes on every new shape (c1, c2a, c2d, c3j); a failed startup
  compaction's reload re-runs the closure, the strip, the gap check, the re-attribution and the as-written
  refusal and lands on the fresh boot's served set.
- **The ceilings and counts.** `ParseLimits::WIRE` admits 4,096 currencies and stops the 4,097th at line 1; the
  L-89 strip precedes boot's count, so boot counts the map peers see; parents are stamped on transactions only;
  the live reconcile with real keys counts a pasted complete envelope as it arrives (96 → 100 crosses, 97 →
  101 refused) and never signs an own unsigned envelope past the cap (the verifier refuses before
  `sign_adopted_entry`); a 4,097-currency `open` with 10,000 signed dependants boots in 3.6 s (closure ≈ 0.7 s),
  a 20,000-record closure costs +13 s, 300 refused `open`s 95 s (parse-bound); a hand line naming a closured
  parent is refused at boot (kept as written) and live (dropped); deleting the refused `open` under a running
  node is undone by the re-persist; a glued record pair is identified under `IDENTIFY` and both children
  closured; `balance`/`price`/`note`/`document`/`pad` on an orphaned account are inserted unchecked at every
  peer too; closure members' lamports stay folded (no pair re-issue).
- **Recovery, journal, symlink.** The over-cap fact is never set falsely (`compaction_text_len` equals
  `compaction_text`, pinned); a journal record is never smaller than the canonical spelling of the same set
  (434 vs 509 B; 43,169 vs 43,246 B for 100), so a peer cannot drive the canonical form over the cap while the
  file stays under it, and without hand lines the reload re-measures the fact; a replacement's parent refused by
  the rebuild's signature pass lands where a fresh boot of the same file lands; the rebuild re-attributes the
  placeholder copy with a verifier, with a signer only, and agrees on `"local"` with neither; the L-81 clock rule
  is one slot weaker than boot's but no executed shape re-issues a pair; L-85 holds on every asked shape but the
  five-byte one — shrunk lengths (1/5/20, over intact or torn, final) are `Corrupt`, no serialized line can start
  with `;;olj `, and a stale block whose prefix is the record's own payload needs the same set appended twice at
  the same offset, which the G-Set and the rename-on-Compact make unreachable; `main.rs` passes the resolved path
  to the lock, `boot` and the watcher, so the only race is inside `resolve_ledger_path`; relative targets resolve,
  `.journal`, `.torn-*` and the sweep sit beside the target; a link to a target in an unwritable directory fails
  loudly at the first write; a link owned by this uid to another uid's file is worked by decision (11).
- **Replication.** A hint cycle terminates in 35 µs; a hint naming a not-wanted parent leaves the Want unchanged;
  a refused-for-good parent is filtered before the ordering; hints cannot be forged (signed parents line); the
  legacy ceilings in a mixed mesh behave as designed and the refusal is permanent so the parent never loops; the
  densest WIRE directive weighs 807 KB resident (10.5×) and phase 1 flushes after ~20 of them.
- **Diagnostics.** The gap check "from 0" fires only for a history whose first record is ≥ 2^28 (threat (e));
  honest meshes and two bootstrap generations show gaps of 9; the L-87 release on a middle-record edit (body or
  lamport → 4·10^9) keeps pairs unique; the L-89 live path is clean and operator input with a stray key is still
  refused; L-92 gives one verdict on the scalar, the parser and the wire for `10^21+1`, `10^29`, `2^96`,
  `-0.(29 zeros)`, and accepts `-0.(28 zeros)`, `1.(28 zeros)`, `0.(28 ones)`; `--health-check` bounds an endless
  200 stream (exit 0 in 0.10 s) and fails closed on a 500.

---

*Previous audits: [SECURITY_AUDIT_0924.md](SECURITY_AUDIT_0924.md) · [SECURITY_AUDIT_0923.md](SECURITY_AUDIT_0923.md) · [SECURITY_AUDIT_0922-v2.md](SECURITY_AUDIT_0922-v2.md) · [SECURITY_AUDIT_0922.md](SECURITY_AUDIT_0922.md) · [SECURITY_AUDIT_0902.md](SECURITY_AUDIT_0902.md) · [SECURITY_AUDIT_0901.md](SECURITY_AUDIT_0901.md) · [docs/CLAUDE_SECURITY_AUDIT_0820.md](docs/CLAUDE_SECURITY_AUDIT_0820.md). Remediation trackers: [docs/OUTSTANDING_TASKS_09_24.md](docs/OUTSTANDING_TASKS_09_24.md) (T79–T83) · [docs/OUTSTANDING_TASKS_09_23.md](docs/OUTSTANDING_TASKS_09_23.md) (T72–T78) · [docs/OUTSTANDING_TASKS_09_22_v2.md](docs/OUTSTANDING_TASKS_09_22_v2.md) (T61–T71) · [docs/OUTSTANDING_TASKS_09_22.md](docs/OUTSTANDING_TASKS_09_22.md) (T46–T60) · [docs/OUTSTANDING_TASKS_09.md](docs/OUTSTANDING_TASKS_09.md) (T18–T45) · [docs/OUTSTANDING_TASKS.md](docs/OUTSTANDING_TASKS.md) (T1–T17). Proof crates for every finding live in this session's scratchpad (`A1` … `A6`, `X1` … `X3`, `D1`); each pass's report §6 gives the re-run command, and the orchestrator's re-runs and per-pass summaries are under `orch/`.*
