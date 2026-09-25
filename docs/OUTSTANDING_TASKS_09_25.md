# Outstanding Security Tasks — 2026-09-25

Remediation backlog for every open finding in [SECURITY_AUDIT_0925.md](../SECURITY_AUDIT_0925.md), the
re-audit of T79–T83. Task numbering continues from [OUTSTANDING_TASKS_09_24.md](OUTSTANDING_TASKS_09_24.md)
(T79–T83, all ☑). Line references are current as of HEAD `45014e9`.

**Already closed — do not re-do:** the 0925 audit verified **22** register entries closed by mechanism
(H-22 · M-51, M-52, M-53, M-54, M-55 · L-80, L-81, L-82, L-83, L-84, L-85, L-86, L-87, L-88, L-89, L-90, L-91,
L-92, L-93, L-94, L-95, plus the M-47, M-50 and L-75 remainders). See [SECURITY_AUDIT_0925.md §1](../SECURITY_AUDIT_0925.md).
This tracker covers only what is open: one new High, seven new Mediums, eighteen new Lows, the informational
items worth a line of code, and the carried partials (L-23, H-01).

**Status legend:** ☐ not started · ◐ in progress · ☑ done
**Effort:** S = < ½ day, M = ~1–2 days.

> **The shape of this backlog.** The 0922 audit found its Highs inside T18–T44's code, 0922-v2 inside T46–T60's,
> 0923 inside the *decisions* T63 and T64 recorded, 0924 in the **order** the T72–T78 fixes ran, and 0925 in
> **what each of T79–T83 tests for**: the T79 served-child WARN asks "is the parent in my quarantine", the T81
> closure asks "did this boot refuse it", the T80 re-attribution asks "is it in the DAG", the L-87 release asks
> "was it edited", the L-80 fact asks "did boot measure", decision (11) asks "who owns the first hop" — where
> the property each approximates is **what a fresh replica would hold**, and **whether a reload, a second boot or
> the operator's remedy re-derives the same answer**. T84 is therefore organised around stating that property
> once at boot, T85 around making the closure ask it the way a peer does, T86 around making the recovery reload
> re-derive every fact and check every parent, and T87–T89 around the guards and diagnostics that ask it
> partially. Every task keeps the campaign's rule: revert the fix → the named test fails → restore; residuals go
> in this file, not in code comments.

> **Acceptance tests already exist.** The audit extended the four invariant files —
> [crates/p2p/tests/convergence.rs](../crates/p2p/tests/convergence.rs) (25 passed / 5 ignored),
> [crates/p2p/tests/boot_fuzz.rs](../crates/p2p/tests/boot_fuzz.rs) (46 / 2),
> [crates/ledger/tests/exact_balances.rs](../crates/ledger/tests/exact_balances.rs) (27 / 4),
> [crates/p2p/tests/m50_wire.rs](../crates/p2p/tests/m50_wire.rs) (10 / 1) — and pinned every new finding that
> has a pinnable shape as an `#[ignore = "<pass>-N: …"]` case that fails at HEAD for the stated reason under
> `--ignored`. **A task is done when its cases are un-ignored and green, with no other test in the file
> changed.** The two pre-existing ignored cases (`h19_fresh_node_converges_after_a_maximal_legal_jump…`,
> `h19_pre_t63_history_with_one_large_jump_is_joinable`) stay ignored by decision (1) of 2026-09-23.

> **Decisions taken 2026-09-25** (user), numbered on from (14) of 2026-09-24, recorded once here and referenced
> from the tasks. **(15)** T84 / H-23: a served transaction whose parent exists nowhere, or that fails I3/I9
> against the surviving `AccountState`, is **quarantined with its descendants and named in a WARN** — the rule T81
> chose, now the one rule for both (T79 (d)'s warn-only arm goes). **(16)** T84 / M-57: operator-input lamports
> are **stamped in `finalize_operator_input`**, after every pass has settled the clock. **(17)** T84 / L-97: the
> release counts an edited record's own lamport unless it lies **≥ 2^28 (`LAMPORT_GAP_WARN`)** above the
> survivors; a re-issued pair stays rated **Low** (L-67's rating). **(18)** T85 / M-56: the closure judges each
> transaction **with the peer's own predicate** (`check_account_open` + `check_currency_constraint_at`) against
> the surviving state **after operator input is adopted** — a back-dated hand `open` that admits it frees it, a
> late one does not; and `refused_history_closure` is applied **on the wire path too**. **(19)** T85 / L-101: the
> 1 MiB body cap **seeds the closure** at boot (T51's load-and-serve for this cap goes). **(20)** T85 / L-110: the
> live path **refuses** an `open` whose account has a quarantined `open`. **(21)** T86 / M-58: **both** — a
> `ResourceLimitExceeded` from `prepare_compaction` skips the L-13 reload in `commit_inline` and gl-node's
> `prepare_or_recover`, and every reload install re-measures the fact; M-58 stays **Medium**. **(22)** T86 /
> M-59: a kept envelope whose parent the rebuild lacks **refuses the install** (`REFUSING`, memory kept).
> **(23)** T86 / L-104: the floor's exemption is keyed on **"finalised"** (author and lamport stamped), not on the
> signature. **(24)** T87 / M-60: a link is followed only when **its directory is owned by this uid and is not
> group- or world-writable**; **link chains are refused**; a directory link in the path is followed by documented
> policy. **(25)** T87 / M-61: a journal beside the link **refuses boot** (H-15's precedent). **(26)** T88 / M-62:
> the uncharged residue is **capped at 1 MiB per connection**, then flushed. **(27)** T88 / L-106: **per-peer
> suppression** of orphans whose only missing parent that peer had refused for a content reason. **(28)** T88 /
> L-107: a **per-peer hint budget**. **(29)** T88 / L-102: **recalibrate** the honest-frame budget to ≈15× with
> the densest admitted shape in the control; decision (6)'s 4,096 ceiling stays. **(30)** T88 / L-103: cap
> `VerifyResult.quarantined` at **1,000** and add **`quarantinedTotal: Int!`**. **(31)** T89 / L-96:
> `PLACEHOLDER_AUTHOR` **counts as this node in every own lookup** once `set_author_id` has run. **(32)** T89 /
> L-99: when every checked signature failed, **skip the release and WARN** not to author until the domain or key
> is fixed (the node still accepts writes). **(33)** T89 / L-113, L-111: keep the 2^28 threshold and
> **distinguish "diagnosed" (below 2^32) from "needs a bootstrap join" (2^32 or more)**; name the author as the
> one at the top of the gap, possibly the first honest record above a removed one. **(34)** T89 / L-109, L-112:
> **strip everywhere** — on the live path as at boot, and at posting level. **(35)** Execution — **one task per
> go-ahead**, as decision (14): full gate and revert-proofs, stop for the commit, ask before the next; T84 first.

## Priority order at a glance

| # | Findings addressed | Sev | Effort | Status |
|---|---|---|---|---|
| T84 | H-23 + M-57 + L-97 — the served-set rule; the rebase and the release under it | **High** | S–M | ☑ |
| T85 | M-56 + L-101 + L-110 — the closure judged as a peer would, on both paths | Med | S | ☐ |
| T86 | M-58 + M-59 + L-104 + L-105 — the recovery reload keeps its facts and checks its parents | Med | S–M | ☐ |
| T87 | M-60 + M-61 — the symlinked ledger: an atomic guard, every hop, the journal beside the link | Med | S | ☐ |
| T88 | M-62 + L-106 + L-107 + L-102 + L-103 — replication cost bounds | Med | S–M | ☐ |
| T89 | L-96 + L-98 + L-99 + L-100 + L-108 + L-109 + L-111 + L-112 + L-113 + §5 — the placeholder in every own lookup, WARNs judged once and after the pass, texts | Low | S | ☐ |

**Coverage check — every open register entry maps to exactly one task:**

H-23→T84 · M-57→T84 · L-97→T84 · M-56→T85 · L-101→T85 · L-110→T85 · M-58→T86 · M-59→T86 · L-104→T86 ·
L-105→T86 · M-60→T87 · M-61→T87 · M-62→T88 · L-106→T88 · L-107→T88 · L-102→T88 · L-103→T88 · L-96→T89 ·
L-98→T89 · L-99→T89 · L-100→T89 · L-108→T89 · L-109→T89 · L-111→T89 · L-112→T89 · L-113→T89.

**Deferred by design to T45 (Format v2), unchanged:** M-09, M-10, L-06. **Deferred by decision, unchanged:**
H-01's loopback API key; L-23 (`meshId` required next release).

**T45 interaction:** waves A and B wait for **T84** as they waited for T79 and T80 — it changes what boot serves
and what a hand line is signed over.

**Landing order:** T84 → T85 → T86 (all three in `service.rs`'s boot pipeline and `finish_recovery`; T84 first,
because T85's per-transaction rule and T86's kept-envelope check both reuse the served-set predicate T84
introduces) → T87 ∥ T88 (disjoint: T87 owns `journal.rs`'s resolution and `boot_with`'s path arm; T88 owns
`anti_entropy_alpn.rs`, `orphan_buffer.rs`, `decode_memory.rs` and the GraphQL query) → T89. `service.rs` is the
contention point again: T84, T85, T86, T89 go to one agent in that order or run sequentially. **Extend the four
invariant files before each task, as the audit did**, and run the whole workspace at the end of every wave: the
gate at HEAD with the extended files is ****1,336 passed, 0 failed, 12 ignored** (418 + 8 + 572 + 27 + 10 + 187 + 46 + 25 + 7 + 10 + 5 + 21)**.

---

## Tier 1 — ship-blocker (the new High)

### ☑ T84 — The served-set rule: a served record's parent must exist, the rebase must not build on one that does not, and operator input is stamped after the release (H-23, M-57, L-97) — S–M, decisions (15), (16), (17) taken
> **Done 2026-09-25 (working tree, not committed).** All in `crates/ledger/src/service.rs`, plus README §Editing and §Upgrading, the CHANGELOG, gl-node's quarantine banner text, and the four invariant files. **(a) H-23, decision (15):** new `unservable_history(exempt)` asks the peer's two questions of every served transaction — every parent in the DAG (not merely "not in the quarantine"), and `validate_transaction` against the surviving `AccountState` (the exact call `stage_remote_directive` makes: I1, I2, I3, I9) — and adds every descendant (`children_of`); `quarantine_unservable_history` quarantines the result through `quarantine_out_of_dag` (kept in the file as loaded, H-08) with one WARN per record naming its reason ("its parent X is not served, which exists nowhere on this node / which is only in this node's quarantine", or the peer's validation error, or "it descends from X") and one summary WARN with the remedies. It runs **at boot after operator-input adoption** (a very old build's envelope-less `open`s are operator input and part of the accounts a peer judges against; the first placement, before adoption, quarantined every transaction of the golden fixture), **after the signature pass's quarantine and release**, and **after finalize's M-54 refusal**; operator input still pending is exempt (the rebuild rebases it). The T79 (d) warn-only function (`warn_about_served_children_of_quarantined_records`) is gone. **(b)** falls out of (a): a stranded head is quarantined before any hand line is stamped at boot, and again before the rebase in the pass, so no hand line is ever signed over one (X1 `c3j` at HEAD: J held, H signed over T1, a peer stages 5 of 5, fixed point). **(c) M-57, decision (16):** operator input adopted at boot gets a provisional lamport that no longer moves the clock (`provisional_stamp` in `adopt_file_directive`, boot path only; the live path is unchanged); `finalize_operator_input` stamps the real lamport in adoption order from the settled clock (a stamp past the ceiling quarantines the entry as written); `set_author_id` no longer re-stamps pending lines, it only raises the clock (L-67 holds through the finalize stamp). **(d) L-97, decision (17):** `release_clock_carried_by_edited_records` leaves pending operator input out of its floor and counts each edited record's own lamport unless it lies ≥ `LAMPORT_GAP_WARN` (2^28) above what remains; the INFO now says "a value no honest mesh reaches". **(e)** Reworded, existing log tags kept verbatim: the H-20 per-record WARN (restore from a peer or backup; strip the `openledger-*` lines of an envelope-only edit; deleting the block leaves its descendants held), the M-52 WARN and the closure WARN (restating/repairing gives a new id, the descendants stay held: repair the chain or join by bootstrap), gl-node's quarantine banner. README §Editing: the remedy paragraph, a new "What no peer could hold is not served" paragraph, the lamport sentence in "fixing and appending in one edit"; §Upgrading: the restate remedy. CHANGELOG: two *Ledger files* bullets amended, one new, the L-87 bullet amended, one *Security* bullet. **(f)** the new WARN names the vanished parent and whether it is quarantined or absent; there is no warn-only arm left. **(g)** `boot_fuzz.rs`: new oracle check 6 (`served_set_self_contained`, in `Checks::ALL`) — nothing served names a parent the node does not serve — so every operator and both proptest sweeps now judge the single-node property. **Acceptance:** un-ignored and green: `a1_1_…`, `a1_2_…` (fuzzer), `a4_2_…` ×2, `a4_3_…` (`exact_balances`), `l87_the_clock_release_does_not_reissue_a_pair…` (harness) — and `a4_1_…`, T85's case, which T84's rule also closes (it judges each transaction with the peer's own check after operator input, decision (18)'s rule). **New tests (1 + an oracle check):** `h23_a_hand_line_is_never_signed_over_a_served_record_whose_parent_vanished` (X1 `c3j` as a unit test); fuzzer check 6 and helper `assert_refused_with_descendants`. **Existing tests changed, by decision (15)/(16):** ledger — `test_boot_from_golden_fixture` (the fixture's "Pending refund" names the §3.3.3 worked-example id, a record the fixture does not hold: 15 served + 1 held), `l40_a_dangling_parent…` (the planted entry is held at boot instead of served as a head; the append and the acyclic reboot are asserted as before), `parent_fan_in_cap…` (the at-cap control now asserts "not refused for fan-in"; its fabricated parents make it an H-23 hold), `test_adversarial_parent_chain…` (the chain fixture gains its two `open`s; counts +2), `test_a_cycle_check_exhaustion…` (the refused directive's descendants are held with it; every record still on disk), the T79 (d) unit test renamed `h22_a_served_record_naming_a_quarantined_parent_is_quarantined_and_named`, and the L-67 doc comment; fuzzer — `op_m`, `op_q`, `op_r`, `op_s`, `op_u`, `op_ab`, the composite crash, the two-pass rebase and the edited-open cases (exact quarantine counts → "the refused records plus node-written transactions that depend on them"), `a1_d_…` (the child is held and named, not served), `a1_2_…` (its "still served" premise inverted, the parent picked by id); harness — `edited_own_record_scenario`'s "exactly one quarantined" relaxed to "at least the edited record". **Revert-proven (7, scratch copy of the working tree, each restored and compared equal):** R1 no boot-time rule → the four `a4_` cases, `a1_2`, `test_boot_from_golden_fixture`, `l40_*` fail; R2 no pass-time rule → `a1_d` and `h22_…_quarantined_and_named` fail; R1+R2 → `h23_*` fails (either site alone catches it); R3 no finalize stamp → `a1_1` and `l67_operator_input_gets_the_same_lamport…` fail; R4 edited lamports never counted → `l87_the_clock_release…` fails; R5 the release counts pending operator input → `a1_1` fails; R6 boot adoption moves the clock again → `l67_operator_input_gets_the_same_lamport…` fails. **Audit probes, re-run against this code:** X1 `c3j` above; X1 `c6a`/`c6b` `RE-ISSUED = false` (next stamp 8, T2's pair 6); X1 `c1`, `c2a`–`c2c`, `c3`, `c4`, `c7 i–iii`, `c8` fixed points as before (the one-slot clock difference across a reboot is identical on `45014e9`); A1 `strand` — every boot serves only what a fresh peer adopts (5 of 5), the strip-the-envelope remedy restores 8 of 8; A1 `lamport` — the hand line stamped at 8, not 5,000,000,002, B accepts everything; A4 `P1`–`P7` — upgraded equals fresh on every shape (`P5-late` held, `P5-early` served). **Cost:** one `validate_transaction` pass per boot (twice when the signature pass quarantines): 150,000 transactions boot in 3.44 s vs 3.17 s on `45014e9` (release, best of 3). **Gate:** clippy `-D warnings` and `fmt --check` clean; `cargo test --workspace --locked --no-fail-fast` **1,344 passed, 0 failed, 5 ignored** (gl-node 418, integration 8, ledger 573, exact_balances 31, property 10, p2p 187, boot_fuzz 48, convergence 26/4, decode_memory 7, m50_wire 10/1, property 5, security 21); the 5 ignored are decision (1)'s two joins and the T85/T88/T89 cases A3-1, A6-2, A6-3. **Behaviour changes:** a node no longer serves a transaction whose parent it does not serve, or that the accounts it serves do not admit — it is quarantined with its descendants, named, kept in the file, and returns by itself once a peer re-supplies the parent (a deleted, restated, edited or text-held record's descendants, a history transaction on an account whose `open` is gone or dated after it, a planted dangling pointer); operator input is stamped at finalisation, so an edited lamport beside a hand line no longer lifts it; a narration fix no longer lets the next write re-issue the edited record's lamport; as a side effect the L-99 walk to 0 on a domain mismatch is gone (every failed signature's lamport is plausible and counted — T89 still owns the WARN). **Residuals:** M-56's same-boot half stays T85's — a hand `open` adopted at boot frees a closure-held transaction only at the next boot (X1 `c2d`, not a fixed point across the first restart), and the wire path does not check `refused_history_closure`; a `balance`/`price`/`note`/`document`/`pad` on an account no served `open` opens stays served (peers insert them unchecked too); a same-date child placed before its hand parent is refused at boot 1 and adopted at boot 2 (L-108, T89); a library caller that appends before `finalize_operator_input` gets a child whose lamport is below its pending parent's final stamp (gl-node and `prepare` always finalise first); the new rule costs one validation pass per boot.
- **Why:** **H-23.** T79 (d)'s WARN ([service.rs:4377-4410](../crates/ledger/src/service.rs#L4377)) asks
  `self.quarantined.contains_key(parent)`; T81's closure is seeded only by what *this* boot refused
  (`content_rule_refused` [:3608](../crates/ledger/src/service.rs#L3608), `amount_cap_refused` [:3375](../crates/ledger/src/service.rs#L3375));
  everything else inserts leniently ([:3692](../crates/ledger/src/service.rs#L3692)) with no lifecycle check
  ([:3494](../crates/ledger/src/service.rs#L3494)). A parent in neither the DAG nor the quarantine is named by
  none of them: (1) an edited own record's *signed child* (a journaled append before a crash) keeps a verifying
  envelope naming the old id, is a rebuilt head, and the rebase ([:5011](../crates/ledger/src/service.rs#L5011))
  signs the hand line over it — silent, a fixed point, peers refuse both (X1 `c3j`); (2) the H-20 remedy "delete
  the edited block" removes the quarantined parent, the WARN stops, the child and every later write stay
  unadoptable on a node no peer has a copy for (A1 `strand`); (3) the M-52 "restate the amount" / closure
  "repair the refused record" / H-08 "repair them" remedies leave every descendant served with no seed,
  `verify.ok=true` for the deleted-`open` case (A4 `P4`, `P6b`); (4) a block held as text for any reason but the
  amount cap has no id, so `IDENTIFY` seeds nothing and its children are served with a dangling parent under
  L-45's own precondition (A4 `P3`, `P7b`, `P7c`). The signature covers `openledger-parents`
  ([signing.rs:38](../crates/security/src/signing.rs#L38)), so descendants cannot be re-parented by hand; the
  working recovery (strip the vanished record's envelope lines so it is re-adopted under the same id) is named
  nowhere. **M-57.** Boot stamps a hand line at `clock + 1` where the clock includes an edited lamport
  ([:7466](../crates/ledger/src/service.rs#L7466), [:7639](../crates/ledger/src/service.rs#L7639)); the rebase
  re-chooses parents only; `release_clock_carried_by_edited_records` ([:4557-4595](../crates/ledger/src/service.rs#L4557))
  takes its floor from the DAG, which holds the hand line at edit+2, so nothing is released and finalize signs it
  there ([:4274-4281](../crates/ledger/src/service.rs#L4274)); past 2^32 every peer defers it forever
  (`LamportAdvance` is retried, [anti_entropy_alpn.rs:2427](../crates/gl-node/src/anti_entropy_alpn.rs#L2427)).
  **L-97.** The release resumes at `highest_remaining + 1` ([:4577](../crates/ledger/src/service.rs#L4577)) and
  excludes the edited record ([:4570](../crates/ledger/src/service.rs#L4570)); an own record that sat two above
  the highest survivor (the first stamp after a restart — boot's `+1`; any record after an adoption — the clock
  is set to `max(local, remote) + 1`, [:8513](../crates/ledger/src/service.rs#L8513)) has its issued pair
  re-issued by `next_stamp` ([:5508](../crates/ledger/src/service.rs#L5508)); the INFO says "an edited lamport
  line" for a body edit.
- **Change:** (a) decision (15): after `quarantine_out_of_dag` and the release, one pass over the DAG that
  judges every served transaction by what a fresh replica could hold — every parent in the DAG (not merely
  absent from the quarantine), `check_account_open`/`check_currency_constraint_at` against the surviving
  `AccountState` — and quarantines (or WARNs about) it with its descendants, naming the vanished parent; run
  it on the reload path too; (b) the rebase's candidate heads exclude any head whose ancestry does not resolve
  (transitively) in the DAG being rebuilt; (c) decision (16): re-stamp still-pending operator-input lamports in
  insertion order from the released clock (as `set_author_id` does for L-67) and re-index, or stamp
  operator-input lamports in `finalize_operator_input`; (d) decision (17): the release counts the edited record's
  own lamport unless it is implausible (≥ the chosen bound above the rest); the INFO distinguishes a body edit
  from a lamport edit; (e) reword the remedies: the H-20 per-record WARN ("… or strip the `openledger-*` lines
  from the edited block to re-adopt it under the same id, if no peer holds the original"), the M-52 WARN
  ([:3363-3372](../crates/ledger/src/service.rs#L3363)), the closure WARN ([:4962](../crates/ledger/src/service.rs#L4962)),
  the H-08 banner ([:3840-3858](../crates/ledger/src/service.rs#L3840)) and README §Editing / §Upgrading:
  descendants go with the record; restate the chain or rebuild by bootstrap; (f) the (d) WARN's "no peer can
  adopt them" only when the parent is unresolvable, not when it is replicated; (g) the boot fuzzer's oracle
  gets a single-node mode (`known_ids = served`), so this class is visible to it.
- **Files:** [service.rs:3363-3375, 3494, 3608, 3692, 3840-3858, 4377-4410, 4557-4595, 4771-4870, 4988-5024, 5508, 6441-6442, 7466, 7639](../crates/ledger/src/service.rs#L4377),
  [boot_fuzz.rs:684-689](../crates/p2p/tests/boot_fuzz.rs#L684), README §Editing, §Upgrading, CHANGELOG.
- **Verify:** un-ignore and pass `a1_1_a_hand_line_stamped_over_an_edited_lamport_is_accepted_by_a_peer`,
  `a1_2_the_prescribed_remedy_leaves_a_stranded_child_and_no_warning` (boot fuzzer),
  `a4_2_restating_a_past_cap_amount_must_not_leave_its_descendants_served_with_a_dangling_parent`,
  `a4_2_deleting_a_refused_open_must_not_leave_the_transactions_on_its_account_served`,
  `a4_3_a_text_held_block_without_an_id_must_not_leave_its_descendants_served` (`exact_balances.rs`),
  `l87_the_clock_release_does_not_reissue_a_pair_a_peer_holds_after_a_body_edit` (harness); X1 `c3j`
  (`…/scratchpad/X1/target/release/x1 c3j`) refuses or re-parents H and names J's vanished parent; X1 `c6a`
  stamps 7, not 6; A1 `strand` boot 2 names the remedy; the controls (`h22_*`, `op_x/y/z`, `a1_d_*`,
  `m51_*`/`m52_*`, `over_cap_history…`) still pass; the 0923 §9 fixed point still holds. Bug-catch proof for
  (a), (b), (c) and (d) separately.

---

## Tier 2 — the closure, the recovery reload, the symlinked ledger, the cost bounds

### ☐ T85 — The closure judged as a peer would, on both paths (M-56, L-101, L-110) — S, decisions (18), (19), (20) taken
- **Why:** **M-56.** `quarantine_descendants_of_refused_history` runs at [:3928](../crates/ledger/src/service.rs#L3928)
  before `adopt_operator_input_at_boot` ([:3932](../crates/ledger/src/service.rs#L3932)); its account term
  ([:4908-4919](../crates/ledger/src/service.rs#L4908)) drops an account when *any* `Open` for it survives — no
  date, no currency — where every peer judges with `check_account_open(account, date)`
  ([accounts.rs:275-292](../crates/ledger/src/accounts.rs#L275)) and `check_currency_constraint_at`
  ([validate.rs:397-401](../crates/ledger/src/validate.rs#L397)). A hand `open` of the account (the natural M-51
  remedy) is adopted (L-77 sees the account closed), signed and written; the next boot serves the transactions
  every peer refuses (`ACCOUNT_NOT_OPEN`, permanent), silently, with `verify.ok=true`; boot → compaction → boot
  is not a fixed point; `stage_remote_directive` ([:8316](../crates/ledger/src/service.rs#L8316)) has no
  `refused_history_closure` check where `adopt_file_directive` ([:7386](../crates/ledger/src/service.rs#L7386))
  has, so a running peer accepts what its own file path refuses. **L-101.** Boot's history arm never calls
  `enforce_economic_bean_limit` ([:1096-1115](../crates/ledger/src/service.rs#L1096), T51's decision), so a
  record over the wire's 1 MiB body cap ([union_merge.rs:210-216](../crates/p2p/src/union_merge.rs#L210)) inside
  every other count loads, is served with its descendants, is refused for good by every peer and strands the
  descendants — M-51's shape. **L-110.** A hand `open` refused at boot as already-open (its history twin being
  quarantined by the signature pass) is adopted by any later live reconcile against replica-local state with the
  transactions boot cascaded: two `open`s for one account mesh-wide.
- **Change:** (a) decision (18): decide "orphaned" per transaction with the peer's predicate against the
  surviving DAG's `AccountState`, after operator input is adopted (or refuse a hand `open` of a closure-orphaned
  account); a release diagnostic at boot when a closure member leaves the quarantine; (b) apply
  `refused_history_closure` in `stage_remote_directive` as on the file path; (c) decision (19): the body cap as a
  third seed of `content_rule_refused` (same WARN, same closure; T51 comment updated), or the T84 WARN naming it
  served-but-unreplicable; (d) decision (20): the live path refuses an `open` whose account has a quarantined
  `open`, or document the outcome.
- **Files:** [service.rs:1096-1115, 3597-3617, 3928-3932, 4902-4967, 7386-7411, 7688, 8316](../crates/ledger/src/service.rs#L4902), README §Upgrading, CHANGELOG.
- **Verify:** un-ignore and pass `a4_1_a_surviving_open_that_does_not_admit_the_transaction_must_not_unstrand_it`
  (`exact_balances.rs`) and `history_over_the_wire_body_cap_is_never_served_or_always_crosses` (`m50_wire.rs`);
  X1 `c2d` fixed point holds and `c8b`'s live stage refuses; A4 `P5-late` fresh holds 5 of 5 or the upgraded
  node serves 3; A1 `reopen` per decision (20). Bug-catch proof for (a), (b), (c) separately.

### ☐ T86 — The recovery reload keeps its facts and checks its parents (M-58, M-59, L-104, L-105) — S–M, decisions (21), (22), (23) taken
- **Why:** **M-58.** `boot_with` measures `canonical_over_cap` only with no operator input pending
  ([:3939-3944](../crates/ledger/src/service.rs#L3939)); the startup compaction hits `prepare`'s L-80 refusal
  ([:5861-5871](../crates/ledger/src/service.rs#L5861)), which `commit_inline` ([:6884-6905](../crates/ledger/src/service.rs#L6884))
  and gl-node's `prepare_or_recover_with_reload` ([ledger_commit.rs:462-478](../crates/gl-node/src/ledger_commit.rs#L462))
  answer with the L-13 reload; the rebuild reads the never-rewritten hand lines raw (pending → no measure),
  `keep_committed_envelopes_in` ([:6422](../crates/ledger/src/service.rs#L6422)) empties the sets so
  `finalize_operator_input` returns at [:4201](../crates/ledger/src/service.rs#L4201) before its measure at
  [:4299](../crates/ledger/src/service.rs#L4299), and `adopt_reloaded` ([:6636-6663](../crates/ledger/src/service.rs#L6636))
  does not carry the flag. Every write then stages, builds the text, fails in `persist_atomically` (`Io`, so the
  M-39 backoff never arms) and reloads (~80 s under the permit on the real binary, the client timing out);
  both `l80_*` tests use comment-only fixtures and never compact first. Found by four passes. **M-59.**
  `keep_committed_envelopes_in` ([:6507-6538](../crates/ledger/src/service.rs#L6507)) replaces the rebuild's
  operator-input copy with memory's envelope without checking its parents exist in `reloaded.dag`;
  `rebuild_dag` inserts leniently ([:4826](../crates/ledger/src/service.rs#L4826)); the parent — the local write
  staged in the same failed commit, adopted as the hand line's parent by the pre-persist reconcile
  ([:5842-5856](../crates/ledger/src/service.rs#L5842), [:7597-7600](../crates/ledger/src/service.rs#L7597)) — is
  floor-exempt and discarded; the hand line is served, written and reloaded naming a record that exists nowhere
  (mitigated by accident when the caller retries the identical body). Signing-off floor (a) variant the same.
  **L-104.** `committed_ids_missing_from` keys the exemption on a signature ([:6483-6486](../crates/ledger/src/service.rs#L6483));
  a signing-off node never signs, so its served hand lines are droppable forever by a restored backup plus one
  failed commit; `keep_committed_envelopes_in` disagrees on "committed". **L-105.** `has_later_intact_record`
  needs a complete `;;olj ` ([journal.rs:496-506](../crates/ledger/src/journal.rs#L496)) before the prefix hash
  ([:512](../crates/ledger/src/journal.rs#L512)): a later append torn inside its first five header bytes still
  drops the acknowledged record as torn.
- **Change:** (a) decision (21): treat `ResourceLimitExceeded` from `prepare_compaction` like `Parse` in
  `commit_inline` and `prepare_or_recover` (no reload), and/or measure unconditionally at the end of
  `finish_recovery`'s install arm; extend the gl-node `l80_*` test to call `ledger_commit::compact` before the
  mutations (fails at HEAD); (b) decision (22): replace only when every parent of memory's envelope is in
  `reloaded.dag` or `replacements`; else refuse the install or keep the rebuild's copy; log the parent ids;
  exclude from the floor's exemption any id a kept record names as a parent; (c) decision (23): exempt only
  while `is_operator_input(memory's copy)`; (d) with no candidate header, hash `region` minus any trailing
  proper prefix of `;;olj ` against `own_hash`; (e) README:994-999 and CHANGELOG:135/:181 say what holds.
- **Files:** [service.rs:3939-3944, 4201-4299, 5861-5871, 6344-6442, 6477-6538, 6636-6663, 6884-6905](../crates/ledger/src/service.rs#L6344),
  [ledger_commit.rs:462-478, 1468-1470](../crates/gl-node/src/ledger_commit.rs#L462), [journal.rs:496-530](../crates/ledger/src/journal.rs#L496), README, CHANGELOG.
- **Verify:** X3 `k3y`/`k3x`/`k3r` (`…/scratchpad/X3/target/release/x3 k3y`) — headroom stays 0 after the
  startup compaction and zero reloads; D1 `case_l80.py` on the real binary — `refused before staging` on every
  mutation, `reload installed` 0; A5 `a5_p2` and X3 `k1a` — `REFUSING` or a hand line with resolvable parents;
  A5 `a5_p3` — `REFUSING`; A5 `a5_p4` — `Corrupt` at 3 and 5 header bytes. New unit tests for each with
  bug-catch proofs; `l80_*`, `l81_*`, `l93_*`, `l85_*`, `m46_*`, `m49_*`, `t78_*` unchanged.

### ☐ T87 — The symlinked ledger: an atomic guard, every hop, the journal beside the link (M-60, M-61) — S, decisions (24), (25) taken
- **Why:** **M-60.** `resolve_ledger_path` ([journal.rs:164-190](../crates/ledger/src/journal.rs#L164)) reads
  the first hop's owner with `symlink_metadata` ([:165](../crates/ledger/src/journal.rs#L165)) and then
  `canonicalize`s ([:189](../crates/ledger/src/journal.rs#L189)) — two walks; whoever can write the directory
  renames their own link over the operator's between them (113 hits in 3 s under load, 5,193 on a quiet machine),
  and every further hop (link chains, directory links) is followed with no owner check, contrary to the code doc
  and README:1019-1024. The next compaction then rewrites any node-uid-owned file. gl-node passes the resolved
  path to the lock, `boot` and the watcher, so this function is the only window. **M-61.** `boot_with` derives
  the journal from the resolved path ([service.rs:3160](../crates/ledger/src/service.rs#L3160)) and never looks
  beside the link; converting to a symlink after an unclean stop leaves `<link>.journal`'s acknowledged records
  unread, unfolded and unrenamed, with no line said and H-15 silent (the `.bean` is present through the link).
- **Change:** (a) decision (24): follow a link only when its parent directory is owned by this uid and not
  group/world-writable (race-free by construction), or resolve through an `O_PATH|O_NOFOLLOW` fd; check every hop
  or refuse chains; document directory links; (b) decision (25): when `file_path != configured`, refuse boot on
  `symlink_metadata(journal_path_for(&configured))` (H-15 style text: move it beside the target, or start on
  the old path to fold it), or WARN; the sweep matches both stems; (c) README §The commit journal: move
  `<name>.journal` with the file, or stop cleanly first; fix `FileTrust::OperatorLedger`'s doc
  ([journal.rs:697-706](../crates/ledger/src/journal.rs#L697)).
- **Files:** [journal.rs:164-201, 697-706](../crates/ledger/src/journal.rs#L164), [service.rs:3153-3190, 207-236](../crates/ledger/src/service.rs#L3153), [main.rs:216-232](../crates/gl-node/src/main.rs#L216), README.
- **Verify:** X3 `k4a` — zero hits (or the function refuses under the swap); X3 `k4b`/A5 `P5` — chains and
  directory links per decision (24); X3 `k4f` — boot refuses or warns and the acked record is served after the
  move; `l84_*` unchanged; unit tests for the hop rule and the journal-beside-the-link arm.

### ☐ T88 — Replication cost bounds: the uncharged hold, the doomed subtree, the hint table, the proxies (M-62, L-106, L-107, L-102, L-103) — S–M, decisions (26)–(30) taken
- **Why:** **M-62.** Phase 1 flushes on `PHASE_ONE_WEIGHT_BUDGET` alone ([anti_entropy_alpn.rs:1894](../crates/gl-node/src/anti_entropy_alpn.rs#L1894))
  and the byte charge is best-effort ([:1918](../crates/gl-node/src/anti_entropy_alpn.rs#L1918)); nothing bounds
  the uncharged sum across connections or peers ([connection_limiter.rs:161-166](../crates/gl-node/src/connection_limiter.rs#L161)):
  16 MiB per connection uncharged, ~460–512 MiB per peer over its 32 connections, 4 GiB across the 256-connection
  cap (three 16.6 MB chunks `charged_beyond_base=0` from one 4.36 MB frame, executed); before T83 the residue
  was one directive. **L-106.** `fetch_want_chunk` re-Wants by membership ([:1459](../crates/gl-node/src/anti_entropy_alpn.rs#L1459)),
  phase 1 parses and verifies before `missing_parents` ([:2064](../crates/gl-node/src/anti_entropy_alpn.rs#L2064)),
  `stage_refusal_is_permanent` ([:2404](../crates/gl-node/src/anti_entropy_alpn.rs#L2404)) excludes `Dag(_)`
  and buffered children never reach the cache: a peer serving the descendants of a refused record costs the
  victim `min(subtree, 1,000)` Ed25519 verifications per tick forever (50 per tick, executed). **L-107.**
  `parent_hints` is process-wide ([orphan_buffer.rs:271, 306-330](../crates/p2p/src/orphan_buffer.rs#L271)) and
  swept lazily only; one peer fills it with ~33k signed orphans and an honest 1,300-chain joins in 25 ticks
  instead of 3. **L-102.** `HONEST_FRAME_PEAK_MULTIPLE = 8` ([decode_memory.rs:824](../crates/p2p/tests/decode_memory.rs#L824))
  is a proxy for one shape; the densest admitted frame parses at 14.4× and T81 tripled its absolute size
  (203 MB per 14 MB frame); the "≤ 0.08×" comment is stale. **L-103.** `VerifyResult.quarantined`
  ([query.rs:293-299](../crates/gl-node/src/graphql/query.rs#L293)) is unbounded where `errors` is capped:
  1.34 MB and 260 ms under the read lock per call at 20k, twice per request.
- **Change:** (a) decision (26): cap the uncharged residue per connection (flush past it) or a per-peer
  uncharged allowance; document the bound; (b) decision (27): per peer, suppress (transitively) buffered orphans
  whose only missing parent is in the `(peer, id)` refusal cache for a content reason, so the retry is bounded by
  the TTL as the parent already is; (c) decision (28): a per-remote hint budget or evict-oldest; sweep hints in
  `evict_expired`; (d) decision (29): add the densest admitted shape to the honest control and state ≈15×, or
  lower `MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY` to 1,024; fix the comment; (e) decision (30): cap
  `quarantined` at 1,000 and add `quarantinedTotal: Int!`.
- **Files:** [anti_entropy_alpn.rs:1459, 1855-1918, 2064, 2404](../crates/gl-node/src/anti_entropy_alpn.rs#L1894),
  [connection_limiter.rs:161-166, 734-762](../crates/gl-node/src/connection_limiter.rs#L161), [orphan_buffer.rs:271-330, 607-640](../crates/p2p/src/orphan_buffer.rs#L271),
  [decode_memory.rs:716-718, 824](../crates/p2p/tests/decode_memory.rs#L824), [limits.rs:76](../crates/ledger/src/limits.rs#L76), [query.rs:293-299](../crates/gl-node/src/graphql/query.rs#L293), [types.rs:190-192](../crates/gl-node/src/graphql/types.rs#L190), README, CHANGELOG.
- **Verify:** un-ignore and pass `l95_a_peer_that_fills_the_parent_hint_table_restores_the_crawl_for_honest_joins`
  (harness); A6's instrumented `l90_*` shows a bounded uncharged residue; X2 `r3` (`…/scratchpad/X2/target/release/x2 r3`)
  validates 0 per tick from tick 2; A3 `mem` under the new control; A4 `P8` response ≤ the cap. Bug-catch proof
  per bound.

---

## Tier 3 — diagnostics and texts

### ☐ T89 — The placeholder in every own lookup, WARNs judged once and after the pass, the texts (L-96, L-98, L-99, L-100, L-108, L-109, L-111, L-112, L-113, §5) — S, decisions (31)–(34) taken
- **Why / change, one line each:**
  - **L-96** — `release_clock_carried_by_edited_records` ([service.rs:4561](../crates/ledger/src/service.rs#L4561)),
    `highest_lamport_author` ([:5526-5545](../crates/ledger/src/service.rs#L5526)) and `set_author_id`
    ([:8044](../crates/ledger/src/service.rs#L8044)) key on the new author id, so a placeholder record outside the
    DAG (text-held, or quarantined for another reason) is foreign to every own lookup: the release drops it and
    the node re-issues its lamport (`DUPLICATE PAIR (8139770e, 5)`), the ceiling refusal names `author local`
    with the mesh-wide remedy (L-91 verbatim), and a Fresh boot and a reload resume at different clocks (9 vs 6).
    Change, decision (31): treat `PLACEHOLDER_AUTHOR` as this node in the three lookups once the id is set, or
    re-key `boot_outside_dag_lamports["local"]` in `set_author_id`.
  - **L-98** — the "EVERY signature failed" WARN ([:4496-4499](../crates/ledger/src/service.rs#L4496)) is judged
    per pass, so two edited own records fire it in the signer's pass while every foreign record verifies in the
    verifier's. Change: judge once in `verify_own_history` over the summed passes.
  - **L-99** — on a real domain/key mismatch the release ([:4520](../crates/ledger/src/service.rs#L4520)) still
    walks the clock to 0. Change, decision (32): skip the release when `every_checked_failed`; the WARN says not
    to author until the domain/key is fixed (or the node refuses to author).
  - **L-100** — boot's gap WARN ([:3798-3830](../crates/ledger/src/service.rs#L3798)) runs before the pass and
    the closure, fires for the record the same boot quarantines, and prescribes the bootstrap join for a gap the
    served history lacks; `lamport_gap()` ([:8173](../crates/ledger/src/service.rs#L8173)) has no production
    caller. Change: re-judge after `verify_history_pass` on the surviving DAG and print from gl-node after
    `verify_own_history`.
  - **L-108** — same-date hand lines keep file order, so a child before its hand parent is refused "exists
    nowhere" at boot 1 and adopted at boot 2 (served set, balances and file bytes change across
    boot → compaction → boot). Change: adopt hand-parented entries after the rest of the batch, or say a later
    hand line is adopted at the next restart.
  - **L-109** — the L-89 strip runs in `boot_with` only ([:3412](../crates/ledger/src/service.rs#L3412)); the
    live path refuses the same block under H-06 ([:7344](../crates/ledger/src/service.rs#L7344)) and the
    re-persist deletes it. Change, decision (34): strip on the live path too, or quarantine instead of drop.
  - **L-111** — the gap WARN names the author at the top ([:3796-3806](../crates/ledger/src/service.rs#L3796)),
    which after the remedy is the first honest record above the gap, every boot. Change, decision (33): reword.
  - **L-112** — the strip reads `directive.metadata()` only ([:3405-3413](../crates/ledger/src/service.rs#L3405));
    a posting-level `openledger-*` key is served and written back forever (local-only). Change, decision (34):
    strip posting-level keys in the same loop.
  - **L-113** — `BOOTSTRAP_JOIN_REMEDY` ([:1417-1424](../crates/ledger/src/service.rs#L1417)) claims
    un-joinability for every gap ≥ 2^28 where the ratchet is 2^32: one peer record at `clock + 2^28` makes every
    node and joiner WARN forever and prescribes a join that is not needed. Change, decision (33): distinguish
    "diagnosed" from "uncrossable" in the text; keep the threshold.
  - **§5 items** — re-pin `dtolnay/rust-toolchain` to a reachable commit or tag; the M-54 text for a
    hand-spelled `"local"` author; `sign_adopted_entry`'s foreign-arm comment ([:7836-7845](../crates/ledger/src/service.rs#L7836));
    the summary H-20 WARN text when every reason was "no openledger-signature"; the `LAMPORT_GAP_WARN <
    MAX_LAMPORT_ADVANCE` assertion at module level; README's shrink remedy (archive/split procedure; peers
    re-supply deleted blocks); the mixed-version note (a T75–T80 node orphans every later HEAD write); the
    as-stored count on signing-off nodes (documented as conservative).
- **Files:** [service.rs:1417-1424, 3394-3432, 3796-3830, 4496-4531, 4557-4595, 5526-5545, 7344, 7836-7845, 8041-8127, 8173](../crates/ledger/src/service.rs#L4496),
  [main.rs:553-566](../crates/gl-node/src/main.rs#L553), `.github/workflows/ci.yml`, README, CHANGELOG.
- **Verify:** un-ignore and pass `h19_the_gap_warning_on_a_node_without_the_jump_names_the_removed_author`
  (harness); A2 `s7` no duplicate pair, `s5` names no author `local`, `s3` no WARN, `s1(e)` clock kept; X1 `c5a`
  clock equal on boot and reload; D1 `case_l87` no gap WARN; X1 `c7 order` fixed point; X1 `c8a` both paths agree;
  A6 `h6_strip` (d) clean on disk. Bug-catch proof per predicate.

---

## Residuals carried into this backlog (unchanged, for the record)

- **H-01** loopback API key (deferred by decision); **M-09 / M-10 / L-06** — T45 (Format v2); waves A+B wait for T84.
- **L-23 / R-9** — `meshId` required next release. **R-8**, **R-14 / R-15**, **R-16** — unchanged since 09/23.
- **H-19 by decision (1):** anti-entropy-only joins across a removed author's jump or a pre-T63 jump remain
  impossible by design; the two ignored harness cases document it.
- **T79** a library caller that installs the verifier after `finalize_operator_input` (no gl-node path does).
- **T80** a signing-off node boots and writes under `"local"`; `set_author_id` after finalize is library misuse.
- **T81** `balance`/`price`/`note`/`document`/`pad` on an orphaned account stay served (inserted unchecked at
  every peer too); the mixed-version window (a T75–T80 node refuses over 64/100 until it upgrades — and orphans
  every later HEAD write); the live reconcile re-refuses the whole closure on every hand edit (log volume).
- **T82** the leading comments are captured at boot and a live deletion is undone by the next rewrite; the
  other-uid link refusal is not unit-tested; a link re-pointed after boot is never followed (L-44); a link owned
  by this uid to another uid's file is worked by decision (11).
- **T83** L-95 helps only when the serving peer answers in the Want's order; L-86 and L-88 are documented, not
  changed; the L-81 clock rule is one slot weaker than boot's (no executed shape re-issues a pair through it).
- **§5 informational items** in the 0925 report not assigned above: a `"local"` child closure-quarantined at
  boot stays `"local"` in the file; an edited descendant of an M-52 record is quarantined under the closure
  reason; later-refused boot adoptions leave the clock at their provisional stamps for the process lifetime;
  `signature_quarantined_total` restarts at 0 on a reload; the temp named after a link's stem is not swept;
  `probe_local_health` fails closed on a 64 KiB cut inside a multibyte character; the fan-in cap is record-only
  at boot.

---

## Regression-test manifest (must exist by the end of Tier 1)

Every item is already pinned as an `#[ignore]`d case; un-ignoring it is the acceptance criterion.

1. A hand line is never signed over a served record whose ancestry does not resolve; the prescribed remedies
   leave no served descendant without a seed; a text-held block without an id strands nothing (T84 / H-23):
   `a1_2_…` (fuzzer), `a4_2_…` ×2, `a4_3_…` (`exact_balances`).
2. A lamport edit plus a hand line in one edit is accepted by a peer; the release never re-issues an issued
   pair (T84 / M-57, L-97): `a1_1_…` (fuzzer), `l87_the_clock_release_…` (harness).
3. A surviving `open` that does not admit the transaction does not un-strand it; a record over the wire's body
   cap is never served or always crosses (T85 / M-56, L-101): `a4_1_…` (`exact_balances`),
   `history_over_the_wire_body_cap_…` (`m50_wire`).
4. On an over-cap ledger with hand lines, mutations refuse pre-stage and zero reloads after the startup
   compaction; a kept envelope never names a parent the rebuild lacks; a signing-off node's served hand line
   survives a backup restore plus a failed commit; a later append torn inside its header is `Corrupt`
   (T86 / M-58, M-59, L-104, L-105): new unit tests (gl-node `l80_*` compacting first; `a5_p2`, `a5_p3`,
   `a5_p4` shapes).
5. The uid guard holds under a link swap and on every hop; a journal beside the link refuses or is folded
   (T87 / M-60, M-61): new unit tests.
6. One peer cannot fill the hint table for honest joins; the uncharged residue is bounded; a doomed subtree is
   not re-verified every tick (T88 / M-62, L-106, L-107): `l95_a_peer_that_fills_…` (harness), new gl-node
   and p2p unit tests.
7. The gap WARN names the jumper, not an honest author (T89 / L-111): `h19_the_gap_warning_on_a_node_…`
   (harness).

Every one needs its **bug-catch proof** — revert the fix, watch the named test fail, restore — and the
orchestrator re-verifies each mechanism in source and re-runs the suite on a quiet machine. The proof crates for
every finding are in the 0925 session's scratchpad (`A1` … `A6`, `X1` … `X3`, `D1`); each pass's report §6
gives the re-run command, and the orchestrator's re-runs and per-pass summaries are under `orch/`.

---

*Audit: [SECURITY_AUDIT_0925.md](../SECURITY_AUDIT_0925.md). Previous trackers:
[OUTSTANDING_TASKS_09_24.md](OUTSTANDING_TASKS_09_24.md) (T79–T83) ·
[OUTSTANDING_TASKS_09_23.md](OUTSTANDING_TASKS_09_23.md) (T72–T78) ·
[OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md) (T61–T71) ·
[OUTSTANDING_TASKS_09_22.md](OUTSTANDING_TASKS_09_22.md) (T46–T60, R-1…R-21) ·
[OUTSTANDING_TASKS_09.md](OUTSTANDING_TASKS_09.md) (T18–T45) · [OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md)
(T1–T17). Format v2 design: [FORMAT_V2_DESIGN.md](FORMAT_V2_DESIGN.md).*
