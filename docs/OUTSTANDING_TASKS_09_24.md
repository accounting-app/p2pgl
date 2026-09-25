# Outstanding Security Tasks — 2026-09-24

Remediation backlog for every open finding in [SECURITY_AUDIT_0924.md](../SECURITY_AUDIT_0924.md), the
re-audit of T72–T78. Task numbering continues from [OUTSTANDING_TASKS_09_23.md](OUTSTANDING_TASKS_09_23.md)
(T72–T78, all ☑). Line references are current as of HEAD `3d64a16`.

**Already closed — do not re-do:** the 0924 audit verified **20** register entries closed by mechanism
(H-19, H-20, H-21 · M-46, M-48, M-49 · L-64, L-66, L-67, L-68, L-69, L-70, L-71, L-72, L-73, L-74, L-76, L-77,
L-78, L-79). See [SECURITY_AUDIT_0924.md §1](../SECURITY_AUDIT_0924.md). This tracker covers only what is open:
one new High, five new Mediums, sixteen new Lows, the informational items worth a line of code, and the carried
partials (M-47, M-50, L-75, L-23, H-01).

**Status legend:** ☐ not started · ◐ in progress · ☑ done
**Effort:** S = < ½ day, M = ~1–2 days.

> **The shape of this backlog.** The 0922 audit found its Highs inside T18–T44's code, 0922-v2 inside T46–T60's,
> 0923 inside the *decisions* T63 and T64 recorded, and 0924 finds them in the **order** the T72–T78 fixes run
> and in **what they count**: parents are chosen before the signature pass removes what they name; a metadata
> count runs before the signature is added; a clock warning is judged against a count the quarantine has since
> shrunk; the caps bind writes but not history; the author id is set after the signer that signs for it. The
> through-line: **each check runs at a moment when its input is not yet the state that will be served.** T79 and
> T80 are therefore organised around moving each check to the point where its input is final, and T81 around
> giving every content rule the upgrade path T76 gave the amount cap. Every task keeps the campaign's rule:
> revert the fix → the named test fails → restore; residuals go in this file, not in code comments.

> **Acceptance tests already exist.** The audit extended the four invariant files —
> [crates/p2p/tests/convergence.rs](../crates/p2p/tests/convergence.rs) (17 passed / 6 ignored),
> [crates/p2p/tests/boot_fuzz.rs](../crates/p2p/tests/boot_fuzz.rs) (32 / 5),
> [crates/ledger/tests/exact_balances.rs](../crates/ledger/tests/exact_balances.rs) (24 / 1),
> [crates/p2p/tests/m50_wire.rs](../crates/p2p/tests/m50_wire.rs) (6 / 0) — and pinned every new finding that
> has a pinnable shape as an `#[ignore = "<pass>-N: …"]` case that fails at HEAD for the stated reason under
> `--ignored`. **A task is done when its cases are un-ignored and green, with no other test in the file
> changed.** The two pre-existing ignored cases (`h19_fresh_node_converges_after_a_maximal_legal_jump…`,
> `h19_pre_t63_history_with_one_large_jump_is_joinable`) stay ignored by decision (1) of 2026-09-23.

> **Decisions taken 2026-09-24** (user), recorded once here and referenced from the tasks: **(6)** T81's rule
> for pre-T75 history is a **legacy ceiling** — one much larger bound for the two cardinality caps (currencies per
> `open`, posting-metadata keys per transaction) applied identically on the wire, at boot and in
> `stage_remote_directive`, with the local write caps staying 64/100; real history loads and replicates, the M-48
> floods stay refused. M-52's past-`10^21` amounts are not covered by a ceiling and take the closure quarantine
> (T81 (b)). **(7)** A hand-spelled foreign `openledger-author` is **refused** — quarantined at boot, rejected on the
> live reconcile, with the existing "remove the openledger-author line" remedy; the T41 warn-and-adopt arm goes.
> **(8)** The ledger author is **derived from the signing key whenever `signing.enabled`**, P2P on or off, before
> `set_signer`; `"local"` never reaches a signed envelope.

> **Decisions taken 2026-09-24, second batch** (user): **(9)** T80 upgrade path — a record whose author is the
> placeholder `"local"` and whose signature verifies under this node's own key is **re-attributed in place** at
> boot (the key's author id written in; the signature covers id, parents and lamport, not the author, so it stays
> valid; with P2P off such records never left the node). **(10)** T81 / M-55 — the metadata cap stays a count of
> the **full envelope**, and the file path checks it **after** the signature is added; the wire rule is
> unchanged. **(11)** T82 / L-84 — a symlinked `.bean` is **followed fully**: the path is resolved once at boot
> and the journal, lock and temp names derive from the target, so the link keeps working (T67's documented
> support). **(12)** T83 / L-94 — the H-19 warning is judged on a **lamport gap** in the history (one jump between
> consecutive lamports ≥ 2^28), not on a clock-to-count ratio. **(13)** T83 / L-95 — a record buffered on a
> missing parent makes the next round **Want that parent by id** (receiver-side, no wire change, the buffer still
> never evicts honest entries). **(14)** Execution — **one task per go-ahead**, as T79 was: full gate and
> revert-proofs, stop for the commit, ask before the next.

## Priority order at a glance

| # | Findings addressed | Sev | Effort | Status |
|---|---|---|---|---|
| T79 | H-22 + M-54 + L-75 remainder — operator input after verification | **High** | S–M | ☑ |
| T80 | M-53 + L-82 + L-91 + §5 banner — the author id is the key | Med | S | ☑ |
| T81 | M-51 + M-52 + M-55 + M-50/M-47 remainders — upgrade paths for every content rule; count the envelope | Med | M | ☑ |
| T82 | L-80 + L-81 + L-84 + L-85 + L-93 — the over-cap state, the floor's identity check, the torn rule, the symlinked `.bean` | Low | S | ☑ |
| T83 | L-83 + L-86 + L-87 + L-88 + L-89 + L-90 + L-92 + L-94 + L-95 + §5 — diagnostics, cost bounds, docs | Low | S | ☑ |

**Coverage check — every open register entry maps to exactly one task:**

H-22→T79 · M-51→T81 · M-52→T81 · M-53→T80 · M-54→T79 · M-55→T81 · L-80→T82 · L-81→T82 · L-82→T80 · L-83→T83 ·
L-84→T82 · L-85→T82 · L-86→T83 · L-87→T83 · L-88→T83 · L-89→T83 · L-90→T83 · L-91→T80 · L-92→T83 · L-93→T82 ·
L-94→T83 · L-95→T83 · M-47 (remainder)→T79 · M-50 (remainder)→T81 · L-75 (remainder)→T79.

**Deferred by design to T45 (Format v2), unchanged:** M-09, M-10, L-06. **Deferred by decision, unchanged:**
H-01's loopback API key; L-23 (`meshId` required next release).

**T45 interaction:** waves A and B wait for **T79 and T80** as they waited for T72 and T73 — both change what
an envelope is verified against and when (the author id, the parents of operator input).

**Landing order:** T79 → T80 (both live in `service.rs`'s boot pipeline and `main.rs`; T79 first, because T80's
author change alters which arm of `verify_history_directive` judges own records, and T79's tests must be green
before that moves) → T81 ∥ T82 (disjoint: T81 owns `union_merge.rs`, the boot history arm at
`service.rs:3387-3400`, `limits.rs`, `adopt_file_directive`'s cap call; T82 owns `finish_recovery`, `prepare`'s
compaction arm, `append_headroom`, `journal.rs`, the `.bean` path derivation) → T83. `service.rs` is the
contention point again: T79, T80, T82 go to one agent in that order or run sequentially; T81 and T83's non-service
items can run alongside. **Extend the four invariant files before each task, as the audit did**, and run the
whole workspace at the end of every wave: the gate at HEAD is **1,276 passed / 0 failed / 12 ignored**.

---

## Tier 1 — ship-blocker (the new High)

### ☑ T79 — Operator input after verification (H-22, M-54, L-75 remainder) — S–M, decision (7) taken
> **Done 2026-09-24 (working tree, not committed).** All in `crates/ledger/src/service.rs`, plus README §Editing and the CHANGELOG. **(a) H-22, the rebase:** `quarantine_out_of_dag` now rebuilds with every still-unsigned operator-input entry rebased onto the DAG it is rebuilding, in insertion order — exactly what boot would have adopted over a file without the refused records: parents this node chose are chosen again from the rebuilt heads by the one rule (`choose_parents` became a thin wrapper over the new free function `choose_parents_in(dag, id)`); parents the operator spelled must all have survived; a transaction must still validate against the rebuilt account state. A refused entry is held in the quarantine **as the file spelled it** (new field `operator_input_as_written`, filled at boot adoption, pruned by the rebuild, cleared by `finalize_operator_input`), and a later entry is judged against a DAG without it, so the refusal cascades exactly as far as it must. Signed history is never re-parented. INFO on a rebase, WARN per cascaded refusal. **(b)** `finish_recovery` runs `verify_own_history` before `finalize_operator_input`. **(c) L-75 in the DAG alone:** `adopt_file_directive`'s hand-parent check no longer admits a quarantined parent (the message says which: "held in this node's quarantine, which is never served" or "exists nowhere"); at boot the rebase re-checks once the signature pass has judged the history. **(d)** implemented as a **WARN, not a quarantine** (design deviation, below): `verify_own_history` names every served record whose parent is only in the quarantine, with the remedy. **(e) M-54, decision (7):** operator input whose file-spelled `openledger-author` names another node is refused — on the live path in `adopt_file_directive` before anything is stamped (new `AdoptionPath { Boot, Live }` parameter; the placeholder author makes the rule unjudgeable at boot adoption), and at boot at the top of `finalize_operator_input`, where it goes through the same rebuild (so a transaction on an account only that `open` opened is refused with it). The T41 warn-and-adopt arm is gone from finalize; `sign_adopted_entry`'s foreign arm stays for a complete-but-unsigned envelope on a verifier-less node, comment updated. One refusal text, `foreign_operator_input_reason`. **(f)** README §Editing: foreign author refused, hand parents must be served records, "fix a record and append in one edit is safe" paragraph; the live-reconcile bullet. CHANGELOG: the M-47 and L-75 bullets amended, one new *Ledger files* bullet, one *Security* bullet. **Design deviation, accepted:** (d) warns instead of quarantining. A served record naming a quarantined parent is acknowledged history, often with long chains of descendants; quarantining the closure would remove all of it from local balances on the strength of what the mesh lacks, and since T79 boot never creates the shape — only an older build's file (no release has shipped T73) or a history this node wrote before enabling signing does. The operator decides (restore the parent, or rebuild by the bootstrap join). **Acceptance:** un-ignored and green: `op_x_edited_record_plus_hand_append_in_one_session`, `op_y_hand_header_pasted_inside_a_signed_block`, `op_z_hand_parent_naming_the_quarantined_id`, `op_aa_foreign_author_half_envelope_is_served_unsigned` (boot fuzzer, now 36 passed / 1 ignored), `h20_operator_input_stamped_at_boot_must_not_name_a_record_the_h20_pass_quarantines` (harness, 18 / 5); doc comments rewritten to say the bug is closed. **New unit tests (5):** `h22_a_hand_line_appended_with_an_edit_is_rebased_before_it_is_signed` (parents move from the edited id to T1, signed over them, read model agrees, reboot a fixed point), `h22_a_hand_parent_on_a_record_quarantined_at_boot_is_refused_and_the_refusal_cascades` (held as written; the line stamped on top is rebased; live refusal; quarantined blocks written back), `m54_a_foreign_author_open_is_refused_at_finalisation_and_what_relied_on_it_goes_with_it`, `h22_a_recovery_reload_verifies_before_it_finalises`, `h22_a_served_record_naming_a_quarantined_parent_is_named_in_a_warning`. **Existing tests changed (2), by decision (7):** `m47_a_half_envelope_is_operator_input_on_both_file_paths_stamped_and_signed` (the foreign line is now quarantined as written, and again at every boot) and `test_reconcile_does_not_sign_for_another_author` (now refused, `rejected: 1`). **Revert-proven (8, each in a scratch copy of the tree, restored and compared equal):** R1 no rebase → four `h22_*`/`m54_*` unit tests, `op_x`, `op_y`, `op_z` and the harness case fail; R2 "DAG ∪ quarantine" restored → the live half of `h22_a_hand_parent_…` fails; R3 hand-parent refusal dropped in the rebase → `h22_a_hand_parent_…` and `op_z` fail (`served-but-refused … names parent … that exists nowhere`); R4 finalize's foreign refusal dropped → `m47_*` and `m54_*` fail (the fuzzer's `op_aa` passes under it: finalize then re-attributes and signs the line — decision (7)'s rejected option — so only the unit tests pin the decision); R5 live foreign refusal dropped → `test_reconcile_does_not_sign_for_another_author` fails; R6 recovery order swapped back → `h22_a_recovery_…` fails; R7 rebase validation dropped → `m54_*` fails; R8 the WARN call dropped → `h22_a_served_record_…` fails. **Gate:** clippy `-D warnings` and `fmt --check` clean; every test binary except gl-node's unit tests green (ledger 554, exact_balances 24/1, property 10, p2p 185, boot_fuzz 36/1, convergence 18/5, decode_memory 7, m50_wire 6, property 5, security 21, gl-node integration 8); gl-node unit tests **383 passed, 29 failed — all 29 real-QUIC loopback tests, an environment outage, not T79**: the same tests fail identically on an untouched `git archive` of the committed `4a3428f` (pre-T79) built in scratch (`happy_path_small_limits_converges`, `eclipsed_node_still_syncs_from_bootstrap_peers`: 0 passed / 2 failed, 93 s), and T79 changes no gl-node code. **Re-run after loopback QUIC recovered (same day): `cargo test --workspace --locked --no-fail-fast` — 1,286 passed, 0 failed, 7 ignored**, gl-node unit tests 412 / 0 including all 29. The 7 ignored are the two H-19 joins kept by decision (1) and the T81/T83 acceptance cases. **Behaviour changes:** a hand line appended in the same edit as a fixed signed record is signed over surviving parents (INFO line); a hand parent held only in the quarantine is refused on both paths; operator input naming another node as author is refused on both paths (quarantined as written at boot and again every boot until the line is fixed; dropped by the live reconcile's rewrite, with its content logged); operator input that no longer validates once a record it relied on is quarantined is quarantined with it; a recovery reload verifies before it signs; a new boot WARN for served records with a quarantined parent. **Residuals:** a hand `open` refused at adoption as already-open, because the history `open` it duplicates is quarantined later by the signature pass, stays refused (loud, not a divergence; the rebase only re-checks what was adopted); a library caller that installs the verifier *after* `finalize_operator_input` can still quarantine a signed operator input's parent (gl-node's order, and `finish_recovery`'s, never do; the new WARN names it); (d) is a WARN by the deviation above.
- **Why:** **H-22.** `boot_with` adopts the file's operator input at
  [service.rs:3825](../crates/ledger/src/service.rs#L3825) (`adopt_operator_input_at_boot` → `adopt_file_directive`),
  which stamps `openledger-parents` with `choose_parents` over the *current* heads
  ([:6626](../crates/ledger/src/service.rs#L6626), [:6662](../crates/ledger/src/service.rs#L6662)). At that moment
  the DAG holds every enveloped record on its envelope's word — an edited own record (new content id, old
  envelope) is in and is a head. The signature pass runs later, from `set_signer`
  ([:7154](../crates/ledger/src/service.rs#L7154)) and `set_verifier` ([:7169](../crates/ledger/src/service.rs#L7169))
  in gl-node's order ([main.rs:436](../crates/gl-node/src/main.rs#L436), [:459](../crates/gl-node/src/main.rs#L459)),
  and `quarantine_out_of_dag` ([:4208](../crates/ledger/src/service.rs#L4208)) rebuilds the DAG from survivors by
  lenient insertion, pruning ids from `unsigned_operator_input` ([:4262](../crates/ledger/src/service.rs#L4262)) but
  never re-parenting what stays in. `finalize_operator_input` ([:3919](../crates/ledger/src/service.rs#L3919)) then
  signs the hand line over those parents (the signature verifies, so the pass it triggers accepts it), the startup
  compaction persists it, and every peer's `stage_remote_directive` refuses it for a parent no replica serves —
  `Dag(_)` refusals are not permanent ([anti_entropy_alpn.rs:2401](../crates/gl-node/src/anti_entropy_alpn.rs#L2401)),
  so it is re-Wanted forever, and with it every API append this node acknowledges afterwards and every bootstrap
  joiner's own writes. Restoring the original line does not repair it. Shape: the README's stop → edit → start
  with a narration fix in a node-written block *and* one hand-typed transaction in the same edit. Three passes
  reproduced it independently (X1 `c2`, A2 `composite`, A1 through the README's bootstrap join). **Second door:**
  the L-75 rule resolves a hand-spelled parent in "DAG ∪ quarantine" ([:6508](../crates/ledger/src/service.rs#L6508)),
  so a hand line naming the id the boot banner printed is adopted and signed the same way. **Third door, by
  accident:** a hand header pasted between a signed block's envelope and its postings makes a 0-posting head
  (quarantined) and a parsable tail adopted with `parents = <the quarantined head>`.
  **M-54.** `is_operator_input` ([:3747](../crates/ledger/src/service.rs#L3747)) parks a block with an author and no
  lamport; `adopt_file_directive` stamps lamport and parents and inserts the author only if absent
  ([:6599](../crates/ledger/src/service.rs#L6599)); `finalize_operator_input` skips signing a file-spelled foreign
  author ([:3945-3953](../crates/ledger/src/service.rs#L3945-L3953)) with the T41 warning "will NOT replicate", whose
  justification "inert outside this node" ([:6895-6899](../crates/ledger/src/service.rs#L6895-L6899)) is false:
  `choose_parents` ([:4740](../crates/ledger/src/service.rs#L4740)) names it, the wire refuses it for good
  (`EnvelopeMissing signature`), and every descendant is buffered forever — M-47's consequence verbatim, through
  M-47's own example (a block copied from another ledger with the lamport line dropped). The stamp also issues
  `(author B, lamport n)`, a pair B never issued.
- **Decision (7), taken:** refuse.
- **Change:** (a) choose and stamp operator-input parents in `finalize_operator_input`, after the signer and
  verifier passes (nothing is signed or served before it), **or** have `quarantine_out_of_dag` re-stamp
  `openledger-parents` for every id still in `unsigned_operator_input` from the rebuilt DAG and re-index it
  (`set_author_id` already re-stamps their lamports this way); (b) on the `finish_recovery` path run
  `verify_own_history` before `finalize_operator_input`
  ([:5645-5649](../crates/ledger/src/service.rs#L5645-L5649)); (c) resolve hand-spelled parents in the DAG alone —
  a quarantined record is never served — with a reason naming the quarantine; (d) quarantine, as written, any
  *signed* survivor whose parent is in quarantine (unadoptable by construction) so the served set is
  self-consistent; (e) decision (7): operator input may name no author but this node — quarantine at boot,
  reject live, with the existing "remove the openledger-author line" remedy — and drop the T41 warn-and-adopt
  arm; (f) README §Editing: the two-edits-in-one-session case, the foreign-author line.
- **Files:** [service.rs:3825-3870, 3919-4000, 4208-4270, 4740-4748, 5645-5649, 6500-6520, 6596-6604, 6867-6899](../crates/ledger/src/service.rs#L3825),
  [README.md §Editing](../README.md).
- **Verify:** un-ignore and pass `op_x_edited_record_plus_hand_append_in_one_session`,
  `op_y_hand_header_pasted_inside_a_signed_block`, `op_z_hand_parent_naming_the_quarantined_id`,
  `op_aa_foreign_author_half_envelope_is_served_unsigned` (boot fuzzer) and
  `h20_operator_input_stamped_at_boot_must_not_name_a_record_the_h20_pass_quarantines` (convergence harness);
  the controls (`h19_bootstrap_join_through_gl_node_order_with_operator_input_converges`, `…with_a_quarantined_block_converges`,
  every `op_*` that passes today) still pass; the 0923 §9 fixed point
  (`composite_crash_between_finalize_and_compaction_is_byte_identical`) still holds with the parents chosen
  later. Bug-catch proof for (a), (c) and (e) separately.

---

## Tier 2 — the placeholder author and the upgrade paths

### ☑ T80 — The author id is the key (M-53, L-82, L-91, §5 banner) — S, decision (8) taken
> **Done 2026-09-24 (working tree, not committed).** **(a) Decision (8):** `main.rs` sets the ledger author from the node key right after loading it, whenever `signing.enabled` (P2P on or off), before the signer, the verifier and `finalize_operator_input` — new `NodeSecretKey::author_id()` (the key's `EndpointId`, spelled as `PeerNode::node_id`). The P2P branch no longer sets the author; it compares the endpoint id with it and aborts on a mismatch. Boot runs under the new `ledger::service::PLACEHOLDER_AUTHOR` (`"local"`), which a signing node never writes any more. **(b) Decision (9):** `reattributed_placeholder_record` — a record whose author is the placeholder, with a lamport and a signature that verifies as this node's (the verifier with this node's id when installed, else the signer's deterministic re-sign), gets this node's author id; the signature covers id, flag, parents and lamport, not the author, so it stays valid. Applied in the signature pass (DAG entry replaced in place — parents and id unchanged — read model re-indexed, `force_compaction` so the file is rewritten, one INFO) and on the live reconcile's two full-envelope arms. A placeholder record that does not verify as this node's takes the normal verdict. **(c) L-91:** `set_author_id` warns, with boot's two predicates, when this node's own records outside the ledger carry the clock to or within one adoption step of the ceiling, naming the node's own file as the source; `highest_lamport_author` also considers `boot_outside_dag_lamports`, so a text-held own record that is the only carrier is named. **(d) §5 banner:** new `signature_quarantined_total()` counts every pass; `main.rs` reports it instead of the last call's return (0 once the setters had quarantined). When every signature a pass checked *failed* (not missing, ≥ 2), a WARN names `p2p.meshId` and the node key. **(e) §5:** the signer is installed only with signing enabled (the GraphQL schema still gets the provider). README: a paragraph in §Editing (a signing node is its key; the pre-T80 `"local"` history is re-attributed, nothing to do) and the `signing.enabled` row; CHANGELOG: one *Ledger files*, two *Changed*, one *Security* bullet. **Tests (7 new):** `m53_a_history_signed_under_the_placeholder_is_reattributed_not_quarantined` (verifier path and signer-only path; signatures unchanged byte for byte, compaction writes the author, reboot a fixed point), `m53_a_placeholder_record_that_does_not_verify_as_ours_is_not_reattributed` (edited record quarantined; live paste re-attributed), `t80_the_signature_quarantine_total_counts_every_pass_and_a_total_failure_names_the_domain`, `l91_set_author_id_warns_when_own_records_outside_the_ledger_reach_the_ceiling`, `l91_the_ceiling_refusal_names_an_own_record_held_as_text_when_it_is_the_only_carrier`, gl-node `t80_the_author_id_from_the_key_is_the_endpoint_id_and_the_signing_key`, and boot-fuzzer operator `PlaceholderAuthorEverywhere` with `op_ac_a_history_signed_under_the_placeholder_is_served_whole`. `OPERATORS_ALL` widened from 25 to 30 (T79's four closed operators plus this one), so the all-operator sweep covers them. **Existing tests changed:** none. **Revert-proven (7, scratch copy restored equal):** R1 no re-attribution in the pass → both `m53_*`, the first `l91_*` and fuzzer `op_ac` fail; R2 re-attribute without the signature check → `m53_…not_reattributed` and `t80_*` fail; R3 no re-attribution live → the live half of `m53_…not_reattributed` fails; R4 no counting → `t80_*` fails; R5 no domain/key hint → `t80_*` fails; R6 no L-91 WARN → `l91_set_author_id_warns…` fails; R7 `highest_lamport_author` without the outside-DAG pairs → `l91_the_ceiling_refusal_names…` fails. **Real binary, before and after (same key, same config, loopback):** the pre-T80 binary with signing on and P2P off writes `openledger-author: "local"` on both records it creates; booting it with P2P on quarantines both ("was this record edited?") and its node banner stays silent (the §5 bug); the T80 binary on that same file with P2P on quarantines nothing, logs the re-attribution, and the compaction writes the key's id. The T80 binary with P2P off writes the key's id from the first record, and boots a file rewritten to the pre-T80 shape with nothing quarantined. **Gate:** clippy `-D warnings` and `fmt --check` clean; `cargo test --workspace --locked --no-fail-fast` **1,293 passed, 0 failed, 7 ignored** (gl-node unit 413, integration 8, ledger 559, exact_balances 24/1, property 10, p2p 185, boot_fuzz 37/1, convergence 18/5, decode_memory 7, m50_wire 6, property 5, security 21). **Behaviour changes:** a signing node writes its key's id as author with P2P off; placeholder-signed history is re-attributed and rewritten at the next compaction; a signing-off node's ledger has no signer installed (`signer_installed=false` in the UNVERIFIED banner, and no foreign-author warning on a complete unsigned envelope there, since nothing is signed); boot aborts if the endpoint id and the key-derived author ever differ; new WARNs for a total signature failure and for L-91. **Residuals:** a signing-off node still boots and writes under `"local"` (nothing is signed there, so nothing is verifiable; turning signing on later is the documented enable-signing migration, and records written unsigned are quarantined then, as before); `set_author_id` remains callable after `finalize_operator_input` (library misuse, documented at T78).
- **Why:** **M-53.** `signing.enabled: true` without `p2p.enabled` is a permitted config
  ([config.rs:1134](../crates/gl-node/src/config.rs#L1134) forces signing on for P2P, not the converse). The key is
  loaded ([main.rs:334](../crates/gl-node/src/main.rs#L334)), the signer and verifier installed
  ([:436](../crates/gl-node/src/main.rs#L436), [:459](../crates/gl-node/src/main.rs#L459)), but `set_author_id` runs
  only inside the P2P branch ([:379](../crates/gl-node/src/main.rs#L379)), so every record such a node writes
  carries `openledger-author: "local"` under a real signature. With P2P off this verifies through the *signer*
  arm ([service.rs:4177](../crates/ledger/src/service.rs#L4177): author == `"local"`, deterministic re-sign). The
  boot that turns P2P on sets the author to the key hex, so the verifier arm
  ([:4159](../crates/ledger/src/service.rs#L4159)) is consulted first with `author = "local"`, which is not a key →
  every record refused, every boot, as a fixed point (`[p2p-on] directives=0 quarantined=3`), with the H-20
  WARN's remedy ("restore the original line from a peer's copy") wrong for this case; the enable-signing remedy
  works but README §Editing describes only the unsigned → signed transition. **L-82.** Same root on a signing
  single node: `finalize_operator_input` stamps author `"local"`, signs, inserts the id into `unverified_history`
  and runs the pass; the verifier arm cannot parse `"local"`, so the hand line the README's primary workflow
  just adopted is quarantined for one process lifetime with a WARN accusing the operator of editing a signed
  record, and served after the next restart. **L-91.** Under the placeholder a planted own envelope (junk text,
  or a parsed own record outside the DAG) is folded only at `set_author_id`, which logs `info!`
  ([:7134](../crates/ledger/src/service.rs#L7134)) and no ceiling WARN; `highest_lamport_author`
  ([:4777](../crates/ledger/src/service.rs#L4777)) does not see text-held pairs, so the first refused write names
  author `local` and prescribes the mesh-wide allowlist remedy. **§5 banner.** [main.rs:510](../crates/gl-node/src/main.rs#L510)
  prints the H-20 banner from `verify_own_history()`'s return, which counts only the *last* pass; the setters'
  passes already quarantined, so in gl-node's order the banner never prints (`quarantined_by_signature: 0` with
  11 quarantined on a `meshId` mismatch, whose per-record WARN says "was this record edited?").
- **Decision (8), taken:** derive the author from the signing key whenever `signing.enabled`.
- **Change:** (a) decision (8): derive the ledger author from the signing key before `set_signer` whenever
  `signing.enabled` (P2P on or off), so `"local"` never reaches a signed envelope; keep `set_author_id` for the
  P2P branch as a no-op when equal; (b) document the single-node → mesh transition in README §Editing and
  §Mesh identity (the enable-signing remedy applies to a history signed under the placeholder by an older
  build); (c) after the raise in `set_author_id` apply boot's ceiling predicate (`lamport_value_is_legal(clock + 1)`)
  and WARN as boot does ([:3515-3560](../crates/ledger/src/service.rs#L3515-L3560)); include
  `boot_outside_dag_lamports` and text-held pairs in `highest_lamport_author`; (d) `main.rs:510` reports the total
  quarantined by signature across all passes (a counter on the service), and the per-record WARN names a
  `meshId` mismatch when every enveloped record failed; (e) the UNVERIFIED warning's `signer_installed` reflects
  `signing.enabled`, not "a provider object exists" (§5).
- **Files:** [main.rs:326-345, 370-384, 428-520](../crates/gl-node/src/main.rs#L326), [service.rs:4043-4060, 4131-4193, 4770-4790, 7078-7150](../crates/ledger/src/service.rs#L7078),
  [README.md §Editing, §Mesh identity](../README.md).
- **Verify:** X1 `k3` (`…/scratchpad/X1/target/release/x1 k3`) boots with 3 served after enabling P2P; X1 `k2`
  serves the hand line in the same lifetime; A6 `l67` case 1 logs a ceiling WARN naming no author; a gl-node
  integration test boots signing-on/P2P-off, writes, then boots P2P-on over the same file and serves everything
  (fails at HEAD); the boot fuzzer's pipeline updated to the new order and still 32/5 → 36/1 after T79.

### ☑ T81 — Upgrade paths for every content rule; count the envelope (M-51, M-52, M-55; M-50 and M-47 remainders) — M, decision (6) taken
> **Done 2026-09-24 (working tree, not committed).** (The M-47 remainder was M-54, closed by T79.) **(a) M-51, decisions (6) and the 4,096 ceilings:** `limits.rs` gains `MAX_CURRENCIES_PER_OPEN_LEGACY` and `MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY` (4,096 each, reasoning in the doc comments). `service.rs` gains `pub enum ResourceRule { Authoring, History }` and `enforce_resource_limits_for(directive, rule)`; `enforce_resource_limits` is the authoring rule, unchanged for the three local write paths. History takes the legacy ceilings for exactly the two T75 caps (every other §3.12 cap predates T75 and is the same for both). Applied in `validate_supply_entry` (new `ParseLimits::WIRE` for the parse, the history rule on the parsed directive), `stage_remote_directive`, boot's history arm (new first check, with its own WARN), and the file path for complete envelopes. **(b) M-52 and the closure:** `ParseLimits` gains `amount_cap: bool` (carried to the posting scanner; on everywhere) and `ParseLimits::IDENTIFY` (every cap off), used only by boot's new `amount_cap_refused_block_ids` to learn the content id of a block it already refused as text for an amount past the cap — the block stays text, nothing is admitted — and the WARN names the cap and the id instead of L-45's Unicode-account text. After construction and before operator input, `quarantine_descendants_of_refused_history` quarantines the closure of everything refused under a content rule: parent-descendants (through `LedgerDag::children_of` and the new `children_awaiting` for absent parents) and — for a refused `open` whose account no surviving `open` opens — every transaction and `close` on that account, with their descendants (M-51's actual shape is account dependence, not parenthood). The service keeps the refused set and closure (`refused_history_closure`, re-derived by every boot and reload), and the file path refuses a complete-envelope record that is in it or names a parent in it, so a live reconcile — which re-reads the whole file after any hand edit — does not re-adopt what boot held back. GraphQL `VerifyResult` gains `quarantined: [String!]!` and `unparsableBlocks: Int!` (additive). **(c) M-55, decision (10):** operator input is checked by the new `enforce_resource_limits_as_stored`, which counts the full envelope the stored record will carry (author, lamport, signature, and parents for a transaction), on both file paths; the wire rule is unchanged. **(d)** README §Upgrading rewritten (authoring vs history limits, the past-10^21 case and its remedy), a line in "Amounts and precision"; CHANGELOG: the two T75 bullets rewritten, two new *Ledger files* bullets (closure; stored-form count), two Rust-API/GraphQL bullets, one *Security* bullet. **Acceptance:** un-ignored and green: `t75_over_cap_open_loaded_from_a_file_partitions_anti_entropy_joiners` (harness, now 19 / 4) and `over_cap_history_keeps_its_descendants_parents_resolvable_or_refuses_loudly` (`exact_balances.rs`, now 25 / 0; passes by its "withheld" branch — X's descendants are not served and a fresh replica refuses nothing). The audit's own probes, rebuilt against this code: X2 `r1_over_cap_open` / `r1_over_cap_posting` now converge (B holds 5 of 5 and 4 of 4; at `3d64a16` 1 of 5 and 2 of 4 — the probes' "diverges" assertions now fail, as they should); A5 `m50wei`: X, its child and grandchild quarantined, none served, `verify` clean, the upgraded node's Cash balance equal to a fresh replica's; A4 `history` case E: the 97-key hand transaction is quarantined at boot. **New tests (6):** `m51_history_over_the_legacy_ceiling_is_quarantined_with_everything_that_depends_on_it` (flood `open`, the transaction on its account, that transaction's child; an unrelated record served; a live reconcile re-adopts none), `m51_history_over_the_authoring_cap_loads_and_the_api_still_refuses_it`, `m55_operator_input_is_counted_as_stored_on_both_file_paths` (96/97 on a transaction, 97/98 on an `open`, boot and live), `m52_an_amount_past_the_cap_in_history_takes_its_descendants_with_it_loudly` (the M-52 WARN with X's id, no Unicode text, the child held across a live reconcile), `m50_wire::a_hand_transaction_adopted_with_a_signer_is_one_every_peer_accepts` (real Ed25519 key: 96 body keys adopted, crosses the wire and stages on a second node; 97 refused locally), gl-node `test_verify_lists_the_quarantine`. **Existing tests changed (3), by decision (6):** `test_stage_refuses_too_many_posting_metadata_keys` (staging refuses at the legacy ceiling; 101 keys stage and are refused for authoring), `union_merge::test_validate_refuses_each_cardinality_cap_on_the_wire` (the two T75 caps at their legacy ceilings on the wire; one past the authoring cap crosses), and the `m50_wire` T75 case, renamed `a_pre_t65_amount_and_pre_t75_history_cross_the_wire_up_to_the_legacy_ceilings` (65 and 4,096 currencies cross, 4,097 is refused for good; the fresh replica's codes are `OK, OK, OK`, were `OK, WIRE_REFUSED, ACCOUNT_NOT_OPEN`). **Revert-proven (8, scratch copy):** R1 wire back on the authoring rule → the wire cardinality test, the harness case and the `m50_wire` T75 case fail; R2 staging back on the authoring rule → the staging test, the harness case and the `m50_wire` T75 case fail; R3 boot's history arm without the content rule → `m51_history_over_the_legacy_ceiling…` fails; R4 no closure → both `m51`/`m52` closure tests, the `exact_balances` acceptance case and the GraphQL test fail; R5 closure without account dependants → `m51_history_over_the_legacy_ceiling…` fails; R6 past-10^21 blocks not identified → `m52_*`, the `exact_balances` case and the GraphQL test fail; R7 live reconcile guard dropped → both `m51`/`m52` closure tests fail; R8 operator input counted before the signature → `m55_*` and the `m50_wire` M-55 case fail. **Gate:** clippy `-D warnings` and `fmt --check` clean; `cargo test --workspace --locked --no-fail-fast` **1,301 passed, 0 failed, 5 ignored** (gl-node unit 414, integration 8, ledger 563, exact_balances 25, property 10, p2p 185, boot_fuzz 37/1, convergence 19/4, decode_memory 7, m50_wire 7, property 5, security 21); `decode_memory` also green in release. **Behaviour changes:** peers, staging and boot accept pre-T75 history up to 4,096 currencies per `open` and 4,096 posting metadata keys per transaction, while the local API and hand edits keep 64/100; history past those ceilings, or with an amount past 10^21, is quarantined at boot with every record that depends on it (named, kept in the file, not re-adopted by a live reconcile) — a node upgraded over such a history serves less than before, and a `balance` assertion that counted a quarantined amount now fails; a hand entry may carry at most 96 (transaction) / 97 (other) body metadata keys; the wire's body-line cap rises to 5,196 with the legacy posting-metadata ceiling; `verify` lists the quarantine. **Residuals:** the closure follows parents and account-opening only — a `balance` or `price` directive on an orphaned account stays served (never refused by a peer for it, R-15); a node on a T75–T80 build still refuses pre-T75 history over 64/100 until it upgrades (mixed-version window, as for T76); a past-10^21 amount has no path to replicate other than restating it in a larger unit.
- **Why:** **M-51.** Boot's history loop applies `validate_parent_fan_in`, `validate_file_envelope_form` and the
  amount cap ([service.rs:3387-3400](../crates/ledger/src/service.rs#L3387-L3400)) with `ParseLimits::UNLIMITED`;
  `enforce_resource_limits` runs on the write paths only (:4360, :4542, :4645, :6632, :7318). A pre-T75 record over
  a T75 cap — a 65-currency `open` was a plain `openAccount` call before L-78 — loads, is served by every holder,
  is refused at intake by every upgraded replica that lacks it ([union_merge.rs:258](../crates/p2p/src/union_merge.rs#L258)
  → `ResourceLimitExceeded`, permanent, [anti_entropy_alpn.rs:2349](../crates/gl-node/src/anti_entropy_alpn.rs#L2349)),
  and every transaction on that account waits for an `open` that never arrives, every descendant on a missing
  parent, evicted after `MAX_ORPHAN_AGE` and re-fetched forever. Same available set, permanently different DAGs
  and balances on honest replicas (`A=5 / B=1 / C=5`); the bootstrap join converges but nothing prescribes it;
  [CHANGELOG.md:59](../CHANGELOG.md#L59) states the refusal with no remedy while [README.md:58](../README.md#L58)
  promises one. T76 gave the amount cap exactly this upgrade path; the two T75 caps got none. **M-52.** M-50 is
  closed only up to `10^21`: a pre-T65 amount past it (a base-unit token ledger, `50000000000000000000000 WEI`)
  fails the whole-file parse at [parse.rs:287](../crates/ledger/src/parse.rs#L287), is salvaged as *text*
  ([service.rs:3184-3230](../crates/ledger/src/service.rs#L3184-L3230)) under L-45's Unicode-account warning, so it
  has no id; children insert leniently with a dangling parent; balances silently drop it (`5·10^22 + 14 → 14`);
  `verify` reports `MissingParent` forever; the wire refuses the parent for good (`ParseError`) and every
  descendant gets `MISSING_PARENT` on a fresh replica. **M-55.** `adopt_file_directive` stamps author, lamport
  and parents ([:6596-6629](../crates/ledger/src/service.rs#L6596-L6629)) and then runs `enforce_resource_limits`
  ([:6632](../crates/ledger/src/service.rs#L6632)), which counts `directive.metadata().len()` — body keys plus the
  three envelope keys stamped so far; the signature is added afterwards by `sign_adopted_entry`
  ([:6867](../crates/ledger/src/service.rs#L6867)) or `finalize_operator_input`. A hand-typed directive with 97
  (transaction) / 98 (other kinds) body keys passes here and carries 101 at every peer, where
  `stage_remote_directive` counts the merged map ([:7318](../crates/ledger/src/service.rs#L7318)) → permanent
  refusal; `choose_parents` names it; every later own write is orphaned. Within the documented cap of 100, so
  the operator cannot know; without a signer there is no gap.
- **Decision (6), taken:** legacy ceiling for the two cardinality caps; closure quarantine only for the amount cap (M-52).
- **Change:** (a) decision (6): a *legacy* ceiling for the two T75 caps — `MAX_CURRENCIES_PER_OPEN_LEGACY` and
  `MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY` (**4,096 each**, decided 2026-09-24: far above any honest list, far below
  the M-48 floods of 262k currencies and 74k keys; the reasoning goes in `limits.rs`) —
  applied identically in `validate_supply_entry`'s parse limits and enforce call, in `stage_remote_directive`,
  and at boot for enveloped history, while the three local write paths and the operator-input adoption keep
  64/100; a record over the legacy ceiling is refused on the wire and quarantined at boot with the closure rule
  of (b); (b) when boot quarantines a block for the amount cap (M-52), quarantine its descendant closure the same way so
  the served set is self-consistent, and give the WARN the cap's text and the ids (not L-45's Unicode text);
  `verify` reports quarantine ids; (c) count the full envelope in the adoption check — run `enforce_resource_limits`
  after signing, or check `body_keys + ENVELOPE_KEYS.len() ≤ MAX_METADATA_KEYS_PER_DIRECTIVE` — or define the cap
  on body keys everywhere and subtract the envelope in `stage_remote_directive`; (d) CHANGELOG remedies under
  L-78/M-48 and M-50 ("a node upgraded over such a file must be joined by bootstrap" until (a) lands; after it,
  the legacy ceiling); a release note for base-unit ledgers.
- **Files:** [service.rs:3184-3230, 3387-3400, 6596-6640, 7318](../crates/ledger/src/service.rs#L3387),
  [union_merge.rs:236-263](../crates/p2p/src/union_merge.rs#L236), [limits.rs](../crates/ledger/src/limits.rs),
  [parse.rs:745-770](../crates/ledger/src/parse.rs#L745) (`ParseLimits`), [verify.rs](../crates/ledger/src/verify.rs),
  CHANGELOG *Breaking* ("Ledger files"), README §Upgrading.
- **Verify:** un-ignore and pass `t75_over_cap_open_loaded_from_a_file_partitions_anti_entropy_joiners`
  (harness) and `over_cap_history_keeps_its_descendants_parents_resolvable_or_refuses_loudly`
  (`exact_balances.rs`); X2 `r1_over_cap_open` / `r1_over_cap_posting` converge (or refuse loudly with the
  closure quarantined on A and C); A5 `m50wei` boots with X's closure quarantined and named, or loads it under
  the legacy rule; A4 `history` case E — a 97-key hand transaction adopted with a signer round-trips through
  `validate_supply_entry` + `stage_remote_directive` on a second service (new `m50_wire.rs` case); the
  `a_pre_t65_amount_crosses_the_wire_but_an_over_t75_cap_directive_never_does` case updated to the legacy ceiling
  (a 65-currency `open` crosses signed; a 4,097-currency one is refused for good).
  Bug-catch proof for (a), (b) and (c) separately.

---

## Tier 3 — recovery, journal, cost bounds and hygiene

### ☑ T82 — The over-cap canonical state, the floor's identity check, the torn rule, the symlinked `.bean` (L-80, L-81, L-84, L-85, L-93) — S
> **Done 2026-09-24 (working tree, not committed).** **L-80:** new `canonical_over_cap` fact, set by `measure_canonical_over_cap` (boot — every boot, warning only on a process start —, the end of `finalize_operator_input`, and a reconcile of bytes this service did not write), cleared by a `Compact` receipt. While set, `append_headroom()` is 0, so gl-node's existing pre-stage checks refuse a mutation (`RESOURCE_LIMIT_EXCEEDED`, "refused before staging") and defer a peer batch with the backoff, with no reload; and `prepare`'s compaction arm, after the adopt-before-persist, re-measures and refuses with `ResourceLimitExceeded` ("every write fails until the file is made smaller (L-64, L-80)") instead of building the text and failing in `persist_atomically`. The L-64 WARN, README and CHANGELOG now say every write fails. **L-81:** `finish_recovery`'s install arm runs `keep_committed_envelopes_in(&mut reloaded)` before `adopt_reloaded`: every id the rebuild holds as pending operator input that memory holds enveloped takes memory's copy, leaves the rebuild's operator-input sets, and the rebuild's DAG is re-derived around it (`quarantine_out_of_dag` generalised into `rebuild_dag(refused, replacements)`); the clock is raised to at least the kept lamports (M-18); the id stays file-adopted, so the next commit rewrites it. **L-93 (better than the tracker asked):** the tracker assumed the L-81 copy covered L-93, but L-93's record is *absent* from the backup, not re-spelled. `committed_ids_missing_from` now exempts a file-adopted id only while memory's copy is unsigned; a signed one is a committed record, and a rebuild that lacks it is REFUSED (memory kept, the next commit writes it back) — the failure path now matches the success path's L-30 union, which is the asymmetry the T74 residual recorded. An unsigned hand line the operator removes before it is signed is still dropped (T62's floor (a), unchanged; `m46_a_reload_after_removing_ones_own_hand_lines_still_installs` green). **L-85 (refined):** the tracker's suggestion — count any candidate header that claims past the region as a later record — would also catch T78's ext4 stale block (old headers cut at block boundaries) and fail it closed again. Instead `has_later_intact_record` now takes the record's own hash: when the bytes before the first `;;olj ` line verify against it, the length was damaged over a real later append (torn in its header or payload) and the record fails closed; stale bytes never verify, so T78's classification is unchanged. The torn-tail WARN now names post-ack damage and the sidecar. **L-84, decision (11) with a guard:** new `journal::resolve_ledger_path` — a `.bean` that is a symbolic link owned by this process's effective uid is resolved once, at boot, and the node works at the target: journal, temp files, compactions (in place, the link is kept) and — in `main.rs`, before the lock — the `.lock` too, so two nodes on one ledger through different links exclude each other. **A link owned by another uid refuses boot**: following any link would let whoever can write the ledger's directory (threat (e)) point `ledger.bean` at any file the node's user owns and have the next compaction overwrite it; another account cannot create a link this uid owns. A dangling link is left unresolved and refused by T67 as before; a link planted after boot is never followed (L-44 unchanged). **Tests (7 new):** `l80_an_over_cap_canonical_form_refuses_every_write_before_it_is_built`, gl-node `l80_writes_on_an_over_cap_canonical_ledger_are_refused_before_staging` (three mutations refused, zero `reload installed`, nothing staged), `l81_a_restored_pre_canonical_backup_keeps_the_committed_envelope_across_a_failed_commit`, `l93_a_signed_hand_line_is_not_exempt_from_the_recovery_floor`, `l85_a_damaged_length_over_a_torn_later_append_is_corrupt` (with a torn-tail control), `l84_a_symlinked_ledger_is_worked_at_its_target_and_the_link_is_kept`. **Existing tests changed:** none. **Revert-proven (6, scratch copy restored equal):** R1 headroom ignores the fact → both `l80_*` fail; R2 no compaction-arm refusal → the ledger `l80_*` fails; R3 no committed-envelope keep → `l81_*` fails; R4 every file-adopted id exempt again → `l93_*` fails; R5 no prefix check → `l85_*` fails; R6 boot at the link path → `l84_*` fails. **Audit probes, rebuilt against this code:** X3 `k1` headroom 0, the peer chunk deferred before staging, library writes refused with the cap's `ResourceLimitExceeded`; X3 `k4` case c now `Corrupt`, a/b/e/f/g/h unchanged; A3 `hunt7` lamport 504 kept, on disk too; X1 `c1` `REFUSING`, the hand line kept in memory and written back; X1 `c9` the target's journal record served through the link, the link kept, the journal folded. **Real binary:** a symlinked `ledgerPath` → `real.bean.lock` beside the target, the write lands in the target, the link survives. **Gate:** clippy `-D warnings` and `fmt --check` clean; `cargo test --workspace --locked --no-fail-fast` **1,307 passed, 0 failed, 5 ignored**. **Behaviour changes:** over-cap ledgers refuse every write up front; a restored pre-canonical backup keeps committed envelopes; a signed hand line is kept across a backup restore plus a failed commit; a damaged length over a torn later append refuses boot; a symlinked `.bean` is worked at its target (journal, lock, temp files beside it) and a link owned by another user refuses boot. **Residuals:** the leading comments of the `.bean` are captured at boot and a live reconcile never re-reads them (pre-existing), so shrinking an over-cap file while the node runs does not clear L-80 — the remedy is the documented stop → shrink → restart; the other-uid link refusal is not unit-tested (a test cannot create a link owned by another uid without root) — reasoned from the ownership check; a hand-added line the node has not yet signed may still be dropped by a restored backup plus a failed commit (T62 floor (a)).
- **Why / change, one line each:**
  - **L-80** — `canonical_is_current` is `false` after every boot ([service.rs:3659](../crates/ledger/src/service.rs#L3659))
    and set only by a `Compact` receipt, so on a ledger whose canonical form exceeds the cap `must_rewrite`
    ([:5055](../crates/ledger/src/service.rs#L5055)) is always true; the compaction arm's cap refusal is
    `Io(InvalidData)` from `persist_atomically` ([:264](../crates/ledger/src/service.rs#L264)), not
    `ResourceLimitExceeded`, so the L-70 backoff arm ([anti_entropy_alpn.rs:2221](../crates/gl-node/src/anti_entropy_alpn.rs#L2221))
    never arms and `append_headroom()` ([:4944](../crates/ledger/src/service.rs#L4944), the append projection) lets
    both pre-stage checks admit: **every** write path stages, fails and pays a full reload with the permit held
    (0.8–1.0 s on the comment fixture, 33–85 s on a 230k-`open` fixture), one per peer tick and per mutation
    attempt, indefinitely; the WARN ([:3725](../crates/ledger/src/service.rs#L3725)), README and
    [CHANGELOG.md:121](../CHANGELOG.md#L121) say "compactions fail". Found by three passes. Change: a
    `canonical_over_cap` fact set by `warn_if_canonical_exceeds_cap` (boot, `finalize_operator_input`, reconcile),
    cleared by a `Compact` receipt, carried through `adopt_reloaded`; while set, `append_headroom()` returns 0 and
    `prepare`'s compaction arm refuses with `ResourceLimitExceeded` before building the text (via
    `compaction_text_len()`), so mutations refuse pre-stage (L-71 path), peer chunks defer with backoff (M-39
    path) and nothing reloads; reword the three texts to "every write fails until the file is made smaller".
  - **L-81** — `committed_ids_missing_from` ([:5675-5681](../crates/ledger/src/service.rs#L5675-L5681)) asks only
    `rebuilt.get(id).is_none()`: a backup taken before a hand line was canonicalised, restored after the record
    was acked, plus one failed commit reads the raw line as operator input under the same id, installs, and
    `finalize_operator_input` ([:5642](../crates/ledger/src/service.rs#L5642)) re-stamps it (lamport 504 → 902, new
    signature) where the success path keeps it; the mesh holds two envelopes for one id forever. Change: in the
    install arm, for each id in `reloaded.unsigned_operator_input` that memory holds *enveloped*, copy memory's
    directive over the rebuilt one and drop it from the rebuild's operator-input set before finalising.
  - **L-93** — a hand line re-adopted by the reload that follows a failed *startup compaction* is finalised,
    signed and served while still in `adopted_from_file` (cleared only by a `Compact` receipt, and that Compact
    failed); a backup `cp` plus one failed commit then drops it without `REFUSING`
    (`discarded_file_adopted=1`, gone from memory and disk; recovered only because a peer re-supplied it).
    Change: the L-81 identity copy covers the served-record case; state the residual precisely in this file.
  - **L-85** — `has_later_intact_record` ([journal.rs:437](../crates/ledger/src/journal.rs#L437)) examines only
    the first `;;olj ` candidate; a torn successor's header parses but does not fit, so a non-final record whose
    length field was damaged is classified torn with it and an acknowledged record is dropped (loudly, bytes in
    the sidecar) where the old rule refused boot. Change: treat a candidate whose header parses but whose claim
    runs past the region as evidence of a later record (`true`); the torn-tail WARN mentions post-ack damage
    and the sidecar (the T78 single-node residual).
  - **L-84** — `journal_path_for` ([journal.rs:144](../crates/ledger/src/journal.rs#L144)) and the T78 probe derive
    from the *link* path, so a symlinked `.bean` reads the target's bytes but never the target's journal (an
    acked record silently absent from service), and `persist_atomically` renames over the link, undoing the
    operator's arrangement with zero WARN lines. Change: refuse a symlinked `.bean` (as the key file is), or
    canonicalise the path once at boot and derive journal, lock and temp names from the target; README §The
    commit journal.
- **Files:** [service.rs:264, 3659, 3713-3735, 4944-4948, 5055-5066, 5101-5120, 5567-5660, 5779-5800](../crates/ledger/src/service.rs#L5567),
  [journal.rs:144, 372-393, 437-473](../crates/ledger/src/journal.rs#L437), [ledger_commit.rs:550-573](../crates/gl-node/src/ledger_commit.rs#L550),
  [anti_entropy_alpn.rs:2015-2017, 2221, 2237-2245](../crates/gl-node/src/anti_entropy_alpn.rs#L2221), README, CHANGELOG.
- **Verify:** X3 `k1`/`k7` (`…/scratchpad/X3/target/release/x3probe k1`) — zero reloads, mutations refused
  pre-stage, the peer batch deferred with the backoff armed; A3 `hunt7` keeps lamport 504 after the failed
  commit; X1 `c1` refuses the install (`REFUSING`) or keeps the hand line; X3 `k4` case c → `Corrupt` while a, e
  stay as they are; X1 `c9` serves the target's journal record or refuses the link. Unit tests for each
  (`l80_*`, `l81_*`, `l85_*`, `l84_*`) with bug-catch proofs; `m49_*`, `t78_*`, `h15_*`, `l64_*` unchanged.

### ☑ T83 — Diagnostics, cost bounds and docs (L-83, L-86, L-87, L-88, L-89, L-90, L-92, L-94, L-95, §5) — S
> **Done 2026-09-24 (working tree, not committed).** **L-94 / L-83, decision (12):** `clock_is_far_above_history`, the `CLOCK_HISTORY_WARN_*` constants and the once-per-2^20 gate are gone (never released). New `pub fn largest_lamport_gap(lamports) -> (gap, top)` (the largest step between consecutive distinct lamports, counting from 0), `pub const LAMPORT_GAP_WARN = 2^28` (a const assertion keeps it below `MAX_LAMPORT_ADVANCE`) and `LedgerService::lamport_gap()`. Boot's third branch warns on the DAG's gap, naming the author at its top ("the ledger history carries a lamport gap no honest mesh makes"). The adoption site (`warn_if_adoption_opens_a_lamport_gap`, called from `stage_remote_directive` with the clock before and the adopted lamport and author) warns only when that one adoption opens a gap ≥ 2^28 above the clock it found. A gap is a content property: fresh joins cannot compound it and a quarantine cannot shrink the count under it. **L-87:** `release_clock_carried_by_edited_records` runs in `verify_history_pass` after `quarantine_out_of_dag` for every id quarantined because its signature does not verify, and lowers the clock to one above the highest of the DAG, this node's own records quarantined for other reasons, and its own records outside the DAG at boot. **L-89 (design deviation, below):** boot drops a directive-level `openledger-*` key that is not one of the four envelope keys from every non-operator-input directive, with a WARN naming the id and keys; the record keeps its id, signature and balances, and the next compaction writes it without the key. **L-90:** phase 1 decides the flush on `PHASE_ONE_WEIGHT_BUDGET` alone; the byte-budget charge is best-effort after it, so a failed charge holds the directive uncharged (the documented residual) instead of flushing a one-entry chunk. **L-95, decision (13):** implemented as parent hints plus ancestors-first ordering rather than a lamport-ordered Want. `OrphanBuffer` remembers, for each orphan it refuses at the per-peer cap, the parents it was missing (`known_missing_parents`; bounded by `MAX_PARENT_HINT_IDS` = 65,536 ids; forgotten when the orphan is buffered or its parent arrives). `p2p::anti_entropy::order_want_ancestors_first` (iterative DFS, stable, cycle-safe) reorders each Want so a hinted parent precedes its child; gl-node's Want session and the harness's `serve_like_gl_node` call it after the ratchet filter. **L-92:** `ledger::validate::explain_unrepresentable_amount` (exact: more than 28 fractional digits, or a mantissa above 2^96 − 1 counted in u128) replaces "Invalid number" in `read_number` and "Invalid decimal string" in the GraphQL `Decimal` scalar. **§5:** a followed dangling link is refused as "a dangling symbolic link"; `health.rs` reads at most 64 KiB; the `ratcheted` / `refusal_log` maps need no pruning, since the allowlist is parsed once at boot and never changes while the process runs, so a peer leaves it only across a restart, where both in-memory maps start empty (and they stay bounded by `SUPPLY_BACKOFF_MAX_PEERS`). **Docs:** README §Mesh identity (the gap wording, the bootstrap-join note, `max(1, 256 / A)`, L-86 beside "same body, two authors", L-88 run the enable-signing remedy on one node and delete the blocks on the others), §Editing (an amount edit that also drops the lamport line is adopted as a second signed transaction), Amounts and precision (the mantissa bound: 10^21 admits at most 7 decimals), §commit journal (L-86); the harness `Snapshot` doc notes L-86. CHANGELOG: T72's warning bullet and Rust-API line rewritten (the old predicate never shipped), five *Ledger files / Mesh* bullets, one *Security* bullet. **Design deviation, accepted:** L-89 drops the key instead of quarantining the record (the tracker's change). A quarantine removed a validly signed record from local balances for a comment-like key outside the hash and the signature, and set off T79's served-record-with-quarantined-parent WARN on every descendant; dropping gives exactly what the Verify line asks (no `openledger-note` on disk) with nothing lost. **Acceptance:** un-ignored and green: `h19_clock_warning_is_silent_on_an_honest_mesh_with_repeated_fresh_joins` and `chain_over_the_orphan_cap_joins_within_thirty_ticks_in_advert_order` (harness; the 3,000-chain joins in 3 ticks), `op_ab_huge_lamport_edit_of_a_quarantined_record_does_not_move_the_clock` (fuzzer). **New tests (10):** `test_h19_lamport_gap_predicate` (replaces `test_h19_clock_is_far_above_history_predicate`), `l83_an_honest_adoption_below_a_high_clock_does_not_warn`, `l89_a_stray_envelope_key_on_history_is_dropped_at_boot`, `l92_an_over_long_amount_spelling_is_explained`, `l92_the_scalar_explains_an_over_long_amount`, `t83_a_dangling_followed_link_is_named_dangling`, `l95_ancestors_come_first_stably_and_cycles_terminate`, `l95_a_refused_orphan_leaves_its_parent_links_behind`, `l90_an_exhausted_byte_budget_does_not_split_a_frame_into_one_commit_per_directive` (the same 4 journal records with the peer's byte budget exhausted as without), `l95_a_chain_longer_than_the_orphan_budget_catches_up_in_a_few_rounds` (1,300-transaction chain over loopback QUIC, 2 rounds). **Existing tests changed (3):** the H-19 boot test renamed `test_h19_boot_warns_on_a_lamport_gap_in_the_history` and, with the adoption test, asserts the "lamport gap" text (the adoption test's second jump is `clock + LAMPORT_GAP_WARN`); `ten_pow_21_at_every_representable_scale_crosses_the_wire_signed` (m50_wire) expects the L-92 explanation instead of "Invalid number". **Revert-proven (11, each in a scratch copy, restored and compared equal):** R1 the old clock-vs-count predicate → the harness h19 joins case fails; R2 no boot gap warning → the boot test; R3 no adoption warning → the adoption test; R4 adoption judged on clock vs count → `l83_*` and the adoption test; R5 clock release dropped → `op_ab`; R6 the strip skipped → `l89_*`; R7 flush on a failed charge → `l90_*`; R8 gl-node's Want unordered → `l95_a_chain_*` (44 of 1,302 after 8 rounds, with `happy_path_small_limits_converges` passing in the same run); R9 no parent hints → `l95_a_refused_orphan_*` and the harness chain case; R10 no explanation → both `l92_*`; R11 the dangling branch dropped → `t83_*`. R8 was run in the repo tree itself (file backed up, restored, compared equal): every freshly built test binary in a scratch target lost loopback QUIC that day — untouched `happy_path_small_limits_converges` failed there too, in debug and release, and the repo's own release build failed the same way — while the repo's debug binary kept it. **Verify:** X1 `c6` adopts the honest `open` with no WARN; A2 `env-edit` serves 6, quarantines nothing, no `openledger-note` on disk; the D1 real-binary probes show the dangling-config text and the GraphQL over-long amount explanation. **Gate:** clippy `-D warnings` and `fmt --check` clean; `cargo test --workspace --locked --no-fail-fast` — **1,319 passed, 0 failed, 2 ignored** (gl-node 418, integration 8, ledger 572, exact_balances 25, property 10, p2p 187, boot_fuzz 38, convergence 21/2, decode_memory 7, m50_wire 7 — its one failure in the run was the pinned message above, fixed and re-run green —, property 5, security 21). The 2 ignored are the H-19 joins kept by decision (1). **Behaviour changes:** the H-19 WARN fires on a gap in the history, not on a clock high relative to the count, at boot and when one adoption opens it; a signature-quarantined edit no longer carries the clock; a stray `openledger-*` key is dropped at boot with a WARN; a peer at its byte budget no longer costs a commit per directive; a long chain joins in a few rounds; three clearer refusal texts. **Residuals:** L-95 helps only when the serving peer answers in the Want's order (gl-node does); a peer that ignores it is not helped; a hint table at `MAX_PARENT_HINT_IDS` records nothing more (one extra round per lost hint); L-86 and L-88 are documented, not changed.

- **Why / change, one line each:**
  - **L-94** — the clock warning's "≤ 2 × count" derivation ([service.rs:1290-1296](../crates/ledger/src/service.rs#L1290-L1296))
    does not hold across repeated fresh joins: each below-clock adoption adds one, a joiner adopts in advert
    (hex) order and stamps its inflated clock into its own directive, the next joiner climbs from there; 12
    fresh joiners over 300 accounts with no jump anywhere → `clock 2314, count 317, threshold 2292, fires true`
    (newest-first: 4042), naming an honest author and prescribing the bootstrap join. **L-83** — the
    adoption-site copy (`warn_if_clock_far_above_history`, [:4800](../crates/ledger/src/service.rs#L4800)) sees the
    post-quarantine `dag.len()` with the clock left where boot put it, so after a first signing boot that
    quarantined this node's own history the first honest adoption trips it (`lamport_clock=2004 directive_count=1
    author=<honest peer>`). Change: judge the warning on a lamport *gap* in the DAG (the largest difference
    between consecutive lamports in sorted order ≥ 2^28, a content property that cannot compound and cannot be
    shrunk by a quarantine), or keep the factor as an explicit heuristic and count the quarantine in the
    adoption-site predicate; README §Mesh identity's "your confirmation that the copy carried the gap" line.
  - **L-87** — `lamport_high.note` on `Inserted` ([:3485](../crates/ledger/src/service.rs#L3485)) runs before
    verification and `quarantine_out_of_dag` leaves the clock, so an own record whose lamport line is edited to
    ~2^32 is quarantined but the clock keeps the jump (`clock=4000000001`), the node's next writes carry it and
    the mesh follows. Change: re-derive the clock in `quarantine_out_of_dag` from survivors ∪ operator input ∪
    own records quarantined for other reasons; un-ignore `op_ab_huge_lamport_edit_of_a_quarantined_record_does_not_move_the_clock`.
  - **L-89** — the boot history arm ([:3387-3399](../crates/ledger/src/service.rs#L3387-L3399)) runs fan-in,
    envelope form and the amount cap only, so a hand-added directive-level `openledger-note` key loads as
    verified history and is written back on every compaction (local-only: `extract_envelope` filters to the
    closed set). Change: `validate_body_envelope_keys(directive, ENVELOPE_KEYS)` in the boot chain as
    `stage_remote_directive` has ([:7325](../crates/ledger/src/service.rs#L7325)).
  - **L-90** — at [anti_entropy_alpn.rs:1877-1907](../crates/gl-node/src/anti_entropy_alpn.rs#L1877-L1907) a failed
    `grow_to` flushes the chunk whatever its weight and holds the directive uncharged, and the next charge fails
    again: a peer that fills its own 32 MiB share (two of its 32 connections each pushing a 16 MiB frame) turns
    each 256-entry frame into 256 commits and fsyncs under the write permit (`4 → 256 journal records`).
    Change: flush on the weight budget only; a failed charge keeps holding (the documented uncharged residual)
    up to `PHASE_ONE_WEIGHT_BUDGET`.
  - **L-95** — Want is heads first then hex order ([anti_entropy.rs:98-118](../crates/p2p/src/anti_entropy.rs#L98)),
    256-entry chunks with a drain per chunk, and the per-peer orphan cap refuses rather than evicts
    ([orphan_buffer.rs:357-366](../crates/p2p/src/orphan_buffer.rs#L357-L366)), so a fresh join of a chain longer
    than `MAX_ORPHANS_PER_PEER` (1,000) progresses a few directives per tick (`n=3000: 83 of 3003 after 30 ticks`;
    newest-first: one per tick; ~500 "orphan buffer full" WARNs per tick). Change: Want in ascending-lamport
    order, or evict-oldest at the per-peer cap, or let the drain fetch a missing parent directly; un-ignore
    `chain_over_the_orphan_cap_joins_within_thirty_ticks_in_advert_order`.
  - **L-86** — a local record whose commit failed can already have been served in the prepare → commit → reload
    window; the caller's retry re-authors the same content id under a different envelope (`lamport 4 → 7`, other
    parents), so replicas hold one id with different parents and their head sets differ permanently (membership
    and balances converge). Change: document beside the "same body, two authors" property (README §Mesh
    identity); the harness's `Snapshot` compares heads, so note it there too.
  - **L-88** — the enable-signing remedy is replica-local: on a mesh that ran with signing off (the Done note and
    README say such history "never replicated"; it did), each replica re-authors the same ids under its own key
    and a fresh replica's attribution depends on which peer serves first. Change: README — run the remedy on
    one node and let peers re-supply; on the others delete the blocks.
  - **L-92** — README "Amounts and precision" and the T76 CHANGELOG bullet promise "any precision up to 28
    fractional digits, trailing zeros are free", but `Decimal::from_str_exact` runs before the cap
    ([scalars.rs:69](../crates/gl-node/src/graphql/scalars.rs#L69), [parse.rs:240](../crates/ledger/src/parse.rs#L240)):
    `1000000000000000000000.00000000` and `10.0000000000000000000000000000` are refused as "Invalid decimal
    string" (a hand block is quarantined as unparsable). Change: state the mantissa bound (≤ 28–29 significant
    digits in total, trailing zeros included; `10^21` admits at most 7 decimals) and map the parse failure to a
    precision message.
  - **§5 items** — `signer_installed=true` on a keyless boot (moved to T80 (e)); the dangling-link config message
    says "is a symbolic link; refusing to follow it" while a link to a regular file is followed — say "dangling";
    README §Editing: an edit that changes an amount *and* drops the lamport line is adopted as a second signed
    transaction, not refused; README nit "at most `256 / authors`" → `max(1, 256 / A)`; `health.rs:124`'s plain
    `read_to_string` of the node's own `/health` response (cap it, Info); the `ratcheted`/`refusal_log` maps
    never pruned when a peer leaves the allowlist (bounded; Info).
- **Files:** [service.rs:1290-1333, 3387-3400, 3485, 4208-4270, 4800-4826](../crates/ledger/src/service.rs#L4800),
  [anti_entropy_alpn.rs:1877-1907](../crates/gl-node/src/anti_entropy_alpn.rs#L1877), [anti_entropy.rs:98-118](../crates/p2p/src/anti_entropy.rs#L98),
  [orphan_buffer.rs:357-366](../crates/p2p/src/orphan_buffer.rs#L357), [scalars.rs:67-78](../crates/gl-node/src/graphql/scalars.rs#L67),
  [parse.rs:236-240](../crates/ledger/src/parse.rs#L236), [journal.rs:771, 893](../crates/ledger/src/journal.rs#L771),
  README, CHANGELOG.
- **Verify:** un-ignore and pass `h19_clock_warning_is_silent_on_an_honest_mesh_with_repeated_fresh_joins`,
  `chain_over_the_orphan_cap_joins_within_thirty_ticks_in_advert_order` (harness) and `op_ab_…` (fuzzer);
  X1 `c6` adopts one honest `open` after the migration boot with no WARN; A4 `a4_exhausted_peer_budget_makes_one_commit_per_directive`
  (in `…/scratchpad/A4/archive-head`) gives ≤ 4 records; A2 `env-edit` shows no `openledger-note` on disk;
  the D1 real-binary probes for the two message texts. Bug-catch proof per predicate.

---

## Residuals carried into this backlog (unchanged, for the record)

- **H-01** loopback API key (deferred by decision); the `OPTIONS`/`Allow` fingerprint is documented.
- **M-09 / M-10 / L-06** — T45 (Format v2); waves A+B wait for T79 and T80.
- **L-23 / R-9** — `meshId` required next release.
- **R-8**, **R-14 / R-15**, **R-16** — unchanged since 09/23.
- **H-19 by decision (1):** anti-entropy-only joins across a removed author's jump or a pre-T63 jump remain
  impossible by design; the two ignored harness cases document it.
- **T72** frontier inflation bounded by the file cap (quantified: one honest append drains ~255 flooded heads);
  the ratchet short-circuit keyed by peer (N hostile peers cost one fetch each).
- **T73** a keyless node serves history as loaded with one WARN; the re-sign check assumes a deterministic
  signer (the verifier decides first); the salvage joins only an unparsable tail.
- **T74** `floor (a)`'s failure path obeys the operator's removal (now stated precisely under L-93); the
  `must_rewrite` term cannot be revert-proven through a public path.
- **T75** a single 1 MiB token ≤ 9× (refused, 1× resident); frames of dense in-cap bodies ~2.7× in phase 1.
- **T76** I1 still runs on rounded weights (≤ ½ ulp at the 28th place per priced leg; pinned as acceptance);
  `OutOfRange` unreachable through any ingress (bounds checked); the multi-currency trial-balance net collapses
  currencies into one row; an inexact total may differ from its rows by ½ ulp of the total plus ½ ulp per
  inexact row.
- **T77** orphans deferred at the cap are re-fetched after the backoff (one round per 60 s window, no reload);
  the mutation estimate over-counts parents above 256 heads (safe direction); the not-allowlisted class is one
  window; `KeyedRefusalLog` at its 64-source bound never names a source that first refuses after the table
  filled (forensic only); a bad-ALPN handshake costs a TLS handshake.
- **T78** a final record hit by bit rot after its commit boots without it, loudly (single node: nothing
  re-supplies; WARN text amended under T82); `set_author_id` after `finalize_operator_input` only raises the
  clock (library misuse).
- **§5 informational items** in the 0924 report not assigned above: a pasted block signed by a non-allowlisted
  same-mesh key is verified at boot and refused by peers (consistent with "rules on content"); a pasted foreign
  full envelope with an unknown parent is adopted leniently on the live path (pre-existing); the convergence
  harness's L-34 memory is per id where gl-node's is per `(peer, id)`; HEAD's `non_fitting_totals_…` test never
  hits an exact tie (the new oracle properties do); `10^21` with 8 or 28 zeros refused before any cap (one
  verdict); mixed-version notes (a pre-T72 replica keeps the head bound until it authors or upgrades; a pre-T75
  replica's API can still author M-51's precondition live; a T71-era node refuses a HEAD node's `10^21`-exact or
  trailing-zero body until upgraded).

---

## Regression-test manifest (must exist by the end of Tier 1)

Every item is already pinned as an `#[ignore]`d case; un-ignoring it is the acceptance criterion.

1. An edited own record plus a hand-appended line in one edit converges after the restart, through the
   bootstrap join too (T79 / H-22): `h20_operator_input_stamped_at_boot_must_not_name_a_record_the_h20_pass_quarantines`,
   `op_x_…`, `op_y_…`, `op_z_…`.
2. A foreign-author half envelope is refused (or adopted as own), never served unsigned (T79 / M-54): `op_aa_…`.
3. A signing-on/P2P-off history serves whole after P2P is enabled; a boot-adopted hand line is served in the
   same lifetime (T80 / M-53, L-82): new gl-node integration test; the fuzzer pipeline under the new order.
4. A pre-T75 over-cap record and a pre-T65 over-`10^21` amount either sync to a fresh replica or are quarantined
   with their closure, loudly (T81 / M-51, M-52): `t75_over_cap_open_loaded_from_a_file_partitions_anti_entropy_joiners`,
   `over_cap_history_keeps_its_descendants_parents_resolvable_or_refuses_loudly`.
5. A 97-key hand transaction adopted with a signer round-trips through the wire validators on a second service
   (T81 / M-55): new `m50_wire.rs` case.
6. On an over-cap canonical ledger, mutations refuse pre-stage and peer chunks defer with the backoff, zero
   reloads; a pre-canonicalisation backup restore keeps the acked envelope; a damaged length over a torn
   successor is `Corrupt` (T82 / L-80, L-81, L-85): new `l80_*`, `l81_*`, `l85_*` unit tests.
7. Twelve fresh joins over an honest mesh fire no clock warning; a 3,000-chain joins within thirty ticks; an
   edited lamport of a quarantined record does not move the clock (T83 / L-94, L-95, L-87):
   `h19_clock_warning_is_silent_on_an_honest_mesh_with_repeated_fresh_joins`,
   `chain_over_the_orphan_cap_joins_within_thirty_ticks_in_advert_order`, `op_ab_…`.

Every one needs its **bug-catch proof** — revert the fix, watch the named test fail, restore — and the
orchestrator re-verifies each mechanism in source and re-runs the suite on a quiet machine. The proof crates for
every finding are in the 0924 session's scratchpad (`A1` … `A6`, `X1` … `X3`, `D1`); each pass's report §6
gives the re-run command, and the orchestrator's re-runs are under `orch/`.

---

*Audit: [SECURITY_AUDIT_0924.md](../SECURITY_AUDIT_0924.md). Previous trackers:
[OUTSTANDING_TASKS_09_23.md](OUTSTANDING_TASKS_09_23.md) (T72–T78) ·
[OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md) (T61–T71) ·
[OUTSTANDING_TASKS_09_22.md](OUTSTANDING_TASKS_09_22.md) (T46–T60, R-1…R-21) ·
[OUTSTANDING_TASKS_09.md](OUTSTANDING_TASKS_09.md) (T18–T45) · [OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md)
(T1–T17). Format v2 design: [FORMAT_V2_DESIGN.md](FORMAT_V2_DESIGN.md).*
