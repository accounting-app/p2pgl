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

## Priority order at a glance

| # | Findings addressed | Sev | Effort | Status |
|---|---|---|---|---|
| T79 | H-22 + M-54 + L-75 remainder — operator input after verification | **High** | S–M | ☐ |
| T80 | M-53 + L-82 + L-91 + §5 banner — the author id is the key | Med | S | ☐ |
| T81 | M-51 + M-52 + M-55 + M-50/M-47 remainders — upgrade paths for every content rule; count the envelope | Med | M | ☐ |
| T82 | L-80 + L-81 + L-84 + L-85 + L-93 — the over-cap state, the floor's identity check, the torn rule, the symlinked `.bean` | Low | S | ☐ |
| T83 | L-83 + L-86 + L-87 + L-88 + L-89 + L-90 + L-92 + L-94 + L-95 + §5 — diagnostics, cost bounds, docs | Low | S | ☐ |

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

### ☐ T79 — Operator input after verification (H-22, M-54, L-75 remainder) — S–M, decision (7) taken
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

### ☐ T80 — The author id is the key (M-53, L-82, L-91, §5 banner) — S, decision (8) taken
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

### ☐ T81 — Upgrade paths for every content rule; count the envelope (M-51, M-52, M-55; M-50 and M-47 remainders) — M, decision (6) taken
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
  `MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY` (proposed 4,096 each: far above any honest list, far below
  the M-48 floods; the exact numbers are the implementer's call, recorded in `limits.rs` with the reasoning) —
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

### ☐ T82 — The over-cap canonical state, the floor's identity check, the torn rule, the symlinked `.bean` (L-80, L-81, L-84, L-85, L-93) — S
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

### ☐ T83 — Diagnostics, cost bounds and docs (L-83, L-86, L-87, L-88, L-89, L-90, L-92, L-94, L-95, §5) — S
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
