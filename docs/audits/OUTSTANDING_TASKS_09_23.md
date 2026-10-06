# Outstanding Security Tasks — 2026-09-23

Remediation backlog for every open finding in [SECURITY_AUDIT_0923.md](SECURITY_AUDIT_0923.md), the
re-audit of T61–T71. Task numbering continues from [OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md)
(T61–T71, all ☑). Line references are current as of HEAD `af14603`.

**Already closed — do not re-do:** the 0923 audit verified **31** register entries closed by mechanism
(H-12, H-13, H-14, H-15, H-16, H-17, H-18 · M-06, M-35 … M-45 · L-35, L-43, L-55 … L-63, L-65). See
[SECURITY_AUDIT_0923.md §1](SECURITY_AUDIT_0923.md). This tracker covers only what is open: three new
Highs, five new Mediums, thirteen new Lows, the informational items worth a line of code, and the carried
partials (L-64, L-66, L-23).

**Status legend:** ☐ not started · ◐ in progress · ☑ done
**Effort:** S = < ½ day, M = ~1–2 days.

> **The shape of this backlog.** The 0922 audit found its Highs inside T18–T44's code, 0922-v2 found them
> inside T46–T60's code, and 0923 finds them inside the *decisions* T63 and T64 recorded as accepted
> deviations and in the one assumption T61's file path still makes. The through-line: **each fix compares
> against a number only this replica holds — its clock, its heads, its staged count — where the property
> is a mesh property; and boot trusts a classification the file cannot enforce.** T72 and T73 are therefore
> organised around restating each rule on the *content* and around verifying what boot loads, not around
> patching the symptoms one at a time. Every task keeps the campaign's rule: revert the fix → the named
> test fails → restore; residuals go in this file, not in code comments.

> **Decisions taken 2026-09-23** (user), recorded once here and referenced from the tasks: work lands in
> the tree uncommitted, at wave boundaries; **two harnesses are built first** and must fail at HEAD before
> T72/T73 land against them — a multi-replica convergence harness (N services, one directive set,
> randomised and adversarial delivery orders and subsets, equal DAGs and balances at the fixed point) and a
> boot file-edit fuzzer (mutate a node-written `.bean`, boot, assert nothing served would be refused by a
> peer); (1) H-19 — **revised after the first choice was shown not to close it**: no per-directive bound can
> let a fresh node cross a removed author's jump by anti-entropy alone (an honest node that adopted a
> 2^32 jump legitimately stamps 2^32 + 1 above its parents; an attacker *transaction* already partitions
> joiners through `MissingParent`), so the ratchet **stays as it is**; the fix is a **trusted-bootstrap
> join** (a fresh node boots from a peer's `.bean`, which loads as history — works at HEAD and is pinned by
> the harness), a boot/adoption **warning** when the clock is far above the directive count, and remedy and
> residual text stating that removing an in-history author requires bootstrap joins; (2) H-21 — the remote per-author head bound is **dropped**; (3) H-20 — an own record whose
> signature does not verify at boot is **quarantined**, rating stays High; (4) M-50 — **exact `i128`
> accumulation now** (per-scale `i128` partials with a posting count; design note
> `scratchpad/T76-design/DESIGN.md`, tests `crates/ledger/tests/exact_balances.rs`). **Refined
> 2026-09-23 after the design phase:** the 21-significant-digit cap is **replaced by one magnitude cap,
> `|amount| ≤ 10^21` at any precision, applied on every path** (authoring, peers, boot, journal alike — a
> content rule, no authoring/history split); `balance` and `price` amounts are uncapped (never summed).
> This admits the M-50 trailing-zero history and makes an unrepresentable total impossible for anyone; the
> design's "peers are history, uncapped" option was rejected because two `Decimal::MAX` postings from one
> allowlisted peer would make an account and the trial balance unreadable on every replica. A total that
> does not fit 96 bits at its printed scale is **rounded once, half to even, and flagged `exact: false`**;
> balance assertions and `verify` compare against the exact sum. GraphQL change is **additive only**
> (`exact: Boolean!`); `BalanceAssertionFailure.actual` stays non-null; `OutOfRange` is an internal typed
> error for the unreachable 2^31-postings case. The read-time wide integer is an in-crate `i256`, checked by
> the test file's oracle; (5) M-48 — rating stays Medium, fix as
> specified. Scope of the first wave: the two harnesses, then T72 and T73.

## Priority order at a glance

| # | Findings addressed | Sev | Effort | Status |
|---|---|---|---|---|
| T72 | H-19 + H-21 + L-68 + L-69 — rules on content, not on the replica | **High** | M | ☑ |
| T73 | H-20 + M-47 + L-74 + L-75 + L-76 + L-77 — boot verifies what it loads | **High** | M | ☑ |
| T74 | M-46 + M-49 + two Info items — the recovery floor and the reload-failure arm | Med | S | ☑ |
| T75 | M-48 + L-78 — wire cardinality caps before staging | Med | S | ☑ |
| T76 | M-50 + Info (trailing zeros) — an upgrade path for over-cap history | Med | M | ☑ |
| T77 | L-70 + L-71 + L-72 + L-73 + Info (throttles, headroom estimate) — near-cap and edge cost bounds | Low | S | ☑ |
| T78 | L-67 + L-79 + L-64 + L-66 + Info (docs, sweep, journal doc, CHANGELOG/README omissions) — hygiene | Low | S | ☑ |

**Coverage check — every open register entry maps to exactly one task:**

H-19→T72 · H-20→T73 · H-21→T72 · M-46→T74 · M-47→T73 · M-48→T75 · M-49→T74 · M-50→T76 · L-67→T78 ·
L-68→T72 · L-69→T72 · L-70→T77 · L-71→T77 · L-72→T77 · L-73→T77 · L-74→T73 · L-75→T73 · L-76→T73 ·
L-77→T73 · L-78→T75 · L-79→T78 · L-64→T78 · L-66→T78.

**Deferred by design to T45 (Format v2), unchanged:** M-09, M-10, L-06. **Deferred by decision, unchanged:**
H-01's loopback API key; L-23 (`meshId` required next release).

**T45 interaction:** waves A and B wait for **T72 and T73**, since both touch the envelope rules Format v2
re-specifies (the ratchet's reference field and the verification of own history).

**Landing order:** T72 → T73 (both are mesh-divergence Highs and both live in `service.rs`; T72's (a)/(b)
need decisions (1)/(2), so if those are slow, land T73 first) → T74 (shares `finish_recovery` with nothing
else; after T73 because both touch `adopt_file_directive`'s `pending_ids` push) → T75 ∥ T76 (disjoint
files: T75 owns `union_merge.rs`/`parse.rs` block loop, T76 owns `validate.rs`/`read_model.rs`/`parse.rs:206`)
→ T77 → T78. `service.rs` is the contention point again: T72, T73, T74 go to one agent in that order or run
sequentially; T75, T76, T77 can run alongside.

---

## Tier 1 — ship-blockers (the three new Highs)

### ☑ T72 — Rules on content, not on the replica (H-19, H-21, L-68, L-69) — M, plus decisions (1) and (2)
> **Done 2026-09-23 (committed `f06cb12`).** (b) **H-21:** the remote per-author unmerged-head bound is gone — `check_unmerged_head_bound`, `MAX_UNMERGED_HEADS_PER_AUTHOR`, `ServiceError::UnmergedHeadLimit` (`UNMERGED_HEAD_LIMIT`), `LedgerDag::heads_authored_by` and the gl-node classification arm removed; `choose_parents`'s truncation and `validate_parent_fan_in` (what closes H-16) unchanged. `h21_disjoint_subset_delivery_of_a_parentless_flood_converges_without_local_authoring` un-ignored and passing. **L-68:** parent choice is `pub fn select_parents`: with `A` distinct head authors at most `max(1, MAX_PARENTS / A)` heads per author smallest-id first, then remaining slots by smallest id — a pure function of the head set, so replicas holding the same heads name the same parents (two-service determinism test). (a) **H-19, decision (1) revised:** `check_lamport_advance` byte-identical. `clock_is_far_above_history(clock, count) = clock > 4 × count + 1024` warns at boot (third branch, naming the suspect author) and at all three adoption sites, gated once per boot then once per 2^20 of clock advance. One `BOOTSTRAP_JOIN_REMEDY` constant ends the `LamportCeiling` remedy, both boot ceiling warnings, the new warning and the `LamportAdvance` message: removing an in-history author means every later joiner and every rebuilt node joins by copying a current peer's compacted `.bean` and booting it under its own key; an attacker transaction has the same effect through `MissingParent`. README §Mesh identity gains "Joining a mesh / removing a peer" with the exact steps `h19_fresh_node_bootstrapped_from_a_peers_file_converges` performs. (d) `highest_lamport_author` and boot's suspect author prefer the highest-lamport directive not authored by this node. (c) **L-69:** `LamportAdvance` stays uncached (not permanent) but `SupplyBackoff` gains an exact per-`(peer, id)` short-circuit: a refusal against `remote` is held out of the Want until the local clock reaches `remote − MAX_LAMPORT_ADVANCE + 1` (the verdict is a pure function of `(remote, local)` and the clock only rises; bounded at 4,096 ids per peer and `SUPPLY_BACKOFF_MAX_PEERS`, at a cap nothing is recorded); recorded from the direct stage path and the orphan drain, never for pushed batches; the "rejected remote directive" warn is one line per peer per 10 s with `suppressed=N`. **Design deviations, accepted:** the warning threshold is `4 × count + 1024`, not `2 × count` — 2× is exactly the honest bound (every adoption, including of a remote below the clock, adds one: harness finding F1) and would false-fire; 4× plus slack cannot, and still fires on any ≥ 2^32 gap under the file cap. Orchestrator re-ran: convergence harness 9 passed / 2 ignored, workspace 1,169 passed / 0 failed / 2 ignored, clippy and fmt clean. **Behaviour changes:** a peer's transaction is never refused for its author's head count; a local append may name a different 256 of the same heads (still ≤ `MAX_PARENTS`, ascending, deterministic); new WARN lines on histories carrying a jump (also fires on the existing NEAR-CEILING fixtures); the ALPN refusal warn is throttled per peer; ratchet-refused ids are not re-fetched while the clock cannot change the verdict. **Existing tests changed:** `test_h16_unmerged_head_bound_is_per_author_and_admits_honest_shapes` replaced by `test_h21_the_257th_parentless_remote_transaction_from_one_author_is_admitted`; `test_h16_parentless_flood_cannot_make_a_local_append_over_cap` asserts order/head-membership/peer-b named instead of "the 256 smallest"; `test_state_dependent_stage_refusals_are_not_cached` loses its `UnmergedHeadLimit` case; convergence case 2 asserts every replica holds the whole flood. **Revert-proven (13):** `test_h21_…`, the two `h21`/`single_subset` harness cases (bound re-inserted), `test_l68_parent_choice_names_the_honest_head_among_256_planted_small_ids`, `test_l68_select_parents_is_author_diverse_then_smallest_and_deterministic`, `test_h19_boot_warns_when_the_clock_is_far_above_the_directive_count`, `test_h19_adoption_warns_once_per_jump_and_names_the_jumping_author`, `test_h19_clock_is_far_above_history_predicate`, `test_h12_ceiling_diagnostics_name_the_peer_not_the_victim_that_authored_on_top`, `test_h19_remedy_texts_state_the_bootstrap_join`, `ratchet_deferral_holds_an_id_exactly_until_the_clock_can_adopt_it`, `ratchet_refused_directive_is_wanted_once_until_the_clock_moves` (real ALPN over loopback), `stage_refusal_warn_is_one_line_per_peer_per_interval_with_a_count`. **Residuals:** anti-entropy-only joins across a removed author's jump or a pre-T63 jump remain impossible by design (two ignored harness cases document it); frontier inflation by a flooding peer is bounded only by the file cap (a cost every replica pays alike, not a divergence); the short-circuit is keyed by peer, so N hostile peers serving one refused id cost one fetch each; the refusal throttle covers every stage refusal from a peer; the T63/T64 residual sentences in `OUTSTANDING_TASKS_09_22_v2.md` are superseded (pointer added there).
- **Why:** two of the three Highs are the same mistake. **H-19:** `check_lamport_advance`
  ([service.rs:1208-1220](../../crates/ledger/src/service.rs#L1208-L1220)) refuses `remote − local ≥ 2^32`
  where `local` is *this node's* clock, and T63 deliberately gave no first-contact exemption. One allowlisted
  peer authors one legal directive at `local + 2^32 − 1`; the honest mesh adopts it and stamps above it; the
  operator follows the remedy the code prescribes (allowlist removal, [:1598-1606](../../crates/ledger/src/service.rs#L1598-L1606),
  [:2917-2924](../../crates/ledger/src/service.rs#L2917-L2924)) — and every future node, and every node restored
  from an empty disk, is permanently unable to adopt anything authored after the jump (the first post-jump
  honest directive sits exactly `2^32 + 1` above the pre-jump clock; the bridge is refused at intake as
  not-allowlisted, a permanent cached refusal). A pre-T63 mesh carrying any jump ≥ 2^32 is in the same state
  with no attacker. Neither boot warning fires (both are anchored to the ceiling, [:2913, :2926](../../crates/ledger/src/service.rs#L2913)).
  The partition is asymmetric — the stuck node's own writes are accepted — and the Done-note residual
  ("cannot be joined until that directive is removed") is wrong: removing it changes nothing, the honest
  history after it *is* the gap. Proof: `D3-lamport-heads/proof hunt.rs h1a/h1b`. **H-21:**
  `check_unmerged_head_bound` ([service.rs:5808-5825](../../crates/ledger/src/service.rs#L5808-L5825)) refuses a
  parentless transaction when its author owns 256 heads *on this replica* ([dag.rs:452](../../crates/ledger/src/dag.rs#L452)).
  A peer serves replica A the subset `{0..255}` of 257 parentless transactions and replica B `{1..256}`;
  each refuses the 257th; A↔B anti-entropy cannot repair it. Same available set, two permanently different
  committed DAGs; self-heals only when *each* replica authors locally; an observer replica diverges
  indefinitely. The remote refusal is redundant — `choose_parents`'s `truncate(MAX_PARENTS)` ([:3656](../../crates/ledger/src/service.rs#L3656))
  already closes H-16's brick. Proof: `X2-convergence/probe 3b`.
- **The Lows this closes with it:** **L-68** — naming any current head is admitted without counting
  ([:5811-5816](../../crates/ledger/src/service.rs#L5811-L5816)), so one author's heads climb past 256 by one
  per honest head consumed, and an id-grinder keeps `choose_parents` naming only attacker heads (each honest
  append becomes a permanent head mesh-wide). **L-69** — `LamportAdvance` and `UnmergedHeadLimit` are
  retried uncached ([anti_entropy_alpn.rs:1735-1746](../../crates/gl-node/src/anti_entropy_alpn.rs#L1735-L1746)),
  so N manufactured refusals are re-fetched, re-parsed, re-verified and re-validated every tick: 32 × 1 MiB
  cost 2.73 s/tick plus 30 MiB of transfer per hostile peer, indefinitely.
- **Decisions (pending):** (1) the ratchet's reference point; a trusted-bootstrap join. (2) whether any
  remote frontier cap survives.
- **Change:** (a) **the ratchet stays** (decision (1), revised): no per-directive bound lets a fresh node
  cross a removed author's jump by anti-entropy alone, so the fix is procedural — document and pin the
  **trusted-bootstrap join** (a fresh node copies a peer's `.bean` and boots it as history; the harness case
  `h19_fresh_node_bootstrapped_from_a_peers_file_converges` pins that it works); add a `warn!` at boot and at
  adoption whenever `lamport_clock > 2 × directive_count` (honest clocks are bounded by events seen), naming
  the author of the highest lamport; correct the `LamportAdvance` message ("accepted once the intervening
  directives have arrived" is false when they never can), the `LamportCeiling`/boot remedy text (removing an
  in-history author from the allowlist requires every *later* joiner to bootstrap from a peer's file, and
  for an attacker *transaction* the same holds through `MissingParent`), and the T63 residual; README §Mesh
  identity gains the join procedure. (b) drop the remote `UnmergedHeadLimit` refusal; if a frontier cap is wanted it must
  be content-deterministic (every replica drops the same heads, e.g. lexicographically largest above the cap);
  choose parents by author diversity (at most N per author) or newest-lamport-first so an id-grinder cannot
  starve honest heads. (c) cache `LamportAdvance` refusals keyed on `(peer, id, local clock)` and invalidate
  on a clock change; cache `UnmergedHeadLimit` until the author's count drops (moot if (b) removes it);
  rate-limit the per-refusal warn. (d) fix the `LamportCeiling` diagnostic that names the victim once it has
  authored on top of the poison ([:3684-3692](../../crates/ledger/src/service.rs#L3684-L3692)).
- **Files:** [service.rs:1132-1300, 3656-3700, 5808-5825, 5869-6060](../../crates/ledger/src/service.rs#L1208),
  [dag.rs:411-463](../../crates/ledger/src/dag.rs#L411), [union_merge.rs:342-346](../../crates/p2p/src/union_merge.rs#L342-L346),
  [anti_entropy_alpn.rs:1866-1940](../../crates/gl-node/src/anti_entropy_alpn.rs#L1866), README §Mesh identity
  (the remedy text).
- **Verify:** the `h1b` shape — A and B adopt `local + 2^32 − 1` from X, author on top, X is dropped from the
  allowlist and the served set: a fresh node **bootstrapped from A's file converges** (harness case; passes at
  HEAD and must keep passing), the anti-entropy-only join stays a documented, ignored harness case, and the
  new warning fires on A, B and the joiner; the `h1a` pre-T63 shape boots with the warning naming the gap; a dense history still converges in ascending, descending and
  interleaved order (`X2 probe 4`); the `3b` disjoint-subset two-replica shape gives **equal DAG membership**
  with no local authoring (fails at HEAD; every `test_h16_*` today is single-replica); 256 planted small-id
  heads plus one honest head → the local append names the honest head; 4,096 ratchet-refused ids cost one
  fetch, not one per tick. Bug-catch proof for each predicate separately.

### ☑ T73 — Boot verifies what it loads (H-20, M-47, L-74, L-75, L-76, L-77) — M, plus decision (3)
> **Done 2026-09-23 (committed `f06cb12`).** Landed against `crates/p2p/tests/boot_fuzz.rs` as its spec: all 14 previously `#[ignore]`d harness tests enabled and green, every operator in `OPERATORS_ENABLED`, `Checks::AT_HEAD` gone, `boot_fuzz_all_operators` green over all 18 operators (23/23). (a) `DirectiveVerifier` + `LedgerService::set_verifier` mirror the signer; `main.rs` builds it from `security::signing::verify_signature` over the wire's `SignableMessage`/mesh id and installs it right after `set_signer`; carried across `adopt_reloaded`. (b) `verify_own_history()`: boot records every enveloped directive in `unverified_history`; the pass runs from `set_signer`, `set_verifier`, `finalize_operator_input`, `finish_recovery` and explicitly from `main.rs` before the startup compaction. Verdict by the verifier (own or foreign author); without one, an own record is checked by deterministic re-signing; missing signature or lamport on an enveloped record is a refusal. Refusals are quarantined via `quarantine_out_of_dag` (DAG/read model/account state rebuilt from survivors; L-35 snapshot reset), per-id WARN "signature does not verify — was this record edited? (H-20)" plus a banner. **Design deviation, accepted:** the verify pass is also triggered by the setters, so a node whose harness or caller never installs a verifier still verifies its own records through the signer (each directive verified once). (c) `split_ledger_blocks` records contiguity; `salvage_unparsable_blocks` demotes a parsed head into the same raw block as an unparsable tail with no blank line between; boot quarantines a salvaged transaction failing I1/I2 (salvage path only); banner no longer says "nothing is lost". (d) `is_operator_input := !author || !lamport`; pre-existing signature stripped when stamping, lamport always re-stamped, author stamped when absent; a file-spelled foreign author keeps T41 warn-and-adopt (tracked so finalize never overwrites it). (e) hand-spelled parents must resolve in DAG ∪ quarantine (quarantine at boot, reject live). (f) every boot quarantine arm uses `quarantine_keeping_envelope` (enveloped spelling wins). (g) `ReadModel::reindex_directive` from `finalize_operator_input`. (h) hand `open` of an open account refused on both file paths. Also: the live reconcile refuses a pasted full envelope whose signature does not verify. (i) README §Editing rewritten; CHANGELOG bullets under Breaking/Changed/Security. Eleven new revert-proven unit tests (`h20_*` ×5, `l45_a_split_transaction_block_is_quarantined_whole_not_loaded_truncated`, `m47_*`, `l75_*`, `l76_*`, `l74_*`, `l77_*`); three `h13_*` tests, `t44b_*` and two `union_merge.rs` tests (`test_a_recovered_commit_failure_still_signs_the_next_adoption`, `test_reconcile_refuses_an_uppercase_parent_the_mesh_would_refuse`) were changed because they encoded the old "unsigned own record loads beside a signer" behaviour or named a nowhere-parent (the orchestrator applied the `union_merge.rs` patch). Orchestrator re-ran the boot fuzzer (23/23) and the workspace (1,157 passed, 0 failed, 3 ignored), clippy and fmt clean. Boot cost, release, cap-sized 130k-directive ledger: signer pass 2.60 s (20 µs/record), verifier-only pass 6.03 s (46 µs/record), one edited record incl. rebuild 4.66 s. **Behaviour changes:** with a signer, an own enveloped record whose signature is missing or does not verify is quarantined at boot and after any reload — **a history written before signing was enabled is quarantined at the first signing boot**; remedy: delete the `openledger-*` lines of those blocks so boot re-adopts them as signed operator input (WARN, README, CHANGELOG say so; with signing disabled nothing changes). Half envelopes are operator input on both paths; dangling hand parents and hand re-opens refused; split blocks held whole; `journal` serves the finalised envelope at once. **Residuals:** a keyless node (no signer, no verifier) serves history as loaded with one WARN; the re-sign check assumes a deterministic signer (the verifier decides first when installed); the salvage joins only an unparsable *tail* to the block above; pre-existing L-14 budget refusal on 130k-long straight chains (2 records quarantined before any signer exists) — record for T77/T78.
- **Why:** **H-20.** `is_operator_input` ([service.rs:3036-3039](../../crates/ledger/src/service.rs#L3036-L3039))
  makes anything carrying an author and a lamport *history*, and the history path
  ([:2826-2880](../../crates/ledger/src/service.rs#L2826-L2880)) checks fan-in, envelope form and the amount cap —
  never the signature (the crate has no verifier) and never I1. Two doors through the README's supported
  stop → edit → start workflow: (a) the operator corrects a narration typo or an amount in a line the node
  wrote; boot loads it under a **new** content id with the **old** signature, zero WARN, the startup
  compaction persists it, every signing peer refuses it (`InvalidSignature`, cached), the node's next write
  names it as a parent and everything authored afterwards is orphaned mesh-wide; an amount edit diverges
  balances (`this node 13.00 / peer 10.00`). (b) a stray dedent, BOM or word inside a node-written transaction
  makes `split_ledger_blocks` ([:433-489](../../crates/ledger/src/service.rs#L433-L489)) start a new block, and
  `salvage_unparsable_blocks` ([:528-548](../../crates/ledger/src/service.rs#L528-L548)) loads the parsable head
  as a *complete* transaction (0 or 1 postings) with the original envelope, keeping `+100` and dropping the
  `−100`, while the banner says "nothing is lost". Proofs: `X1-adoption-interplay/x1probe p12`,
  `D1-filepath/probe split`. README §Editing ([README.md:702-780](../../README.md#L702-L780)) describes only
  *adding* lines and never says "do not edit an existing record". **M-47.** A half envelope — author *or*
  lamport, not both — is history at boot (raw, unlamported or unauthored, unsigned, a head, zero WARN, a
  fixed point on disk) but operator input on the live reconcile (`needs_stamp` [:5201](../../crates/ledger/src/service.rs#L5201)):
  T61's decision text says "a node never writes a directive without author *and* lamport", the code tests
  "lacks both". Peers refuse it with `EnvelopeMissing`; the next write is orphaned. Proof: `x1probe p1`.
- **The Lows this closes with it:** **L-74** — `finalize_operator_input` rewrites the DAG copy only; the read
  model keeps boot's clone, so `journal` serves the hand record as `author: "local"`, unsigned, until restart
  (`x1probe p3`). **L-75** — hand-typed `openledger-parents` are honoured verbatim ([:5294](../../crates/ledger/src/service.rs#L5294));
  a parent that exists nowhere becomes a signed head and every later write is orphaned on peers, no WARN
  (`x1probe p9`). **L-76** — the boot cycle arm's `quarantined.insert` ([:2760](../../crates/ledger/src/service.rs#L2760))
  lets a later envelope-less spelling replace the signed one; the compaction drops the signed copy and the
  next boot re-authors it (`x1probe p4`). **L-77** — a hand `open` of an already-open account is adopted at
  boot and live while the API refuses it (`AccountAlreadyOpen` [:3442](../../crates/ledger/src/service.rs#L3442)
  vs [:5381-5423](../../crates/ledger/src/service.rs#L5381-L5423)); currencies get re-constrained.
- **Decision (pending):** (3) quarantine (recommended) vs refuse-to-boot for an own record whose signature does
  not verify; whether H-20 stays High.
- **Change:** (a) a `set_verifier(DirectiveVerifier)` mirroring `set_signer`, installed in `main.rs` right
  after `set_signer`, and a `verify_own_history()` pass before the startup compaction: for every directive
  whose author is this node — and, since the author id *is* the key, every foreign-authored one too — verify
  the signature; on failure quarantine it with the reason "signature does not verify — was this record
  edited?" (the compaction keeps it in the file, H-08); a truncated fragment fails the same check because its
  signature was made over the original id. (b) in the salvage, an unparsable block with no blank line before
  it belongs to the block above: demote the parsed head into the same raw `UnparsableBlock`; quarantine any
  salvaged transaction that fails I1; fix the banner. (c) `is_operator_input := !author || !lamport`, or
  quarantine exactly-one-of in `validate_file_envelope_form` with an `EnvelopeMissing` reason; strip a
  hand-typed signature when `needs_stamp`; warn or refuse an entry that cannot be signed (lamport-only on the
  live path, [:5553](../../crates/ledger/src/service.rs#L5553)). (d) require hand-spelled parents to resolve, else
  quarantine. (e) `entry().or_insert` in the cycle arm, preferring the enveloped spelling. (f) re-index the
  finalized directive in the read model. (g) `AccountAlreadyOpen` parity on both file paths. (h) README
  §Editing: never edit an existing record, append a reversing entry; a deleted signed line is re-supplied by
  peers; adoption is one-way; the lamport-only exception.
- **Files:** [service.rs:433-548, 2760-2880, 3036-3039, 3145-3230, 5129-5420, 5553](../../crates/ledger/src/service.rs#L433),
  [read_model.rs](../../crates/ledger/src/read_model.rs) (re-index), [main.rs:421-468](../../crates/gl-node/src/main.rs#L421),
  `security/src/signing.rs` (a verifier the ledger crate can call through a closure, as the signer is),
  [README.md:702-780](../../README.md#L702-L780).
- **Verify:** the `p12` shape — boot on an edited signed body quarantines it, `directive_count` stays, and
  everything served passes `verify_remote_signature`; `l45_a_split_transaction_block_is_quarantined_whole_not_loaded_truncated`
  (`split-dedent2` and `dedent1`); the `p1` shape — both half lines carry author, lamport, parents and
  signature after boot + finalize (or are quarantined) and `validate_supply_entry` accepts what is served;
  `p3` — `journal` and `transaction` agree after finalize; `p9` — a dangling hand-spelled parent is
  quarantined; `p4` — the signed copy survives; `reopen` — a hand `open` of an open account is refused on
  both file paths. The existing `h13_*` peer-acceptance assertion should run `validate_supply_entry` +
  `verify_remote_signature`, not only `stage_remote_directive` (a proxy).

---

## Tier 2 — recovery, wire and upgrade

### ☑ T74 — The recovery floor and the reload-failure arm (M-46, M-49, two Info items) — S
> **Done 2026-09-23 (committed `f06cb12`).** **M-46:** ids adopted *from the file* no longer go onto `pending_ids`; `adopt_file_directive`'s two `Inserted` arms (which boot's operator-input adoption also uses) record them in a new `adopted_from_file` set, cleared by a `Compact` receipt, pruned by `quarantine_out_of_dag`, counted in the L-43 fingerprint and not carried by `adopt_reloaded`. `prepare`'s `must_rewrite` gains `|| !adopted_from_file.is_empty()` (belt and braces: every adoption path already forces the rewrite). `uncommitted_count()` counts staged directives only and is 0 right after any boot. `finish_recovery` refuses a rebuild that lacks **any** memory id outside `pending_ids ∪ adopted_from_file` (`committed_ids_missing_from` over the new `LedgerDag::ids()`); the refusal log adds `missing` and a sample of up to 8 ids; the install log reports exact `discarded_staged` and `discarded_file_adopted`. The seven genuine staging sites are unchanged. **M-49:** `finish_recovery`'s `Err` arm sets `force_compaction = true` and `journal_torn_at_boot = true`; the refusing arm ORs in `reloaded.journal_torn_at_boot`. **Design deviations, accepted:** (1) the per-id check is the real guard and the count floor a cross-check — the exact count floor would refuse `floor (a)` (the operator removed their own un-canonicalised hand lines), which T62 requires to install; (2) a failed reload keeps the journal as a sidecar every time, not only when the error names the journal, because the failed read is the one that would have judged it ("never unlink on a heuristic"); the cost when the journal was healthy is one redundant sidecar and a WARN. Orchestrator re-ran the six new tests plus every `h15_*`/`l64_*`/`l43_*` test (12 passed) and the probe outputs: `floor (b)` REFUSING, memory 7, next write 8 on disk with `Acked1` present; `floor (b3)` REFUSING, `F000498` kept on disk; `torn` B next commit `Compact`, reboot Ok with 5 directives; `sidecars (b)`/(c) one sidecar each. README §Editing and §The commit journal and the CHANGELOG updated by the orchestrator. **Behaviour changes:** a failed commit after a content-replacing edit (a backup `cp`'d over the live file) now refuses the rebuild and the next commit writes the union; `uncommitted_count()` excludes file-adopted directives; after a failed reload the next commit is always `Compact` and the journal becomes a `.torn-*` sidecar; a refused reload of a torn journal renames it; log lines reworded (still contain `REFUSING`, `H-15`, `L-13 reload installed`). **Existing tests changed:** none. **Revert-proven (6):** `m46_a_live_file_replacement_and_a_failed_commit_keep_every_acked_record`, `m46_boot_adopted_operator_input_does_not_lower_the_recovery_floor`, `m46_uncommitted_count_is_zero_after_a_boot_that_adopted_operator_input`, `m46_a_reload_after_removing_ones_own_hand_lines_still_installs`, `m49_a_failed_reload_after_a_torn_append_forces_a_compaction_and_the_reboot_succeeds`, `m49_a_refused_reload_keeps_the_torn_journal_fact_so_the_journal_is_renamed_not_unlinked` (eight separate reverts, each restored byte-for-byte). **Residuals:** `floor (a)`'s failure path obeys the operator's removal while its success path writes the lines back (L-30 union) — kept by spec from T62; the `must_rewrite` term cannot be revert-proven through a public path; a refused rebuild on a disk that keeps failing repeats refuse → rewrite fails → refuse with memory kept (no wedge, unchanged); an H-20-shaped content edit plus a failed commit now refuses where it used to install, matching the success path.
- **Why:** **M-46.** `finish_recovery`'s floor is `dag.len() − pending_ids.len()`
  ([service.rs:4356-4360](../../crates/ledger/src/service.rs#L4356-L4360)), meant as "what a failed commit may
  legitimately have left behind". But `adopt_file_directive` pushes the ids it adopts *from the file* onto
  `pending_ids` ([:5364, :5407](../../crates/ledger/src/service.rs#L5364)) and boot's operator-input adoption does
  the same ([:3062-3070](../../crates/ledger/src/service.rs#L3062-L3070)), so the floor is understated by exactly
  that number. A `cp` of a backup over the live file (removes M acked lines, adds N ≥ M) plus one failed
  commit installs the replacement over memory: `before=7 after=3 discarded_staged=4`, `Acked1..3` gone from
  memory and, after the next write, from disk. The T61-adoption × T62-recovery interaction. Proof:
  `D2-recovery-journal/d2probe floor` (b, b3; controls a, b2, c, d). **M-49.** `finish_recovery`'s
  `Err(reload_error)` arm ([:4385-4392](../../crates/ledger/src/service.rs#L4385-L4392)) leaves `force_compaction`
  as it was (the refusing arm at :4372 sets it) and carries no `journal_torn_at_boot`. A torn append followed
  by a failed reload → the next commit is an `Append` behind the torn tail → T68's classifier makes the
  journal `Corrupt` → the next boot refuses (`LEDGER_JOURNAL`) with an acked record behind the tail. The
  09/22-v2 §5 item, escalated by T68. Proof: `X3-commit-recovery/x3probe torn` case B.
- **Info items closed with it:** a *refused* reload also discards the rebuilt `journal_torn_at_boot`, so the
  following compaction unlinks a torn journal instead of renaming it (`d2probe sidecars`); the
  `uncommitted_count()` doc ("non-zero only between a staged mutation and its commit",
  [:3821](../../crates/ledger/src/service.rs#L3821)) is false after a boot that adopted operator input; the install
  log's `discarded_staged` label counts file-adopted ids.
- **Change:** keep file-adopted ids out of `pending_ids` (a separate `adopted_from_file` counter feeds the
  "nothing to do" short-circuit and `uncommitted_count`), and/or refuse a rebuild in which any non-pending
  memory id is absent (an `ids()` iterator on `LedgerDag`, O(N) lookups; proven on a scratch copy: both
  shapes refuse, 20 recovery tests pass); in the `Err` arm set `force_compaction = true`; carry
  `journal_torn_at_boot |= reloaded.journal_torn_at_boot` on the refusing arm and re-derive it on the `Err`
  arm from the failed attempt; fix the doc and the label.
- **Files:** [service.rs:3062-3070, 3821, 4334-4420, 5364, 5407](../../crates/ledger/src/service.rs#L4334),
  [dag.rs](../../crates/ledger/src/dag.rs) (`ids()`).
- **Verify:** `floor (b)` — three acked opens, three different opens written over the file, commit under an
  unwritable directory → `REFUSING`, memory keeps six, the next commit writes seven; `floor (b3)` at boot;
  `floor (c)` still refuses and `(a)` (operator removed their own hand lines) still installs; `torn` case B —
  the next commit is `Compact`, the reboot succeeds, one `.torn-*` sidecar; `sidecars (b)` — a refused reload
  over a truncated journal still leaves a sidecar; `uncommitted_count() == 0` right after a boot with
  operator input.

### ☑ T75 — Wire cardinality caps before staging (M-48, L-78) — S, plus decision (5) on the rating only
> **Done 2026-09-23 (committed `f06cb12`).** (1) `validate_supply_entry` calls `ledger::service::enforce_resource_limits` on the directive as soon as it is parsed — before the hash, the body checks and the envelope merge — so nothing over a §3.12 cap can leave intake and be queued in phase 1; the refusal maps to `MergeError::ResourceLimitExceeded`, already permanent, so no classifier change. (2) `parse_file_bounded(input, max_errors, limits: ParseLimits)` counts postings, tags, links, distinct directive metadata keys, posting metadata keys (summed per transaction) and `open` currencies inside the block loop and stops at the first item past a cap; body lines are counted while collected (cap 1,200); `ParseLimits::RESOURCE` references the constants, `ParseLimits::UNLIMITED` is `parse_file` (the file loader, unchanged — reconcile's `enforce_resource_limits` covers the file path). (3) `MAX_CURRENCIES_PER_OPEN = 64` in the new `crates/ledger/src/limits.rs`, enforced by the parser and, via the `service.rs` diff the orchestrator applied after T74, by `enforce_resource_limits` on every write path. **Design additions, accepted:** (a) `MAX_POSTING_METADATA_KEYS_PER_TRANSACTION = MAX_METADATA_KEYS_PER_DIRECTIVE` as a sum over postings — nothing counted posting metadata before (74,896 keys passed at 10.2×); (b) the parser's `Scanner` materialises a line lazily instead of collecting it into `Vec<char>` first (without this, tag and currency floods stay at 6×); (c) `validate_currency` counts before collecting and excerpts an over-long code (11× → ~7×). Deliberately not added: account-name and tag length caps (1× resident, no amplification). (4) `decode_memory.rs`: `parsed_flood_bodies_are_refused_within_the_entry_budget` (the four audit shapes plus posting-metadata and junk-line floods under `ENTRY_PEAK_BUDGET_MULTIPLE = 4`, true ids) and `a_frame_of_flood_bodies_is_refused_within_the_frame_budget` (15 × 41,941-posting frame ≤ 4×, nothing staged; honest 256 × 1,000-posting control held to `HONEST_FRAME_PEAK_MULTIPLE = 8`, measured 6.07×). (5) The L-65 doc in `connection_limiter.rs` carries the measured multiples. **Measured (release, counting allocator):** 61,678 postings 19.94× Ok → 0.07× refused; 41,941 postings + meta 41.72× → 0.07×; 349,518 tags/links 30.63× → 0.01×; 349,515 currencies 24.00× → 0.01×; 262k-currency `open` 17.3× Ok → 0.01× refused; 15 × 42k frame 546,083,498 B (34.7×), 15 staged → 73,728 B, 0 staged; honest frames unchanged (6.07×). Orchestrator applied the `service.rs` diff after T74 and re-ran the gate: workspace 1,197 passed / 0 failed / 9 ignored (7 T76 targets, 2 documented H-19), clippy and fmt clean, `decode_memory` 7/7 in release. **Behaviour changes:** an over-cap peer entry is refused at intake (cached per peer) instead of at stage; an `open` with more than 64 currencies is refused on every path; a transaction whose postings carry more than 100 metadata keys in total is refused on every write path; existing history over these caps still loads at boot and is served, but upgraded peers refuse it (the T51 residual class). **Revert-proven:** `parsed_flood_bodies_are_refused_within_the_entry_budget`, `a_frame_of_flood_bodies_is_refused_within_the_frame_budget` (fails only with BOTH mechanisms reverted — either alone stops the accumulation; the narration unit test pins the enforce call, the per-shape memory test pins the parse limits), `test_validate_refuses_each_cardinality_cap_on_the_wire`, `test_validate_refuses_a_262k_currency_open`, `test_validate_refuses_the_audited_flood_shapes`, `test_validate_runs_the_resource_limits_after_the_parse`, `parse_limits_admit_the_cap_and_stop_one_past_it`, `a_tripped_cap_stops_the_parse_and_renders_small`, `an_over_long_currency_is_excerpted`, and the diff's three service tests. **Residuals:** frames of dense bodies inside every cap still reach ~12.7× the frame in phase 1 (~63 MB per frame; ~3.5 GiB if one peer fills the 256 MiB budget with them) — the fix is in gl-node's phase 1 (charge staged weight, or stage in chunks) → **moved to T77**; a single 1 MiB token is still ≤ 6.5× its body (the scanner stores 4 bytes per character; a byte-offset scanner would touch `read_number`).
- **Why:** **M-48.** `validate_supply_entry` ([union_merge.rs:205-215](../../crates/p2p/src/union_merge.rs#L205-L215))
  never calls `enforce_resource_limits`; the parser caps nothing by count
  ([parse.rs:1322-1341, 872-905, 1000-1030](../../crates/ledger/src/parse.rs#L1322-L1341)); `MAX_POSTINGS_PER_TRANSACTION
  = 1000`, `MAX_TAGS = 100`, `MAX_METADATA_KEYS = 100` are enforced only in `stage_remote_directive`
  ([service.rs:5869-5880](../../crates/ledger/src/service.rs#L5869-L5880)), and `apply_supply_entries` accumulates
  every parsed entry of a frame before the first stage ([anti_entropy_alpn.rs:1522-1590](../../crates/gl-node/src/anti_entropy_alpn.rs#L1522-L1590)).
  A valid 1 MiB body of 41,941 postings with one metadata line each peaks at **43.7 MB (41.7×)**, `Ok`
  with a correct id, refused only at stage; a 15 MiB frame of them holds **546 MB (34.7×)** through phase 1;
  per peer ≈ 1.1 GB transient, ≈ 9 GB under the 256 MiB global byte budget, which L-65 documents as 2–6×.
  Refused shapes also beat the Done note's 6× (262k junk lines 9.0×, a 1 MiB currency 11.0×). Proof:
  `D5-wire-bounds/probe shapes`, `batch`. **L-78.** `open` currencies are uncapped: a 786 KB `open` with 262k
  currencies stages `Ok` at 5.2 MB resident, permanently on every replica.
- **Change:** call `enforce_resource_limits` in `validate_supply_entry` immediately after the parse (kills the
  batch accumulation); add parse-time limits to `parse_file_bounded` (a `ParseLimits` with the three counts
  plus `MAX_CURRENCIES_PER_OPEN`) so counts are refused inside the block loop and the ~6× floor is restored;
  add `MAX_CURRENCIES_PER_OPEN` (and a reasonable account-name / tag length) to `enforce_resource_limits`;
  extend the `decode_memory.rs` `ENTRY_PEAK_BUDGET_MULTIPLE = 4` assertion to the parsed shapes (today it is
  asserted only on refused shapes) and add a 15-entry batch bound. **Do not touch `parse.rs:206`** (the amount
  cap), which T76 owns.
- **Files:** [union_merge.rs:169-230](../../crates/p2p/src/union_merge.rs#L169), [parse.rs:589-707, 872-905,
  1000-1030, 1322-1341](../../crates/ledger/src/parse.rs#L589), [service.rs:28-38, 671-705](../../crates/ledger/src/service.rs#L671),
  [p2p/tests/decode_memory.rs](../../crates/p2p/tests/decode_memory.rs), [connection_limiter.rs:66-85](../../crates/gl-node/src/connection_limiter.rs#L66)
  (the byte-budget doc).
- **Verify:** the 41,941-posting, 349,518-tag, 349,515-currency and 61,678-posting bodies each refuse
  inside 6× under the counting allocator; the 15 × 42k batch peaks ≤ 4× the frame; a 262k-currency `open` is
  refused on the wire and by `stage_remote_directive`; honest 256 × 1000-posting frames unchanged.

### ☑ T76 — An upgrade path for over-cap history (M-50, Info) — M, plus decision (4)
> **Done 2026-09-23 (committed `f06cb12`).** Implemented in two phases: a design phase (`scratchpad/T76-design/DESIGN.md` plus `crates/ledger/tests/exact_balances.rs`, whose ignored tests defined "done"), then the implementation under decision (4) as refined by the user, which overrides the design's D1/D3/D4. **Cap:** H-17's 21-significant-digit cap is replaced by `limits::MAX_AMOUNT_MAGNITUDE = 10^21`, inclusive, at any precision (`validate::amount_within_cap` compares `|mantissa| ≤ 10^21·10^scale` on integers), applied to every summed amount (posting units, cost, price, the resolved elided leg) on every path: the parser's new `read_summed_amount` (wire re-parse, boot, journal, reconcile), `validate_transaction` (local, peer staging, reconcile, boot salvage), the GraphQL `Decimal` scalar, and boot's quarantine arm. `balance`/`price` amounts are uncapped. `MAX_AMOUNT_SIGNIFICANT_DIGITS`/`MAX_AMOUNT_MANTISSA` removed. The new rule strictly relaxes the old one; stored amounts are hashed as spelled and no id changes (CT-3 and the elision txid pins unchanged). **Exact accumulation:** `ExactSum` keeps one `Partial{scale: u8, count: u32, sum: i128}` per scale, with a sticky, order-free `OutOfRange` past 2^31 postings per partial; `ExactAmount` holds the exact value as an in-crate `wide::I256` mantissa at its spelling scale and reproduces `rust_decimal`'s addition scale, so every fitting balance prints digit for digit as before. **Rule R:** exact when it fits 96 bits at the spelling scale; else one half-to-even rounding at the finest coarser scale that fits (`exact` true only if the dropped digits were zero); else `OutOfRange`. Report-level sums are exact folds reported once. Infallible report methods keep their signatures (an out-of-range figure reads as ±`Decimal::MAX` with `exact: false`); new `try_*` forms return `Err(OutOfRange)` and the GraphQL resolvers use them, logging and returning a generic internal error. Balance assertions (per-assertion and batched `verify`) compare `ExactAmount::equals(claim)`. **API, additive only:** `exact: Boolean!` on `AccountBalance`, `TrialBalanceRow`, `TrialBalance`, `BalanceSheet`, `IncomeStatement`; `actualExact: Boolean!` on `BalanceAssertionFailure`; `actual` stays non-null; no new error code. `weights.rs` untouched (I1 stays on rounded weights). Orchestrator re-ran: `exact_balances` 16/16 (0 ignored), `m50_wire` 2/2 (the M-50 fixture's X signed by a real key accepted through `validate_supply_entry` + `verify_remote_signature`; an over-cap amount refused on the wire, permanent), the new convergence case (five delivery orders, equal DAGs and balance text including `exact`), workspace **1,217 passed, 0 failed, 2 ignored** (the two documented H-19 joins), clippy and fmt clean; the agent ran the read-model property at 100,000 cases in release. README gains "Amounts and precision"; CHANGELOG's T65 cap bullet replaced. **Behaviour changes:** `10^21` and any precision within it accepted everywhere (including `12.12345678 BTC @ 45123.45678901 USD` and trailing-zero legs); `balance`/`price` amounts of any size; pre-T65 files load whole (the M-50 fixture boots with nothing quarantined, `verify` ok, a fresh replica syncs it); any summed amount above `10^21` refused on every path (new error text); non-fitting totals move by at most one ulp; a `balance` claim equal only to a rounded figure now fails (`m08_extreme_assertion_values_report_cleanly` changed accordingly); `Equity:Net-Income` prints `0.00` not `-0.00` for an exactly-zero net; `account(at:)` sums only the requested account (same result, less work). **Existing tests changed:** the H-17 cap tests in `validate.rs`, `parse.rs`, `service.rs`, `read_model.rs`, `verify.rs`, `scalars.rs` moved from the digit rule to the magnitude rule; in `exact_balances.rs` two history tests were rewritten to "up to the cap … exact" plus a new `amounts_over_the_cap_are_refused_on_every_path`, and the 22-digit resolved-leg control became an acceptance test. **Revert-proven:** i128 accumulation → Decimal fold; single rounding → double rounding (and a digit-by-digit variant, caught by the property only); exact assertion compare → `actual == claim`; the cap removed from the parser, the scalar, `validate_transaction` and the resolved leg one at a time; magnitude → digit rule; `balance` amount capped again. **Measured (release, 130k cap-sized ledger):** boot unchanged (~3.7 s), `trial_balance` unchanged, `verify_dag` +5–9 %, a 100k-assertion pass 26 → 48 ms (linear), `account()` 160 → 330 ns. **Residuals:** `OutOfRange` is unreachable through any ingress, so its GraphQL path has no end-to-end test (covered by read-model `try_*` unit tests and an injectable count bound); I1 still runs on rounded weights — any future exactness change there must not refuse history; mixed-version meshes (T65–T75 nodes still refuse `10^21`-exact and trailing-zero bodies until upgraded) are not simulated; an inexact trial-balance total may differ from the sum of its displayed rows by that rounding (documented on `exact`); the multi-currency trial-balance net still collapses currencies into one row.
- **Why:** **M-50.** The 21-digit cap counts **trailing zeros** as significant ([parse.rs:206](../../crates/ledger/src/parse.rs#L206)),
  so before T65 every elided leg from an 8-decimal quantity × an 8-decimal price with value ≥ 10⁵
  (`1.00000000 BTC @ 100000.00000000 USD` → `-100000.0000000000000000`, 22 digits) and every base-unit token
  amount was stored over the cap. On upgrade that block fails the parser and is quarantined as *text*
  ([service.rs:2628-2680](../../crates/ledger/src/service.rs#L2628-L2680)); its children are inserted leniently
  with a dangling parent ([:2864](../../crates/ledger/src/service.rs#L2864)); balances silently exclude it
  (`1000000000000000000014 → 14`); `verify` reports `MissingParent` forever; and a **fresh replica** refuses
  the parent permanently (parse refusal, L-34 cached) and gets `MISSING_PARENT` on every descendant (the wire
  path inserts with `require_parents: true`, [:6000](../../crates/ledger/src/service.rs#L6000)) — it can never
  sync anything below that transaction. Upgraded and non-upgraded nodes disagree meanwhile. The CHANGELOG's
  "quarantined at boot" is true and incomplete. Proof: `D4-balances/probe upgrade`, fixture
  `fixtures/pre_upgrade.bean`. **Info:** the same trailing-zero rule refuses ordinary elided 8-decimal
  purchases *today* with a clear error (workaround: an explicit rounded leg).
- **Decision (pending):** (4) exact `i128`-per-scale accumulation now (the T65 design item — history need not
  be quarantined and the cap becomes an *authoring* rule) vs interim tooling; whether M-50 is High for the
  intended deployments.
- **Change:** (a) `normalize()` the resolved leg (and any parsed amount) before the cap so trailing zeros do
  not count — this alone removes the most common precondition; (b) either the exact accumulation (per-scale
  `i128` partials with checked conversion at read time, surfacing overflow as an error) so pre-T65 amounts
  load, or, interim: a `gl-node --scan-amounts` pre-upgrade tool, a release note, `verify` reporting the
  quarantine ids and `over_cap_posting_count()`, and a boot that refuses loudly when a quarantined block has
  descendants in the DAG rather than serve a history a fresh replica cannot take; (c) L-79's half that is
  cheap here: `verify` compares balance assertions against the exact partials rather than the rounded total,
  and the read-model doc states the read-time precision.
- **Files:** [validate.rs:119-200](../../crates/ledger/src/validate.rs#L119), [read_model.rs:90-230](../../crates/ledger/src/read_model.rs#L90),
  [parse.rs:190-210](../../crates/ledger/src/parse.rs#L190) (T76 owns `:206`), [service.rs:2628-2680, 2864](../../crates/ledger/src/service.rs#L2628),
  [verify.rs](../../crates/ledger/src/verify.rs), CHANGELOG *Breaking* ("Ledger files").
- **Verify:** the `pre_upgrade.bean` fixture — the upgraded node keeps its descendants' parents resolvable
  (or refuses loudly) and a fresh replica converges to the same balance; `1.00000000 BTC @ 100000.00000000
  USD` is accepted; the every-ingress test's boot arm gains children (today it does not pin this shape); the
  bignum oracle from `D4-balances/probe` runs as a proptest with an independent oracle (the repo's is
  code-against-code); CT-9 still byte-identical.

---

## Tier 3 — cost bounds, edges and hygiene

### ☑ T77 — Near-cap and edge cost bounds (L-70, L-71, L-72, L-73, Info) — S
> **Done 2026-09-23 (committed `3d64a16`).** No `service.rs` change was needed; everything uses existing public API. **(1) L-70:** the Supply size check uses the exact journal record (`p2p::anti_entropy::RecordEstimate`, pinned equal to `record_bytes(full_file_serialize(set))`), taken under the permit before staging; `drain_orphans` takes a `&mut DrainBudget` and checks each freed orphan against the record the staged set has already become, deferring (and backing the peer off) what does not fit, so the chunk and the orphans that fit commit with no reload; the backoff is also armed on any `ResourceLimitExceeded` from prepare or commit; GraphQL subscribers are told only after `commit_pending` returns `Ok`, on both the batch and the drain path. **(2) L-71:** `ledger_commit::refuse_if_local_write_cannot_fit`, called in all three mutations under the permit just before staging, builds the stored form (resolved body, author, next lamport, every admissible head as parents, the signer's signature) and refuses with `RESOURCE_LIMIT_EXCEEDED` when it exceeds `append_headroom()` — no stage, no clock move, no reload; O(1) when headroom ≥ 2 × `MAX_ECONOMIC_BEAN_LENGTH`. **(3) L-72:** the not-allowlisted arm closes, logs through the limiter's throttle as one class and returns `Ok(())`; default filter `info,iroh::protocol=error`. **(4) L-73:** the config is opened with `open_checked(…, FileTrust::OperatorConfig)` (symlink followed, non-regular refused without blocking, no owner/mode check) and read with `read_to_end_capped` at 1 MiB; `--health-check` shares the loader. **(5) Throttles:** a bounded per-source `KeyedRefusalLog` (≤ 64 sources plus one overflow window); the limiter is keyed by `(peer, reason)` or the not-allowlisted class, the HTTP guard by client address; the suppressed count is reported when a window closes. **(6)** `RecordEstimate` replaces the per-entry over-estimate on the receive side. **(7) T75 residual:** phase 1 stages in chunks whenever the held `resident_weight` (calibrated 1.02–1.49× real residency) would pass 16 MiB, and a pushed Supply charges that weight to the inbound byte budget. **(8)** the ALPN failure log says whether the batch was rolled back or stays staged. **Design deviations, accepted:** the L-70 re-check runs per orphan before it is staged, not once after the drain; L-71 is an exact pre-stage estimate from public API, not a new accessor; item 7 uses both chunking and charging. **Measured:** densest in-cap 256-entry frame, phase-1 peak 63.5 MB (12.77× frame) → 13.5 MB (2.71×); four refused mutations at the cap: four reloads (0.5–2.6 s each, honest write waited 814 ms) → zero reloads, 18–135 µs each, honest write 5.5 ms; 50 not-allowlisted + 50 bad-ALPN dials over real iroh: 48 own WARN lines and 34 KB → ≤ 1 own line, 0 `iroh::protocol` lines, 917 B under the default filter; FIFO or 2 MiB config: hang (exit 142) → immediate exit 1 with a reason; a 256-open batch 40 KiB below the cap: deferred → admitted. **Behaviour changes:** see the CHANGELOG T77 bullets (not-allowlisted dials closed with `Ok` and throttled as a class; default log filter; per-source throttles with expiry reports; config file must be regular and ≤ 1 MiB; near-cap mutations refused before staging — at the cap an otherwise invalid write may get the cap error instead of its validation error; Supply checked against the exact record, orphans deferred, subscribers notified after durability, frames over 16 MiB of parsed weight applied in chunks; Rust API changes). **Revert-proven:** `l73_a_fifo_config_is_refused_without_blocking`, `l73_a_config_over_the_cap_is_refused`, `l73_a_symlinked_config_is_followed_and_non_files_are_refused`, `refusal_logging_is_per_source`, `refusal_log_sources_are_bounded_and_pruned`, `suppressed_refusals_are_reported_when_the_window_closes`, `guard_refusals_are_throttled_per_client_and_reported_at_expiry`, `foreign_host_refusals_from_two_clients_each_get_a_line`, `l72_refused_dials_on_a_public_bind_cost_at_most_one_line`, `l70_drained_orphans_that_do_not_fit_are_deferred_without_a_reload`, `t77_a_fitting_batch_in_the_last_40kb_is_admitted`, `l70_subscribers_hear_nothing_from_a_batch_whose_commit_failed`, `t77_phase_one_holds_at_most_its_weight_budget_of_the_densest_frame`, `t77_phase_one_weight_is_charged_to_the_inbound_budget`, `l71_refused_writes_at_the_cap_reload_nothing_and_never_hold_the_permit`, `l71_the_pre_stage_estimate_is_the_staged_record`, and in p2p `record_estimate_is_the_journal_record_length`, `resident_weight_counts_postings_and_metadata`. **Residuals:** the pre-stage chunk estimate still counts entries that end up buffered, duplicate or refused; orphans deferred at the cap are re-fetched after the backoff; the mutation estimate over-counts parents when there are more than `MAX_PARENTS` heads; `append_headroom` does not see a hand edit that grew the `.bean` (mutations then still pay a reload); on the prepare `CommitInFlight`/`Parse` arms a staged batch is written later but subscribers are never told; still uncharged: the decode transient (≤ 4× a body), one directive per connection when the budget is exhausted, and outbound (Wanted) frames (16 MiB per exchange); the not-allowlisted class is one window, so identities after the first are counted, not named; a bad-ALPN handshake still costs a TLS handshake in CPU.
- **Why:** **L-70** — the pre-stage headroom check covers only the page's `staged_bytes`
  ([anti_entropy_alpn.rs:1670](../../crates/gl-node/src/anti_entropy_alpn.rs#L1670)); `drain_orphans` (:1788) stages
  up to 16 MiB per peer after it; `SupplyBackoff::arm` has one call site (:1677, the deferral branch), so a
  cap-refused prepare on this path reloads off-lock every tick with no backoff — a peer alternating adverts
  drives one reload per two ticks forever; ALPN also publishes to GraphQL subscribers at stage time
  (:1728-1733, :2010-2016) before the rollback. **L-71** — an API-key holder retrying a refused write at the
  cap reloads per attempt while holding the FIFO permit; K ≥ 9 concurrent requests give honest mutations 408.
  **L-72** — on a public QUIC bind the not-allowlisted arm ([:439-444](../../crates/gl-node/src/anti_entropy_alpn.rs#L439-L444))
  logs its own unthrottled `warn!` and returns `Err`, so iroh logs a second line (vendored
  `iroh-1.0.3/src/protocol.rs:654`); a bad ALPN dies in the handshake and iroh logs per attempt (:629);
  measured ≈ 83 KB/s from eight loopback dialers at 0.8 % CPU. **L-73** — the config file is opened with a
  plain `File::open` + uncapped `read_to_string` ([config.rs:949-952](../../crates/gl-node/src/config.rs#L949-L952));
  a FIFO parks boot before the ledger lock with one log line, `--health-check` hangs the same way, a 200 MB
  config is still loading at 30 s. **Info** — both log throttles are process-wide (the guard's
  [request_guard.rs:66-110](../../crates/gl-node/src/request_guard.rs#L66-L110), whose `suppressed` count is
  printed only by the *next* refusal; the limiter's [connection_limiter.rs:301-316](../../crates/gl-node/src/connection_limiter.rs#L301-L316));
  the headroom estimate over-counts ~150–190 B/entry ([anti_entropy.rs:240](../../crates/p2p/src/anti_entropy.rs#L240)),
  so in the last ~40 KB before the cap a fitting honest batch is deferred forever.
- **Added from T75:** phase 1 of `apply_supply_entries` holds every staged directive of a frame at once; frames of dense bodies inside every cap reach ~12.7× the frame (~3.5 GiB per peer at the 256 MiB budget). Charge the staged directives' resident weight against the byte budget, or stage in chunks.
- **Change:** re-check headroom against the actual staged set after `drain_orphans` and arm the backoff on
  any cap-refused prepare; publish to subscribers after durability (from `finish_commit`'s receipt); a
  pre-stage headroom check in the three GraphQL mutations, refusing without a reload; route the
  not-allowlisted arm through `should_log_refusal` and `return Ok(())` after the close, and add
  `iroh::protocol=error` to the default `EnvFilter`, documenting that a public QUIC bind needs the same
  log-volume controls as the HTTP edge; `FileTrust::OperatorConfig` through `open_checked` plus
  `read_to_end_capped(1 MiB)` for the config; key both throttles by source (client IP / `(peer, reason)`)
  with the same bounded-map discipline as `accept_rate`, and print `suppressed` when the window expires;
  use `record_bytes(pending_block)` for the headroom estimate.
- **Files:** [anti_entropy_alpn.rs:439-471, 1655-1830, 2010-2016](../../crates/gl-node/src/anti_entropy_alpn.rs#L1655),
  [mutation.rs](../../crates/gl-node/src/graphql/mutation.rs), [ledger_commit.rs](../../crates/gl-node/src/ledger_commit.rs),
  [config.rs:949](../../crates/gl-node/src/config.rs#L949), [main.rs:126-160](../../crates/gl-node/src/main.rs#L126)
  (the filter), [request_guard.rs:66-110](../../crates/gl-node/src/request_guard.rs#L66),
  [connection_limiter.rs:301-316](../../crates/gl-node/src/connection_limiter.rs#L301), [anti_entropy.rs:232-250](../../crates/p2p/src/anti_entropy.rs#L232).
- **Verify:** `x3probe orphan` — B + drained O defers and arms the backoff, no reload; `x3probe cap 4` — four
  refused mutations at the cap perform zero reloads and an honest open waits < 10 ms; 50 non-allowlisted
  dials and 50 bad-ALPN dials in 10 s under a `tracing` capture layer → ≤ 1 own line and 0 `WARN` from
  `iroh::protocol`; a FIFO at `GL_NODE_CONFIG` → `Err` within the test timeout; a 2 MiB config → refused; the
  headroom fixture 40 KB below the cap admits a fitting 256-entry batch.

### ☑ T78 — Hygiene (L-67, L-79, L-64, L-66, Info, docs) — S
> **Done 2026-09-23 (committed `3d64a16`).** **(1) L-67:** closed in `set_author_id` (the tracker's alternative; `main.rs` is T77's): boot keeps a per-author lamport high over everything that did not reach the DAG (quarantined records, duplicate-body envelopes, envelopes inside unparsable text) and the clock it resumed from; when the new author's high is above it, the clock resumes above it, and unfinalised boot operator input is re-stamped by the same uniform shift (read model re-indexed, parents untouched; a shift that would pass `LAMPORT_CEILING` is not applied, with a WARN). D3 `h5` at HEAD: pair re-issued = true; after: false. The audit's X1-3 (same hand line lamport 8 on a placeholder boot, 14 on a reload) still reproduced after T73 and now agrees. Addition: own envelope pairs inside unparsable text count toward the boot clock. **(2) L-64:** a Fresh boot warns, naming canonical/file/journal sizes, the cap and the overage, when the canonical form exceeds `MAX_LEDGER_FILE_BYTES` (with pending operator input, checked at the end of `finalize_operator_input`); measured by a new allocation-free `compaction_text_len()` pinned equal to `compaction_text().len()` (~+0.2 s on a 62 MB boot). **(3) Journal, option (b):** a final record complete by length that fails its checksum is torn unless an *intact* record (header parses, bytes fit, hash matches) starts inside it — the ext4 `data=writeback` stale-block shape; mid-journal checksum failures and a length damaged to swallow intact later records stay `Corrupt`; bytes kept in the `.torn-*` sidecar; module doc rewritten. **(4)** The sweep matches only `<name>.tmp` and `<name>.tmp.<1–10 digits>.<16 lowercase hex>` (what `temporary_path_for` produces); `boot_with`'s journal probe uses `symlink_metadata`, so a dangling journal link beside an absent `.bean` refuses boot and creates nothing. **(5) L-66:** `pin_page_assets` rewrites `GraphiQLSource::finish()` to React/React-DOM 18.3.1 production builds and adds `integrity="sha384-…"` + `crossorigin="anonymous"` to every external tag; the `graphql.org` favicon is removed; hashes hard-coded beside their URLs, version not restated. Orchestrator re-fetched all four assets from unpkg and jsDelivr: every hash matches. **(6) L-79:** the half-ulp bound added to the `read_model` doc. README and CHANGELOG text applied by the orchestrator (upgrade note and CHANGELOG link, clippy line, reserved temp names, torn rule, GraphiQL SRI, the four CHANGELOG omissions the audit listed). Orchestrator re-ran the 12 ledger tests in the tree; the agent's gate on an archive copy with its files: 1,230 passed, 0 failed, 2 ignored, clippy and fmt clean. **Behaviour changes:** a hash-failing final journal record with no intact record inside boots torn instead of refusing; the sweep no longer deletes non-reserved `<name>.tmp.*` files; a dangling journal link with no `.bean` refuses boot without creating one; `set_author_id` can raise the clock and re-stamp unfinalised operator input; own envelopes in unparsable text move the boot clock; a new L-64 WARN; GraphiQL loads only SRI-pinned production assets and no longer contacts `graphql.org`. **Existing tests changed:** none. **Revert-proven (11):** `journal::tests::t78_a_stale_final_payload_is_a_torn_tail`, `t78_a_checksum_failure_before_the_end_or_over_an_intact_record_is_corrupt`, `service::tests::t78_a_stale_final_journal_record_boots_torn_and_its_bytes_are_kept`, `t78_the_sweep_leaves_an_operator_tmp_backup_alone`, `t78_a_dangling_journal_link_without_a_bean_refuses_boot_and_creates_nothing`, `l67_set_author_id_resumes_the_clock_above_own_quarantined_records`, `l67_operator_input_gets_the_same_lamport_on_a_placeholder_boot_and_a_reload`, `t78_an_own_envelope_in_unparsable_text_feeds_the_clock`, `l64_a_dense_file_whose_canonical_form_is_over_the_cap_boots_with_a_warning`, `t78_compaction_text_len_is_the_length_of_compaction_text`, `graphql::tests::test_graphiql_page_loads_only_pinned_assets_with_integrity`. **Residuals:** stale crash bytes in a final *header* line (not NUL) still fail closed, as does a stale block holding one whole old verifying record; a final record hit by bit rot after its commit returned now boots without it, loudly (bytes in the sidecar, peers re-supply a replicated record); `set_author_id` after `finalize_operator_input` only raises the clock (library misuse; `gl-node` orders them correctly); the L-64 check does not run on a reload; the CDN is still a single origin — SRI makes substitution fail closed (blank page), not available; self-hosting remains the alternative.
- **Why / change, one line each:**
  - **L-67** — `gl-node` boots the ledger with author `"local"` ([main.rs:219](../../crates/gl-node/src/main.rs#L219))
    and sets the real id at :364, so `note_if_own` ([service.rs:1268-1272](../../crates/ledger/src/service.rs#L1268-L1272))
    never counts an own quarantined record and the node re-issues its `(author, lamport)` pair; the same
    hand line gets a different lamport on a Fresh boot than on a reload. Load the key and derive the
    `EndpointId` before `LedgerService::boot`, or re-fold the quarantine in `set_author_id`.
  - **L-79** — mixed-scale totals round at read time, deterministically, and the ascending fold is not
    correctly rounded (1,167 of 4,787 non-fitting oracle cases > ½ ulp); `balance Assets:Cash 1000 USD`
    passes on `1000 + 1e-28`. The `verify`-against-exact-partials half lands with T76; here: state the
    precision in the `ExactSum` doc and the README.
  - **L-64** (carried) — warn at boot when `compaction_text().len() > MAX_LEDGER_FILE_BYTES` for a dense
    hand-written file.
  - **L-66** (carried) — a post-processing pass over `GraphiQLSource::finish()` pinning `react`/`react-dom`
    to 18.3.1 production builds with `integrity` on the four known tags (test fails if the template
    changes), or self-host; document the `graphql.org/favicon.ico` third origin or strip it.
  - **Journal doc** — narrow the M-44 claim to zero-filling filesystems (XFS): ext4 `data=writeback`
    exposes stale data, so a hash-failing final record with no NUL is `Corrupt` on a node-written file
    (plausible, not executed on a real filesystem); or widen the torn rule to any hash-failing *final* record
    with no later header (the bytes are kept in the sidecar).
  - **Sweep** — match only `<name>.tmp.<digits>.<16 hex>` and document the reserved pattern (today any
    same-uid `<name>.tmp.*` is deleted, e.g. `ledger.bean.tmp.backup`); `symlink_metadata` for the
    journal-presence probe at [service.rs:2523](../../crates/ledger/src/service.rs#L2523).
  - **Log text** — "rolled back in memory, will re-pull" ([anti_entropy_alpn.rs:1819-1823](../../crates/gl-node/src/anti_entropy_alpn.rs#L1819-L1823))
    is false on the `Parse`/`CommitInFlight` arms; the `LamportCeiling` diagnostic (T72 (d)) if not done there.
  - **CHANGELOG omissions** — L-60 (unsolicited Supply entries dropped with a WARN), the Rust-API change
    `ConnectionLimiter::try_acquire` → `Result<_, Refusal>` plus `pub enum Refusal`, the journal appender
    requiring 0600 on an *existing* journal, GraphiQL's third origin; add every T72–T78 behaviour change.
  - **README** — an upgrade note about older binaries and a link to `CHANGELOG.md`; the clippy line with
    `--workspace --locked -- -D warnings`; §Editing's three omissions land with T73.
- **Files:** [main.rs:190-230, 364](../../crates/gl-node/src/main.rs#L190), [service.rs:167-200, 1250-1275,
  2523, 5683](../../crates/ledger/src/service.rs#L167), [read_model.rs:90-140](../../crates/ledger/src/read_model.rs#L90),
  [journal.rs:60-110](../../crates/ledger/src/journal.rs#L60), [graphql/mod.rs:122-170](../../crates/gl-node/src/graphql/mod.rs#L122),
  README, CHANGELOG.
- **Verify:** boot under the placeholder with an own quarantined directive, `set_author_id`, assert the clock
  is above it (`D3 hunt h5`); a dense 63 MiB file boots with the warning; the GraphiQL page carries
  `integrity` on every script tag; `ledger.bean.tmp.backup` survives a boot; the CHANGELOG bullet-by-bullet
  check from `D9-docs-supply/REPORT.md §7` still passes with the additions.

---

## Residuals carried into this backlog (unchanged, for the record)

- **H-01** loopback API key (deferred by decision); the `OPTIONS`/`Allow` fingerprint is documented.
- **M-09 / M-10 / L-06** — T45 (Format v2); waves A+B wait for T72 and T73.
- **L-23 / R-9** — `meshId` required next release.
- **R-8** (runtime-teardown `JoinError`; `mem::forget`) — documented, shutdown-only.
- **R-14 / R-15** — `verify` on the read lock; `balance` directives admitted without account existence.
- **R-16** — the 900 ms perf budget; monitor.
- **§5 informational items** in the 0923 report not assigned above: a child with a lamport below its
  parent's is accepted (harmless); I1 judged on `checked_mul`-rounded weights (a 3-leg in-cap transaction
  with an exact 10⁻¹⁶ imbalance is accepted); the scalar accepts `1_000` and the parser `1,000`; a partial
  that cancels to zero drops out of the printed scale; the compaction arm holds the write lock across a
  64 MiB read + hash + serialize (pre-existing); `stage_remote_directive` accepts an envelope-less directive
  (library API only); a journal record duplicating a canonical body with this node's author and a large
  lamport moves the boot clock silently (file writer); macOS `EOPNOTSUPP` on a swapped-in socket (still
  refused); the two swallowed directory `fsync`s; the unpinned `LEGAL_*` constants; G-1; the non-canonical
  envelope spellings; `AccountClosed` drain churn; parents naming non-transaction ids; zero-unit `@@` and
  zero-posting transactions; `trial_balance` netting currencies.

---

## Regression-test manifest (must exist by the end of Tier 1)

1. A fresh node converges after the mesh adopted `local + 2^32 − 1` from X, authored on top, and dropped X;
   a pre-T63 jump converges or is diagnosed at boot (T72 / H-19).
2. Two replicas fed disjoint 256-subsets of one author's 257 parentless transactions end with equal DAG
   membership after anti-entropy with no local authoring (T72 / H-21).
3. Boot on an edited signed body quarantines it and everything served passes `verify_remote_signature`;
   a split node-written block is quarantined whole, not loaded truncated (T73 / H-20).
4. A half envelope is adopted and signed, or quarantined, on both file paths, and the wire accepts what is
   served (T73 / M-47).
5. A live file replacement plus a failed commit is refused by the floor and the next commit writes the union;
   a torn append plus a failed reload compacts and reboots with a sidecar (T74 / M-46, M-49).
6. The four cardinality shapes refuse inside 6× and a 15-entry batch stays ≤ 4× the frame (T75 / M-48).
7. The `pre_upgrade.bean` fixture keeps its descendants resolvable on the upgraded node and a fresh replica
   converges; `1.00000000 BTC @ 100000.00000000 USD` is accepted (T76 / M-50).

Every one needs its **bug-catch proof** — revert the fix, watch the named test fail, restore — and the
orchestrator re-verifies each mechanism in source and re-runs the suite three times on a quiet machine.
The proof crates for every finding are in the 0923 session's scratchpad (`D1-filepath` … `X3-commit-recovery`);
each pass's report §6 gives the re-run command, and the shapes above name them.

---

*Audit: [SECURITY_AUDIT_0923.md](SECURITY_AUDIT_0923.md). Previous trackers:
[OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md) (T61–T71) ·
[OUTSTANDING_TASKS_09_22.md](OUTSTANDING_TASKS_09_22.md) (T46–T60, R-1…R-21) ·
[OUTSTANDING_TASKS_09.md](OUTSTANDING_TASKS_09.md) (T18–T45) · [OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md)
(T1–T17). Format v2 design: [FORMAT_V2_DESIGN.md](../FORMAT_V2_DESIGN.md).*
