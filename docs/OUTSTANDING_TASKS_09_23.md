# Outstanding Security Tasks — 2026-09-23

Remediation backlog for every open finding in [SECURITY_AUDIT_0923.md](../SECURITY_AUDIT_0923.md), the
re-audit of T61–T71. Task numbering continues from [OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md)
(T61–T71, all ☑). Line references are current as of HEAD `af14603`.

**Already closed — do not re-do:** the 0923 audit verified **31** register entries closed by mechanism
(H-12, H-13, H-14, H-15, H-16, H-17, H-18 · M-06, M-35 … M-45 · L-35, L-43, L-55 … L-63, L-65). See
[SECURITY_AUDIT_0923.md §1](../SECURITY_AUDIT_0923.md). This tracker covers only what is open: three new
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
> accumulation now**, the 21-digit cap becomes an authoring rule; (5) M-48 — rating stays Medium, fix as
> specified. Scope of the first wave: the two harnesses, then T72 and T73.

## Priority order at a glance

| # | Findings addressed | Sev | Effort | Status |
|---|---|---|---|---|
| T72 | H-19 + H-21 + L-68 + L-69 — rules on content, not on the replica | **High** | M | ☐ |
| T73 | H-20 + M-47 + L-74 + L-75 + L-76 + L-77 — boot verifies what it loads | **High** | M | ☐ |
| T74 | M-46 + M-49 + two Info items — the recovery floor and the reload-failure arm | Med | S | ☐ |
| T75 | M-48 + L-78 — wire cardinality caps before staging | Med | S | ☐ |
| T76 | M-50 + Info (trailing zeros) — an upgrade path for over-cap history | Med | M | ☐ |
| T77 | L-70 + L-71 + L-72 + L-73 + Info (throttles, headroom estimate) — near-cap and edge cost bounds | Low | S | ☐ |
| T78 | L-67 + L-79 + L-64 + L-66 + Info (docs, sweep, journal doc, CHANGELOG/README omissions) — hygiene | Low | S | ☐ |

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

### ☐ T72 — Rules on content, not on the replica (H-19, H-21, L-68, L-69) — M, plus decisions (1) and (2)
- **Why:** two of the three Highs are the same mistake. **H-19:** `check_lamport_advance`
  ([service.rs:1208-1220](../crates/ledger/src/service.rs#L1208-L1220)) refuses `remote − local ≥ 2^32`
  where `local` is *this node's* clock, and T63 deliberately gave no first-contact exemption. One allowlisted
  peer authors one legal directive at `local + 2^32 − 1`; the honest mesh adopts it and stamps above it; the
  operator follows the remedy the code prescribes (allowlist removal, [:1598-1606](../crates/ledger/src/service.rs#L1598-L1606),
  [:2917-2924](../crates/ledger/src/service.rs#L2917-L2924)) — and every future node, and every node restored
  from an empty disk, is permanently unable to adopt anything authored after the jump (the first post-jump
  honest directive sits exactly `2^32 + 1` above the pre-jump clock; the bridge is refused at intake as
  not-allowlisted, a permanent cached refusal). A pre-T63 mesh carrying any jump ≥ 2^32 is in the same state
  with no attacker. Neither boot warning fires (both are anchored to the ceiling, [:2913, :2926](../crates/ledger/src/service.rs#L2913)).
  The partition is asymmetric — the stuck node's own writes are accepted — and the Done-note residual
  ("cannot be joined until that directive is removed") is wrong: removing it changes nothing, the honest
  history after it *is* the gap. Proof: `D3-lamport-heads/proof hunt.rs h1a/h1b`. **H-21:**
  `check_unmerged_head_bound` ([service.rs:5808-5825](../crates/ledger/src/service.rs#L5808-L5825)) refuses a
  parentless transaction when its author owns 256 heads *on this replica* ([dag.rs:452](../crates/ledger/src/dag.rs#L452)).
  A peer serves replica A the subset `{0..255}` of 257 parentless transactions and replica B `{1..256}`;
  each refuses the 257th; A↔B anti-entropy cannot repair it. Same available set, two permanently different
  committed DAGs; self-heals only when *each* replica authors locally; an observer replica diverges
  indefinitely. The remote refusal is redundant — `choose_parents`'s `truncate(MAX_PARENTS)` ([:3656](../crates/ledger/src/service.rs#L3656))
  already closes H-16's brick. Proof: `X2-convergence/probe 3b`.
- **The Lows this closes with it:** **L-68** — naming any current head is admitted without counting
  ([:5811-5816](../crates/ledger/src/service.rs#L5811-L5816)), so one author's heads climb past 256 by one
  per honest head consumed, and an id-grinder keeps `choose_parents` naming only attacker heads (each honest
  append becomes a permanent head mesh-wide). **L-69** — `LamportAdvance` and `UnmergedHeadLimit` are
  retried uncached ([anti_entropy_alpn.rs:1735-1746](../crates/gl-node/src/anti_entropy_alpn.rs#L1735-L1746)),
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
  authored on top of the poison ([:3684-3692](../crates/ledger/src/service.rs#L3684-L3692)).
- **Files:** [service.rs:1132-1300, 3656-3700, 5808-5825, 5869-6060](../crates/ledger/src/service.rs#L1208),
  [dag.rs:411-463](../crates/ledger/src/dag.rs#L411), [union_merge.rs:342-346](../crates/p2p/src/union_merge.rs#L342-L346),
  [anti_entropy_alpn.rs:1866-1940](../crates/gl-node/src/anti_entropy_alpn.rs#L1866), README §Mesh identity
  (the remedy text).
- **Verify:** the `h1b` shape — A and B adopt `local + 2^32 − 1` from X, author on top, X is dropped from the
  allowlist and the served set: a fresh node **bootstrapped from A's file converges** (harness case; passes at
  HEAD and must keep passing), the anti-entropy-only join stays a documented, ignored harness case, and the
  new warning fires on A, B and the joiner; the `h1a` pre-T63 shape boots with the warning naming the gap; a dense history still converges in ascending, descending and
  interleaved order (`X2 probe 4`); the `3b` disjoint-subset two-replica shape gives **equal DAG membership**
  with no local authoring (fails at HEAD; every `test_h16_*` today is single-replica); 256 planted small-id
  heads plus one honest head → the local append names the honest head; 4,096 ratchet-refused ids cost one
  fetch, not one per tick. Bug-catch proof for each predicate separately.

### ☐ T73 — Boot verifies what it loads (H-20, M-47, L-74, L-75, L-76, L-77) — M, plus decision (3)
- **Why:** **H-20.** `is_operator_input` ([service.rs:3036-3039](../crates/ledger/src/service.rs#L3036-L3039))
  makes anything carrying an author and a lamport *history*, and the history path
  ([:2826-2880](../crates/ledger/src/service.rs#L2826-L2880)) checks fan-in, envelope form and the amount cap —
  never the signature (the crate has no verifier) and never I1. Two doors through the README's supported
  stop → edit → start workflow: (a) the operator corrects a narration typo or an amount in a line the node
  wrote; boot loads it under a **new** content id with the **old** signature, zero WARN, the startup
  compaction persists it, every signing peer refuses it (`InvalidSignature`, cached), the node's next write
  names it as a parent and everything authored afterwards is orphaned mesh-wide; an amount edit diverges
  balances (`this node 13.00 / peer 10.00`). (b) a stray dedent, BOM or word inside a node-written transaction
  makes `split_ledger_blocks` ([:433-489](../crates/ledger/src/service.rs#L433-L489)) start a new block, and
  `salvage_unparsable_blocks` ([:528-548](../crates/ledger/src/service.rs#L528-L548)) loads the parsable head
  as a *complete* transaction (0 or 1 postings) with the original envelope, keeping `+100` and dropping the
  `−100`, while the banner says "nothing is lost". Proofs: `X1-adoption-interplay/x1probe p12`,
  `D1-filepath/probe split`. README §Editing ([README.md:702-780](../README.md#L702-L780)) describes only
  *adding* lines and never says "do not edit an existing record". **M-47.** A half envelope — author *or*
  lamport, not both — is history at boot (raw, unlamported or unauthored, unsigned, a head, zero WARN, a
  fixed point on disk) but operator input on the live reconcile (`needs_stamp` [:5201](../crates/ledger/src/service.rs#L5201)):
  T61's decision text says "a node never writes a directive without author *and* lamport", the code tests
  "lacks both". Peers refuse it with `EnvelopeMissing`; the next write is orphaned. Proof: `x1probe p1`.
- **The Lows this closes with it:** **L-74** — `finalize_operator_input` rewrites the DAG copy only; the read
  model keeps boot's clone, so `journal` serves the hand record as `author: "local"`, unsigned, until restart
  (`x1probe p3`). **L-75** — hand-typed `openledger-parents` are honoured verbatim ([:5294](../crates/ledger/src/service.rs#L5294));
  a parent that exists nowhere becomes a signed head and every later write is orphaned on peers, no WARN
  (`x1probe p9`). **L-76** — the boot cycle arm's `quarantined.insert` ([:2760](../crates/ledger/src/service.rs#L2760))
  lets a later envelope-less spelling replace the signed one; the compaction drops the signed copy and the
  next boot re-authors it (`x1probe p4`). **L-77** — a hand `open` of an already-open account is adopted at
  boot and live while the API refuses it (`AccountAlreadyOpen` [:3442](../crates/ledger/src/service.rs#L3442)
  vs [:5381-5423](../crates/ledger/src/service.rs#L5381-L5423)); currencies get re-constrained.
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
  live path, [:5553](../crates/ledger/src/service.rs#L5553)). (d) require hand-spelled parents to resolve, else
  quarantine. (e) `entry().or_insert` in the cycle arm, preferring the enveloped spelling. (f) re-index the
  finalized directive in the read model. (g) `AccountAlreadyOpen` parity on both file paths. (h) README
  §Editing: never edit an existing record, append a reversing entry; a deleted signed line is re-supplied by
  peers; adoption is one-way; the lamport-only exception.
- **Files:** [service.rs:433-548, 2760-2880, 3036-3039, 3145-3230, 5129-5420, 5553](../crates/ledger/src/service.rs#L433),
  [read_model.rs](../crates/ledger/src/read_model.rs) (re-index), [main.rs:421-468](../crates/gl-node/src/main.rs#L421),
  `security/src/signing.rs` (a verifier the ledger crate can call through a closure, as the signer is),
  [README.md:702-780](../README.md#L702-L780).
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

### ☐ T74 — The recovery floor and the reload-failure arm (M-46, M-49, two Info items) — S
- **Why:** **M-46.** `finish_recovery`'s floor is `dag.len() − pending_ids.len()`
  ([service.rs:4356-4360](../crates/ledger/src/service.rs#L4356-L4360)), meant as "what a failed commit may
  legitimately have left behind". But `adopt_file_directive` pushes the ids it adopts *from the file* onto
  `pending_ids` ([:5364, :5407](../crates/ledger/src/service.rs#L5364)) and boot's operator-input adoption does
  the same ([:3062-3070](../crates/ledger/src/service.rs#L3062-L3070)), so the floor is understated by exactly
  that number. A `cp` of a backup over the live file (removes M acked lines, adds N ≥ M) plus one failed
  commit installs the replacement over memory: `before=7 after=3 discarded_staged=4`, `Acked1..3` gone from
  memory and, after the next write, from disk. The T61-adoption × T62-recovery interaction. Proof:
  `D2-recovery-journal/d2probe floor` (b, b3; controls a, b2, c, d). **M-49.** `finish_recovery`'s
  `Err(reload_error)` arm ([:4385-4392](../crates/ledger/src/service.rs#L4385-L4392)) leaves `force_compaction`
  as it was (the refusing arm at :4372 sets it) and carries no `journal_torn_at_boot`. A torn append followed
  by a failed reload → the next commit is an `Append` behind the torn tail → T68's classifier makes the
  journal `Corrupt` → the next boot refuses (`LEDGER_JOURNAL`) with an acked record behind the tail. The
  09/22-v2 §5 item, escalated by T68. Proof: `X3-commit-recovery/x3probe torn` case B.
- **Info items closed with it:** a *refused* reload also discards the rebuilt `journal_torn_at_boot`, so the
  following compaction unlinks a torn journal instead of renaming it (`d2probe sidecars`); the
  `uncommitted_count()` doc ("non-zero only between a staged mutation and its commit",
  [:3821](../crates/ledger/src/service.rs#L3821)) is false after a boot that adopted operator input; the install
  log's `discarded_staged` label counts file-adopted ids.
- **Change:** keep file-adopted ids out of `pending_ids` (a separate `adopted_from_file` counter feeds the
  "nothing to do" short-circuit and `uncommitted_count`), and/or refuse a rebuild in which any non-pending
  memory id is absent (an `ids()` iterator on `LedgerDag`, O(N) lookups; proven on a scratch copy: both
  shapes refuse, 20 recovery tests pass); in the `Err` arm set `force_compaction = true`; carry
  `journal_torn_at_boot |= reloaded.journal_torn_at_boot` on the refusing arm and re-derive it on the `Err`
  arm from the failed attempt; fix the doc and the label.
- **Files:** [service.rs:3062-3070, 3821, 4334-4420, 5364, 5407](../crates/ledger/src/service.rs#L4334),
  [dag.rs](../crates/ledger/src/dag.rs) (`ids()`).
- **Verify:** `floor (b)` — three acked opens, three different opens written over the file, commit under an
  unwritable directory → `REFUSING`, memory keeps six, the next commit writes seven; `floor (b3)` at boot;
  `floor (c)` still refuses and `(a)` (operator removed their own hand lines) still installs; `torn` case B —
  the next commit is `Compact`, the reboot succeeds, one `.torn-*` sidecar; `sidecars (b)` — a refused reload
  over a truncated journal still leaves a sidecar; `uncommitted_count() == 0` right after a boot with
  operator input.

### ☐ T75 — Wire cardinality caps before staging (M-48, L-78) — S, plus decision (5) on the rating only
- **Why:** **M-48.** `validate_supply_entry` ([union_merge.rs:205-215](../crates/p2p/src/union_merge.rs#L205-L215))
  never calls `enforce_resource_limits`; the parser caps nothing by count
  ([parse.rs:1322-1341, 872-905, 1000-1030](../crates/ledger/src/parse.rs#L1322-L1341)); `MAX_POSTINGS_PER_TRANSACTION
  = 1000`, `MAX_TAGS = 100`, `MAX_METADATA_KEYS = 100` are enforced only in `stage_remote_directive`
  ([service.rs:5869-5880](../crates/ledger/src/service.rs#L5869-L5880)), and `apply_supply_entries` accumulates
  every parsed entry of a frame before the first stage ([anti_entropy_alpn.rs:1522-1590](../crates/gl-node/src/anti_entropy_alpn.rs#L1522-L1590)).
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
- **Files:** [union_merge.rs:169-230](../crates/p2p/src/union_merge.rs#L169), [parse.rs:589-707, 872-905,
  1000-1030, 1322-1341](../crates/ledger/src/parse.rs#L589), [service.rs:28-38, 671-705](../crates/ledger/src/service.rs#L671),
  [p2p/tests/decode_memory.rs](../crates/p2p/tests/decode_memory.rs), [connection_limiter.rs:66-85](../crates/gl-node/src/connection_limiter.rs#L66)
  (the byte-budget doc).
- **Verify:** the 41,941-posting, 349,518-tag, 349,515-currency and 61,678-posting bodies each refuse
  inside 6× under the counting allocator; the 15 × 42k batch peaks ≤ 4× the frame; a 262k-currency `open` is
  refused on the wire and by `stage_remote_directive`; honest 256 × 1000-posting frames unchanged.

### ☐ T76 — An upgrade path for over-cap history (M-50, Info) — M, plus decision (4)
- **Why:** **M-50.** The 21-digit cap counts **trailing zeros** as significant ([parse.rs:206](../crates/ledger/src/parse.rs#L206)),
  so before T65 every elided leg from an 8-decimal quantity × an 8-decimal price with value ≥ 10⁵
  (`1.00000000 BTC @ 100000.00000000 USD` → `-100000.0000000000000000`, 22 digits) and every base-unit token
  amount was stored over the cap. On upgrade that block fails the parser and is quarantined as *text*
  ([service.rs:2628-2680](../crates/ledger/src/service.rs#L2628-L2680)); its children are inserted leniently
  with a dangling parent ([:2864](../crates/ledger/src/service.rs#L2864)); balances silently exclude it
  (`1000000000000000000014 → 14`); `verify` reports `MissingParent` forever; and a **fresh replica** refuses
  the parent permanently (parse refusal, L-34 cached) and gets `MISSING_PARENT` on every descendant (the wire
  path inserts with `require_parents: true`, [:6000](../crates/ledger/src/service.rs#L6000)) — it can never
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
- **Files:** [validate.rs:119-200](../crates/ledger/src/validate.rs#L119), [read_model.rs:90-230](../crates/ledger/src/read_model.rs#L90),
  [parse.rs:190-210](../crates/ledger/src/parse.rs#L190) (T76 owns `:206`), [service.rs:2628-2680, 2864](../crates/ledger/src/service.rs#L2628),
  [verify.rs](../crates/ledger/src/verify.rs), CHANGELOG *Breaking* ("Ledger files").
- **Verify:** the `pre_upgrade.bean` fixture — the upgraded node keeps its descendants' parents resolvable
  (or refuses loudly) and a fresh replica converges to the same balance; `1.00000000 BTC @ 100000.00000000
  USD` is accepted; the every-ingress test's boot arm gains children (today it does not pin this shape); the
  bignum oracle from `D4-balances/probe` runs as a proptest with an independent oracle (the repo's is
  code-against-code); CT-9 still byte-identical.

---

## Tier 3 — cost bounds, edges and hygiene

### ☐ T77 — Near-cap and edge cost bounds (L-70, L-71, L-72, L-73, Info) — S
- **Why:** **L-70** — the pre-stage headroom check covers only the page's `staged_bytes`
  ([anti_entropy_alpn.rs:1670](../crates/gl-node/src/anti_entropy_alpn.rs#L1670)); `drain_orphans` (:1788) stages
  up to 16 MiB per peer after it; `SupplyBackoff::arm` has one call site (:1677, the deferral branch), so a
  cap-refused prepare on this path reloads off-lock every tick with no backoff — a peer alternating adverts
  drives one reload per two ticks forever; ALPN also publishes to GraphQL subscribers at stage time
  (:1728-1733, :2010-2016) before the rollback. **L-71** — an API-key holder retrying a refused write at the
  cap reloads per attempt while holding the FIFO permit; K ≥ 9 concurrent requests give honest mutations 408.
  **L-72** — on a public QUIC bind the not-allowlisted arm ([:439-444](../crates/gl-node/src/anti_entropy_alpn.rs#L439-L444))
  logs its own unthrottled `warn!` and returns `Err`, so iroh logs a second line (vendored
  `iroh-1.0.3/src/protocol.rs:654`); a bad ALPN dies in the handshake and iroh logs per attempt (:629);
  measured ≈ 83 KB/s from eight loopback dialers at 0.8 % CPU. **L-73** — the config file is opened with a
  plain `File::open` + uncapped `read_to_string` ([config.rs:949-952](../crates/gl-node/src/config.rs#L949-L952));
  a FIFO parks boot before the ledger lock with one log line, `--health-check` hangs the same way, a 200 MB
  config is still loading at 30 s. **Info** — both log throttles are process-wide (the guard's
  [request_guard.rs:66-110](../crates/gl-node/src/request_guard.rs#L66-L110), whose `suppressed` count is
  printed only by the *next* refusal; the limiter's [connection_limiter.rs:301-316](../crates/gl-node/src/connection_limiter.rs#L301-L316));
  the headroom estimate over-counts ~150–190 B/entry ([anti_entropy.rs:240](../crates/p2p/src/anti_entropy.rs#L240)),
  so in the last ~40 KB before the cap a fitting honest batch is deferred forever.
- **Change:** re-check headroom against the actual staged set after `drain_orphans` and arm the backoff on
  any cap-refused prepare; publish to subscribers after durability (from `finish_commit`'s receipt); a
  pre-stage headroom check in the three GraphQL mutations, refusing without a reload; route the
  not-allowlisted arm through `should_log_refusal` and `return Ok(())` after the close, and add
  `iroh::protocol=error` to the default `EnvFilter`, documenting that a public QUIC bind needs the same
  log-volume controls as the HTTP edge; `FileTrust::OperatorConfig` through `open_checked` plus
  `read_to_end_capped(1 MiB)` for the config; key both throttles by source (client IP / `(peer, reason)`)
  with the same bounded-map discipline as `accept_rate`, and print `suppressed` when the window expires;
  use `record_bytes(pending_block)` for the headroom estimate.
- **Files:** [anti_entropy_alpn.rs:439-471, 1655-1830, 2010-2016](../crates/gl-node/src/anti_entropy_alpn.rs#L1655),
  [mutation.rs](../crates/gl-node/src/graphql/mutation.rs), [ledger_commit.rs](../crates/gl-node/src/ledger_commit.rs),
  [config.rs:949](../crates/gl-node/src/config.rs#L949), [main.rs:126-160](../crates/gl-node/src/main.rs#L126)
  (the filter), [request_guard.rs:66-110](../crates/gl-node/src/request_guard.rs#L66),
  [connection_limiter.rs:301-316](../crates/gl-node/src/connection_limiter.rs#L301), [anti_entropy.rs:232-250](../crates/p2p/src/anti_entropy.rs#L232).
- **Verify:** `x3probe orphan` — B + drained O defers and arms the backoff, no reload; `x3probe cap 4` — four
  refused mutations at the cap perform zero reloads and an honest open waits < 10 ms; 50 non-allowlisted
  dials and 50 bad-ALPN dials in 10 s under a `tracing` capture layer → ≤ 1 own line and 0 `WARN` from
  `iroh::protocol`; a FIFO at `GL_NODE_CONFIG` → `Err` within the test timeout; a 2 MiB config → refused; the
  headroom fixture 40 KB below the cap admits a fitting 256-entry batch.

### ☐ T78 — Hygiene (L-67, L-79, L-64, L-66, Info, docs) — S
- **Why / change, one line each:**
  - **L-67** — `gl-node` boots the ledger with author `"local"` ([main.rs:219](../crates/gl-node/src/main.rs#L219))
    and sets the real id at :364, so `note_if_own` ([service.rs:1268-1272](../crates/ledger/src/service.rs#L1268-L1272))
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
    journal-presence probe at [service.rs:2523](../crates/ledger/src/service.rs#L2523).
  - **Log text** — "rolled back in memory, will re-pull" ([anti_entropy_alpn.rs:1819-1823](../crates/gl-node/src/anti_entropy_alpn.rs#L1819-L1823))
    is false on the `Parse`/`CommitInFlight` arms; the `LamportCeiling` diagnostic (T72 (d)) if not done there.
  - **CHANGELOG omissions** — L-60 (unsolicited Supply entries dropped with a WARN), the Rust-API change
    `ConnectionLimiter::try_acquire` → `Result<_, Refusal>` plus `pub enum Refusal`, the journal appender
    requiring 0600 on an *existing* journal, GraphiQL's third origin; add every T72–T78 behaviour change.
  - **README** — an upgrade note about older binaries and a link to `CHANGELOG.md`; the clippy line with
    `--workspace --locked -- -D warnings`; §Editing's three omissions land with T73.
- **Files:** [main.rs:190-230, 364](../crates/gl-node/src/main.rs#L190), [service.rs:167-200, 1250-1275,
  2523, 5683](../crates/ledger/src/service.rs#L167), [read_model.rs:90-140](../crates/ledger/src/read_model.rs#L90),
  [journal.rs:60-110](../crates/ledger/src/journal.rs#L60), [graphql/mod.rs:122-170](../crates/gl-node/src/graphql/mod.rs#L122),
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

*Audit: [SECURITY_AUDIT_0923.md](../SECURITY_AUDIT_0923.md). Previous trackers:
[OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md) (T61–T71) ·
[OUTSTANDING_TASKS_09_22.md](OUTSTANDING_TASKS_09_22.md) (T46–T60, R-1…R-21) ·
[OUTSTANDING_TASKS_09.md](OUTSTANDING_TASKS_09.md) (T18–T45) · [OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md)
(T1–T17). Format v2 design: [FORMAT_V2_DESIGN.md](FORMAT_V2_DESIGN.md).*
