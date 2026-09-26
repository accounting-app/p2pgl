# Outstanding Security Tasks — 2026-09-26

Remediation backlog for every open finding in [SECURITY_AUDIT_0926.md](../SECURITY_AUDIT_0926.md), the
re-audit of T84–T89. Task numbering continues from [OUTSTANDING_TASKS_09_25.md](OUTSTANDING_TASKS_09_25.md)
(T84–T89, all ☑). Line references are current as of HEAD `8c0a87e`.

**Already closed — do not re-do:** the 0926 audit verified **26** register entries closed by mechanism
(H-23 · M-56, M-57, M-58, M-59, M-60, M-61, M-62 · L-96 … L-113). See [SECURITY_AUDIT_0926.md §1](../SECURITY_AUDIT_0926.md).
Three of them are closed only for the shapes their tests pin; the doors the audit found next to them are new
entries below (M-58 → M-65, M-60 → M-68, L-105 → L-122). This tracker covers only what is open: one new High,
seven new Mediums, the M-09 remainder re-rated High by decision (38), twenty-three new Lows, and the carried partials.

**Status legend:** ☐ not started · ◐ in progress · ☑ done
**Effort:** S = < ½ day, M = ~1–2 days.

> **The shape of this backlog.** 0923 found its Highs in the decisions T63/T64 recorded, 0924 in the **order** the
> fixes ran, 0925 in **what each fix tests for** ("what a fresh replica would hold" approximated five ways). T84
> stated that property once, as a rule, and 0926 finds the rule and its neighbours **judging a snapshot where the
> property is a history**: the T85 closure is a set of content ids where membership is a property of one copy's
> parents (H-24); the served-set rule judges admitted history against the *final* account state, which a later
> `open` can narrow (M-63); the rule runs once where its own quarantine creates new strays (M-64); the M-59 refusal
> keeps memory as it stands, including the write the call just failed (M-65); T88's filter reads whichever peer's
> copy it finds (M-66); the M-60 guard binds the link's directory by path, not by handle (M-68). And, as in 0925,
> **the remedies the code prints create the shapes it then refuses**: "restate the chain" is what H-24 partitions,
> "add the missing open" is refused by L-77 (L-121), gl-node's H-20 banner double-counts (M-69). T90 is organised
> around keying the closure on parenthood; T91 around lifecycle verdicts that never retract; T92 around the rule
> reaching a fixpoint and every remedy it prints working; T93–T95 around the recovery reload, the symlink guard
> and the Want filter; T96 around the texts and the proxies. Every task keeps the campaign's rule: revert the fix →
> the named test fails → restore; residuals go in this file, not in code comments.

> **Acceptance tests already exist.** The audit extended the four invariant files —
> [crates/p2p/tests/convergence.rs](../crates/p2p/tests/convergence.rs) (33 passed / 6 ignored),
> [crates/p2p/tests/boot_fuzz.rs](../crates/p2p/tests/boot_fuzz.rs) (55 / 3),
> [crates/ledger/tests/exact_balances.rs](../crates/ledger/tests/exact_balances.rs) (35 / 2),
> [crates/p2p/tests/m50_wire.rs](../crates/p2p/tests/m50_wire.rs) (17 / 5) — and pinned every new finding that
> has a pinnable shape as an `#[ignore = "<pass>-N: …"]` case that fails at HEAD for the stated reason under
> `--ignored` (14 cases). **A task is done when its cases are un-ignored and green, with no other test in the
> file changed** (except where a decision below says so). The two pre-existing ignored cases in `convergence.rs`
> (`h19_fresh_node_converges_after_a_maximal_legal_jump…`, `h19_pre_t63_history_with_one_large_jump_is_joinable`)
> stay ignored by decision (1) of 2026-09-23. Boot fuzzer check 7 (`Checks::EXACT`, "the served set is exactly
> what a fresh peer adopts") is new and runs only in the new sweep until decision (52) says otherwise.

> **Decisions taken 2026-09-26** (user), numbered on from (35) of 2026-09-25 — **the recommended option every
> time**, marked *(chosen)* below; the other options are kept for the record. **(36)** T90 / H-24 — how the
> wire and the live file path decide closure membership: (a) refuse only a copy that names a closure parent the
> DAG lacks, drop an id from the closure once a copy is adopted, and have boot's duplicate-body arm prefer the
> copy whose parents are served *(chosen; validated by A2 and X2 in the archive, every T85 pin green)*;
> (b) drop T85's wire check (pre-T85 behaviour); (c) keep it and document "restate on every node that holds the
> originals, or bootstrap them". **(37)** T91 / M-63 — lifecycle verdicts that a later `open` retracts: (a) the
> wire refuses an `open` of an account already open (reintroduces admission-order dependence for concurrent
> first opens); (b) judge the rule's I3/I9 arm only for accounts this node's own edits changed, and WARN naming
> the narrowing `open`'s author; (c) make the currency constraint in force at date *d* the **union** of every
> `open` dated ≤ *d*, so a later `open` can only admit more and the rule stays "what a fresh replica holds"
> *(chosen)*. **(38)** T91 / M-09 remainder — X1 executed state divergence between honest replicas under
> `compute_want`'s own order (a `close` refused for good because the account was re-opened and posted to later):
> (a) re-rate the remainder **High** and fix now — refuse a `close` only when, under the lifecycle fold, it would
> invalidate a held transaction *(chosen)*; (b) stage lifecycle directives before transactions within a
> Supply; (c) keep it deferred to T45 (Format v2) and document the divergence. **(39)** T92 / M-64 — (a) re-run
> the rule to a fixpoint after every quarantine step (the rebuild's refusals, the finalize ceiling arm)
> *(chosen)*; (b) refuse a hand-parented half envelope whose hand parent is later held. **(40)** T92 / M-69 —
> gl-node's H-20 banner: (a) defer to the per-record reasons and name the working remedies, pinned by a gl-node
> test *(chosen)*; (b) drop the remedy clause from the banner. **(41)** T92 / L-114 — the "EVERY signature
> failed" verdict: (a) leave `finalize_operator_input`'s own fresh signatures out of the verified total
> *(chosen)*; (b) (a) plus refusing to author while the verdict holds (revisits decision (32)).
> **(42)** T92 / L-121 — the "add the missing open" remedy at boot: (a) re-judge operator-input `open`s after the
> signature pass, as the live path's L-110 clause does *(chosen)*; (b) word the remedy per cause ("restore the
> node's own `open`" vs "add one"). **(43)** T93 / M-65 — the M-59 refusal: (a) choose operator input's parents
> from committed records only (exclude `pending_ids`) **and** (b) gl-node refuses before staging whenever
> `canonical_over_cap`, whatever `uncommitted_count()` says *(chosen: both)*; (c) keep and document "a failed
> write may be kept, served and later written". **(44)** T93 / L-115 — the reload's clock: (a)
> `max(rebuild, this node's own discarded staged lamports)` *(chosen)*; (b) memory's whole clock (would also
> keep a discarded peer's jump). **(45)** T93 / L-116 — a live-adopted hand line whose compaction failed: (a) not
> served until its compaction succeeds *(chosen)*; (b) a node-private sidecar of stamped-but-uncompacted
> envelopes boot honours; (c) document "after a failed rewrite, restart only once a write has succeeded".
> **(46)** T94 / M-68 — the symlink guard: (a) resolve through one directory handle (`openat` / `fstatat` /
> `readlinkat`, compare `(dev, ino)`) — race-free for every ancestor, refuses nothing new *(chosen)*; (b) an
> OpenSSH-style ancestor walk (refuses more layouts); (c) document "the directories above matter too".
> **(47)** T94 / L-120 — macOS ACLs: (a) refuse a link directory carrying an extended ACL *(chosen)*; (b)
> document. **(48)** T95 / M-66, L-133 — `retain_not_doomed`: (a) judge only copies or hints the asked peer itself
> delivered, and skip parents the DAG now holds *(chosen)*; (b) drop the filter and accept the TTL-bounded
> cost. **(49)** T95 / L-132 — the uncharged bound: (a) document ~2 MiB per connection (≈60 MiB per peer,
> ≈480 MiB global) and pin the decode control's absolute peak (≈211 MB) instead of a ratio *(chosen)*; (b)
> defer a frame whose next directive alone exceeds the cap, and lower the 4,096-key legacy ceiling (revisits
> decision (29)). **(50)** T96 / L-127 — the gap verdict: (a) also judge the gap without the named top author's
> records, reword the sub-2^32 branch "crossable while every author inside it stays allowlisted", and fix the
> off-by-one at exactly 2^32 *(chosen)*; (b) prescribe the bootstrap join again for every gap ≥ 2^28.
> **(51)** T96 / L-123 — CI: (a) pin a `master` commit of `dtolnay/rust-toolchain` *(chosen)*; (b) replace
> the action with an explicit `rustup` step. **(52)** T96 / L-135 — run `Checks::EXACT` in the existing fuzzer
> sweeps and bound `convergence.rs:3110`'s `>= 1`, which changes existing tests *(chosen: yes)*; or leave the
> existing sweeps as they are. **(53)** Execution — **one task per go-ahead**, as decisions (14) and (35): full
> gate and revert-proofs, stop for the commit, ask before the next; T90 first *(chosen)*.

## Priority order at a glance

| # | Findings addressed | Sev | Effort | Status |
|---|---|---|---|---|
| T90 | H-24 + L-126 — the closure keyed on parenthood; the live path holds what boot holds | **High** | S | ☑ |
| T91 | M-63 + M-09 remainder — lifecycle verdicts that never retract | **High** (M-09 re-rated, decision (38)) | M | ☐ |
| T92 | M-64 + M-69 + L-114 + L-121 + L-125 + L-128 + L-129 + L-131 — the rule reaches a fixpoint; every remedy it prints works | Med | S–M | ☐ |
| T93 | M-65 + L-115 + L-116 + L-117 + L-122 + L-124 — the recovery reload rolls back what failed and keeps the clock | Med | S–M | ☐ |
| T94 | M-68 + L-118 + L-119 + L-120 — the symlink guard bound to one directory handle | Med | S | ☐ |
| T95 | M-66 + M-67 + L-130 + L-132 + L-133 + L-134 — the Want filter: own copies, linear, outside the lock | Med | S–M | ☐ |
| T96 | L-123 + L-127 + L-135 + L-136 — texts, CI, proxies | Low | S | ☐ |

**Coverage check — every open register entry maps to exactly one task:**

H-24→T90 · L-126→T90 · M-63→T91 · M-09 (remainder)→T91 · M-64→T92 · M-69→T92 · L-114→T92 · L-121→T92 ·
L-125→T92 · L-128→T92 · L-129→T92 · L-131→T92 · M-65→T93 · L-115→T93 · L-116→T93 · L-117→T93 · L-122→T93 ·
L-124→T93 · M-68→T94 · L-118→T94 · L-119→T94 · L-120→T94 · M-66→T95 · M-67→T95 · L-130→T95 · L-132→T95 ·
L-133→T95 · L-134→T95 · L-123→T96 · L-127→T96 · L-135→T96 · L-136→T96.

**Deferred by design to T45 (Format v2), unchanged:** M-10, L-06. M-09's remainder is pulled into T91 by
decision (38). **Deferred by decision, unchanged:** H-01's loopback API key; L-23 (`meshId` required next
release).

**T45 interaction:** waves A and B wait for **T90 and T91** — T90 changes what the wire refuses, T91 what an
`open` means for the accounts every replica derives.

**Landing order:** T90 → T91 → T92 → T93 (all four in `service.rs`; T90 first because T92's fixpoint and T93's
reload both re-run the closure T90 re-keys; T91 before T92 because T92's re-judged remedies depend on T91's
lifecycle semantics) → T94 ∥ T95 (disjoint: T94 owns `journal.rs`'s resolution and gl-node `main.rs`'s path arm;
T95 owns `orphan_buffer.rs` and `anti_entropy_alpn.rs`'s Want session) → T96. `service.rs` is the contention point
again: T90–T93 go to one agent in that order or run sequentially. **Extend the four invariant files before each
task, as the audit did**, and run the whole workspace at the end of every wave: the gate at HEAD with the extended
files is **1,396 passed, 0 failed, 16 ignored** (421 + 8 + 594 + 35 + 10 + 190 + 55 + 33 + 7 + 17 + 5 + 21).

---

## Tier 1 — ship-blocker (the new High)

### ☑ T90 — The closure keyed on parenthood, not on content ids; the live path holds what boot holds (H-24, L-126) — S, decision (36) taken
> **Done 2026-09-26 (working tree, not committed).** In `crates/ledger/src/service.rs`, plus README (§Upgrading, the §Editing remedy paragraph, the live-reconcile bullet), the CHANGELOG and `m50_wire.rs`. **(a) H-24, decision (36):** new `names_a_held_back_parent(parent)` — in `refused_history_closure` **and** not in the DAG — is the one test on both paths. `stage_remote_directive` no longer refuses a record by its own id; it refuses (`InvalidInput`, permanent as before) only a copy naming such a parent, and a record whose own body breaks a content rule is still refused by those rules below (`enforce_resource_limits_for`, `enforce_economic_bean_limit`, the amount cap in the wire parser). The live file path (`adopt_file_directive`) drops its own-id refusal the same way: the file's held copy of a closure member still names its refused parent and is refused (and kept) as before, while a pasted copy naming parents this node serves is adopted under the same id. An id leaves the closure when a copy is adopted over the wire or by the live reconcile; the DAG-presence half covers a copy adopted through a path that does not prune (the local API re-entering a held body). **(b) the duplicate-body arm:** boot's loop now keeps the second copy of a transaction body it meets (`duplicate_copies`), and new `prefer_copies_whose_parents_are_served` — run after the loop and **before** the closure is walked — replaces the loaded copy through `rebuild_dag(∅, replacements)` when the loaded copy names a parent the DAG does not hold and the other copy's parents all resolve and none descends from the record (INFO "(H-24)"); the signature pass then judges the copy served. So an API re-entry of a held record followed by a crash is served from the journal's copy, with `Y` on top, with P2P off. **(c) L-126:** new `hold_refused_file_entry` keeps a complete-envelope (history) entry the live path refuses in the quarantine, so the canonical re-persist writes it back as boot does — for the fan-in/parity arm (body cap, envelope form), the History limits, `validate_transaction` (I1–I3, I9), the resolved-body cap and a held-back parent. Operator input the live path refuses is still dropped. **(d)** the closure WARN spells out "restate the chain" (restate the refused record, delete the `openledger-*` lines of each descendant, peers holding the old copies adopt the restated ones) and gains the H-24 tag; the T85 comment in `stage_remote_directive` rewritten (its "no later record can make it adoptable" was false for the own-id term). README §Upgrading and the §Editing remedy paragraph say the same; the live-reconcile bullet says which refused entries are kept. **(e)** `m56_the_wire_refuses_what_the_closure_holds` keeps its assertions (a copy naming the flood, and one naming the held child, are still `INVALID_INPUT`); its doc now says it drives the library entry point and that gl-node buffers a missing parent before staging. **Acceptance:** un-ignored and green: `a2_a_restated_chain_reaches_every_node_that_held_the_old_one`, `a2_a_record_reentered_through_the_api_returns_from_a_peer_after_a_crash`, `a2_the_live_reconcile_keeps_in_the_file_what_boot_keeps` (`m50_wire.rs`, now 21 / 2 ignored — the two left are T91's A2-4 and T92's A2-2). **New tests (4):** ledger `h24_a_restated_copy_of_a_held_record_is_adopted_on_the_wire` (the flood-child copy stays `INVALID_INPUT`, the restated copy is adopted, the id leaves the closure, a child on top stages — also after the id is put back, i.e. through a non-pruning path), `h24_a_pasted_copy_of_a_held_record_naming_served_parents_is_adopted_live` (adopted live, the held copy released, served after a restart), `l126_a_pasted_record_over_the_body_cap_or_a_history_limit_stays_in_the_file` (a 1.1 MB body and a 4,097-key record, each held and kept by the compaction); `m50_wire` `h24_after_a_crash_the_node_serves_its_re_entered_record_and_what_it_wrote_on_top` (the A2-1 crash with no peer: `C` and `Y` served after the restart, `C`'s served parents all resolve, a fixed point across the next restart). **Existing tests changed (1), by (c):** `a_pasted_complete_envelope_is_counted_as_it_arrives_and_an_unsigned_own_one_is_never_signed_past_the_cap` — its second reconcile counts `(0, 2)` rejected instead of `(0, 1)`: B's 97-key record is now held and kept in the file, so the next reconcile reads and refuses it again (as every boot-held record already is at every reconcile). **Revert-proven (8, scratch copy of the working tree, each restored and compared equal):** R1 the wire refuses by content id again → `h24_a_restated_copy…` and `a2_a_restated_chain…` fail; R2 the live path refuses by content id again → `h24_a_pasted_copy…` fails; R3 no duplicate-copy preference → `h24_after_a_crash…` fails; R4a no hold in the validation arm → `a2_the_live_reconcile_keeps…` fails; R4b no hold in the parity arm and R4c none in the limits arm → `l126_*` fails; R5 no closure pruning on the wire → `h24_a_restated_copy…` fails (the id stays held back); R6 the parent test without DAG presence → `h24_a_restated_copy…` fails (the child on top refused). **Audit probes, re-run against this code:** X2 `c1f` — A2 holds `D` and `E` in the DAG from round 1, `A1==C` and `A2==C` true in all three restart rounds (was `REFUSED-for-good`, balances differing); `c1e` — `A==C`, `B==C` true in every round; `c1d` — `K`, `L`, `M` in A's DAG from tick 1 with no restart (was refused until A restarted). **Gate:** clippy `-D warnings` and `fmt --check` clean; `cargo test --workspace --locked --no-fail-fast` **1,403 passed, 0 failed, 13 ignored** (gl-node 421, integration 8, ledger 597, exact_balances 35/2, property 10, p2p 190, boot_fuzz 55/3, convergence 33/6, decode_memory 7, m50_wire 21/2, property 5, security 21); the 13 ignored are decision (1)'s two joins and the eleven 0926 cases T91–T96 own. **Behaviour changes:** a copy of a held record whose parents this node serves is adopted from a peer or a pasted block, so a chain restated on one node reaches every node that holds the old copies; after a crash that leaves two copies of one record in the file and the journal, boot serves the one whose parents it holds; a node-written record the live reconcile refuses for a reason boot would hold it for stays in the file, held, instead of being deleted by the re-persist — and, like boot's held records, is counted as rejected at every later reconcile. **Residuals:** a complete envelope the live path refuses for its signature (H-20), a stray `openledger-*` key the strip cannot remove, or a control character is still dropped from the file where boot quarantines it (outside (c)'s list; H-20's live refusal is the pre-existing design); the duplicate-copy preference applies only when the loaded copy's parents do not resolve — two copies that both resolve keep the first, as before; the wire's "names a held-back parent" branch is still reached only by library callers, gl-node buffering a missing parent first (the child of a refused record is then suppressed by L-106, as before); a `balance`/`note`/… on a held account stays as T85 left it.
- **Why:** **H-24.** `refused_history_closure` is a set of content ids built from *this file's copy's* parents
  ([service.rs:5244-5263](../crates/ledger/src/service.rs#L5244)); a content id hashes the economic body only
  ([hash.rs:15-19](../crates/ledger/src/hash.rs#L15)). `stage_remote_directive` refuses any record whose own id is in
  the closure, whatever the offered copy's parents ([:8857-8881](../crates/ledger/src/service.rs#L8857)), and so
  does the live file path ([:7843-7870](../crates/ledger/src/service.rs#L7843)); gl-node classifies the refusal
  permanent ([anti_entropy_alpn.rs:2473-2497](../crates/gl-node/src/anti_entropy_alpn.rs#L2473)); the held block
  stays in the file (H-08) and re-seeds the closure at every boot. (1) The README's own "restate the chain"
  remedy on one node of a pre-T65 mesh: that node and fresh replicas serve C and G, every other node refuses them
  for good across restarts, balances differ (A2 `a2_a_restated_chain…`, X2 `c1f`, `c1e`); a T79–T83 receiver
  adopts them (mixed-version divergence). (2) An API re-entry of a held record plus a crash: boot's duplicate-body
  arm keeps the canonical file's old copy, the closure takes the node's own acknowledged records and refuses every
  peer's copy (A2 `a2_a_record_reentered…`). (3) Restating through the API: the node refuses its peers' children of
  the restated records until it restarts (X2 `c1d`). T84 healed all three over the wire; T85 made them permanent.
  The "names a closure parent" branch never fires on gl-node's path (missing parents are buffered first,
  [anti_entropy_alpn.rs:2138-2160](../crates/gl-node/src/anti_entropy_alpn.rs#L2138)); `m56_the_wire_refuses…`
  pins the library entry point. **L-126.** T85's live hold covers the missing-parent arm only
  ([:8082-8108](../crates/ledger/src/service.rs#L8082)); a pasted complete envelope that fails
  `validate_transaction` goes to `tally.refuse` ([:8164-8166](../crates/ledger/src/service.rs#L8164)) and the
  re-persist drops it from the file, where boot quarantines and keeps the same bytes.
- **Change:** (a) decision (36): refuse on the wire and on the live file path only a copy that names a closure
  parent the DAG lacks (drop the `contains(&content_id)` term), and remove an id from the closure once a copy of it
  is adopted; (b) boot's duplicate-body arm prefers the copy whose parents are served (so an API re-entry survives
  a crash); (c) L-126: quarantine every complete envelope the live path refuses for a reason boot would hold it for
  (validation, body cap, closure), as T89 did for stray keys; (d) re-word the closure WARN's "no later record can
  make it adoptable" and the T85 comment at :8852-8855; (e) replace `m56_the_wire_refuses…`'s library-level
  premise with gl-node's intake order, or add the gl-node-path case beside it.
- **Files:** [service.rs:3860, 5244-5280, 7843-7870, 8082-8166, 8852-8881](../crates/ledger/src/service.rs#L8857),
  [anti_entropy_alpn.rs:2138-2160](../crates/gl-node/src/anti_entropy_alpn.rs#L2138), README §Upgrading, CHANGELOG.
- **Verify:** un-ignore and pass `a2_a_restated_chain_reaches_every_node_that_held_the_old_one`,
  `a2_a_record_reentered_through_the_api_returns_from_a_peer_after_a_crash`,
  `a2_the_live_reconcile_keeps_in_the_file_what_boot_keeps` (`m50_wire.rs`); X2 `c1f`, `c1e`, `c1d`
  (`…/scratchpad/X2/target/release/x2 c1f`) converge; `m56_*`, `l110_*`, `l40_*`, `ct9_*`,
  `a2_the_closure_is_refused_on_the_wire…` stay green. Bug-catch proof for (a), (b), (c) separately.

---

## Tier 2 — lifecycle, the rule's fixpoint, the recovery reload, the symlink guard, the Want filter

### ☐ T91 — Lifecycle verdicts that never retract (M-63, M-09 remainder) — M, decisions (37), (38) taken
- **Why:** **M-63.** `stage_remote_directive` inserts a peer's `open` as data with no lifecycle check
  ([service.rs:9015-9027](../crates/ledger/src/service.rs#L9015), M-09's design); the L-77 "already open" refusal
  exists only on the file path ([:8187](../crates/ledger/src/service.rs#L8187)) and the API. I9 at date *d* is
  decided by the latest `open` on or before *d*, so a later-arriving `open Assets:Cash 2024-01-04 EUR` retroactively
  refuses USD transactions every replica admitted. `unservable_history` judges every served transaction against
  the *final* `AccountState` ([:4593](../crates/ledger/src/service.rs#L4593)) and walks descendants
  ([:4600-4616](../crates/ledger/src/service.rs#L4600)) — through heads, all later history on every account — at
  the next boot ([:4051](../crates/ledger/src/service.rs#L4051)) or live reconcile ([:7642](../crates/ledger/src/service.rs#L7642)).
  Executed (A1 `a1p0926 i9`, A2 `a2_a_peer_open…`): the running node serves T1–T4, the restarted node T1 only; a
  fresh node's acknowledged write vanishes at its restart; no remedy the WARN prints works (the hand `open` is
  refused as already open; a bootstrap copies the same `open`). An honest variant: two partitioned nodes opening
  one account with different currency lists. **M-09 remainder.** `reject_backdated_close`
  ([:8460](../crates/ledger/src/service.rs#L8460)) refuses a `close` when any held posting is later, including
  postings after a later re-open that the fold ([accounts.rs:247-256](../crates/ledger/src/accounts.rs#L247))
  admits; `compute_want` puts remote heads first ([anti_entropy.rs:35](../crates/p2p/src/anti_entropy.rs#L35)),
  arrival order is kept ([anti_entropy_alpn.rs:1980](../crates/gl-node/src/anti_entropy_alpn.rs#L1980)) and
  `AccountHasLaterTransactions` is permanent ([:2483](../crates/gl-node/src/anti_entropy_alpn.rs#L2483)). X1
  `n3e`: a replica back online refuses the honest `close` for good; its balance is 8.00 where every other
  replica's is 7.00, and its next back-dated entry and every later write are refused mesh-wide. T29's residual
  "STATE divergence for a fixed set is not possible" is wrong for this shape.
- **Change:** (a) decision (37): make the lifecycle verdict for a transaction monotone in the directive set — the
  recommended form is the union of currencies over every `open` dated ≤ *d*; the served-set rule's I9 arm then
  agrees with every fresh replica in every order; (b) whatever (37) chooses, the H-23 WARN names the `open` (id,
  author) whose arrival changed the verdict; (c) decision (38): refuse a `close` only when, under the fold, it
  would invalidate a held transaction (re-opened intervals admitted), so its admission commutes; extend T29's
  permutation fixture with postings after the re-open; (d) README §Editing / the M-09 notes.
- **Files:** [accounts.rs:142-292](../crates/ledger/src/accounts.rs#L142), [validate.rs:397-401](../crates/ledger/src/validate.rs#L397),
  [service.rs:4570-4618, 8460, 9015-9027](../crates/ledger/src/service.rs#L4570), [anti_entropy_alpn.rs:6405-6439](../crates/gl-node/src/anti_entropy_alpn.rs#L6405), README, CHANGELOG.
- **Verify:** un-ignore and pass `a1_0926_1_a_restart_with_nothing_edited_serves_what_the_running_node_served`
  (`boot_fuzz.rs`) and `a2_a_peer_open_never_unserves_history_this_node_already_serves` (`m50_wire.rs`); X1 `n3e`
  and `n3a` converge (`…/scratchpad/X1/target/release/x1 n3e`); `lifecycle_converges_under_every_arrival_order`
  extended with a posting after the re-open. Bug-catch proof for (a) and (c) separately.

### ☐ T92 — The served-set rule reaches a fixpoint, and every remedy it prints works (M-64, M-69, L-114, L-121, L-125, L-128, L-129, L-131) — S–M, decisions (39)–(42) taken
- **Why:** **M-64.** `quarantine_unservable_history` exempts pending operator input
  ([service.rs:4629](../crates/ledger/src/service.rs#L4629)) and its walk stops at it ([:4608](../crates/ledger/src/service.rs#L4608));
  the rebuild it triggers then refuses a hand-parented half envelope whose hand parent it just held
  (`rebase_operator_input` [:5302](../crates/ledger/src/service.rs#L5302), `refused_now` :5156) and re-inserts
  that line's signed history child with a dangling parent (:5163); nothing re-runs the rule (boot :4051, pass
  :4779 is the last step, finalize returns at :4334). X1 `n1a`/`n1b`: C served over a parent held in the
  quarantine, a fresh peer refuses C and every later write, a fixed point, no log line names C. The finalize
  ceiling arm ([:4389-4412](../crates/ledger/src/service.rs#L4389)) quarantines unstampable operator input without
  the rule at all (X1 `n2`, A1 `a1p0926 ceiling`). **M-69.** gl-node's H-20 banner ([main.rs:560-572](../crates/gl-node/src/main.rs#L560))
  still prescribes "delete the edited block and append a reversing entry": followed literally the child stays held
  and the reversal double-counts (X1 `n6a`: Cash 110 vs 88; D1 `case_h23a` Cash −1 vs 3); after enabling signing
  over an unsigned history the operator ends with an empty served ledger (D1 `case_banner_b`). T84's Done note (e)
  says the banner was reworded; only the H-08 banner was. **L-114.** `finalize_operator_input` puts what it just
  signed into `unverified_history` (:4453) and its pass (:4469) counts it verified (:4722): one hand line in the
  same boot, or one write before the next boot, hides the "EVERY signature failed / do not author" WARN and releases
  `release_on_hold` (:4732); the reload judges before finalize (:6818-6819) and prints it — Fresh boot and reload
  differ. A regression against T88 (A6 differential); found by X1, X3 and A6. **L-121.** The H-23 remedy "add the
  missing open, dated no later than the first transaction" is refused by L-77 at boot
  ([:8186-8195](../crates/ledger/src/service.rs#L8186)) whenever the node's own (edited, moved) `open` is still in
  the DAG at adoption — "already open" while `account(...)` is `null` (D1 `case_h23b`, A1 `dated_after`).
  **L-125.** The L-110 clause ([:8208-8226](../crates/ledger/src/service.rs#L8208)) refuses the remedy its own WARN
  names when applied under a running node (the stripped `open` has the held record's own id), and the compaction
  writes the edited envelope back (A2-2). **L-128.** `hand_parented_last` ([:9174-9203](../crates/ledger/src/service.rs#L9174))
  keys on the file-spelled id; an elided-posting hand parent's stored id differs (I2), so its hand child is
  refused at boot 1 and served at boot 2, and deleted from the file on the live path (A6-3). **L-129.** The same
  function is quadratic: a 20,000-line reversed chain boots in 58 s against 0.87 s (A6-5). **L-131.** A held
  descendant the operator retypes beside its original: `unverified_history` is keyed by id, the hand copy is judged
  as history ("no openledger-signature") and the startup compaction drops the typed block silently (X2-3).
- **Change:** (a) decision (39): run `quarantine_unservable_history` to a fixpoint after every quarantine step —
  the rebuild's refusals, the finalize ceiling arm, the M-54 arm; (b) decision (40): the banner defers to the
  per-record reasons and names the working remedies; pin its text in a gl-node test; (c) decision (41): finalize's
  own signatures are not counted as verified history, so the verdict and `release_on_hold` are judged on the
  history only; (d) decision (42): operator-input `open`s re-judged after the signature pass (the live path's L-110
  test, same text) and the H-23 summary words the remedy per cause; (e) L-125: the clause exempts a held record with
  the same id; (f) L-128/L-129: Kahn's algorithm over the stored (I2-resolved) ids; (g) L-131: the signature pass
  skips `unsigned_operator_input` ids and names the collision.
- **Files:** [service.rs:4051, 4333-4470, 4570-4661, 4722-4735, 5145-5163, 5302, 8186-8226, 9174-9203](../crates/ledger/src/service.rs#L4628),
  [main.rs:560-572](../crates/gl-node/src/main.rs#L560), README §Editing, CHANGELOG.
- **Verify:** un-ignore and pass `a1_0926_2_a_ceiling_refused_hand_line_leaves_nothing_served_over_it`,
  `a1_0926_3_the_add_the_missing_open_remedy_frees_what_a_late_open_held` (`boot_fuzz.rs`),
  `a2_the_l110_remedy_followed_under_a_running_node_opens_the_account` (`m50_wire.rs`),
  `a6_2_a_hand_line_in_the_same_boot_does_not_hide_a_wrong_mesh_id`,
  `a6_3_a_hand_child_of_an_elided_posting_hand_parent_is_served_in_one_boot` (`convergence.rs`); X1 `n1`, `n2`,
  `n5`, `n6`; X3 `diff=sh:domain+handopen` → SAME; D1 `case_h23a`, `case_h23b`, `case_banner_b`; A6 `$P/cost`
  reversed 20,000 within 2× of forward; new unit test for L-131. Bug-catch proof per mechanism.

### ☐ T93 — The recovery reload rolls back what failed and keeps the clock (M-65, L-115, L-116, L-117, L-122, L-124) — S–M, decisions (43)–(45) taken
- **Why:** **M-65.** With the watcher off (the default) a running node adopts a hand edit inside the next write's
  `prepare` ([service.rs:6182](../crates/ledger/src/service.rs#L6182), [:6194](../crates/ledger/src/service.rs#L6194));
  the adoption stamps the hand line's parents from every head, including the write staged in the same call
  ([:8003-8010](../crates/ledger/src/service.rs#L8003)); a failed commit then trips T86's M-59 check
  ([:6939-6941](../crates/ledger/src/service.rs#L6939) → REFUSING [:6761-6780](../crates/ledger/src/service.rs#L6761)),
  so memory — with the write whose call returned an error — is kept, counted and served (library: 112 vs 105).
  Near the cap the adopted envelopes push the canonical form over it, the staged write can never be written,
  `pending_ids` stays non-empty so `prepare_refusal_needs_no_reload` is false, and gl-node's pre-stage refusal
  steps aside on `uncommitted_count() > 0` ([ledger_commit.rs:561](../crates/gl-node/src/ledger_commit.rs#L561)):
  every mutation stages, rebuilds under the permit (25–46 s), is refused for the cap and is kept (GraphQL probe:
  Cash −230 running, −215 after restart) — M-58's symptom through a new door; README:1038 is wrong for it.
  **L-115.** `finish_recovery`'s install takes the rebuild's clock (`max + 1`); `keep_committed_envelopes_in`
  raises it only to kept records ([:6951-6957](../crates/ledger/src/service.rs#L6951), whose comment states the
  M-18 rule this breaks); the discarded staged write's lamport is never counted, so the next write re-issues its
  `(author, lamport)` pair — 26 of 27 shapes (X3 `diff=all`), including one with no backup (`k7`); T84's
  provisional stamp turned the 0925 backup shape (`k1b`) into a re-issue; 0925 §9 "no executed shape re-issues a
  pair" is wrong at HEAD. **L-116.** A hand line adopted live and served whose compaction fails is re-stamped from
  the restarted clock at the next boot: two envelopes for one id mesh-wide (X3 `k9`). **L-117.** The reload
  re-resolves `file_path` (`boot_with` → `resolve_ledger_path` [:3263](../crates/ledger/src/service.rs#L3263));
  a ledger moved behind a link while the node runs is worked at the new target while gl-node's lock and watcher
  stay on the old path (X3 `k12`); `adopt_reloaded`'s doc (:7041) says the path is carried. **L-122.** L-105's
  five-byte gap survives in the over-claim arm ([journal.rs:470-497](../crates/ledger/src/journal.rs#L470)): only a
  complete `;;olj ` tag fails closed there, so an acknowledged record under a damaged length over an append torn
  after 1, 3 or 5 bytes is dropped as a torn tail (D1 `case_l105b`); CHANGELOG:133/:188 say the opposite.
  **L-124.** T86's L-104 exemption is dead: boot adoption writes the author and a provisional lamport into the DAG
  copy, so `is_operator_input(memory copy)` is never true ([:6873-6877](../crates/ledger/src/service.rs#L6873));
  the floor's log text (:6745-6750), `finish_recovery`'s doc (:6644-6648) and CHANGELOG:124 describe an empty set.
- **Change:** (a) decision (43): operator input adopted inside `prepare` takes its parents from committed records
  only, so the reload installs and rolls the failed write back as its error says (M-59 stays a backstop); gl-node
  refuses before staging whenever `canonical_over_cap`; (b) decision (44): the install sets the clock to at least
  the highest own lamport among the discarded `pending_ids`; (c) decision (45); (d) L-117: the reload uses
  `file_path` as stored and refuses if it has become a link; fix the doc; (e) L-122: in the over-claim arm, fail
  closed when the remaining bytes minus a trailing proper prefix of `;;olj ` at a line start hash to the record's
  own hash; (f) L-124: delete the exemption and correct the three texts; (g) README:1038 and CHANGELOG:124 say what
  the REFUSING arm keeps.
- **Files:** [service.rs:3263, 6182-6210, 6644-6960, 7041, 8003-8010](../crates/ledger/src/service.rs#L6699),
  [ledger_commit.rs:555-566](../crates/gl-node/src/ledger_commit.rs#L555), [journal.rs:470-497, 549, 586-614](../crates/ledger/src/journal.rs#L470), README, CHANGELOG.
- **Verify:** un-ignore and pass `a3_1_a_write_whose_commit_failed_is_not_in_the_balance_after_the_m59_refusal`
  and `a3_1_a_write_refused_for_the_cap_is_neither_counted_nor_reloaded_for` (`exact_balances.rs`); A3's gl-node
  probe (`…/scratchpad/A3/gl_probe_ledger_commit.rs`) refuses before staging with zero rebuilds; X3 `k7`, `k1b`,
  `diff=all` never re-issue a pair; X3 `k9` same envelope after restart (or not served before); X3 `k12` refuses;
  D1 `case_l105b` k = 1, 3, 5 refuse boot; `m58_*`, `m59_*`, `l104_*`, `l105_*`, `m46_*` stay green. Bug-catch proof
  per mechanism.

### ☐ T94 — The symlink guard bound to one directory handle (M-68, L-118, L-119, L-120) — S, decisions (46), (47) taken
- **Why:** **M-68.** `resolve_ledger_path` inspects the link's directory by path ([journal.rs:208](../crates/ledger/src/journal.rs#L208))
  and follows by path again (`canonicalize` [:226](../crates/ledger/src/journal.rs#L226), `read_link` :231,
  `canonicalize(target dir)` :244): whoever can write any **ancestor** of the link's directory swaps the whole
  directory between the check and the follow (`renamex_np(RENAME_SWAP)` / `renameat2(RENAME_EXCHANGE)`); the
  follow and the one-hop comparison both see the attacker's link and agree. A4 `raceswap`: 152–276 victim
  resolutions per 5 s; `consequence`: `boot(victim)` + `compact()` rewrites the victim file. T87's "race-free by
  construction" holds for the link's own directory only; README says nothing about the directories above.
  **L-118.** The Fresh-boot sweep of `<link>.tmp.*` ([service.rs:3297](../crates/ledger/src/service.rs#L3297)) runs
  only when `file_path != configured`; gl-node passes `boot` the resolved path (main.rs:216, :247), so it never runs
  on the binary (A4 `case_sweep_and_remedy.py`); `m61_boot…` pins a library path. **L-119.** The one-hop check
  compares path strings ([journal.rs:237-250](../crates/ledger/src/journal.rs#L237)); a link whose target differs
  from the on-disk name in case or Unicode normalisation (macOS default APFS) is refused as "itself a symbolic
  link" (A4 `hops`, real binary exit 1). **L-120.** The directory rule reads mode bits only
  ([:208-210](../crates/ledger/src/journal.rs#L208)); a macOS ACL granting everyone add/delete passes (A4 `acl`,
  X3 `k11`).
- **Change:** (a) decision (46): open the link's directory once (`O_DIRECTORY`), `fstat` it for owner/mode,
  `fstatat(AT_SYMLINK_NOFOLLOW)` the link, `readlinkat` the target, and compare the target by `(dev, ino)` against
  the resolved file — every check bound to one directory inode; README: the directories above matter; (b) L-118: a
  public sweep gl-node calls after taking the lock when the resolved path differs from the configured one (never by
  passing the link path to `boot`, which would resolve twice); a gl-node-level test; (c) L-119: identity compare
  (falls out of (a)); (d) decision (47); (e) the README/CHANGELOG upgrade note names `chmod g-w,o-w <dir>` for
  umask-002 (0775) data directories (Info from A4).
- **Files:** [journal.rs:181-279, 800-815](../crates/ledger/src/journal.rs#L181), [service.rs:3290-3299](../crates/ledger/src/service.rs#L3290),
  [main.rs:195-247](../crates/gl-node/src/main.rs#L195), README §The commit journal, CHANGELOG.
- **Verify:** A4 `p1 raceswap` (`…/scratchpad/A4/target-p1/release/p1 raceswap …/A4/runs 5`) — zero victim
  resolutions; A4 `hops` — case/NFD variants resolve, chains still refused; A4 `acl` refused (per (47));
  `case_sweep_and_remedy.py` — the stale temp beside the link is swept on the binary; `m60_*`, `m61_*`, `l84_*`
  stay green; new unit tests per mechanism with bug-catch proofs.

### ☐ T95 — The Want filter: own copies only, linear, outside the lock; the stated bounds (M-66, M-67, L-130, L-132, L-133, L-134) — S–M, decisions (48), (49) taken
- **Why:** **M-66.** `retain_not_doomed(peer=H)` takes a Want id's parents from whichever peer's buffered copy or
  hint it finds ([orphan_buffer.rs:348-356](../crates/p2p/src/orphan_buffer.rs#L348)) and asks only whether they are
  refused for H (:362). A content id covers the body only, so an allowlisted author M pushes a second envelope of
  its own record C (parents = a record V refused from H for good — the M-09 close split M controls by delivery
  order) and V never Wants C, or anything honest written on top of it, from any honest peer: real QUIC in the repo
  (A5-1): control C and D adopted; attacked C Wanted 0 times, not adopted; with the call removed, adopted. Renewable
  every ~10 min (the refusal TTL) with each new record; gossip does not rescue it (announces are for local writes).
  T88's "other peers are unaffected" is wrong. **M-67.** The filter's fixpoint re-walks the whole Want per newly
  doomed id and runs before `order_want_ancestors_first` ([anti_entropy_alpn.rs:1289](../crates/gl-node/src/anti_entropy_alpn.rs#L1289)
  vs :1311), under `orphan_buffer.read()`: a child-first advert of 9,192 ids costs 9.8–14.6 s per exchange (3.5 ms
  parent-first), every 5 s; phase 2 of any batch holds `ledger.write()` while it waits for `orphan_buffer.write()`,
  so GraphQL queues behind it (stall PLAUSIBLE, from the lock order). **L-130.** The filter covers only a root the
  same peer served and whose refusal is still cached: a root never served, or a peer past its 4,096-entry refusal
  share ([anti_entropy.rs:788-790](../crates/p2p/src/anti_entropy.rs#L788)), costs a full verify per buffered child
  per tick forever — an honest T79–T83 node serving H-23's dangling records triggers it (X2 `c3`, `xver s1`).
  **L-132.** The uncharged bound is `max(1 MiB, one directive)` per connection
  ([anti_entropy_alpn.rs:1953-1980](../crates/gl-node/src/anti_entropy_alpn.rs#L1953)); one admitted directive
  weighs 1.87–1.97 MB, so ≈60 MiB per peer and ≈480 MiB global, where [connection_limiter.rs:90-104](../crates/gl-node/src/connection_limiter.rs#L90)
  and CHANGELOG:118 say "about its own byte budget"; dense content commits once per directive, not per ~1 MiB
  (A5-6a); `decode_memory`'s "densest admitted" control is 14.4× where the same caps admit 28.25× (211 MB absolute,
  A5-6b). **L-133.** A hint C→[X] survives `parent_arrived(X)` ([orphan_buffer.rs:582-585](../crates/p2p/src/orphan_buffer.rs#L582))
  and the filter never checks X is still missing: C stays unrequested up to the TTL after X arrived from another
  peer. **L-134.** The hint sweep is a full pass per distinct expiring hint time (`oldest_hint_at`,
  [:428-450](../crates/p2p/src/orphan_buffer.rs#L428)), 0.4–9 ms each at a full table, under the orphan write lock.
- **Change:** (a) decision (48): judge only copies/hints the asked peer itself delivered (`from_peer`, the hint's
  peer) and skip parents the DAG now holds (closes L-133); (b) M-67: order ancestors-first before filtering and
  compute the doomed set in one pass over a parent→children index, on a snapshot outside the lock; (c) L-130: do
  not re-Want ids already in the orphan buffer — Want their missing parents instead; (d) decision (49); (e) L-134:
  keep hints in insertion order (a `VecDeque`, as `RefusalCache`) and pop the expired front.
- **Files:** [orphan_buffer.rs:271-450, 582-585, 741](../crates/p2p/src/orphan_buffer.rs#L340),
  [anti_entropy_alpn.rs:1289-1315, 1712, 1953-1991](../crates/gl-node/src/anti_entropy_alpn.rs#L1289),
  [connection_limiter.rs:90-104](../crates/gl-node/src/connection_limiter.rs#L90), [decode_memory.rs](../crates/p2p/tests/decode_memory.rs), CHANGELOG.
- **Verify:** A5's `a5_1_an_equivocating_author_suppresses_an_honest_peers_copy` (`…/scratchpad/A5/proofs/a5_1_repo.rs`,
  real QUIC, in the repo tree by the gotcha-6 procedure) adopts C and D; `a5_orphan` `a5_7` child-first within 2×
  of parent-first, `a5_4` keeps C, `a5_6` O(expired) per sweep; X2 `c3` validates 0 per tick from tick 2; the
  decode control pinned per (49); `l90_*`, `l106_*`, `l107_*`, `l95_*` stay green. Bug-catch proof per mechanism.

---

## Tier 3 — texts, CI, proxies

### ☐ T96 — The gap verdict, the CI pin, the proxies and the texts (L-123, L-127, L-135, L-136) — S, decisions (50)–(52) taken
- **Why / change, one line each:**
  - **L-127** — `lamport_gap_verdict` ([service.rs:1434-1451](../crates/ledger/src/service.rs#L1434)) is judged over
    the served DAG, which still holds a removed author's records (gl-node's verifier does not consult the
    allowlist), so two consecutive sub-2^32 jumps by that author are "crossable, no join needed" while a fresh
    joiner is partitioned (A6-1); 17 or more sub-2^28 steps partition with no WARN at all (a blind spot since T83);
    the verdict's `>=` at exactly 2^32 is one off against the ratchet ([:1562](../crates/ledger/src/service.rs#L1562)) and
    adoption's `max + 1` (A6-4). Change, decision (50).
  - **L-123** — the CI re-pin `dtolnay/rust-toolchain@6bed076` ([ci.yml:30](../.github/workflows/ci.yml#L30)) is a
    leaf reachable only from the regenerated `stable` branch; the next regeneration orphans it as it orphaned
    `4360b52`. Change, decision (51).
  - **L-135 (proxies)** — the boot fuzzer is blind to T84's I3/I9 arm (mutation off: 48/0 green) and
    `assert_refused_with_descendants` ([boot_fuzz.rs:1794](../crates/p2p/tests/boot_fuzz.rs#L1794)) is a count bound
    (hold-everything: 10 of 11 T84-changed cases still pass), `convergence.rs:3110`'s `>= 1` is unbounded (A1-4);
    `l108_*` does not catch a missing topological sort (A6 R5b); `m56_the_wire_refuses…` pins the library entry, not
    gl-node's order (X2); `l90_*`'s high-water mark runs with an uncharged body (A5); the log check in
    `m51_history_over_the_legacy_ceiling…` fails whenever it runs beside the T85 tests (tracing's callsite-interest
    cache; `--test-threads=1` passes) (A2-5). Change: decision (52); `capture_warnings` calls
    `tracing::callsite::rebuild_interest_cache()`; each named test gains the missing assertion.
  - **L-136 (texts)** — README live-path bullets ([README.md:999-1011](../README.md#L999)) do not describe T85's
    hold or T89's strip; §Verify lacks `quarantined`, `quarantinedTotal`, `unparsableBlocks` (D1-5); "returns by
    itself once a peer re-supplies the parent" (service.rs:8103, README:861, CHANGELOG:60) — only if a peer also
    holds the record itself (X2-4); the L-81 keep WARN ([:6800-6808](../crates/ledger/src/service.rs#L6800)) blames a
    restored backup on ordinary failed-compaction reloads (X3-6); the M-52 "restate" remedy is refused on a
    currency-constrained account and needs the `open` edited too (D1); T85's "`close_account`'s size check is
    unreachable" is wrong — an `open` of exactly 1,048,576 bytes makes its `close` one byte over, so that account
    can never be closed (A2). Change: reword each.
- **Files:** [service.rs:1434-1451, 6800-6808, 8103](../crates/ledger/src/service.rs#L1434), `.github/workflows/ci.yml`,
  [boot_fuzz.rs](../crates/p2p/tests/boot_fuzz.rs), [convergence.rs](../crates/p2p/tests/convergence.rs), README, CHANGELOG.
- **Verify:** un-ignore and pass `a6_1_a_removed_authors_two_sub_2_32_steps_are_called_crossable_yet_block_a_join`
  and `a6_4_a_gap_of_exactly_2_32_is_called_uncrossable_by_a_node_that_just_crossed_it` (`convergence.rs`);
  `git ls-remote` shows the new pin on `master`; `cargo test -p ledger --lib -- m56_ l110_ m51_ l40_ ct9_` green in
  parallel; under decision (52) the existing sweeps fail under A1's M1 and M2 mutations.

---

## Residuals carried into this backlog (unchanged, for the record)

- **H-01** loopback API key (deferred by decision); **M-10 / L-06** — T45 (Format v2); **M-09** — T91 by
  decision (38); waves A+B wait for T90 and T91.
- **L-23 / R-9** — `meshId` required next release. **R-8**, **R-14 / R-15**, **R-16** — unchanged since 09/23.
- **H-19 by decision (1):** anti-entropy-only joins across a removed author's jump or a pre-T63 jump remain
  impossible by design; the two ignored harness cases document it.
- **T84–T89 residuals re-checked and still accurate:** a library caller that appends before
  `finalize_operator_input`; a `balance`/`price`/`note`/`document`/`pad` on an account no served `open` opens stays
  served (peers insert them unchecked); a library write on an over-cap ledger pays one reload; the leading comments
  are captured at boot only; the reverse symlink move leaves the target's journal behind; the other-uid owner and
  directory refusals are untestable without a second account; a budget-exhausted peer's frame costs more commits;
  the "do not author" instruction is advisory (decision (32)); the one-slot clock step across a restart.
- **§5 informational items** in the 0926 report not assigned above: the reload's clock is one higher than a Fresh
  boot's when the kept hand line is counted by the L-87 release (safe direction); a sticky 1777 directory is
  refused (policy); four colluding allowlisted transport ids fill the hint table and the refusal cache (¼ shares, by
  design); `finalize_operator_input` re-stamps the DAG and the read model but not `self.accounts`' lifecycle keys
  (PLAUSIBLE, relative order preserved); the live `ReconcileResult` counts a record the post-loop rule then holds as
  new, whose foreign lamport has already moved the clock; the H-23 summary and banners join every id into one line
  (67 KB at 1,005 ids); the T85 live hold is logged under the "already quarantined" header on first sight; a
  re-adopted parent's lamport can sit above its child's (no consumer checks); the "no signature" summary wording also
  covers M-47 "author but no lamport" refusals.

---

## Regression-test manifest (must exist by the end of Tier 2)

Every item is already pinned as an `#[ignore]`d case (or a named probe); un-ignoring it is the acceptance
criterion.

1. A restated or re-entered record reaches every node that held the old copy; the live path keeps what boot keeps
   (T90 / H-24, L-126): `a2_a_restated_chain_…`, `a2_a_record_reentered_…`, `a2_the_live_reconcile_keeps_…`
   (`m50_wire`).
2. A peer's `open` never un-serves admitted history; a `close` admission commutes with a later re-open (T91 /
   M-63, M-09): `a1_0926_1_…` (fuzzer), `a2_a_peer_open_never_…` (`m50_wire`), X1 `n3e`.
3. Nothing is served over a held parent after any quarantine step; every remedy the code prints works; the
   "EVERY failed" verdict ignores this boot's own signatures; hand-parented ordering by stored id (T92 / M-64,
   M-69, L-114, L-121, L-125, L-128): `a1_0926_2_…`, `a1_0926_3_…` (fuzzer), `a2_the_l110_remedy_followed_…`
   (`m50_wire`), `a6_2_…`, `a6_3_…` (harness), a gl-node banner test.
4. A write whose call failed is never counted or kept; the reload never re-issues a pair; a torn-in-tag append
   under a damaged length fails closed in both arms (T93 / M-65, L-115, L-122): `a3_1_…` ×2 (`exact_balances`),
   X3 `k7`/`k1b`, D1 `case_l105b` as unit tests.
5. The symlink guard holds against an ancestor swap and compares identities (T94 / M-68, L-119): A4 `raceswap`,
   `hops` as unit tests.
6. One peer cannot suppress another's copy; the filter is linear (T95 / M-66, M-67): A5-1 as a gl-node QUIC test,
   `a5_7` as a p2p test.
7. The gap verdict matches the join a fresh node can make (T96 / L-127): `a6_1_…`, `a6_4_…` (harness).

Every one needs its **bug-catch proof** — revert the fix, watch the named test fail, restore — and the
orchestrator re-verifies each mechanism in source and re-runs the suite on a quiet machine. The proof crates for
every finding are in the 0926 session's scratchpad (`A1` … `A6`, `X1` … `X3`, `D1`); each pass's summary and
re-run commands are under `orch/reports/`. Real-QUIC revert-proofs run in the repo tree only (fresh binaries in
scratch targets cannot use loopback QUIC on this machine — §6 of the report).

---

*Audit: [SECURITY_AUDIT_0926.md](../SECURITY_AUDIT_0926.md). Previous trackers:
[OUTSTANDING_TASKS_09_25.md](OUTSTANDING_TASKS_09_25.md) (T84–T89) ·
[OUTSTANDING_TASKS_09_24.md](OUTSTANDING_TASKS_09_24.md) (T79–T83) ·
[OUTSTANDING_TASKS_09_23.md](OUTSTANDING_TASKS_09_23.md) (T72–T78) ·
[OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md) (T61–T71) ·
[OUTSTANDING_TASKS_09_22.md](OUTSTANDING_TASKS_09_22.md) (T46–T60, R-1…R-21) ·
[OUTSTANDING_TASKS_09.md](OUTSTANDING_TASKS_09.md) (T18–T45) · [OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md)
(T1–T17). Format v2 design: [FORMAT_V2_DESIGN.md](FORMAT_V2_DESIGN.md).*
