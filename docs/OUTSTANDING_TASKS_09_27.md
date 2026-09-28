# Outstanding Security Tasks — 2026-09-27

Remediation backlog for every open finding in [SECURITY_AUDIT_0927.md](../SECURITY_AUDIT_0927.md), the re-audit of
T90–T97. Task numbering continues from [OUTSTANDING_TASKS_09_26.md](OUTSTANDING_TASKS_09_26.md) (T90–T97, all ☑).
Line references are current as of HEAD `a5313a1`.

**Already closed — do not re-do:** the 0927 audit verified **33** register entries closed by mechanism (H-24 · M-63,
M-64, M-65, M-66, M-67, M-68, M-69, M-70 · L-114 … L-136), and the M-09 remainder closed for the order 0926 executed
(`n3e`). See [SECURITY_AUDIT_0927.md §1](../SECURITY_AUDIT_0927.md).

Seven of them are closed only for the shapes their tests pin; the doors the audit found next to them are new entries
below:

| Closed | Door found beside it |
|---|---|
| H-24 | M-72 |
| M-65 | M-74 |
| M-66 | M-76 |
| M-68 | M-71 |
| L-115 | L-148 |
| L-131 | L-143 |
| M-09 (0926 order) | H-25 |

This tracker covers only what is open: one new High, the M-09 remainder (still High), six new Mediums, twenty-one new
Lows, and the carried partials.

**Status legend:** ☐ not started · ◐ in progress · ☑ done
**Effort:** S = < ½ day, M = ~1–2 days.

> **The shape of this backlog.**
> - Each audit has found its Highs somewhere new: 0923 in the decisions T63/T64 recorded, 0924 in the **order** the
>   fixes ran, 0925 in **what each fix tests for**, 0926 in **judging a snapshot where the property is a history**.
> - T90–T97 re-keyed each check on the history. 0927 finds that **each new verdict is still taken at a moment,
>   against the state that moment holds, and the machinery that makes it is replica- or process-local**:
>   - T91's `close` interval is bounded by the events held at arrival, and gl-node caches the refusal as permanent
>     (H-25);
>   - T90's copy preference is judged before the closure, the signature pass and the rule have spoken (M-72);
>   - T93's cap gate trusts a fact measured before the pending rewrite (M-74), and its clock floor lives in memory
>     (L-148);
>   - T94's identity check binds the file, not the path (M-71);
>   - T95 made the filters per-peer, but not the buffer slot or the Want order (M-76).
> - **The remedies the code prints still create the shapes it refuses**:
>   - "restate the chain" is printed on every node (M-73);
>   - "restore the original line" after a local `close` partitions the node (M-75);
>   - "add the missing open" typed as the account's own line is dropped at boot (L-143).
> - How the tasks are organised:
>   - T98 — lifecycle verdicts that are a function of the directive set;
>   - T99 — boot judging copies after the passes, in one iteration;
>   - T100 — the commit gate and every refusing arm measuring and keeping only what the commit wrote;
>   - T101 — the symlink guard binding the returned path;
>   - T102 — the orphan buffer keyed per delivering peer;
>   - T103 — the remedy texts.
> - Every task keeps the campaign's rule: revert the fix → the named test fails → restore; residuals go in this file,
>   not in code comments.

> **Acceptance tests already exist.** The audit extended the four invariant files:
> - [crates/p2p/tests/m50_wire.rs](../crates/p2p/tests/m50_wire.rs): 26 passed / 6 ignored;
> - [crates/ledger/tests/exact_balances.rs](../crates/ledger/tests/exact_balances.rs): 40 / 3;
> - [crates/p2p/tests/boot_fuzz.rs](../crates/p2p/tests/boot_fuzz.rs): 61 / 5;
> - [crates/p2p/tests/convergence.rs](../crates/p2p/tests/convergence.rs): 38 / 6.
>
> Every new finding with a pinnable shape in those files is pinned as an `#[ignore = "<pass>-N: …"]` case that fails
> at HEAD for the stated reason under `--ignored` (17 cases). **A task is done when its cases are un-ignored and green,
> with no other test in the file changed** (except where a decision below says so).
>
> Three pre-existing ignored cases in `convergence.rs` stay ignored:
> - `h19_fresh_node_converges_after_a_maximal_legal_jump…` and `h19_pre_t63_history_with_one_large_jump_is_joinable`,
>   by decision (1);
> - `l114_one_write_under_the_wrong_domain…`, by decision (41).
>
> Five findings are pinned by **proposed tests in `src` files**, which the audit did not modify (no product code). The
> task adds each one, ignored, before its fix; the passes' sources are quoted in the task. They cover:
> - H-25: X2's gl-node test;
> - M-71: A5's `journal.rs` test;
> - M-74: A4's gl-node probes;
> - M-76: X2's real-QUIC gl-node test;
> - decision (44)'s re-application: A4's `a4_l115b_…`, a passing pin.

> **Decisions taken 2026-09-27** (user), numbered on from (53) of 2026-09-26 — **the recommended option every
> time**, marked *(recommended)* below; the other options are kept for the record. (55) and (56) were answered as
> fallbacks and are **moot under (54a)**: with a peer's or file `close` never refused, H-25's refusal and M-75's
> door do not arise; T98 implements (54a) and adds neither.
>
> **T98**
> - **(54) the M-09 remainder** — one allowlisted peer's `close` plus one posting inside its interval, or an honest
>   partition, split honest replicas for good:
>   - (a) *(recommended)* make the verdict a function of the directive set. A peer's or a file's `close` is never
>     refused, and it is inert over any interval that holds a transaction in the set. It still binds this node's own
>     API writes (FR-3 AC2), and I3 on the ingest and served-set paths ignores a `close` that has a held transaction
>     after it inside its interval. This needs no Format change and also removes H-25's refusal and M-75. The
>     trade-off: a `close` no longer stops a peer's back-dated posting; only the node's own API is stricter.
>   - (b) keep it open, High, for T45's causal `close` (a lifecycle record naming parents). Do H-25's wait (55) now,
>     and document the consequence and the re-open repair in README and the refusal WARN.
>   - (c) accept it as a residual, as T91 did.
> - **(55) H-25**, needed unless (54a):
>   - (a) *(recommended; fix-proven by X2)* gl-node treats `AccountHasLaterTransactions` as an account wait,
>     re-judged when an `open` of the account lands, never cached permanent. This changes one assertion of
>     `backdated_remote_close_is_rejected_and_appends_keep_working` (the close now waits).
>   - (b) the ledger re-judges refused `close`s on each `open` it stages.
>   - (c) document the window.
> - **(56) M-75**, needed unless (54a):
>   - (a) *(recommended)* judge every `close` (API, file, wire) against the read model plus this node's held history
>     (the quarantine's complete-envelope transactions on the account).
>   - (b) refuse any `close` while the account has held history.
>   - (c) document the limit of the "restore" remedy.
> - **(57) widen `lifecycle_converges_when_the_account_is_posted_to_after_a_reopen`'s seeds** from `1..=32` to
>   `1..=400`. This changes an existing test; seed 42 fails at HEAD. *(recommended: yes)*
>
> **T99**
> - **(58) M-72**:
>   - (a) *(recommended)* keep the duplicate copies until after the closure, the signature pass and the rule. Inside
>     the fixpoint, install an alternative that verifies and whose parents are served, then re-run; detect cycles once
>     over the chosen copies.
>   - (b) the journal's copy always wins at boot.
>   - (c) document "after a crash, re-enter a held chain parent-first".
> - **(59) L-143 / L-145, typed copies of held records**:
>   - (a) *(recommended)* park an envelope-less duplicate of an id still unverified, and re-offer it as operator input
>     when the history copy ends held. Keep a typed spelling that finalize refuses in the file, and prune the closure
>     only once the typed copy is finalised. This gives the in-place strip's outcome.
>   - (b) narrow the Done note and CHANGELOG to "closure-held records", with an INFO naming the dropped block and the
>     WARN worded per outcome.
> - **(60) L-146, the fixpoint**:
>   - (a) *(recommended; fix-proven by A3)* walk through pending hand-parented children whose hand parent is held, so
>     one round suffices, and iterate for anything else.
>   - (b) iterate only, keeping the rounds (quadratic, no abort).
>   - (c) decision (39b): refuse a hand-parented half envelope whose hand parent is held.
>
> **T100**
> - **(61) M-74, the cap gate**:
>   - (a) *(recommended)* while a rewrite is pending, gate on memory's canonical length; re-measure the over-cap fact
>     in both REFUSING arms; return `ResourceLimitExceeded` from the compaction arm before building an over-cap text;
>     drop the `uncommitted_count() > 0` exemption.
>   - (b) only map `persist_atomically`'s cap error to `ResourceLimitExceeded` and set the fact (peers back off; the
>     first retry still reloads).
>   - (c) document it.
> - **(62) L-147, what a refused install keeps**:
>   - (a) *(recommended)* the REFUSING and reload-failed arms drop the `pending_ids` records before keeping memory.
>     This is safe since decision (43a): no committed record names a staged one.
>   - (b) document "error but durable" for these arms.
> - **(63) L-148 / L-154, what is served before its commit**:
>   - (a) *(recommended)* the `served_*` views also hide `pending_ids` and the descendants of `adopted_from_file`.
>     Nothing is offered before its commit succeeds; this closes L-86's window. X3 validated the first half.
>   - (b) persist a clock floor.
>   - (c) document.
>
> **T101**
> - **(64) M-71**:
>   - (a) *(recommended; validated by A5)* also require the returned path's parent directory to be the directory the
>     target was opened in through the handle.
>   - (b) derive the path from the opened fd (`F_GETPATH` / `/proc/self/fd`).
>   - (c) document it.
>
>   Reword README:1097-1098 in every case.
> - **(65) L-137, the ACL rule**:
>   - (a) *(recommended)* refuse only allow entries that are not inherit-only and grant add-file, add-subdirectory,
>     delete-child, write-security or change-owner.
>   - (b) keep refusing every ACL, and replace the `chmod -N` remedy with "move the link into a subdirectory",
>     naming the home-folder default in README.
>
> **T102**
> - **(66) M-76**:
>   - (a) *(recommended)* buffer per (id, delivering peer), and order a peer's Want by that peer's own entries and
>     hints only.
>   - (b) let a later copy displace an earlier one. Not recommended: the attacker can then displace the honest copy.
>   - (c) document it.
> - **(67) L-151**:
>   - (a) *(recommended)* give `retain_not_buffered_from` a `holds` argument.
>   - (b) drain the orphan buffer after the watcher's reconcile and the recovery reload.
>   - (c) accept the one-hour delay.
>
> **T103**
> - **(68) M-73, the restate remedy**:
>   - (a) *(recommended)* the WARNs and README say "restate on ONE node; the others adopt it and must not restate",
>     and once the closure is empty for a block's id the per-block WARN says "delete this block".
>   - (b) (a), plus boot WARNs when two restatements of one quarantined seed are served.
>   - (c) document "restate byte-identically on every node".
> - **(69) L-140**:
>   - (a) *(recommended)* document the lamport-ratchet refusal as live-only.
>   - (b) hold it live, so a restart serves it.
> - **(70) L-141**:
>   - (a) *(recommended)* fold a held own complete envelope's lamport into the clock on the live path, as boot does.
>   - (b) stop holding own records live (pre-T90).
> - **(71) L-157, `m67_…`'s 2 s debug wall-clock bound**, which flakes under load:
>   - (a) *(recommended)* assert on work done, or run the bound in release with headroom. This changes an existing
>     test.
>   - (b) leave it, and re-run on failure.
>
> **Execution**
> - **(72)** *(recommended)* one task per go-ahead, as decisions (14), (35) and (53): full gate and revert-proofs, stop
>   for the commit, ask before the next; T98 first.

## Priority order at a glance

| # | Findings addressed | Sev | Effort | Status |
|---|---|---|---|---|
| T98 | H-25 + M-09 remainder + M-75 + L-153 — lifecycle verdicts that are a function of the directive set | **High** | M | ☑ |
| T99 | M-72 + L-142 + L-143 + L-144 + L-145 + L-146 — boot chooses between copies after judging them, in one iteration | Med | M | ☐ |
| T100 | M-74 + L-147 + L-148 + L-149 + L-154 — the commit gate and every refusing arm measure and keep only what the commit wrote | Med | S–M | ☐ |
| T101 | M-71 + L-137 + L-138 + L-139 — the symlink guard binds the returned path | Med | S | ☐ |
| T102 | M-76 + L-150 + L-151 + L-152 — the orphan buffer keyed per delivering peer; the filters' holds and cost | Med | S–M | ☐ |
| T103 | M-73 + L-140 + L-141 + L-155 + L-156 + L-157 — "restate on one node", the live lamport arms, texts, proxies | Med | S | ☐ |

**Coverage check — every open register entry maps to exactly one task:**

| Task | Entries |
|---|---|
| T98 | H-25, M-09 (remainder), M-75, L-153 |
| T99 | M-72, L-142, L-143, L-144, L-145, L-146 |
| T100 | M-74, L-147, L-148, L-149, L-154 |
| T101 | M-71, L-137, L-138, L-139 |
| T102 | M-76, L-150, L-151, L-152 |
| T103 | M-73, L-140, L-141, L-155, L-156, L-157 |

**Deferred by design to T45 (Format v2), unchanged:** M-10, L-06. M-09's remainder is in T98 (decision (54) says
whether it is fixed now or deferred to T45). **Deferred by decision, unchanged:** H-01's loopback API key; L-23
(`meshId` required next release).

**T45 interaction:** if decision (54) chooses (b), T45 Facet A gains the causal `close`. Waves A and B wait for
**T98** either way: it changes what a `close` means for every replica.

**Landing order:**
1. T98 first.
2. T99, then T100. Both are in `service.rs`: T99 owns the boot pipeline (`boot_with`, `prefer_copies…`,
   `adopt_operator_input_at_boot`, the fixpoint); T100 owns commit/recovery, the `served_*` views and gl-node's
   `ledger_commit.rs`. Run them sequentially or give them to one agent.
3. T101 ∥ T102, which are disjoint: T101 owns `journal.rs`'s resolution and gl-node `main.rs`'s claim; T102 owns
   `orphan_buffer.rs` and `anti_entropy_alpn.rs`'s Want and intake.
4. T103 last, since its texts describe what T98–T102 settle.

**Extend the four invariant files before each task, as the audit did**, and run the whole workspace at the end of
every wave. The gate at HEAD with the extended files is **1,447 passed, 0 failed, 20 ignored** (425 + 8 + 610 + 40 + 10 + 195 + 61 + 38 + 8 + 26 + 5 + 21).

---

## Tier 1 — ship-blocker (the new High and the M-09 remainder)

### ☑ T98 — Lifecycle verdicts that are a function of the directive set (H-25, M-09 remainder, M-75, L-153) — M, decisions (54)–(57) taken
> **Done 2026-09-27 (working tree, not committed).** In `crates/ledger/src/accounts.rs`, `validate.rs`, `read_model.rs`, `service.rs`, gl-node `anti_entropy_alpn.rs` and `ledger_commit.rs`, `exact_balances.rs`, README (§Open an Account, §Upgrading) and the CHANGELOG. **(a) Decision (54a) — two rules.** *Data* (what a peer supplies, what the `.bean` holds, what the served-set rule re-judges) is validated by new `validate_transaction_as_data`: I3 is `AccountState::check_account_opened_by` — any `open` of the account sorting at or before the transaction admits it (new `CurrencyIndex::first_open`), no `close` refuses it — and I9 is `check_currency_admitted_by`, the T91 union whether or not a `close` sits between. It is used by `stage_remote_directive`, `adopt_file_directive` (boot and live), `rebase_operator_input` (boot's re-validation of pending input after a quarantine) and `unservable_history`. No ingest path refuses a `close` any more: `reject_backdated_close` is gone from the wire and the file path, and with it `AccountState::dates_a_close_would_close` and `ReadModel::latest_posting_date_in`. *Authoring* (this node's own API write, and gl-node's pre-stage estimate, both through new `LedgerService::validate_own_transaction`) is the lifecycle fold with its `close`s, except that a deciding `close` whose interval (new `AccountState::deciding_close_interval`: after its date, up to the next `open` exclusive / the next `close` inclusive / unbounded) already holds a posting (new `ReadModel::holds_posting_in`) is inert — `validate_transaction_as_author`. Without that exception one peer's back-dated `close`, now accepted as data, would have shut the account for every local write (the M-09 write-DoS `test_remote_backdated_close_is_…` pins). `close_account` keeps FR-3 AC2. **(b) Decisions (55), (56):** moot under (54a) — nothing added; H-25's refusal and M-75's door are gone with the refusal itself. **(c) L-153:** falls out of (a) — a hand `close` is no longer refused at adoption, so there is nothing to move to `finalize_operator_input`. **(d) Texts:** gl-node's `stage_refusal_is_permanent` doc (the "monotone … can never become acceptable" justification, false since T91) and `account_wait_target` doc; the service docs; README :136 rewritten (what a `close` binds, data vs this node's writes, same-day `open`), README :58 gains the lifecycle mixed-version clause (pre-T90, pre-T91, pre-T98 — part of L-155); the CHANGELOG T91 bullet loses its "no longer depend on … which order" claim and a T98 *Security* bullet is added. **(e) Decision (57):** `lifecycle_converges_when_the_account_is_posted_to_after_a_reopen` runs 400 seeds. **Acceptance:** un-ignored and green: `a2_0927_1_one_peers_close_and_posting_in_opposite_orders_leave_two_replicas_converged`, `x3_0927_2_a_close_over_a_locally_held_record_does_not_outlive_the_remedy` (`exact_balances.rs`, now 42 / 1 ignored — T100's A4-2); X2's test added to gl-node as `h25_a_close_arriving_before_its_reopen_is_admitted`. **New tests (5):** ledger `t98_an_ingested_close_is_data_and_binds_only_this_nodes_own_writes` (a `close` before the `open`, one beside a held posting and a forward one are all accepted; the local write beside the held posting goes through; the forward one refuses a local write until a peer's posting after it makes it inert), `t98_a_hand_transaction_after_a_hand_close_is_data_at_boot_and_live` (boot, with a dangling history record forcing the rebase, and live), `l153_a_hand_close_is_served_at_the_first_boot` (X3 `k15`'s shape, fixed point), accounts `t98_the_data_rule_ignores_closes_and_keeps_the_union` (the data rule's I3/I9 and the interval bounds); gl-node `h25_…`. **Existing tests changed (8 and one fixture), by decisions (54)/(57):** ledger `m09_a_close_that_closes_nothing…` replaced by `t98_an_ingested_close…`; `test_remote_backdated_close_is_rejected` → `…_is_data_and_local_writes_go_on`; `test_reconcile_rejects_backdated_close` → `test_reconcile_adopts_a_backdated_close_as_data`; `test_a_rejected_remote_directive_does_not_move_the_clock` refuses a transaction on a never-opened account instead of a `close`; `exact_balances` `a2_0927_an_ingested_close_is_refused_exactly_when…` (T91's rule, retired) → `a2_0927_an_ingested_close_is_data_in_every_order_and_after_a_restart` (every lifecycle directive held, the transactions an independent data oracle admits, one set and balance in three orders, restart changes nothing); gl-node `backdated_remote_close_is_rejected_and_appends_keep_working` → `…_is_data_and_appends_keep_working`; the L-34 `refusal_fixture`'s permanent refusal is now an unbalanced transaction naming `txn1` (I1) instead of the back-dated `close` (the four L-34 tests keep their assertions); the lifecycle seeds `1..=32` → `1..=400`. **Revert-proven (8, scratch copy of the working tree, each restored and compared equal):** R1 the wire judges by the authoring fold → `a2_0927_1_…`, `t98_an_ingested…` fail; R2 the wire refuses a `close` with a later posting → `h25_…`, `backdated_remote_close_is_data…`, `test_remote_backdated_close_is_data…` fail; R3 the file path refuses it → `l153_…`, `test_reconcile_adopts_a_backdated_close…` fail; R4 the served-set rule by the authoring fold → `x3_0927_2_…`, `a2_0927_an_ingested_close_is_data…` fail; R5 no inert-`close` exception for this node's writes → `t98_an_ingested…`, `test_remote_backdated_close_is_data…`, `test_reconcile_adopts…` fail; R6 the data rule's I9 skipped after a `close` → `t98_the_data_rule…` fails; R7 file adoption by the authoring fold and R8 boot's rebase by it → `t98_a_hand_transaction…` fails (both first changed no test's outcome; that test was written for them). **Audit probes, re-run against this code:** A2 `x1 p1peer` and `p1honest` — R1 and R2 hold the same set and balances after every round and restart, fresh F1 == F2 (were split); `p2write` — the `close` is accepted; `p3` — every order the same held set: true; X2 `x2_p2a` — the `close` refused for 0 of 27 re-open days (10 before); `x2_p2b` — the offline writer's records and M's `close` held by both after 5 rounds (were apart); X3 `k16` (API and wire) — node and peer both serve T and the `close`, Bank 3 on both (were 3 vs –), and the unedited API control is still refused (FR-3 AC2); `k15` — the hand `close` in the DAG at boot 1 (was HELD); `diff=all` — DIFFERS only `lampP-On` (0926 §5 Info; `editopen+handclose+handopen` no longer differs). **Gate:** clippy `-D warnings` and `fmt --check` clean; `cargo test --workspace --locked --no-fail-fast` **1,453 passed, 0 failed, 18 ignored** on the first run (gl-node 426, integration 8, ledger 613, exact_balances 42/1, property 10, p2p 195, boot_fuzz 61/5, convergence 38/6, decode_memory 8, m50_wire 26/6, property 5, security 21); the 18 ignored are decision (1)'s two joins, decision (41)'s residual, and the 15 0927 cases T99–T103 own; loopback QUIC green. **Behaviour changes:** a peer's or a hand-typed `close` is always accepted; a transaction from a peer or the file is accepted whenever an `open` of its account is dated on or before it, whatever `close` sits between; this node's API refuses a transaction after a `close` only when no transaction dated inside that `close`'s interval is held; `ACCOUNT_HAS_LATER_TRANSACTIONS` now comes only from the API's own `closeAccount`. **Residuals:** a `close` no longer stops an allowlisted peer's back-dated posting (it could already author anything else); `AccountState::is_open` / `is_open_at` stay the plain fold — the "already open" / "not open" guards of `open_account` and `close_account` and tests read them, GraphQL exposes no lifecycle state — so after a peer posts past a `close` they still answer "closed" and the account may be re-opened; the authoring exception reads this node's read model, so which local write it allows depends on what this node holds (authoring is local by nature); mixed versions — a pre-T98 node refuses a peer's `close` over a later posting and parks a posting after a `close` as an account wait forever, so a mesh must be upgraded as a whole (README :58); `account_wait_target` keeps `AccountClosed`, which remote data can no longer earn; `posting_dates` stays a set though only `latest_posting_date` reads it now.

- **Why: H-25.** `reject_backdated_close` ([service.rs:8860](../crates/ledger/src/service.rs#L8860)) refuses a
  `close` when a held posting lies in `dates_a_close_would_close`
  ([accounts.rs:490-514](../crates/ledger/src/accounts.rs#L490)). That interval ends at the next lifecycle event
  **this node holds**, so before the re-open lands it is unbounded.
  - `open`/`close` records name no parents, so `compute_want` stages a `close` and its re-open in content-id order
    after the heads ([anti_entropy.rs:35-59, 88, 120](../crates/p2p/src/anti_entropy.rs#L35)).
  - gl-node classes the refusal as permanent with a justification that has been false since T91
    ([anti_entropy_alpn.rs:2484-2510](../crates/gl-node/src/anti_entropy_alpn.rs#L2484)). It is not an account-wait
    target (`:2535-2545`), and the L-34 cache keeps it out of the Want for 10 minutes.
  - X2 `x2_p2a`: refused for 10 of 27 re-open days; with the returning replica's 02-15 receipt, Cash 141 vs 140 and
    Bank 3 vs – for good, and the replica's later writes are buffered mesh-wide.
  - A2's gl-node probe on T29's fixture accepts 9 of 10.
  - T91's own gl-node test fails at seed 42 of `1..=400`.
- **Why: the M-09 remainder.** One peer's `close` plus a posting inside its interval, delivered in opposite orders
  (A2 `x1 p1peer`), or an honest partition (`p1honest`: A closes, offline B posts), leaves R1 holding the `close` and
  R2 holding the posting and every write after it, for good.
  - `p3`: an inert `close` dated before the `open` is made live by an earlier `open` that arrives later; the held set
    differs by order.
  - X2 `p2b`: one peer's `close` dated after the last posting the online mesh holds cuts an offline writer off on
    every account; fresh replicas split by the first peer they meet.
  - T91's residual "a genuine conflict of two concurrent writes" understates it.
- **Why: M-75.** `close_account_staged` ([service.rs:6017](../crates/ledger/src/service.rs#L6017)) and
  `reject_backdated_close` from the file (`:8583`) and the wire (`:9530`) read the read model, which excludes this
  node's quarantine.
  - X3 `k16`: with T held locally (edited envelope), this node's API `close`, a hand `close`, or a peer's `close`
    dated before T is accepted.
  - Every peer that serves T refuses it for good. After "restore the original line", the rule holds T on I3 forever,
    and the node never resolves a peer write through T.
- **Why: L-153.** Boot judges a hand `close` at adoption (`:8583` via `:4131`), before the signature pass and before a
  later hand re-`open` (adoption is in date order). X3 `k15`: held at boot 1, served at boot 3, with no edit.
- **Change:**
  - (a) per decision (54);
  - (b) per decision (55), unless (54a);
  - (c) per decision (56), unless (54a);
  - (d) L-153: judge operator-input `close`s in `finalize_operator_input`, after the pass and the hand `open`s, as T92
    did for L-77;
  - (e) correct the gl-node comment at `:2484-2487`, service.rs:8846-8848, README:136 (also the same-day `open`
    wording) and CHANGELOG:195; README §Upgrading names the T91 mixed-version consequence (part of L-155);
  - (f) per decision (57), widen the gl-node lifecycle seeds.
- **Files:** [accounts.rs:374-514](../crates/ledger/src/accounts.rs#L374),
  [service.rs:4131, 6017, 8583, 8840-8876, 9525-9541](../crates/ledger/src/service.rs#L8860),
  [read_model.rs:1100-1117](../crates/ledger/src/read_model.rs#L1100),
  [anti_entropy_alpn.rs:2484-2545](../crates/gl-node/src/anti_entropy_alpn.rs#L2484), README §Open an Account,
  CHANGELOG.
- **Verify:** un-ignore and pass `a2_0927_1_one_peers_close_and_posting_in_opposite_orders_leave_two_replicas_converged`
  and `x3_0927_2_a_close_over_a_locally_held_record_does_not_outlive_the_remedy` (`exact_balances.rs`); add and pass
  X2's gl-node test below. Re-run the probes:
  - A2 `x1 p1peer`, `p1honest`, `p2write`, `p3`;
  - X2 `x2_p2a` (0 of 27 refused), `x2_p2b`;
  - X3 `k15`, `k16`, `k16b`.

  The gl-node lifecycle test passes with `1..=400`; `m09_a_close…`, T91's property tests and `a2_0927_…` stay green.
  Bug-catch proof for each of (a)–(d).
- **Acceptance test to add (X2, `crates/gl-node/src/anti_entropy_alpn.rs` tests module; fails at HEAD, passes under
  (55a)):** `x2_a_close_arriving_before_its_reopen_is_admitted_once_the_reopen_lands`.
  - It seeds a source with `open Equity:Opening`, `open Assets:Cash` and a 01-15 posting (the prefix), then a
    `close` 02-01, a re-open 03-01 and a 03-15 posting.
  - It applies the prefix, then the batch `[03-15 posting, close, re-open]`, through `apply_supply_entries`.
  - It asserts that the sink holds the `close` and that Cash is closed on 02-15.
  - Full source: `…/081b9088-…/scratchpad/X2/glprobe/` (also quoted in the 0927 X2 report,
    `…/scratchpad/orch/reports/X2.md`).

---

## Tier 2 — the boot pipeline's copies and fixpoint, the commit gate, the symlink path, the buffer

### ☐ T99 — Boot chooses between copies after judging them, in one iteration (M-72, L-142, L-143, L-144, L-145, L-146) — M, decisions (58)–(60)

- **Why: M-72.** `prefer_copies_whose_parents_are_served`
  ([service.rs:5477](../crates/ledger/src/service.rs#L5477)) runs at `:4126`, before the closure (`:4127`), the
  operator input, the signature pass and the rule.
  - Its "resolves" is the lenient pre-closure DAG (`:5488-5495`), and it switches only when the loaded copy's parents
    do not resolve (`:5493`).
  - The canonical file's copy is loaded first (`:3490-3496`).
  - A1-1: a chain re-entered child-first (date order), or restated on another node, is held after a crash with C, D
    and Y. A1-2 / X1-2: a re-entered signature-held record is held with Y; Cash is 87 running and 100 after the
    restart.
  - The compaction deletes the journal's only valid copies. This is H-24's shape 2 again.
- **Why: L-142.** The preference walks all descendants per pair (`:5497-5505`): 4,000 pairs boot in 4.45 s vs 0.29 s.
- **Why: L-143.** `adopt_operator_input_at_boot` counts an id already in the DAG as a duplicate (`:4350-4354`) before
  the pass and the rule hold the history copy.
  - A block typed beside a rule-held or signature-held record (A3-1, D1-1), or "the missing open" typed as the
    account's own `open` (X1-1), is dropped silently; the live path adopts the same bytes.
  - The comment at `:4849` ("or its envelope edited") describes a shape that never reaches the pass.
- **Why: L-144.** The closure is walked by id before the operator input: a retyped closure member frees its
  descendants only at the next boot (A3-2).
- **Why: L-145.** A typed copy the pass skipped and finalize then refuses goes through `quarantine_keeping_envelope`
  (`:4250-4264`), which keeps the enveloped original. The WARN says "kept in the file as written", and the closure was
  pruned at adoption (`:8549`) (A3-3, X1-3).
- **Why: L-146.** `ids.len() + self.quarantine_unservable_history()` (`:4832`) recurses once per round, and each round
  is a full `rebuild_dag`.
  - A chain `C0 ← P1 ← C1 ← … ← Pk ← Ck` of hand-parented half envelopes forces k rounds.
  - 1,000 pairs take 68 s; 3,200 take 235 s.
  - The L-13 reload's 2 MiB `spawn_blocking` stack aborts the process at ~2,800 rounds; X1 `m3 0 3000 2048` gives
    `stack overflow, aborting`.
- **Change:**
  - (a) decision (58);
  - (b) L-142: one Kahn cycle scan over the chosen copies;
  - (c) decision (59);
  - (d) L-144: re-judge the closure after the operator input, on the DAG copy's parents (or remove a finalised copy's
    id and re-admit members whose loaded parents are all served);
  - (e) decision (60), and iterate instead of recursing whatever (60) says;
  - (f) correct the comment at `:4849` and the L-131 CHANGELOG bullet.
- **Files:** [service.rs:3490-3496, 3669-3944, 4126-4139, 4250-4265, 4346-4360, 4790-4832, 4849-4908, 5358-5374, 5477-5520, 5605-5616, 8549](../crates/ledger/src/service.rs#L5477),
  CHANGELOG.
- **Verify:** un-ignore and pass:
  - in `m50_wire.rs`:
    - `a1_0927_after_a_crash_a_re_entered_chain_is_served_whatever_order_it_was_re_entered_in`
    - `a1_0927_after_a_crash_a_restated_chain_adopted_from_a_peer_is_still_served`
    - `a1_0927_after_a_crash_a_re_entered_signature_held_record_is_served`
  - in `boot_fuzz.rs`:
    - `a3_0927_1_a_block_retyped_beside_a_record_the_rule_or_the_pass_holds_is_adopted`
    - `a3_0927_2_a_retyped_closure_member_serves_the_same_set_at_the_next_boot`
    - `a3_0927_3_a_retyped_copy_refused_at_finalisation_is_kept_as_written`
    - `a3_0927_4_the_rule_reaches_its_fixpoint_without_a_round_per_record`
    - `x1_0927_the_missing_open_retyped_beside_its_edited_envelope_opens_the_account_at_boot`

  Re-run the probes:
  - X1 `m8`, `m2`, `m4`, and `m3 0 3000 2048` (no abort);
  - A3 `fp 3200 chain 2048` (one round);
  - A1 `perfdup 8000 dup` (within 2× of `nodup`);
  - D1 `c_l131b`.

  `h24_*`, `m64_`, `l121_`, `l131_`, `l77_`, `a1_0926_*` and every `a1_0927_`/`a3_0927_` passing case stay green.
  Bug-catch proof per mechanism.

### ☐ T100 — The commit gate and every refusing arm measure and keep only what the commit wrote (M-74, L-147, L-148, L-149, L-154) — S–M, decisions (61)–(63)

- **Why: M-74.** `refuse_if_local_write_cannot_fit` ([ledger_commit.rs:556-590](../crates/gl-node/src/ledger_commit.rs#L556))
  decides on `append_headroom()` ([service.rs:6389-6398](../crates/ledger/src/service.rs#L6389)), which is file-based,
  and on the over-cap fact through headroom 0 (`:565`). It skips the exact estimate whenever `uncommitted_count() > 0`
  (`:573`).
  - While `must_rewrite` holds (`:6524-6528`), the commit is a compaction of memory's canonical form, including
    envelopes awaiting their rewrite, which no gate counts.
  - `prepare` re-measures the fact only if it is set (`:6572`); `persist_atomically` refuses over-cap text as
    `Io(InvalidData)` (`:282-290`) without setting it; both REFUSING arms return (`:7128`, `:7151`) before the
    re-measure (`:7220`).
  - L-70's peer backoff arms only on `ResourceLimitExceeded` ([anti_entropy_alpn.rs:2319](../crates/gl-node/src/anti_entropy_alpn.rs#L2319)).
  - A4 `g2`: mutations 1–3 are each `IO_ERROR` after a full reload (14–27 s). `g4`: every peer batch reloads (~12 s),
    with no backoff. `g3`: in the kept-write state each refused write is counted and served
    (`REFUSING so far 1/2/3/4; cash -10/-15/-20/-25`), then lost at restart.
- **Why: L-147.** The L-117 refusal (`:3319-3334`), the committed-id floor arm (`:7102-7129`) and the reload-failed
  arm (`:7222-7237`) keep `pending_ids`.
  - The write whose call failed is counted and served, and the next commit writes it.
  - After L-117 that compaction also replaces the operator's link, and the moved file lacks the write (A4 `a4l1`,
    D1 `c_l117`, X3 `k12`).
  - The comment at `:3317-3318` names the wrong arm.
- **Why: L-148.** `discarded_own_high` (`:7189-7213`) is memory-only. A restart after a failed commit, before any
  write succeeds, resumes at the file's `max + 1` and re-issues the discarded write's pair, which was served while
  staged (L-86). X3 `diff=all`: 52 of 52 restart shapes; A4 `a4l5`.
- **Why: L-149.** `choose_committed_parents` (`:6146`) rebuilds the pending set and walks every pending chain per
  call, twice per line: 1,000 staged × 5,000 lines take 18–42 s under the write lock.
- **Why: L-154.** The views withhold a line awaiting its rewrite but advertise and supply its signed child. While the
  startup compaction keeps failing, a fresh peer is offered a record it can never adopt (X1 `m9`).
- **Change:**
  - (a) decision (61);
  - (b) decision (62);
  - (c) decision (63);
  - (d) L-149: compute the committed heads once per adoption pass and update them incrementally;
  - (e) correct the `:3317-3318` comment, CHANGELOG:193's three overclaims, and README:1103-1106 on what follows the
    L-117 refusal;
  - (f) add A4's `a4_l115b_…` beside `l115_…` in `service.rs`'s tests (it passes at HEAD and pins the `:7213`
    re-application, which is unpinned).
- **Files:** [ledger_commit.rs:556-590](../crates/gl-node/src/ledger_commit.rs#L556),
  [service.rs:282-290, 3317-3340, 6146, 6389-6398, 6524-6572, 7102-7237, 8959-9029](../crates/ledger/src/service.rs#L7072),
  README, CHANGELOG.
- **Verify:**
  - Un-ignore and pass `a4_0927_a_write_whose_reload_is_refused_for_a_link_is_not_in_the_balance`
    (`exact_balances.rs`) and `x3_0927_1_a_restart_after_a_failed_commit_never_reuses_the_served_writes_lamport`
    (`convergence.rs`).
  - Add A4's gl-node probes `a4_probe_window_and_remedy`, `a4_probe_stuck_staged_small_headroom` and
    `a4_probe_peer_batches_in_the_window` (`…/scratchpad/A4/archive/crates/gl-node/src/`) as assertions. Every
    mutation and every batch after the first should be refused before staging in milliseconds, with 0 further
    reloads, and running == restart.
  - Re-run the probes:
    - X3 `diff=all` and `live=all` (0 restart re-issues);
    - X1 `m9` (the child withheld too);
    - A4 `a4l3` (linear).
  - `a3_1_…`, `a3_m59_…`, `l115_`, `l116_`, `l117_`, `l122_`, `m58_*` stay green. Bug-catch proof per mechanism.

### ☐ T101 — The symlink guard binds the returned path (M-71, L-137, L-138, L-139) — S, decisions (64), (65)

- **Why: M-71.** [journal.rs:328-341](../crates/ledger/src/journal.rs#L328) returns `canonicalize(configured)` — a
  second by-path walk — accepted on `(dev, ino)` alone.
  - After an ancestor swap, `evil/ledger.bean → attacker/h`, a hard link of the operator's target, passes.
  - A5 `hlrace hardout`: 915 of 26,369 resolutions returned `…/attacker/h` in 5 s; `boot + compact: Ok(())`.
  - The `.bean`'s owner is never checked, so the attacker's lines are then adopted and signed.
  - README:1097-1098 says a swap from above "cannot redirect the node".
- **Why: L-137.** Any ACL entry refuses (`:421-447`), including macOS's default `group:everyone deny delete` on `~`,
  `~/Desktop`, `~/Documents` and `~/Downloads`. The `chmod -N` remedy strips that protection.
- **Why: L-138.** `File::open(link_directory)` (`:263`) has no `O_DIRECTORY | O_NONBLOCK`, so a FIFO at the path hangs
  boot before the lock, silently.
- **Why: L-139.** `sweep_stale_temporaries` ([service.rs:226-271](../crates/ledger/src/service.rs#L226)) deletes the
  link's own target when it is named `<link>.tmp[.pid.hex]`, and boot starts an empty ledger.
- **Change:**
  - (a) decision (64);
  - (b) decision (65);
  - (c) L-138: open the directory `O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_CLOEXEC` (optionally `O_SEARCH`/`O_PATH`,
    so a 0300 directory keeps working — 0927 §5);
  - (d) L-139: skip a candidate whose `(dev, ino)` equals the resolved target's;
  - (e) have `claim_ledger_path` refuse a resolution that is still a symbolic link (the §5 double resolution);
  - (f) add `O_NOCTTY` to the target open;
  - (g) update journal.rs:1310-1311, :885-888 and p2p_service.rs:1088-1090 (part of L-156);
  - (h) `m68_…` also asserts that no other path is returned (part of L-157).
- **Files:** [journal.rs:181-447, 885-888, 1310-1318](../crates/ledger/src/journal.rs#L247),
  [service.rs:193-271](../crates/ledger/src/service.rs#L193), [main.rs:72-79](../crates/gl-node/src/main.rs#L72),
  README §The commit journal, CHANGELOG.
- **Verify:**
  - Add A5's `a5_0927_a_path_through_a_directory_the_checks_never_saw_is_never_returned` to `journal.rs`'s tests
    module, beside `m68_…`, ignored first. It uses `t87_directory` and `swap_directories`; full source in the 0927 A5
    report (`…/scratchpad/orch/reports/A5.md`, the validated fix at `…/scratchpad/A5/journal.rs.fix_a5_1`).
  - Re-run A5 `p1`:
    - `hlrace hardout`: 0 other paths;
    - `acls`: the default home ACL accepted, a granting allow entry refused;
    - `fifo`: `ENOTDIR` at once;
    - `sweeptarget`: target intact;
    - `twice`: refused.
  - `m60_*`, `m61_*`, `l84_*`, `m68_`, `l119_`, `l120_`, `l118_` stay green. Bug-catch proof per mechanism.

### ☐ T102 — The orphan buffer keyed per delivering peer; the filters' holds and cost (M-76, L-150, L-151, L-152) — S–M, decisions (66), (67)

- **Why: M-76.** `insert_waiting` returns `Duplicate` for any existing entry, whoever delivered it
  ([orphan_buffer.rs:692](../crates/p2p/src/orphan_buffer.rs#L692)); gl-node drops the second copy
  ([anti_entropy_alpn.rs:2153-2172](../crates/gl-node/src/anti_entropy_alpn.rs#L2153)); and `known_missing_parents`
  (`:317`) orders every peer's Want by the first copy's parents (`:1320-1325`).
  - An allowlisted M pushes its own envelopes of H's bodies (each naming the next record).
  - V then catches up H's chain one record per exchange: `x2 c9` 300 records in 300 exchanges vs 1; real QUIC 200 vs
    1.
- **Why: L-150.** `remember_parent_hint` pushes `(now, id)` (`:568`), compacts the queue against `parent_hints`
  (`:571-577`), and inserts the hint only after (`:579`). The fresh entry is dropped, so that hint never expires
  (A6-1).
- **Why: L-151.** `retain_not_buffered_from` (`:458-527`) has no `holds`. A child buffered on a parent that then
  arrives through the file is dropped from its only peer's Want for up to `MAX_ORPHAN_AGE` (1 h); the watcher's
  reconcile never drains the buffer (A6-2).
- **Why: L-152.** Both filters build sets over the whole Want under `ledger.read()` + `orphan_buffer.read()`
  (`:1292-1302`), ~13 hashes per advertised id. A 1M-id Want with a full per-peer share takes 8.3 s vs T88's 1.6–2.2
  s, and GraphQL writes and phase 2 queue behind it (A6-3).
- **Change:**
  - (a) decision (66);
  - (b) L-150: insert the hint before compacting (or compact before the `push_back`);
  - (c) decision (67);
  - (d) L-152: iterate the filters' roots over the peer's own buffered and hinted ids (≤ ~9.2k), share one Want set,
    and precompute `holds` under a short ledger guard;
  - (e) `m67_…` per decision (71).
- **Files:** [orphan_buffer.rs:275-603, 692](../crates/p2p/src/orphan_buffer.rs#L353),
  [anti_entropy_alpn.rs:884-893, 1290-1330, 2153-2172](../crates/gl-node/src/anti_entropy_alpn.rs#L1290), CHANGELOG.
- **Verify:**
  - Un-ignore and pass `a6_0927_3_a_hint_recorded_as_the_hint_queue_is_compacted_still_ages_out` and
    `a6_0927_2_a_buffered_record_whose_parent_arrived_through_the_file_is_asked_for_again` (`convergence.rs`).
  - Add X2's real-QUIC `x2_another_peers_copies_do_not_slow_an_honest_catch_up`
    (`…/scratchpad/X2/proposed_gl_node_test_2.rs`) to gl-node's tests, ignored first. It should end with all 40
    records held within 3 exchanges.
  - Re-run the probes:
    - X2 `c9` (`[reverse]` within 2× of `[none]`), `c3`;
    - A6 `a6p5` (the filters within 2× of `compute_want`).
  - `m66_`, `l133_`, `m67_`, `l130_`, `l134_`, `l106_`, `l107_`, `l95_`, `a6_0927_1_…` stay green. Bug-catch proof per
    mechanism.

---

## Tier 3 — remedies, texts, proxies

### ☐ T103 — "Restate on one node", the live lamport arms, the texts and the proxies (M-73, L-140, L-141, L-155, L-156, L-157) — S, decisions (68)–(71)

- **Why / change, one line each:**
  - **M-73** — the closure WARN ([service.rs:5588-5600](../crates/ledger/src/service.rs#L5588)), the M-52 per-block
    WARN (`:3553-3566`), the H-08 banner and README (:58, :875-880) print "restate the chain" on every node, and keep
    printing after another node's restatement arrived. Two restatements are two records: X2 `c10` Cash 19,895 vs
    9,895; A1-4 114 vs 64. Also: the restate remedy should say to strip the restated record's own envelope (0927 §5).
    Change: decision (68).
  - **L-140** — the live reconcile's lamport-ratchet refusal (`:8357-8362`) precedes every hold, so a pasted complete
    envelope over the ratchet is deleted from the file while boot serves it (A1-3). README:1025 says "kept when boot
    would keep it". Change: decision (69).
  - **L-141** — `hold_refused_file_entry` (`:5550`), and the T85 missing-parent hold (`:8487-8495`), keep a held own
    record without folding its lamport into the clock, so the node re-issues its own pair (A1-5: clock 2 after holding
    lamport 5). Change: decision (70).
  - **L-155 (texts)**:
    - CHANGELOG:195 and README:136, beyond what T98 corrects;
    - README §Upgrading / :58 name the T90/T91 mixed-version consequence (D1-2);
    - CHANGELOG:193's three overclaims (A4; with T100);
    - README:1097-1098 (with T101);
    - the garbled H-23 summary sentence (`:4808-4822`) and the journal's Corrupt message for a 1–5-byte tag
      (journal.rs:677);
    - the banner on the EVERY-failed shape: add "if the EVERY-signature warning printed, fix `p2p.meshId` or the key
      first and repair nothing" (A3, 0927 §5).

    Change: reword each.
  - **L-156 (comments)** — move `type ServedIdSnapshot` and its doc above the L-57 comment
    ([service.rs:193-209](../crates/ledger/src/service.rs#L193)); ci.yml:25-27; boot_fuzz.rs:73; the
    `posting_dates` doc (read_model.rs:531-535); and whatever T98/T100/T101 leave (the `unsafe` counts, `:3317`,
    `:4849`, anti_entropy_alpn.rs:2484). Change: reword each.
  - **L-157 (proxies)** — `m68_…` counts only the victim path (with T101); `m67_…`'s debug bound (decision (71)); the
    gl-node lifecycle seeds (decision (57), with T98); decision (44)'s re-application (with T100); T90's resolved-body
    -cap hold (A1 R4d) gains a pin, or the Done note says it is unpinned.
- **Files:** [service.rs:3553-3566, 4808-4822, 5550, 5588-5600, 8357-8362, 8487-8495](../crates/ledger/src/service.rs#L5588),
  gl-node `main.rs` (banner), `.github/workflows/ci.yml`, [boot_fuzz.rs:73](../crates/p2p/tests/boot_fuzz.rs#L73),
  README, CHANGELOG.
- **Verify:**
  - Un-ignore and pass `a1_0927_the_restate_remedy_followed_on_two_nodes_counts_the_deposit_once`,
    `a1_0927_a_pasted_record_over_the_lamport_ratchet_is_kept_in_the_file_as_boot_keeps_it` (or, under (69a), replace
    it with a test of the documented live-only refusal — an existing-test change the decision allows), and
    `a1_0927_a_held_own_record_s_lamport_is_never_re_issued` (`m50_wire.rs`).
  - X2 `c10` counts one restatement when the WARN is followed; D1 re-runs every changed remedy on the binary.
  - Bug-catch proof for M-73 (a boot test that the WARN says "delete this block" once the closure is empty) and
    L-141.

---

## Residuals carried into this backlog (unchanged, for the record)

- **H-01** loopback API key (deferred by decision); **M-10 / L-06** — T45 (Format v2); **M-09** — T98 by decision
  (54); waves A+B wait for T98.
- **L-23 / R-9** — `meshId` required next release. **R-8**, **R-14 / R-15**, **R-16** — unchanged since 09/23.
- **H-19 by decision (1):** anti-entropy-only joins across a removed author's jump or a pre-T63 jump remain
  impossible by design; the two ignored harness cases document it.
- **Decision (41)'s residual:** one write authored under the wrong `meshId` hides the EVERY WARN at the next boot
  (ignored `l114_…`). A3 re-checked that releasing the clock there cannot re-issue a pair.
- **T90–T97 residuals re-checked and still accurate:**
  - a complete envelope refused live for its signature (H-20), a stray key the strip cannot remove, or a control
    character is still dropped live where boot quarantines it;
  - the wire's "names a held-back parent" branch is reached only by library callers;
  - a `balance`/`note`/… on a held account stays as T85 left it;
  - on a signing-off node "add the missing open" is refused as already open (the summary says to correct the `open`'s
    date; D1 and X1 executed that);
  - a library caller that never finalises keeps a duplicate hand `open` unrefused;
  - the M-59 parent check is a backstop no known shape reaches (X3 `k18`, A4);
  - lines adopted from the file are not served while the compaction keeps failing (the price of (45a));
  - after the L-117 refusal the next compaction renames onto the path (L-44) — now with L-147;
  - T94's four `unsafe` blocks;
  - the ACL check is macOS only;
  - the filters run under the buffer's read lock (and, per L-152, the ledger's);
  - a root refused but not cached keeps its buffered children re-Wanted;
  - four colluding transport ids fill the hint table (¼ shares, by design);
  - a history of 17 or more sub-2^28 steps partitions a joiner with no WARN (confirmed on the binary);
  - `l90_*`'s high-water mark runs with an uncharged frame body;
  - gl-node's own capture helpers lack the global subscriber;
  - T97's boot at 10,000 pairs ~0.25 s above `8c0a87e` (not re-measurable under the audit's load).
- **§5 informational items** in the 0927 report not assigned above:
  - the fallback's double resolution (in T101 (e));
  - `O_NOCTTY` (in T101 (f));
  - an ACL behind SMB/NFS is not seen;
  - a 0300 link directory now `EACCES` (T101 (c) optional);
  - `order_want_ancestors_first` reading any peer's copy (with M-76);
  - the hint queue bound is ~4× the live maximum;
  - the adoption-time gap WARN is single-step;
  - the mixed mesh re-judges after an upgrade;
  - boot 1's clock after a swap to a foreign copy;
  - the reload's clock one above a Fresh boot's in `lampP On`;
  - fresh-binary loopback QUIC works again.

---

## Regression-test manifest (must exist by the end of Tier 2)

Every item is already pinned as an `#[ignore]`d case, or a proposed test whose source is named above; un-ignoring or
adding it is the acceptance criterion.

1. **A `close` gets one verdict whatever order it arrives in, and replicas that took a `close` and a posting inside
   its interval in opposite orders converge** (T98 / H-25, M-09, M-75, L-153).
   - `a2_0927_1_…`, `x3_0927_2_…` (`exact_balances`);
   - X2's gl-node test;
   - the lifecycle seeds `1..=400`;
   - X3 `k15` as a test.
2. **After a crash, a re-entered or restated record is served whichever copy the file lists first; a typed copy of a
   held record is adopted on every hold; the rule reaches its fixpoint in one pass and bounded stack**
   (T99 / M-72, L-143 … L-146).
   - `a1_0927_after_a_crash_…` ×3 (`m50_wire`);
   - `a3_0927_1_…` … `a3_0927_4_…`, `x1_0927_the_missing_open_…` (`boot_fuzz`).
3. **A write whose call failed is never counted, served or written; nothing re-issues a pair across a restart; the cap
   gate refuses before staging whenever the commit would exceed the cap** (T100 / M-74, L-147, L-148, L-154).
   - `a4_0927_…` (`exact_balances`), `x3_0927_1_…` (`convergence`);
   - A4's gl-node probes as tests;
   - `a4_l115b_…` (`service.rs`);
   - X1 `m9` as a test.
4. **The symlink guard never returns a path through a directory it did not check** (T101 / M-71): A5's `journal.rs`
   test.
5. **One peer's copies never decide another peer's slot or Want order; hints expire; a child whose parent arrived
   through the file is re-Wanted** (T102 / M-76, L-150, L-151).
   - X2's real-QUIC gl-node test;
   - `a6_0927_2_…`, `a6_0927_3_…` (`convergence`).
6. **Every remedy the code prints, followed on every node that prints it, counts each record once**
   (T103 / M-73, L-140, L-141): `a1_0927_the_restate_remedy…`, `a1_0927_a_pasted_record_over_the_lamport_ratchet…`,
   `a1_0927_a_held_own_record_s_lamport…` (`m50_wire`).

Every one needs its **bug-catch proof** — revert the fix, watch the named test fail, restore. The orchestrator
re-verifies each mechanism in source and re-runs the suite on a quiet machine.
- **Proof crates** for every finding are in the 0927 session's scratchpad
  (`…/081b9088-6279-4044-bf1c-6c0e8ffb910d/scratchpad/`: `A1` … `A6`, `X1` … `X3`, `D1`).
- **Each pass's summary and re-run commands** are under `orch/reports/`.
- **Real QUIC:** loopback QUIC worked for fresh scratch-target binaries on 2026-09-27; re-check the control
  `happy_path_small_limits_converges` in the same binary before relying on it, and fall back to the repo-tree
  procedure if it fails.

---

*Audit: [SECURITY_AUDIT_0927.md](../SECURITY_AUDIT_0927.md). Previous trackers:
[OUTSTANDING_TASKS_09_26.md](OUTSTANDING_TASKS_09_26.md) (T90–T97) ·
[OUTSTANDING_TASKS_09_25.md](OUTSTANDING_TASKS_09_25.md) (T84–T89) ·
[OUTSTANDING_TASKS_09_24.md](OUTSTANDING_TASKS_09_24.md) (T79–T83) ·
[OUTSTANDING_TASKS_09_23.md](OUTSTANDING_TASKS_09_23.md) (T72–T78) ·
[OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md) (T61–T71) ·
[OUTSTANDING_TASKS_09_22.md](OUTSTANDING_TASKS_09_22.md) (T46–T60, R-1…R-21) ·
[OUTSTANDING_TASKS_09.md](OUTSTANDING_TASKS_09.md) (T18–T45) · [OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md)
(T1–T17). Format v2 design: [FORMAT_V2_DESIGN.md](FORMAT_V2_DESIGN.md).*
