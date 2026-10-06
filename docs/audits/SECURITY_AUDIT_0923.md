# Security Audit — openledger-v2 (0923: re-audit of T61–T71)

**Date:** 2026-09-23 · **Baseline:** HEAD `af14603` (branch `main`, clean tree) · **Previous:** [SECURITY_AUDIT_0922-v2.md](SECURITY_AUDIT_0922-v2.md) (HEAD `3d5ff71`)

Scope: re-verification of **every** open entry in the 09/22-v2 register (§7 there) and of **every** residual
recorded in the T61–T71 "Done" notes of [docs/audits/OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md)
against source at HEAD, plus fresh hunts over the ~13,500 lines T61–T71 added or changed (35 files, four
commits after `3d5ff71`), treated as unreviewed code. Priority went to the places where one fix touched
another, as asked: boot operator-input adoption and `finalize_operator_input` against the quarantine and
the recovery reload; the off-lock prepare recovery against the supply backoff; the lamport ratchet and the
head bound against anti-entropy convergence; the file-type helper on every path; the journal Corrupt/torn
policy and the `.torn` sidecars; the per-scale `ExactSum` balances; the new config keys and their wiring.
The accepted design deviations in the Done notes were each probed for safety, and `CHANGELOG.md` was checked
bullet by bullet against the code.

Method as established for the series: twelve parallel passes (nine per task group, each re-verifying then
hunting; three cross-cutting interaction hunters), each read-only on the repo with its own scratch crates
and target directory; library semantics checked against vendored sources under `~/.cargo/registry`;
every mechanism an agent reported was re-read in source and **every executable proof was re-run by the
orchestrator** before it appears below; `cargo audit`, lockfile sources and CI pins re-checked. Test suite
at HEAD before the audit started, quiet machine: **1,115 passed, 0 failed, 0 ignored** (390 + 8 + 497 +
10 + 179 + 5 + 5 + 21). Loopback QUIC worked on this machine for the whole audit (every iroh-backed test
ran first time; a scratch iroh dialer completed 1,200 handshakes), so the environment caveat in the brief
did not apply. The repository was not modified except to add this file.

---

## Executive summary

**T61–T71 closed what they set out to close.** All seven of the 09/22-v2 Highs are closed by mechanism
(H-12, H-13, H-14, H-15, H-16, H-17, H-18), all eleven Mediums (M-35 … M-45) and ten of the twelve Lows,
plus the carried partials M-06, L-35 and L-43. The regression tests pin the security property in most
cases; the ones that pin a proxy are named in §1. Several fixes are better than asked: T67's checked-open
helper survived a rename-storm TOCTOU race with zero violations; T70's accept bucket spends a token only
after every other budget admits; T69's off-lock recovery is cancellation-safe at every await with no lost
update; T65's cap is on every ingress and a bignum oracle confirms the per-scale sums are exact whenever
the result fits. `cargo audit` is clean, CI is green, the lockfile is entirely crates.io, `clippy -D
warnings` and `fmt --check` pass. The CHANGELOG is accurate in every statement it makes (72 bullets, 41
executed); it omits two things (§5).

**But the pattern has repeated a third time, and this time it is in the accepted design decisions.** The
0922 audit found its Highs inside T18–T44's code; 0922-v2 found them inside T46–T60's code. This audit
finds three Highs inside the *decisions* T63 and T64 recorded as accepted deviations, and in the one
assumption T61's file path still makes. Three new Highs:

- **H-19** — The T63 ratchet is measured against the *adopter's own clock*, and the "no first-contact
  exemption" decision means a fresh or rebuilt node can only join by climbing through a bridge directive.
  One allowlisted peer authors one legal directive at `local + 2^32 − 1`; the honest mesh adopts it and
  stamps above it; the operator follows the documented remedy and removes the peer from the allowlist —
  and from then on **every future node, and every node restored from an empty disk, is permanently unable
  to adopt anything authored after the jump**, while the mesh still accepts that node's own writes. A
  pre-T63 mesh that already carries one jump ≥ 2^32 is in the same state with no further action. No
  warning fires (the thresholds sit next to the ceiling). The Done-note residual "cannot be joined until
  that directive is removed" is wrong: removing it changes nothing, because the honest history after it
  *is* the gap.
- **H-20** — Boot trusts the envelope. A record that carries an author and a lamport is history, and
  nothing verifies its signature or its integrity. Two doors, both through the README's one supported
  edit workflow: (a) the operator corrects a narration typo or an amount in a line the node wrote — boot
  loads it under a **new** content id with the **old** signature, zero warnings, the startup compaction
  persists it, every signing peer refuses it forever, everything the node authors afterwards is orphaned
  mesh-wide, and an amount edit diverges balances; (b) a stray dedent, BOM or word inside a node-written
  transaction splits the block and the salvage loads the **truncated head as a complete transaction**
  (no I1 at boot), keeping one posting and dropping its counter-posting, while the banner says "nothing is
  lost". Pre-existing, unregistered, and exactly the H-13 consequence T61 closed for envelope-less lines.
- **H-21** — The T64 per-author head bound is judged against *this replica's* transient head set, so DAG
  membership is now delivery-order-dependent. One allowlisted peer serves replica A the subset `{0..255}` of
  257 parentless transactions and replica B `{1..256}`; each refuses the 257th at the cap, and anti-entropy
  between A and B cannot repair it. **Same available directive set, two permanently different committed
  DAGs** — the H-03/H-06/M-09 invariant — self-healing only when *each* diverged replica authors locally;
  an auditor or observer replica that never authors diverges indefinitely. The remote refusal is
  redundant: `choose_parents`'s truncation already closes H-16's brick on its own.

Five new Mediums: the T62 "never install an emptier ledger" floor counts file-adopted lines as staged, so a
live file replacement plus one failed commit installs over acked records (M-46); a half envelope (author
*or* lamport, not both) is history at boot but operator input on the live reconcile — H-13's shape through
the boundary T61 drew (M-47); the cardinality caps run only at stage time, so a valid one-block body peaks
at 42× and a 15 MiB Supply frame holds 546 MB (M-48); the reload-failure arm's stale `force_compaction`
now composes with T68's fail-closed classifier into a boot refusal with an acked record behind the tail
(M-49); and upgrading over a pre-T65 file that holds one 22-digit amount — which any elided 8-decimal
purchase over 10⁵ produced — silently drops it and everything below it from balances and makes a fresh
replica unable to sync past it (M-50).

The through-line: **the fixes reason about one replica's state where the property is a mesh property.**
H-19's ratchet, H-21's head bound and M-46's floor each compare against a number only this node holds
(its clock, its heads, its staged count); H-20 and M-47 trust a classification the file cannot enforce.
The backlog below is therefore organised around stating each rule on the *content* rather than on the
replica.

---

## Threat model

Unchanged from [09/22](SECURITY_AUDIT_0922.md) and [09/22-v2](SECURITY_AUDIT_0922-v2.md): (a) a web page in
an operator's browser, (b) an API-key holder, (c) a **malicious or compromised allowlisted peer**, (d) a
network attacker on a public bind, (e) whoever can write the `.bean` or its directory, plus the no-attacker
cases (an operator following the README, an editor autosave, a backup `cp`/`mv`, a crash, an upgrade over
an old file, a long-offline or freshly restored replica). This audit adds one: **the operator following a
remedy the code itself prescribes** (allowlist removal after a lamport incident).

---

## 1. Status of the 09/22-v2 register, re-verified at HEAD `af14603`

Every entry was re-verified in source; the tracker's "Done" paragraphs were treated as claims. Every
09/22-v2 proof was re-run at HEAD. Regression tests were read for whether they pin the property or a proxy.

### 1.1 Closed — verified by mechanism (31)

**Highs — 7 of 7:**

| ID | Verdict | Mechanism confirmed at HEAD |
|---|---|---|
| **H-12** | **Closed** (new residual → **H-19**) | One predicate, `lamport_value_is_legal` ([service.rs:1140](../../crates/ledger/src/service.rs#L1140)), behind the sole gate `checked_lamport` (:1158), used by both stamp sites via `next_stamp` (:3672; largest stamp `CEILING−2`), remote adoption on `max(local, remote)` (:5984), file adoption (:5210, :5250), the wire ([union_merge.rs:342-346](../../crates/p2p/src/union_merge.rs#L342-L346) calls the same function) and the boot warning on `clock + 1` (:2913). No second spelling exists in the workspace. `check_lamport_advance` (:1208) refuses `remote − local ≥ 2^32` on the remote and file paths; the clock moves only after insert (:6061, :5357, :5403). Re-run: A adopts at `CEILING−4`, authors `CEILING−2`, B accepts; at `CEILING−3` A refuses naming the attacker and the allowlist remedy; `2^53−1` refused on wire, remote, stamp and file. `LamportCeiling` names the author and remedy — after the victim has authored on top it names the victim (Info). Boot warning fires exactly when the stamp will refuse, and within 2^32 of the ceiling (the deviation from the tracker's `clock + 1 ≥ CEILING` is correct). |
| **H-13** | **Closed** for envelope-less lines (residual class → **H-20**, **M-47**) | `is_operator_input` (:3036, "neither key"); boot parks (:2776) and adopts through the same `adopt_file_directive` (:5129) the reconcile uses; `finalize_operator_input` (:3145) from [main.rs:447](../../crates/gl-node/src/main.rs#L447) after `set_author_id` (:364) and `set_signer` (:421), before the startup compaction (:468), the router (:478), the watcher (:497) and HTTP; also from `prepare`'s compaction branch (:3936) and `finish_recovery` (:4393). Re-run offline-edit probe: the hand-typed record carries author, lamport, parents and signature, four envelope lines on disk, `validate_supply_entry` Ok, peer accepts, reboot `unsigned=0`. Revert-proven: the three `h13_*` tests fail with the boot split removed. Peer acceptance in the tests is via `stage_remote_directive`, a **proxy** (it runs no wire check). The Done note says thirteen tests; ten exist (9 ledger + 1 gl-node). |
| **H-14** | **Closed** | `reconcile_content` parses first (:4948-4966) and writes `last_file_hash`/`canonical_bytes`/`canonical_marker` (:4974-4976) and clears `canonical_is_current` (:4998) only after; every other write site checked (boot :2991-3004, `adopt_external_edits` :4617/:4627, `reconcile_file_staged` :4840/:4849, `finish_commit` :4211-4221, `adopt_reloaded` :4502-4514). Re-run `e1` on both sides of `COMPACTION_MIN_CANONICAL_BYTES`: next write `PARSE_ERROR`, both hand lines survive. Revert-proven. |
| **H-15** | **Closed** for the shape reported (gap → **M-46**) | `BootMode` (:2102); a reload never creates the `.bean` (:2528-2541); a fresh boot refuses an absent `.bean` beside a journal (:2542-2555); `NotFound` in `adopt_external_edits` is "nothing to adopt" plus a forced compaction (:4611-4622, :4830-4844); the watcher treats `Deleted` as a change ([main.rs:530](../../crates/gl-node/src/main.rs#L530)); `finish_recovery` refuses a rebuild below `dag.len() − pending_ids.len()` and logs both counts (:4356-4384). Re-run `rm`/`mv`/large-with-journal: next write `Ok`, file holds every directive, journal folded. The gl-node watcher test drives `reconcile_file_staged` directly (**proxy** for the loop). |
| **H-16** | **Closed** for the single-replica brick (new residual → **H-21**) | `choose_parents` keeps the 256 smallest admissible heads (:3656-3661) on the local stamp and the file adoption (:3623, :5287, :5333); `validate_parent_fan_in` before the local insert is unreachable by construction (no call — truncation makes it so; the test asserts post hoc, a **proxy**); `check_unmerged_head_bound` (:5808-5825) on the remote path, `heads_authored_by` ([dag.rs:452](../../crates/ledger/src/dag.rs#L452)). Re-run: 257th single-author parentless refused, the victim names 256 parents, peer accepts, reboot quarantines 0. All `test_h16_*` are single-replica. |
| **H-17** | **Closed** (new residuals → **M-50**, **L-79**) | `MAX_AMOUNT_SIGNIFICANT_DIGITS = 21` ([validate.rs:119](../../crates/ledger/src/validate.rs#L119), `MAX_AMOUNT_MANTISSA` :167) enforced in the parser ([parse.rs:206](../../crates/ledger/src/parse.rs#L206) — file, journal and wire re-parse), the GraphQL scalar ([scalars.rs:63-77](../../crates/gl-node/src/graphql/scalars.rs#L63-L77)), `validate_transaction` inputs (:284-287) and the resolved elided leg (:326-327), `enforce_resource_limits` for `balance`/`price` ([service.rs:689](../../crates/ledger/src/service.rs#L689)), the reconcile (:5304/:5309) and the boot quarantine (:2628-2680). `ExactSum` keeps one partial per `(account, currency, scale)` ([read_model.rs:141-220](../../crates/ledger/src/read_model.rs#L141-L220)); `saturating_add` survives only in the `debug_assert`-guarded fallback (:196/:218), unreachable through any ingress. The `2^26` derivation is sound (the real bound is ≤ 9.6 × 10⁶ postings per partial, 8.2× inside 2^96). Re-run ±MAX peer proof: ±(10²¹−1) admitted, ±`Decimal::MAX` refused, balance 7 on `account()`, `account(at)`, `trial_balance`, the batched sweep, after reboot and on a reverse-arrival replica. An independent bignum oracle (8,000 cases, scratch) confirms digit-for-digit exactness whenever the sum fits 96 bits at the finest scale and order independence; the repo's proptest is code-against-code. Lockfile pins `rust_decimal` **1.42.1** (the cross-scale `rescale` is byte-identical to 1.43.0). |
| **H-18** | **Closed** | `parse_file_bounded` ([parse.rs:589-707](../../crates/ledger/src/parse.rs#L589-L707)) keeps three errors ≤ 256 chars plus a count; `validate_supply_entry` ([union_merge.rs:169](../../crates/p2p/src/union_merge.rs#L169)) refuses cheaply first (content-id form, body length, envelope, one block). Re-measured under the counting allocator: `"x\n"` × 512k → **136 B peak / 87 B** error text; a 1 MiB body under a bad id → 150 B, 0.3 µs, one allocation; 15 MiB body → 60 B. The check order itself is untested (a parse-first revert passes). But see **M-48** for valid-shaped bodies. |

**Mediums — 12 of 12** (M-35 … M-45 plus the carried M-06): M-35 (journal budget `MAX_LEDGER_FILE_BYTES`
:2578; `brick` fixture `C = 62.9 MiB + J = 5.2 MiB` boots and compacts), M-36 (`open_checked`
[journal.rs:624](../../crates/ledger/src/journal.rs#L624) on the `.bean` read :343-348, watcher
[file_watcher.rs:120](../../crates/ledger/src/file_watcher.rs#L120), journal read/append :232/:452, `.lock`
[ledger_lock.rs:110](../../crates/gl-node/src/ledger_lock.rs#L110), key [p2p_service.rs:976](../../crates/gl-node/src/p2p_service.rs#L976);
7 openers × 13 fixtures every refusal < 11 ms; rename-storm TOCTOU 10 variants × ~100k opens, **0
violations**, the `(dev, ino)` arm fired 1,957× and the `ENXIO` arm 140×; real binary refuses FIFO / 0644 /
hard link / socket / dangling / over-4 KiB at every path in ≤ 70 ms), M-37 (a: [ledger_commit.rs:452](../../crates/gl-node/src/ledger_commit.rs#L452)
and `commit_inline` :4748 return `Parse` without reloading; b: `rejected > 0` forces the compaction at
:4790, :4854 and [main.rs:571](../../crates/gl-node/src/main.rs#L571)), M-38 (Kahn pre-scan over file ∪ live
quarantine :5023-5029, release after :5064; `e3` re-run), M-39 (headroom pre-check before staging
[anti_entropy_alpn.rs:1668-1691](../../crates/gl-node/src/anti_entropy_alpn.rs#L1668-L1691), `SupplyBackoff`
armed there and consulted at :1067/:1269/:1504; near-cap batch deferred without staging or reload, read
wait < 100 ms; async `prepare_or_recover` drops the guard before the reload at all eleven call sites — but
see **L-70**, **L-71**), M-40 (server `SessionBudget` at accept :502, `clamped_io` at :574/:635,
`timeout_at(deadline)` :653; close 5 `session-deadline`; GCRA bucket
[connection_limiter.rs:414-432](../../crates/gl-node/src/connection_limiter.rs#L414-L432), token spent last
:399-401, survives disconnect; close 6; refusals one line per 10 s and `accept` returns `Ok`; four
iroh-backed tests green on loopback), M-41 (real node: 1,000 foreign-Host requests of 20 KB → 1,000 × 403,
**one** guard line, host cut at 128 chars, longest line 431 B; `max_buf_size` 64 KiB gives 431 at exactly
114,688 B in one burst — the CHANGELOG's "about 112 KiB" is exact — and at 69,632 B trickled; 461 KB
responses and 300 KB bodies unaffected; all 14 intake sites use `log_error`, `?other` → `variant_name`;
**no test captures an intake warn line**), M-42 (`FilePoller` reads only on stat-key change, racy window or
every 40 polls; `spawn_blocking`; `MissedTickBehavior::Delay`), M-43 (over-long header → `Corrupt` when
over budget or a later `;;olj ` line follows, else torn; all four spellings → `corrupt at byte 105` naming
the arm; `.torn-<secs>[-N]` rename, collision picks `-2`; boot ignores sidecars), M-44 (zero-fill boots
torn with a sidecar; NUL elsewhere still `Corrupt` — but see Info for ext4 `data=writeback`), M-45
(`journal` weight `max(512, (limit/100) × (1 + child))`; a GraphQL *variable* is resolved at complexity
time — async-graphql 7.2.1 `validation/visitor.rs:99-139` — so `journal(limit: $n)` weighs 600 like the
literal; `txid` passed, not re-hashed), M-06 (server half closed by M-40, cross-peer cap by R-5's outbound
semaphore, the FIFO deviation sound — one task per peer, worst honest delay one session deadline).

**Lows — 12 of 14:** L-55, L-56 (real binary: `got <redacted, 26 bytes, starts acme…> with whitespace at
byte 25`; `P2pConfig`/`AuthConfig` have hand-written `Debug`), L-57 (`<name>.tmp.<pid>.<nonce>`, sweep
under the lock, same-uid only), L-58, L-59, L-60 (`retain_wanted_entries` :1423 before apply — "not
validated" is a **proxy**), L-61 (doc only, by decision), L-62 (revert-proven), L-63 (per node, cap 1,000,
`truncated` counts nodes), L-65 (documents the real 2–6× — but see **M-48**), L-35 (no production
`all_directive_ids()` caller; adverts byte-identical over 7 shapes and after every insert path), L-43.

### 1.2 Partially closed (3)

| ID | What remains reachable at HEAD |
|---|---|
| **L-64** | The reload half is closed (`adopt_reloaded` carries `canonical_is_current` on a hash match; a healthy ledger keeps `Append` after a reload — the negative half, a reload over a hand-edited file, is unpinned but correct). Boot still does not warn when `compaction_text().len() > MAX` for a dense hand-written file, as the Done note records. |
| **L-66** | `GRAPHIQL_VERSION = "4.1.2"` pinned ([graphql/mod.rs:122](../../crates/gl-node/src/graphql/mod.rs#L122)). The page still loads `react@18`/`react-dom@18` **development** builds from unpkg with no SRI, and — undocumented — `https://graphql.org/favicon.ico`, a third origin. |
| **L-23** | R-9 warning and docker `meshId` done; `meshId` remains opt-in until the next release, by decision. |

### 1.3 Unchanged by decision (4)

H-01 (loopback API key; the `OPTIONS`/`Allow` fingerprint is now documented), M-09, M-10, L-06 (T45).

### 1.4 Done-note residuals, dispositions at HEAD

| Residual (task) | Disposition | Evidence |
|---|---|---|
| T61 "at the ceiling operator input is quarantined" | Confirmed; a documented fixed point with the H-12 warning. | executed |
| T61 "adoption is one-way" | Confirmed, and wider than stated: deletion semantics are timing-dependent (live deletion → resurrected at the next rewrite; restart before a write → dropped; anti-entropy re-supplies from any peer). Undocumented → Info. | executed |
| T62 "boot does not warn when `compaction_text().len() > MAX`" | Still open (L-64 half). | — |
| T62 "a count is compared, not content" | **Not safe** → **M-46**. | executed |
| T63 "a mesh already holding a single > 2^32 jump cannot be joined until that directive is removed" | **Wrong, and the reachable case is worse** → **H-19**. | executed |
| T63 "the ratchet slows exhaustion to ~2^21 attributable directives" | Confirmed arithmetic; the allowlist remains the control. | reasoned |
| T64 "smallest-id parent choice … costs frontier size only, capped per author" | Imprecise: naming any current head is admitted without counting, so an author's heads exceed 256 by one per honest head consumed; an id-grinder keeps honest heads permanently unmerged → **L-68**. Convergence itself is not stalled by that shape; it is by **H-21**. | executed |
| T65 "exact i128 accumulation stays a design item" | Still open, and now the fix for **M-50**. | — |
| T65 "I1 products can round inside `rust_decimal` past scale 28" | Confirmed: a 3-leg in-cap transaction with an exact 10⁻¹⁶ imbalance is accepted (Info). | executed |
| T65 "`verify` does not yet report `over_cap_posting_count() > 0`" | Still open; the count is exposed nowhere, and unreachable through any ingress. | grep |
| T66 "a single 1 MiB bad line still peaks at 6×" | **Understated**: valid one-block bodies reach 42× → **M-48**. | executed |
| T66 "pushed Supply frames are still fully validated" | Confirmed: 1.4–3.7 ms/MiB when refused in the parser, 132–229 ms/MiB for valid shapes — the same per-byte cost as honest frames, so CPU is not an amplification; memory is (M-48). | executed |
| T66 "the unsolicited-entry warning is per round, not rate-limited" | Confirmed; ~2,000 lines/s per hostile peer on a LAN, ~170 B each (plausible, not executed on the wire). | reasoned |
| T67 "a hard-linked or foreign-owned journal wedges writes" | Confirmed fail-closed with the remedy in the message. | executed |
| T67 "the `.bean` has no owner/mode/link check by policy" | Confirmed; a hard link or 0644 `.bean` boots. | executed |
| T67 "`O_NONBLOCK` stays set" | Confirmed harmless: regular files ignore it; `try_lock` is `flock(LOCK_NB)`. | executed |
| T68 "a damaged length on the last record within budget is torn" | Confirmed; one acked record dropped, logged with `dropped_bytes`, bytes kept in the sidecar. | executed |
| T69 "a local write refused at the cap still pays a full off-lock reload" | Confirmed and quantified → **L-71**. | executed |
| T69 "the headroom estimate over-counts ~190 B/entry and ignores drain-freed orphans" | Confirmed both halves → Info (over-count) and **L-70** (orphans; no backoff armed). | executed |
| T69 "one `journal(limit: 10000)` with postings can still materialise limit × 1,000 postings" | Still open, as stated. | — |
| T70 "an honest pooled connection is cut every 300 s" | Confirmed; one redial per code-5 close, inside the bucket. No test drives a pooled client across a code-5 close. | reasoned |
| T70 "the not-allowlisted refusal still returns `Err` and is logged unthrottled by iroh" | Confirmed and measured, plus an unrecorded sibling (bad ALPN) → **L-72**. | executed |
| T71 L-66 residual | Confirmed (§1.2). | executed |
| T71 L-61 no cooldown | Confirmed by decision; not a finding. | — |
| §5 "`finish_recovery`'s reload-failure arm leaves `force_compaction` stale" | **Escalated** through T68 → **M-49**. | executed |
| §5 informational items (OPTIONS fingerprint, non-canonical envelope spellings, `AccountClosed` churn, parents naming non-transaction ids, zero-unit `@@`, zero-posting transactions, `trial_balance` netting, swallowed directory `fsync`s, unpinned `LEGAL_*`, G-1) | All unchanged; each re-executed where cheap. | executed |
| R-8, R-10, R-14, R-15, R-16 | Unchanged. R-10's ≥ 2^32 fresh-join case is now **H-19**. | — |

---
## 2. New findings — High

Every finding below was executed and re-run by the orchestrator; the command and observed output come from
a scratch crate against the workspace crates at HEAD.

### H-19 — The adoption ratchet is measured against the adopter's own clock, so one legal directive plus the prescribed remedy permanently partitions every future or rebuilt node from all later history

**Where:** [service.rs:1208-1220](../../crates/ledger/src/service.rs#L1208-L1220) (`check_lamport_advance`:
`remote − local ≥ 2^32` with `local` = this node's clock; the no-first-contact rationale at :1178-1206),
[service.rs:1132](../../crates/ledger/src/service.rs#L1132) (`MAX_LAMPORT_ADVANCE`), [service.rs:2913,
2926](../../crates/ledger/src/service.rs#L2913) (the two boot warnings, both anchored to the *ceiling*),
[union_merge.rs:504-520](../../crates/p2p/src/union_merge.rs#L504-L520) (author must be allowlisted — a
permanent refusal per [anti_entropy_alpn.rs:1866-1880](../../crates/gl-node/src/anti_entropy_alpn.rs#L1866-L1880)),
[anti_entropy_alpn.rs:1910-1938](../../crates/gl-node/src/anti_entropy_alpn.rs#L1910-L1938) (`LamportAdvance`
retried, never cached), the remedy text at :1598-1606 and :2917-2924, and the T63 Done note's residual.

T63 made the ratchet relative to the local clock and, deliberately, gave no exemption on first contact.
Joinability therefore requires that every directive a node needs sits within 2^32 of *something it has
already adopted*. The Done note argues a fresh node climbs: each round adopts what is within reach, the
clock rises, the next round adopts the rest. That holds as long as the history is dense. It stops holding
the moment the history contains one gap of exactly the size the ratchet permits:

1. An allowlisted peer authors one directive at `local + 2^32 − 1` — legal, inside the ratchet, adopted by
   every current node. Their clocks become `local + 2^32`; every honest directive from then on carries
   `local + 2^32 + 1` or more.
2. A fresh node adopts the pre-jump history and reaches clock `local`. The first post-jump honest
   directive is `2^32 + 1` above it: refused with `LAMPORT_ADVANCE`, every tick, forever. The only way
   across is the attacker's bridge directive itself.
3. The operator does what the `LamportCeiling` text and the boot warning tell them to do about the author
   of a suspicious lamport: remove the peer from the allowlist. Now the bridge is refused at intake
   (`verify_author_allowlisted`, cached as permanent) on every new node — and the gap is unbridgeable.

A pre-T63 mesh needs no step 1 by an attacker: any jump ≥ 2^32 already in its history (a hostile peer
before T63, or a hand-typed `openledger-lamport`, M-20's own example) leaves old nodes booting and
authoring normally (a clock of 5 × 10⁹ triggers no warning) and every new node stuck. The partition is
**asymmetric and silent**: the stuck node's own writes are accepted by the mesh (`remote ≤ local` never
trips the ratchet), reads and `verify` pass, nothing logs above `debug` except one `LAMPORT_ADVANCE` warn
per refused directive per tick.

**Executed** (`D3-lamport-heads/proof`, `hunt.rs` `h1a`/`h1b`, re-run):

```
old node authors at 5000000005
fresh node: rounds=2 adopted=2 clock=3 stuck=4
   stuck lamport Some(5000000000): LAMPORT_ADVANCE (… from author attacker would advance this node's clock from 3 by more than 4294967296 in one step
fresh node with the jump directive REMOVED mesh-wide: rounds=2 adopted=2 stuck=3
old node accepts the fresh node's directive (lamport 4): true
A/B adopt the attacker's directive at local+2^32-1: clocks 4294967298 4294967298
honest directives authored after the jump carry lamports [4294967299, 4294967300, 4294967301, 4294967299]
fresh node, attacker still allowlisted: rounds=1 stuck=0 adopted=7/7
fresh node, attacker de-allowlisted: rounds=2 stuck=4 adopted=2 clock=3
mesh accepts the partitioned node's directive: true
```

The retry loop runs to a fixed point; the real anti-entropy retry (drop the refusal at :1735-1746, re-Want
by membership at :1071-1097) cannot do better. Delivery order does not matter: ascending, descending and
interleaved feeds of a dense history all converge (`X2-convergence/probe 4`, clock 12,000,000,001 in 1/4/3
rounds); only the gap does not. Reaching actor: (c) one allowlisted peer plus the operator's remedy; or no
one, on a mesh with a pre-T63 jump; the same state hits any node restored from an empty disk.

**Fix (M):** state the bound on the *content*, not the replica — refuse a directive whose lamport exceeds
its causal predecessor (the largest lamport among its parents, or among the directives it must already
hold) by ≥ 2^32, so every replica gives the same verdict and a fresh node can always climb. Cheaper (S), in
addition: warn at boot and at adoption whenever `clock > 2 × directive_count` (honest clocks are bounded by
the number of events; a 2^32 clock over thousands of directives is diagnosable at once); an operator-driven
trusted-bootstrap join; correct the residual text and the `LamportAdvance` message ("accepted once the
intervening directives have arrived" is false when they never can). **Regression:** A and B adopt
`local + 2^32 − 1` from X and author on top; drop X from the served set; a fresh node must converge (fails
at HEAD).

### H-20 — Boot trusts the envelope: an edited or split node-written record loads as history under a new content id with the original envelope, unverified and unwarned; peers refuse it and everything authored afterwards

**Where:** [service.rs:3036-3039](../../crates/ledger/src/service.rs#L3036-L3039) (`is_operator_input`: neither
key ⇒ operator input; anything else ⇒ history), [service.rs:2826-2880](../../crates/ledger/src/service.rs#L2826-L2880)
(the history path: fan-in, envelope *form*, amount cap, `dag.insert(…, false)` — no signature check, no I1;
the crate has no verifier), [service.rs:433-489](../../crates/ledger/src/service.rs#L433-L489)
(`split_ledger_blocks` starts a new block at any non-indented line), [service.rs:528-548](../../crates/ledger/src/service.rs#L528-L548)
(`salvage_unparsable_blocks` parses the parsable head of a broken block as a complete directive; the parser
accepts 0- and 1-posting transactions), [main.rs:447-468](../../crates/gl-node/src/main.rs#L447-L468) (finalize
sees nothing; the startup compaction persists it), [union_merge.rs:459-497](../../crates/p2p/src/union_merge.rs#L459-L497)
(the receiver's `verify_remote_signature` fails), README §Editing (:702-780: describes the stop → edit →
start path and only ever *adding* lines; nowhere says "do not edit an existing record").

The content id covers the economic body; the signature covers `(content_id, is_transaction, parents,
lamport)`. Two doors, both on the README's one supported edit path:

(a) **Edited record.** The operator stops the node and corrects a narration typo or an amount in a line
the node wrote, leaving the four envelope lines alone. Boot sees an author and a lamport, classifies it as
history, applies the form checks, and inserts it under the **new** content id with the **old** signature.
The old id vanishes from this node's DAG (every peer keeps it). Zero warnings. The startup compaction
persists the mismatch. The new id is a head, so the node's next write names it as a parent; every signing
peer refuses the edited record with `InvalidSignature` — a content-determined refusal the L-34 cache holds —
and buffers every descendant as an orphan, Wants the parent, gets it, refuses it again. An amount edit
diverges balances between this node and the mesh.

(b) **Split record.** A stray dedent, a BOM glued to a posting, or a stray word inside a node-written
transaction makes `split_ledger_blocks` start a new block mid-transaction. The head fragment — header,
envelope, some postings — parses as a *complete* transaction and is loaded as history with no I1 (boot
applies none); the tail is quarantined as unparsable text. The banner says the rest of the file still
loads and "nothing is lost". The truncated copy keeps one posting and drops its counter-posting, or keeps
zero postings, under a new content id with the original envelope. The live reconcile, by contrast, fails
closed on the same edit (`parse_around_quarantined_text` returns `None`) — so this is boot-only, i.e. the
supported workflow.

**Executed** (`X1-adoption-interplay/x1probe p12`, real Ed25519 via `PeerKeySignatureProvider`, re-run;
`D1-filepath/probe split`, re-run):

```
  original 1f933403 verifies on the wire? Ok("ok")
boot after typo fix: directives=3 quarantined=0 unsigned_operator_input=0 WARN lines=0
  edited record new id=00cb94d7 (old 1f933403), loaded as HISTORY: author=Some("ea4a…d22c") lamport=Some("3") signature=Some("1d9bf945…")
  edited record verifies on the wire? Err(InvalidSignature("… Verification equation was not satisfied"))
  on disk after startup compaction: edited block carries the OLD signature? true
  peer (holds original): stage(edited) -> wire verify Err(InvalidSignature(…)); stage(next) = Err("DAG: Missing parent: 571fc194… references unknown parent 00cb94d7…")
  balances: this node Assets:Cash={"USD": 11.00} ; peer Assets:Cash={"USD": 10.00}
boot after amount fix: … WARN lines=0 ; this node Assets:Cash={"USD": 13.00} (peer still holds the 10.00 original)

[dedent2] boots; unparsable_blocks=1 quarantined=1 ; A loaded with 1 posting(s) ; id changed: true ; author=Some("node-A") lamport=Some("3")
[dedent2] Assets:Cash balance before={"USD": 100} after={"USD": 100}      (the −100 counter-posting is gone)
[dedent1] A loaded with 0 posting(s) … balance after=None ; a peer's stage_remote_directive(truncated A) -> Ok(true)   (signing off)
banner: "… the rest of the file still loads …" / "… so nothing is lost … quarantined=0 unparsable_blocks=1"
```

Reaching actor: the operator, following the README, editing their own file; no attacker. The series ranks
silent divergence of committed records highest; this is that, plus the permanent orphaning of everything
the node authors afterwards, reached by the most natural edit there is. An append-only mesh cannot honour a
correction anyway (peers keep the original) — the defect is the silence and the poisoning of later writes.
The user may re-rate to Medium on "editing a signed line is not the documented use of the workflow"; the
README does not say so, and door (b) needs no intent at all.

**Fix (M, one fix for both doors):** boot must verify what it loads. Mirror the signer with a
`set_verifier` installed in `main.rs` right after `set_signer`, and a `verify_own_history()` pass before
the startup compaction: for every directive whose author is this node (and, since the author id is the
key, every foreign-authored one too), verify the signature; on failure **quarantine** it with the reason
"signature does not verify — was this record edited?" (the compaction keeps it in the file, H-08). A
truncated fragment fails the same check because its signature was made over the original id. Additionally
(S): the salvage must demote the parsed head of a split block into the same raw `UnparsableBlock` as its
tail (an unparsable block with no blank line before it belongs to the block above), and boot should
quarantine any salvaged transaction that fails I1; fix the banner. README: "Never edit an existing record;
append a reversing entry. A record you delete is re-supplied by peers." **Regression:** the `p12` shape
(boot on an edited signed body quarantines it; everything served passes `verify_remote_signature`) and
`l45_a_split_transaction_block_is_quarantined_whole_not_loaded_truncated`.

### H-21 — The per-author head bound makes DAG membership delivery-order-dependent: one peer's split delivery leaves two honest replicas with permanently different committed DAGs

**Where:** [service.rs:5808-5825](../../crates/ledger/src/service.rs#L5808-L5825) (`check_unmerged_head_bound`
refuses a parentless transaction when its author already owns 256 heads *on this replica*),
[dag.rs:452-463](../../crates/ledger/src/dag.rs#L452-L463) (`heads_authored_by`, transient local state),
[anti_entropy_alpn.rs:1930-1934](../../crates/gl-node/src/anti_entropy_alpn.rs#L1930-L1934) (`UnmergedHeadLimit`
retried, not cached — but a retry can never succeed without a local append), [service.rs:3656](../../crates/ledger/src/service.rs#L3656)
(`choose_parents` truncation, which already closes H-16's brick on its own).

T64 added two things: the local stamp names at most 256 parents (which alone stops the victim's own append
from being refused everywhere), and the remote path refuses a 257th unmerged head per author. The second
rule is evaluated against a number only this replica holds. An allowlisted peer authors 257 parentless
transactions and serves replica A the subset `{0..255}` and replica B `{1..256}` (a peer chooses what it
advertises to whom). Each replica admits 256 and refuses the one it was not given first. A and B then run
anti-entropy with each other: A Wants #256, B Wants #0, each serves it, each refuses it at its own cap.
Same available directive set, two permanently different committed DAGs — "same directive set ⇒ same
state" (C4/I7, the premise of M-09 and of every convergence test) is broken through a door T64 opened.

It self-heals only when **each** diverged replica authors locally (its own append merges its 256 heads
below the cap); an append from the *other* replica names parents this one lacks and is orphaned, so it does
not help. A pure observer, auditor or validator replica that never authors diverges indefinitely, and an
authoring-quiescent mesh diverges for the length of the quiescence. If the 257 transactions carry distinct
economic bodies, `trial_balance` and every report diverge, not only ids.

**Executed** (`X2-convergence/probe 3b`, re-run):

```
initial: A membership=256/257 (heads 256), B membership=256/257 (heads 256)
after anti-entropy to fixpoint (1 rounds, no local authoring):
  DAG membership identical? false  (A-only=1, B-only=1)
  *** PERMANENT DIVERGENCE: same available directive set, different committed DAGs ***
after ONE local append on A + re-gossip (2 rounds): A=257/257 B=256/257 converged=false
```

Single-subset delivery (one replica short) converges once the passive replica adopts any propagated local
append (`probe 3`); the disjoint-subset shape does not. Reaching actor: (c) one allowlisted peer.

**Fix (S):** drop the remote `UnmergedHeadLimit` refusal. `choose_parents`'s `truncate(MAX_PARENTS)` plus
`validate_parent_fan_in` already make H-16's brick unreachable, and the residual — frontier size — is
convergent. If a frontier cap is wanted, it must be content-deterministic (M): every replica drops the same
heads (e.g. lexicographically largest above the cap) so equal sets give equal DAGs. **Regression:** a
two-replica disjoint-subset test asserting equal DAG membership after anti-entropy with no local authoring
(fails at HEAD); every `test_h16_*` today is single-replica.

---
## 3. New findings — Medium

### M-46 — The T62 floor counts file-adopted lines as "staged", so a live file replacement plus one failed commit installs a rebuild over acked records, and the log labels them as staged
[service.rs:4356-4360](../../crates/ledger/src/service.rs#L4356-L4360) (`floor = dag.len() − pending_ids.len()`),
[service.rs:5364, 5407](../../crates/ledger/src/service.rs#L5364) (`adopt_file_directive` pushes the ids it adopts
*from the file* onto `pending_ids`), [service.rs:3062-3070](../../crates/ledger/src/service.rs#L3062-L3070) (boot's
operator-input adoption does the same, so `uncommitted_count()` is non-zero right after boot, contradicting
its doc at :3821), [service.rs:4378-4384](../../crates/ledger/src/service.rs#L4378-L4384) (the install log's
`discarded_staged`). The floor is meant to be "what a failed commit may legitimately have left behind: the
staged batch was never on disk". But every line reconcile or boot adopts from the `.bean` *is* on disk and
is counted as staged, so the floor is understated by exactly that number. Operator habit: `cp` a backup over
the live file (removes M acked lines, adds N ≥ M others); the next commit fails (ENOSPC, EPERM, read-only
remount, a `chflags`); the reload's floor is `old`, the replacement holds `old`, it is installed, the M acked
records leave memory, and the next successful write puts the replacement on disk — gone. Had the persist
succeeded, the union would have been written (control). **Executed** (`D2-recovery-journal/d2probe floor`,
re-run): `(b) acked on disk: 3 … write after replace, persist failing → Err(PermissionDenied) … L-13 reload
installed … before=7 after=3 discarded_staged=4 … Assets:Acked1..3 in memory: false … next write → Ok; on
disk: Ok(4); Acked1 on disk: false`; `(b3)` the same at boot with two hand lines adopted and two history
lines deleted; `(c)` pure truncation with nothing adopted is refused (correct). This is the T61-adoption ×
T62-recovery interaction: T61 pushes to `pending_ids`, T62 subtracts it. The precondition (a live edit that
removes records, plus a commit failure) is unsupported by the README and needs two events, which is why this
is Medium rather than the High H-15 was; it is the guard failing at exactly its own job, and the actor who
can write the directory can fill the disk. **Fix (S):** keep file-adopted ids out of `pending_ids` (a
separate counter for the "nothing to do" short-circuit), which also fixes the doc and the label; or refuse
the rebuild when any non-pending id in memory is absent from it (proven on a scratch copy: both shapes
refuse, 20 recovery tests pass). **Regression:** shape `(b)` → `REFUSING`, memory keeps six, the next commit
writes seven; and `(b3)` at boot.

### M-47 — A half envelope (author *or* lamport, not both) is history at boot but operator input on the live reconcile: loaded raw, unsigned, served, refused by every peer, and every later write descends from it
[service.rs:3036-3039](../../crates/ledger/src/service.rs#L3036-L3039) (`!author && !lamport`),
[service.rs:865-871](../../crates/ledger/src/service.rs#L865-L871) (`validate_file_envelope_form` checks the *form*
of a lamport that is present, never presence), [service.rs:2857-2880](../../crates/ledger/src/service.rs#L2857-L2880)
(inserted raw; `BootLamportHigh::note` ignores it — no lamport), [service.rs:5201](../../crates/ledger/src/service.rs#L5201)
(the live reconcile's `needs_stamp = !contains(lamport)` stamps the missing half and signs),
[union_merge.rs:271-277](../../crates/p2p/src/union_merge.rs#L271-L277) (the wire requires both). T61's decision
text says "a node never writes a directive without `openledger-author` *and* `openledger-lamport`"; the exact
negation is "lacks either", and the code tests "lacks both". A line with only an author (an operator who
thinks the author line is required; a block copied from another ledger with the lamport line dropped) or only
a lamport takes the history path — no lifecycle rule, no body cap, no stamp, no signature, the list the H-13
comment gives for why history is the wrong path. It is a head; the node's next write names it; the compaction
writes it back half-enveloped (fixed point); the reconcile never sees it again (it is in the DAG). The same
line pasted while the node runs is adopted, stamped and signed. **Executed** (`x1probe p1`, `D1 probe
partial-author`, re-run): `txn half-author in DAG: author=Some("nodeA") lamport=None … signature=None` (zero
WARN); `peer validate_supply_entry(half-author) = Err(EnvelopeMissing("openledger-lamport"))`;
`peer.stage_remote_directive(next) = Err("DAG: Missing parent …")`; live: `lamport=Some("4") …
signature=Some(…)`. Also on the live path: lamport-only is adopted unsigned with no author and no warning
(`sign_adopted_entry` :5553 returns on `None`) — a third exception the README's "two exceptions" omits — and
a hand-typed signature is kept under a freshly stamped lamport and parents, so "adopted untouched" is false.
**Fix (S):** `is_operator_input := !author || !lamport`, or quarantine exactly-one-of in
`validate_file_envelope_form` with an `EnvelopeMissing` reason; strip a pre-existing signature when
`needs_stamp`. **Regression:** the `p1` shape — both half lines carry author, lamport, parents and signature
after boot + finalize (or are quarantined) and `validate_supply_entry` accepts what is served.

### M-48 — The cardinality caps run only at stage time, so a valid one-block Supply body peaks at 42× in `validate_supply_entry` and a 15 MiB frame of them holds 546 MB before anything is refused
[union_merge.rs:205-215](../../crates/p2p/src/union_merge.rs#L205-L215) (no `enforce_resource_limits` after the
parse), [parse.rs:1322-1341, 872-905, 1000-1030](../../crates/ledger/src/parse.rs#L1322-L1341) (postings, tags/links,
currencies uncapped), [service.rs:28-38, 671-705](../../crates/ledger/src/service.rs#L671-L705) (`MAX_POSTINGS_PER_TRANSACTION
= 1000`, `MAX_TAGS = 100`, `MAX_METADATA_KEYS = 100`, enforced in `stage_remote_directive` :5869-5880 — phase 2),
[anti_entropy_alpn.rs:1522-1590](../../crates/gl-node/src/anti_entropy_alpn.rs#L1522-L1590) (`staged` accumulates
every parsed entry of a frame before the first stage). T66 bounded the *error* path; the *success* path of
the parser is unbounded in what it materialises. **Executed** (`D5-wire-bounds/probe shapes`, `batch`,
counting allocator, release, re-run): `41941 postings + 1 meta each: body=1,048,538 peak=43,745,442 (41.72×)
Ok(directive)`; `349518 tags: 30.63×`; `349515 currencies: 24.00×`; `61678 postings: 19.94×`; every one
`Ok` with a correct id, refused only at stage. `batch/15 × (42k postings+meta): frame≈15,731,565 B, phase-1
peak=546,083,498 B (34.7×)` versus `256 × honest 1000-posting: 6.1×`. Per peer ≈ 1.1 GB transient (two 32 MiB
frames in flight), ≈ 9 GB under the 256 MiB global byte budget — the L-65 doc says 2–6×. Refused-path shapes
also exceed the Done note's 6×: 262k junk body lines 9.0×, a 1 MiB currency 11.0×. Actor (c). Medium rather
than High because it needs allowlist membership, is bounded by the byte budget (unlike H-18's 186×), and
costs the attacker the same bytes; the user may apply the series' 4× bar as for H-18. **Fix (S):** call
`enforce_resource_limits` in `validate_supply_entry` immediately after the parse (kills the batch
accumulation), and add parse-time limits to `parse_file_bounded` so counts are refused inside the block loop
(restores the ~6× floor). **Regression:** these shapes in `decode_memory.rs` under the 4× assertion (today it
is asserted only on refused shapes), plus a 15-entry batch bound.

### M-49 — A failed reload leaves `force_compaction` stale, so the next commit appends behind a torn tail; T68's classifier then makes the journal `Corrupt` and the next boot refuses, with an acked record behind it
[service.rs:4385-4392](../../crates/ledger/src/service.rs#L4385-L4392) (`finish_recovery`'s `Err(reload_error)` arm
logs and returns; the refusing arm at :4372 sets `force_compaction = true`, this one does not, and neither
carries the rebuild's `journal_torn_at_boot`), [service.rs:3910-3920](../../crates/ledger/src/service.rs#L3910-L3920)
(`prepare` chooses `Append` when nothing forces a rewrite), [journal.rs:296-337](../../crates/ledger/src/journal.rs#L296-L337)
(a record following a damaged one is now `Corrupt`, by the R-18 decision). The 09/22-v2 report listed this
arm as informational ("cheap hardening: set it"); T68 turned it into a boot refusal. Sequence: an append
tears (crash or disk error mid-write) → the reload fails (the same disk trouble, or a transient read error)
→ memory is kept ahead of disk with `force_compaction = false` → the next successful commit is an `Append`
whose record lands after the torn tail → the next boot's scan finds a header after a damaged record →
`Corrupt`, `exit(1)`. The operator's only remedy is to move the journal away, which drops the acked
directive with it. **Executed** (`X3-commit-recovery/x3probe torn` case B, re-run): `torn tail 184 B, reload
Err: compaction_pending=false uncommitted=1 … next commit kind = Append; committed OK … reboot → Err: ledger
journal is corrupt at byte 307: record payload does not match its recorded SHA-256 [LEDGER_JOURNAL]`. Case A
(reload succeeds) correctly compacts and leaves a sidecar. Two failures are needed, but they are the same
failure twice; rated with M-35 (crash → boot brick). **Fix (S):** in the `Err` arm set `force_compaction =
true` and `journal_torn_at_boot |= …` from the failed attempt's knowledge (or simply always force a
compaction after a failed reload, which is what the refusing arm already does). **Regression:** case B
asserting the next commit is `Compact` and the reboot succeeds with a sidecar.

### M-50 — Upgrading over a pre-T65 file that holds one over-cap amount silently drops it and everything below it from balances, and a fresh replica can never sync past it
[service.rs:2628-2680](../../crates/ledger/src/service.rs#L2628-L2680) (the over-cap block fails the parser and is
quarantined as *text*), [service.rs:2864](../../crates/ledger/src/service.rs#L2864) (its children are inserted
leniently, `dag.insert(…, false)`, with a dangling parent), [service.rs:6000](../../crates/ledger/src/service.rs#L6000)
(the wire path inserts with `require_parents: true`), [parse.rs:206](../../crates/ledger/src/parse.rs#L206) (the
cap counts **trailing zeros** as significant), CHANGELOG "Ledger files" ("A directive like that already on
disk is quarantined at boot" — true, and incomplete). The precondition is realistic and needs no attacker:
before T65 an elided leg from an 8-decimal quantity times an 8-decimal price with value ≥ 10⁵ was stored
with 22 significant digits (`1.00000000 BTC @ 100000.00000000 USD` → `-100000.0000000000000000`), as were
base-unit token amounts. After the upgrade that transaction is quarantined as text (kept through
compaction), its children load with a missing parent, balances silently exclude it, `verify` reports
`MissingParent` forever, and a **fresh replica** refuses the parent permanently (parse refusal, L-34 cached)
and gets `MISSING_PARENT` on every descendant — it can never sync anything below that transaction.
Upgraded and non-upgraded nodes disagree on balances meanwhile. **Executed** (`D4-balances/probe upgrade`,
re-run): `pre-upgrade balance Assets:Cash = 1000000000000000000014 · upgraded boot: unparsable_blocks=2
quarantined_directives=2 has X? false has C? true · upgraded balance = 14 · verify: ok=false errors=["Missing
parent: …"] · fresh: stage X → refused [INVALID_POSTING] permanent-class; stage C → refused [MISSING_PARENT];
stage G → refused [MISSING_PARENT]; fresh replica balance: None`. Medium because it affects only files
written before T65 (no versioned release exists yet); High if such histories are common in the deployments
this is meant for. **Fix (M):** the deferred exact `i128`-per-scale accumulation, so history need not be
quarantined and the cap becomes an *authoring* rule; interim (S): a pre-upgrade scan tool, a release note,
`verify` reporting quarantine ids, and `normalize()` of the resolved leg before the cap so trailing zeros do
not count (which also stops the node refusing ordinary 8-decimal purchases today — Info below).
**Regression:** the `pre_upgrade.bean` fixture — the boot must keep the descendants' parents resolvable, or
refuse loudly rather than serve a history a fresh replica cannot take.

---
## 4. New findings — Low

- **L-67 — gl-node boots the ledger with the placeholder author `"local"`, so T63's own-quarantine clock rule never fires at a process boot.** [main.rs:219](../../crates/gl-node/src/main.rs#L219) (`"local"`), :364 (`set_author_id` after boot), [service.rs:1268-1272](../../crates/ledger/src/service.rs#L1268-L1272) (`note_if_own` compares to the boot author). An own quarantined record contributes nothing, so the node re-issues its `(author, lamport)` pair (M-18); operator input adopted at boot gets a different lamport on a Fresh boot than on an L-13 reload. **Executed:** `pair re-issued = true`; control booting with the real id `clock=14`. The Done note's claim holds for the library only; `test_boot_clock_counts_quarantined_directives_only_when_own` boots with the real id (proxy). Fix: load the key and derive the `EndpointId` before `LedgerService::boot`, or re-fold the quarantine in `set_author_id`.
- **L-68 — The head bound is looser than named, and smallest-id parent choice lets an id-grinder keep every honest head permanently unmerged.** [service.rs:5811-5816](../../crates/ledger/src/service.rs#L5811-L5816) admits any transaction naming a current head without counting, so an author's heads climb 257, 258, … one per honest head consumed; grinding ~10× ids per round (plain SHA-256 over a metadata field) keeps `choose_parents` naming only attacker heads, so the victim never merges an honest head nor its own previous append — each honest append becomes a permanent head mesh-wide, bypassing the bound, and `heads_authored_by` is O(|heads|) per remote transaction. **Executed:** six rounds, 0 honest heads named, honest unmerged 1 → 6; 25 permanent honest heads after 25 rounds. Consistent across replicas (no divergence); frontier and advert amplification only. Fix: with H-21's (S) fix the remote count goes away; choose parents by author diversity or newest lamport.
- **L-69 — Ratchet- and head-bound-refused directives are re-fetched, re-parsed, re-verified and re-validated every tick with no cap.** [anti_entropy_alpn.rs:1735-1746, 1071-1097](../../crates/gl-node/src/anti_entropy_alpn.rs#L1735-L1746). Both classes are trivially manufacturable (N signed directives at `local + 2^32`, or N parentless past 256), nothing is stored so no size cap or backoff engages. **Executed** (release, ledger side): 4,096 small ratchet-refused entries 122 ms/tick; 32 × ~1 MiB 2.73 s/tick plus 30 MiB of transfer and 32 signature verifies, per hostile peer, indefinitely; 4,096 head-bound-refused 518 ms/tick. Same shape as orphan re-delivery, which the series accepted. Fix: cache `LamportAdvance` keyed on `(peer, id, local clock)` and invalidate on clock change; cache `UnmergedHeadLimit` until the count drops; rate-limit the warn.
- **L-70 — Orphans freed by a batch bypass the headroom check; the resulting prepare failure reloads off-lock every tick and arms no backoff.** The pre-stage check covers only the page's `staged_bytes` ([anti_entropy_alpn.rs:1670](../../crates/gl-node/src/anti_entropy_alpn.rs#L1670)); `drain_orphans` (:1788) stages up to 16 MiB per peer after it; `SupplyBackoff::arm` has exactly one call site (:1677, the deferral branch). Near the cap a peer alternating adverts (orphan children, then their parent) drives one full reload per two ticks forever (3.65 s each on 305k directives, permit held ~35 %); readers are unaffected (the reload is off the lock). ALPN also publishes to GraphQL subscribers at stage time (:1728-1733, :2010-2016), before the rollback. **Executed:** `B alone: prepare Ok (489 B) … B + drained O: prepare Err(RESOURCE_LIMIT_EXCEEDED) → reload 545 ms, no SupplyBackoff armed`. Fix: re-check headroom after the drain and arm the backoff on a cap-refused prepare; publish after durability.
- **L-71 — An API-key holder retrying a refused write at the cap serialises every other writer behind a full reload per attempt.** Each refused mutation reloads off-lock while holding the FIFO permit; K concurrent requests queue the watcher, peer batches and the shutdown compaction for K × 3.65 s; K ≥ 9 gives honest mutations 408 for the attack's duration; reads are alive. **Executed:** four refused attempts 1.3 s (comment fixture, lower bound), an honest open waited 104 ms; with a queued compaction 2.73 s. The T69 residual, quantified. Fix: the pre-stage headroom check in the three mutations, as the peer path has.
- **L-72 — Any dialer on a public QUIC bind drives ~730 B of unthrottled WARN per handshake.** [anti_entropy_alpn.rs:439-444](../../crates/gl-node/src/anti_entropy_alpn.rs#L439-L444) (own `warn!` then `Err`, so iroh's router logs a second line, vendored `iroh-1.0.3/src/protocol.rs:654`); an unknown ALPN dies in the TLS handshake and iroh logs `accepting failed` (:629) per attempt; the T70 throttle covers only limiter refusals (:462). **Executed** (scratch iroh dialer against the real node): 200 non-allowlisted dials → +400 WARN lines, 145,600 B; 200 bad-ALPN → +200 lines, 57,400 B in 1 s; eight loopback dialers ≈ 83 KB/s (≈ 7 GB/day) at 0.8 % CPU — the handshake, not the log, bounds it. M-41's shape on the QUIC edge; the first half is a recorded T70 residual, the second is not. Fix: route the not-allowlisted arm through `should_log_refusal` and return `Ok`; `iroh::protocol=error` in the default `EnvFilter`.
- **L-73 — The config file is the one operator file opened with a plain, blocking, symlink-following, uncapped read.** [config.rs:949-952](../../crates/gl-node/src/config.rs#L949-L952). A FIFO at `GL_NODE_CONFIG` parks boot before the ledger lock with one log line; `--health-check` hangs the same way; a 200 MB config is still loading at 30 s. **Executed** (real binary): `exit=142` after the alarm with only `loading configuration` logged. Needs write access to the config's directory. Fix: `FileTrust::OperatorConfig` through `open_checked` plus `read_to_end_capped(1 MiB)`.
- **L-74 — `finalize_operator_input` rewrites the DAG copy only; the read model keeps boot's clone.** The `journal` query serves the hand record as `author: "local"`, unsigned, until restart, while `transaction(txid)` serves the finalized record. **Executed** (`x1probe p3`): read-model copy `author=Some("local") … signature=None` after finalize and after compaction; correct after restart. Fix: re-index the finalized directive.
- **L-75 — Hand-typed `openledger-parents` on operator input are honoured verbatim; a parent that exists nowhere becomes a signed head and every later write is orphaned on peers, with no warning.** [service.rs:5294](../../crates/ledger/src/service.rs#L5294) ("parents the FILE spelled are the operator's own and are left alone"), both file paths. **Executed** (`x1probe p9`, `D3 hunt h6`): `dangling id … parents=Some("ffffffff") signature=Some(…) is head? true`; `peer.stage_remote_directive(next) = Err("DAG: Missing parent …")`. Pre-existing L-40 territory, now signed. Fix: require hand-spelled parents to resolve, else quarantine.
- **L-76 — The boot cycle arm's `quarantined.insert` lets a later envelope-less spelling of the same id replace the signed one; the compaction drops the signed copy and the next boot re-authors the record.** [service.rs:2760](../../crates/ledger/src/service.rs#L2760). **Executed** (`x1probe p4`): `signed cycle copy of T2 still on disk? false`; reboot: `T2 now in DAG as author=Some("nodeA") lamport=Some("5") parents=Some("") signature=None` while peers keep the original envelope. Fix: `entry().or_insert` as the other arms do, preferring the enveloped spelling.
- **L-77 — A hand-typed `open` of an already-open account is adopted at boot and live while the local API refuses it.** [service.rs:3442](../../crates/ledger/src/service.rs#L3442) (`AccountAlreadyOpen`) vs :5381-5423 (no check). **Executed:** currencies re-constrained to EUR; the next USD transaction fails `ACCOUNT_CURRENCY_MISMATCH`. The same shape is reachable by a peer (M-09), so parity, not a new vector.
- **L-78 — `open` currencies are uncapped.** [parse.rs:1000-1030](../../crates/ledger/src/parse.rs#L1000-L1030), [service.rs:671-695](../../crates/ledger/src/service.rs#L671-L695). **Executed:** a 786 KB `open` with 262k currencies stages `Ok` at 5.2 MB resident, permanently on every replica (~440 MB mesh-wide under the file cap). A 1 MiB account name or tag also stages `Ok` (1×). Fix: `MAX_CURRENCIES_PER_OPEN`.
- **L-79 — Mixed-scale totals round at read time, deterministically everywhere, and the ascending fold is not correctly rounded.** [read_model.rs:172-180](../../crates/ledger/src/read_model.rs#L172-L180). **Executed:** `1000 + 1e-28` prints `1000.0000000000000000000000000` on every path and `balance Assets:Cash 1000 USD` passes — a peer's scale-28 dust vanishes from the printed balance; `1234567.12345678 + 8e20` prints `800000000000001234567.1234568`; the oracle finds 1,167 of 4,787 non-fitting cases more than half an ulp off (≤ 1 ulp per step — double rounding). The doc's "exact when it fits" holds; "exact" otherwise does not. Fix: `verify` against the exact partials; state the precision.

## 5. New informational

- **Loopback QUIC worked for the whole audit** — every iroh-backed test passed first time; the environment note did not apply.
- **Journal, ext4 `data=writeback`** (PLAUSIBLE): the M-44 NUL rule covers zero-filling filesystems (XFS); ext4 writeback exposes *stale* data after the same crash — a last record with the right length, the wrong hash and no NUL → `Corrupt` → boot refusal on a node-written file. The module doc and the T68 note claim otherwise. Byte-level shape executed (`corrupt at byte 106`); not executable on APFS. Fix: narrow the claim, or treat any hash-failing *final* record with no later header as torn (the bytes are kept in the sidecar anyway).
- **A refused reload discards `journal_torn_at_boot`**, so the following compaction unlinks a torn journal instead of renaming it — the "never unlinked" policy broken forensically, nothing lost. Executed: `sidecars=[] journal_exists=false`.
- **A journal record duplicating a canonical body with this node's author and a large lamport moves the boot clock silently** (`note_if_own` on `Duplicate`, :2916-2918): `lamport_clock=4000000001`, no warning. File-writer only.
- **`uncommitted_count()`'s doc** ("non-zero only between a staged mutation and its commit") is false after a boot that adopted operator input (M-46's root).
- **Headroom estimate over-counts** ~150–190 B/entry ([anti_entropy.rs:240](../../crates/p2p/src/anti_entropy.rs#L240): 128 B framing + 64 B id vs ~10–30 B real), so in the last ~40 KB before the cap a fitting honest batch is deferred forever; compaction makes no room. Directives re-replicate once the operator archives.
- **Fresh-boot combinations:** absent `.bean` beside `.torn-*` only, `.lock` only, or a stale `.tmp` silently start an empty ledger (documented non-signals; not crash-reachable). `journal_path.exists()` (:2523) follows symlinks: a dangling journal link plus an absent `.bean` creates an empty `.bean` and then fails.
- **The sweep deletes any same-uid file named `<name>.tmp.*`** (e.g. `ledger.bean.tmp.backup`); the reserved pattern is undocumented. Fix: match `<name>.tmp.<digits>.<16 hex>` and say so in the README.
- **macOS: a Unix socket swapped in between `lstat` and `open`** is refused with the raw `EOPNOTSUPP` (102), not the T67 text; still refused, never blocks.
- **Process-wide log throttles hide other sources** for 10 s at a time: the guard's ([request_guard.rs:66-110](../../crates/gl-node/src/request_guard.rs#L66-L110) — and the `suppressed` count is printed only by the *next* refusal, so a flood's 999 were never reported) and the limiter's ([connection_limiter.rs:301-316](../../crates/gl-node/src/connection_limiter.rs#L301-L316)). Key by client / `(peer, reason)`.
- **Bounded formatter caveats:** a 64-char non-printable envelope key `Debug`-escapes to 686 chars (field 277 B); the 256-char cut drops the `(InvalidAccountName)`/`(InvalidCurrency)` code because those messages embed the whole token and the kind renders last ([parse.rs:367-414](../../crates/ledger/src/parse.rs#L367-L414)).
- **`LamportCeiling` names the victim** once it has authored on top of the poison (the highest lamport is now its own).
- **A child with a lamport below its parent's is accepted** (`accepted=true clock=4000002`); harmless for the ratchet argument since children wait on parents in the orphan buffer.
- **I1 is judged on `checked_mul`-rounded weights** (pre-existing): a 3-leg in-cap transaction with an exact 10⁻¹⁶ imbalance is accepted; `10^20 @ 10^20` refused; 1,000 rounded products → "per-currency weight sum overflows".
- **Trailing zeros count as significant digits**, so an ordinary elided `1.00000000 BTC @ 100000.00000000 USD` purchase is refused today with a clear error (M-50's precondition). `normalize()` the resolved leg before the cap.
- **Amount forms:** the scalar accepts `1_000`, the parser `1,000`; both refuse exponents and > 28 fractional digits even when all-zero; a partial that cancels to zero drops out of the printed scale (`[2, −1, 0.1, −0.1]` prints `1`), deterministically.
- **ALPN log text "rolled back in memory, will re-pull"** ([anti_entropy_alpn.rs:1819-1823](../../crates/gl-node/src/anti_entropy_alpn.rs#L1819-L1823)) is false on the `Parse`/`CommitInFlight` arms: the batch stays staged and served and is written by the next commit.
- **The compaction arm holds the write lock across a 64 MiB read + SHA-256 + serialize** (`adopt_external_edits` + `compaction_text`): readers waited 1.10 s during a concurrent `compact()`. Pre-existing, not T69's reload.
- **`stage_remote_directive` accepts an envelope-less directive** (library API only; the wire refuses); its journal record then carries it and the next boot adopts it as operator input.
- **README §Editing omits** that a deleted signed line is re-supplied by peers, that adoption is one-way, and the lamport-only third exception; it has **no upgrade note** about older binaries and never links `CHANGELOG.md`; its clippy line lacks `--workspace --locked -- -D warnings`.
- **CHANGELOG omissions:** L-60 (unsolicited Supply entries dropped with a WARN, [anti_entropy_alpn.rs:1297-1303](../../crates/gl-node/src/anti_entropy_alpn.rs#L1297-L1303)); the Rust-API change `ConnectionLimiter::try_acquire` → `Result<_, Refusal>` and `pub enum Refusal`; the journal appender requiring 0600 on an *existing* journal (docs say only "not group- or world-writable"); GraphiQL's third origin. Every statement the CHANGELOG makes is true (§6).
- **Test-net notes:** the two T63 convergence tests are direct `stage_remote_directive` loops with a hand-ordered feed (no anti-entropy, no orphan buffer); `test_state_dependent_stage_refusals_are_not_cached` pins the classifier only; the M-40 wire tests restate burst 3 / refill 3 s and `io` 600 ms / `session` 2 s, and the close-code *numbers* 5/6 are never asserted; no test captures iroh's `warn!` ("`Ok` so iroh does not log" is inspection only); `ENTRY_PEAK_BUDGET_MULTIPLE = 4` is asserted only on refused shapes; the `(dev, ino)` and `ENXIO` arms of `open_checked`, the key 4 KiB cap and the sweep-after-lock order are unpinned; the repo's H-17 proptest has no independent oracle and the every-ingress test's boot arm has no children (it does not pin M-50); `m39_a_mutation_refused…` asserts lock hold on a comment-only fixture; the `.torn-<secs>-N` collision arm, L-64's negative half, M-46, M-49 and every finding in §2 are unpinned.

---

## 6. Dependencies, supply chain, and verification runs

**`cargo audit`** (v0.22.2, DB fetched 2026-09-23 `1e640cd`, 1,267 advisories, 499 locked crates): **exit
0**; sole output is the allowed warning RUSTSEC-2024-0436 (`paste`, build-time proc-macro). `.cargo/audit.toml`
still ignores exactly RUSTSEC-2026-0235 (`rkyv`) with evidence; `cargo tree -i rkyv -e all --target all` prints
nothing. Lockfile at HEAD: 495 `registry+https://github.com/rust-lang/crates.io-index` + 4 workspace crates,
**zero** git sources; the one change since `3d5ff71` is `"libc",` under `ledger` (0.2.189, already compiled
transitively; `libc = "0.2.189"` is a caret requirement held by `--locked` — the Done note says "direct
dependency", which is accurate). `rust_decimal` **1.42.1** (matches `.cargo/audit.toml`). Toolchain rustc
1.97.1; `rust-version = "1.91"` everywhere including the Dockerfile digest pin.

**CI** (`.github/workflows/ci.yml`): pins re-verified with `git ls-remote` — `actions/checkout` `11d5960…` =
`v4.4.0` ✔ · `Swatinem/rust-cache` `6323deb…` = `v2.9.2` ✔ · `rustsec/audit-check` `69366f3…` = `v2.0.0` ✔ ·
`dtolnay/rust-toolchain` `4360b52…` fetched by SHA, still the 2026-08-04 "toolchain: stable" commit. `cargo
clippy --workspace --all-targets --locked -- -D warnings` exit 0; `cargo fmt --check` exit 0.

**`unsafe`:** exactly one production occurrence, `libc::geteuid()` at [journal.rs:870](../../crates/ledger/src/journal.rs#L870)
(R-17 closed as specified); `main.rs`'s `libc_umask` is test-only.

**CHANGELOG vs code:** 72 bullets checked, 41 executed against the real binary or a scratch crate (431 at
exactly 114,688 B in one burst; h2c preface closed and `--http2-prior-knowledge` fails; `/health` 116 × 200 +
14 × 429 of 130; guard `suppressed=7`; `Origin: null` 403; localhost ↔ 127.0.0.1 `Origin` equivalence;
`verify.truncated`; `2^53−1` illegal and `2^53−2` legal; 22 significant and 29 fractional digits refused;
unknown keys refused in every section; every *Added* default and range; close reasons `session-deadline` and
`accept-rate-limit`; `.torn-<unix-seconds>`; `<name>.tmp.<pid>.<nonce>`; GraphiQL 4.1.2 URLs; docker
`meshId`; the `supply_backoff` API fields). **Every statement is true.** Omissions are listed in §5. All
twelve new config keys are parsed, validated at boot with the documented floors and ceilings (58 real-binary
boots: floor/ceiling accepted, floor−1/ceiling+1 refused naming the key; every shipped config validates;
`deny_unknown_fields` proven at top level, `p2p` and `http`), land in exactly one struct field and are consumed
at runtime (`antiEntropyMaxSessionFrames` in both budgets; `antiEntropySupplyBackoffSeconds` → `SupplyBackoff::arm`;
`antiEntropyMaxConcurrentExchanges` → the semaphore, shown as `max_concurrent=3` in the live loop's start log);
no consumer reads a literal in place of the config value; only `GL_NODE_CONFIG` and `GL_NODE_API_KEY` are read
from the environment.

**Test suite at HEAD:** `cargo test --workspace --locked` — **1,115 passed, 0 failed, 0 ignored** before the
audit started and **1,115 passed, 0 failed, 0 ignored** (identical per-binary counts) after all passes completed. Every named regression test in §1 was
additionally run in isolation by the re-verification passes (10 for T61, 19 for T62/T68, 14 for T63/T64, all
H-17 tests, all T66 tests, 26 for T67, 26 for T69, 23 for T70/config, 18 for T71; all green). The repository
is unchanged except for this file.

---

## 7. Consolidated open-findings register

Everything open as of this audit. IDs are stable across the 09/01, 09/02, 09/22, 09/22-v2 and 09/23 reports.

| ID | Sev | One-liner | Origin |
|---|---|---|---|
| **H-19** | High | Ratchet relative to the adopter's clock: one legal `local + 2^32 − 1` directive plus allowlist removal (or any pre-T63 jump) permanently partitions every future or rebuilt node; silent, asymmetric | **09/23** |
| **H-20** | High | Boot trusts the envelope: an edited signed record, or a split node-written block, loads as history under a new id with the old signature, unverified, unwarned; peers refuse it and everything after | **09/23** |
| **H-21** | High | Per-author head bound judged per replica: a peer's split delivery of 257 parentless transactions leaves honest replicas with permanently different DAGs unless each authors | **09/23** |
| H-01 | High→Low | *Partially closed.* Loopback API key deferred; `OPTIONS` fingerprint documented | 09/01 |
| M-09 | Med | *Partially closed.* Remote-close admission order-dependent (T45) | 09/01 |
| M-10 | Med | *Interim only.* T45 Facet A | 09/01 |
| **M-46** | Med | T62 floor counts file-adopted lines as staged; live replacement + failed commit installs over acked records | **09/23** |
| **M-47** | Med | Half envelope is history at boot, operator input live: raw, unsigned, served, head | **09/23** |
| **M-48** | Med | Cardinality caps only at stage: 42× per valid body, 546 MB per 15 MiB frame | **09/23** |
| **M-49** | Med | Failed reload leaves `force_compaction` stale → append behind a torn tail → `Corrupt` → boot refusal with an acked record | **09/23** |
| **M-50** | Med | Upgrade over a pre-T65 22-digit amount: quarantined as text, children dangling, balances drop it, fresh replicas cannot sync past it | **09/23** |
| L-23 | Low | *Partially closed.* `meshId` still opt-in (next release) | 09/02 |
| L-64 | Low | *Partially closed.* No boot warning for a dense file whose canonical form exceeds the cap | 09/22-v2 |
| L-66 | Low | *Partially closed.* GraphiQL pinned; React dev builds, no SRI, third origin | 09/22-v2 |
| **L-67…L-79** | Low | Thirteen new Lows — see §4 | **09/23** |
| L-06 | Latent | `\|`-delimited signature message — injective at HEAD; length-prefix at T45 Facet B | 09/01 |

**Closed this audit (31):** H-12, H-13, H-14, H-15, H-16, H-17, H-18 · M-06, M-35, M-36, M-37, M-38, M-39,
M-40, M-41, M-42, M-43, M-44, M-45 · L-35, L-43, L-55, L-56, L-57, L-58, L-59, L-60, L-61, L-62, L-63, L-65.
**Residuals re-rated:** T63 fresh-join residual / R-10's ≥ 2^32 case → H-19; §5 `finish_recovery` stale flag →
M-49; T66 "6×" → M-48; T69 orphan-drain residual → L-70; T69 local-write reload → L-71; T70 unthrottled
`Err` → L-72; T64 "capped per author" → L-68.

---

## 8. Remediation backlog

Task numbering continues from T71. Effort: S = < ½ day, M = ~1–2 days. Every task keeps the campaign's rule:
revert the fix → the named test fails → restore; residuals go in the tracker.

### Tier 1 — ship-blockers

**☐ T72 — Rules on content, not on the replica (H-19, H-21, L-68, L-69) — M, plus a decision**
Change: (a) bound the lamport advance against the directive's causal predecessor (largest lamport among its
parents / the directives it must already hold), not the adopter's clock, so every replica gives the same
verdict and a fresh node always climbs; warn when `clock > 2 × directive_count`; correct the residual text and
the `LamportAdvance` message; (b) drop the remote `UnmergedHeadLimit` refusal (the truncation already closes
H-16) or replace it with a content-deterministic frontier cap; choose parents by author diversity; (c) cache
`LamportAdvance` keyed on `(peer, id, local clock)` and `UnmergedHeadLimit` until the count drops; rate-limit
the warn. **Decision:** a trusted-bootstrap join for meshes that already carry a jump. Files:
[service.rs:1132-1300, 3656, 5808-5825, 5869-6060](../../crates/ledger/src/service.rs#L1208),
[dag.rs:452](../../crates/ledger/src/dag.rs#L452), [anti_entropy_alpn.rs:1866-1940](../../crates/gl-node/src/anti_entropy_alpn.rs#L1866).
Verify: the `h1b` shape converges after allowlist removal; the `3b` disjoint-subset shape gives equal DAGs with
no local authoring; a dense history still converges in any order.

**☐ T73 — Boot verifies what it loads (H-20, M-47, L-74, L-75, L-76, L-77) — M**
Change: `set_verifier` mirroring `set_signer`; `verify_own_history()` before the startup compaction,
quarantining any directive whose signature does not verify (author id is the key, so foreign authors too);
the salvage demotes the parsed head of a split block with its tail and quarantines salvaged transactions
failing I1; fix the banner; `is_operator_input := !author || !lamport` (or quarantine exactly-one-of); strip a
hand-typed signature when stamping; require hand-spelled parents to resolve; `entry().or_insert` in the cycle
arm; re-index the finalized directive in the read model; `AccountAlreadyOpen` parity on the file paths;
README: never edit an existing record, append a reversal; deleted lines are re-supplied; the lamport-only
exception. Files: [service.rs:433-548, 2760-2880, 3036, 3145, 5129-5420, 5553](../../crates/ledger/src/service.rs#L433),
[main.rs:421-468](../../crates/gl-node/src/main.rs#L421), README §Editing. Verify: `p12`, `split-dedent2`, `p1`, `p3`,
`p9`, `p4`, `reopen` shapes; everything served passes `verify_remote_signature`.

**☐ T74 — Recovery floor and the reload-failure arm (M-46, M-49, Info) — S**
Change: keep file-adopted ids out of `pending_ids` (separate counter for the short-circuit; fixes the
`uncommitted_count` doc and the `discarded_staged` label) and/or refuse a rebuild missing any non-pending
memory id; in `finish_recovery`'s `Err` arm set `force_compaction = true` and carry `journal_torn_at_boot`;
also carry it on the refusing arm so a torn journal is renamed, not unlinked. Files:
[service.rs:4334-4420, 5364, 5407, 3062-3070](../../crates/ledger/src/service.rs#L4334). Verify: `floor (b)`/`(b3)`
refuse and the next commit writes the union; `torn` case B compacts and reboots with a sidecar.

**☐ T75 — Wire cardinality caps before staging (M-48, L-78) — S**
Change: `enforce_resource_limits` in `validate_supply_entry` right after the parse; parse-time limits in
`parse_file_bounded`; `MAX_CURRENCIES_PER_OPEN`; extend the `decode_memory.rs` 4× assertion to parsed shapes
and a 15-entry batch. Files: [union_merge.rs:169-230](../../crates/p2p/src/union_merge.rs#L169),
[parse.rs:589-707, 872-905, 1000-1030, 1322-1341](../../crates/ledger/src/parse.rs#L589), [service.rs:671-705](../../crates/ledger/src/service.rs#L671).

**☐ T76 — Upgrade path for over-cap history (M-50, Info) — M, plus the deferred decision**
**Decision:** exact `i128`-per-scale accumulation (the T65 design item) so history need not be quarantined and
the cap becomes an authoring rule; or, interim: `normalize()` the resolved leg before the cap, a pre-upgrade
scan tool, a release note, `verify` reporting quarantine ids and `over_cap_posting_count`, and a boot that
refuses loudly rather than serve a history a fresh replica cannot take. Files:
[validate.rs](../../crates/ledger/src/validate.rs), [read_model.rs](../../crates/ledger/src/read_model.rs),
[parse.rs:206](../../crates/ledger/src/parse.rs#L206), [service.rs:2628-2680, 2864](../../crates/ledger/src/service.rs#L2628).
Verify: the `pre_upgrade.bean` fixture keeps its descendants' parents resolvable on the upgraded node and a
fresh replica converges.

### Tier 2 — cost bounds and edges

**☐ T77 — Near-cap and edge cost bounds (L-70, L-71, L-72, L-73, Info) — S**
Change: re-check headroom after `drain_orphans` and arm the backoff on a cap-refused prepare; publish to
subscribers after durability; pre-stage headroom check in the three mutations; route the not-allowlisted arm
through `should_log_refusal` and return `Ok`, `iroh::protocol=error` in the default filter; `FileTrust::OperatorConfig`
plus a 1 MiB cap for the config; key both log throttles by source and print `suppressed` on expiry; use
`record_bytes(pending_block)` for the headroom estimate. Files: [anti_entropy_alpn.rs:439-471, 1655-1830](../../crates/gl-node/src/anti_entropy_alpn.rs#L1655),
[mutation.rs](../../crates/gl-node/src/graphql/mutation.rs), [config.rs:949](../../crates/gl-node/src/config.rs#L949),
[request_guard.rs:66-110](../../crates/gl-node/src/request_guard.rs#L66), [connection_limiter.rs:301-316](../../crates/gl-node/src/connection_limiter.rs#L301).

**☐ T78 — Small hygiene (L-67, L-79, Info) — S**
Derive the `EndpointId` before `LedgerService::boot`; `verify` against the exact partials and state the
read-time precision; narrow the M-44 doc claim to zero-filling filesystems or widen the torn rule for a
hash-failing final record; document the `<name>.tmp.<pid>.<nonce>` reservation and tighten the sweep's
match; `symlink_metadata` for the journal-presence probe; fix the "rolled back" log text; add the CHANGELOG
omissions (L-60, `Refusal` API, journal 0600 rule, GraphiQL third origin), the README upgrade note and
CHANGELOG link, and the clippy line; pin React 18.3.1 with SRI via a post-processing pass over the GraphiQL
page or self-host.

### Finding → task coverage map

H-19→T72 · H-20→T73 · H-21→T72 · M-46→T74 · M-47→T73 · M-48→T75 · M-49→T74 · M-50→T76 · L-67→T78 · L-68→T72 ·
L-69→T72 · L-70→T77 · L-71→T77 · L-72→T77 · L-73→T77 · L-74→T73 · L-75→T73 · L-76→T73 · L-77→T73 · L-78→T75 ·
L-79→T78 · L-64→T78 · L-66→T78 · L-23→next release · H-01/M-09/M-10/L-06→deferred/T45.

**Decisions this audit puts to the user:** the ratchet's reference point (causal predecessor vs adopter clock)
and a trusted-bootstrap join (H-19); whether to keep any remote frontier cap at all (H-21); H-20's rating and
whether boot quarantines or refuses an unverifiable own record; M-50's route (exact accumulation now vs
interim tooling) and its rating for the intended deployments; M-48's rating against the 4× bar.

**Recommended order:** T72 and T73 first (both are mesh-divergence Highs; T73 shares `service.rs` with T74, so
run T74 after it), then T75 and T76 in parallel (disjoint files), then T77, T78. T45 waves A+B should
additionally wait for T72 and T73, since both touch the envelope rules Format v2 re-specifies.

---

## 9. Checked and found sound (new this audit)

Beyond the 31 closures in §1.1, these were probed adversarially and held:

- **Commit choreography, new async shape.** `prepare_or_recover_with_reload` drops the guard, spawns
  `recover_off_lock` on a task that owns the permit and awaits only the `JoinHandle`, which detaches on drop
  (vendored tokio `task/join.rs:357-365`). Executed cancellation matrix: cancel at the permit or the write
  lock → nothing held, nothing staged; cancel at `recovery.await` or at `commit.await` with a parked reload →
  the task keeps the permit, the `RwLock` is free, the staged batch stays visible until the install, the next
  writer waits. **Lost update impossible:** a writer arriving during a detached reload waits for it and its
  directive is in memory and on disk afterwards. `Parse`/`CommitInFlight` return without spawning and leave
  the batch staged (documented). Shutdown, precisely: SIGTERM → HTTP drain ≤ 10 s (request futures dropped;
  their tasks keep the permit) → watcher abort → `compact` waits unbounded on the gate → `Runtime::drop` drops
  async tasks → `BlockingPool::drop` joins every blocking thread (`pool.rs:244-285`); no `shutdown_timeout`
  anywhere; measured 3.2 s / 1.5 s waits with the load and commit completing. The watcher's
  `reconcile_file_staged` and the shutdown compaction wait on the permit, never skip. Reads wait ≤ 15.5 µs
  during a reload. The T62 floor versus a planted cycle (H-14's shape through the guard) is sound: the smaller
  rebuild is refused, memory kept, the next compaction writes memory plus the operator's new line.
- **Boot adoption × journal × crash.** A crash between `finalize_operator_input` and the compaction re-derives
  a byte-identical envelope on the next boot (same lamport, same parents; the signer is deterministic) and a
  peer dedupes. A reload with outstanding operator input passes the floor exactly, re-derives the set from the
  raw file and re-finalises with the carried signer. `finalize_operator_input` is idempotent across a double
  call, a reload, and a changed signer or author. Operator input is stamped `clock + 1` after the whole
  history, and a remote directive staged between boot and finalize changes neither its lamport nor its
  parents. A raw duplicate of a signed history record collapses to the signed copy (except in the cycle arm,
  L-76). The ceiling residual is a documented fixed point with the H-12 warning. Journal payloads never carry
  envelope-less directives on any gl-node path. `main.rs` ordering closes the watcher-vs-finalize race
  (`boot_p2p` binds and joins gossip only; no router or ledger access before the compaction); `--health-check`
  boots no ledger.
- **Recovery and journal.** `rm`/`mv` of the `.bean` on the small path, on the append path with a journal, and
  by the watcher: the next write recreates it with every directive and folds the journal. The `brick` fixture
  boots. Crash matrix for every step of Compact (temp → write+fchmod+fsync → rename → dir fsync → retire
  rename or unlink → dir fsync → receipt) and Append (checked open → write_all → fsync → dir fsync → receipt):
  no acked directive lost or duplicated and boot succeeds, except the ext4-writeback shape (§5). `remove_journal`
  or `retire` failure after a landed rename is error-but-durable, no duplication, recovers once unlinkable.
  Torn classification: NUL in a non-final payload or header → `Corrupt`; a fake `\n;;olj ` in a torn tail →
  `Corrupt` (false positive, needs journal write access); the last acked record with one byte → NUL is torn,
  exactly one directive dropped, logged with `dropped_bytes`, bytes kept in the sidecar. Sidecar `-N`
  collision picks the next free name; boot ignores all sidecars; the sweep never touches them. On-disk worst
  case after a rename crash ≤ MAX + MAX/3 ≈ 85 MiB; hard ceiling 128 MiB read, ≈ 4× the cap in memory.
  `adopt_reloaded` keeps `canonical_is_current` only on a hash match.
- **Lamport and heads.** Every bound site goes through one predicate; refusals (ceiling, ratchet, head bound)
  move neither the clock nor the DAG on remote and file paths; author spoofing is impossible (allowlisted
  `EndpointId` plus signature, [union_merge.rs:504-520](../../crates/p2p/src/union_merge.rs#L504-L520)); hand-typed
  > 256 parents are refused on the file path; ratchet convergence is delivery-order-independent on a dense
  history; the orphan buffer has a 1 h TTL, a full budget defers rather than evicts honest entries, one hostile
  peer is capped at 1,000 entries / 16 MiB and four are needed to fill the 64 MiB global; a 60 MiB catch-up is
  ~4–8k frames, far inside one 300 s session, and progress is monotone across sessions (per-batch commit,
  Want recomputed from membership, no rollback); a near-cap node keeps *serving* while its pulls are backed
  off; the outbound FIFO deviation admits one task per peer with the healthy peer delayed at most one session
  deadline.
- **Balances.** The cap is on every ingress including journal replay; `±(10²¹ − 1)` admitted and
  `±Decimal::MAX` refused; 7 on every view, after reboot, on a reverse-arrival replica. The bignum oracle
  (8,000 cases) confirms exactness whenever the sum fits at the finest scale, and order independence
  everywhere. No `saturating_*` on the validated path. CT-9 byte-identical. `1000 + 1e-28 + 1e-14`,
  `1234567.12345678 + 8e20 − 8e20` and a `10²¹ − (10²¹ − 0.1) + 1e-28` cancellation all agree across
  `account()`, `account(at)`, `build`, reversed, batched and `trial_balance`.
- **Wire.** Cheap-first order proven by allocation (a 1 MiB body under a bad id costs one allocation); the
  one-block count gate is unfoolable (600k-body fuzz, 0 disagreements) and honest nodes never emit multi-block
  entries; `BoundedSink`/`excerpt` are char-safe on combining sequences and 4-byte chars; no parser recursion;
  `max_buf_size` caps neither bodies nor responses; gossip echoes are bounded inside 4,096-byte frames;
  pushed-frame no-cache is not a bypass (same per-byte cost as honest frames); `RefusalCache::record` dedups
  and refuses non-ids; the guard throttle holds against a 1,000-request flood with one line.
- **Files.** `open_checked` on every ledger-side open; a rename-storm TOCTOU race across all three trust
  levels gives zero violations; `.lock` and journal have been created 0600 since their first commits so the
  mode check cannot brick an upgrade; the sweep runs under the process lock and removes only same-uid temps;
  a hard link or 0644 `.bean` boots by policy; a root-owned readable journal is refused naming both uids.
- **Server and config.** The bucket key is the QUIC-authenticated `EndpointId` (vendored iroh
  `connection.rs:1127` ← `peer_identity()`); check order allowlist → global → per-peer → bucket, and `Global`/
  `PerPeer` refusals spend nothing; the honest pooled dial pattern is ≤ 1 dial per code-5 close (≥ 30 s at the
  floor) against burst 8 / refill 2 s, and the ceiling values still admit one dial per 30 s; GCRA arithmetic
  cannot overflow at the ceilings (`saturating_mul`, `Instant + Duration`); the `meshId` warning fires on every
  signing boot (signing is forced by `p2p.enabled`); nested removed keys fail closed through
  `deny_unknown_fields`; the `maxConnectionsPerIp` clamp is applied at serve time; `headerReadTimeout` is armed
  with a timer.
- **Docs.** The README's `OPTIONS`/`Allow`, `Origin` equivalence, commit-journal and `verify.truncated`
  sections match the code; the docker config's `meshId` equals its `swarmTopic`; the L-56 redaction never echoes
  the value (hand-written `Debug` on `P2pConfig`/`AuthConfig`, no `{:?}` of the config in `main.rs`).

---

*Previous audits: [SECURITY_AUDIT_0922-v2.md](SECURITY_AUDIT_0922-v2.md) · [SECURITY_AUDIT_0922.md](SECURITY_AUDIT_0922.md) · [SECURITY_AUDIT_0902.md](SECURITY_AUDIT_0902.md) · [SECURITY_AUDIT_0901.md](SECURITY_AUDIT_0901.md) · [docs/audits/CLAUDE_SECURITY_AUDIT_0820.md](CLAUDE_SECURITY_AUDIT_0820.md). Remediation trackers: [docs/audits/OUTSTANDING_TASKS_09_22_v2.md](OUTSTANDING_TASKS_09_22_v2.md) (T61–T71) · [docs/audits/OUTSTANDING_TASKS_09_22.md](OUTSTANDING_TASKS_09_22.md) (T46–T60, R-1…R-21) · [docs/audits/OUTSTANDING_TASKS_09.md](OUTSTANDING_TASKS_09.md) (T18–T45) · [docs/audits/OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md) (T1–T17). Format v2 design: [docs/FORMAT_V2_DESIGN.md](../FORMAT_V2_DESIGN.md). Proof crates for every finding live in this session's scratchpad (`D1-filepath` … `X3-commit-recovery`); each report's §6 gives the re-run command.*
