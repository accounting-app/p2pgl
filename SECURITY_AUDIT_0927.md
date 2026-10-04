# Security Audit — openledger-v2 (0927: re-audit of T90–T97)

**Date:** 2026-09-27 · **Baseline:** HEAD `a5313a1` (branch `main`, clean tree) · **Previous:** [SECURITY_AUDIT_0926.md](SECURITY_AUDIT_0926.md) (HEAD `8c0a87e`)

**Closing verification:** 2026-10-05 at HEAD `ef584ee` — the fixes T98–T103 re-checked against this report; see [§10](#10-closing-verification-2026-10-05).

Scope: re-verification of **every** claim, revert-proof, existing-test change, behaviour change, design deviation and
residual in the T90–T97 "Done" notes of [docs/OUTSTANDING_TASKS_09_26.md](docs/OUTSTANDING_TASKS_09_26.md) against
source at HEAD, plus fresh hunts over the ~3,600 lines T90–T97 added or changed (18 files, six commits after the 0926
audit commit `d77fcf2`: T90 `e3efd6f`, T91 `a04f844`, T92 `ceec19e`, T93 `ac84d82`, T94–T96 `397d749`, T97 `a5313a1`),
treated as unreviewed code. Priority went to:
- the two semantic changes to what the mesh agrees on — T90's closure keyed on parenthood with a duplicate-copy
  preference at boot, and T91's lifecycle rules (the union of currencies, a `close` refused only if it closes a held
  transaction's date);
- the new machinery T92 and T93 added to the boot and recovery paths: the rule's fixpoint, the revised decision (42),
  committed-only parents, and the three `served_*` views;
- the first new production `unsafe` of the series (T94);
- T95's second Want filter and advert cache;
- every remedy text T90–T96 reworded, **followed literally as the remedy an operator will apply**.

Method as established for the series: ten parallel passes.
- **Six per task group**, each re-verifying then hunting: A1 T90, A2 T91 + T97, A3 T92, A4 T93, A5 T94, A6 T95 + T96.
  Four of them own one invariant test file each.
- **Three cross-cutting interaction hunters** with named compositions: X1 the boot pipeline, X2 replication and the
  mixed-version mesh, X3 commit/recovery/file.
- **One documentation, configuration and supply-chain pass** (D1), which executed the CHANGELOG on the real binary.

Each pass was read-only on the repo apart from its owned test file, with its own scratch crates and target directory
and a `git archive HEAD` copy for revert-proofs. Every mechanism a pass reported was re-read in source and **every
executable proof below was re-run by the orchestrator**. The quoted outputs are the re-runs; where a figure differs
from the pass's, the re-run's is given.

Test suite at HEAD before the audit, quiet machine: **1,437 passed, 0 failed, 3 ignored** (425 + 8 + 610 + 37 + 10 +
195 + 58 + 37 + 8 + 23 + 5 + 21), matching T97's Done note.

**Loopback QUIC for fresh binaries works today**, contrary to the expectation this audit started with (0926 §5).
- D1's fresh `cargo build` of the archive into a scratch target passed the control
  `happy_path_small_limits_converges` (5.21 s), and the orchestrator re-ran it from the same binary at 20:01 (ok,
  0.27 s).
- A6 and X2 then ran their real-QUIC proofs and revert-proofs in scratch archive copies, with the control passing in
  the same binary.
- One real-QUIC proof (A6, before the update) was run in the repo tree by the back-up / apply / restore / `cmp`
  procedure; the restored file compared identical and `git status` was re-checked.

The repository was modified in exactly six files: this report, the new tracker, and the four invariant test files (§6).

---

## Executive summary

**T90–T97 closed what they set out to close.** All 33 register entries the 0926 backlog assigned are closed by
mechanism (H-24 · M-63 … M-70 · L-114 … L-136), and the M-09 remainder is closed for the shape 0926 executed. Every
regression test the Done notes name is green, and every revert-proof a pass repeated (54 across the ten passes) failed
the named test. Several claims were re-measured and held:
- **H-24** — X2's `c1f`/`c1e`/`c1d` converge across restarts; with the own-id refusal restored in an archive they are
  refused for good again.
- **T93** — X3's Fresh-boot vs L-13-reload differential, now 52 shapes with the served view and served heads compared,
  agrees in 50 of 52; no reload re-issues an `(author, lamport)` pair (26 of 27 did at 0926).
- **M-68** — A4's `raceswap` returns the victim 0 times (152–276 per 5 s at 0926).
- **M-66** — the equivocating-author attack over real QUIC is closed (C and D adopted).
- **M-70** — the 150,000-transaction boot is linear in lifecycle records on the real binary.
- **Supply chain** — every remedy text T90–T96 changed works on the real binary when followed on one node;
  `cargo audit` is clean; the lockfile is unchanged; the CI pin is on `master`; clippy and fmt pass.

**But the through-line has moved again, and the High is T91's.** 0926 found the rule and its neighbours "judging a
snapshot where the property is a history". T90–T97 answered by re-keying each check on the history. What 0927 finds is
that **each new verdict is still taken at a moment, against the state that moment happens to hold — and the new
machinery that makes those verdicts (a cache, a preference, a floor, a view, a fixpoint) is itself replica-local or
process-local**:

- **H-25** — T91's `close` rule judges the interval the `close` would close against the lifecycle events **held at
  arrival**.
  - A `close` staged before its own re-open sees an unbounded interval and is refused.
  - `open`/`close` records name no parents, so `compute_want` asks for them in content-id order: the refusal happens in
    10 of 27 honest cases.
  - gl-node still classifies the refusal as permanent, with a comment that says it "can never become acceptable" —
    true before T91, false since.
  - A receipt the returning replica writes in that window makes the split permanent, and every later write of that
    replica is buffered mesh-wide forever.
  - T91's own acceptance test fails at seed 42 of a wider sweep.
  - Found independently by **A2** and **X2**; fix-proven by X2.
- **The M-09 remainder stays open and High.** T91 recorded it as "a genuine conflict of two concurrent writes". A2 and
  X2 executed it from **one allowlisted peer** (a `close` plus one posting inside its interval, delivered in opposite
  orders) and from an **honest partition** (one operator closes while another, offline, posts). Two honest replicas
  then hold different DAGs and balances for good, and a fresh replica's state depends on which peer it meets first.
  Its fix is decision (54).
- **Six Mediums.**
  - M-71: T94's `(dev, ino)` check accepts a hard link in the attacker's directory after an ancestor swap.
  - M-72: T90's duplicate-copy preference is taken before the closure, the signature pass and the rule, so after a
    crash a re-entered chain or a re-entered signature-held record is held and its only valid copy deleted. This is
    H-24's shape 2 through two new doors.
  - M-73: the "restate the chain" remedy is printed on every node and, followed on two, counts the record twice
    mesh-wide.
  - M-74: T93's pre-stage cap gate trusts a stale over-cap fact and the append headroom while a rewrite is pending, so
    every mutation and every peer batch pays a full reload (M-58/M-65's symptom).
  - M-75: a `close` judged against what this node serves lets through a close every peer refuses, and the printed
    remedy then partitions the node for good.
  - M-76: another peer's buffered copy still decides the buffer slot and the Want order, so an equivocating peer slows
    catch-up to one record per exchange over real QUIC.
- **Twenty-one Lows** (§4). The widest:
  - the rule's fixpoint recurses once per round with a full rebuild, so a crafted file boots quadratically and aborts
    gl-node's recovery reload by stack overflow (L-146);
  - the L-117 refusal and the other REFUSING arms keep the write whose call failed (L-147);
  - T93's clock floor is lost at a restart (L-148);
  - L-131 is fixed only for records the closure holds (L-143);
  - the gl-node sweep beside the link can delete the link's own target (L-139).

As in 0925 and 0926, **the remedies the code prints create the shapes it then refuses**:
- "restate the chain", printed on every node, double-counts (M-73);
- "restore the original line" after a local `close` partitions the node (M-75);
- "add the missing open" typed as the account's own `open` is dropped at boot (L-143);
- the L-117 text's "stop the node" is followed by a compaction that replaces the operator's link (L-147).

The backlog (§8) is organised around:
- making every lifecycle verdict a function of the directive set (T98);
- boot choosing between copies after it has judged them, in one iteration (T99);
- the commit gate and every refusing arm measuring and keeping only what the commit wrote (T100);
- the symlink guard binding the returned path, not only the file (T101);
- the orphan buffer keyed per delivering peer (T102);
- the remedy texts (T103).

---

## Threat model

Unchanged from [09/22](SECURITY_AUDIT_0922.md) through [09/26](SECURITY_AUDIT_0926.md):
- (a) a web page in an operator's browser;
- (b) an API-key holder;
- (c) a **malicious or compromised allowlisted peer**, which may equivocate (two envelopes of one body);
- (d) a network attacker on a public bind;
- (e) whoever can write the `.bean` or its directory, or an ancestor of the link's directory (0926);
- plus the no-attacker cases: an operator following the README, an editor autosave, a backup `cp`/`mv`, a crash, an
  upgrade over an old file, a long-offline or freshly restored replica, a mixed-version mesh, and the operator
  following a remedy the code prescribes.

This audit exercised four cases the new code made reachable:
- **a replica returning online** after its peers closed and re-opened an account (T91's order);
- **two operators** each following a remedy printed on their own node (M-73);
- **a disk or directory that fails a commit** followed by the operator's natural reaction (fix it, restart) (L-148);
- **a mixed mesh of HEAD beside `8c0a87e`** during a rolling upgrade. The old build refuses more; everything re-judges
  after the upgrade unless a write lands in the mixed window (X2 `xver`).

---

## 1. Status of the 09/26 register, re-verified at HEAD `a5313a1`

Every entry is re-verified by mechanism in source and by the named regression test. "Revert-proof" means a pass
reverted the mechanism in a `git archive` copy (or, for one real-QUIC case, in the repo tree with restore and `cmp`)
and the named test failed.

### 1.1 Closed — verified by mechanism (33, plus the M-09 remainder's executed shape)

| ID | Task | Mechanism at HEAD | Pinned by | Revert-proof |
|---|---|---|---|---|
| H-24 | T90 | `names_a_held_back_parent` ([service.rs:5535](crates/ledger/src/service.rs#L5535)) on the wire (`:9354-9376`) and live (`:8237-8262`); pruning on adopt (`:9555-9558`, `:8550`, `:8649`); `prefer_copies_whose_parents_are_served` (`:5477`, called `:4126`) | `h24_*` ×3, `a2_a_restated_chain…`, `a2_a_record_reentered…`, X2 `c1f`/`c1e`/`c1d` | yes (A1 R1–R3, R5, R6; X2 own-id revert → `c1f` REFUSED-for-good) — **the preference is judged before the closure, the pass and the rule (M-72)** |
| L-126 | T90 | `hold_refused_file_entry` (`:5550`) in the parity (`:8191`), limits (`:8418`), validation (`:8570`), resolved-body-cap (`:8466`) and held-parent (`:8247`) arms | `l126_*`, `a2_the_live_reconcile_keeps…`, A1 `a1_0927_a_pasted_child…` | yes (A1 R4a–c, R4e); the resolved-body-cap arm is unpinned (R4d) — **the lamport arms are outside the list (L-140); a held own record's lamport is not counted (L-141)** |
| M-63 | T91 | union in `currencies_at` / `check_currency_constraint_at` ([accounts.rs:374-401, 468](crates/ledger/src/accounts.rs#L374)) | `a1_0926_1_…`, `a2_a_peer_open_never…`, A2's two new property tests vs an independent oracle | yes (A2 R1); A1 `a1p0926 i9` re-run: N serves T1–T4 after its restart, F keeps W |
| M-09 remainder (0926 X1 `n3e`) | T91 | `dates_a_close_would_close` ([accounts.rs:490-514](crates/ledger/src/accounts.rs#L490)) in `reject_backdated_close` ([service.rs:8860](crates/ledger/src/service.rs#L8860)) | `m09_a_close…`, gl-node `lifecycle_converges_when…` | yes (A2 R2) — **closed for `n3e`'s order only: a `close` staged before its re-open is refused and cached permanent (H-25); the concurrent shape stays open (§3)** |
| M-64 | T92 | fixpoint `ids.len() + self.quarantine_unservable_history()` ([:4832](crates/ledger/src/service.rs#L4832)); ceiling arm runs the rule (`:4566-4572`) | `m64_…`, `a1_0926_2_…`, A3 `a3_0927_the_rule_holds_an_alternating_chain…` | yes (A3 R1, R1b; X1 R-a) — **recursive, one full rebuild per round (L-146)** |
| M-69 | T92 | `SIGNATURE_QUARANTINE_BANNER` ([main.rs:90-97](crates/gl-node/src/main.rs#L90)) | `m69_…`; D1 `c_banner` three shapes on the binary (Cash 3, 0 held, fixed point); X1 `m6a`/`m6b` (Cash 88.00, peer 6/6) | Done note R7 |
| L-114 | T92 | `signed_by_finalize` (`:4615`, `:4888`) | `a6_2_…`; X1 `n5` 1 WARN; D1 `c_every` 1 WARN; X3 `domain+handopen` SAME | yes (A3 R2) |
| L-121, L-125 | T92 | L-77 at finalize via `is_open_excluding` (`:4490-4530`, [accounts.rs:527](crates/ledger/src/accounts.rs#L527)); live L-110 clause removed | `l121_…`, `l77_…`, `a1_0926_3_…`, `a2_the_l110_remedy…`, A3 `a3_0927_a_hand_open_then_the_original…` | yes (A3 R3, R3b; X1 R-c) — **a typed `open` with the held record's own id is dropped at boot (L-143)** |
| L-128, L-129 | T92 | `hand_parented_last` Kahn over `stored_content_id` (`:9673-9740`) | `a6_3_…`, `l108_a_hand_chain…`; A3 `a6cost 20000`: reverse 1.11× forward | yes (A3 R5) |
| L-131 | T92 | pass skips pending operator input (`:4856-4866`) | `l131_…`, X1 `m4c` | yes (A3 R6, X1 R-b) — **only for a closure-held record (L-143); not a fixed point there (L-144); a typed copy finalize refuses is dropped (L-145)** |
| M-65 | T93 | `choose_committed_parents` ([:6146](crates/ledger/src/service.rs#L6146), `:8398`, `:8449`); gl-node headroom 0 ([ledger_commit.rs:565](crates/gl-node/src/ledger_commit.rs#L565)) | `a3_1_…` ×2, `a3_m59_…`; A3's 0926 gl probe: mutations 1–2 refused in ~1 ms, running == restart | yes (A4 R1, X3 `X3_RE`) — **the gate trusts a stale fact while a rewrite is pending (M-74)** |
| L-115 | T93 | `discarded_own_high` (`:7189-7213`) | `l115_…`; X3 `diff=all` 0 of 52 reload re-issues | yes (X3 `X3_RA`); the re-application after `verify_own_history` (`:7213`) is unpinned (A4 R3b) — **lost at a restart (L-148)** |
| L-116 | T93 | `served_directive` / `served_head_txids` / `served_sorted_directive_ids` (`:8959-9029`); gl-node `:1572`, `:1611` | gl-node `l116_…`, ledger `l116_the_served…`, X3 `k14` (1 envelope) | yes (X3 `X3_RD`) — **the signed child of a withheld line is advertised (L-154)** |
| L-117 | T93 | `BootMode::Reload` refuses a link (`:3319-3334`) | `l117_…`; D1 `c_l117` on the binary | yes (A4 R5, X3 `X3_RB`) — **the refusal keeps the failed write (L-147)** |
| L-122 | T93 | `has_later_intact_record` in the over-claim arm ([journal.rs:658-662](crates/ledger/src/journal.rs#L658)) | `l122_…`; D1 `c_l122` k = 1, 3, 5 corrupt on the binary; X3 `k17` 407 prefixes, 0 false positives | yes (A4 R6, X3 `X3_RC`) |
| L-124 | T93 | exemption removed (`:7256`), texts corrected | `m46_*`, `l104_*` | — (dead code; no outcome to revert) |
| M-68 | T94 | `resolve_link_in_its_directory` ([journal.rs:247-341](crates/ledger/src/journal.rs#L247)): one handle, `fstat`, `fstatat`, `readlinkat`, `openat(O_NOFOLLOW)`, `(dev, ino)` compare | `m68_…`; A4 `raceswap` VICTIM=0 | yes (A5 R1) — **a hard link in the attacker's directory passes the identity compare (M-71); the test counts only the victim path (L-157)** |
| L-118 | T94 | `claim_ledger_path` sweeps beside the link ([main.rs:72-79](crates/gl-node/src/main.rs#L72)) | gl-node `l118_…`; D1 `c_sweep` on the binary | yes (A5 R4) — **can delete the link's own target (L-139)** |
| L-119 | T94 | identity compare replaces the string compare | `l119_…`; A4 `hops`: case and NFD variants resolve | probe (T87's compare no longer exists to restore) |
| L-120 | T94 | macOS `acl_get_fd_np` + `acl_get_entry` (`:421-447`) | `l120_…`; X3 `k11`, D1 `chmod +a` refused, `chmod -N` fixes | yes (A5 R3) — **refuses every ACL entry, including macOS's default on `~` (L-137)** |
| M-66, L-133 | T95 | `retain_not_doomed(peer, …, holds)` judges only the asked peer's copies ([orphan_buffer.rs:362-372](crates/p2p/src/orphan_buffer.rs#L362), `:406`) | `m66_…`, `l133_…`; **real QUIC**: attacked `C adopted true, D adopted true` (0926: false) | yes (A6 R1 over real QUIC in a scratch archive with the control green; R2) — **the buffer slot and the Want order still read any peer's copy (M-76)** |
| M-67 | T95 | one memoised pass | `m67_…`; `a5_7` child-first 13 ms (0926: 9.8 s) | yes (A6 R3: 62.6 s) — **`m67_`'s debug 2 s bound flakes under load (L-157)** |
| L-130 | T95 | `retain_not_buffered_from` (`:458-527`) | `l130_…`; X2 `c3` 0 validated per tick | yes (A6 R4) — **no `holds` term (L-151)** |
| L-132 | T95 | limiter note and CHANGELOG; `decode_memory` 224 MiB absolute pin | `decode_memory` 8/8; X2 `c5` 1.87 MiB per directive | — (a pin on a measured bound) |
| L-134 | T95 | `hint_order` `VecDeque` (`:275`, `:586-603`) | `l134_…`; `a5_6` 1.3 µs per expiry | yes (A6 R5) — **the compaction drops the hint it just pushed (L-150)** |
| L-127 | T96 | `lamport_gap_verdict(gap, without_named)`, strict `> 2^32` ([service.rs:1463-1482](crates/ledger/src/service.rs#L1463)) | `a6_1_…`, `a6_4_…`; D1 `c_gap96` on the binary | yes (A6 V1, V2) |
| L-123 | T96 | `dtolnay/rust-toolchain@02cb101` | `git ls-remote`: `HEAD`, `refs/heads/master`, `refs/tags/v1` | — |
| L-135 | T96 | check 7 in `Checks::ALL`; `WITHOUT_FRESH_PEER`; the edited-record bound; the global always-interested subscriber | every sweep runs check 7; A6: the subscriber masks nothing | Done note R3–R6 |
| L-136 | T96 | texts | D1: README §Verify's query returns the documented fields; "by itself" gone | — |
| M-70 | T97 | `CurrencyIndex` ([accounts.rs:139-186](crates/ledger/src/accounts.rs#L139)) | `m70_*` ×2; A2's properties; D1 `c_m70` on the binary: 10,000 pairs 60.5 s vs 26.2 s debug, linear in records | yes (A2 R7, R8, R9) |

### 1.2 Unchanged by decision (4) and re-opened (1)

- **Unchanged by decision:** H-01 (loopback API key), M-10, L-06 (T45 Format v2), L-23 (`meshId` required next
  release).
- **Re-opened: the M-09 remainder.** Decision (38) of 0926 re-rated it High and T91 fixed the executed order. The
  concurrent shape T91 kept as a residual is executed at 0927 from one allowlisted peer and from an honest partition
  (§3). It stays **High, open**, for decision (54).

### 1.3 Done-note residuals, existing-test changes and unrequested design — dispositions at HEAD

**T90**
- **"Two copies that both resolve keep the first, as before"** is understated. The kept copy can be one the signature
  pass then holds, which gives H-24's crash outcome (M-72, A1-2 and X1-2).
- **"Operator input the live path refuses is still dropped"** is accurate (X3 `live close-in-interval`).
- **The L-126 residual list** omits the lamport arms (L-140), and the resolved-body-cap hold is unpinned.
- **The existing-test change `(0,1)→(0,2)`** is not weakened: `new_directives == 0` still pins the refusal (A1).
- **README "peers that hold the old copies adopt the restated ones"** is right for one node. It is wrong for a
  T85–T89 peer until that peer is upgraded (X2 and A1 `xver`), and wrong when printed on every node (M-73).

**T91**
- **"The verdict on the `close` does not depend on whether the re-`open` … arrived first"**
  ([service.rs:8846-8848](crates/ledger/src/service.rs#L8846), CHANGELOG:195, README:136) is **wrong** in one order
  (H-25).
- **The gl-node acceptance test `lifecycle_converges_when_the_account_is_posted_to_after_a_reopen`** is a proxy. Its
  03-15 posting names the 06-01 Bank transaction, so it is usually buffered until after the `close`. With seeds
  `1..=400` it fails at `reopen-seed-42` "accepted directive set diverged" (X2, restored afterwards).
- **The interval bounds were unpinned.** Next-`open` inclusive (A2 R5) and next-`close` exclusive (A2 R6) passed every
  existing test; A2's new property test pins both.
- **"A genuine conflict of two concurrent writes"** is **understated** (§3). Neither concurrency nor two authors is
  needed.
- **"A `close` dated before the `open` is stored … as inert data"** is understated. An earlier `open` arriving later
  makes it live, and four delivery orders give two different held sets (A2 `p3`).
- **"Mixed versions … (README's 'upgrade every node' note)"** cites a note that gives only the T75–T80 reason (L-155).
- **The six existing tests changed** (the "poison" `close` moved to 2024-01-10) are not weakened (A2).
- **The `posting_dates` doc** at [read_model.rs:531-535](crates/ledger/src/read_model.rs#L531) ("nothing is ever
  removed") is stale (Info).

**T92**
- **"Each round takes at least one record out of the DAG, so this ends"** is true, but it is silent on cost and depth
  (L-146).
- **"A block retyped beside a held record … is adopted"** is overstated three ways:
  - only records the closure holds (L-143);
  - even there it is not a fixed point (L-144);
  - a copy finalize refuses is deleted under a WARN that says it is kept (L-145).
- **The comment at `:4849` "or its envelope edited"** describes a shape that never reaches the pass.
- **"A hand `open` of an account whose own `open` is held is adopted at boot"** is true only for a different id
  (L-143).
- **Decision (41)'s residual** is correctly stated. Releasing the clock at the boot after the wrong-domain write cannot
  re-issue a pair, because W carries the top lamport (A3).
- **Decision (42)'s "two `open`s after the original returns; no verdict changes"** is correct (A3's new test, on Food
  and on Travel).
- **The five existing tests changed** are not weakened (A3).

**T93**
- **"The M-59 check is reached by no known shape"** is accurate (X3 `k18`, A4).
- **(44) "the reload never lowers the clock below a discarded write's lamport"** is exact for the reload, but a
  restart drops the floor (L-148, 52 of 52 shapes).
- **The re-application of the floor after `verify_own_history`** is load-bearing and unpinned. A4's proposed
  `a4_l115b_…` passes at HEAD and fails with `:7213` removed.
- **"At the size cap every mutation is refused before staging, however many writes are pending"** (CHANGELOG:193)
  holds only while `canonical_over_cap` is current (M-74).
- **"After the L-117 refusal the next compaction renames onto the path (L-44)"** is understated. That compaction also
  writes the failed call's write, and the operator's moved file lacks it (L-147).
- **(45a) "lines adopted from the file are not served until a compaction succeeds"** is understated. Their signed
  children are advertised and supplied (L-154, X1 `m9`).
- **The three existing-test changes and the gl-node fixture change** are accepted (A4).

**T94**
- **Decision (46) "race-free for every ancestor, refuses nothing new"** is wrong on both halves:
  - it is not race-free (M-71);
  - a 0300 link directory now fails with `EACCES` (Info), and a FIFO at the directory's path now hangs boot (L-138).
- **"The path is still used by path afterwards"** is understated. M-71 gives an ancestor-of-the-LINK writer the same
  end state, and README:1097 says the swap "cannot redirect the node".
- **"Four unsafe blocks"** is accurate, and every SAFETY note is true (A5's FFI review: `stat` layouts, `readlinkat`
  bounds, `O_CLOEXEC`, `acl_free` once). The in-code count at journal.rs:1310 still says "one" (L-156).
- **"The ACL check is macOS only"** is accurate for local ACLs, but the check refuses far more than it needs to
  (L-137).

**T95**
- **The deviation "the filters run under the buffer's read lock"** is understated: they also hold `ledger.read`,
  ≈4.7× T88's per-id cost (L-152).
- **The served-id cache is sound.** The DAG only grows between `rebuild_dag` resets, and the held-back count in the
  key is redundant. But `l116_the_served…` pins sharing, not invalidation (A6 R7 passes it); A6's new
  `a6_0927_1_…` closes that.
- **"A copy with bad parents buffered first holds the id until its TTL"** is understated: M-76.

**T96**
- **"Calls a gap of exactly 2^32 crossable"** holds for the single-gap measure only. With the node's own records above
  the jump, `without_named > 2^32` prescribes the bootstrap join (Info; the verdict is right, the CHANGELOG wording
  misleads).
- **`Checks::ALL` / `WITHOUT_FRESH_PEER`** do not weaken any existing case.

**T97**
- **The +0.25 s residual** could not be re-measured under this audit's load (load average 40–130). No quadratic signal
  remains on the binary (D1) or in A2's 300-pair, 301-currency case.

---

## 2. New findings — High

### H-25 — T91's `close` verdict is taken against the lifecycle events held at arrival: a `close` staged before its own re-open sees an unbounded interval and is refused, gl-node caches the refusal as permanent, and a receipt written in that window splits honest replicas for good

Found independently by **A2** (A2-2) and **X2** (X2-1). **EXECUTED** through gl-node's real phase 2
(`apply_supply_entries`) with the Want the head exchange builds. **Fix-proven** (X2).

**Mechanism.**
- `reject_backdated_close` ([service.rs:8860](crates/ledger/src/service.rs#L8860)) refuses a `close` when a held
  posting falls in `dates_a_close_would_close` ([accounts.rs:490-514](crates/ledger/src/accounts.rs#L490)). That
  interval ends at the next lifecycle event **this node holds**. Until the re-open lands, it is unbounded, so the
  posting after the re-open refuses the `close`.
- `open` and `close` records name no parents (the lifecycle insert at `:9512-9541`).
- `compute_want` asks for remote heads first, then ids in sorted order
  ([p2p anti_entropy.rs:35-59, 88](crates/p2p/src/anti_entropy.rs#L35)), and `order_want_ancestors_first` (`:120`)
  never moves a parentless id. So a `close` and its re-open are staged in content-id (hex) order, after the head.
- gl-node classifies `AccountHasLaterTransactions` as permanent
  ([anti_entropy_alpn.rs:2484-2510](crates/gl-node/src/anti_entropy_alpn.rs#L2484)). The justification there reads:
  "the later posting that refutes the close is in a G-Set DAG and can never leave, so the close can never become
  acceptable". Since T91 a later **re-open** makes it acceptable.
- It is not an account-wait target (`account_wait_target`, `:2535-2545`). The drain never re-tries it, and the L-34
  cache keeps it out of the Want for 10 minutes per (peer, id) ([anti_entropy.rs:678](crates/p2p/src/anti_entropy.rs#L678)).

**Proof** (X2 `x2_p2a_close_before_its_reopen_in_want_order`, re-run in the scratch archive):
```
reopen 03-02: R's Want from A: txn 03-28 -> close 02-01 -> reopen 03-02; merged 2 rejected 1 -> close held by R: false
  FINAL: A holds R's receipt false and R's next write false; R holds A's close false; A buffer 2 entries
  FINAL balances: Cash R={"USD": 141} A={"USD": 140}; Bank R={"USD": 3} A=-
SUMMARY: close refused (re-open staged after it) for re-open days [2, 6, 10, 13, 14, 21, 22, 23, 26, 28]; accepted for [3, 4, 5, …, 27]
```
- A2's gl-node probe on T29's fixture, one Supply `[bank 06-01, cash 03-15, close 02-01, re-open 03-01, …]`, re-run:
  `accepted 9 of 10; close 02-01 held: false`. In two Supplies: `in the L-34 cache=true; sink says Cash open on
  02-10=true`, while the reference says `false`.
- A2 `x1 p2write` (library, n3e's data delivered txnA → closeF → openM), re-run:
  - `R stages closeF(02-01): Err("[ACCOUNT_HAS_LATER_TRANSACTIONS] … as late as 2024-04-01")`
  - after the TTL, with R's operator's 02-15 receipt in between: `Err(… as late as 2024-02-15)`
  - `[A <- R] NEVER LANDS R-receipt(02-15): [ACCOUNT_CLOSED]; R-next(05-01, Cash): orphan: missing parent`
- T91's own gl-node test with seeds `1..=400`: `order reopen-seed-42: accepted directive set diverged`.

**Consequence.**
- A replica returning online refuses the honest `close` for at least the cache's TTL. In that window its operator sees
  the account open and can write a receipt inside the closed interval — 0926 `n3e`'s story, which T91 claims closed.
- Once such a write lands, two honest replicas with the same available set hold different lifecycle state and
  balances for good, and **every later write of that replica, on every account**, is buffered mesh-wide forever (all
  heads are parents).
- Without a write it heals at the TTL or a restart.
- Decision (38) rated exactly this consequence High.

**Fix (T98, decision (54)/(55)).**
- X2's fix-proof, in the archive: make `AccountHasLaterTransactions` an account-wait target — buffer the `close`, and
  re-judge it when an `open` of its account lands, never caching it. The result: 0 of 27 refused, T91's two gl-node
  lifecycle tests pass, and `backdated_remote_close_is_rejected_and_appends_keep_working` changes only its premise
  (the close now waits).
- Correct the gl-node comment, README:136 and CHANGELOG:195.
- Decision (54)'s option (a) removes the refusal altogether.

**Acceptance.** X2's proposed gl-node test
`x2_a_close_arriving_before_its_reopen_is_admitted_once_the_reopen_lands` (the tracker has the source; it goes in
`anti_entropy_alpn.rs`'s tests module, a `src` file this audit did not modify), and the seed sweep widened to
`1..=400` (decision (57)).

---

## 3. New findings — Medium, and the M-09 remainder

### The M-09 remainder — still open, still High (not a new ID)

Found by **A2** (A2-1) and **X2** (§3, `x2_p2b`). **EXECUTED**; pinned: `a2_0927_1_…` (`exact_balances.rs`, ignored).

**Mechanism.** The `close` is judged against the postings held on arrival.
- A posting that arrives after the `close` fails I3 with `AccountClosed`, which gl-node treats as an account wait that
  no `open` will ever end.
- A `close` that arrives after the posting fails with `AccountHasLaterTransactions`, cached permanent.
- Every later write on the side that took the posting names it as a parent.

**Proof.** A2 `x1 p1honest`, re-run: A closes Side through its API while a partitioned B posts on 02-15 through its
API.
```
[R1 <- T] NEVER LANDS T=Side 02-15: [ACCOUNT_CLOSED] … closed on 2024-02-01, cannot post on 2024-02-15
[R2 <- C] NEVER LANDS C=close Side 02-01: [ACCOUNT_HAS_LATER_TRANSACTIONS] … as late as 2024-02-15
[round 1: R1 <- R2] NEVER LANDS W2(R2 write, Cash): orphan: missing parent (buffered)
after round 1 + restart of both: R1 vs R2 only-first=["C=close Side 02-01"] only-second=["T=Side 02-15", "W2(R2 write, Cash)"]
  R1: Side open at 02-15=false Side=5.00 Cash=2.00 | R2: Side open at 02-15=true Side=6.00 Cash=5.00
```
- `x1 p1peer`: one peer M signs both C and T, and the result is identical.
- `x1 p3`: M's `close` dated before the `open` is accepted as inert data by every node; M's earlier `open` then makes
  it live, and `every order the same held set: false`.
- X2 `p2b`: one peer's `close` dated after the last posting the online mesh holds cuts an offline writer's whole later
  history off, on every account (Cash A 100 vs H 112). Fresh replicas split by the first peer they meet.
- A repair exists — a re-open dated between the `close` and the writer's first posting — and is printed nowhere.
- `a2_0927_1_…` under `--ignored`: `same available set, different DAGs for good: only R1 {859f73b2…}, only R2
  {e209be19…, eb212a20…}; Cash R1 Some("5.00") vs R2 Some("6.00")`.

**Consequence.** Mesh divergence between honest replicas and a permanent partition of the writer, from one allowlisted
peer's two ordinary signed records, or from two honest operators. T91's residual "a genuine conflict of two concurrent
writes" understates it: T is not concurrent in `p2b`, and a single author suffices in `p1peer`.

**Fix: decision (54)**
- (a) Make the verdict a function of the set. A peer's or a file's `close` is never refused, and it is inert over any
  interval that holds a transaction in the set. It binds only local API writes (FR-3 AC2). This also removes H-25's
  refusal and M-75.
- (b) Keep it open for T45's causal `close`; do H-25's wait now; document the consequence and the re-open repair.
- (c) Accept it.

### M-71 — T94's identity check binds the file, not the path: after an ancestor swap, the second walk of the configured path returns a hard link to the target inside a directory the checks never saw, and the node then works in the attacker's directory

Found by **A5** (A5-1). **EXECUTED** as the same uid with the attacker's directory at 0777. The cross-uid hard-link
premise is **PLAUSIBLE**.

**Mechanism.** [journal.rs:328-341](crates/ledger/src/journal.rs#L328) calls `canonicalize(configured)` — a second,
by-path walk — and accepts its result when `(dev, ino)` equals the file opened through the handle (`:314`). A hard
link has the same `(dev, ino)`.
- When the handle saw the operator's `node/`, but the swap put the attacker's `evil/` there for the second walk, the
  compare passes. Here `evil/ledger.bean → attacker/h`, and `h` is a hard link of the operator's target.
- The target's own directory (`store/`) is one the attacker cannot write. This is outside T94's stated
  "writer of an ancestor of the TARGET" residual.

**Proof** (re-run, `p1 hlrace … 5 hardout`):
```
hlrace[hardout] 5s: calls=26369 swaps=5987 -> operator_target=4196 OTHER_PATH=915 unresolved=0 refused=21258
   returned …/attacker/h  x915
   boot(…/attacker/h) + compact: Ok(())
   operator's target ino 12366299 ; node's working file …/attacker/h ino 12366959 (same file: false)
```

**Consequence.**
- After one compaction, the node's `.bean` is a new file in the attacker's directory. The `.bean`'s owner is never
  checked (`FileTrust::OperatorLedger`, journal.rs:978-994), so the attacker's lines are adopted as operator input and
  signed as this node's own.
- The attacker can also remove the lock (M-17).
- This is the power M-60/M-68 exist to deny, reached by a writer of an ancestor of the link's directory.
- The premise:
  - macOS `link(2)` has no ownership rule, while Linux's default `fs.protected_hardlinks=1` forbids it;
  - the attacker also needs search permission on the target's directory;
  - untestable here: one uid.

**Fix (T101, decision (64)).** Also require the returned path's parent directory to be the directory the target was
opened in through the handle (`fstatat(handle, dirname(link text))` against `metadata(resolved.parent())`), validated
by A5 (`journal::tests` 39/39). Alternatively, derive the path from the fd (`F_GETPATH`, `/proc/self/fd`). Reword
README:1097-1098 either way. Acceptance: A5's proposed `a5_0927_a_path_through_a_directory_the_checks_never_saw…`
(the tracker has the source; `journal.rs` tests, a `src` file).

### M-72 — T90's duplicate-copy preference is judged before the closure, the signature pass and the served-set rule: after a crash, a chain re-entered child-first or a re-entered signature-held record is held, and the startup compaction deletes the only copy that would have been served

Found by **A1** (A1-1, A1-2) and **X1** (X1-2). **EXECUTED**; pinned: three `a1_0927_…` cases (`m50_wire.rs`,
ignored).

**Mechanism.** `prefer_copies_whose_parents_are_served` ([service.rs:5477](crates/ledger/src/service.rs#L5477))
runs at `:4126`, before the closure walk (`:4127`), the operator input, the signature pass and the rule.
- **Its "resolves" is "the parent is in the lenient, pre-closure DAG"** (`:5488-5495`). The file's D (naming the
  file's C, whose parent is the refused X) counts as resolving and is kept. The journal's C names D, which descends
  from the file's C, so the cycle guard (`:5498-5511`) keeps the file's C too. The closure then takes C, D and Y (A1-1).
- **It switches only when the loaded copy's parents do not resolve** (`:5493`). The canonical file's text comes first
  (`:3490-3496`), so its copy is loaded and the journal's copy becomes the duplicate. There is no verifier yet, so an
  edited-envelope file copy is kept, the pass holds it, and the rule holds its descendants (A1-2, X1-2).
- The compaction writes only the DAG and the quarantine (`:6735-6745`), so the journal's valid copies are deleted.

**Proof** (re-run):
```
A1-1: D, C, Y served after the crash [false, false, false], after the next restart [false, false, false], held [3ddde67f…, b60ba2f4…, d8aaeaf3…]; the copies of C on disk after the startup compaction name ["eff96f25…"]
A1-1 (peer): B serves C, D after the crash: [false, false] …; A re-supplying them: ["OK" ×5], then served [true, true]
A1-2: C, Y served after the crash [false, false], after the next restart [false, false], held [b60ba2f4…, e485ce5a…]; a fresh replica holds both
X1 m8a: API re-entry of T2: txid == T2 id: true; served = true … after the crash + restart: T2 served = false; Y served = false; Cash running before the crash 87.00 / after the restart 100.00
```

**Consequence.** Loud loss of acknowledged records: permanent with P2P off, until a peer re-supplies them otherwise. The
only envelope that verifies is deleted from disk. This is H-24's shape 2 — which T90's CHANGELOG says is fixed —
through a two-record chain or a signature hold.

**Fix (T99, decision (58)).** Keep the alternatives until after the closure, the pass and the rule. Inside the
fixpoint, install an alternative that verifies and whose parents are served (`rebuild_dag(∅, {id: alt})`), then
re-run. Detect cycles once over the chosen copies (Kahn), not per record (L-142).

### M-73 — The "restate the chain" remedy is printed on every node, and keeps printing after another node's restatement has arrived: two operators who follow it count the refused record twice on every replica

Found by **A1** (A1-4) and **X2** (X2-3). **EXECUTED**; pinned: `a1_0927_the_restate_remedy_followed_on_two_nodes…`
(`m50_wire.rs`, ignored).

**Mechanism.**
- The closure WARN ([service.rs:5588-5600](crates/ledger/src/service.rs#L5588)), the M-52 per-block WARN
  (`:3553-3566`), the H-08 banner and README (:58, :875-880, as reworded by T90 (d)) print at every boot of every
  node whose file holds the refused record. They keep printing after a restatement from another node has arrived and
  the closure is empty.
- A restatement that is not byte-identical (10000 vs 10000.00 USD) is a new record, adopted everywhere.

**Proof** (re-run):
```
X2 c10 [differ] restated deposits held by C: 2 (["6e7d5bbb", "87a6e6cf"]); A1/A2/C Cash {"USD": 19895.00}   ([same]: 1 restated, Cash 9895)
A1-4: restated deposits served per node [2, 2], Assets:Cash ["114", "114"] (one restatement: 64 USD)
```

**Consequence.** Incorrect balances mesh-wide, reached through the code's own remedy, silently (M-69's precedent).
Parent edges also differ per replica for good.

**Fix (T103, decision (68)).** Restate on ONE node; the others adopt. Once the closure is empty for a block's id, the
WARN says "delete this block".

### M-74 — T93's pre-stage cap gate trusts a stale `canonical_over_cap` and the file-based headroom while the next commit will be a compaction: every mutation and every peer batch pays a full reload and fails as `IO_ERROR`, and in the kept-write state each refused write is counted and served

Found by **A4** (A4-1). **EXECUTED** on gl-node's GraphQL path and its peer path. **Fix-proven** for the kept-write
state.

**Mechanism.** `refuse_if_local_write_cannot_fit` ([ledger_commit.rs:556](crates/gl-node/src/ledger_commit.rs#L556))
decides on three inputs:
- the file-based `append_headroom()` ([service.rs:6389-6398](crates/ledger/src/service.rs#L6389));
- the over-cap fact, through headroom 0 (`:565`);
- an exact estimate, skipped when `uncommitted_count() > 0` (`:573`).

While `must_rewrite` holds (`:6524-6528`), the commit is a compaction of **memory's** canonical form. That form
includes the envelopes of lines still waiting for their rewrite, which `canonical_bytes` does not count.
- `prepare` re-measures the fact only if it is already set (`:6572`).
- `persist_atomically` refuses an over-cap text as `Io(InvalidData)` (`:282-290`) and sets nothing.
- Both REFUSING arms return (`:7128`, `:7151`) before the re-measure (`:7220`).
- The L-70 peer backoff arms only on `ResourceLimitExceeded` ([anti_entropy_alpn.rs:2319](crates/gl-node/src/anti_entropy_alpn.rs#L2319)).

**Proof** (A4 `a4_probe_window_and_remedy`, re-run):
```
mutation 0: "…the canonical form of this ledger is 67109024 bytes, over the file cap…" RESOURCE_LIMIT_EXCEEDED in 37.7s; reload installed 1
mutation 1: "internal storage error" IO_ERROR in 27.1s; reload installed 2; uncommitted 0; headroom 8469; compaction_pending true
mutation 2: IO_ERROR in 26.0s; reload installed 3 …   mutation 3: IO_ERROR in 14.4s; reload installed 4
after-remedy mutation 4: RESOURCE_LIMIT_EXCEEDED …; REFUSING 1
kept after refused mutation: aa8caa95… served=true
cash running Some("-205") after restart None
```
- A4 `g4`: peer batches `in 11.9s|12.1s|12.1s; backed off false`.
- A4 `g3` (kept-write state, headroom 3000): `mutation 0..3: IO_ERROR … REFUSING so far 1/2/3/4; uncommitted
  1/2/3/4; cash -10/-15/-20/-25`.
- Fix-proof with the `:573` exemption removed: `"this write's journal record (3348 bytes) does not fit in the 3000"
  RESOURCE_LIMIT_EXCEEDED in 4.5ms/3.5ms/3.3ms`.

**Consequence.** It needs a rewrite pending and a gap under ~1 MiB: an operator's hand edit under a running node near
the cap. An API-key holder can then keep it there.
- Every retry and every peer batch pays a full 64 MiB rebuild under the single-writer permit, and the error is a
  misleading `IO_ERROR`.
- In the kept-write state each refused write is counted, served and lost at restart: M-65's exact symptom.
- Decision (43b) is met literally, not in purpose.

**Fix (T100, decision (61)).**
- While a rewrite is pending, gate on memory's canonical length.
- Re-measure the fact in both REFUSING arms.
- Return `ResourceLimitExceeded` from the compaction arm before building an over-cap text.
- Drop the `:573` exemption.

### M-75 — A `close` is judged against what this node serves, so a record held on this node alone lets through a `close` every replica that serves the record refuses for good; the printed remedy then cannot bring the record back, and the node never resolves a later peer write through it

Found by **X3** (X3-2). **EXECUTED**; pinned: `x3_0927_2_…` (`exact_balances.rs`, ignored).

**Mechanism.** Three checks read `latest_posting_date(_in)` over the read model
([read_model.rs:1108](crates/ledger/src/read_model.rs#L1108)), which excludes the quarantine:
- `close_account_staged` ([service.rs:6017](crates/ledger/src/service.rs#L6017));
- `reject_backdated_close` from the file path (`:8583`);
- `reject_backdated_close` from the wire (`:9530`).

A record T held here for a local reason — an H-20 edited signature, an H-23 edited parents line — is invisible to all
three. Every peer that serves T refuses the `close` for good. The remedy the WARN prints ("restore the original line")
brings T back, and the served-set rule then holds T on I3 forever.

**Proof** (`x3 k16`, re-run):
```
[k16 api T-edited-on-this-node=true] close of Bank dated 2024-01-02 (T is 2024-01-04) → ACCEPTED
  after stop → restore T → start (twice): node serves T? false close? true Bank=- | peer stages the close → Err("AccountHasLaterTransactions { … 2024-01-04 }"); peer serves T? true close? false Bank=3
    peer's next write names Some(["9fb0f92f"]) → node: missing parents ["9fb0f92f"]
[k16 api T-edited-on-this-node=false] → AccountHasLaterTransactions   (control)
[k16 wire T-edited-on-this-node=true] (another allowlisted author's close) → ACCEPTED … same outcome
```
`x3_0927_2_…` under `--ignored`: `left: (Some("100"), false) right: (Some("105"), true)`.

**Consequence.** The node and the mesh disagree on the account for good, and every later peer write whose parents lead
through T is unresolvable on the node. Three triggers reach it: the node's own API `close`, a hand `close` typed while
it runs, or one peer's `close`. Medium (a check on replica-local state where the property is mesh-wide; the trigger
needs a local hold); a permanent partition of one replica argues for High. Rated with the M-09 decision.

**Fix (T98).** Under decision (54a) it dissolves: the `close` is inert over T's interval once T returns. Otherwise,
decision (56): judge every `close` against the read model plus held history.

### M-76 — Another peer's buffered copy still decides the buffer slot and the Want order of an honest peer's records: an allowlisted peer's envelopes of an honest chain slow a replica's catch-up to one record per exchange

Found by **X2** (X2-2). **EXECUTED over real loopback QUIC** (scratch archive, control green in the same binary).

**Mechanism.**
- A content id covers the body only, so M signs its own envelopes (its own parents) over H's bodies and pushes them
  ([anti_entropy_alpn.rs:884-893](crates/gl-node/src/anti_entropy_alpn.rs#L884)).
- `insert_waiting` returns `Duplicate` for any existing entry, whoever delivered it
  ([orphan_buffer.rs:692](crates/p2p/src/orphan_buffer.rs#L692)), and gl-node drops H's copy (`:2153-2172`).
- `known_missing_parents` (`:317`) reads M's copy's parents, and gl-node orders H's Want by it (`:1320-1325`).
- T95 made only the two filters per-peer.

**Proof** (re-run, library harness `x2 c9`, 300 records):
```
[none]    V joins H's 300-record chain in 1 exchanges with H
[bogus]   V joins H's 300-record chain in 142 exchanges with H … progress t1:4 t2:7 t3:8 t100:213
[reverse] V joins H's 300-record chain in 300 exchanges with H … progress t1:1 t2:2 t3:3 t100:100 t200:200
```
Over real QUIC (X2 `x2_c9_quic…`, 200 records): `[reverse] … after 200 exchanges` against `[none] … after 1`.

**Consequence.**
- Per M transport id: up to 1,000 ids (`MAX_ORPHANS_PER_PEER`) for an hour, renewable by re-pushing.
- A lagging or returning replica then catches up at one record per exchange per honest peer — about 83 minutes for
  1,000 records at the 5 s default — and a writer faster than that stays out of reach.
- Only debug logs show it: a resource/liveness attack by an allowlisted peer beyond the documented budgets.

**Fix (T102, decision (66)).** Buffer per (id, delivering peer), and order a peer's Want by that peer's own entries and
hints only.

---

## 4. New findings — Low

- **L-137 — The L-120 ACL rule refuses any ACL entry, including macOS's default `group:everyone deny delete` on `~`,
  `~/Desktop`, `~/Documents` and `~/Downloads`; its `chmod -N` remedy strips Apple's home-folder protection.** A5-2.
  - `acl_get_entry(FIRST) == 0` ⇒ refuse ([journal.rs:421-447](crates/ledger/src/journal.rs#L421)); allow/deny,
    permissions and inheritance are never read.
  - Re-run: `ls -led ~` → `0: group:everyone deny delete`; `p1 acls` refuses a deny-only entry, an `only_inherit`
    allow and the owner's `readextattr`.
  - A link kept directly in `~` worked through T87 and refuses boot after T94. Fix (T101, decision (65)).
- **L-138 — The link directory is opened without `O_DIRECTORY | O_NONBLOCK`: a FIFO put at its path hangs boot before
  the lock, with no log line.** A5-3; `File::open(link_directory)` (`:263`).
  - Re-run: `fifo: call #4676 has not returned for 3 s — PARKED in open(2) of a FIFO at the link directory's path`.
  - T87 used `stat`, which cannot hang; T67 treated the same for the `.bean` as a bug.
  - Fix (T101): `O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_CLOEXEC` (`ENOTDIR` at once, checked by A5).
- **L-139 — gl-node's sweep beside the link deletes the link's own target when the target is named like a reserved
  temporary (`<link>.tmp`, `<link>.tmp.<pid>.<16hex>`), and boot starts an empty ledger.** A5-4.
  - `sweep_stale_temporaries` ([service.rs:226-271](crates/ledger/src/service.rs#L226)) never compares with the
    resolved target.
  - Re-run `p1 sweeptarget`: `target exists after the sweep: false … boot: Ok(0) … target content now: Some("")`.
  - Fix (T101): skip the resolved target by `(dev, ino)`.
- **L-140 — The live reconcile deletes a pasted complete envelope over the lamport ratchet from the file, while a boot
  of the same bytes serves it.** A1-3.
  - The refusal at `:8357-8362` precedes every hold; README:1025 says a full envelope "is kept when boot would keep
    it".
  - Re-run: `[("live", false, false), ("boot", true, true)]`.
  - Fix (T103, decision (69)).
- **L-141 — A held own record's lamport is not folded into the clock on the live path (T90's new holds), so the node
  re-issues its own pair.** A1-5; `hold_refused_file_entry` (`:5550`).
  - `BootLamportHigh`'s own doc (`:1636-1639`) names the risk.
  - Re-run: `clock 2 after holding a record at lamport 5; 2 records on disk and 2 served carry this node's pair
    (author, 5)`.
  - The T85 missing-parent hold has the same shape (PLAUSIBLE). Fix (T103, decision (70)).
- **L-142 — `prefer_copies_whose_parents_are_served` walks every descendant once per duplicate pair: boot is
  quadratic on a crafted file.** A1-6; `:5497-5505`.
  - Re-run: 2,000 pairs 1.30 s vs 0.13 s without duplicates; 4,000 pairs 4.45 s vs 0.29 s. A1 measured 8,000 pairs:
    190.7 s vs 4.5 s.
  - Needs the `.bean` writer. Fix (T99): one Kahn scan over the chosen copies.
- **L-143 — L-131 is fixed only for records the closure holds: a block typed beside a record held by the served-set
  rule or the signature pass — or "the missing open" typed as the account's own `open` line — is dropped at boot as a
  duplicate, silently, while the live path adopts the same bytes.** A3-1, D1-1, X1-1.
  - `adopt_operator_input_at_boot` counts an id already in the DAG as a duplicate
    ([service.rs:4350-4354](crates/ledger/src/service.rs#L4350)) before the pass and the rule have held the history
    copy.
  - Re-runs:
    - D1 `c_l131b` on the binary: `served [] quarantined 2 … operator_input=0 … log lines naming L-131 / a duplicate:
      NONE`;
    - X1 `m2a`: `Food open = false … the typed line in the file after the startup compaction: false`, while `m2b`
      (live) opens Food.
  - Pinned: `a3_0927_1_…`, `x1_0927_the_missing_open_retyped…` (`boot_fuzz.rs`, ignored). Fix (T99, decision (59)).
- **L-144 — A retyped closure member frees its held descendants only at the next boot: a restart with nothing edited
  changes the served set and the balances.** A3-2.
  - The closure (`:4127`) is walked by id before the operator input is adopted.
  - Re-run `a3_0927_2_…`: `quarantine changed across the reboot: ["832b02ad", "c9224dac"] -> ["832b02ad"]`.
  - It converges at boot 2. Fix (T99): re-judge the closure after the operator input, on the DAG copy's parents.
- **L-145 — A typed copy the pass skipped and finalize then refuses (M-54, the ceiling, L-77) is deleted from the file
  under a WARN that says "kept in the file as written", after an INFO that said it was adopted; the closure was
  already pruned.** A3-3, X1-3.
  - `hold_refused_in_quarantine` (`:5605`) → `quarantine_keeping_envelope` (`:4250-4264`) keeps the enveloped
    original (L-76).
  - Re-run X1 `m4a`: `blocks with H's body in the file = 1; of them without an openledger-signature (the typed one) =
    0`.
  - Nothing acknowledged is lost (A3's passing companion test). Pinned: `a3_0927_3_…`. Fix (T99, decision (59)).
- **L-146 — The rule's fixpoint recurses once per round, each round a full `rebuild_dag`; a file can force one round
  per chained hand-parented half envelope: boot is quadratic, and gl-node's recovery reload aborts the process by stack
  overflow at ~2,800 rounds.** A3-4, X1-4.
  - `ids.len() + self.quarantine_unservable_history()` (`:4832`) is not a tail call: 0.72–0.8 KiB per level.
  - The L-13 reload's `boot_with` runs under `spawn_blocking` (`ledger_commit.rs:298`, 2 MiB stack), and a stack
    overflow aborts — no `JoinError` catches it.
  - Re-runs:
    - X1 `m3 0 3000 2048`: `has overflowed its stack / fatal runtime error: stack overflow, aborting`;
    - `m3 0 2200 2048`: `thread result: ok`.
  - A3: 1,000 pairs (451 KB) boot in 68 s at load 26 vs 0.5 s flat; 3,200 pairs 235 s on the main thread.
  - About 11,000 pairs would overflow the 8 MiB main thread at every start (extrapolated). That is a boot brick, but
    only the `.bean` writer or the operator can make it: no peer can create pending input.
  - Low, as L-129. Pinned: `a3_0927_4_…`. Fix (T99, decision (60)), fix-proven: walk through pending hand-parented
    children, so one round suffices — k = 3,200 in 0.39 s, 610/610 ledger tests.
- **L-147 — The L-117 refusal, the committed-id floor arm and the reload-failed arm keep the failed call's staged
  write: it is counted and served at once, the next commit writes it, and after the L-117 refusal that compaction also
  replaces the operator's link.** A4-2, D1-3, X3-4.
  - `:3319-3334` → `:7222-7237` keeps `pending_ids`; the comment at `:3317-3318` names the wrong arm.
  - Re-runs:
    - A4 `a4l1`: `W1 → Io(PermissionDenied) | … W1 in memory true served true … reboot: W1 (whose call failed) on
      disk? true | … moved.bean holds W1? false`;
    - D1 `c_l117` on the binary: `served ['during', 'after'] … ledger.bean is link: False`.
  - CHANGELOG:193 says "rolls back exactly what failed". Pinned: `a4_0927_…` (`exact_balances.rs`, ignored). Fix
    (T100, decision (62)).
- **L-148 — Decision (44)'s floor lives in memory: a restart after a failed commit, before any write succeeds,
  re-issues the discarded write's pair, which was served while staged (L-86).** A4-3, X3-1.
  - Re-run X3 `diff=all`: `[summary] reload re-issues=0 restart re-issues=52`.
  - A4 `a4l5`: `restart: clock 3 … first write after the restart lamport 4 | same (author, lamport) as the served S?
    true`.
  - The trigger is the natural response to a failed write (fix the disk, restart). Pinned: `x3_0927_1_…`
    (`convergence.rs`, ignored). Fix (T100, decision (63)).
- **L-149 — `choose_committed_parents` rebuilds the pending set and walks every pending chain per call, twice per
  adopted line, under the write lock.** A4-4; `:6146`.
  - A4 `a4l3` (release, loaded): 1,000 staged × 5,000 lines 18–42 s; 0 staged × 5,000 lines 0.30 s.
  - Fix (T100): committed heads once per adoption pass.
- **L-150 — T95's hint-queue compaction drops the entry it has just pushed, so that hint never expires.** A6-1.
  - `push_back` at [orphan_buffer.rs:568](crates/p2p/src/orphan_buffer.rs#L568), `retain` against `parent_hints` at
    `:571-577`, insert only at `:579` (re-read in source).
  - Pinned: `a6_0927_3_…` (`convergence.rs`, ignored). Fix (T102): insert before compacting.
- **L-151 — `retain_not_buffered_from` has no `holds`: a child buffered on a parent that then arrives through the file
  is dropped from its only peer's Want for up to an hour.** A6-2; `:462-469`.
  - The watcher's reconcile never drains the buffer.
  - Pinned: `a6_0927_2_…` (`convergence.rs`, ignored): `after 3 exchanges V lacks c: Wants [[], [], []], still
    buffered 1`.
  - Pre-T95 it arrived at the next exchange. Fix (T102, decision (67)).
- **L-152 — T95's filters hold `ledger.read` for ~13 hashes per advertised id.** A6-3.
  - A 1M-id Want with a full per-peer share takes 8.3 s under both locks, against T88's 1.6–2.2 s under the buffer
    lock only (loaded machine; ratios from one process).
  - GraphQL writes and phase 2 queue behind it. Fix (T102): roots over the peer's own ≤ 9.2k ids.
- **L-153 — At boot a hand `close` is judged at adoption, before the signature pass and before a later hand re-`open`,
  so boot → compaction → boot is not a fixed point.** X3-3; `:8583` via `:4131`, adoption in date order.
  - Re-run `x3 k15`: `boot 1: close HELD | re-open in DAG … boot 2: close in DAG … boot 3: close served`.
  - Fix (T98): judge it in `finalize_operator_input`, as T92 did for L-77.
- **L-154 — T93's views withhold a line awaiting its rewrite but advertise and supply its signed child: while the
  startup compaction keeps failing, a fresh peer is offered a record it can never adopt.** X1 §3.
  - Re-run `x1 m9`: `advertised/supplied (served_*): T2 false T3 true; served heads = ["T3(36e473fe)"] … fresh peer …
    T3: DAG: Missing parent`.
  - It heals at the rewrite. Fix (T100, decision (63)): the views also withhold descendants.
- **L-155 — Texts T90–T94 added that say more than the code does.** A2-3, D1-2, A4, A5, X1.
  - CHANGELOG:195 "no longer depend on … which order" and README:136 (H-25). README:136 also says "the latest `open`
    or `close` dated before it", whereas a same-day `open` decides.
  - README:58 does not carry the T90/T91 mixed-version consequence the T91 Done note says it does.
  - CHANGELOG:193 overclaims three times (M-74, L-147, L-148).
  - README:1097-1098 says a swap from above "cannot redirect the node" (M-71).
  - README:1103-1106 omits what follows the L-117 refusal (L-147).
  - Fix (T103).
- **L-156 — Code comments T94–T96 made false.**
  - journal.rs:1310-1311 says "the workspace's one production `unsafe` expression"; there are five, plus an `extern`
    block.
  - journal.rs:885-888 calls `fcntl` "an `unsafe` FFI call this crate avoids".
  - p2p_service.rs:1088-1090 says "the only production FFI declaration".
  - T95 inserted `type ServedIdSnapshot` between `sweep_stale_temporaries`' doc and the function
    ([service.rs:193-209](crates/ledger/src/service.rs#L193)), so rustdoc attaches the L-57 text to the alias.
  - ci.yml:25-27 says "stable branch tip" beside the `master` pin.
  - boot_fuzz.rs:73 says check 7 "is off in `Checks::ALL`".
  - service.rs:3317-3318 names the REFUSING arm for the reload-failed arm.
  - service.rs:4849 says "or its envelope edited".
  - anti_entropy_alpn.rs:2484-2487 (H-25).
  - Found by A5, D1, A6, X1 and X3. Fix (T103).
- **L-157 — Proxies in the tests T90–T96 added or changed.**
  - `m68_…` counts only resolutions equal to the victim path, so M-71's other path passes it; its doc says
    `../store/real.bean` for `../../store/real.bean` (A5).
  - `m67_…`'s 2 s debug bound failed on the unmodified repo under load (2.03 s; A6).
  - The gl-node lifecycle test's 32 seeds miss H-25's order (X2).
  - The re-application of decision (44)'s floor (`:7213`) is unpinned (A4 R3b).
  - The T90 resolved-body-cap hold is unpinned (A1 R4d).
  - Closed by this audit's new tests: T90's cycle guard and held-parent hold (A1), T91's interval bounds (A2), and the
    served-id cache's invalidation (A6).
  - Fix (T103, decision (71) for the existing-test change).

---

## 5. New informational

- **Loopback QUIC works for fresh binaries today.** D1 and the orchestrator both passed the control from a scratch
  target; the 0926 block did not recur. Real-QUIC revert-proofs no longer need the repo-tree procedure while this
  holds.
- **T94's fallback resolves twice.**
  - `resolve_link_in_its_directory` returns "use the link" (`Ok(None)`) for every `openat` errno but `ELOOP` and for
    every `canonicalize` failure.
  - gl-node then locks `<link>.lock`, and `boot_with` resolves again. If the target has appeared by then, the node
    works at the target under the link's lock, and every reload refuses (A5 `twice`).
  - T94 widened a pre-existing (T82) fallback.
- **The FFI code has three small gaps.** A5, by reading.
  - `O_NOCTTY` is missing from the target `openat`: a link to a tty would acquire it.
  - `acl_get_fd_np` returning NULL is treated as "no ACL" for every errno, so an ACL enforced by an SMB or NFS server
    is not seen.
  - NFSv4 ACLs on a Linux NFS client are not reflected in the mode bits.
- **A 0300 link directory now fails with `EACCES`.** T94's `open(O_RDONLY)` needs read permission, where T87's `stat`
  did not. `O_SEARCH` (macOS) or `O_PATH` (Linux) would keep it working.
- **`order_want_ancestors_first` still reads any peer's `known_missing_parents`,** so a forged envelope can reorder an
  honest peer's Want. Part of M-76's mechanism; alone, a one-round delay.
- **The hint queue's "twice the table" bound** counts hints, while the table counts ids, so the real bound is about 4×
  the live maximum. The adoption-time gap WARN uses the single step only; its text is hedged.
- **Mixed mesh HEAD × `8c0a87e` (X2 `xver`).**
  - The old build refuses more: a `close` with a held re-open, a USD transaction after another node's EUR-only
    `open`, and H-24's restated chain.
  - After an upgrade on the same file every case re-judges and nothing sticks, unless a write lands in the mixed
    window.
  - A1 saw the same with `8c0a87e` receiving a restated chain (`INVALID_INPUT`, cleared by the upgrade). README says
    to upgrade every node, but not why for T90/T91 (L-155).
- **The banner also prints on the EVERY-signature-failed shape** (a wrong `meshId` or key), where its strip remedy
  would re-author the history under the wrong domain. The EVERY WARN printed before it says to check both first. A3,
  not executed.
- **The H-23 summary sentence is garbled** ("… it re-supplies it — and these records too — they return: …",
  service.rs:4808-4822). The journal's Corrupt message says "a later record header follows" when only 1–5 bytes of a
  tag follow (journal.rs:677).
- **The restate remedy does not say to strip the envelope of the restated record itself.** An in-place amount edit
  with its envelope intact is held by H-20 (A1).
- **After a swap to a foreign copy, boot 1's clock can sit below a served record.** The replacement copy's lamport is
  not counted at boot 1; boot 2 counts it. Harmless (A1).
- **The reload's clock is one above a Fresh boot's in one shape** (`lampP On`, 8 vs 9), as recorded at 0926 §5. It
  errs in the safe direction.

---

## 6. Dependencies, supply chain, verification runs, and the four invariant test files

**Supply chain** (D1, re-checked where cheap).
- **`cargo audit`.** With a fresh DB (`e2111519`, 2026-09-25) run from the archive root, so `.cargo/audit.toml` is
  read, it exits 0. The only output is the allowed RUSTSEC-2024-0436 (`paste`) warning. The rkyv ignore's evidence
  still holds: `cargo tree -i rkyv -e all --target all` prints nothing.
- **Manifests.** `Cargo.lock` and every manifest are unchanged since `45014e9`. `libc = "0.2.189"` was already a
  dependency.
- **CI pins**, checked with `git ls-remote`:
  - `dtolnay/rust-toolchain@02cb101` is on `HEAD`, `refs/heads/master` and `refs/tags/v1`, and its `action.yml` takes
    the `toolchain` input the workflow gives;
  - checkout `11d5960` = v4.4.0;
  - rust-cache `6323deb` = v2.9.2;
  - audit-check `69366f3` = v2.0.0.
- **Dockerfile** unchanged since `af14603`. `deny_unknown_fields` on 7 of 7 config structs. No error code added.
  `cargo +1.92.0 check --workspace --all-targets --locked` is clean; 1.91 itself is not installed.
- **`unsafe`.** Production `unsafe` went from one expression to five (journal.rs :356, :380, :407, :438, :1318) plus
  an `extern "C"` block (:427-435). Every SAFETY note is true (A5's FFI review, D1). The in-code count is stale
  (L-156).
- **GraphQL.** The introspection schema is byte-identical to 0926's.
- **Lint and format.** `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo fmt --all --
  --check` exit 0:
  - on the pristine archive (D1);
  - on the repo with the four extended test files in (orchestrator, after one `iter().any` → `contains` lint in an
    added test).

**CHANGELOG vs code.** Every bullet tagged T90–T97 was executed on the real binary (D1, 24 scripts) or pinned by a
named test. The remedy texts, followed on one node, all work: the banner in three shapes, "add the missing open" at
boot and live, "correct that open's date", the strip remedy live, "restate the chain", the constrained-account step,
`chmod g-w,o-w` and `chmod -N`. The bullets are true except for:
- the T91 order claim (H-25);
- "rolls back exactly what failed" and "however many writes are pending" (M-74, L-147);
- the L-131 behaviour change (L-143);
- the symlink "cannot redirect" (M-71).

**The four invariant test files.** They contain pure additions (2,684 lines, 0 deleted); no existing test was
modified or removed.
- Every new test that pins an existing mechanism was revert-proven in an archive copy.
- Every test that pins a new finding is `#[ignore = "<pass>-N: …"]` and fails for the stated reason under `--ignored`.
  The orchestrator re-ran all 17.
- Four of the 17 were proposed by non-owner passes and added by the orchestrator after the owners finished: A4-2 and
  X3-2 in `exact_balances.rs`, X3-1 in `convergence.rs`, X1-1 in `boot_fuzz.rs`.

| File | Before | After | New cases (pins) |
|---|---|---|---|
| [crates/p2p/tests/m50_wire.rs](crates/p2p/tests/m50_wire.rs) | 23 / 0 | **26 / 6 ign** | a chain re-entered parent-first served after a crash, no parent cycle ever written (R3, R7); a restated parent frees the held child's original copy live and on the wire (R568); a pasted child of a held record kept in the file as boot keeps it (R4e); ignored: A1-1 ×2 (M-72), A1-2 (M-72), A1-3 (L-140), A1-4 (M-73), A1-5 (L-141) |
| [crates/ledger/tests/exact_balances.rs](crates/ledger/tests/exact_balances.rs) | 37 / 0 | **40 / 3 ign** | T91's union against an independent oracle in 3 orders + a restart (proptest; R1, R7, R9); an ingested `close` refused exactly when it would close a held transaction (proptest; R2, R5, R6 — R5/R6 caught by no other test); a 300-pair reopen history in 301 currencies across a restart (R1); ignored: A2-1 (M-09 remainder), A4-2 (L-147), X3-2 (M-75) |
| [crates/p2p/tests/boot_fuzz.rs](crates/p2p/tests/boot_fuzz.rs) | 58 / 0 | **61 / 5 ign** | the rule holds an alternating chain over 5 rounds (R1); a hand `open` then the original returning changes no verdict, on Food and Travel (R3); a retyped copy refused at finalisation leaves the record held and on disk (R76); ignored: A3-1 (L-143), A3-2 (L-144), A3-3 (L-145), A3-4 (L-146), X1-1 (L-143) |
| [crates/p2p/tests/convergence.rs](crates/p2p/tests/convergence.rs) | 37 / 3 ign | **38 / 6 ign** | the cached advert tracks a record staged while a line waits for its rewrite, replaying gl-node's head exchange, served views and both T95 filters (R7 — the first harness case to exercise T93's views and T95's filters); ignored: A6-1 (L-150), A6-2 (L-151), X3-1 (L-148) |

**Test suite.** `cargo test --workspace --locked --no-fail-fast` gave **1,437 passed, 0 failed, 3 ignored** before
the audit, and **1,447 passed, 0 failed, 20 ignored** (425 + 8 + 610 + 40 + 10 + 195 + 61 + 38 + 8 + 26 + 5 + 21) after all passes completed, with the four files extended. The ignored cases are
decision (1)'s two anti-entropy-only joins, decision (41)'s one-write residual, and the 17 new finding cases.

**Revert-proofs.** 54 across the passes, each done in a `git archive` copy and restored (one real-QUIC case in the repo
tree with `cmp`):

| Pass | Revert-proofs |
|---|---|
| T90 (A1) | R1, R2, R3, R4a, R4b, R4c, R4e, R5, R6, R7, R568 |
| T90 (X2) | the own-id refusal restored |
| T91 + T97 (A2) | R1, R2, R5, R6, R7, R8, R9 |
| T92 (A3) | R1, R1b, R2, R3, R3b, R5, R6, R76 |
| T92 (X1) | R-a, R-b, R-c, R-d |
| T93 (A4) | R1, R3b, R5, R6 |
| T93 (X3) | `X3_RA` … `X3_RE` |
| T94 (A5) | R1, R3, R4, R5 |
| T95 + T96 (A6) | R1 (real QUIC), R2, R3, R4, R5, R6, R7, R9, V1, V2 |

Fix-proofs validated in archives:
- M-71's parent-directory compare (A5);
- H-25's account wait (X2);
- M-74's `:573` removal (A4);
- L-146's walk-through, which gives one round (A3), and its loop (X1);
- L-148's hidden pending ids (X3).

---

## 7. Consolidated open-findings register

Everything open as of this audit. IDs are stable across the 09/01 … 09/27 reports.

| ID | Sev | One-liner | Origin |
|---|---|---|---|
| **H-25** | High | T91's `close` verdict taken against the events held at arrival: a `close` staged before its re-open is refused, cached permanent; a receipt in the window splits replicas for good | **09/27** |
| M-09 | **High** | *Remainder open.* One peer's `close` + a posting inside its interval, or an honest partition, split honest replicas permanently (A2-1, X2 `p2b`) | 09/01 |
| H-01 | High→Low | *Partially closed.* Loopback API key deferred | 09/01 |
| M-10 | Med | *Interim only.* T45 Facet A | 09/01 |
| **M-71** | Med | T94's `(dev, ino)` compare accepts a hard link in the attacker's directory after an ancestor swap | **09/27** |
| **M-72** | Med | T90's duplicate-copy preference judged before the closure / pass / rule: re-entered records held after a crash, valid copy deleted | **09/27** |
| **M-73** | Med | "Restate the chain" printed on every node: two restatements double-count mesh-wide | **09/27** |
| **M-74** | Med | T93's cap gate trusts a stale fact while a rewrite is pending: reload per mutation and per peer batch; kept-write state counts refused writes | **09/27** |
| **M-75** | Med | A `close` judged against the served read model passes over a locally held record; the remedy then partitions the node | **09/27** |
| **M-76** | Med | Another peer's buffered copy decides the slot and the Want order: catch-up at one record per exchange | **09/27** |
| L-23 | Low | *Partially closed.* `meshId` still opt-in | 09/02 |
| **L-137 … L-157** | Low | Twenty-one new Lows — see §4 | **09/27** |
| L-06 | Latent | `\|`-delimited signature message — injective at HEAD; T45 Facet B | 09/01 |

**Closed this audit (33):** H-24 · M-63, M-64, M-65, M-66, M-67, M-68, M-69, M-70 · L-114 … L-136.

**Next IDs:** H-26 / M-77 / L-158.

**Residuals re-rated:**

| Residual (task) | Now |
|---|---|
| T90 "two copies that both resolve keep the first" | M-72 |
| T90 README "peers adopt the restated ones" | M-73 |
| T90 L-126 list (lamport arms) | L-140 |
| T91 "verdict independent of the re-open's arrival" | H-25 |
| T91 "a genuine conflict of two concurrent writes" | M-09 (open, High) |
| T91 "a `close` before the `open` is inert" | M-09 (A2 `p3`) |
| T91 "README's upgrade-every-node note" | L-155 |
| T92 (a) "this ends" | L-146 |
| T92 (g) "a retyped block … is adopted" | L-143, L-144, L-145 |
| T93 (43b) "refused before staging however many are pending" | M-74 |
| T93 (44) "never lowers the clock" | L-148 |
| T93 L-117 "the next compaction renames onto the path" | L-147 |
| T93 (45a) "not served until a compaction succeeds" | L-154 |
| T94 (46) "race-free for every ancestor, refuses nothing new" | M-71, L-138 |
| T94 "ACL check macOS only" | L-137 |
| T95 "runs under the buffer's read lock" | L-152 |
| T95 "a copy with bad parents buffered first holds the id until its TTL" | M-76 |

---

## 8. Remediation backlog

Tracked in [docs/OUTSTANDING_TASKS_09_27.md](docs/OUTSTANDING_TASKS_09_27.md). Task numbering continues from T97.
Effort: S = < ½ day, M = ~1–2 days. Every task keeps the campaign's rule: revert the fix → the named test fails →
restore; residuals go in the tracker. The `#[ignore]`d cases in the four invariant files are the acceptance tests. Decisions
(54)–(72) were taken on 2026-09-27 (the recommended option every time; (55)/(56) moot under (54a)) and are recorded in
the tracker's header.

### Tier 1 — ship-blockers

**☐ T98 — Lifecycle verdicts that are a function of the directive set (H-25, M-09 remainder, M-75, L-153) — M, decisions (54)–(57).**
- Change: per (54), a peer's or file `close` never refuses and is inert over any interval holding a transaction in
  the set; or, per (55), buffer a refused `close` until an `open` of its account lands. Judge boot's hand `close` at
  finalize.
- Verify:
  - un-ignore `a2_0927_1_…` and `x3_0927_2_…`;
  - add X2's gl-node test;
  - widen the lifecycle seeds to `1..=400`.

### Tier 2 — the boot pipeline's copies and fixpoint, the commit gate, the symlink path, the buffer

**☐ T99 — Boot chooses between copies after judging them, in one iteration (M-72, L-142, L-143, L-144, L-145, L-146) — M, decisions (58)–(60)**

**☐ T100 — The commit gate and every refusing arm measure and keep only what the commit wrote (M-74, L-147, L-148, L-149, L-154) — S–M, decisions (61)–(63)**

**☐ T101 — The symlink guard binds the returned path (M-71, L-137, L-138, L-139) — S, decisions (64), (65)**

**☐ T102 — The orphan buffer keyed per delivering peer; the filters' holds and cost (M-76, L-150, L-151, L-152) — S–M, decisions (66), (67)**

### Tier 3 — remedies, texts, proxies

**☐ T103 — "Restate on one node", the live lamport arms, the texts and the proxies (M-73, L-140, L-141, L-155, L-156, L-157) — S, decisions (68)–(71)**

### Finding → task coverage map

- **T98:** H-25, M-09 (remainder), M-75, L-153.
- **T99:** M-72, L-142, L-143, L-144, L-145, L-146.
- **T100:** M-74, L-147, L-148, L-149, L-154.
- **T101:** M-71, L-137, L-138, L-139.
- **T102:** M-76, L-150, L-151, L-152.
- **T103:** M-73, L-140, L-141, L-155, L-156, L-157.

**Deferred by design to T45:** M-10, L-06. **Deferred by decision:** H-01, L-23.

**Landing order:**
1. T98 first. It changes what every replica holds, and T99's re-judged copies and T103's texts depend on its
   lifecycle semantics.
2. T99 and T100 next, both in `service.rs`, sequentially. T99 owns the boot pipeline; T100 owns commit/recovery and
   the `served_*` views.
3. T101 ∥ T102 (disjoint: `journal.rs` + gl-node `main.rs` vs `orphan_buffer.rs` + gl-node `anti_entropy_alpn.rs`'s
   Want session).
4. T103 last.

---

## 9. Checked and found sound (new this audit)

Beyond the closures in §1.1, these were probed adversarially and held.

**The boot pipeline (X1, A3)**
- gl-node's order at HEAD is `claim_ledger_path` :250 → `boot` :274 → `set_author_id` :400 → signer :509 → verifier
  :532 → finalize :569 → `verify_own_history` :583 → banner :593 → compaction :609 → P2P :619.
- A preferred copy whose parent the rule holds later is held with it, and nothing is served over a held parent
  (`m1a`–`m1c`; fresh peer 4/4 or 7/7 in three orders).
- Two replacements that would form a cycle converge through `check_no_cycle` and the next boot's pre-scan (by
  reading).
- A hand `open` under revised (42), with the original returning from a peer and B's `close`s: running = restarted,
  fresh peer 7/7 (`m2c`).
- Crash between finalize and compaction, and a failed startup compaction, on four new shapes: 0 diffs, fixed points.
- `is_open_excluding` handles a hand re-open after a served `close`, and a pending hand `close` then re-open.
- Kahn's order is deterministic; self-loops and cycles are placed as documented.
- The reload verifies before it finalizes.
- Termination of the fixpoint; a live reconcile needs at most 2 calls.

**Fresh boot vs reload (X3)**
- 52 shapes, including duplicate pairs, revised (42), `close` before `open`, reopen histories and a `close` inside an
  interval: 50 SAME, with the served view and served heads compared, and the compacted file byte-identical 52/52.
- 12 live-adoption shapes: 10 SAME; the 2 others are T90's documented residual.
- M-59 is unreachable on gl-node's order and on the library's stage-before-finalize order (`k18`).
- The new over-claim term has no false positive (`k17`: 407 prefixes, including a payload carrying the previous
  record's text).
- A line awaiting its rewrite is never served with an envelope other than the one the file finally keeps (`k14`).
- `discarded_own_high` counts the placeholder as own.

**Lifecycle (A2, X2, D1)**
- The union through the peer path in 3 orders, plus a restart, equals an independent oracle (1,500 cases). An accepted
  `close` un-serves nothing across a restart.
- `CurrencyIndex` cannot go stale, since `AccountState` is only rebuilt wholesale.
- The Lamport in `LifecycleKey` changes no union or interval.
- The refusal message's union is bounded in gl-node's log.
- `AccountCurrencyMismatch` waits for an account and is drained on any `open`, so the I9 arm is order-independent on
  the wire.
- On the binary: the union, FR-3 AC2 on the API, and a `close` before the `open` accepted as inert.

**The closure and the wire (A1, X2)**
- A re-supply heals both of M-72's shapes after a restart.
- An old copy offered after the restated one is a dedup, never a refusal.
- A node never offered the restated copy keeps the id in its closure but adopts on first offer.
- The T93 views do not change T90's verdicts.

**Recovery and commit (A4)**
- `choose_committed_parents` returns exactly the committed DAG's heads: never a pending, quarantined or descendant id
  (by reading, plus `k10`).
- No gossip, GraphQL or Want path serves a held-back line. An API duplicate of one returns `alreadyExisted` and
  announces nothing.
- The headroom-0 refusal holds, with running = restart.

**The symlink guard (A5, D1)**
- Inside the handle, `fstatat`, `readlinkat` and `openat` go through one fd on a directory only this uid can modify,
  so nothing can change between them.
- A FIFO target is opened without blocking and refused by T67. A socket target, an empty link text and
  `nothere/../real` all come back unresolved.
- Every fd and the ACL object are released exactly once.
- On the binary:
  - case and NFD spellings resolve; a chain is refused;
  - 0775 is refused and `chmod g-w,o-w` fixes it;
  - `chmod +a` is refused and `chmod -N` fixes it;
  - the sweep removes only reserved names owned by this uid (apart from L-139).
- Linux types, signatures and `cfg` gating are right (by reading; no Linux target is installed).

**Replication bounds (A6, X2)**
- No lock-order inversion: every path takes the ledger before the buffer.
- The memoised DFS equals T88's least fixpoint, including cycles.
- A peer's own copies decide only that peer's Want (real QUIC).
- `retain_not_buffered_from` is keyed on the delivering peer and cannot be used against an honest peer (X2 `c9`).
- The served-id cache cannot go stale: the DAG only grows between `rebuild_dag` resets, and a reload replaces the
  service.
- The global test subscriber masks nothing; the CI pin is reachable from `master` and `v1`.
- 0926's X2 `c1f`/`c1e`/`c1d`/`c3`/`c5` behave as T90/T95 state.

**On the real binary (D1)**
- Every T90–T97 CHANGELOG bullet with a binary-observable effect was executed, and every remedy text T90–T96 changed
  was followed literally on one node; each ended where it promises.
- L-122 k = 1, 3, 5 now fail closed.
- The M-65 cap refusal is ~1 ms with 0 reloads.
- The T96 gap verdicts are as documented; the 17 × (2^28 − 1) blind spot is confirmed with no WARN.
- README §Verify's own query returns the documented fields.

## 10. Closing verification (2026-10-05)

The audit series ended on 2026-09-28, before an audit re-checked T98–T103 as each earlier round was re-checked by
the next. This section is that check, scoped by decision to **verification only**: does each fix still close the
findings this report assigned it, at HEAD `ef584ee` — after the `service.rs` split into `service/`, the `boot_with`
and `adopt_file_directive` refactors, the elided-posting fix (`76f2096`), H-19's join window, the l114 write refusal
and Format v2. No new hunt was run, so this section adds no finding IDs.

**Method.**
- Every mechanism each task's Done note names was located in source at HEAD, and every acceptance and new test it
  names exists and runs (none is `#[ignore]`d).
- The workspace gate was run once.
- Revert checks were re-run in a scratch copy of HEAD (each edit applied, its named tests run, the file restored and
  compared byte-identical). They were re-written against HEAD's code, since the original edits targeted
  `service.rs` before the split.
- Each Done note's residuals were read against the code.
- The audit probes from the scratch harnesses (A1–A6, X1–X3, D1) were **not** re-run.

**Gate at HEAD:** `cargo test --workspace --locked --no-fail-fast` — **1,518 passed, 1 failed, 0 ignored**.
- The failure was gl-node's `a_frame_trickled_past_the_deadline_is_cut_at_the_deadline` (M-40, from T41). It failed
  in its setup (`connect_retry: no dial succeeded (connect timed out)`) under the gate's load, not on the deadline it
  tests.
- It passed 5 of 5 runs in isolation, and is not part of T98–T103.

**Revert checks re-run: 30 of the 45 the Done notes record.** Every one failed its named tests as the note says,
except T98 R4 (below).

| Task | Re-run | Findings re-proven by a revert at HEAD | Not re-proven here (tests pass; the note's own proof stands) |
|---|---|---|---|
| T98 | R1, R4 (as R4b), R5, R6, R7, R8 | M-09 remainder, M-75 | H-25 and L-153: the refusal they came from is deleted, so there is nothing to revert to. Verified structurally instead: the remote `close` arm inserts with no refusal, and gl-node's permanence doc is corrected. `h25_…` and `l153_…` pass. |
| T99 | R1b, R2, R3, R4, R7, R8 | M-72, L-143, L-144, L-145 | L-142 (falls out of M-72's fix), L-146 (`a3_0927_4_…` passes) |
| T100 | R1, R2, R4, R5, R6 | M-74, L-147, L-148, L-154 | L-149 (cost only) |
| T101 | R1–R5 | M-71, L-137, L-138, L-139, and A5-5 | — |
| T102 | R1, R2, R3, R6 | M-76, L-151 | L-150 (`a6_0927_3_…` passes), L-152 (`l152_…` passes) |
| T103 | R1, R3, R4, R5 | M-73, L-140, L-141 | L-155 and L-156 (texts, no test), L-157 (`l157_…` passes) |

**One observation, not a gap: T98 R4 is pinned only as a pair since T99.**
- The served-set rule judges a body by the data rule in two places: `unservable_history` (service/verify.rs:129)
  and the copy chooser T99 added (service/quarantine.rs:468), which re-admits the DAG's own copy when its body
  passes.
- Each covers for the other. Reverting either alone to the authoring fold leaves `x3_0927_2_…` and
  `a2_0927_an_ingested_close_is_data_…` green, and the served set really is unchanged. Reverting both fails both
  tests.
- At T98's commit only the first check existed, so its recorded R4 was correct then. The overlap is the same kind
  T99's Done note records for the closure's rescue and the boot re-admission.

**Residuals:** every residual in the six Done notes was checked against the code and still holds as stated. Among
them:
- `is_open` is still the plain lifecycle fold, and `AccountClosed` is still kept as an account-wait target;
- `alternative_copies` is never cleared;
- no lamport floor is persisted;
- hints stay one per id;
- the L-140 live refusal is not held.

T103's unnumbered "new, for the next audit" item (boot served a complete envelope with an elided posting when no
verifier could check it) was fixed in `76f2096`, pinned by `a_history_record_with_an_elided_posting_is_held_at_boot`.

**Register after this check:**
- **Closed by mechanism:** H-25, the M-09 remainder, M-71 … M-76, and L-137 … L-157 (L-155 and L-156 are texts,
  checked by reading).
- **Implemented as T45 (Format v2, `ef584ee`), off by default:** M-10 and L-06. They are closed on a mesh that turns
  `format.idv2` on.
- **Still deferred by decision:** H-01 (loopback API key) and L-23 (`meshId` still optional).

---

*Previous audits: [SECURITY_AUDIT_0926.md](SECURITY_AUDIT_0926.md) · [SECURITY_AUDIT_0925.md](SECURITY_AUDIT_0925.md) · [SECURITY_AUDIT_0924.md](SECURITY_AUDIT_0924.md) · [SECURITY_AUDIT_0923.md](SECURITY_AUDIT_0923.md) · [SECURITY_AUDIT_0922-v2.md](SECURITY_AUDIT_0922-v2.md) · [SECURITY_AUDIT_0922.md](SECURITY_AUDIT_0922.md) · [SECURITY_AUDIT_0902.md](SECURITY_AUDIT_0902.md) · [SECURITY_AUDIT_0901.md](SECURITY_AUDIT_0901.md) · [docs/CLAUDE_SECURITY_AUDIT_0820.md](docs/CLAUDE_SECURITY_AUDIT_0820.md). Remediation trackers: [docs/OUTSTANDING_TASKS_09_27.md](docs/OUTSTANDING_TASKS_09_27.md) (T98–T103) · [docs/OUTSTANDING_TASKS_09_26.md](docs/OUTSTANDING_TASKS_09_26.md) (T90–T97) · [docs/OUTSTANDING_TASKS_09_25.md](docs/OUTSTANDING_TASKS_09_25.md) (T84–T89) · [docs/OUTSTANDING_TASKS_09_24.md](docs/OUTSTANDING_TASKS_09_24.md) (T79–T83).*
