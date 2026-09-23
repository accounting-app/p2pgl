# Outstanding Security Tasks — 2026-09-22 (v2)

Remediation backlog for every open finding in [SECURITY_AUDIT_0922-v2.md](../SECURITY_AUDIT_0922-v2.md),
the re-audit of T46–T60. Task numbering continues from [OUTSTANDING_TASKS_09_22.md](OUTSTANDING_TASKS_09_22.md)
(T46–T60, all ☑). Line references are current as of HEAD `3d5ff71`.

**Already closed — do not re-do:** the v2 re-audit verified **44** register entries closed by mechanism
(H-08, H-09, H-10, H-11 · M-16, M-19…M-34 · L-01, L-02, L-29, L-33, L-34, L-36…L-42, L-44…L-54) and
residuals R-11, R-12, R-21. See [SECURITY_AUDIT_0922-v2.md §1](../SECURITY_AUDIT_0922-v2.md). This tracker
covers only what is open: seven new Highs, eleven new Mediums, twelve new Lows, and the carried partials
(H-07→H-12, H-01, M-06→M-40, L-23, L-35, L-43→M-39).

**Status legend:** ☐ not started · ◐ in progress · ☑ done
**Effort:** S = <½ day, M = ~1–2 days.

> **The shape of this backlog.** The 0922 audit found its Highs inside T18–T44's own code. This one finds
> them inside T46–T60's code *and* in the pre-existing file-ingest path those fixes built on. The
> through-line is one disagreement: **boot treats the `.bean` as history, reconcile treats it as operator
> input, and the compaction treats it as this node's own bytes.** Five of the seven Highs and five of the
> Mediums are consequences of that disagreement, so T61 and T62 are organised around making the file path
> one path, not around patching six symptoms. Every task keeps the campaign's rule: revert the fix → the
> named test fails → restore; residuals go in this file, not in code comments.

> **Decisions taken 2026-09-22** (user), recorded once here and referenced from the tasks: work lands in
> the tree uncommitted; the H-12 ratchet is **in scope** (2^32 per-directive advance); envelope-less file
> records are **adopted and signed at boot**; the remote per-author unmerged-head bound is **in scope**
> (256); H-17 takes the **magnitude cap** route now, exact i128 accumulation deferred; R-18 **fails closed**
> and torn journals are **renamed, never unlinked**; `libc` becomes a **direct dependency**; `meshId` gets
> the boot warning + docker config now, required a release later; a `CHANGELOG.md` is added.

## Priority order at a glance

| # | Findings addressed | Sev | Effort | Status |
|---|---|---|---|---|
| T61 | H-13 + H-14 + M-37 + M-38 + L-55 + L-62 — one file path | **High** | M | ☑ |
| T62 | H-15 + M-35 + L-64 — recovery never installs an emptier ledger | **High** | S | ☑ |
| T63 | H-12 — the ceiling as one rule, plus the adoption ratchet | **High** | S | ☑ |
| T64 | H-16 — bounded parent choice, per-author head bound | **High** | S | ☑ |
| T65 | H-17 — exact, order-independent balances (magnitude cap) | **High** | M | ☑ |
| T66 | H-18 + M-41 + L-60 — bounded errors and unsolicited input on the wire | **High** | S–M | ☑ |
| T67 | M-36 + L-57 + L-58 + L-59 + R-17 — file-type discipline for every ledger-side open | Med | S–M | ☐ |
| T68 | M-43 + M-44 (R-18) — journal policy | Med | S | ☐ |
| T69 | M-39 + M-42 + M-45 + L-63 + L-65 + L-35/R-19 + L-43/R-20 — cost bounds on read, watch, near-cap | Med | M | ☐ |
| T70 | M-40 + M-06 + R-5 + R-7 — server-side session deadline, cross-peer cap | Med | S–M | ☐ |
| T71 | L-56 + L-61 + L-66 + L-23/R-9 + R-13 + §5 items — docs, config, hygiene | Low | S | ☐ |

**Coverage check — every open register entry maps to exactly one task:**

H-12→T63 · H-13→T61 · H-14→T61 · H-15→T62 · H-16→T64 · H-17→T65 · H-18→T66 · M-35→T62 · M-36→T67 ·
M-37→T61 · M-38→T61 · M-39→T69 · M-40→T70 · M-41→T66 · M-42→T69 · M-43→T68 · M-44→T68 · M-45→T69 ·
L-55→T61 · L-56→T71 · L-57→T67 · L-58→T67 · L-59→T67 · L-60→T66 · L-61→T71 · L-62→T61 · L-63→T69 ·
L-64→T62 · L-65→T69 · L-66→T71 · M-06→T70 · L-23→T71 · L-35→T69 · L-43→T69 · R-5→T70 · R-7→T70 ·
R-9→T71 · R-13→T71 · R-17→T67.

**Deferred by design to T45 (Format v2), unchanged:** M-09, M-10, L-06 (injective at HEAD since T57; the
length-prefix lands at Facet B). **Deferred by decision, unchanged:** H-01's loopback API key.

**T45 interaction:** waves A and B wait for **T61 and T63**, since both touch the envelope fields Format v2
re-specifies. Wave C may proceed.

**Landing order:** T61 → T62 (they share `service.rs` and are the two silent-loss Highs) → T63 → T64 (both
small, both `service.rs`) → T65 ∥ T66 (disjoint files; T66 must not touch `parse.rs:195`, which T65 owns) →
T67 + T68 together (the filesystem boundary) → T69 → T70 → T71. `service.rs` is the contention point again:
T61–T64 go to one agent in that order or run sequentially; T65, T66, T67, T70 can run alongside.

---

## Tier 1 — ship-blockers (the seven new Highs)

### ☑ T61 — One file path (H-13, H-14, M-37, M-38, L-55, L-62) — M
> **Done 2026-09-23 (working tree, not committed).** (a) `reconcile_content` parses first; the file-state fields are written only on success. (b) `prepare_or_recover` and `commit_inline` return `Parse` without reloading. (c) **Design deviation from the brief, accepted:** boot adopts envelope-less directives (no author and no lamport, `is_operator_input`) through the same `adopt_file_directive` the reconcile uses — one code path, extracted from the reconcile loop — and records them in `unsigned_operator_input`; `finalize_operator_input()` later stamps the current author and signs, idempotently, from `main.rs` right after `set_signer`, from `prepare`'s compaction branch (library callers without a signer get unsigned entries) and from `finish_recovery`. Chosen over a parked list so balances include the edit from boot and a reload re-derives the set for free. A refused operator entry is quarantined, never dropped. (d) `main.rs` order is now boot → banner → P2P identity → `set_signer` → `finalize_operator_input` → startup compaction → P2P tasks → watcher → HTTP. (e) `rejected > 0` forces the compaction (reconcile_file, reconcile_file_staged, watcher). (f) Kahn pre-scan over file ∪ live quarantine. (g) clock assigned only in the two `Inserted` arms. (h) `parse_block` refuses a block starting with U+FEFF. (i) README §Editing rewritten. Thirteen revert-proven tests (`h13_*`, `h14_*`, `m37a_*`, `m37b_*`, `m38_*`, `l55_*`, `l62_*`). Orchestrator re-ran the offline-edit probe: the hand-typed transaction now carries author, lamport, parents and signature. **Behaviour change:** a `.bean` that does not parse keeps blocking writes with `PARSE_ERROR` until repaired; envelope-less opens in legacy files are stamped and signed as this node's own on first start. **Residual:** at the lamport ceiling, operator input cannot be adopted and is quarantined; adoption is one-way (an edit adopted at boot and removed from the file before the first compaction is not un-adopted).
- **Why first:** two of the three routes by which an operator following the README loses or corrupts
  records live here. H-13: the supported stop-edit-start workflow produces records with no envelope and no
  signature, refused by every peer, and the node's next transaction names one as a parent — everything the
  node authors afterwards is orphaned mesh-wide. H-14: a failed reconcile records the broken file's hash as
  the baseline *before* it parses, so the next commit's adopt-before-persist sees "nothing changed" and
  rewrites the file over the operator's edit, valid lines included, after two log lines said it was safe.
- **The defects, precisely:**
  1. **H-13** — [service.rs:1937-1946](../crates/ledger/src/service.rs#L1937-L1946) boot inserts every parsed
     directive with whatever metadata it has; [:2289](../crates/ledger/src/service.rs#L2289) records the
     file's hash as the baseline; [:3526-3534](../crates/ledger/src/service.rs#L3526-L3534)
     `adopt_external_edits` returns on an equal hash, so the startup compaction adopts nothing;
     [main.rs:251](../crates/gl-node/src/main.rs#L251) compacts before [:392](../crates/gl-node/src/main.rs#L392)
     installs the signer. Proof: `scratchpad/orch/offline-edit` (metadata `{}`, zero envelope lines on disk,
     next local txn parents = the hand txn).
  2. **H-14** — [service.rs:3760-3763](../crates/ledger/src/service.rs#L3760-L3763) writes `last_file_hash`,
     `canonical_bytes`, `canonical_marker` before the parse; [:3785](../crates/ledger/src/service.rs#L3785)
     clears `canonical_is_current`; [:3826-3832](../crates/ledger/src/service.rs#L3826-L3832) returns
     `Err(Parse)` restoring nothing; [:3695-3712](../crates/ledger/src/service.rs#L3695-L3712) and the
     watcher [main.rs:474-477](../crates/gl-node/src/main.rs#L474-L477) restore nothing either. Proof: B2 `e1`.
  3. **M-37(a)** — API-first ordering: `adopt_external_edits` parse failure → `prepare` `Err` →
     `prepare_or_recover` ([ledger_commit.rs:353-370](../crates/gl-node/src/ledger_commit.rs#L353-L370)) →
     `recover_failed_commit` ([service.rs:3279](../crates/ledger/src/service.rs#L3279)) → `boot`, which since
     L-45 succeeds on the unparsable file and loads every parseable hand-typed block raw, bypassing I3,
     H-06, L-26, L-02, the stamp and L-11. **M-37(b)** — `reconcile_file` ([:3668](../crates/ledger/src/service.rs#L3668)),
     `reconcile_file_staged` ([:3709](../crates/ledger/src/service.rs#L3709)) and the watcher
     ([main.rs:465](../crates/gl-node/src/main.rs#L465)) re-persist only when `new_directives > 0`, so a
     *rejected-only* edit stays on disk and loads at the next boot (boot applies no I3). Proofs: `e1b`, `e12`, `e13`.
  4. **M-38** — reconcile has no Kahn pre-scan; the DAG's I8 passes the first member of a planted cycle;
     `release_quarantined_now_in_dag` ([:4132](../crates/ledger/src/service.rs#L4132)) frees it; it becomes a
     head; the node's own later transactions descend from it and are quarantined at the next boot. Proof: `e3`.
  5. **L-55** — [service.rs:3991](../crates/ledger/src/service.rs#L3991) assigns the reconcile lamport before
     `enforce_resource_limits` / `validate_transaction` / `dag.insert`; a rejected entry moves the clock.
  6. **L-62** — `salvage_unparsable_blocks` ([:384](../crates/ledger/src/service.rs#L384)) parses each block
     with `parse_file`, which strips a per-block BOM ([parse.rs:546](../crates/ledger/src/parse.rs#L546)); a
     mid-file `U+FEFF` makes every block parse after the whole file failed → the fail-closed arm → `exit(1)`.
- **Decision (taken): envelope-less file directives are operator input, adopted and signed at boot.**
- **Change:** (a) `reconcile_content` parses first and commits `last_file_hash`/`canonical_bytes`/
  `canonical_marker`/`canonical_is_current` only once `file_directives` exists (or snapshots and restores on
  the `Err` path); (b) `prepare_or_recover` returns `ServiceError::Parse` without reloading — a parse failure
  then mutates nothing; (c) boot routes any directive lacking `openledger-author`/`openledger-lamport`
  through the adoption path (stamp, parents via `heads_admissible_as_parents_of`, sign) instead of inserting
  it raw — implemented so that a node with no signer installed yet defers the adoption to the point where
  `set_signer` has run; (d) `main.rs` installs the author id and signer **before** the startup compaction
  and before the P2P tasks are spawned; (e) a reconcile with `rejected > 0` forces the compaction its
  warning promises; (f) `reconcile_content` runs `directives_blocked_by_parent_cycles` over
  `file_directives ∪ quarantine` and keeps blocked ids quarantined; (g) the reconcile lamport is assigned only
  in the `Inserted` arm (mirror [:4753-4757](../crates/ledger/src/service.rs#L4753-L4757)); (h) salvage parses
  blocks without BOM stripping, or refuses a block that begins with `U+FEFF`; (i) README §Editing states the
  now-true behaviour.
- **Files:** [service.rs](../crates/ledger/src/service.rs) (`boot`, `reconcile_content`,
  `reconcile_file_staged`, `reconcile_file`, `salvage_unparsable_blocks`, the three lamport sites),
  [ledger_commit.rs:353-370](../crates/gl-node/src/ledger_commit.rs#L353-L370), [main.rs:190-260,
  320-400](../crates/gl-node/src/main.rs#L190), [README.md:643-700](../README.md#L643-L700).
- **Verify:** the H-13 probe asserts the hand-typed record carries this node's author, lamport, parents and
  signature after boot + startup compaction, and that a second service's `stage_remote_directive` accepts it;
  the H-14 `e1` shape asserts the next write returns `PARSE_ERROR` and both hand-written lines survive, on
  both sides of `COMPACTION_MIN_CANONICAL_BYTES`; `e1b`/`e12` assert a refused edit is **not** in the DAG
  after the recovery; `e13` asserts a rejected-only edit is dropped from the file (or, if kept, is not loaded
  raw at the next boot); `e3` asserts the quarantine stays `{A, B}` and `heads` excludes A; the L-55 shape
  asserts the clock is unchanged after a rejected entry; the `e7` BOM fixture boots. Bug-catch proof for each.

### ☑ T62 — Recovery must never install an emptier ledger (H-15, M-35, L-64) — S
> **Done 2026-09-23 (working tree, not committed).** Private `BootMode { Fresh, Reload }`: a reload never creates the `.bean`; a fresh boot refuses an absent `.bean` beside a journal (the `.lock` is not used as a signal — `main.rs` creates it before boot). `NotFound` in `adopt_external_edits`/`reconcile_file_staged` = nothing to adopt, forces a compaction that recreates the file from memory; the watcher reacts to `Deleted`. `finish_recovery` refuses a rebuild holding fewer than `dag.len() − pending_ids.len()` directives, keeps memory, sets `force_compaction`, and logs before/after counts on every install. Boot's journal budget is `MAX_LEDGER_FILE_BYTES`; the `TooLarge` message names a possibly folded leftover. `adopt_reloaded` keeps `canonical_is_current` when the rebuild read the bytes this service last wrote. Orchestrator re-ran `rm-bean` (3 → 4 → 5 directives, nothing lost) and `brick` (boots, 60,001 directives). **Behaviour change:** a missing `.bean` with a journal beside it refuses to boot. **Residual (L-64 half):** boot does not yet warn when `compaction_text().len() > MAX` for a dense hand-written file; the reload-induced wedge is gone.
- **Why:** H-15 is the cheapest total loss in the series. `mv ledger.bean ledger.bak` under a running node:
  the next `prepare` sees `FileMarker::of == None` ([service.rs:3190-3205](../crates/ledger/src/service.rs#L3190-L3205)),
  escalates to a compaction, `adopt_external_edits` fails `NotFound`, the L-13 reload runs `boot`, and `boot`
  **creates an empty file** ([:1937-1946](../crates/ledger/src/service.rs#L1937-L1946)) and `adopt_reloaded`
  installs it over the complete in-memory DAG. Nothing is logged on the successful-reload path. Proof: B8 `rm-bean`
  (`before 3 → after 0 → next write Ok, 1 directive`).
- **M-35:** boot budgets the journal at `MAX − canonical_bytes` ([:1954-1955](../crates/ledger/src/service.rs#L1954-L1955))
  and `read_journal` fails `TooLarge` before parsing ([journal.rs:177-179](../crates/ledger/src/journal.rs#L177-L179)).
  After a crash between the compaction's rename and `remove_journal` ([:1516-1517](../crates/ledger/src/service.rs#L1516-L1517))
  the state is `canonical + 2·journal`, over the cap whenever `journal > (64 MiB − canonical)/2` — a boot brick
  on a fully redundant journal. Proof: B1 `brick`.
- **L-64 / R-2:** boot sets `canonical_is_current = false` ([:2300](../crates/ledger/src/service.rs#L2300)),
  so after *any* reload every write is a forced compaction; a file whose canonical spelling exceeds the cap
  then wedges every write, reloading on each attempt.
- **Change:** `adopt_external_edits` and `reconcile_file_staged` treat `NotFound` as nothing-to-adopt and let
  the compaction recreate the file from memory; `boot` refuses (or warns loudly, with the count) when the
  `.bean` is absent but a journal or `.lock` sidecar exists; every L-13 reload logs before/after directive
  counts and `finish_recovery` refuses to install a rebuild holding fewer directives than memory unless the
  caller asked for exactly that; boot's journal budget becomes `MAX_LEDGER_FILE_BYTES` (the journal is already
  bounded at append time by the projection at [:2989-2999](../crates/ledger/src/service.rs#L2989-L2999) and the
  compacted file by `persist_atomically`); the `TooLarge` message says a journal older than the `.bean` may be
  a folded leftover; a reload does not by itself force a compaction (carry `canonical_is_current` when the
  reload read the bytes this service last wrote).
- **Files:** [service.rs](../crates/ledger/src/service.rs) (`boot`, `adopt_external_edits`,
  `reconcile_file_staged`, `finish_recovery`, `adopt_reloaded`), [journal.rs:168-184](../crates/ledger/src/journal.rs#L168-L184).
- **Verify:** boot three directives, `remove_file(.bean)`, `open_account` → `Ok`, `directive_count() == 4`,
  file holds four; the `brick` fixture (`C + J > MAX`, `J ⊂ C`) boots with `directive_count == boot(C alone)`;
  a dense 63 MiB hand-written file boots and compacts; after one `recover_failed_commit()` on a healthy
  ledger the next prepare is still `Append`.

### ☑ T63 — The ceiling as one rule, plus the adoption ratchet (H-12) — S
> **Done 2026-09-23 (working tree, not committed).** `lamport_value_is_legal(v) := v + 1 < CEILING` is the one rule, called by both stamp sites (`next_stamp`, largest stamp `CEILING-2`), the wire (`union_merge.rs`) and both adoption paths. `MAX_LAMPORT_ADVANCE = 2^32`; `check_lamport_advance` refuses `remote − local >= 2^32` on the remote and file paths with a new `LamportAdvance` error, classified **not permanent** (retried, not cached). Boot clock counts inserted directives plus quarantined ones authored by this node. Boot warns exactly when authoring will be refused (the stamp predicate on `clock + 1`, so it fires at `CEILING-2` too — a deliberate deviation from the tracker's `clock + 1 >= CEILING`) and again within 2^32 of the ceiling. `LamportCeiling` names the author and the mesh-wide remedy. **Fresh-join decision:** no first-contact exemption — an exemption would hand an allowlisted peer the one-step jump on every new node. Honest histories fit (`test_fresh_node_converges_with_a_history_reaching_1e9`), and larger totals converge over retried rounds because parents carry smaller lamports (`test_ratchet_refusal_is_retried_and_a_stepped_history_converges`, 3e9 → 12e9 in 4 rounds). Orchestrator re-ran the variant proof: the directive A authors at `CEILING-2` is adopted by B. **Behaviour change:** `2^53−1` is now refused everywhere; `LAMPORT_ADVANCE` is a new error. **Residuals:** a mesh already holding a single >2^32 jump cannot be joined until that directive is removed; the ratchet slows exhaustion to ~2^21 attributable directives rather than preventing it — the allowlist remains the control.
- **Why:** H-07 is only partially closed. `checked_lamport` ([service.rs:929-934](../crates/ledger/src/service.rs#L929-L934))
  is applied to `clock + 1` at the stamp sites ([:2737, :2759](../crates/ledger/src/service.rs#L2737)), to
  `value` on the wire ([union_merge.rs:289-292](../crates/p2p/src/union_merge.rs#L289-L292)) and to
  `max(local, remote) + 1` at adoption ([:4678-4681](../crates/ledger/src/service.rs#L4678-L4681)), so
  `CEILING-1` is stamped and accepted on the wire but refused at adoption. One peer directive at `CEILING-3`
  makes every adopter author one silently unreplicable record and then brick on restart; the boot warning
  ([:2231](../crates/ledger/src/service.rs#L2231), `>= CEILING`) never fires for the reachable `CEILING-1`;
  `max_lamport` is scanned before every quarantine skip ([:2088](../crates/ledger/src/service.rs#L2088)), so
  the quarantine writes the poison back forever; and removing the line is undone by the next anti-entropy
  tick. The repository's own tests pin both halves of the contradiction (`union_merge.rs:2160-2165` vs
  `service.rs:7337`). Proofs: A1 `h07proof`, A5 `r1_*`, `r1_bootwarn`.
- **Decision (taken): the adoption ratchet is in scope.** Honest traffic advances the clock by one per
  stamp, so a per-directive advance bound of **2^32** never fires for an honest mesh (even a replica offline
  for years) and stops a single directive from walking a node to the ceiling.
- **Change:** one rule stated on the *adopted* value — stamp refuses when `next + 1 >= CEILING` (largest
  stamp `CEILING-2`), wire requires `value + 1 < CEILING`, boot warns when `clock + 1 >= CEILING`; adoption
  additionally refuses a directive whose `max(local, remote) + 1` exceeds `local + 2^32` (a new
  `ServiceError`/`MergeError` variant, **not** cached by the refusal cache since it is state-dependent);
  boot warns when the file's clock is within 2^32 of the ceiling; `max_lamport` counts inserted directives
  only unless `openledger-author` is this node; `LamportCeiling` names the author id and states the
  mesh-wide remedy (allowlist removal plus coordinated removal on every node).
- **Files:** [service.rs:916-934, 2088, 2223-2238, 2737, 2759, 3938-3991, 4678-4757](../crates/ledger/src/service.rs#L916),
  [union_merge.rs:286-296](../crates/p2p/src/union_merge.rs#L286-L296), [anti_entropy_alpn.rs:1409-1437](../crates/gl-node/src/anti_entropy_alpn.rs#L1409-L1437)
  (classification of the new variant).
- **Verify:** the `h07proof` shape ends in peer acceptance of the last authored directive; the restart half of
  `test_authoring_refuses_at_the_lamport_ceiling` asserts the warning fires at `CEILING-1`; a remote directive
  at `local + 2^32 + 1` is refused and does not move the clock; a remote directive at `local + 2^32 − 1` is
  adopted; property test: no reachable ingest path can push the clock past `CEILING − 1` or by more than 2^32
  in one step. Bug-catch proof against each of the three predicates separately.

### ☑ T64 — Bounded parent choice (H-16) — S
> **Done 2026-09-23 (working tree, not committed).** `choose_parents` keeps the 256 smallest admissible heads, used by the local stamp and file adoption; `validate_parent_fan_in` runs before the local insert; `MAX_UNMERGED_HEADS_PER_AUTHOR = 256` enforced on the remote path via `dag.heads_authored_by` with a new `UnmergedHeadLimit` error, not permanent. Honest shapes pinned: a first parentless transaction on an empty ledger and any transaction naming a current head are admitted. Orchestrator re-ran the variant proof: 257th single-author head refused; victim names 256 parents, peer accepts, reboot quarantines 0, balance 252. **Residual:** smallest-id parent choice lets an attacker who grinds small ids hold honest heads unmerged by this node; costs frontier size only, capped per author.
- **Why:** `stamp_transaction_envelope` names **every** admissible head with no cap
  ([service.rs:2746-2748](../crates/ledger/src/service.rs#L2746-L2748)) and the local insert
  ([:2479](../crates/ledger/src/service.rs#L2479)) runs no `validate_parent_fan_in`; the remote path accepts
  parentless transactions on a non-empty ledger ([union_merge.rs:226](../crates/p2p/src/union_merge.rs#L226),
  [service.rs:4636-4646](../crates/ledger/src/service.rs#L4636-L4646) form only). 257 valid parentless
  transactions (~64 KB) from one peer make the victim's next append name 257 parents: refused by every peer,
  and quarantined out of the victim's own DAG at its next boot — its own posting vanishes from its own
  balances — while the planted heads re-inflate so it repeats. Proof: B6 `heads_inflation_makes_local_append_over_cap`.
- **Decision (taken): the per-author unmerged-head bound is in scope, at 256.** An honest author holds
  about one unmerged head at a time.
- **Change:** when admissible heads exceed `MAX_PARENTS`, name the `MAX_PARENTS` lexicographically smallest
  and let the rest merge on later appends; run `validate_parent_fan_in` before the local insert as an
  invariant; on the remote path refuse a transaction that names no current head while its author already
  owns ≥ 256 heads (state-dependent → not cached by the refusal cache; classify accordingly).
- **Files:** [service.rs:2732-2757, 2474-2482, 4588-4770](../crates/ledger/src/service.rs#L2732),
  [dag.rs:411-441](../crates/ledger/src/dag.rs#L411-L441) (a `heads_by_author` view if needed),
  [anti_entropy_alpn.rs:1409-1437](../crates/gl-node/src/anti_entropy_alpn.rs#L1409-L1437).
- **Verify:** stage `MAX_PARENTS + 1` parentless remote transactions, append locally, assert the stored
  directive passes `validate_parent_fan_in`, a second service accepts it, and reboot quarantines nothing;
  the 257th parentless transaction from one author is refused while a 256th is admitted; a transaction from
  the same author that names a current head is always admitted.

### ☑ T65 — Exact, order-independent balances (H-17) — M
> **Done 2026-09-23 (working tree, not committed).** Cap `MAX_AMOUNT_SIGNIFICANT_DIGITS = 21` (`validate.rs`): 2^26 postings × (10^21 − 1) < 2^96, so no same-scale sum can round, with 8× headroom over the M-35 worst case. Enforced in the parser (`from_str_exact` plus the cap — fractions over 28 digits are refused, no longer silently rounded), the GraphQL scalar, `validate_transaction` (inputs and the resolved elided leg), `enforce_resource_limits` for non-transaction directives, and the boot quarantine chain. **Design deviation from the tracker, accepted:** no scale cap. A scale ≤ 8 cap would make ordinary unit × rate legs (scale ≥ 10) unrecordable and quarantine existing history. Instead `ExactSum` keeps one exact partial per `(account, currency, scale)`, combined in ascending-scale order at read time, so the result is independent of arrival order by construction and no canonical re-fold is needed (which would have made gossip catch-up quadratic). No `saturating_*` remains on the validated path; an impossible overflow falls back without panicking and is counted by `over_cap_posting_count()`. Permanent 256-case proptest compares arrival order vs `build` vs reverse vs batched vs a shuffled replica, as printed text. Orchestrator re-ran the ±MAX peer proof: both refused, balance 7 on every view and after reboot. **Behaviour change:** amounts over 21 significant digits are refused; a mixed-scale balance may print with different trailing zeros than before. **Residuals:** exact i128 accumulation stays a design item; I1 products can round inside `rust_decimal` past scale 28 (deterministic); `verify` does not yet report `over_cap_posting_count() > 0`.
- **Why:** `saturating_add` is not associative and neither is `Decimal` addition across a >28-digit scale
  gap; live reports fold in arrival order ([read_model.rs:182, 617](../crates/ledger/src/read_model.rs#L182)),
  `verify` and boot fold in date order ([:539](../crates/ledger/src/read_model.rs#L539)); no magnitude cap
  exists at [parse.rs:195](../crates/ledger/src/parse.rs#L195), [scalars.rs:57](../crates/gl-node/src/graphql/scalars.rs#L57)
  or `enforce_resource_limits`. Two ~120-byte directives from a peer (`+MAX` later-dated, `−MAX`
  earlier-dated) zero any open account's live balance on a chosen replica while `verify` reports every
  assertion passing; a reboot changes the number; replicas holding the same set disagree. Proof: B6
  `saturating_sums_are_order_dependent`, `remote_path_admits_decimal_max_postings`.
- **Decision (taken): magnitude cap now; exact i128 accumulation deferred.**
- **Change:** refuse at every ingress — local API, `stage_remote_directive`, reconcile — any amount whose
  mantissa exceeds 10^22 (≈14 integer + 8 fractional digits), and quarantine such a directive at boot (H-08
  shape: kept in the file, out of the DAG, banner names it); with that bound every per-currency sum is exact
  in `Decimal`, so replace `saturating_add` with `checked_add` that cannot fail; fold the no-`at` path in
  canonical `(date, type priority, content id)` order so live reports and `verify` agree by construction;
  the cap is a single constant referenced by `validate.rs`, the GraphQL scalar and the wire validator.
- **Files:** [read_model.rs](../crates/ledger/src/read_model.rs), [validate.rs](../crates/ledger/src/validate.rs),
  [weights.rs](../crates/ledger/src/weights.rs), [parse.rs:158-197](../crates/ledger/src/parse.rs#L158-L197),
  [scalars.rs](../crates/gl-node/src/graphql/scalars.rs), [union_merge.rs](../crates/p2p/src/union_merge.rs),
  [service.rs](../crates/ledger/src/service.rs) (boot quarantine arm, `enforce_resource_limits`).
- **Verify:** the B6 proptest as written (random arrival order vs `build` vs batched, with `±MAX` and mixed
  scales, checked at every prefix) passes; an over-cap amount is refused on all three ingress paths and
  quarantined at boot; `account()` equals the batched sweep at all times; CT-9 still byte-identical.
- **Residual to record:** the i128 route (exact for any magnitude) stays open as a design item.

### ☑ T66 — Bounded errors and unsolicited input on the wire (H-18, M-41, L-60) — S/M
> **Done 2026-09-23 (working tree, not committed).** `parse_file_bounded` + `count_directive_headers`; `validate_supply_entry` now refuses cheaply first (content-id form, body length, envelope, one directive block) and parses with three errors kept, each ≤ 256 chars. Re-measured: the `"x\n"` × 512k shape went from 194.9 MB / 55 MB of log to **136 B / 87 B**. Bounded echoes everywhere on the intake/drain path (`log_error`), `frame=variant_name()`, keyword excerpt 60 chars, long envelope keys by length. HTTP: one process-wide throttle for guard refusals (one line per 10 s with `suppressed=N`, values cut at 128 chars) and `max_buf_size` 64 KiB. L-60: `fetch_want_chunk` keeps only Wanted ids; pushed Supply frames record no refusals (`SupplyOrigin`). **Behaviour changes:** a Supply entry with a malformed id is refused before parsing; HTTP heads over ~64–112 KiB get 431; new error texts and log fields. **Residuals:** a single 1 MiB bad line still peaks at 6× in the per-character scanner; pushed Supply frames are still fully validated (bounded); the unsolicited-entry warning is per round, not rate-limited.
- **Why:** `validate_supply_entry` ([union_merge.rs:152-154](../crates/p2p/src/union_merge.rs#L152-L154))
  runs `parse_file`, which pushes one `ParseError` per block with no cap ([parse.rs:592-599](../crates/ledger/src/parse.rs#L592-L599)),
  then Debug-renders and joins them all; a 1 MiB body of `"x\n"` × 524,288 costs **194,924,029 B (185.9×)**
  and a **55 MB** `warn!` line at [anti_entropy_alpn.rs:1156](../crates/gl-node/src/anti_entropy_alpn.rs#L1156);
  32 such frames per peer ≈ 6 GB transient. **M-41:** the request guard's `warn!(%host)`/`(%origin)`/
  content-type lines ([request_guard.rs:84, 105-108, 130](../crates/gl-node/src/request_guard.rs#L84)) sit
  outside the rate limiter and echo up to hyper's 417,792-byte head buffer (`serve_hardened` sets no
  `max_buf_size`) — measured 100–190 MB/s of log from one client; on the ALPN side `ContentHashMismatch{claimed}`
  ([union_merge.rs:173-176](../crates/p2p/src/union_merge.rs#L173-L176)), the envelope-key echo (:305-307),
  the keyword echo ([parse.rs:723, 758](../crates/ledger/src/parse.rs#L723)) and `warn!(?other)` at
  [anti_entropy_alpn.rs:996](../crates/gl-node/src/anti_entropy_alpn.rs#L996) are unbounded. **L-60:** every
  Supply entry is recorded as an intake refusal whether or not it was Wanted
  ([:1140-1158](../crates/gl-node/src/anti_entropy_alpn.rs#L1140-L1158)), so a peer fills its own 4,096
  quota and four peers FIFO-evict everyone's. Proofs: B5 `merge`, B4 live probes, B3 `[5]`.
- **Change:** a `max_errors` variant of `parse_file` for the remote path (first three plus a count, each
  rendered through a 256-char `BoundedSink`-style truncation, never `collect`ing the full vector); run the
  cheap refusals (`is_content_id(entry.id)`, envelope key set, author allowlist, signature form) before the
  parse; make `BoundedSink` a `pub` bounded formatter and use it at every `warn!(%error …)` on the
  intake/drain path (:1138, :1146, :1156, :1250, :1494, :1500, :1516); `ContentHashMismatch` carries
  `claimed` only when `is_content_id`, else its length; `warn!(?other)` → variant name; keyword and
  envelope-key excerpts like `reject_trailing_content` (60 chars); throttle the pre-auth guard `warn!`s the
  way `PerIpConnections::should_log_refusal` does, truncate echoed header values, set `http1().max_buf_size()`;
  filter Supply entries to the outstanding `remaining` set in `fetch_want_chunk` and in the serve loop's
  pushed-Supply arm before `apply_supply_entries` (drop + count unsolicited).
- **Files:** [union_merge.rs:143-176, 303-320](../crates/p2p/src/union_merge.rs#L143),
  [parse.rs:545-603, 723, 758](../crates/ledger/src/parse.rs#L545) (**not** `:195` — T65 owns that),
  [protocol.rs:569-640](../crates/p2p/src/protocol.rs#L569) (`BoundedSink`),
  [anti_entropy_alpn.rs:511, 996-1017, 1086-1341](../crates/gl-node/src/anti_entropy_alpn.rs#L996),
  [request_guard.rs:58-139](../crates/gl-node/src/request_guard.rs#L58-L139),
  [http_server.rs:229-395](../crates/gl-node/src/http_server.rs#L229-L395).
- **Verify:** the `"x\n"` × 512k entry under `decode_memory.rs`'s counting allocator peaks ≤ 4× the body and
  `error.to_string().len() < 1024`; every echo shape (2 MiB id, 15 MiB envelope key, 1 MiB keyword, a
  HaveHeads page) renders `< 512` chars; N foreign-Host refusals emit ≤ K log lines and never echo more than
  T bytes; a Supply reply containing an unwanted id records no refusal and is not validated.

---

## Tier 2 — the filesystem boundary and the journal

### ☐ T67 — File-type discipline for every ledger-side open (M-36, L-57, L-58, L-59, R-17) — S/M
- **Why:** `append_record` ([journal.rs:291-306](../crates/ledger/src/journal.rs#L291-L306)) refuses only a
  symlink, then `open(O_WRONLY|O_APPEND|O_CREAT)` — on a FIFO this blocks before the post-open `is_file()`
  runs, **on the blocking thread that owns the `WritePermit`**: every writer waits on the gate forever,
  reads and `/health` stay green, SIGTERM's compaction waits forever, the restart parks in `read_journal`
  ([:168-184](../crates/ledger/src/journal.rs#L168-L184)) with no exit code. `read_ledger_file`
  ([service.rs:218-226](../crates/ledger/src/service.rs#L218-L226)) and `FileState::from_path`
  ([file_watcher.rs:108](../crates/ledger/src/file_watcher.rs#L108)) have the same stat-then-read shape: a
  FIFO passes the cap at `len == 0` and then streams past it (73 MB loaded through a 64 MiB cap), a symlink is
  read through. Confirmed by four passes, twice with the real binary. **L-57:** a directory at the predictable
  `.tmp` ([service.rs:160-167](../crates/ledger/src/service.rs#L160-L167)) makes `remove_file` fail →
  every full rewrite fails. **L-58:** the journal's owner, mode and link count are never checked; a
  pre-planted 0644 or hard-linked journal receives every commit. **L-59:** `ledger_lock::acquire`
  ([ledger_lock.rs:89-101](../crates/gl-node/src/ledger_lock.rs#L89-L101)) follows a symlink. The key reader
  ([p2p_service.rs:898-926](../crates/gl-node/src/p2p_service.rs#L898-L926)) has a narrow lstat→open race.
- **Decision (taken): `libc` becomes a direct dependency** (already compiled into `gl-node` transitively;
  zero new code). Keep "no hand-written FFI in production" as the invariant and replace the `geteuid` block.
- **Change:** one helper for every ledger-side open: `symlink_metadata` → require a regular file →
  `open(O_NOFOLLOW | O_NONBLOCK …)` → `fstat` → require `is_file()`, `(dev, ino)` match, `uid == geteuid()`,
  `nlink == 1`, `mode & 0o077 == 0`; every read goes through `handle.take(MAX_LEDGER_FILE_BYTES + 1)` and
  refuses past the cap; `boot` refuses a non-regular `.bean`/`.journal` outright (the node never creates
  one); the watcher's read runs in `spawn_blocking`; `persist_atomically` uses a randomised temp name
  (`.tmp.<pid>.<nonce>`) with a boot-time sweep under the lock; `ledger_lock` refuses symlinks and checks
  the handle. The `.bean` may deliberately be a symlink in some deployments — refuse non-regular *after*
  following if so, but never block.
- **Files:** [journal.rs](../crates/ledger/src/journal.rs), [service.rs:118-240](../crates/ledger/src/service.rs#L118-L240),
  [file_watcher.rs:88-140](../crates/ledger/src/file_watcher.rs#L88-L140), [ledger_lock.rs](../crates/gl-node/src/ledger_lock.rs),
  [p2p_service.rs:895-1050](../crates/gl-node/src/p2p_service.rs#L895), `crates/gl-node/Cargo.toml`,
  `crates/ledger/Cargo.toml`.
- **Verify:** `mkfifo` at `.bean`, `.journal`, the key path → `boot`/`append_record`/`from_path` return
  `Err` within the test's timeout; a symlink at each → `Err`; a directory at `.tmp` → the write succeeds; a
  pre-created 0644 journal and a hard-linked journal → `append_record` is `Err` and the file is unchanged; a
  symlink at `.lock` → `acquire` is `Err` and the target is not locked; a 64 MiB + 1 stream →
  `ResourceLimitExceeded`; `grep unsafe crates/*/src` outside `#[cfg(test)]` is empty.

### ☐ T68 — Journal policy (M-43, M-44) — S
- **Why:** R-18 confirmed three times: a mid-file header whose length exceeds the remainder is classified as
  a torn tail ([journal.rs:224-233](../crates/ledger/src/journal.rs#L224-L233)), boot loads only the prefix,
  the warning ([service.rs:1957-1966](../crates/ledger/src/service.rs#L1957-L1966)) says the node "crashed
  mid-append" and the record "never reported success" — both false — and the startup compaction unlinks
  the journal. Not reachable by a crash (no `Append` is ever chosen while a torn tail is outstanding);
  reachable by one flipped digit or journal write access. **M-44 (plausible):** a crash-time zero-filled
  final payload on a metadata-first filesystem is a complete header with the wrong hash → `Corrupt`
  ([:237-244](../crates/ledger/src/journal.rs#L237-L244)) → boot refusal, on a file the node wrote.
- **Decision (taken): fail closed; torn journals are renamed, never unlinked.**
- **Change:** a header whose length exceeds the remainder is `Corrupt` when the remainder contains a later
  `\n;;olj ` line or the claimed length exceeds the journal budget (a node-written payload can contain
  neither — control characters are refused in every string field, `pending_block` passes no comments);
  after any boot that saw `torn_tail_bytes > 0`, the compaction renames the journal to
  `<journal>.torn-<unix-ts>` and logs its path; a **final** record whose payload contains a NUL byte is a
  torn tail, not corruption; fix the warning text and the module doc's "cannot be produced by a crash" and
  "fails closed on its hash" (it is an unkeyed checksum) claims.
- **Files:** [journal.rs:168-282, 356-378](../crates/ledger/src/journal.rs#L168), [service.rs:1510-1553,
  1957-1966](../crates/ledger/src/service.rs#L1510).
- **Verify:** the R-18 fixture (`86 → 986`, `999999`, `10^23`, `u64::MAX`) → `Err(Corrupt)` naming the
  offset; the `zero-fill` fixture boots with a torn warning; a real torn tail leaves a `.torn-*` sidecar and
  the next boot ignores it; `l41_*` still pass.

### ☐ T69 — Cost bounds on the read, watch and near-cap paths (M-39, M-42, M-45, L-63, L-65, L-35/R-19, L-43/R-20) — M
- **Why:** **M-39:** [anti_entropy_alpn.rs:1281](../crates/gl-node/src/anti_entropy_alpn.rs#L1281) calls
  `prepare_or_recover` with the ledger **write guard** held and the prepare-failure arm reloads inline
  ([ledger_commit.rs:353-370](../crates/gl-node/src/ledger_commit.rs#L353-L370)); near the cap a 256-entry
  batch fails the projection deterministically, is rolled back, is not cached, and is re-Wanted next tick —
  measured 3.65 s of write-lock hold per tick per peer, forever. **M-42:** `FileState::from_path`
  ([file_watcher.rs:90-112](../crates/ledger/src/file_watcher.rs#L90-L112)) reads and hashes the whole file
  every 250 ms tick regardless of change — 216 ms/tick on 59 MiB (86% of a core), `Burst` semantics
  ([main.rs:412-422](../crates/gl-node/src/main.rs#L412-L422)). **M-45:** the `journal` resolver's weight
  ignores `limit` and child complexity ([query.rs:195-196](../crates/gl-node/src/graphql/query.rs#L195-L196))
  and `domain_txn_to_graphql` re-hashes per row (:383-388). **L-63:** `VerifyReport.errors` is one per
  dangling edge ([verify.rs:164](../crates/ledger/src/verify.rs#L164)): 1,024,000 errors / 166 MiB.
  **L-65:** the byte budget charges the frame body only. **L-35/R-19:** `contains_directive`/`is_head`/
  `sorted_directive_ids` have zero production callers; `all_directive_ids()` still cloned at :801, :1020, :1581.
- **Change:** an async `prepare_or_recover` that drops the guard and reuses `recover_off_lock` (the permit
  is already held), with call-site changes in `mutation.rs`, `anti_entropy_alpn.rs` and `main.rs`; in
  `apply_supply_entries`, ask the service for its append headroom before staging and skip the batch with a
  `warn!` and a **transient** per-peer backoff (not the refusal cache); watcher: keep the last
  `(len, mtime, ino)`, read + hash only when it changed or every Nth tick, run the read in `spawn_blocking`,
  `MissedTickBehavior::Delay`; `journal` complexity = `(clamp_journal_limit(limit) / 100).max(1) * (1 +
  child_complexity)` (or a per-request row cap across aliases), pass `txid` instead of re-hashing (also for
  `transaction(txid)`); cap `VerifyReport.errors` at the first 1,000 plus a `truncated` count, per node;
  switch the three `all_directive_ids()` callers (needs `compute_want`/`paginate_have_heads` variants in
  `p2p` that take a lookup and a sorted slice); document the byte budget's real multiple (≈ body + decoded +
  `Content` + staged).
- **Files:** [ledger_commit.rs](../crates/gl-node/src/ledger_commit.rs), [mutation.rs:85-290](../crates/gl-node/src/graphql/mutation.rs#L85),
  [anti_entropy_alpn.rs:794-813, 1018-1027, 1086-1341, 1567-1622](../crates/gl-node/src/anti_entropy_alpn.rs#L1086),
  [anti_entropy.rs:35-116](../crates/p2p/src/anti_entropy.rs#L35), [file_watcher.rs](../crates/ledger/src/file_watcher.rs),
  [main.rs:412-495](../crates/gl-node/src/main.rs#L412), [query.rs:11-62, 195-240, 281-320, 383-388](../crates/gl-node/src/graphql/query.rs#L195),
  [verify.rs:140-204](../crates/ledger/src/verify.rs#L140), [connection_limiter.rs](../crates/gl-node/src/connection_limiter.rs) (docs).
- **Verify:** near-cap fixture, one 256-entry `apply_supply_entries`: the `RwLock` is never held > 100 ms
  (probe with a concurrent timed `read()`) and a second call does not re-stage; two consecutive watcher
  polls of an unchanged file perform one read; eight aliased `journal(limit: 10000)` with a postings
  selection is refused while a dashboard call still fits; `verify` on the 4,000 × 256 fixture returns ≤ 1,000
  errors + a count; `l35_*` plus a test that the advert equals `all_directive_ids()` after every insert path.

### ☐ T70 — Server-side session deadline and cross-peer cap (M-40, M-06, R-5, R-7) — S/M
- **Why:** `serve_anti_entropy` uses only the per-frame `io` ([anti_entropy_alpn.rs:353](../crates/gl-node/src/anti_entropy_alpn.rs#L353),
  `accept_bi` :422, reads :478) and `max_requests_per_connection`; `timeouts.session` is consumed by the
  client only ([:245](../crates/gl-node/src/anti_entropy_alpn.rs#L245)). A ~30 B `Announce` every 29 s holds
  a slot for ≈ 34 days; one peer pins 12.5% of the 256 global slots, eight pin all. Each 40 B
  `HaveHeads{more:false}` costs a full O(N) local advert under the read lock, bounded per connection but not
  across free reconnects. **R-5:** `InFlightGuard` is per-peer only; nothing bounds exchanges across peers
  (≈130–150 MiB resident per hostile exchange × allowlist). **R-7:** the T49/T58 bounds have no config surface.
- **Change:** a server `SessionBudget` whose deadline clamps `accept_bi` and every frame's `io`, closing
  with a distinct code; a per-peer accept token bucket in `ConnectionLimiter::try_acquire`; a semaphore
  across concurrent outbound exchanges sized against the allowlist; config keys for the session, page, id-byte
  and frame bounds under `p2p.antiEntropy*`, validated like the existing interval.
- **Files:** [anti_entropy_alpn.rs:137-275, 348-546](../crates/gl-node/src/anti_entropy_alpn.rs#L348),
  [connection_limiter.rs](../crates/gl-node/src/connection_limiter.rs), [p2p_service.rs:426-632](../crates/gl-node/src/p2p_service.rs#L426),
  [config.rs](../crates/gl-node/src/config.rs), README options table.
- **Verify:** a client sending `Announce` every `io/2` past `session` is closed with the session code; a
  peer reconnecting in a tight loop is admitted at the bucket rate only; with an allowlist of N + 1 peers at
  most N exchanges run concurrently and the healthy peer still converges.

---

## Tier 3 — documentation, configuration and hygiene

### ☐ T71 — Docs, config and small hygiene (L-56, L-61, L-66, L-23/R-9, R-13, §5 items) — S
- **Decisions (taken):** `meshId` gets a boot `warn!` now and ships in `deploy/gl-node.docker.json`,
  required a release later; a `CHANGELOG.md` is added.
- **Change:** `validate_signature_domain`'s whitespace arm ([config.rs:1063-1065](../crates/gl-node/src/config.rs#L1063-L1065))
  prints `crate::auth::redact(value)` or the byte offset, never the value (L-56); the per-IP cap docs
  ([http_server.rs:73-79](../crates/gl-node/src/http_server.rs#L73-L79), README:462) carry the /48 caveat
  `rate_limit.rs:10-19` already states, and over-cap addresses get a short admission cooldown (L-61); GraphiQL
  pins a version with SRI or is self-hosted ([graphql/mod.rs:107](../crates/gl-node/src/graphql/mod.rs#L107), L-66);
  `main.rs:311` becomes a `warn!` when `meshId` is unset whose remedy text leads with *"set it to your current
  `swarmTopic` verbatim"*, README §Mesh identity says the same and stops recommending `uuidgen` for an
  existing mesh, `deploy/gl-node.docker.json` sets `meshId` (R-9); `CHANGELOG.md` covers `externalFileEdits`
  → `watchLedgerFile`, `/health` 403/429, `maxConnectionsPerIp`, HTTP/1.1-only (no h2c), the printable-ASCII
  `apiKey` rule, `"null"`-origin refusal, plain-`http` `Origin` refusal under `terminated`, new config keys
  vs older binaries, and every T61–T70 behaviour change (R-13); `allowedHosts` entries with a port or
  trailing dot are refused at boot; `GL_NODE_API_KEY` with `auth.enabled: false` warns; document `OPTIONS`
  (Allow-header fingerprint), `Origin` localhost/127.0.0.1 equivalence, "error but durable" on
  `remove_journal` failure, and the unkeyed journal hash.
- **Files:** [config.rs](../crates/gl-node/src/config.rs), [main.rs:300-320](../crates/gl-node/src/main.rs#L300),
  [http_server.rs](../crates/gl-node/src/http_server.rs), [graphql/mod.rs](../crates/gl-node/src/graphql/mod.rs),
  [README.md](../README.md), [deploy/gl-node.docker.json](../deploy/gl-node.docker.json), `CHANGELOG.md` (new).
- **Verify:** the padded-topic boot error does not contain the topic; a port entry in `allowedHosts` is a
  `ConfigError::Validation`; boot with `meshId` unset logs a WARN naming `swarmTopic`;
  `test_shipped_sample_configs_still_validate` passes with `meshId` in the docker config.

---

## Residuals carried into this backlog (unchanged, for the record)

- **R-8** (runtime-teardown `JoinError` without recovery; `mem::forget`) — documented, shutdown-only.
- **R-10** — an over-cap directive or a lamport ≥ 2^53 already on disk loads, is served, and is refused by
  peers; the L-34 cache bounds the churn. Retire-by-repair remains manual.
- **R-14 / R-15** — `verify` on the read lock; `balance` directives admitted without account existence.
- **R-16** — the 900 ms perf budget; monitor.
- **§5 informational items** in the v2 report (OPTIONS fingerprint, `validate_supply_entry` ordering,
  `AccountClosed` drain churn, non-canonical envelope spellings, parents naming non-transaction ids,
  zero-unit `@@` and zero-posting transactions, `trial_balance` netting currencies, the two swallowed
  directory `fsync`s, `finish_recovery`'s stale `force_compaction`, the unpinned `LEGAL_*` constants, G-1).

---

## Regression-test manifest (must exist by the end of Tier 1)

1. Stop-edit-start: the hand-typed record carries this node's envelope and signature after boot + startup
   compaction, and a second service accepts it (T61 / H-13).
2. A failed reconcile is followed by a write that returns `PARSE_ERROR` and leaves both hand-written lines on
   disk, on both sides of the compaction threshold (T61 / H-14).
3. `remove_file(.bean)` under a running service → the next write succeeds and the file holds every directive
   (T62 / H-15); the `brick` fixture boots (T62 / M-35).
4. Ingest at `CEILING-3` → the next authored directive is accepted by a peer; the restart half warns at
   `CEILING-1`; a remote advance of 2^32 + 1 is refused (T63 / H-12).
5. `MAX_PARENTS + 1` parentless remote transactions → the local append passes fan-in everywhere and reboot
   quarantines nothing; the 257th unmerged head from one author is refused (T64 / H-16).
6. The order-independence proptest at every prefix with `±MAX` and mixed scales; an over-cap amount refused
   on all three ingress paths (T65 / H-17).
7. The `"x\n"` × 512k Supply entry peaks ≤ 4× and renders < 1024 chars; N foreign-Host refusals ≤ K log lines
   (T66 / H-18, M-41).

Every one needs its **bug-catch proof** — revert the fix, watch the named test fail, restore — and the
orchestrator re-verifies each mechanism in source and re-runs the suite three times on a quiet machine.

---

*Audit: [SECURITY_AUDIT_0922-v2.md](../SECURITY_AUDIT_0922-v2.md). Previous trackers:
[OUTSTANDING_TASKS_09_22.md](OUTSTANDING_TASKS_09_22.md) (T46–T60, R-1…R-21) ·
[OUTSTANDING_TASKS_09.md](OUTSTANDING_TASKS_09.md) (T18–T45) · [OUTSTANDING_TASKS.md](OUTSTANDING_TASKS.md)
(T1–T17). Format v2 design: [FORMAT_V2_DESIGN.md](FORMAT_V2_DESIGN.md).*
