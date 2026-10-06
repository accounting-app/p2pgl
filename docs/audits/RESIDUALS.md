# Residual close-out (draft, 2026-10-07)

Every item the audits and their fix rounds recorded but did not number as a
finding — the trackers' "Residuals carried … (for the record)" sections, each
task's **Residuals** note, and the reports' unassigned §5 informational items —
with one final disposition each. Numbered findings (H-01 … H-25, M-01 … M-76,
L-01 … L-157) are all closed; see the trackers.

**Fixed** — closed by later work; the evidence is named. **Fix** — proposed for
this close-out, each with a test and a revert check. **Accept** — a known limit
we keep, for the reason given; the maintainer's sign-off makes it final.

Status: **draft — dispositions awaiting the maintainer's approval.**

## A. Decisions and older residuals carried since 09/22

| # | Item | Source | Disposition |
|---|---|---|---|
| A1 | H-01: loopback API key deferred | 0927 tracker, carried | **Fixed** — auth on by default, generated key file (2026-10-05) |
| A2 | M-10 / L-06: closed only behind Format v2 | 0927 tracker, carried | **Fixed** — Format v2 on by default (`963cb4d`) |
| A3 | M-09: T98 by decision (54) | 0927 tracker, carried | **Fixed** — T98 (`7e4750b`) |
| A4 | L-23 / R-9: `meshId` required "next release" | 0927 tracker, carried | **Fixed** — required on a signing node (2026-10-05) |
| A5 | Decision (41): one write under the wrong `meshId` hides the EVERY WARN | 0927 tracker, carried | **Fixed** — writes refused while every signature fails (`f708d87`); `l114_a_node_refuses_to_write_while_every_signature_fails` runs |
| A6 | H-19 by decision (1): anti-entropy-only joins across a removed author's or pre-T63 jump impossible | 0927 tracker, carried | **Fixed in part / Accept the rest** — `p2p.joinFrom` (`fa3a1a3`) joins across a jump from a named peer; a removed author's transaction still needs the file copy (by design: no peer may vouch for an author the mesh removed) |
| A7 | R-8: a runtime teardown can drop a spawned commit (`Io(JoinError)` without recovery); `mem::forget` on a `PendingCommit` leaks its flag | 0922 tracker | **Accept** — shutdown-only, the next boot re-derives from disk; no call site forgets a `PendingCommit` |
| A8 | R-14: `verify` runs on the ledger's read lock (writers wait hundreds of ms on a large ledger) | 0922 tracker | **Accept** — bounded by `MAX_VERIFY_PER_REQUEST` and the weight limiter; the real fix (DAG and read model behind `Arc`) is a large refactor with no current need |
| A9 | R-15: a peer's `balance` directives are admitted without any check that the account exists (unbounded per account; cost now linear) | 0922 tracker | **Fix** — hold a remote `balance` to the data rule's I3 (an `open` of its account at or before its date), waiting on the account like a transaction; covers B3 too |
| A10 | R-16: the M-23 perf test's margin shrinks under load | 0922 tracker | **Accept** — ~4× margin fully loaded; the weekly health check reports it if it ever trips |

## B. T90–T97 residuals (re-checked at 0927)

| # | Item | Disposition |
|---|---|---|
| B1 | A complete envelope refused live for its signature, a stray key the strip cannot remove, or a control character is dropped by the live reconcile where boot quarantines it | **Accept** — operator input typed under a running node; the reconcile summary names each drop, and a restart keeps the line |
| B2 | The wire's "names a held-back parent" branch is reached only by library callers | **Accept** — gl-node never calls it that way |
| B3 | A `balance` / `note` / … on a held account stays as T85 left it | **Fix** with A9 for `balance`; **Accept** for `note`/`document`/`event` (no balance effect) |
| B4 | On a signing-off node "add the missing open" is refused as already open | **Accept** — the summary gives the working remedy (correct the `open`'s date), executed by D1 and X1 |
| B5 | A library caller that never finalises keeps a duplicate hand `open` unrefused | **Accept** — gl-node always finalises |
| B6 | The M-59 parent check is a backstop no known shape reaches | **Accept** — defence in depth |
| B7 | Lines adopted from the file are not served while the compaction keeps failing | **Accept** — the price of decision (45a) |
| B8 | After the L-117 refusal the next compaction renames onto the path (L-44, with L-147) | **Accept** — T100 rolls the failed write back; the rename is the documented recovery |
| B9 | T94's four `unsafe` blocks | **Accept** — each carries a SAFETY argument and a revert-checked test |
| B10 | The directory ACL check is macOS only | **Accept** — Linux is guarded by mode and owner checks; documented |
| B11 | The Want filters run under the buffer's read lock (and the ledger's) | **Fixed** — T102 (L-152): the ledger is read only for the peer's own parents |
| B12 | A root refused but not cached keeps its buffered children re-Wanted (X2 `c3` (b)) | **Accept** — bounded by that peer's own share and the L-34 cache |
| B13 | Four colluding transport ids fill the hint table (¼ shares) | **Accept** — by design: four allowlisted identities |
| B14 | A history of 17 or more sub-2^28 lamport steps partitions a joiner with no WARN | **Fix** — WARN when the ratchet refuses a whole catch-up, naming `p2p.joinFrom` |
| B15 | `l90_*`'s high-water mark runs with an uncharged frame body | **Accept** — test-precision only; L-90's bound is pinned by its own tests |
| B16 | gl-node's capture helpers lack the global subscriber | **Accept** — test infrastructure; no assertion depends on it |
| B17 | T97's boot at 10,000 pairs ~0.25 s slower | **Accept** — within measurement noise |

## C. T98–T103 residuals

| # | Item | Disposition |
|---|---|---|
| C1 | T98: a `close` no longer stops an allowlisted peer's back-dated posting | **Accept** — decision (54a); the peer could author anything else |
| C2 | T98: `is_open` stays the plain fold, so after a peer posts past a `close` the API still says "closed" and allows a re-open | **Accept** — no API exposes lifecycle state; a re-open is harmless data |
| C3 | T98: the authoring exception reads this node's read model | **Accept** — authoring is local by nature |
| C4 | T98: a pre-T98 node refuses what this build accepts (mixed versions) | **Accept** — README: upgrade every node; no mesh is deployed |
| C5 | T98: `account_wait_target` keeps an `AccountClosed` arm remote data can no longer earn; `posting_dates` stays a set | **Accept** — harmless; removing them is cosmetic |
| C6 | T99: the closure's rescue and the boot re-admission overlap | **Accept** — both kept deliberately (hand lines adopted in the same boot name the rescued records) |
| C7 | T99: an alternative installed before a signer exists is judged by the signature pass later | **Accept** — the pass tries the remaining copies |
| C8 | T99: a line typed beside a record that stays served is dropped as a duplicate with no log line | **Fix** — log it, naming the record it duplicates |
| C9 | T99: `alternative_copies` lives for the process | **Accept** — one extra copy per record the file spells twice |
| C10 | T99: no test runs the rule on a small stack | **Accept** — the one-round assertion pins the depth fix |
| C11 | T100: a restart after a failed commit reuses the discarded write's lamport | **Accept** — decision (63a); no peer was ever offered that write |
| C12 | T100: `write_headroom` costs one ledger pass per gated write while a rewrite is pending | **Accept** — the pending rewrite costs the same |
| C13 | T100: the served-id cache is pinned for sharing only | **Accept** — test precision |
| C14 | T100: two lamport-only differential DIFFs, safe direction | **Accept** |
| C15 | T100: the M-74 gl-node test takes ~75 s in debug | **Accept** |
| C16 | T101: the resolved path is used by path afterwards; a writer above the target controls the ledger | **Accept** — true of any `.bean`; stated in README |
| C17 | T101: an allow ACL entry for the node's own user is refused too | **Accept** — fails closed |
| C18 | T101: ACLs enforced by SMB/NFS servers and NFSv4 ACLs on Linux are not seen | **Accept** — documented; not a supported deployment |
| C19 | T101: a 0300 link directory fails the open (`EACCES`) | **Accept** — give the directory read permission; `O_SEARCH`/`O_PATH` are platform-specific |
| C20 | T101: the Linux branch is compiled only by CI | **Accept** — CI builds and tests it on every push |
| C21 | T102: hints stay one per id | **Accept** |
| C22 | T102: a record two peers send with different parents takes a slot in each share | **Accept** — bounded per peer |
| C23 | T102: the real-QUIC test pins the per-peer slot, not the order | **Accept** — the order has its own unit test |
| C24 | T103: "nothing held descends from it" cannot tell a served restatement from none | **Accept** — the WARN states both cases |
| C25 | T103: the banner says "restate … as its warning says" where that warning may say delete | **Fix** — make the banner defer to the per-block WARN |
| C26 | T103: the L-140 live refusal is not held | **Accept** — decision (69a); the refusal says how to keep the record |
| C27 | T103: a hand lamport on this node's own held record can move its clock up to the ratchet | **Accept** — boot already did; bounded |
| C28 | T103: boot served a complete envelope with an elided posting (new, unnumbered) | **Fixed** — `76f2096`, `a_history_record_with_an_elided_posting_is_held_at_boot` |

## D. 0927 §5 informational items not assigned to a task

| # | Item | Disposition |
|---|---|---|
| D1 | T94's fallback resolves twice | **Fixed** — T101 (e) |
| D2 | `O_NOCTTY` missing on the target `openat` | **Fixed** — T101 (f) |
| D3 | SMB/NFS and NFSv4 ACLs not seen | see C18 |
| D4 | A 0300 link directory now `EACCES` | see C19 |
| D5 | `order_want_ancestors_first` reads any peer's copy | **Fixed** — T102 (`order_want_for_peer`) |
| D6 | The hint queue's "twice the table" bound is really ~4× | **Fix** — correct the bound or its documentation |
| D7 | The adoption-time gap WARN is single-step | **Accept** — its text is hedged; B14 adds the missing case |
| D8 | A mixed mesh re-judges after an upgrade | **Accept** — README says to upgrade every node (L-155) |
| D9 | Boot 1's clock can sit below a served record after a swap to a foreign copy | **Accept** — harmless; boot 2 counts it |
| D10 | The reload's clock is one above a Fresh boot's in one shape | **Accept** — errs in the safe direction |
| D11 | Loopback QUIC works for fresh binaries | — observation, no action |

## E. Residuals of the post-audit work

| # | Item | Disposition |
|---|---|---|
| E1 | Format v2: a line typed into the `.bean` keeps v1 identity, so a hand-typed record is still squattable | **Accept** — by design: the repairs every WARN prescribes need the v1 id |
| E2 | Format v2: a build from before Format v2 reads neither v2 records nor the v2 wire | **Accept** — no mesh is deployed; README and CHANGELOG say so |

## To fix in this close-out

A9 + B3 (`balance` admission), B14 (joiner partition WARN), C8 (duplicate-line log),
C25 (banner text), D6 (hint bound). Each as its own commit-sized unit with a test
and a revert check.
