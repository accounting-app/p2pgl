# Format v2 — the coordinated identity / signature / wire version transition (T45)

**Status: IMPLEMENTED (2026-10-04), on by default since 2026-10-06 — decisions 1–3 taken as recommended. See §7 for where the build departs from this design.**
**Date: 2026-09-21 · Baseline: HEAD `13beca5` (T18–T44 complete) · Author: security-campaign orchestrator**

This document designs the one deliberate compatibility break the remediation campaign
deferred, and asks for three decisions at the end. It bundles every finding whose real fix
was postponed "to the next format bump":

| Deferred item | Source | What v2 owes it |
|---|---|---|
| **M-10** authorship squatting (T33 is interim) | 09/01 audit | Fold the author into the content id |
| **L-06** `\|`-concatenated signature message (latent) | 09/01 audit | Length-prefix the signed fields at the next domain bump |
| **T43 option (b)** internally-tagged wire enum | 09/02 backlog | An encoding serde can dispatch on without Content-buffering |

The central design claim: these are **three independent version surfaces**, not one, and
treating them as one flag day is both unnecessary and riskier than the alternative. They
share this document because they were deferred together — not because they must ship
together.

---

## 0. Current state (what exactly is versioned today)

1. **Identity (implicit v1).** `content_id = SHA-256(economic_canonical_serialize(d))`,
   lowercase hex ([hash.rs](../crates/ledger/src/hash.rs)). The canonical serialization
   excludes every `openledger-*` envelope key at both directive and posting level — so the
   id covers only the economic body. Ids are **computed, never carried**: no directive
   transports its own id; every node derives it.
2. **Signature domain (explicit v3).** `openledger-sig-v3|{kind}|{content_id}|parents|{parents}|lamport|{lamport}|mesh|{mesh_id}`
   ([signing.rs](../crates/security/src/signing.rs)), Ed25519 `verify_strict` (T40), domain
   resolved from `p2p.meshId` with `swarmTopic` fallback (T39). L-06's remote injection is
   closed (M-01 constrains the interpolated fields to hex-CSV/decimal), but the format is
   injective only because of those per-field constraints — design debt, not design.
3. **Wire (explicit v1).** `WIRE_VERSION = 1`; `WireMessage` is `#[serde(tag = "type")]`
   (internally tagged), so serde Content-buffers every frame before dispatch. T26/T43/T43b
   bound the damage (pre-caps + the `cbor_scan` header pre-gates); the encoding itself is
   why those gates are load-bearing rather than defence-in-depth.

Everything downstream consumes ids as opaque strings: `openledger-parents` envelope
values in the `.bean` and journal, `Want`/`HaveHeads` id lists, the orphan buffer, the
T29 lifecycle event keys, the read model, GraphQL `txid` outputs.

---

## 1. Facet A — Identity v2: author in the content id (M-10)

### The fix

    id_v2 = SHA-256( "olid-v2" ‖ LP(author) ‖ LP(economic_canonical_serialize(d)) )

where `LP(x)` = 8-byte big-endian byte-length prefix followed by the bytes. Length
prefixing here is deliberate (the L-06 philosophy applied to the id preimage): no
separator to inject, injectivity by construction, and the domain string makes a v2 id
un-confusable with a v1 hash of anything.

**Only the author joins the preimage.** Lamport and parents stay out: including lamport
would break same-author retry idempotency (a client retrying an append after a lost
response would mint a second id once the envelope re-stamps), and parents stay envelope
metadata for exactly the reasons T21/T31 settled.

### What it changes semantically

- **Cross-author squatting dies** (the M-10 attack): a peer publishing your economic body
  first no longer owns "the" directive — its copy is a different id. T33's interim
  `already_existed` signal stays useful (same-author retries still dedupe) but stops
  being a security control.
- **Identical bodies from different authors both apply.** Today the second arrival is
  deduped; under v2 both are real transactions. That is *more* correct for a ledger (two
  people can each spend 5 USD), but it is a real semantic change and the doc's Decision 1
  asks you to own it.
- **Same-author identical bodies still collapse** — unchanged from v1. Two genuinely
  distinct same-day identical purchases still need a distinguishing metadata key. Not a
  regression; documented limitation.
- Replay by a relay is unchanged-or-better: a replayed foreign directive keeps its id
  (author is in the hash, signature covers the id); a body copied under the attacker's
  own key is now simply the attacker's own — signed, attributed, and rate-limited —
  transaction.

### Migration: **an epoch, not a rewrite**

Changing the id function invalidates, in principle, every stored id — including every
`openledger-parents` reference and every stored signature (signatures cover the id). A
history rewrite is a non-starter: **a node cannot re-sign directives authored by other
peers**, so any "re-hash the file" migration ends with either discarded provenance or a
flag-day ceremony involving every key that ever wrote. Instead:

- Each directive carries `openledger-idv: 2` in its envelope from the cutover on.
  Directives without the key are v1 forever. Id computation dispatches on the key.
- **Tamper-evidence:** the version marker is envelope (outside the hash), but the
  signature covers the *resulting id*, so flipping the marker on a signed directive
  changes the computed id and fails verification. On signing-disabled meshes the marker
  is as malleable as everything else already is — no new trust assumption.
- **History is untouched.** Pre-epoch directives keep their v1 ids and their sig-v3
  signatures verify exactly as today. Parents may cross the boundary freely (a v2
  directive citing a v1 parent id is just a string reference).
- Both id functions live in the codebase permanently (or until a future genesis-cut,
  which is explicitly out of scope — §5).
- **Cutover rule:** a node starts *emitting* `idv: 2` when its config says so
  (`format.idv2: true`); it *accepts* both versions always. Rollout is therefore the
  T39 meshId procedure: flip the flag mesh-wide in a maintenance window. Mixed-window
  behavior is safe — a v1-emitting node and a v2-emitting node disagree only about the
  ids of *new, distinct* directives, which are distinct either way; convergence tests
  must prove the mixed window byte-converges after compaction (§4).

### Cost

Two id functions forever; every id-consuming path gains a per-directive version dispatch
(cheap — one envelope lookup); the 66-permutation/byte-identity suites double across the
epoch matrix. The heavy cost is testing, not runtime.

---

## 2. Facet B — Signature v4: length-prefixed message (L-06)

### The fix

    msg_v4 = "openledger-sig-v4" ‖ LP(kind) ‖ LP(content_id) ‖ LP(parents_csv) ‖ LP(lamport_dec) ‖ LP(mesh_id)

Injective by construction; the per-field character-set constraints M-01 imposes become
defence-in-depth instead of the only thing standing between `|` and a forged message.

### Versioning and rollout

- New envelope key `openledger-sigv: 4` on newly signed directives; absent means v3.
  Verifier dispatches on the key; **v3 verification is kept indefinitely** (history is
  signed under it and cannot be re-signed — same argument as Facet A).
- The marker sits outside the hash but inside the signed message? **No** — simpler: the
  domain prefix *inside* the message already states the version, and the envelope key is
  merely the dispatch hint. A stripped/flipped hint makes verification fail (wrong
  format tried), never succeed wrongly. Fail-closed.
- Natural cutover: **the same flag day as Facet A** (`format.idv2` also flips signing to
  v4). They are both "new directives only, history untouched, dual-accept forever"
  changes with identical rollout shape; splitting their flag days doubles the ceremony
  for zero risk reduction. (They remain *logically* independent — if Decision 1 rejects
  author-in-hash, sig-v4 can still ship alone under its own flag.)

### Cost

Trivial next to Facet A: one message builder, one dispatch, a tamper-vector test per
field boundary (the classic "move bytes across a `|`" corpus, which today's format
cannot even express as a test).

---

## 3. Facet C — Wire v2: externally-tagged encoding (T43 option b)

### The fix

Re-declare `WireMessage` externally tagged (serde default): a frame becomes
`{"supply": {...}}` — a one-key map whose key is the variant. ciborium emits the tag
first; serde dispatches on it **without Content-buffering the body**. The T26 pre-cap and
the T43/T43b `cbor_scan` gates stop being load-bearing and become belt-and-braces (they
should stay — they are cheap and they bound even a future regression to internal
buffering inside a variant).

### Negotiation: **a second ALPN, not an in-band version**

The in-band `v` field cannot version the *encoding* (you must decode to read it). Instead:

- New ALPN `openledger/anti-entropy/2` served **alongside** the v1 ALPN by every upgraded
  node (iroh routers accept multiple ALPNs; the serve loop is shared, only the codec
  differs).
- Client side: `format.wire2: true` makes a node dial the v2 ALPN; false (default) keeps
  dialing v1. Same T39-style mesh-wide flip; no per-connection fallback probing (a failed
  dial is ambiguous with a down peer — probing would mask real outages and add a
  downgrade path an attacker on the path could exploit).
- Gossip frames carry no ALPN; the gossip topic string gets the same treatment
  (`swarmTopic` + "/2" derived automatically when `wire2` is on), which cleanly
  partitions mixed-version gossip instead of letting v1 nodes warn-spam on undecodable
  v2 frames.
- After the mesh flips, v1 serving can be retired in a later release (config-gated,
  default-on for one release, then gone).

### Cost

A codec fork during the transition (both encodings compiled, one dial-side switch), the
ALPN/topic plumbing, and a full re-run of the amplification measurements on the v2
decoder (the decode_memory suite gains a v2 twin — expected result: forged-count frames
are refused by the *decoder itself* with peaks near zero, and `cbor_scan` never fires).

### Why Facet C ships FIRST and alone

It is hop-by-hop (no persisted state, no history, no signatures), independently
reversible (flip the flag back), mechanically testable, and it deletes the largest
remaining class of "the guard must be perfect" pressure from the wire path. Shipping it
first also rehearses the T39-style mesh-wide flip on the lowest-stakes surface before
the identity epoch uses the same procedure.

---

## 4. Test obligations (all three facets)

- **Epoch matrix:** the arrival-order/byte-identity suites (T29's permutations, T27's
  batch-equivalence, T44's compaction determinism) run at v1-only, v2-only, and
  mixed-epoch files; mixed windows must byte-converge after compaction.
- **Dual-verify corpus:** golden files carrying real v3-signed v1 directives must verify
  forever; a checked-in fixture pins this against accidental v3 removal.
- **Injectivity property tests:** v2 id preimage and v4 message get proptest coverage
  moving bytes across every field boundary (expressible now that boundaries are LP'd).
- **Squatting regression:** the M-10 attack script (foreign body republished first) —
  asserted *effective* at v1, *ineffective* at v2 — both directions pinned.
- **Wire dual-stack:** three-node convergence with mixed `wire2` flags on the partitioned
  topics; decode_memory v2 twins; downgrade-refusal (a v2-only node never dials v1).
- **Bug-catch discipline** as throughout the campaign: every new guard proven by revert.

## 5. Non-goals

Genesis-cut / history compaction (interacts with T44's journal; separate design if ever
wanted); multi-signature or key-rotation schemes; changing what the economic body
contains; retiring sig-v3 or v1 ids for existing history (impossible without rewriting
provenance — accepted permanently).

---

## 6. Decisions requested

1. **Adopt author-in-hash semantics?** (Facet A — including "identical bodies from two
   authors both apply". This is the substantive product decision; everything else is
   engineering.) *Recommendation: yes.*
2. **Bundle sig-v4 with the identity epoch's flag day?** (Facet B riding Facet A's
   cutover; or ship v4 alone if A is rejected.) *Recommendation: bundle.*
3. **Ship wire v2 first, as its own release, via dual-ALPN + topic suffix?** (Facet C
   decoupled and leading.) *Recommendation: yes — it is the rehearsal for the epoch.*

On approval, T45 becomes three implementation waves in the campaign's established
pattern (spec → Opus implementation → line review → independent verification → tracker),
ordered C → A+B, with the re-audit (Step 6) either before wave C or after A+B — before
is recommended, so the audit baselines the campaign as shipped and v2 lands against a
clean register.

---

## 7. Implementation (2026-10-04)

All three facets ship, each behind its own switch in a new top-level config
section: `format.wire2` (Facet C) and `format.idv2` (Facets A + B, one flag day
as Decision 2 chose). Both default to `false`; every node accepts both formats
regardless.

**Facet C, as designed.** `WireCodec` selects the encoding per connection from
its ALPN (`openledger/anti-entropy/2` served beside v1 by every node) and per
gossip topic (`<swarmTopic>/2`); the client side dials what `format.wire2`
says, with no fallback. The v1 pre-scans are kept and run over the variant's
body map. Measured with `decode_memory`'s v2 twin: forged frames are refused at
a 0-byte peak, and an honest maximal `Supply` decodes at ~1.02× its size — the
same as v1 on this machine, since ciborium's string copies dominate. So the
gain is structural (the encoding no longer depends on the pre-scan to avoid
buffering a frame whole) rather than a measured peak; the pre-scan does still
fire, not "never" as §3 expected.

**Facets A + B, with three departures:**

1. **One marker, not two.** `openledger-format: "2"` selects identity v2 *and*
   signature v4. §1 and §2 proposed `openledger-idv` and `openledger-sigv`;
   with Decision 2 bundling them, a second key would only add a state ("v2 id,
   v3 signature") nothing should produce. The marker has one legal value, and a
   v2 record must name its author (refused on the wire and held at boot
   otherwise).
2. **Only API writes are emitted in v2.** A line typed into the `.bean` keeps
   v1 identity. The repairs every WARN prescribes — "delete its `openledger-*`
   lines so it is re-adopted under the same id" — depend on it: the stripped
   line is then the record's only copy, nothing can tell it from a new line,
   and a v2 id would make it a second record beside the one every peer holds.
   (An "epoch rule" keying on records the node knows was tried first and fails
   exactly there.) A typed line that spells the marker itself stays v2.
   Consequence: a hand-typed record is still squattable as before; API writes —
   the main path — are not.
3. **The signer and verifier callbacks take the record's format.** A node
   signs and verifies each record in the format its own envelope declares, not
   in the node's emitting format. Otherwise a node switching to v2 re-derived
   its own v1 signatures as v4 at boot, found every one "edited" and
   quarantined its whole history.

**Tests** (`crates/p2p/tests/format_v2.rs`, plus unit tests in `hash.rs`,
`security::signing`, `protocol.rs`, `decode_memory.rs` and gl-node): the
squatting regression pinned in both directions; a mixed v1/v2 mesh converging
and surviving restarts; 120 arrival orders of a mixed set converging to
byte-identical files; v1 history verifying after the switch; tamper evidence
(a stripped marker fails the id check); the marker's validation on both paths;
real-QUIC exchanges in both encodings against one server and no fallback to v1.
Every mechanism is revert-proven. The router's v2 registration was the last
without a proof; since 2026-10-05 the two-encoding QUIC test serves through the
production `spawn_router` on a real `PeerNode`, and dropping the v2 ALPN from it
fails that test.

**The epoch matrix (§4), added 2026-10-05.** The three suites §4 names run at
v1-only, v2-only and mixed:
- T29's arrival-order suite (`lifecycle_converges_under_every_arrival_order`,
  65 orders);
- T27's batch equivalence (`batch_path_is_byte_identical_to_per_entry_path`);
- T44's compaction determinism
  (`t44_compaction_is_byte_identical_across_every_arrival_order`, 24 orders).

The two gl-node fixtures are written by a source node that starts in v1, or in
v2, or — for the mixed epoch — writes its first records in v1, compacts and
restarts writing v2, as an operator switching `format.idv2` on does. Each epoch
asserts its fixture really holds the formats it claims. T44's fixture marks
none, all, or two of its four records. With the 120-order mixed test in
`format_v2.rs`, every ordering and byte-identity property §4 lists holds in
each epoch.

**Not done from §4:** §6's suggested re-audit, since the audit series has
ended.

**On by default (2026-10-06).** Both switches default to `true`, before any
release, so no deployed mesh has to switch over: a mesh is born in v2, with
M-10 and L-06 closed. `false` remains for writing to nodes on a build from
before Format v2.

