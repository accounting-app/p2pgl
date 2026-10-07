//! The Lamport clock: the ceiling, the adoption ratchet, gap diagnostics, and what
//! boot counts (`BootLamportHigh`).

use super::*;

/// Exclusive ceiling on every Lamport value in the mesh (0820-M3, H-07, H-12).
///
/// **One rule (T63 / H-12).** A Lamport value `v` is *legal* when `v + 1 <
/// LAMPORT_CEILING` — i.e. when the clock of a node that adopts `v` still sits
/// below the ceiling. Every site applies exactly that predicate,
/// [`lamport_value_is_legal`], to the value it is about to write or read:
///
/// * **stamp** — the value to be stamped must be legal, so the largest value
///   this node ever stamps is `LAMPORT_CEILING - 2`;
/// * **wire** — `p2p::union_merge` requires `value + 1 < LAMPORT_CEILING` of
///   every inbound `openledger-lamport`, by calling the same function;
/// * **adoption** — the ledger requires `max(local, remote)` to be legal, so the
///   clock it moves to (`max + 1` on the peer path, `max` on the file path) is
///   at most `LAMPORT_CEILING - 1`;
/// * **boot** — warns when the value the node would stamp next is not legal,
///   i.e. exactly when the stamp site is going to refuse.
///
/// Before T63 the three checks bounded *different* quantities against the same
/// number (stamp: the value; wire: the value; adoption: the value plus one), so
/// `LAMPORT_CEILING - 1` was a legal stamp, passed every peer's wire check and
/// was refused by every peer's adoption: a node one peer directive away from
/// the ceiling authored exactly one silently unreplicable record and then
/// bricked on restart (H-12). With one predicate a value is either legal
/// everywhere or nowhere, and the only way to meet the ceiling is loudly, at
/// this node's own stamp site, before anything is emitted.
///
/// Why a cap, and why `2^53`: the clock update saturates, so without an inbound
/// bound a single peer sending `u64::MAX` would pin every replica's clock at
/// the saturation point forever, degenerating Lamport ordering to all-ties.
/// Legitimate clocks track mesh event counts (the 64 MiB file cap bounds
/// directives to well under a million), so 2^53 is absurd headroom for honest
/// traffic while keeping `u64::MAX` unreachable — from this cap the clock would
/// need 2^63 further single-step increments to saturate.
///
/// Single-sourced here and aliased by `p2p::union_merge`, for the same reason
/// [`ENVELOPE_KEYS`] and [`MAX_PARENTS`] are. It lived in `p2p` alone until
/// T46, and that split *was* H-07: the cap bounded what a node **accepted** and
/// nothing bounded what it **stamped**.
///
/// ## Reachability, and the ratchet that closes it (T63)
///
/// A hard cap on a clock that adopts peer values is always reachable by the
/// peers *if a single directive may carry the clock any distance*: one legal
/// directive at `LAMPORT_CEILING - 2` stopped authoring on every node that
/// adopted it, survived restarts through the file, and came back with the next
/// anti-entropy round after an operator removed it. T46 made that failure loud;
/// T63 makes it expensive. Adoption also refuses a directive that would advance
/// this node's clock by more than [`MAX_LAMPORT_ADVANCE`] (2^32) in one step —
/// see [`check_lamport_advance`] — so walking a node from an honest clock to the
/// ceiling now takes on the order of 2^21 accepted directives, each of which is
/// ordinary, attributable, allowlisted traffic, rather than one.
///
/// Remedy when a node does meet the ceiling (the error and the boot warning both
/// say this): the directive that carried the clock there is legal and every
/// replica that holds it re-serves it, so removing it from one `.bean` is undone
/// by the next anti-entropy round. Remove its author from the allowlist on every
/// node, then remove the directive from every node's file.
pub const LAMPORT_CEILING: u64 = 1 << 53;

/// Largest advance one adopted directive may make to this node's Lamport clock
/// (T63 / H-12 — the adoption ratchet; decided 2026-09-22).
///
/// Honest traffic advances a clock by one per stamp or adoption, so the gap
/// between any two honest clocks in a mesh is bounded by the number of events
/// the mesh has ever seen — far below 2^32 (≈ 4.3 × 10^9) given the 64 MiB
/// file cap, even for a replica that has been offline for years. A directive
/// that claims a larger jump is not ordinary causality; it is the one-shot
/// H-12 move, and it is refused. See [`check_lamport_advance`] for the rule and
/// for why it deliberately has no first-contact exemption.
pub const MAX_LAMPORT_ADVANCE: u64 = 1 << 32;

/// The lamport-gap warning (T72 / H-19; T83 / L-94, decision (12)): the
/// history this node serves holds a jump of at least this size between two
/// consecutive lamport values.
///
/// # Why a warning, and why a gap
///
/// The ratchet ([`MAX_LAMPORT_ADVANCE`]) is judged against THIS node's clock,
/// deliberately with no first-contact exemption, so joinability is a property
/// of the history: every directive a joiner needs must sit within 2^32 of
/// something it has already adopted. One legal directive at `local + 2^32 − 1`
/// — or any pre-T63 jump — puts a gap of that size into the history, and once
/// the author of the bridging directive is removed from the allowlist (the
/// H-12 remedy) every LATER joiner, and every node rebuilt from an empty disk,
/// is stuck below the gap for good while every existing node carries on. The
/// join is procedural (the joiner boots from a peer's compacted `.bean`); what
/// this buys is that the state is **diagnosed** instead of silent.
///
/// T72 judged it by the clock against the directive count (the clock above
/// four times the count plus 1024). That was not a bound on honest clocks: each adoption below the
/// clock still adds one, a fresh joiner stamps its inflated clock into its own
/// directive, and the next joiner climbs from there, so a dozen honest joins
/// fired it (L-94); and a quarantine that shrank the count fired it on the
/// next honest adoption (L-83). A GAP is a property of the content: honest
/// traffic moves the highest clock by one per event, so no honest history
/// holds a 2^28 gap (it would take 268 million events), joins cannot compound
/// one, and a quarantine cannot create one. 2^28 sits far below the 2^32 a
/// ratchet-legal jump makes, so every such jump is diagnosed.
pub const LAMPORT_GAP_WARN: u64 = 1 << 28;

// A gap the warning names must be one the ratchet could have admitted in a
// single step (0925 §5: this held only inside a unit test).
const _: () = assert!(LAMPORT_GAP_WARN < MAX_LAMPORT_ADVANCE);

/// The largest difference between consecutive distinct values of
/// `lamports`, counting from 0, and the value at the top of it (T83 /
/// L-94). `(0, 0)` for an empty history. The predicate behind the H-19
/// warning: `largest_lamport_gap(..).0 >= LAMPORT_GAP_WARN`.
pub fn largest_lamport_gap(lamports: impl IntoIterator<Item = u64>) -> (u64, u64) {
    let mut values: Vec<u64> = lamports.into_iter().collect();
    values.sort_unstable();
    values.dedup();
    let mut previous = 0u64;
    let mut largest = (0u64, 0u64);
    for value in values {
        let gap = value - previous;
        if gap > largest.0 {
            largest = (gap, value);
        }
        previous = value;
    }
    largest
}

/// The author whose records, left out, leave the largest gap — and that gap
/// and the value at its top — when that gap is more than
/// [`MAX_LAMPORT_ADVANCE`] (B14 of `docs/audits/RESIDUALS.md`).
///
/// [`largest_lamport_gap`] sees one step at a time, so an author who advanced
/// the clock in many steps each below [`LAMPORT_GAP_WARN`] (17 steps of just
/// under 2^28 already pass 2^32) drew no warning, yet once that author is off
/// the allowlist a joiner refuses those records and faces the whole span as
/// one gap it cannot cross. A value stays in the history when any record at it
/// is by another author. `skip` names an author a warning has already named,
/// left out of the search. `None` when no other author's removal leaves such
/// a gap — always when every value is at most 2^32 (callers check the top
/// first, so a normal history is not measured at all).
pub fn gap_left_by_removing_an_author<'a>(
    records: impl IntoIterator<Item = (u64, &'a str)>,
    skip: Option<&str>,
) -> Option<(String, u64, u64)> {
    let mut by_value: std::collections::BTreeMap<u64, std::collections::BTreeSet<&'a str>> =
        std::collections::BTreeMap::new();
    for (value, author) in records {
        by_value.entry(value).or_default().insert(author);
    }
    if by_value.keys().next_back().copied().unwrap_or(0) <= MAX_LAMPORT_ADVANCE {
        return None;
    }
    let authors: std::collections::BTreeSet<&str> = by_value.values().flatten().copied().collect();
    let mut worst: Option<(String, u64, u64)> = None;
    for removed in authors.into_iter().filter(|author| Some(*author) != skip) {
        let mut previous = 0u64;
        let mut largest = (0u64, 0u64);
        for (value, authors_at) in &by_value {
            if authors_at.iter().all(|author| *author == removed) {
                continue;
            }
            if value - previous > largest.0 {
                largest = (value - previous, *value);
            }
            previous = *value;
        }
        if largest.0 > MAX_LAMPORT_ADVANCE && worst.as_ref().is_none_or(|w| largest.0 > w.1) {
            worst = Some((removed.to_owned(), largest.0, largest.1));
        }
    }
    worst
}

/// The operator-facing sentence every H-19 diagnostic ends with: how a node
/// joins a mesh whose history carries a gap, or a removed author's records.
///
/// One spelling, used by the boot warnings, the adoption warning and the
/// `LamportCeiling` / `LamportAdvance` error texts, so the remedy cannot drift
/// between them. The README's "Joining a mesh / removing a peer" section is
/// the long form.
/// The author id a service is booted under before the node's identity is
/// known (T80 / M-53).
///
/// `gl-node` boots the ledger before it loads the node key, so boot runs
/// under this placeholder and [`LedgerService::set_author_id`] replaces it.
/// Since T80 it is replaced whenever signing is enabled, P2P on or off, so no
/// signed envelope carries it any more. Before T80 a node that signed with
/// P2P off wrote it into every record: [`LedgerService::verify_own_history`]
/// re-attributes such a record to this node when its signature verifies
/// under this node's key (the signature does not cover the author).
pub const PLACEHOLDER_AUTHOR: &str = "local";

/// What a lamport-gap warning says about crossing the gap and about whom it
/// names (T89 / L-111, L-113, decision (33)).
///
/// A gap of at least [`LAMPORT_GAP_WARN`] (2^28) is diagnosed; only one of at
/// least [`MAX_LAMPORT_ADVANCE`] (2^32) is beyond what anti-entropy crosses in
/// one step, and only then does a later joiner need the bootstrap join. The
/// author named is the one at the top of the gap — the jumper, or, on a node
/// that no longer holds the jumping directive, the first honest record above
/// it — so the text never calls it the jumper outright.
///
/// T96 / L-127, decision (50): `without_named` is the largest gap the history
/// shows once the named author's records are left out — what a joiner must
/// cross once that author is off the allowlist, since it then refuses them. Two
/// consecutive sub-2^32 steps by one author are each crossable, but together
/// they are not: judged on the single step, the WARN said "no bootstrap join is
/// needed" while a fresh node stayed partitioned. And a gap of exactly 2^32 is
/// crossable — a joiner adopts the record below it at `below + 1`, and the
/// ratchet refuses only a step of 2^32 or more from there — so "uncrossable"
/// is strictly more than 2^32 (T89 said "at least", one off).
pub(super) fn lamport_gap_verdict(gap: u64, without_named: u64) -> String {
    let named = "The author named is the one at the top of the gap: the node that jumped \
                 the clock — or, on a node that no longer holds the jumping directive (its \
                 author removed from the allowlist, or the directive deleted), the first \
                 honest record stamped above it";
    if gap > MAX_LAMPORT_ADVANCE || without_named > MAX_LAMPORT_ADVANCE {
        format!(
            "{named}. Past 2^32 — as one step, or as the steps of the named author taken \
             together — the gap is uncrossable by anti-entropy once that author is off the \
             allowlist. {BOOTSTRAP_JOIN_REMEDY}"
        )
    } else {
        format!(
            "{named}. Up to 2^32 the gap is diagnosed, not uncrossable: anti-entropy crosses it \
             (the adoption ratchet admits up to 2^32 a step) while every author inside it stays \
             allowlisted, so no bootstrap join is needed for it; watch for it growing (H-19, \
             L-111, L-113, L-127)"
        )
    }
}

pub const BOOTSTRAP_JOIN_REMEDY: &str =
    "A node that joins later, or is rebuilt from an empty disk, cannot cross a gap this \
     size by anti-entropy alone once the author that made it is off the allowlist, and \
     anything authored on top of a removed author's transaction is refused for a \
     missing parent: join such a node by bootstrap — for a gap alone, set p2p.joinFrom \
     on the joiner to a current peer, whose history it then adopts past the gap; for a \
     removed author's transaction too, stop a current peer, copy its compacted .bean (not \
     its .journal) to the joiner's ledgerPath, and boot the joiner under its own key and \
     author id; the copy loads as history and the joiner's clock resumes above it (H-19)";

/// THE Lamport rule (T63 / H-12): a value is legal when a node that adopts it
/// still has a clock below [`LAMPORT_CEILING`], i.e. `value + 1 < CEILING`.
///
/// Public so the wire check in `p2p::union_merge` calls this function rather
/// than restating the inequality — the restated copy is how the stamp, the
/// wire and adoption came to bound three different quantities (H-12).
pub const fn lamport_value_is_legal(value: u64) -> bool {
    value < LAMPORT_CEILING - 1
}

/// Apply the [`LAMPORT_CEILING`] rule to a value this node is about to stamp,
/// or to the `max(local, remote)` it is about to adopt (H-07, H-12).
///
/// The single place the ceiling is enforced inside this crate: every write to
/// `lamport_clock` on an author or an adopt path goes through here, so a new
/// call site cannot quietly acquire a different bound — which is exactly how
/// the stamp sites came to have none.
///
/// It does NOT clamp. Saturating at the cap would stamp two directives with the
/// same `(author, lamport)` pair — the uniqueness M-18 depends on — and would
/// do it silently, which is the shape of the original defect. The caller is told
/// instead, and refuses the write. `author` is the author whose directive
/// carried the clock this far, where the caller knows it; it goes into the
/// error so the operator knows whom to remove from the allowlist.
pub(super) fn checked_lamport(value: u64, author: Option<&str>) -> Result<u64, ServiceError> {
    if !lamport_value_is_legal(value) {
        return Err(ServiceError::LamportCeiling {
            next: value,
            author: author.map(str::to_owned),
        });
    }
    Ok(value)
}

/// The adoption ratchet (T63 / H-12): refuse a directive whose adoption would
/// move this node's clock from `local` to more than `local +`
/// [`MAX_LAMPORT_ADVANCE`].
///
/// Adoption moves the clock to `max(local, remote) + 1` on the peer path (and
/// to `max(local, remote)` on the file path, which is never further), so the
/// refusal is `max(local, remote) + 1 > local + MAX_LAMPORT_ADVANCE`, which is
/// `remote - local >= MAX_LAMPORT_ADVANCE`. A remote value at or below the local
/// clock can never trip it.
///
/// # Relative to THIS node's clock — and no first-contact exemption
///
/// The obvious worry is a fresh node (clock 0) joining a mesh whose history is
/// already far above 0. It is not refused, for three reasons, and the design
/// deliberately stays this simple:
///
/// 1. **Honest histories fit.** Every honest Lamport value is bounded by the
///    number of events the mesh has ever seen, and that is orders of magnitude
///    below 2^32 — a fresh node admits a whole honest history *in any arrival
///    order*, its highest directive first. The test
///    `test_fresh_node_converges_with_a_history_reaching_1e9` pins this at
///    lamport 10^9, a thousand times what the file cap allows.
/// 2. **A history with larger totals still converges, by climbing.** The
///    refusal is state-dependent — it is [`ServiceError::LamportAdvance`],
///    which the node's refusal cache classifies as NOT permanent — so a
///    directive refused now is asked for again on the next anti-entropy
///    round. A directive's parents always carry smaller lamports than it does
///    (a stamp is `max(everything seen) + 1`), so the lower part of any history
///    never waits on the higher part: each round adopts everything within 2^32
///    of the clock, the clock rises, and the next round adopts the rest.
///    `test_ratchet_refusal_is_retried_and_a_stepped_history_converges`.
/// 3. **An exemption would be the attack.** "No bound on first contact" (or
///    while the clock is 0, or for an author not seen before) gives an
///    allowlisted peer exactly the single unbounded jump the ratchet exists to
///    remove, on precisely the nodes least able to notice — new ones. The one
///    exemption there is, the join window (`p2p.joinFrom`,
///    [`LedgerService::open_join_trust`]), is not first contact: it is one
///    peer the operator names, on a node that has written nothing, until it
///    holds that peer's history — the trust of copying that peer's `.bean`,
///    which boot adopts past any gap anyway.
///
/// # What the ratchet cannot do, and what does it instead (T72 / H-19)
///
/// Point 2 holds only while the history is dense. One directive at exactly
/// `local + 2^32 − 1` is legal and is adopted by every current node, which
/// then stamps `2^32 + 1` above the pre-jump clock — and a joiner that has
/// climbed to the pre-jump clock is a full step short of the first honest
/// post-jump directive. The bridge is the jump itself; once its author is
/// removed from the allowlist (the H-12 remedy) the bridge is refused at
/// intake and the joiner is stuck for good, while every existing node — and
/// the joiner's own writes — carry on. A pre-T63 mesh with any jump ≥ 2^32 in
/// its history (a hand-typed `openledger-lamport`, M-20's own example) is in
/// the same state with no attacker. T63's residual said "cannot be joined until
/// that directive is removed"; that was wrong — removing it changes nothing,
/// the honest history after it *is* the gap.
///
/// No per-directive bound closes this (an honest node that adopted the jump
/// legitimately stamps `2^32 + 1` above its parents, and an attacker
/// *transaction* partitions joiners through `MissingParent` whatever the
/// lamport rule says), so the ratchet stays exactly as it is and the join is
/// procedural — the **trusted-bootstrap join**, [`BOOTSTRAP_JOIN_REMEDY`]: the
/// joiner boots from a peer's compacted `.bean`, which loads as history and
/// puts its clock above the gap, or — for a gap alone — names that peer in
/// `p2p.joinFrom` and takes the same history over the wire (the join window). The state is no longer silent: boot and
/// adoption warn when the history holds a lamport gap of at least
/// [`LAMPORT_GAP_WARN`] ([`largest_lamport_gap`]), naming the author of the
/// directive at its top.
pub(super) fn check_lamport_advance(
    local: u64,
    remote: u64,
    author: Option<&str>,
) -> Result<(), ServiceError> {
    if remote.saturating_sub(local) >= MAX_LAMPORT_ADVANCE {
        return Err(ServiceError::LamportAdvance {
            remote,
            local,
            author: author.map(str::to_owned),
        });
    }
    Ok(())
}

/// Whether `author` is this node's own when this node's id is `own_author`
/// (T89 / L-96, decision (31)): its id, or the pre-T80 placeholder
/// ([`PLACEHOLDER_AUTHOR`]) — only this node ever wrote `"local"` into its own
/// file (a signing node before T80, or any signing-off node). T80
/// re-attributed such records in the DAG, but everything outside it
/// (quarantined, held as text) kept the placeholder and dropped out of every
/// "own" lookup once the id was set: the L-87 release re-issued its lamport,
/// the ceiling diagnostics named `"local"` with the mesh-wide remedy, and a
/// boot and a reload of the same file resumed at different clocks.
pub(super) fn is_own_author(author: &str, own_author: &str) -> bool {
    author == own_author || author == PLACEHOLDER_AUTHOR
}

/// The highest Lamport value boot's clock must resume above (M-18, T63 / H-12).
///
/// # Which directives count
///
/// * **Every directive boot inserts into the DAG** — whatever its author. The
///   clock is a Lamport clock over the history this node holds and serves, so
///   it must sit above every value in it; that is the M-18 rule, unchanged.
/// * **A directive that does NOT reach the DAG** (quarantined by the cycle
///   scan, the fan-in / envelope-form checks or a DAG refusal, or dropped as a
///   duplicate body) counts **only if its `openledger-author` is this node**.
///
/// # Why that still keeps `(author, lamport)` unique
///
/// M-18's uniqueness is about the pairs THIS node signs: the next value it
/// stamps must differ from every value it has already stamped that still
/// exists anywhere. A pair `(other, n)` can never collide with `(self, m)`,
/// whatever `n` is, because the author component differs — so a foreign
/// directive outside the DAG constrains nothing this node will stamp, and
/// neither does it constrain causality: nothing in the DAG descends from it, so
/// no directive this node stamps needs to order after it. This node's OWN
/// records are all still counted, wherever they landed: a quarantined one stays
/// in the file (H-08) and may already be on peers, and ignoring its value
/// could re-issue its pair. Before T63 every quarantined directive counted,
/// which is how a foreign directive the node refused to load still set its
/// clock — and, since the quarantine is written back by every compaction,
/// kept setting it forever (H-12 fact 3).
///
/// Unparsable blocks (L-45) are not directives, but a block that carries an
/// `openledger-author` / `openledger-lamport` pair naming this node counts
/// (T78): it is text this node signed — typically a node-written record the
/// H-20 salvage held whole beside a damaged neighbour — it stays in the file
/// and may be on peers, so its pair must not be re-issued either. Before T78
/// they were never counted.
///
/// # When "this node" is only learnt after boot (L-67, T78)
///
/// `gl-node` boots with a placeholder author and learns its `EndpointId`
/// afterwards, so at boot no out-of-DAG record is "own". Every out-of-DAG
/// value is therefore also kept per author ([`Self::outside_dag`], moved into
/// [`LedgerService::boot_outside_dag_lamports`]), and
/// [`LedgerService::set_author_id`] folds the new author's entry exactly as
/// this fold would have had boot known it.
#[derive(Default)]
pub(super) struct BootLamportHigh {
    pub(super) value: u64,
    /// Author of the directive carrying `value`, for the H-12 boot warning.
    pub(super) author: Option<String>,
    /// The highest lamport among directives NOT authored by this node, and its
    /// author (T72 / H-19 diagnostics — see [`Self::suspect_author`]).
    pub(super) foreign_value: u64,
    pub(super) foreign_author: Option<String>,
    /// The highest lamport per author among everything boot saw that did NOT
    /// reach the DAG — quarantined, duplicate-body envelopes, envelopes in
    /// unparsable text (L-67, T78).
    pub(super) outside_dag: BTreeMap<String, u64>,
}

impl BootLamportHigh {
    /// Fold a directive that is in the DAG.
    pub(super) fn note(&mut self, directive: &Directive, own_author: &str) {
        if let Some(lamport) = directive.lamport_clock() {
            let author = directive_author(directive);
            if lamport > self.value || self.author.is_none() && lamport == self.value {
                self.value = lamport;
                self.author = author.map(str::to_owned);
            }
            if author.is_some_and(|author| !is_own_author(author, own_author))
                && (lamport > self.foreign_value || self.foreign_author.is_none())
            {
                self.foreign_value = lamport;
                self.foreign_author = author.map(str::to_owned);
            }
        }
    }

    /// Fold a directive that is NOT in the DAG: only this node's own count;
    /// every author's value is remembered for a later `set_author_id`.
    pub(super) fn note_if_own(&mut self, directive: &Directive, own_author: &str) {
        if let (Some(author), Some(lamport)) =
            (directive_author(directive), directive.lamport_clock())
        {
            self.remember_outside_dag(author, lamport);
        }
        if directive_author(directive).is_some_and(|author| is_own_author(author, own_author)) {
            self.note(directive, own_author);
        }
    }

    /// Fold the envelopes spelled in one unparsable block (T78): only this
    /// node's own count; every author's value is remembered.
    pub(super) fn note_text_if_own(&mut self, text: &str, own_author: &str) {
        for (author, lamport) in envelope_pairs_in_text(text) {
            self.remember_outside_dag(&author, lamport);
            if is_own_author(&author, own_author)
                && (lamport > self.value || self.author.is_none() && lamport == self.value)
            {
                self.value = lamport;
                self.author = Some(author);
            }
        }
    }

    pub(super) fn remember_outside_dag(&mut self, author: &str, lamport: u64) {
        let slot = self.outside_dag.entry(author.to_owned()).or_insert(0);
        *slot = (*slot).max(lamport);
    }

    /// The author to name in a clock diagnostic: whoever carried the clock
    /// highest among OTHER nodes when any foreign directive exists, else the
    /// author of the highest value (this node itself).
    ///
    /// Once this node has authored on top of a peer's jump, its own record is
    /// the highest and naming it would name the victim (the 0923 audit's
    /// `LamportCeiling` finding, T72 (d)). The peer that carried the clock
    /// there is the one the remedy starts with.
    pub(super) fn suspect_author(&self) -> Option<&str> {
        self.foreign_author.as_deref().or(self.author.as_deref())
    }
}

/// The `(openledger-author, openledger-lamport)` pairs spelled in raw ledger
/// text that did not parse (T78).
///
/// Line-based and deliberately forgiving — the block is unparsable, so its
/// structure cannot be trusted: a directive starts at every non-indented,
/// non-comment line, and an indented `openledger-author:` /
/// `openledger-lamport:` metadata line belongs to the directive above it.
/// Values are unquoted; a lamport that is not a decimal `u64` is skipped. A
/// directive with only one of the two lines yields nothing.
pub(super) fn envelope_pairs_in_text(text: &str) -> Vec<(String, u64)> {
    fn value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        let rest = line.trim_start().strip_prefix(key)?.strip_prefix(':')?;
        let rest = rest.trim();
        Some(
            rest.strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
                .unwrap_or(rest),
        )
    }
    let mut pairs = Vec::new();
    let mut current: (Option<String>, Option<u64>) = (None, None);
    let mut flush = |current: &mut (Option<String>, Option<u64>)| {
        if let (Some(author), Some(lamport)) = (current.0.take(), current.1.take()) {
            pairs.push((author, lamport));
        }
        *current = (None, None);
    };
    for line in text.lines() {
        let indented = line.starts_with([' ', '\t']);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        if !indented {
            flush(&mut current);
            continue;
        }
        if let Some(author) = value(line, ENVELOPE_KEY_AUTHOR) {
            current.0 = Some(author.to_owned());
        } else if let Some(lamport) = value(line, ENVELOPE_KEY_LAMPORT) {
            current.1 = lamport.parse::<u64>().ok();
        }
    }
    flush(&mut current);
    pairs
}

/// A directive's `openledger-author`, for any kind.
pub(super) fn directive_author(directive: &Directive) -> Option<&str> {
    directive
        .metadata()
        .get(ENVELOPE_KEY_AUTHOR)
        .map(String::as_str)
}
