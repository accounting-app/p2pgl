//! Anti-entropy protocol (§3.4).
//!
//! On connect and every `antiEntropyIntervalMilliseconds`, peers exchange
//! heads + non-transaction ID digests. The lagging peer pulls missing
//! directives until closed.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::protocol::{
    is_content_id, SupplyEntry, WireMessage, MAX_HAVE_HEADS, MAX_SUPPLY_ENTRIES,
    SUPPLY_FRAME_BUDGET_BYTES,
};

/// Per-entry framing allowance in the `Supply` size estimate (H-02).
///
/// Covers the CBOR map keys, the kind tag, and the length prefixes around each
/// string; generous so the estimate stays an over-approximation of the encoded
/// size, which is what keeps the frame under `MAX_MESSAGE_SIZE`.
const SUPPLY_ENTRY_OVERHEAD_BYTES: usize = 128;

/// Compute which IDs the remote has that we don't (the `want` set).
///
/// Given our local heads and the remote's advertised heads + directive IDs,
/// returns the IDs we should request via a `want` message.
///
/// The remote lists arrive already **form-checked**: T49 made the advert reader
/// (`gl-node`'s `read_have_heads_advert`) refuse a page carrying anything that
/// is not a `protocol::is_content_id` — the rule `openledger-parents` has had
/// since L-29 (M-26, L-53). The check is deliberately there and NOT repeated
/// here: this function would have to *filter*, and a filter would let a
/// malformed advert produce a successful-looking exchange in which the two
/// nodes silently disagree about what was offered. One refusal, at the point
/// where the bytes are first retained, is the stronger property.
pub fn compute_want(
    local_txids: &HashSet<String>,
    local_directive_ids: &HashSet<String>,
    remote_head_txids: &[String],
    remote_directive_ids: &[String],
) -> Vec<String> {
    // L-21: every head txid is also a directive id, so a missing head is
    // advertised in both `remote_head_txids` and `remote_directive_ids` and would
    // be wanted twice; a list that repeats an id doubles up the same way. Dedup
    // the output — preserving first-occurrence order — so each missing id is
    // requested (and later served + re-validated by the peer) exactly once.
    let mut want = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for txid in remote_head_txids {
        if !local_txids.contains(txid) && seen.insert(txid.clone()) {
            want.push(txid.clone());
        }
    }

    for id in remote_directive_ids {
        if !local_directive_ids.contains(id) && seen.insert(id.clone()) {
            want.push(id.clone());
        }
    }

    want
}

/// [`compute_want`] against a membership lookup instead of two cloned sets
/// (L-35 / R-19, T69).
///
/// # Why
///
/// The node used to build both `HashSet<String>` arguments of
/// [`compute_want`] for every head exchange — `head_txids()` and
/// `all_directive_ids()`, the latter an O(N) `String` clone of the whole DAG,
/// under the ledger read lock, per peer per tick. What the diff actually needs
/// is membership, which the ledger answers in O(1) without allocating
/// (`LedgerService::contains_directive`).
///
/// # One deliberate difference: heads are checked for membership (T59 note)
///
/// [`compute_want`] checks a remote *head* against the local *heads*, so a
/// remote head this node holds as an interior directive (it has since built on
/// it) is wanted, served and re-validated only to be skipped as present. Here
/// every remote id, head or not, is checked against the DAG. The result is
/// [`compute_want`]'s output minus exactly those locally present ids — same
/// order, same first-occurrence dedup (L-21) — which
/// `want_by_membership_is_the_old_want_minus_present_ids` pins.
///
/// The dedup set borrows the remote ids rather than cloning them; only the
/// ids actually wanted are cloned, once, into the result.
pub fn compute_want_by_membership<F>(
    is_local: F,
    remote_head_txids: &[String],
    remote_directive_ids: &[String],
) -> Vec<String>
where
    F: Fn(&str) -> bool,
{
    let mut want = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for id in remote_head_txids.iter().chain(remote_directive_ids) {
        if seen.insert(id.as_str()) && !is_local(id) {
            want.push(id.clone());
        }
    }
    want
}

/// Compute the `have_heads` message for our local state.
///
/// This advertises our DAG frontier to the remote peer so they can
/// determine what they're missing.
pub fn make_have_heads(
    local_head_txids: &HashSet<String>,
    local_directive_ids: &HashSet<String>,
) -> WireMessage {
    let mut heads: Vec<String> = local_head_txids.iter().cloned().collect();
    heads.sort();
    let mut directives: Vec<String> = local_directive_ids.iter().cloned().collect();
    directives.sort();

    WireMessage::have_heads(heads, directives)
}

/// Split our local frontier into `have_heads` pages the receiver will accept (H-02).
///
/// `make_have_heads` advertises every id in one frame, which a conforming peer
/// rejects outright once the ledger passes `MAX_HAVE_HEADS` directives — every
/// head exchange then fails and the mesh stops syncing. Each returned page
/// carries at most `MAX_HAVE_HEADS` head txids and at most `MAX_HAVE_HEADS`
/// directive ids; every page but the last has `more: true`.
///
/// Always returns at least one page, so an empty ledger still advertises.
pub fn paginate_have_heads(
    local_head_txids: &HashSet<String>,
    local_directive_ids: &HashSet<String>,
) -> Vec<WireMessage> {
    let mut heads: Vec<String> = local_head_txids.iter().cloned().collect();
    heads.sort();
    let mut directives: Vec<String> = local_directive_ids.iter().cloned().collect();
    directives.sort();

    let page_count = heads
        .len()
        .div_ceil(MAX_HAVE_HEADS)
        .max(directives.len().div_ceil(MAX_HAVE_HEADS))
        .max(1);

    (0..page_count)
        .map(|index| {
            let start = index * MAX_HAVE_HEADS;
            WireMessage::have_heads_page(
                page_slice(&heads, start),
                page_slice(&directives, start),
                index + 1 < page_count,
            )
        })
        .collect()
}

/// [`paginate_have_heads`] over already-sorted ids, one page at a time (L-35 /
/// R-19, T69).
///
/// `directive_ids` is the ledger's shared sorted snapshot
/// (`LedgerService::sorted_directive_ids`), taken with an `Arc` clone — O(1)
/// under the read lock on a ledger at rest — instead of cloning every id into
/// a `HashSet` and then again into a `Vec` to sort it. The pages are produced
/// lazily, so at most one page of ids is copied out at a time rather than the
/// whole advert being materialised up front; the page count is known in
/// advance (`ExactSizeIterator`) for the serve loop's L-01 charge.
///
/// Byte-identical to [`paginate_have_heads`] for the same sets:
/// `sorted_pagination_is_identical_to_the_set_pagination` pins it. Both inputs
/// must be sorted ascending and duplicate-free — the old function's own sort of
/// a set, which the ledger's snapshot and a sorted `head_txids()` both are.
pub fn paginate_have_heads_sorted(
    head_txids: Vec<String>,
    directive_ids: std::sync::Arc<[String]>,
) -> HaveHeadsPages {
    debug_assert!(head_txids.windows(2).all(|pair| pair[0] < pair[1]));
    debug_assert!(directive_ids.windows(2).all(|pair| pair[0] < pair[1]));
    let page_count = head_txids
        .len()
        .div_ceil(MAX_HAVE_HEADS)
        .max(directive_ids.len().div_ceil(MAX_HAVE_HEADS))
        .max(1);
    HaveHeadsPages {
        head_txids,
        directive_ids,
        page_count,
        next: 0,
    }
}

/// The lazy advert [`paginate_have_heads_sorted`] returns.
#[derive(Debug, Clone)]
pub struct HaveHeadsPages {
    head_txids: Vec<String>,
    directive_ids: std::sync::Arc<[String]>,
    page_count: usize,
    next: usize,
}

impl Iterator for HaveHeadsPages {
    type Item = WireMessage;

    fn next(&mut self) -> Option<WireMessage> {
        if self.next >= self.page_count {
            return None;
        }
        let index = self.next;
        self.next += 1;
        let start = index * MAX_HAVE_HEADS;
        Some(WireMessage::have_heads_page(
            page_slice(&self.head_txids, start),
            page_slice(&self.directive_ids, start),
            index + 1 < self.page_count,
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.page_count - self.next;
        (left, Some(left))
    }
}

impl ExactSizeIterator for HaveHeadsPages {}

/// One `MAX_HAVE_HEADS`-sized window of `ids` starting at `start` (empty past the end).
fn page_slice(ids: &[String], start: usize) -> Vec<String> {
    if start >= ids.len() {
        return Vec::new();
    }
    ids[start..(start + MAX_HAVE_HEADS).min(ids.len())].to_vec()
}

/// Estimated encoded size of one supply entry (H-02). An over-approximation.
///
/// The SENDER's frame budget. T69 also used it on the receiver to bound the
/// journal record a batch would become; that over-counted ~150–190 B an entry
/// (the 128-byte framing allowance and the 64-byte id are not in the record),
/// which near the cap deferred a batch that fit, forever. The receiver now
/// uses [`RecordEstimate`], which is the record's exact length (T77).
pub fn estimated_entry_bytes(entry: &SupplyEntry) -> usize {
    let envelope: usize = entry
        .envelope
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum();
    entry
        .economic_bean
        .len()
        .saturating_add(envelope)
        .saturating_add(entry.id.len())
        .saturating_add(SUPPLY_ENTRY_OVERHEAD_BYTES)
}

/// The exact length of the journal record a set of staged directives becomes
/// (T77) — what `LedgerService::prepare_commit`'s append arm writes and its
/// cap projection counts: `journal::record_bytes(full_file_serialize(set))`.
///
/// `full_file_serialize` of a set is the per-directive canonical forms (with
/// their envelope metadata) joined by one blank-line `\n`, in an order that
/// does not change the length, so the payload is the sum of
/// [`Self::directive_bytes`] plus one byte per separator; the record adds a
/// header whose only variable part is the payload length's digits. Each
/// directive is therefore serialized once, when it is added, and the running
/// total answers "does the set plus this one still fit?" in O(1).
///
/// # Why exact is still conservative
///
/// The estimate is taken on the directive as it arrived (validated, not yet
/// staged). Staging stores that same value — a remote transaction must arrive
/// with every posting resolved, so `validate_transaction` changes nothing it
/// serializes, and the other kinds are inserted as given — so the staged
/// record is exactly this long when every counted directive is staged, and
/// shorter when some are duplicates, buffered or refused. It never counts a
/// directive it was not given, so it can under-estimate only a record that
/// also carries something ELSE staged earlier; the ALPN path takes it under
/// the single-writer permit, where nothing else is pending.
///
/// It replaces [`estimated_entry_bytes`] on the receive side: that adds a
/// 128-byte framing allowance and the 64-byte id, neither of which is in the
/// record, so near the cap a batch that fit was deferred forever.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordEstimate {
    /// Sum of the counted directives' serialized lengths.
    serialized: u64,
    /// How many directives are counted.
    count: u64,
}

impl RecordEstimate {
    /// An empty set: no record at all.
    pub fn new() -> Self {
        Self::default()
    }

    /// The canonical, envelope-bearing serialization length of one directive
    /// — its share of a journal record's payload, separators aside.
    pub fn directive_bytes(directive: &ledger::model::Directive) -> u64 {
        ledger::serialize::full_file_serialize(std::slice::from_ref(directive), &[]).len() as u64
    }

    /// This set plus one directive of `directive_bytes` serialized bytes.
    #[must_use]
    pub fn with(self, directive_bytes: u64) -> Self {
        Self {
            serialized: self.serialized.saturating_add(directive_bytes),
            count: self.count.saturating_add(1),
        }
    }

    /// Add one directive of `directive_bytes` serialized bytes.
    pub fn add(&mut self, directive_bytes: u64) {
        *self = self.with(directive_bytes);
    }

    /// How many directives are counted.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The journal payload: the forms plus one separator between each pair.
    pub fn payload_bytes(&self) -> u64 {
        self.serialized.saturating_add(self.count.saturating_sub(1))
    }

    /// The whole record, header included; 0 for an empty set (nothing staged
    /// writes no record).
    pub fn record_bytes(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let payload = self.payload_bytes();
        record_header_bytes(payload).saturating_add(payload)
    }
}

/// Length of a journal record header for a `payload`-byte payload. Taken from
/// `ledger::journal::record_bytes` itself — the header of an empty payload,
/// with the one-digit `0` swapped for the payload length's digits — so the
/// frame format is referenced, not restated.
fn record_header_bytes(payload: u64) -> u64 {
    static EMPTY_RECORD: std::sync::LazyLock<u64> =
        std::sync::LazyLock::new(|| ledger::journal::record_bytes("").len() as u64);
    let digits = payload.checked_ilog10().map_or(1, |log| u64::from(log) + 1);
    EMPTY_RECORD.saturating_sub(1).saturating_add(digits)
}

/// A conservative estimate of the heap one parsed directive holds (T77).
///
/// Phase 1 of the receiver's `Supply` handling keeps every directive it has
/// validated until it stages them, and a parsed directive is much larger than
/// its text: each posting is a `Posting` inline in a `Vec` plus its own
/// strings, and every non-empty metadata map allocates a whole B-tree leaf.
/// The densest body inside every §3.12 cap (1,000 postings, 100 posting and
/// 100 directive metadata keys, 100 tags and links, ~19 KB) holds ~12.7× its
/// text once parsed (T75's measurement), so bounding phase 1 by frame BYTES
/// bounds nothing; the receiver bounds it by this instead.
///
/// Counted from the value, never from the text: every `String` and `Vec` at
/// its capacity plus a per-allocation overhead, every metadata map as whole
/// leaves of [`BTREE_NODE_CAPACITY`] entries. Calibrated against a counting
/// allocator (gl-node's phase-1 residency test): at or above the real
/// resident size for each shape measured, and within about 2× of it.
pub fn resident_weight(directive: &ledger::model::Directive) -> usize {
    use ledger::model::Directive;
    let size = std::mem::size_of::<Directive>();
    let body = match directive {
        Directive::Transaction(txn) => {
            let postings: usize = txn
                .postings
                .iter()
                .map(|posting| {
                    string_weight(&posting.account)
                        + posting
                            .amount
                            .as_ref()
                            .map_or(0, |amount| string_weight(&amount.currency))
                        + posting
                            .cost
                            .as_ref()
                            .and_then(|cost| cost.amount.as_ref())
                            .map_or(0, |amount| string_weight(&amount.currency))
                        + posting.price.as_ref().map_or(0, |price| match price {
                            ledger::model::PriceSpec::Unit(amount)
                            | ledger::model::PriceSpec::Total(amount) => {
                                string_weight(&amount.currency)
                            }
                        })
                        + metadata_weight(&posting.metadata)
                })
                .sum();
            vec_weight::<ledger::model::Posting>(txn.postings.capacity())
                + postings
                + txn.payee.as_ref().map_or(0, string_weight)
                + txn.narration.as_ref().map_or(0, string_weight)
                + strings_weight(&txn.tags)
                + strings_weight(&txn.links)
                + metadata_weight(&txn.metadata)
        }
        Directive::Open(open) => {
            string_weight(&open.account)
                + strings_weight(&open.currencies)
                + metadata_weight(&open.metadata)
        }
        Directive::Close(close) => string_weight(&close.account) + metadata_weight(&close.metadata),
        Directive::Commodity(commodity) => {
            string_weight(&commodity.currency) + metadata_weight(&commodity.metadata)
        }
        Directive::Pad(pad) => {
            string_weight(&pad.account)
                + string_weight(&pad.source_account)
                + metadata_weight(&pad.metadata)
        }
        Directive::Balance(balance) => {
            string_weight(&balance.account)
                + string_weight(&balance.amount.currency)
                + metadata_weight(&balance.metadata)
        }
        Directive::Note(note) => {
            string_weight(&note.account)
                + string_weight(&note.comment)
                + metadata_weight(&note.metadata)
        }
        Directive::Document(document) => {
            string_weight(&document.account)
                + string_weight(&document.path)
                + metadata_weight(&document.metadata)
        }
        Directive::Event(event) => {
            string_weight(&event.event_type)
                + string_weight(&event.description)
                + metadata_weight(&event.metadata)
        }
        Directive::Price(price) => {
            string_weight(&price.currency)
                + string_weight(&price.amount.currency)
                + metadata_weight(&price.metadata)
        }
    };
    size + body
}

/// Allocator bookkeeping and size-class rounding charged per heap block by
/// [`resident_weight`] — generous for the system allocators this runs on.
const ALLOCATION_OVERHEAD_BYTES: usize = 16;

/// Entries in one `BTreeMap` node (`2B − 1`, `B = 6` in std). Every non-empty
/// map owns at least one whole node, which is what makes a map of one
/// posting-metadata key cost ~0.5 KB.
const BTREE_NODE_CAPACITY: usize = 11;

fn string_weight(value: &String) -> usize {
    if value.capacity() == 0 {
        0
    } else {
        value.capacity() + ALLOCATION_OVERHEAD_BYTES
    }
}

fn vec_weight<T>(capacity: usize) -> usize {
    if capacity == 0 {
        0
    } else {
        capacity * std::mem::size_of::<T>() + ALLOCATION_OVERHEAD_BYTES
    }
}

fn strings_weight(values: &Vec<String>) -> usize {
    vec_weight::<String>(values.capacity()) + values.iter().map(string_weight).sum::<usize>()
}

fn metadata_weight(metadata: &ledger::model::Metadata) -> usize {
    if metadata.is_empty() {
        return 0;
    }
    // Leaves hold up to BTREE_NODE_CAPACITY entries; internal nodes add one
    // node per BTREE_NODE_CAPACITY + 1 children, so leaves + leaves / 11
    // rounded up bounds the node count. An internal node is a leaf plus its
    // edge array, charged here as a second leaf's worth.
    let leaves = metadata.len().div_ceil(BTREE_NODE_CAPACITY);
    let internal = if leaves > 1 {
        leaves.div_ceil(BTREE_NODE_CAPACITY + 1) * 2
    } else {
        0
    };
    let node = BTREE_NODE_CAPACITY * 2 * std::mem::size_of::<String>()
        + 4 * std::mem::size_of::<usize>()
        + ALLOCATION_OVERHEAD_BYTES;
    (leaves + internal) * node
        + metadata
            .iter()
            .map(|(key, value)| string_weight(key) + string_weight(value))
            .sum::<usize>()
}

/// One `Supply` reply being filled under both receive-side caps (H-02, L-33).
///
/// The single statement of the prefix rule that [`truncate_supply`] and
/// [`build_supply`] share, so the two cannot drift: entries are admitted in
/// order until either `MAX_SUPPLY_ENTRIES` or `SUPPLY_FRAME_BUDGET_BYTES` would
/// be exceeded, and the FIRST entry that does not fit closes the reply. A later,
/// smaller entry is deliberately not admitted past it — the reply must stay a
/// prefix of what was offered, because that is what the requester's re-`Want`
/// loop measures its progress against.
#[derive(Debug, Default)]
pub struct SupplyBudget {
    used: usize,
    kept: Vec<SupplyEntry>,
    closed: bool,
}

impl SupplyBudget {
    /// An empty reply with the whole frame budget available.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether another entry could still be admitted.
    ///
    /// False once the entry cap is reached — which callers check BEFORE
    /// producing the next entry, so an entry that could never be admitted is
    /// never serialized (L-33) — and once any entry has been refused.
    pub fn is_open(&self) -> bool {
        !self.closed && self.kept.len() < MAX_SUPPLY_ENTRIES
    }

    /// Offer the next entry in order; returns whether it was admitted.
    ///
    /// A refusal closes the budget (see the type docs for why).
    pub fn offer(&mut self, entry: SupplyEntry) -> bool {
        if !self.is_open() {
            return false;
        }
        let size = estimated_entry_bytes(&entry);
        if self.used.saturating_add(size) > SUPPLY_FRAME_BUDGET_BYTES {
            self.closed = true;
            return false;
        }
        self.used += size;
        self.kept.push(entry);
        true
    }

    /// The `Supply` frame for everything admitted.
    pub fn into_message(self) -> WireMessage {
        WireMessage::supply(self.kept)
    }
}

/// Trim a supply batch to a prefix the receiver will accept (H-02).
///
/// Answering a `Want` with everything it asked for violates both receive-side
/// caps: `MAX_SUPPLY_ENTRIES` (a 1024-id `Want` cannot be answered in one
/// `Supply`) and `MAX_MESSAGE_SIZE` (~17 max-size entries overflow the frame).
/// Entries past either bound are dropped; the requester re-`Want`s whatever it
/// did not receive, so truncation costs a round trip rather than correctness.
///
/// Serving a `Want` should use [`build_supply`] instead, which applies the same
/// rule WITHOUT first materializing entries it is about to drop (L-33).
pub fn truncate_supply(entries: Vec<SupplyEntry>) -> WireMessage {
    let mut budget = SupplyBudget::new();
    for entry in entries {
        if !budget.offer(entry) {
            break;
        }
    }
    budget.into_message()
}

/// Answer a `Want` for `ids`, producing each entry only once it could still be
/// sent (L-01, L-33).
///
/// `produce` looks one id up and serializes it (`None` when this node does not
/// hold it). The reply used to be built by producing an entry for EVERY
/// requested id and only then trimming with [`truncate_supply`] — so a 1,024-id
/// `Want`, a ~68 KiB request, cost up to 1,024 serializations and hashes (up to
/// ~64 MiB of allocation at the file-size cap) under the ledger read lock, of
/// which at most 256 entries / 15 MiB could ever be sent. Budgeting WHILE
/// collecting bounds the work by what the reply can carry: at most
/// `MAX_SUPPLY_ENTRIES` entries are produced, and past the byte budget exactly
/// one more — the entry whose size is what reveals that the budget is spent.
///
/// The reply is BYTE-IDENTICAL to the old collect-then-truncate one: same
/// dedup (first occurrence wins, L-21), same skipping of ids this node lacks,
/// same prefix rule via [`SupplyBudget`]. That equivalence is what keeps the
/// requester's re-`Want` loop (H-02) converging — each round it is served a
/// non-empty prefix of what it still lacks and this node holds, so its
/// remaining set strictly shrinks. An entry too large to be framed at all is
/// still answered with the (possibly empty) prefix before it, exactly as
/// before; that coupling is unreachable while `MAX_ECONOMIC_BEAN_LENGTH` is far
/// below the frame budget, and T60 documents it.
pub fn build_supply<F>(ids: &[String], mut produce: F) -> WireMessage
where
    F: FnMut(&str) -> Option<SupplyEntry>,
{
    let mut seen: HashSet<&str> = HashSet::new();
    let mut budget = SupplyBudget::new();
    for id in ids {
        if !budget.is_open() {
            break;
        }
        if !seen.insert(id.as_str()) {
            continue;
        }
        let Some(entry) = produce(id) else {
            continue;
        };
        if !budget.offer(entry) {
            break;
        }
    }
    budget.into_message()
}

/// How long a permanent refusal suppresses re-`Want`ing that id from that peer
/// (L-34).
///
/// The cache is an optimization, never a verdict, so the TTL is what makes a
/// misclassification self-healing: the worst a wrongly cached id can cost is
/// being fetched this much later. Ten minutes is 120 ticks of the default
/// 5-second anti-entropy interval — the churn on a permanently refused id drops
/// by two orders of magnitude — while staying far inside the one-hour orphan
/// TTL that bounds how long anything else waits.
pub const REFUSAL_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

/// Cap on (peer, id) refusals held across all peers (L-34).
///
/// ~16k × (two 64-byte strings + bookkeeping) is a few MiB. Past it the oldest
/// refusal is forgotten, which costs one extra fetch of it — never data.
pub const REFUSAL_CACHE_CAPACITY: usize = 16_384;

/// Cap on refusals held for one peer (L-34).
///
/// Without it one peer serving junk could flush every other peer's entries out
/// of the shared capacity. A peer past its share simply stops being cached,
/// which is exactly the pre-L-34 behaviour for its surplus.
pub const REFUSAL_CACHE_PER_PEER: usize = 4_096;

/// Bounded, TTL'd memory of directives this node PERMANENTLY refused, per peer
/// (L-34).
///
/// `compute_want` just diffs, so before this a directive the node will never
/// accept — a backdated close (the M-09 residual), an unbalanced transaction, a
/// bad signature — was re-`Want`ed, re-transferred and re-validated on every
/// anti-entropy tick, forever. This mirrors `FetchCoordinator`'s negative cache
/// on the gossip path, with two deliberate differences:
///
/// * **Keyed by (peer, id), not id.** A content id covers the economic body
///   only — the envelope (author, signature, Lamport, parents) is not hashed —
///   so one peer's bad envelope for id X says nothing about another peer's copy
///   of X. Keyed by id alone, any allowlisted peer could suppress a directive
///   node-wide by serving a corrupt copy first. Per peer it can only suppress
///   its own copy, which an honest peer never gets wrong and a hostile one
///   gains nothing by.
/// * **Only permanent refusals go in.** Deciding which refusals those are is the
///   caller's job (`gl-node`'s intake path) and the dangerous half of this
///   design: anything that can become acceptable later — a missing parent, an
///   account not yet open, a full orphan buffer, an I/O or commit failure — must
///   never be recorded, or the cache silently turns a delay into a loss for a
///   whole TTL.
///
/// Every operation is amortized O(1): entries leave in insertion order (the
/// TTL is uniform, so that is also expiry order), and an existing entry is
/// never refreshed, so the queue and the map stay in 1:1 correspondence.
#[derive(Debug)]
pub struct RefusalCache {
    ttl: Duration,
    capacity: usize,
    per_peer: usize,
    /// peer → id → when it was refused. Two levels so lookups borrow `&str`.
    by_peer: HashMap<String, HashMap<String, Instant>>,
    /// Insertion (= expiry) order, one record per cached (peer, id).
    order: VecDeque<(String, String, Instant)>,
}

impl RefusalCache {
    /// The production limits ([`REFUSAL_CACHE_TTL`], [`REFUSAL_CACHE_CAPACITY`],
    /// [`REFUSAL_CACHE_PER_PEER`]).
    pub fn new() -> Self {
        Self::with_limits(
            REFUSAL_CACHE_TTL,
            REFUSAL_CACHE_CAPACITY,
            REFUSAL_CACHE_PER_PEER,
        )
    }

    /// Explicit limits, so tests can drive the TTL and the caps directly.
    pub fn with_limits(ttl: Duration, capacity: usize, per_peer: usize) -> Self {
        Self {
            ttl,
            capacity,
            per_peer,
            by_peer: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Cached (peer, id) pairs, fresh or not yet swept.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    fn is_fresh(&self, refused_at: Instant, now: Instant) -> bool {
        now.saturating_duration_since(refused_at) < self.ttl
    }

    /// Record that `id`, as served by `peer`, was refused for good. Returns
    /// whether the pair is cached once this returns.
    ///
    /// Only a content id is ever recorded. `Want`s are built from adverts that
    /// are form-checked to 64-hex content ids (M-26), so nothing else could be
    /// suppressed by an entry — and an unchecked `SupplyEntry.id` is peer-chosen
    /// and may be most of a frame long, which would make the count caps bound
    /// nothing about memory.
    ///
    /// An already-cached pair is left alone rather than refreshed: every re-
    /// refusal inside the TTL would otherwise extend it indefinitely, and the
    /// TTL is the self-healing guarantee.
    pub fn record(&mut self, peer: &str, id: &str, now: Instant) -> bool {
        self.evict_expired(now);
        if !is_content_id(id) {
            return false;
        }
        let held_for_peer = match self.by_peer.get(peer) {
            Some(ids) if ids.contains_key(id) => return true,
            Some(ids) => ids.len(),
            None => 0,
        };
        if held_for_peer >= self.per_peer {
            return false;
        }
        while self.order.len() >= self.capacity {
            if !self.pop_oldest() {
                return false;
            }
        }
        self.by_peer
            .entry(peer.to_owned())
            .or_default()
            .insert(id.to_owned(), now);
        self.order.push_back((peer.to_owned(), id.to_owned(), now));
        true
    }

    /// Whether `id` from `peer` was permanently refused within the TTL.
    pub fn is_refused(&self, peer: &str, id: &str, now: Instant) -> bool {
        self.by_peer
            .get(peer)
            .and_then(|ids| ids.get(id))
            .is_some_and(|refused_at| self.is_fresh(*refused_at, now))
    }

    /// Drop from `want` every id `peer` served us a refused copy of; returns
    /// how many were dropped.
    ///
    /// Order-preserving, so the `Want` chunks still follow the advert.
    pub fn retain_wanted(&self, peer: &str, want: &mut Vec<String>, now: Instant) -> usize {
        let Some(refused) = self.by_peer.get(peer) else {
            return 0;
        };
        let before = want.len();
        want.retain(|id| {
            !refused
                .get(id.as_str())
                .is_some_and(|refused_at| self.is_fresh(*refused_at, now))
        });
        before - want.len()
    }

    /// Forget every refusal older than the TTL; returns how many were dropped.
    ///
    /// Stops at the first fresh entry, so the cost is the number evicted.
    pub fn evict_expired(&mut self, now: Instant) -> usize {
        let mut evicted = 0;
        while let Some((_, _, refused_at)) = self.order.front() {
            if self.is_fresh(*refused_at, now) {
                break;
            }
            self.pop_oldest();
            evicted += 1;
        }
        evicted
    }

    /// Remove the oldest record from both structures; false when empty.
    fn pop_oldest(&mut self) -> bool {
        let Some((peer, id, _)) = self.order.pop_front() else {
            return false;
        };
        if let Some(ids) = self.by_peer.get_mut(&peer) {
            ids.remove(&id);
            if ids.is_empty() {
                self.by_peer.remove(&peer);
            }
        }
        true
    }
}

impl Default for RefusalCache {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DirectiveKind, MAX_MESSAGE_SIZE};
    use std::collections::BTreeMap;

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// `count` distinct 64-hex ids, the shape real content ids have.
    fn hex_ids(count: usize) -> HashSet<String> {
        (0..count).map(|index| format!("{index:064x}")).collect()
    }

    fn sorted(ids: &HashSet<String>) -> Vec<String> {
        let mut sorted: Vec<String> = ids.iter().cloned().collect();
        sorted.sort();
        sorted
    }

    fn as_page(message: &WireMessage) -> (&[String], &[String], bool) {
        match message {
            WireMessage::HaveHeads {
                head_txids,
                directive_ids,
                more,
                ..
            } => (head_txids, directive_ids, *more),
            other => panic!("expected HaveHeads, got {other:?}"),
        }
    }

    fn as_entries(message: &WireMessage) -> &[SupplyEntry] {
        match message {
            WireMessage::Supply { entries, .. } => entries,
            other => panic!("expected Supply, got {other:?}"),
        }
    }

    /// Assert a frame is one the receive path accepts (H-02).
    fn assert_frameable(message: &WireMessage) {
        let wire = message.to_wire().expect("frame must encode");
        assert!(wire.len() <= 4 + MAX_MESSAGE_SIZE as usize);
        WireMessage::decode_checked(&wire[4..]).expect("frame must decode");
    }

    #[test]
    fn test_compute_want_empty_local() {
        let local = HashSet::new();
        let want = compute_want(
            &local,
            &HashSet::new(),
            &["tx1".to_owned(), "tx2".to_owned()],
            &[],
        );
        assert_eq!(want.len(), 2);
    }

    #[test]
    fn test_compute_want_all_present() {
        let local = set(&["tx1", "tx2"]);
        let want = compute_want(
            &local,
            &HashSet::new(),
            &["tx1".to_owned(), "tx2".to_owned()],
            &[],
        );
        assert!(want.is_empty(), "All present → nothing to want");
    }

    #[test]
    fn test_compute_want_partial_overlap() {
        let local = set(&["tx1", "tx3"]);
        let want = compute_want(
            &local,
            &HashSet::new(),
            &["tx1".to_owned(), "tx2".to_owned(), "tx3".to_owned()],
            &[],
        );
        assert_eq!(want, vec!["tx2"]);
    }

    #[test]
    fn test_compute_want_includes_directive_ids() {
        let local_txids = set(&["tx1"]);
        let local_dir = set(&["dir1"]);
        let want = compute_want(
            &local_txids,
            &local_dir,
            &["tx1".to_owned()],
            &["dir1".to_owned(), "dir2".to_owned()],
        );
        assert_eq!(want, vec!["dir2"]);
    }

    #[test]
    fn test_compute_want_dedups_head_also_in_directives() {
        // L-21: every head txid is also a directive id, so a missing head is
        // advertised in both lists. It must be wanted EXACTLY once.
        let want = compute_want(
            &HashSet::new(),
            &HashSet::new(),
            &["tx1".to_owned()],
            &["tx1".to_owned(), "dir2".to_owned()],
        );
        assert_eq!(want, vec!["tx1", "dir2"], "the shared id collapses to one");
    }

    #[test]
    fn test_compute_want_dedups_within_list() {
        // A single list that repeats an id collapses to one want too, in
        // first-occurrence order.
        let want = compute_want(
            &HashSet::new(),
            &HashSet::new(),
            &["tx1".to_owned(), "tx1".to_owned(), "tx2".to_owned()],
            &["dir1".to_owned(), "dir1".to_owned()],
        );
        assert_eq!(want, vec!["tx1", "tx2", "dir1"]);
    }

    #[test]
    fn test_make_have_heads_sorted() {
        let heads = set(&["zzz", "aaa", "mmm"]);
        let msg = make_have_heads(&heads, &HashSet::new());
        match msg {
            WireMessage::HaveHeads { head_txids, .. } => {
                assert_eq!(head_txids, vec!["aaa", "mmm", "zzz"]);
            }
            _ => panic!("Expected HaveHeads"),
        }
    }

    // ── H-02: have_heads pagination ──────────────────────────────────────

    #[test]
    fn test_paginate_have_heads_empty_still_advertises() {
        let pages = paginate_have_heads(&HashSet::new(), &HashSet::new());
        assert_eq!(pages.len(), 1);
        let (heads, directives, more) = as_page(&pages[0]);
        assert!(heads.is_empty());
        assert!(directives.is_empty());
        assert!(!more);
        assert_frameable(&pages[0]);
    }

    #[test]
    fn test_paginate_have_heads_single_id() {
        let ids = hex_ids(1);
        let pages = paginate_have_heads(&ids, &ids);
        assert_eq!(pages.len(), 1);
        let (heads, directives, more) = as_page(&pages[0]);
        assert_eq!(heads.len(), 1);
        assert_eq!(directives.len(), 1);
        assert!(!more);
    }

    #[test]
    fn test_paginate_have_heads_exactly_at_cap() {
        let ids = hex_ids(MAX_HAVE_HEADS);
        let pages = paginate_have_heads(&ids, &ids);
        assert_eq!(pages.len(), 1, "a full page must not spill into a second");
        let (heads, directives, more) = as_page(&pages[0]);
        assert_eq!(heads.len(), MAX_HAVE_HEADS);
        assert_eq!(directives.len(), MAX_HAVE_HEADS);
        assert!(!more);
        assert_frameable(&pages[0]);
    }

    #[test]
    fn test_paginate_have_heads_one_past_cap() {
        let ids = hex_ids(MAX_HAVE_HEADS + 1);
        let pages = paginate_have_heads(&ids, &ids);
        assert_eq!(pages.len(), 2);
        assert_eq!(as_page(&pages[0]).0.len(), MAX_HAVE_HEADS);
        assert!(as_page(&pages[0]).2, "non-final page sets more");
        assert_eq!(as_page(&pages[1]).0.len(), 1);
        assert!(!as_page(&pages[1]).2, "final page clears more");
    }

    #[test]
    fn test_paginate_have_heads_ten_thousand_ids() {
        let ids = hex_ids(10_000);
        let pages = paginate_have_heads(&ids, &ids);
        assert_eq!(pages.len(), 3);
        let sizes: Vec<usize> = pages.iter().map(|page| as_page(page).0.len()).collect();
        assert_eq!(sizes, vec![MAX_HAVE_HEADS, MAX_HAVE_HEADS, 1808]);
        let flags: Vec<bool> = pages.iter().map(|page| as_page(page).2).collect();
        assert_eq!(flags, vec![true, true, false]);
        for page in &pages {
            assert_frameable(page);
        }
    }

    #[test]
    fn test_paginate_have_heads_preserves_content_in_order() {
        let heads = hex_ids(5_000);
        let directives = hex_ids(9_000);
        let pages = paginate_have_heads(&heads, &directives);

        let mut head_union: Vec<String> = Vec::new();
        let mut directive_union: Vec<String> = Vec::new();
        for page in &pages {
            let (page_heads, page_directives, _) = as_page(page);
            head_union.extend_from_slice(page_heads);
            directive_union.extend_from_slice(page_directives);
        }
        assert_eq!(head_union, sorted(&heads));
        assert_eq!(directive_union, sorted(&directives));
    }

    #[test]
    fn test_paginate_have_heads_uneven_list_lengths() {
        // Directives outnumber heads by two pages; the short list simply runs dry.
        let heads = hex_ids(10);
        let directives = hex_ids(MAX_HAVE_HEADS * 2 + 5);
        let pages = paginate_have_heads(&heads, &directives);
        assert_eq!(pages.len(), 3);
        assert_eq!(as_page(&pages[0]).0.len(), 10);
        assert!(as_page(&pages[1]).0.is_empty());
        assert!(as_page(&pages[2]).0.is_empty());
        assert_eq!(as_page(&pages[2]).1.len(), 5);
    }

    // ── H-02: supply truncation ──────────────────────────────────────────

    fn supply_entry(index: usize, bean_bytes: usize) -> SupplyEntry {
        SupplyEntry {
            id: format!("{index:064x}"),
            kind: DirectiveKind::Open,
            economic_bean: "x".repeat(bean_bytes),
            envelope: BTreeMap::from([("openledger-author".to_owned(), "peer-1".to_owned())]),
        }
    }

    #[test]
    fn test_truncate_supply_under_both_caps_is_untouched() {
        let entries: Vec<SupplyEntry> = (0..10).map(|index| supply_entry(index, 64)).collect();
        let message = truncate_supply(entries.clone());
        assert_eq!(as_entries(&message), entries.as_slice());
        assert_frameable(&message);
    }

    #[test]
    fn test_truncate_supply_enforces_entry_cap() {
        let entries: Vec<SupplyEntry> = (0..MAX_SUPPLY_ENTRIES * 4)
            .map(|index| supply_entry(index, 32))
            .collect();
        let message = truncate_supply(entries.clone());
        let kept = as_entries(&message);
        assert_eq!(kept.len(), MAX_SUPPLY_ENTRIES);
        assert_eq!(kept, &entries[..MAX_SUPPLY_ENTRIES], "keeps a prefix");
        assert_frameable(&message);
    }

    /// The finding's worst case: ~17 max-size (1 MiB) entries overflow the frame.
    #[test]
    fn test_truncate_supply_enforces_byte_budget() {
        let entries: Vec<SupplyEntry> = (0..20)
            .map(|index| supply_entry(index, 1024 * 1024))
            .collect();
        let message = truncate_supply(entries);
        let kept = as_entries(&message);
        assert!(
            kept.len() < 20,
            "20 one-MiB entries must not all be framed, kept {}",
            kept.len()
        );
        assert!(!kept.is_empty(), "1 MiB entries fit individually");
        assert!(kept.len() <= MAX_SUPPLY_ENTRIES);
        let wire = message.to_wire().expect("truncated frame must encode");
        assert!(
            wire.len() <= 4 + MAX_MESSAGE_SIZE as usize,
            "frame is {} bytes",
            wire.len()
        );
        WireMessage::decode_checked(&wire[4..]).expect("truncated frame must decode");
    }

    #[test]
    fn test_truncate_supply_drops_entry_larger_than_the_whole_budget() {
        // Cannot ever be framed, so it is filtered rather than emitted.
        let message = truncate_supply(vec![supply_entry(0, SUPPLY_FRAME_BUDGET_BYTES + 1)]);
        assert!(as_entries(&message).is_empty());
    }

    // ── L-33: budget while collecting ────────────────────────────────────

    /// `count` content ids in order, the shape a `Want` carries.
    fn want_ids(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("{index:064x}")).collect()
    }

    /// Index encoded in a `want_ids` id.
    fn index_of(id: &str) -> usize {
        usize::from_str_radix(id, 16).expect("hex id")
    }

    /// L-33 (bytes): a full 1,024-id `Want` whose every match is a 1 MiB entry
    /// produces only what fits the 15 MiB frame — plus the ONE entry whose size
    /// revealed the budget was spent — not all 1,024.
    #[test]
    fn test_build_supply_stops_producing_at_the_byte_budget() {
        let ids = want_ids(crate::protocol::MAX_WANT_IDS);
        let mut produced = 0usize;
        let mut produced_bytes = 0usize;
        let message = build_supply(&ids, |id| {
            produced += 1;
            let entry = supply_entry(index_of(id), 1024 * 1024);
            produced_bytes += estimated_entry_bytes(&entry);
            Some(entry)
        });
        let kept = as_entries(&message).len();
        assert!(
            kept > 0 && kept < 20,
            "the frame holds ~14 MiB entries: {kept}"
        );
        assert_eq!(
            produced,
            kept + 1,
            "exactly one entry past the budget may be produced; the other {} must not be",
            ids.len() - kept - 1
        );
        assert!(
            produced_bytes
                <= SUPPLY_FRAME_BUDGET_BYTES + estimated_entry_bytes(&supply_entry(0, 1024 * 1024)),
            "bytes produced ({produced_bytes}) must be bounded by the budget plus one entry"
        );
        assert_frameable(&message);
    }

    /// L-33 (count): a 1,024-id `Want` of small entries produces exactly
    /// `MAX_SUPPLY_ENTRIES` — the entry cap is checked BEFORE producing, so not
    /// even one extra is serialized.
    #[test]
    fn test_build_supply_stops_producing_at_the_entry_cap() {
        let ids = want_ids(crate::protocol::MAX_WANT_IDS);
        let mut produced = 0usize;
        let message = build_supply(&ids, |id| {
            produced += 1;
            Some(supply_entry(index_of(id), 32))
        });
        assert_eq!(as_entries(&message).len(), MAX_SUPPLY_ENTRIES);
        assert_eq!(
            produced, MAX_SUPPLY_ENTRIES,
            "nothing past the cap is produced"
        );
    }

    /// The re-`Want` loop's contract (H-02): `build_supply` returns exactly
    /// what the old collect-then-`truncate_supply` did — a prefix, deduped,
    /// skipping ids this node lacks — across entry-cap, byte-budget and
    /// oversized-first-entry cases.
    #[test]
    fn test_build_supply_is_identical_to_collect_then_truncate() {
        // Mixed sizes, repeats, and ids the "ledger" does not hold.
        let size_of = |index: usize| match index % 7 {
            0 => 900 * 1024,
            3 => 5,
            _ => 4 * 1024,
        };
        let holds = |index: usize| index % 5 != 2;
        let mut ids = want_ids(700);
        ids.extend(want_ids(40)); // repeats of the first 40
        let lookup = |id: &str| {
            let index = index_of(id);
            holds(index).then(|| supply_entry(index, size_of(index)))
        };

        let mut seen = HashSet::new();
        let old: Vec<SupplyEntry> = ids
            .iter()
            .filter(|id| seen.insert(id.as_str()))
            .filter_map(|id| lookup(id))
            .collect();
        assert_eq!(build_supply(&ids, lookup), truncate_supply(old));

        // An entry too large to frame, FIRST: both answer with an empty Supply
        // (pinned behaviour; see `build_supply`'s docs and T60).
        let oversized = |id: &str| Some(supply_entry(index_of(id), SUPPLY_FRAME_BUDGET_BYTES + 1));
        assert!(as_entries(&build_supply(&want_ids(3), oversized)).is_empty());
        // ...and in the MIDDLE: both answer with the prefix before it.
        let middle = |id: &str| {
            let index = index_of(id);
            let bytes = if index == 2 {
                SUPPLY_FRAME_BUDGET_BYTES + 1
            } else {
                16
            };
            Some(supply_entry(index, bytes))
        };
        let served: Vec<usize> = as_entries(&build_supply(&want_ids(5), middle))
            .iter()
            .map(|entry| index_of(&entry.id))
            .collect();
        assert_eq!(served, vec![0, 1]);
    }

    /// End-to-end over the prefix rule: a requester re-`Want`ing whatever was
    /// not served always makes progress and finishes, under both caps at once.
    #[test]
    fn test_build_supply_rewant_loop_converges() {
        let lookup = |id: &str| {
            let index = index_of(id);
            // Every 100th id is not held: the loop must end, not spin on it.
            (index % 100 != 99).then(|| {
                supply_entry(
                    index,
                    if index.is_multiple_of(3) {
                        700 * 1024
                    } else {
                        64
                    },
                )
            })
        };
        let mut remaining = want_ids(crate::protocol::MAX_WANT_IDS);
        let mut received: HashSet<String> = HashSet::new();
        let mut rounds = 0;
        loop {
            rounds += 1;
            assert!(rounds < 1_000, "the re-Want loop must terminate");
            let message = build_supply(&remaining, lookup);
            assert_frameable(&message);
            let served: HashSet<&str> =
                as_entries(&message).iter().map(|e| e.id.as_str()).collect();
            let next: Vec<String> = remaining
                .iter()
                .filter(|id| !served.contains(id.as_str()))
                .cloned()
                .collect();
            received.extend(served.iter().map(|id| (*id).to_owned()));
            if next.len() == remaining.len() {
                break;
            }
            remaining = next;
        }
        let expected = (0..crate::protocol::MAX_WANT_IDS)
            .filter(|i| i % 100 != 99)
            .count();
        assert_eq!(received.len(), expected, "every held id arrives");
        assert!(remaining.iter().all(|id| index_of(id) % 100 == 99));
    }

    // ── L-34: refusal cache ──────────────────────────────────────────────

    fn cid(index: usize) -> String {
        format!("{index:064x}")
    }

    #[test]
    fn test_refusal_cache_records_per_peer_and_expires_at_the_ttl() {
        let ttl = Duration::from_secs(60);
        let mut cache = RefusalCache::with_limits(ttl, 100, 100);
        let start = Instant::now();
        assert!(cache.record("peer-a", &cid(1), start));
        assert!(cache.is_refused("peer-a", &cid(1), start));
        assert!(
            !cache.is_refused("peer-b", &cid(1), start),
            "a refusal of peer-a's copy says nothing about peer-b's"
        );

        let mut want = vec![cid(0), cid(1), cid(2)];
        assert_eq!(cache.retain_wanted("peer-a", &mut want, start), 1);
        assert_eq!(want, vec![cid(0), cid(2)], "order-preserving");
        let mut other = vec![cid(1)];
        assert_eq!(cache.retain_wanted("peer-b", &mut other, start), 0);

        let almost = start + ttl - Duration::from_millis(1);
        assert!(cache.is_refused("peer-a", &cid(1), almost));
        let at_ttl = start + ttl;
        assert!(
            !cache.is_refused("peer-a", &cid(1), at_ttl),
            "self-heals at the TTL"
        );
        let mut want = vec![cid(1)];
        assert_eq!(cache.retain_wanted("peer-a", &mut want, at_ttl), 0);
        assert_eq!(cache.evict_expired(at_ttl), 1);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_refusal_cache_does_not_refresh_an_existing_entry() {
        let ttl = Duration::from_secs(60);
        let mut cache = RefusalCache::with_limits(ttl, 100, 100);
        let start = Instant::now();
        cache.record("peer-a", &cid(1), start);
        // Re-refused just before expiry: must NOT extend the TTL.
        assert!(cache.record("peer-a", &cid(1), start + ttl - Duration::from_secs(1)));
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_refused("peer-a", &cid(1), start + ttl));
    }

    #[test]
    fn test_refusal_cache_bounds_memory() {
        let now = Instant::now();
        let mut cache = RefusalCache::with_limits(Duration::from_secs(60), 8, 5);
        // Per-peer share: the sixth id from one peer is not cached...
        for index in 0..6 {
            cache.record("peer-a", &cid(index), now);
        }
        assert_eq!(cache.len(), 5);
        assert!(!cache.is_refused("peer-a", &cid(5), now));
        // ...global capacity evicts the OLDEST, whoever it belonged to.
        for index in 0..5 {
            cache.record("peer-b", &cid(index), now);
        }
        assert_eq!(cache.len(), 8);
        assert!(!cache.is_refused("peer-a", &cid(0), now), "oldest evicted");
        assert!(cache.is_refused("peer-a", &cid(2), now));
        assert!(cache.is_refused("peer-b", &cid(4), now));
        // Anything but a content id is never recorded (peer-chosen length).
        assert!(!cache.record("peer-c", &"z".repeat(4096), now));
        assert!(!cache.record("peer-c", &format!("{:064X}", 0xabcdusize), now));
        assert_eq!(cache.len(), 8);
    }

    // ─── L-35 / R-19 (T69): the lookup/sorted-slice variants ─────────────

    fn sorted_arc(ids: &HashSet<String>) -> std::sync::Arc<[String]> {
        sorted(ids).into()
    }

    /// The advert is byte-identical: every page the lazy, sorted-slice
    /// pagination yields encodes to exactly the bytes the set-based one does,
    /// for empty, single-page, boundary and multi-page shapes, with uneven
    /// head and directive counts in both directions.
    ///
    /// Bug-catch: compute `page_count` from the directive count alone, or
    /// mark the last page `more: true`, and the frames differ.
    #[test]
    fn sorted_pagination_is_identical_to_the_set_pagination() {
        let shapes = [
            (0, 0),
            (1, 1),
            (0, 7),
            (3, MAX_HAVE_HEADS),
            (2, MAX_HAVE_HEADS + 1),
            (MAX_HAVE_HEADS + 5, 10),
            (17, 3 * MAX_HAVE_HEADS + 123),
        ];
        for (head_count, directive_count) in shapes {
            let directives = hex_ids(directive_count);
            // Heads come from a disjoint range so a shape can have more heads
            // than directives; pagination treats the two lists independently.
            let heads: HashSet<String> = (0..head_count)
                .map(|index| format!("{:064x}", index * 7 + 1_000_000))
                .collect();

            let old: Vec<WireMessage> = paginate_have_heads(&heads, &directives);
            let lazy = paginate_have_heads_sorted(sorted(&heads), sorted_arc(&directives));
            assert_eq!(
                lazy.len(),
                old.len(),
                "page count, shape {head_count}/{directive_count}"
            );
            let new: Vec<WireMessage> = lazy.collect();
            assert_eq!(new, old, "shape {head_count}/{directive_count}");
            for (new_page, old_page) in new.iter().zip(&old) {
                assert_eq!(
                    new_page.to_wire().unwrap(),
                    old_page.to_wire().unwrap(),
                    "byte-identical frames, shape {head_count}/{directive_count}"
                );
            }
        }
    }

    /// The Want set: identical to [`compute_want`] whenever the old function
    /// was right, and differing only by the T59 fix — a remote head this node
    /// holds as an interior (non-head) directive is no longer wanted.
    ///
    /// Bug-catch: check remote heads against the local HEADS again (the old
    /// rule) and `interior` reappears in the Want.
    #[test]
    fn want_by_membership_is_the_old_want_minus_present_ids() {
        let local_all = hex_ids(50);
        let local_heads: HashSet<String> = sorted(&local_all).into_iter().rev().take(3).collect();
        let interior = sorted(&local_all)[10].clone();
        assert!(!local_heads.contains(&interior));
        let missing: Vec<String> = (100..110).map(|index| format!("{index:064x}")).collect();

        // The remote advertises: a missing head, a local head, our interior
        // directive as ITS head, a repeat, and a mix of present and missing ids.
        let remote_heads = vec![
            missing[0].clone(),
            sorted(&local_heads)[0].clone(),
            interior.clone(),
            missing[0].clone(),
        ];
        let mut remote_ids: Vec<String> = sorted(&local_all).into_iter().step_by(5).collect();
        remote_ids.extend(missing.iter().cloned());
        remote_ids.push(missing[3].clone());

        let old = compute_want(&local_heads, &local_all, &remote_heads, &remote_ids);
        let new =
            compute_want_by_membership(|id| local_all.contains(id), &remote_heads, &remote_ids);

        let expected: Vec<String> = old
            .iter()
            .filter(|id| !local_all.contains(*id))
            .cloned()
            .collect();
        assert_eq!(
            new, expected,
            "the old Want minus locally present ids, order kept"
        );
        assert!(
            old.contains(&interior),
            "premise: the old rule re-wanted a held head"
        );
        assert!(!new.contains(&interior), "T59: a held id is never wanted");
        assert_eq!(
            new, missing,
            "every missing id exactly once, first-occurrence order"
        );

        // Where the old rule was right (no remote head is a local interior
        // directive), the two are identical.
        let honest_heads = vec![missing[0].clone(), sorted(&local_heads)[1].clone()];
        assert_eq!(
            compute_want_by_membership(|id| local_all.contains(id), &honest_heads, &remote_ids),
            compute_want(&local_heads, &local_all, &honest_heads, &remote_ids)
        );
    }

    // ── T77: the receiver's record estimate ─────────────────────────────

    fn parsed(text: &str) -> Vec<ledger::model::Directive> {
        ledger::parse::parse_file(text).expect("fixture parses")
    }

    /// `RecordEstimate` is the append arm's record length to the byte, for
    /// sets whose payload length crosses a digit boundary of the header.
    ///
    /// Bug-catch: add the old per-entry `estimated_entry_bytes` allowance (or
    /// drop the separators) and the equality fails.
    #[test]
    fn record_estimate_is_the_journal_record_length() {
        let mut text = String::new();
        let mut directives = Vec::new();
        for index in 0..300 {
            text = format!(
                "2024-01-01 open Assets:A{index:03} USD\n  openledger-author: \"a\"\n  \
                 openledger-lamport: \"{}\"\n",
                index + 1
            );
            directives.extend(parsed(&text));
            let mut estimate = RecordEstimate::new();
            for directive in &directives {
                estimate.add(RecordEstimate::directive_bytes(directive));
            }
            let record = ledger::journal::record_bytes(&ledger::serialize::full_file_serialize(
                &directives,
                &[],
            ));
            assert_eq!(
                estimate.record_bytes(),
                record.len() as u64,
                "{} directives",
                directives.len()
            );
        }
        assert!(!text.is_empty());
        assert_eq!(RecordEstimate::new().record_bytes(), 0);
        // A one-byte payload, the smallest header.
        let one = RecordEstimate::new().with(1);
        assert_eq!(
            one.record_bytes(),
            ledger::journal::record_bytes("x").len() as u64
        );
    }

    /// `resident_weight` grows with what a directive holds, and charges every
    /// non-empty metadata map at least a whole B-tree node.
    #[test]
    fn resident_weight_counts_postings_and_metadata() {
        let small = parsed("2024-01-01 *\n  Assets:A 1 USD\n  Assets:B -1 USD\n");
        let with_meta = parsed("2024-01-01 *\n  Assets:A 1 USD\n    k: \"v\"\n  Assets:B -1 USD\n");
        let small = resident_weight(&small[0]);
        let with_meta = resident_weight(&with_meta[0]);
        assert!(
            with_meta >= small + BTREE_NODE_CAPACITY * 2 * std::mem::size_of::<String>(),
            "{small} → {with_meta}"
        );
    }
}
