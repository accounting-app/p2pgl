//! Orphan buffer (§3.4.4).
//!
//! Buffers transactions that cannot be applied yet:
//! - their parent txids are not in the local DAG, or
//! - an account they post to is not open at their date (M-09).
//!
//! - Max 10,000 entries or 1 hour TTL, whichever first.
//! - On parent arrival — or on an `open` for a waited-on account — re-attempt
//!   the insert.
//! - Emits `want` for missing parent IDs.
//!
//! Both wait reasons share ONE buffer, and therefore one set of budgets: the
//! global and per-peer entry counts, the global and per-peer byte budgets
//! (0820-L8) and the TTL. A separate account-wait buffer would have doubled the
//! resident-memory ceiling a peer can pin and would have needed every one of
//! those budgets re-implemented — a fresh M-05 for the price of avoiding one
//! extra index.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use ledger::model::Directive;

use crate::anti_entropy::RefusalCache;

/// Maximum number of orphans to buffer.
pub const MAX_ORPHANS: usize = 10_000;
/// Maximum orphans attributed to a single peer (M-3).
pub const MAX_ORPHANS_PER_PEER: usize = 1_000;

/// Maximum total *cost* of buffered orphans in bytes (0820-L8, 0902-L20).
///
/// Entry counts alone let one peer pin ~1 GiB (1,000 × 1 MiB max-size bodies)
/// for the full TTL. Sizing the buffer bounds resident memory regardless of
/// how large individual directives are.
///
/// L-20: what is measured is the entry's FULL cost, not just its economic body.
/// The body is what `economic_canonical_serialize` produces — which by
/// definition omits every `openledger-*` key — so under the old body-only
/// accounting the envelope (a 128-char signature hex, an author id, a parents
/// list that grows with the merge width) and both reverse indexes rode free. An
/// envelope-heavy directive therefore cost the budget a small fraction of what
/// it cost the allocator; see [`entry_cost_bytes`].
pub const MAX_ORPHAN_BYTES: usize = 64 * 1024 * 1024;
/// Maximum cost in bytes attributed to a single peer. See [`MAX_ORPHAN_BYTES`].
pub const MAX_ORPHAN_BYTES_PER_PEER: usize = 16 * 1024 * 1024;

/// Maximum age for an orphan entry.
pub const MAX_ORPHAN_AGE: Duration = Duration::from_secs(3600); // 1 hour

/// Cadence for the background TTL sweep (L-20).
///
/// Derived from [`MAX_ORPHAN_AGE`] rather than configured: it is not a policy
/// knob, it is how often the policy is applied. A quarter of the TTL bounds how
/// long an expired entry can keep holding budget at 25% of its own lifetime,
/// for four sweeps per TTL over a buffer that is empty on a quiet mesh — which
/// is exactly the case this timer exists for.
pub const ORPHAN_EVICTION_INTERVAL: Duration = Duration::from_secs(MAX_ORPHAN_AGE.as_secs() / 4);

/// Prefix of the envelope metadata keys excluded from the economic body.
///
/// Mirrors `ledger::serialize`'s own test for envelope keys; these are the
/// bytes that are resident in the buffered `Directive` but absent from
/// `economic_canonical_serialize`, and so the bytes L-20 was under-counting.
const ENVELOPE_KEY_PREFIX: &str = "openledger-";

/// Bookkeeping charged per reverse-index entry (L-20).
///
/// A `waiting_on` / `waiting_on_account` entry is a map key, a `HashSet` that
/// holds the orphan id, and the table slots both live in. The two strings are
/// charged at their real length; this constant stands in for the slots and the
/// set's own allocation. One flat number covers both indexes — precision is not
/// the goal, a bounded ceiling is.
pub const INDEX_ENTRY_OVERHEAD_BYTES: usize = 64;

/// Bookkeeping charged once per buffered entry (L-20).
///
/// Covers the `entries` map slot, the `OrphanEntry` struct's own fields, and
/// the per-peer counter rows. The id and the envelope are charged separately at
/// their real length.
pub const ENTRY_OVERHEAD_BYTES: usize = 128;

/// What [`OrphanBuffer::insert_waiting`] did with a directive (L-20).
///
/// A three-way outcome rather than a `bool`, because "already buffered" and
/// "refused for want of budget" are different events that used to share the
/// `false`-ish path: at a full buffer a re-gossiped duplicate was charged
/// against the budget gate *before* containment was checked, so it was logged
/// and counted as a refusal even though the entry was sitting in the buffer
/// already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanInsert {
    /// Newly buffered; its cost is now charged against the budgets.
    Buffered,
    /// Already buffered. Nothing changed and nothing was charged — in
    /// particular the entry is NOT charged a second time.
    Duplicate,
    /// Refused: a global or per-peer budget (entry count or cost bytes) is
    /// exhausted.
    BudgetExhausted,
}

impl OrphanInsert {
    /// Whether the directive is in the buffer once this call returns.
    ///
    /// True for both [`Buffered`](Self::Buffered) and
    /// [`Duplicate`](Self::Duplicate) — the callers that only want to know
    /// "is it safe to stop tracking this id" ask this.
    pub fn accepted(&self) -> bool {
        matches!(self, OrphanInsert::Buffered | OrphanInsert::Duplicate)
    }
}

/// A buffered orphan entry.
#[derive(Debug, Clone)]
pub struct OrphanEntry {
    /// The content ID of this directive.
    pub id: String,
    /// The directive waiting for its parents.
    pub directive: Directive,
    /// The parent txids that are currently missing.
    pub missing_parents: Vec<String>,
    /// Accounts whose `open` this entry is waiting for (M-09).
    pub missing_accounts: Vec<String>,
    /// When this orphan was first buffered.
    pub buffered_at: Instant,
    /// Gossip sender that delivered this orphan, when known.
    pub from_peer: Option<String>,
    /// Full cost charged to the byte budgets when this entry was inserted.
    ///
    /// Stored rather than recomputed on removal *because* the wait lists shrink
    /// in place as reasons resolve: recomputing at removal time would refund
    /// less than was charged and leak budget on every partially-resolved entry.
    /// Charging and refunding this one number keeps the accounting symmetric by
    /// construction (L-20).
    cost_bytes: usize,
}

impl OrphanEntry {
    /// Whether every reason this entry was buffered has been resolved.
    fn is_ready(&self) -> bool {
        self.missing_parents.is_empty() && self.missing_accounts.is_empty()
    }
}

/// Envelope bytes a metadata map holds that the economic body does not (L-20).
fn envelope_bytes(metadata: &BTreeMap<String, String>) -> usize {
    metadata
        .iter()
        .filter(|(key, _)| key.starts_with(ENVELOPE_KEY_PREFIX))
        .map(|(key, value)| key.len().saturating_add(value.len()))
        .sum()
}

/// The full budgeted cost of one buffered entry, in bytes (L-20).
///
/// Body + envelope + index bookkeeping. The body is the only part the pre-L-20
/// accounting charged; the audit measured the gap at 3–5× under envelope-heavy
/// load, and the gap grows with the signature, the author id, the parents list
/// and the number of things the entry waits on — i.e. precisely with what a
/// hostile peer controls.
///
/// This is an estimate and is meant to be: it does not model allocator
/// behaviour, capacity slack or the `Directive`'s own in-memory layout. It only
/// has to be an over-approximation of nothing and an under-approximation of
/// little, so that the budgets bound resident memory rather than tracking one
/// summand of it.
fn entry_cost_bytes(
    id: &str,
    directive: &Directive,
    missing_parents: &[String],
    missing_accounts: &[String],
) -> usize {
    let body = ledger::serialize::economic_canonical_serialize(directive).len();

    let mut envelope = envelope_bytes(crate::union_merge::directive_metadata(directive));
    if let Directive::Transaction(transaction) = directive {
        // Posting-level `openledger-*` keys are stripped from the economic body
        // by the same rule, so they were uncounted for the same reason.
        for posting in &transaction.postings {
            envelope = envelope.saturating_add(envelope_bytes(&posting.metadata));
        }
    }

    let index: usize = missing_parents
        .iter()
        .chain(missing_accounts.iter())
        .map(|waited_on| {
            waited_on
                .len()
                .saturating_add(id.len())
                .saturating_add(INDEX_ENTRY_OVERHEAD_BYTES)
        })
        .sum();

    ENTRY_OVERHEAD_BYTES
        .saturating_add(id.len())
        .saturating_add(body)
        .saturating_add(envelope)
        .saturating_add(index)
}

/// The orphan buffer.
#[derive(Debug)]
pub struct OrphanBuffer {
    /// Orphans keyed by their content ID.
    entries: HashMap<String, OrphanEntry>,
    /// Reverse index: parent_id → [orphan_id]. For fast lookup on parent arrival.
    waiting_on: HashMap<String, HashSet<String>>,
    /// Reverse index: account → [orphan_id], for lookup on `open` arrival (M-09).
    waiting_on_account: HashMap<String, HashSet<String>>,
    /// Count of buffered orphans per delivering peer.
    peer_counts: HashMap<String, usize>,
    /// Buffered cost in bytes per delivering peer (0820-L8, 0902-L20).
    peer_bytes: HashMap<String, usize>,
    /// Total buffered cost in bytes.
    total_bytes: usize,
    /// Global byte budget (`MAX_ORPHAN_BYTES`; overridable in tests).
    max_bytes: usize,
    /// Per-peer byte budget (`MAX_ORPHAN_BYTES_PER_PEER`; overridable in tests).
    max_bytes_per_peer: usize,
    /// A lower bound on every resident entry's `buffered_at` (L-54).
    ///
    /// `insert_waiting` used to run the full O(n) TTL sweep on EVERY insert —
    /// and `drain_orphans` re-buffers a freed entry through `insert_waiting`,
    /// under both the ledger and the buffer write locks, so a drain releasing k
    /// account-waiting entries paid k full passes over the buffer. Nothing can
    /// have expired before `oldest_buffered_at + MAX_ORPHAN_AGE`, so a sweep
    /// before then is pure waste; this makes the check O(1) and a pass happen
    /// only once something may genuinely be stale.
    ///
    /// Kept as a BOUND, not the exact minimum: inserts only lower it, removals
    /// leave it (possibly stale, never wrong), and each full sweep recomputes it
    /// exactly — so a stale bound costs at most one pass that then corrects it.
    /// `None` exactly when the buffer is empty.
    oldest_buffered_at: Option<Instant>,
    /// Full sweeps actually performed; the observable L-54's tests read.
    #[cfg(test)]
    sweeps: usize,
    /// Directives the anti-entropy path refused for good, per peer (L-34).
    ///
    /// Lives here because this buffer is already the node's one shared,
    /// lock-guarded record of "what intake did with a directive it could not
    /// stage": every ALPN ingest path reaches it, and its timer-driven
    /// [`Self::evict_expired`] sweep ages this cache out on a quiet mesh too. A
    /// separate handle would have to be threaded through every construction
    /// site of the ALPN handler. It shares NO budget with the orphans: a refused
    /// id is never buffered, and an orphan is never a refusal.
    refusals: RefusalCache,
}

impl OrphanBuffer {
    pub fn new() -> Self {
        OrphanBuffer {
            entries: HashMap::new(),
            waiting_on: HashMap::new(),
            waiting_on_account: HashMap::new(),
            peer_counts: HashMap::new(),
            peer_bytes: HashMap::new(),
            total_bytes: 0,
            max_bytes: MAX_ORPHAN_BYTES,
            max_bytes_per_peer: MAX_ORPHAN_BYTES_PER_PEER,
            oldest_buffered_at: None,
            #[cfg(test)]
            sweeps: 0,
            refusals: RefusalCache::new(),
        }
    }

    /// The anti-entropy refusal cache (L-34). See the field docs.
    pub fn refusals(&self) -> &RefusalCache {
        &self.refusals
    }

    /// Mutable access to the anti-entropy refusal cache (L-34).
    pub fn refusals_mut(&mut self) -> &mut RefusalCache {
        &mut self.refusals
    }

    /// Test-only constructor with small byte budgets.
    #[cfg(test)]
    fn with_byte_budgets(max_bytes: usize, max_bytes_per_peer: usize) -> Self {
        OrphanBuffer {
            max_bytes,
            max_bytes_per_peer,
            ..Self::new()
        }
    }

    /// Buffer an orphan waiting for missing parents.
    pub fn insert(
        &mut self,
        id: String,
        directive: Directive,
        missing_parents: Vec<String>,
        from_peer: Option<String>,
    ) -> OrphanInsert {
        self.insert_waiting(id, directive, missing_parents, Vec::new(), from_peer)
    }

    /// Buffer an orphan waiting for an `open` on each of `missing_accounts`
    /// (M-09). Same budgets and TTL as the parent-wait path.
    pub fn insert_awaiting_accounts(
        &mut self,
        id: String,
        directive: Directive,
        missing_accounts: Vec<String>,
        from_peer: Option<String>,
    ) -> OrphanInsert {
        self.insert_waiting(id, directive, Vec::new(), missing_accounts, from_peer)
    }

    /// Buffer an orphan waiting on any mix of parents and accounts.
    ///
    /// See [`OrphanInsert`] for the three outcomes. Order of the checks is
    /// load-bearing (L-20): TTL sweep, then containment, then the budgets.
    pub fn insert_waiting(
        &mut self,
        id: String,
        directive: Directive,
        missing_parents: Vec<String>,
        missing_accounts: Vec<String>,
        from_peer: Option<String>,
    ) -> OrphanInsert {
        // Expired entries first — they may be exactly what is holding the
        // budget this insert is about to be measured against. (The background
        // sweep in gl-node keeps this true on a quiet mesh too; see
        // `evict_expired`.) O(1) unless something can actually have expired
        // (L-54): see `oldest_buffered_at`.
        let now = Instant::now();
        self.evict_expired(now);

        // L-20: containment BEFORE the budget gates. A re-gossiped duplicate
        // changes nothing and costs nothing, so at a full buffer it must report
        // itself as the duplicate it is. The old order asked the budgets first
        // and turned every duplicate arriving at a full buffer into a "buffer
        // full or per-peer quota exceeded" warning and a refusal metric —
        // pointing operators at capacity when the real event was ordinary
        // gossip redelivery.
        if self.entries.contains_key(&id) {
            return OrphanInsert::Duplicate;
        }

        if self.entries.len() >= MAX_ORPHANS {
            return OrphanInsert::BudgetExhausted;
        }

        // Byte budgets (0820-L8): entry counts alone let one peer pin ~1 GiB of
        // max-size bodies for the TTL; size the buffer as well. The size charged
        // is the entry's full cost, not its body alone (L-20).
        let cost_bytes = entry_cost_bytes(&id, &directive, &missing_parents, &missing_accounts);
        if self.total_bytes.saturating_add(cost_bytes) > self.max_bytes {
            return OrphanInsert::BudgetExhausted;
        }

        if let Some(ref peer_id) = from_peer {
            let count = self.peer_counts.get(peer_id).copied().unwrap_or(0);
            if count >= MAX_ORPHANS_PER_PEER {
                return OrphanInsert::BudgetExhausted;
            }
            let bytes = self.peer_bytes.get(peer_id).copied().unwrap_or(0);
            if bytes.saturating_add(cost_bytes) > self.max_bytes_per_peer {
                return OrphanInsert::BudgetExhausted;
            }
        }

        // Build reverse indexes.
        for parent in &missing_parents {
            self.waiting_on
                .entry(parent.clone())
                .or_default()
                .insert(id.clone());
        }
        for account in &missing_accounts {
            self.waiting_on_account
                .entry(account.clone())
                .or_default()
                .insert(id.clone());
        }

        if let Some(ref peer_id) = from_peer {
            *self.peer_counts.entry(peer_id.clone()).or_insert(0) += 1;
            *self.peer_bytes.entry(peer_id.clone()).or_insert(0) += cost_bytes;
        }
        self.total_bytes += cost_bytes;

        self.oldest_buffered_at = Some(
            self.oldest_buffered_at
                .map_or(now, |oldest| oldest.min(now)),
        );
        self.entries.insert(
            id.clone(),
            OrphanEntry {
                id,
                directive,
                missing_parents,
                missing_accounts,
                buffered_at: now,
                from_peer,
                cost_bytes,
            },
        );

        OrphanInsert::Buffered
    }

    /// Notify the buffer that a parent ID has arrived.
    /// Returns any orphans that are now fully resolved.
    pub fn parent_arrived(&mut self, parent_id: &str) -> Vec<OrphanEntry> {
        let Some(orphan_ids) = self.waiting_on.remove(parent_id) else {
            return Vec::new();
        };
        self.release_resolved(orphan_ids, |entry| {
            entry.missing_parents.retain(|p| p != parent_id)
        })
    }

    /// Notify the buffer that an `open` for `account` is now in the DAG (M-09).
    /// Returns any orphans that are now fully resolved.
    pub fn account_opened(&mut self, account: &str) -> Vec<OrphanEntry> {
        let Some(orphan_ids) = self.waiting_on_account.remove(account) else {
            return Vec::new();
        };
        self.release_resolved(orphan_ids, |entry| {
            entry.missing_accounts.retain(|a| a != account)
        })
    }

    /// Drop one wait reason from each named entry and hand back those that are
    /// now ready. An entry blocked on several reasons stays until the last one
    /// clears.
    fn release_resolved(
        &mut self,
        orphan_ids: HashSet<String>,
        mut clear_reason: impl FnMut(&mut OrphanEntry),
    ) -> Vec<OrphanEntry> {
        let mut resolved = Vec::new();
        for orphan_id in orphan_ids {
            let Some(entry) = self.entries.get_mut(&orphan_id) else {
                continue;
            };
            clear_reason(entry);
            if !entry.is_ready() {
                continue;
            }
            if let Some(entry) = self.entries.remove(&orphan_id) {
                self.release_entry_accounting(&entry);
                resolved.push(entry);
            }
        }
        self.forget_bound_if_empty();
        self.debug_assert_accounting_drained();
        resolved
    }

    /// Get all parent IDs we're still waiting on (for `want` messages).
    pub fn wanted_parent_ids(&self) -> HashSet<String> {
        self.waiting_on.keys().cloned().collect()
    }

    /// Get all accounts whose `open` some buffered entry is waiting for (M-09).
    ///
    /// Deliberately NOT part of [`Self::wanted_parent_ids`]: these are account
    /// names, not content ids, and must never be put on the wire as `want`s.
    pub fn wanted_accounts(&self) -> HashSet<String> {
        self.waiting_on_account.keys().cloned().collect()
    }

    /// Number of buffered orphans.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total cost currently charged against the global byte budget (L-20).
    ///
    /// Exposed so the accounting can be asserted symmetric: whatever
    /// `insert_waiting` charges, removal, resolution and eviction refund, and
    /// this returns to zero whenever the buffer empties.
    pub fn total_cost_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Evict every entry older than [`MAX_ORPHAN_AGE`] as of `now`, returning
    /// the ids removed.
    ///
    /// Public and `now`-parameterised on purpose (L-20). Eviction used to run
    /// only as a side effect of `insert_waiting`, so a mesh that went quiet —
    /// no gossip, nothing to buffer, which is exactly the state a stalled peer
    /// leaves behind — retained expired orphans for as long as it stayed quiet,
    /// holding budget against the traffic that would eventually need it. The
    /// `gl-node` binary drives this on a timer at [`ORPHAN_EVICTION_INTERVAL`];
    /// `insert_waiting` still calls it so a busy buffer frees space before it
    /// measures itself.
    ///
    /// Taking `now` rather than reading the clock keeps the TTL testable
    /// without sleeping for an hour.
    ///
    /// ## Lock-hold cost (T41 — verified, left whole rather than chunked)
    ///
    /// The `gl-node` sweep holds the buffer's write lock for this entire pass,
    /// so nothing can buffer or drain an orphan while it runs. That is fine at
    /// the current [`MAX_ORPHANS`] (10,000): the pass is two in-memory walks
    /// with no I/O and no hashing — one `filter` over the entry map, then one
    /// `remove` per expired id, each unlinking that id from the wait indices
    /// and refunding its recorded `cost_bytes`. It is microseconds at this size,
    /// against a sweep cadence of a quarter of the one-hour TTL.
    ///
    /// Chunking it (collect a bounded slice of expired ids, release the lock,
    /// repeat) would buy nothing today and would cost the property that makes
    /// the accounting checkable: `debug_assert_accounting_drained` and
    /// `total_cost_bytes()` describe a buffer nobody is mutating mid-pass.
    ///
    /// The trade flips if `MAX_ORPHANS` grows by an order of magnitude, since
    /// the hold is linear in the buffer and the contention it creates is on the
    /// P2P receive path. Raising that constant is the signal to revisit this.
    ///
    /// ## Amortized (L-54)
    ///
    /// The pass only runs once the oldest resident entry can have expired —
    /// `oldest_buffered_at` is a lower bound on every `buffered_at` — so
    /// the per-insert call in `insert_waiting` (and with it every re-buffer a
    /// drain performs under both write locks) is O(1) until something is
    /// genuinely stale, and the pass that then runs re-derives the bound.
    ///
    /// Also ages out the anti-entropy refusal cache (L-34), whose own sweep
    /// costs only what it evicts.
    pub fn evict_expired(&mut self, now: Instant) -> Vec<String> {
        self.refusals.evict_expired(now);
        let Some(oldest) = self.oldest_buffered_at else {
            return Vec::new();
        };
        if now.saturating_duration_since(oldest) <= MAX_ORPHAN_AGE {
            return Vec::new();
        }
        #[cfg(test)]
        {
            self.sweeps += 1;
        }

        let mut expired: Vec<String> = Vec::new();
        let mut survivors_oldest: Option<Instant> = None;
        for (id, entry) in &self.entries {
            if now.saturating_duration_since(entry.buffered_at) > MAX_ORPHAN_AGE {
                expired.push(id.clone());
            } else {
                survivors_oldest = Some(
                    survivors_oldest.map_or(entry.buffered_at, |at| at.min(entry.buffered_at)),
                );
            }
        }

        for id in &expired {
            self.remove(id);
        }
        self.oldest_buffered_at = survivors_oldest;
        expired
    }

    /// Release count and cost accounting for a removed entry.
    ///
    /// Refunds the number that was charged at insert (`cost_bytes`), never a
    /// recomputation: the wait lists shrink in place as reasons resolve, so a
    /// recomputed refund would be smaller than the charge and leak budget.
    fn release_entry_accounting(&mut self, entry: &OrphanEntry) {
        self.total_bytes = self.total_bytes.saturating_sub(entry.cost_bytes);
        let Some(peer_id) = entry.from_peer.as_deref() else {
            return;
        };
        if let Some(count) = self.peer_counts.get_mut(peer_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.peer_counts.remove(peer_id);
            }
        }
        if let Some(bytes) = self.peer_bytes.get_mut(peer_id) {
            *bytes = bytes.saturating_sub(entry.cost_bytes);
            if *bytes == 0 {
                self.peer_bytes.remove(peer_id);
            }
        }
    }

    /// Remove an orphan by ID and clean up both reverse indexes.
    fn remove(&mut self, id: &str) {
        if let Some(entry) = self.entries.remove(id) {
            self.release_entry_accounting(&entry);
            for parent in &entry.missing_parents {
                if let Some(set) = self.waiting_on.get_mut(parent) {
                    set.remove(id);
                    if set.is_empty() {
                        self.waiting_on.remove(parent);
                    }
                }
            }
            for account in &entry.missing_accounts {
                if let Some(set) = self.waiting_on_account.get_mut(account) {
                    set.remove(id);
                    if set.is_empty() {
                        self.waiting_on_account.remove(account);
                    }
                }
            }
        }
        self.forget_bound_if_empty();
        self.debug_assert_accounting_drained();
    }

    /// An empty buffer has no oldest entry (L-54), so the next insert starts
    /// the bound afresh instead of inheriting a stale one that would trigger a
    /// pointless pass.
    fn forget_bound_if_empty(&mut self) {
        if self.entries.is_empty() {
            self.oldest_buffered_at = None;
        }
    }

    /// An empty buffer must own no budget (L-20).
    ///
    /// The cheap invariant that catches an asymmetric charge/refund: every
    /// removal path funnels through here, so a cost charged on insert and not
    /// given back shows up as soon as the buffer drains.
    #[inline]
    fn debug_assert_accounting_drained(&self) {
        debug_assert!(
            !self.entries.is_empty()
                || (self.total_bytes == 0
                    && self.peer_bytes.is_empty()
                    && self.peer_counts.is_empty()),
            "orphan accounting must return to zero when the buffer empties: \
             total_bytes={} peer_bytes={:?} peer_counts={:?}",
            self.total_bytes,
            self.peer_bytes,
            self.peer_counts
        );
    }
}

impl Default for OrphanBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use ledger::model::*;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_directive(narration: &str) -> Directive {
        Directive::Transaction(Transaction {
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            flag: Flag::Complete,
            payee: None,
            narration: Some(narration.to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        })
    }

    #[test]
    fn test_insert_and_len() {
        let mut buf = OrphanBuffer::new();
        let d = make_directive("orphan-1");
        assert_eq!(
            buf.insert("id1".to_owned(), d, vec!["parent1".to_owned()], None),
            OrphanInsert::Buffered
        );
        assert_eq!(buf.len(), 1);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_duplicate_insert_is_noop() {
        let mut buf = OrphanBuffer::new();
        let d1 = make_directive("orphan-1");
        let d2 = make_directive("orphan-1");
        buf.insert("id1".to_owned(), d1, vec!["p1".to_owned()], None);
        let charged = buf.total_cost_bytes();
        assert_eq!(
            buf.insert("id1".to_owned(), d2, vec!["p1".to_owned()], None),
            OrphanInsert::Duplicate
        );
        assert_eq!(buf.len(), 1, "Duplicate insert should be no-op");
        assert_eq!(
            buf.total_cost_bytes(),
            charged,
            "a duplicate must not be charged a second time"
        );
    }

    #[test]
    fn test_parent_arrived_resolves_orphan() {
        let mut buf = OrphanBuffer::new();
        let d = make_directive("orphan-waiting");
        buf.insert("id1".to_owned(), d, vec!["parent1".to_owned()], None);

        let resolved = buf.parent_arrived("parent1");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, "id1");
        assert!(buf.is_empty(), "Resolved orphan should be removed");
    }

    #[test]
    fn test_parent_arrived_partial() {
        let mut buf = OrphanBuffer::new();
        let d = make_directive("two-parents");
        buf.insert(
            "id1".to_owned(),
            d,
            vec!["parent1".to_owned(), "parent2".to_owned()],
            None,
        );

        // Only one parent arrives.
        let resolved = buf.parent_arrived("parent1");
        assert!(resolved.is_empty(), "Still waiting for parent2");
        assert_eq!(buf.len(), 1);

        // Second parent arrives.
        let resolved = buf.parent_arrived("parent2");
        assert_eq!(resolved.len(), 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_parent_arrived_unblocks_multiple() {
        let mut buf = OrphanBuffer::new();
        buf.insert(
            "id1".to_owned(),
            make_directive("orphan-1"),
            vec!["shared_parent".to_owned()],
            None,
        );
        buf.insert(
            "id2".to_owned(),
            make_directive("orphan-2"),
            vec!["shared_parent".to_owned()],
            None,
        );
        assert_eq!(buf.len(), 2);

        let resolved = buf.parent_arrived("shared_parent");
        assert_eq!(resolved.len(), 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_wanted_parent_ids() {
        let mut buf = OrphanBuffer::new();
        buf.insert(
            "id1".to_owned(),
            make_directive("o1"),
            vec!["p1".to_owned(), "p2".to_owned()],
            None,
        );
        buf.insert(
            "id2".to_owned(),
            make_directive("o2"),
            vec!["p2".to_owned(), "p3".to_owned()],
            None,
        );

        let wanted = buf.wanted_parent_ids();
        assert_eq!(wanted.len(), 3);
        assert!(wanted.contains("p1"));
        assert!(wanted.contains("p2"));
        assert!(wanted.contains("p3"));
    }

    #[test]
    fn test_parent_arrived_nonexistent() {
        let mut buf = OrphanBuffer::new();
        // Should not panic on unknown parent.
        let resolved = buf.parent_arrived("unknown");
        assert!(resolved.is_empty());
    }

    // ── M-09 account waiters ─────────────────────────────────────────────

    #[test]
    fn test_account_opened_resolves_waiter() {
        let mut buf = OrphanBuffer::new();
        assert!(buf
            .insert_awaiting_accounts(
                "id1".to_owned(),
                make_directive("waiting-on-open"),
                vec!["Assets:Cash".to_owned()],
                None,
            )
            .accepted());
        assert_eq!(buf.wanted_accounts().len(), 1);
        assert!(
            buf.wanted_parent_ids().is_empty(),
            "account names must never leak into `want` ids"
        );

        assert!(buf.account_opened("Other:Account").is_empty());
        let resolved = buf.account_opened("Assets:Cash");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, "id1");
        assert!(buf.is_empty());
        assert!(buf.wanted_accounts().is_empty());
    }

    #[test]
    fn test_entry_waiting_on_both_needs_both() {
        let mut buf = OrphanBuffer::new();
        buf.insert_waiting(
            "id1".to_owned(),
            make_directive("both"),
            vec!["p1".to_owned()],
            vec!["Assets:Cash".to_owned()],
            None,
        );

        assert!(
            buf.account_opened("Assets:Cash").is_empty(),
            "still waiting on the parent"
        );
        assert_eq!(buf.len(), 1);
        let resolved = buf.parent_arrived("p1");
        assert_eq!(resolved.len(), 1);
        assert!(buf.is_empty());
    }

    /// Full cost of one `make_directive("sizer")` entry waiting on one parent
    /// whose id is one character long, buffered under a three-character id.
    ///
    /// The budget tests below size themselves in these units rather than in
    /// body bytes (L-20): the budgets now measure the entry's whole cost, so a
    /// body-only unit would no longer fit the number of entries they mean.
    fn parent_wait_unit() -> usize {
        entry_cost_bytes(
            "id1",
            &make_directive("sizer"),
            &["p".to_owned()],
            &[] as &[String],
        )
    }

    #[test]
    fn test_account_waiters_share_the_orphan_budgets() {
        // M-09 waiters are charged the same byte budget as parent waiters —
        // they are not a second, unbudgeted buffer.
        let parent_unit = parent_wait_unit();
        let account_unit = entry_cost_bytes(
            "id2",
            &make_directive("sizer"),
            &[] as &[String],
            &["Assets:Cash".to_owned()],
        );
        let mut buf = OrphanBuffer::with_byte_budgets(
            parent_unit + account_unit,
            (parent_unit + account_unit) * 10,
        );
        assert_eq!(
            buf.insert(
                "id1".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                Some("peer-a".to_owned()),
            ),
            OrphanInsert::Buffered
        );
        assert_eq!(
            buf.insert_awaiting_accounts(
                "id2".to_owned(),
                make_directive("sizer"),
                vec!["Assets:Cash".to_owned()],
                Some("peer-b".to_owned()),
            ),
            OrphanInsert::Buffered
        );
        assert_eq!(
            buf.insert_awaiting_accounts(
                "id3".to_owned(),
                make_directive("sizer"),
                vec!["Assets:Cash".to_owned()],
                Some("peer-c".to_owned()),
            ),
            OrphanInsert::BudgetExhausted,
            "the account waiter shares the global byte budget"
        );
        // Resolving an account waiter releases its bytes again.
        assert_eq!(buf.account_opened("Assets:Cash").len(), 1);
        assert_eq!(
            buf.insert_awaiting_accounts(
                "id4".to_owned(),
                make_directive("sizer"),
                vec!["Assets:Cash".to_owned()],
                Some("peer-c".to_owned()),
            ),
            OrphanInsert::Buffered
        );
    }

    #[test]
    fn test_per_peer_byte_budget() {
        // 0820-L8: a peer's buffered cost is bounded, not just its entry count.
        let unit = parent_wait_unit();
        // Budget fits exactly two entries for one peer, plenty globally.
        let mut buf = OrphanBuffer::with_byte_budgets(unit * 10, unit * 2);
        let peer = Some("peer-a".to_owned());
        assert_eq!(
            buf.insert(
                "id1".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                peer.clone(),
            ),
            OrphanInsert::Buffered
        );
        assert_eq!(
            buf.insert(
                "id2".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                peer.clone(),
            ),
            OrphanInsert::Buffered
        );
        // Third entry exceeds the peer's byte budget.
        assert_eq!(
            buf.insert(
                "id3".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                peer.clone(),
            ),
            OrphanInsert::BudgetExhausted
        );
        // A different peer still has budget.
        assert_eq!(
            buf.insert(
                "id4".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                Some("peer-b".to_owned()),
            ),
            OrphanInsert::Buffered
        );
        // Resolving releases the bytes: peer-a can buffer again.
        let resolved = buf.parent_arrived("p");
        assert_eq!(resolved.len(), 3);
        assert_eq!(
            buf.insert(
                "id5".to_owned(),
                make_directive("sizer"),
                vec!["q".to_owned()],
                peer,
            ),
            OrphanInsert::Buffered
        );
    }

    #[test]
    fn test_global_byte_budget() {
        let unit = parent_wait_unit();
        // Global budget fits two entries regardless of peer attribution.
        let mut buf = OrphanBuffer::with_byte_budgets(unit * 2, unit * 10);
        assert_eq!(
            buf.insert(
                "id1".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                Some("peer-a".to_owned()),
            ),
            OrphanInsert::Buffered
        );
        assert_eq!(
            buf.insert(
                "id2".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                Some("peer-b".to_owned()),
            ),
            OrphanInsert::Buffered
        );
        assert_eq!(
            buf.insert(
                "id3".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                Some("peer-c".to_owned()),
            ),
            OrphanInsert::BudgetExhausted
        );
    }

    #[test]
    fn test_per_peer_quota() {
        let mut buf = OrphanBuffer::new();
        let peer = Some("peer-a".to_owned());
        for index in 0..MAX_ORPHANS_PER_PEER {
            assert_eq!(
                buf.insert(
                    format!("id-{index}"),
                    make_directive("orphan"),
                    vec!["parent".to_owned()],
                    peer.clone(),
                ),
                OrphanInsert::Buffered,
                "insert {index} should fit per-peer quota"
            );
        }
        assert_eq!(
            buf.insert(
                "overflow".to_owned(),
                make_directive("overflow"),
                vec!["parent".to_owned()],
                peer,
            ),
            OrphanInsert::BudgetExhausted
        );
        assert_eq!(
            buf.insert(
                "other".to_owned(),
                make_directive("other"),
                vec!["parent".to_owned()],
                Some("peer-b".to_owned()),
            ),
            OrphanInsert::Buffered
        );
    }

    // ── L-20: full-cost budgets, timer eviction, contains-before-budget ──

    /// A directive whose envelope dwarfs its economic body: the full signature
    /// hex, an author id, a Lamport stamp and a wide parents list — i.e. what
    /// every signed, well-connected transaction on a busy mesh looks like.
    ///
    /// None of these bytes appear in `economic_canonical_serialize` output, by
    /// definition: that is the form the content hash is taken over, and the
    /// envelope is excluded from it (I5). They are nonetheless resident for the
    /// whole TTL, which is what L-20 is about.
    fn envelope_heavy_directive(parents: &[String]) -> Directive {
        let mut envelope = BTreeMap::new();
        envelope.insert("openledger-signature".to_owned(), "ab".repeat(64));
        envelope.insert("openledger-author".to_owned(), "cd".repeat(32));
        envelope.insert("openledger-lamport".to_owned(), "123456".to_owned());
        envelope.insert("openledger-parents".to_owned(), parents.join(","));
        match make_directive("envelope-heavy") {
            Directive::Transaction(txn) => Directive::Transaction(Transaction {
                metadata: envelope,
                ..txn
            }),
            other => other,
        }
    }

    /// Eight 64-hex parent ids — a merge-width the envelope carries verbatim.
    fn wide_parents() -> Vec<String> {
        (0..8u8)
            .map(|index| format!("{index:02x}").repeat(32))
            .collect()
    }

    /// L-20(a): the budget charges the entry's full cost, so a flood sized
    /// against body-only accounting is refused long before it lands.
    ///
    /// The budget is set to exactly two entries at their *true* cost. The same
    /// number of bytes measured the pre-L-20 way — body only — is room for
    /// `ATTEMPTS` of them or more, so under the old accounting every insert in
    /// the flood below was admitted while the buffer's real footprint ran to
    /// several times its ceiling.
    #[test]
    fn test_full_cost_budget_refuses_an_envelope_heavy_flood() {
        /// Directives in the flood. Comfortably above what the budget allows on
        /// full cost, comfortably below what it allowed on body-only cost.
        const ATTEMPTS: usize = 8;

        let parents = wide_parents();
        let directive = envelope_heavy_directive(&parents);
        let body_only = ledger::serialize::economic_canonical_serialize(&directive).len();
        let full_cost = entry_cost_bytes("id0", &directive, &parents, &[] as &[String]);
        assert!(
            full_cost > body_only * 3,
            "envelope + index cost must dominate the body under this load: \
             body_only={body_only} full_cost={full_cost}"
        );

        let budget = full_cost * 2;
        let body_only_would_admit = budget / body_only;
        assert!(
            body_only_would_admit >= ATTEMPTS,
            "the test is vacuous unless body-only accounting would have admitted the \
             whole flood: it would admit {body_only_would_admit} of {ATTEMPTS}"
        );

        let mut buf = OrphanBuffer::with_byte_budgets(budget, budget);
        let admitted = (0..ATTEMPTS)
            .filter(|index| {
                buf.insert(
                    format!("id{index}"),
                    directive.clone(),
                    parents.clone(),
                    Some("peer-a".to_owned()),
                ) == OrphanInsert::Buffered
            })
            .count();
        assert_eq!(
            admitted, 2,
            "a budget worth two full-cost entries must admit two of the {ATTEMPTS} \
             offered — body-only accounting would have admitted {body_only_would_admit} \
             (body_only={body_only} full_cost={full_cost})"
        );
        assert!(
            buf.total_cost_bytes() <= budget,
            "the tracked cost must stay inside the budget it gates on"
        );

        // And the accounting is symmetric: drain what can be resolved, evict the
        // rest, and the buffer owns nothing.
        buf.parent_arrived(&parents[0]);
        for parent in &parents[1..] {
            buf.parent_arrived(parent);
        }
        buf.evict_expired(Instant::now() + MAX_ORPHAN_AGE + Duration::from_secs(1));
        assert!(buf.is_empty(), "drain + evict must empty the buffer");
        assert_eq!(
            buf.total_cost_bytes(),
            0,
            "every charged byte must be refunded once the buffer empties"
        );
    }

    /// L-20(a): partially-resolved entries refund exactly what they were
    /// charged, even though their wait lists shrank in place first.
    #[test]
    fn test_accounting_returns_to_zero_after_partial_resolution() {
        let mut buf = OrphanBuffer::new();
        assert_eq!(buf.total_cost_bytes(), 0);
        buf.insert_waiting(
            "id1".to_owned(),
            make_directive("both"),
            vec!["p1".to_owned(), "p2".to_owned()],
            vec!["Assets:Cash".to_owned()],
            Some("peer-a".to_owned()),
        );
        let charged = buf.total_cost_bytes();
        assert!(charged > 0);

        // Two of the three reasons clear without releasing the entry.
        assert!(buf.parent_arrived("p1").is_empty());
        assert!(buf.account_opened("Assets:Cash").is_empty());
        assert_eq!(
            buf.total_cost_bytes(),
            charged,
            "a partially-resolved entry is still resident and still charged"
        );

        assert_eq!(buf.parent_arrived("p2").len(), 1);
        assert!(buf.is_empty());
        assert_eq!(
            buf.total_cost_bytes(),
            0,
            "the refund must be the amount charged, not a recomputation over the \
             shrunken wait lists"
        );
    }

    /// L-20(b): an expired orphan leaves through the TTL sweep alone — no
    /// insert, no other traffic. This is the method `gl-node`'s timer drives.
    #[test]
    fn test_evict_expired_drops_stale_entries_without_any_insert() {
        let mut buf = OrphanBuffer::new();
        // Taken *before* the insert, so it is no later than the entry's own
        // `buffered_at` and `at_ttl` is genuinely "at most one TTL later".
        let before_insert = Instant::now();
        buf.insert(
            "id1".to_owned(),
            make_directive("stale"),
            vec!["p".to_owned()],
            Some("peer-a".to_owned()),
        );
        assert_eq!(buf.len(), 1);

        // Exactly at the TTL is not yet "older than" it.
        let at_ttl = before_insert + MAX_ORPHAN_AGE;
        assert!(buf.evict_expired(at_ttl).is_empty());
        assert_eq!(buf.len(), 1, "an entry at exactly the TTL survives");

        let past_ttl = at_ttl + Duration::from_secs(1);
        assert_eq!(buf.evict_expired(past_ttl), vec!["id1".to_owned()]);
        assert!(buf.is_empty(), "the sweep alone must empty the buffer");
        assert_eq!(buf.total_cost_bytes(), 0);
        assert!(
            buf.wanted_parent_ids().is_empty(),
            "eviction must clear the reverse index too, or `want` names a parent \
             nothing is waiting for"
        );
    }

    /// L-54: re-buffering is O(1) in the buffer's size. A drain that frees and
    /// re-buffers every entry — the `restage_freed_entry` shape, under both
    /// write locks in `gl-node` — used to run one full TTL pass PER re-buffer;
    /// with nothing old enough to have expired it now runs none at all, and a
    /// pass happens exactly when something can be stale.
    #[test]
    fn test_rebuffering_does_not_sweep_until_something_can_have_expired() {
        const ENTRIES: usize = 500;
        let mut buf = OrphanBuffer::new();
        for index in 0..ENTRIES {
            buf.insert_awaiting_accounts(
                format!("id{index}"),
                make_directive(&format!("wait-{index}")),
                vec!["Assets:Cash".to_owned()],
                Some("peer-a".to_owned()),
            );
        }
        // The drain: release everything waiting on the account, then put each
        // entry back under a new blocking account, one insert at a time.
        let freed = buf.account_opened("Assets:Cash");
        assert_eq!(freed.len(), ENTRIES);
        for entry in freed {
            let outcome = buf.insert_awaiting_accounts(
                entry.id,
                entry.directive,
                vec!["Assets:Bank".to_owned()],
                entry.from_peer,
            );
            assert_eq!(outcome, OrphanInsert::Buffered);
        }
        assert_eq!(buf.len(), ENTRIES);
        assert_eq!(
            buf.sweeps,
            0,
            "{} inserts must not have run a single O(n) TTL pass",
            ENTRIES * 2
        );
        // The background sweep is O(1) too while nothing is old enough.
        assert!(buf.evict_expired(Instant::now()).is_empty());
        assert_eq!(buf.sweeps, 0);

        // Once the oldest CAN have expired, exactly one pass runs, evicts, and
        // re-derives the bound (the buffer is empty, so there is none).
        let later = Instant::now() + MAX_ORPHAN_AGE + Duration::from_secs(1);
        assert_eq!(buf.evict_expired(later).len(), ENTRIES);
        assert_eq!(buf.sweeps, 1);
        assert!(buf.is_empty());
        assert_eq!(buf.total_cost_bytes(), 0);
        assert!(buf.evict_expired(later).is_empty());
        assert_eq!(buf.sweeps, 1, "an empty buffer is never swept");
    }

    /// L-54: the bound is a LOWER bound, so a pass is never skipped while an
    /// entry is stale, and survivors keep their own expiry after a pass.
    #[test]
    fn test_amortized_eviction_never_skips_a_stale_entry() {
        let mut buf = OrphanBuffer::new();
        let before = Instant::now();
        buf.insert(
            "old".to_owned(),
            make_directive("old"),
            vec!["p".to_owned()],
            None,
        );
        std::thread::sleep(Duration::from_millis(5));
        let middle = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        buf.insert(
            "new".to_owned(),
            make_directive("new"),
            vec!["q".to_owned()],
            None,
        );

        // Past "old"'s TTL but not "new"'s: exactly "old" goes.
        let between = middle + MAX_ORPHAN_AGE;
        assert!(between > before + MAX_ORPHAN_AGE);
        assert_eq!(buf.evict_expired(between), vec!["old".to_owned()]);
        assert_eq!(buf.len(), 1);
        // The re-derived bound still covers "new".
        let past_new = Instant::now() + MAX_ORPHAN_AGE + Duration::from_secs(1);
        assert_eq!(buf.evict_expired(past_new), vec!["new".to_owned()]);
        // Removing the oldest by resolution leaves a stale (early) bound: it
        // costs at most one pass, which evicts nothing wrongly.
        buf.insert(
            "a".to_owned(),
            make_directive("a"),
            vec!["pa".to_owned()],
            None,
        );
        std::thread::sleep(Duration::from_millis(5));
        // Taken before "b" is inserted, so "b" is at most one TTL old at
        // `b_at_ttl` — while the stale bound ("a") is strictly older than that.
        let before_b = Instant::now();
        buf.insert(
            "b".to_owned(),
            make_directive("b"),
            vec!["pb".to_owned()],
            None,
        );
        assert_eq!(buf.parent_arrived("pa").len(), 1);
        let sweeps_before = buf.sweeps;
        let b_at_ttl = before_b + MAX_ORPHAN_AGE;
        assert!(buf.evict_expired(b_at_ttl).is_empty(), "b is still fresh");
        assert_eq!(buf.len(), 1);
        assert_eq!(
            buf.sweeps,
            sweeps_before + 1,
            "the stale bound cost one pass"
        );
        assert!(buf.evict_expired(b_at_ttl).is_empty());
        assert_eq!(buf.sweeps, sweeps_before + 1, "...which corrected it");
    }

    /// L-34: the refusal cache the buffer hosts is aged out by the same
    /// timer-driven sweep, even when there are no orphans at all.
    #[test]
    fn test_evict_expired_also_ages_out_refusals() {
        let mut buf = OrphanBuffer::new();
        let id = format!("{:064x}", 7);
        let now = Instant::now();
        assert!(buf.refusals_mut().record("peer-a", &id, now));
        assert!(buf.refusals().is_refused("peer-a", &id, now));
        buf.evict_expired(now + crate::anti_entropy::REFUSAL_CACHE_TTL);
        assert!(buf.refusals().is_empty());
    }

    /// The sweep cadence stays a derivation of the TTL, not an independent
    /// number that can drift away from it.
    #[test]
    fn test_eviction_interval_is_derived_from_the_ttl() {
        assert_eq!(ORPHAN_EVICTION_INTERVAL * 4, MAX_ORPHAN_AGE);
        assert!(ORPHAN_EVICTION_INTERVAL < MAX_ORPHAN_AGE);
    }

    /// L-20(c): at a full buffer, a re-gossiped duplicate reports itself as a
    /// duplicate rather than as a capacity refusal — and is not charged again.
    #[test]
    fn test_duplicate_insert_at_a_full_buffer_reports_duplicate_not_full() {
        let unit = parent_wait_unit();
        // Budget for exactly one entry: the buffer is full after the first.
        let mut buf = OrphanBuffer::with_byte_budgets(unit, unit);
        let peer = Some("peer-a".to_owned());
        assert_eq!(
            buf.insert(
                "id1".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                peer.clone(),
            ),
            OrphanInsert::Buffered
        );
        let charged = buf.total_cost_bytes();

        // A genuinely new entry is refused — the buffer really is full.
        assert_eq!(
            buf.insert(
                "id2".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                peer.clone(),
            ),
            OrphanInsert::BudgetExhausted
        );

        // The same id arriving again is a duplicate, not a refusal.
        assert_eq!(
            buf.insert(
                "id1".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                peer,
            ),
            OrphanInsert::Duplicate,
            "a duplicate at a full buffer must not be reported as buffer-full"
        );
        assert_eq!(buf.len(), 1);
        assert_eq!(
            buf.total_cost_bytes(),
            charged,
            "the duplicate must not be charged against the budget a second time"
        );
    }

    /// A duplicate is also not charged against the *per-peer* budgets, and
    /// re-attributing it to a second peer does not add a second peer row.
    #[test]
    fn test_duplicate_insert_does_not_double_charge_the_peer() {
        let mut buf = OrphanBuffer::new();
        buf.insert(
            "id1".to_owned(),
            make_directive("sizer"),
            vec!["p".to_owned()],
            Some("peer-a".to_owned()),
        );
        let charged = buf.total_cost_bytes();
        assert_eq!(
            buf.insert(
                "id1".to_owned(),
                make_directive("sizer"),
                vec!["p".to_owned()],
                Some("peer-b".to_owned()),
            ),
            OrphanInsert::Duplicate
        );
        assert_eq!(buf.total_cost_bytes(), charged);
        // Resolving the one entry must return the accounting to zero — proof
        // that no second peer row was opened for the duplicate.
        assert_eq!(buf.parent_arrived("p").len(), 1);
        assert_eq!(buf.total_cost_bytes(), 0);
    }
}
