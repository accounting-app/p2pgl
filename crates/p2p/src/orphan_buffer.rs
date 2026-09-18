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

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ledger::model::Directive;

/// Maximum number of orphans to buffer.
pub const MAX_ORPHANS: usize = 10_000;
/// Maximum orphans attributed to a single peer (M-3).
pub const MAX_ORPHANS_PER_PEER: usize = 1_000;

/// Maximum total bytes of buffered orphan bodies (0820-L8).
///
/// Entry counts alone let one peer pin ~1 GiB (1,000 × 1 MiB max-size bodies)
/// for the full TTL. Sizing the buffer bounds resident memory regardless of
/// how large individual directives are.
pub const MAX_ORPHAN_BYTES: usize = 64 * 1024 * 1024;
/// Maximum bytes of buffered orphan bodies attributed to a single peer.
pub const MAX_ORPHAN_BYTES_PER_PEER: usize = 16 * 1024 * 1024;

/// Maximum age for an orphan entry.
pub const MAX_ORPHAN_AGE: Duration = Duration::from_secs(3600); // 1 hour

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
    /// Serialized size of the economic body, counted against the byte budgets.
    size_bytes: usize,
}

impl OrphanEntry {
    /// Whether every reason this entry was buffered has been resolved.
    fn is_ready(&self) -> bool {
        self.missing_parents.is_empty() && self.missing_accounts.is_empty()
    }
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
    /// Buffered body bytes per delivering peer (0820-L8).
    peer_bytes: HashMap<String, usize>,
    /// Total buffered body bytes.
    total_bytes: usize,
    /// Global byte budget (`MAX_ORPHAN_BYTES`; overridable in tests).
    max_bytes: usize,
    /// Per-peer byte budget (`MAX_ORPHAN_BYTES_PER_PEER`; overridable in tests).
    max_bytes_per_peer: usize,
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
        }
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

    /// Buffer an orphan waiting for missing parents. Returns false if a global
    /// or per-peer budget (entry count or bytes) is exhausted.
    pub fn insert(
        &mut self,
        id: String,
        directive: Directive,
        missing_parents: Vec<String>,
        from_peer: Option<String>,
    ) -> bool {
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
    ) -> bool {
        self.insert_waiting(id, directive, Vec::new(), missing_accounts, from_peer)
    }

    /// Buffer an orphan waiting on any mix of parents and accounts. Returns
    /// false if a global or per-peer budget (entry count or bytes) is
    /// exhausted.
    pub fn insert_waiting(
        &mut self,
        id: String,
        directive: Directive,
        missing_parents: Vec<String>,
        missing_accounts: Vec<String>,
        from_peer: Option<String>,
    ) -> bool {
        // Evict expired entries first.
        self.evict_expired();

        if self.entries.len() >= MAX_ORPHANS {
            return false;
        }

        // Byte budgets (0820-L8): entry counts alone let one peer pin ~1 GiB of
        // max-size bodies for the TTL; size the buffer as well.
        let size_bytes = ledger::serialize::economic_canonical_serialize(&directive).len();
        if self.total_bytes.saturating_add(size_bytes) > self.max_bytes {
            return false;
        }

        if let Some(ref peer_id) = from_peer {
            let count = self.peer_counts.get(peer_id).copied().unwrap_or(0);
            if count >= MAX_ORPHANS_PER_PEER {
                return false;
            }
            let bytes = self.peer_bytes.get(peer_id).copied().unwrap_or(0);
            if bytes.saturating_add(size_bytes) > self.max_bytes_per_peer {
                return false;
            }
        }

        // Skip if already buffered.
        if self.entries.contains_key(&id) {
            return true;
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
            *self.peer_bytes.entry(peer_id.clone()).or_insert(0) += size_bytes;
        }
        self.total_bytes += size_bytes;

        self.entries.insert(
            id.clone(),
            OrphanEntry {
                id,
                directive,
                missing_parents,
                missing_accounts,
                buffered_at: Instant::now(),
                from_peer,
                size_bytes,
            },
        );

        true
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

    /// Evict entries older than MAX_ORPHAN_AGE.
    fn evict_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.buffered_at) > MAX_ORPHAN_AGE)
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            self.remove(&id);
        }
    }

    /// Release count and byte accounting for a removed entry.
    fn release_entry_accounting(&mut self, entry: &OrphanEntry) {
        self.total_bytes = self.total_bytes.saturating_sub(entry.size_bytes);
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
            *bytes = bytes.saturating_sub(entry.size_bytes);
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
        assert!(buf.insert("id1".to_owned(), d, vec!["parent1".to_owned()], None));
        assert_eq!(buf.len(), 1);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_duplicate_insert_is_noop() {
        let mut buf = OrphanBuffer::new();
        let d1 = make_directive("orphan-1");
        let d2 = make_directive("orphan-1");
        buf.insert("id1".to_owned(), d1, vec!["p1".to_owned()], None);
        buf.insert("id1".to_owned(), d2, vec!["p1".to_owned()], None);
        assert_eq!(buf.len(), 1, "Duplicate insert should be no-op");
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
        assert!(buf.insert_awaiting_accounts(
            "id1".to_owned(),
            make_directive("waiting-on-open"),
            vec!["Assets:Cash".to_owned()],
            None,
        ));
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

    #[test]
    fn test_account_waiters_share_the_orphan_budgets() {
        // M-09 waiters are charged the same byte budget as parent waiters —
        // they are not a second, unbudgeted buffer.
        let entry_size =
            ledger::serialize::economic_canonical_serialize(&make_directive("sizer")).len();
        let mut buf = OrphanBuffer::with_byte_budgets(entry_size * 2, entry_size * 10);
        assert!(buf.insert(
            "id1".to_owned(),
            make_directive("sizer"),
            vec!["p".to_owned()],
            Some("peer-a".to_owned()),
        ));
        assert!(buf.insert_awaiting_accounts(
            "id2".to_owned(),
            make_directive("sizer"),
            vec!["Assets:Cash".to_owned()],
            Some("peer-b".to_owned()),
        ));
        assert!(
            !buf.insert_awaiting_accounts(
                "id3".to_owned(),
                make_directive("sizer"),
                vec!["Assets:Cash".to_owned()],
                Some("peer-c".to_owned()),
            ),
            "the account waiter shares the global byte budget"
        );
        // Resolving an account waiter releases its bytes again.
        assert_eq!(buf.account_opened("Assets:Cash").len(), 1);
        assert!(buf.insert_awaiting_accounts(
            "id4".to_owned(),
            make_directive("sizer"),
            vec!["Assets:Cash".to_owned()],
            Some("peer-c".to_owned()),
        ));
    }

    #[test]
    fn test_per_peer_byte_budget() {
        // 0820-L8: a peer's buffered bytes are bounded, not just its entry count.
        let entry_size =
            ledger::serialize::economic_canonical_serialize(&make_directive("sizer")).len();
        // Budget fits exactly two entries for one peer, plenty globally.
        let mut buf = OrphanBuffer::with_byte_budgets(entry_size * 10, entry_size * 2);
        let peer = Some("peer-a".to_owned());
        assert!(buf.insert(
            "id1".to_owned(),
            make_directive("sizer"),
            vec!["p".to_owned()],
            peer.clone(),
        ));
        assert!(buf.insert(
            "id2".to_owned(),
            make_directive("sizer"),
            vec!["p".to_owned()],
            peer.clone(),
        ));
        // Third entry exceeds the peer's byte budget.
        assert!(!buf.insert(
            "id3".to_owned(),
            make_directive("sizer"),
            vec!["p".to_owned()],
            peer.clone(),
        ));
        // A different peer still has budget.
        assert!(buf.insert(
            "id4".to_owned(),
            make_directive("sizer"),
            vec!["p".to_owned()],
            Some("peer-b".to_owned()),
        ));
        // Resolving releases the bytes: peer-a can buffer again.
        let resolved = buf.parent_arrived("p");
        assert_eq!(resolved.len(), 3);
        assert!(buf.insert(
            "id5".to_owned(),
            make_directive("sizer"),
            vec!["p2".to_owned()],
            peer,
        ));
    }

    #[test]
    fn test_global_byte_budget() {
        let entry_size =
            ledger::serialize::economic_canonical_serialize(&make_directive("sizer")).len();
        // Global budget fits two entries regardless of peer attribution.
        let mut buf = OrphanBuffer::with_byte_budgets(entry_size * 2, entry_size * 10);
        assert!(buf.insert(
            "id1".to_owned(),
            make_directive("sizer"),
            vec!["p".to_owned()],
            Some("peer-a".to_owned()),
        ));
        assert!(buf.insert(
            "id2".to_owned(),
            make_directive("sizer"),
            vec!["p".to_owned()],
            Some("peer-b".to_owned()),
        ));
        assert!(!buf.insert(
            "id3".to_owned(),
            make_directive("sizer"),
            vec!["p".to_owned()],
            Some("peer-c".to_owned()),
        ));
    }

    #[test]
    fn test_per_peer_quota() {
        let mut buf = OrphanBuffer::new();
        let peer = Some("peer-a".to_owned());
        for index in 0..MAX_ORPHANS_PER_PEER {
            assert!(
                buf.insert(
                    format!("id-{index}"),
                    make_directive("orphan"),
                    vec!["parent".to_owned()],
                    peer.clone(),
                ),
                "insert {index} should fit per-peer quota"
            );
        }
        assert!(!buf.insert(
            "overflow".to_owned(),
            make_directive("overflow"),
            vec!["parent".to_owned()],
            peer,
        ));
        assert!(buf.insert(
            "other".to_owned(),
            make_directive("other"),
            vec!["parent".to_owned()],
            Some("peer-b".to_owned()),
        ));
    }
}
