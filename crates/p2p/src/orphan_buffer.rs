//! Orphan buffer (§3.4.4).
//!
//! Buffers transactions whose parent txids are not yet in the local DAG.
//! - Max 10,000 entries or 1 hour TTL, whichever first.
//! - On parent arrival, re-attempt insert.
//! - Emits `want` for missing parent IDs.

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
    /// When this orphan was first buffered.
    pub buffered_at: Instant,
    /// Gossip sender that delivered this orphan, when known.
    pub from_peer: Option<String>,
    /// Serialized size of the economic body, counted against the byte budgets.
    size_bytes: usize,
}

/// The orphan buffer.
#[derive(Debug)]
pub struct OrphanBuffer {
    /// Orphans keyed by their content ID.
    entries: HashMap<String, OrphanEntry>,
    /// Reverse index: parent_id → [orphan_id]. For fast lookup on parent arrival.
    waiting_on: HashMap<String, HashSet<String>>,
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

    /// Buffer an orphan. Returns false if a global or per-peer budget
    /// (entry count or bytes) is exhausted.
    pub fn insert(
        &mut self,
        id: String,
        directive: Directive,
        missing_parents: Vec<String>,
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

        // Build reverse index.
        for parent in &missing_parents {
            self.waiting_on
                .entry(parent.clone())
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
                buffered_at: Instant::now(),
                from_peer,
                size_bytes,
            },
        );

        true
    }

    /// Notify the buffer that a parent ID has arrived.
    /// Returns any orphans that now have all parents resolved.
    pub fn parent_arrived(&mut self, parent_id: &str) -> Vec<OrphanEntry> {
        let mut resolved = Vec::new();

        if let Some(orphan_ids) = self.waiting_on.remove(parent_id) {
            for orphan_id in orphan_ids {
                if let Some(entry) = self.entries.get_mut(&orphan_id) {
                    entry.missing_parents.retain(|p| p != parent_id);

                    if entry.missing_parents.is_empty() {
                        if let Some(entry) = self.entries.remove(&orphan_id) {
                            self.release_entry_accounting(&entry);
                            resolved.push(entry);
                        }
                    }
                }
            }
        }

        resolved
    }

    /// Get all parent IDs we're still waiting on (for `want` messages).
    pub fn wanted_parent_ids(&self) -> HashSet<String> {
        self.waiting_on.keys().cloned().collect()
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

    /// Remove an orphan by ID and clean up reverse index.
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
