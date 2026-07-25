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
}

/// The orphan buffer.
#[derive(Debug)]
pub struct OrphanBuffer {
    /// Orphans keyed by their content ID.
    entries: HashMap<String, OrphanEntry>,
    /// Reverse index: parent_id → [orphan_id]. For fast lookup on parent arrival.
    waiting_on: HashMap<String, HashSet<String>>,
}

impl OrphanBuffer {
    pub fn new() -> Self {
        OrphanBuffer {
            entries: HashMap::new(),
            waiting_on: HashMap::new(),
        }
    }

    /// Buffer an orphan. Returns false if the buffer is full.
    pub fn insert(&mut self, id: String, directive: Directive, missing_parents: Vec<String>) -> bool {
        // Evict expired entries first.
        self.evict_expired();

        if self.entries.len() >= MAX_ORPHANS {
            return false;
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

        self.entries.insert(
            id.clone(),
            OrphanEntry {
                id,
                directive,
                missing_parents,
                buffered_at: Instant::now(),
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

    /// Remove an orphan by ID and clean up reverse index.
    fn remove(&mut self, id: &str) {
        if let Some(entry) = self.entries.remove(id) {
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
        assert!(buf.insert("id1".to_owned(), d, vec!["parent1".to_owned()]));
        assert_eq!(buf.len(), 1);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_duplicate_insert_is_noop() {
        let mut buf = OrphanBuffer::new();
        let d1 = make_directive("orphan-1");
        let d2 = make_directive("orphan-1");
        buf.insert("id1".to_owned(), d1, vec!["p1".to_owned()]);
        buf.insert("id1".to_owned(), d2, vec!["p1".to_owned()]);
        assert_eq!(buf.len(), 1, "Duplicate insert should be no-op");
    }

    #[test]
    fn test_parent_arrived_resolves_orphan() {
        let mut buf = OrphanBuffer::new();
        let d = make_directive("orphan-waiting");
        buf.insert("id1".to_owned(), d, vec!["parent1".to_owned()]);

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
        );
        buf.insert(
            "id2".to_owned(),
            make_directive("orphan-2"),
            vec!["shared_parent".to_owned()],
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
        );
        buf.insert(
            "id2".to_owned(),
            make_directive("o2"),
            vec!["p2".to_owned(), "p3".to_owned()],
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
}
