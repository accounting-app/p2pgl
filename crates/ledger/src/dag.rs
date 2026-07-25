//! Transaction Merkle-DAG and directive G-Set (§3.3, §3.4).
//!
//! The DAG tracks parent→child edges for transactions. Non-transaction directives
//! are stored in a flat G-Set keyed by `directiveId`. Both are content-addressed
//! and deduplicated.

use std::collections::{HashMap, HashSet};

use crate::hash::compute_content_id;
use crate::model::*;

// ─── DAG node ────────────────────────────────────────────────────────────────

/// A node in the transaction DAG.
#[derive(Debug, Clone)]
struct DagNode {
    directive: Directive,
    /// Parent txids (transactions only). Empty for genesis or non-transactions.
    parents: Vec<String>,
    /// Child txids (reverse edges for traversal).
    children: Vec<String>,
}

// ─── Ledger DAG ──────────────────────────────────────────────────────────────

/// The core data structure: a G-Set of directives with a Merkle-DAG over transactions.
#[derive(Debug, Clone)]
pub struct LedgerDag {
    /// All directives keyed by content ID.
    nodes: HashMap<String, DagNode>,
    /// Transaction IDs that have no children — the frontier.
    heads: HashSet<String>,
    /// Insertion order (for deterministic iteration).
    insertion_order: Vec<String>,
}

/// Result of inserting a directive into the DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertResult {
    /// Successfully inserted (new directive).
    Inserted { content_id: String },
    /// Already present (G-Set idempotency).
    Duplicate { content_id: String },
}

/// Error from a DAG insert operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagError {
    /// I8: adding this transaction would create a cycle.
    CycleDetected { txid: String },
    /// A parent txid is not (yet) in the DAG.
    MissingParent { txid: String, parent: String },
}

impl std::fmt::Display for DagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DagError::CycleDetected { txid } => {
                write!(f, "Cycle detected: adding {txid} would create a cycle")
            }
            DagError::MissingParent { txid, parent } => {
                write!(
                    f,
                    "Missing parent: {txid} references unknown parent {parent}"
                )
            }
        }
    }
}

impl std::error::Error for DagError {}

impl LedgerDag {
    pub fn new() -> Self {
        LedgerDag {
            nodes: HashMap::new(),
            heads: HashSet::new(),
            insertion_order: Vec::new(),
        }
    }

    /// Insert a directive into the G-Set / DAG.
    ///
    /// For transactions: validates parent links and acyclicity (I8).
    /// For non-transactions: simple G-Set insert.
    ///
    /// `require_parents` controls whether missing parents cause an error or are
    /// tolerated (e.g., during boot where directives are loaded in file order,
    /// parents may arrive later via anti-entropy).
    pub fn insert(
        &mut self,
        directive: Directive,
        require_parents: bool,
    ) -> Result<InsertResult, DagError> {
        let content_id = compute_content_id(&directive);

        // G-Set dedup: if already present, no-op.
        if self.nodes.contains_key(&content_id) {
            return Ok(InsertResult::Duplicate { content_id });
        }

        let parents = match &directive {
            Directive::Transaction(txn) => txn.parent_ids().iter().map(|s| s.to_string()).collect(),
            _ => Vec::new(),
        };

        // Validate parent links for transactions.
        if matches!(directive, Directive::Transaction(_)) && require_parents {
            for parent_id in &parents {
                if !parent_id.is_empty() && !self.nodes.contains_key(parent_id) {
                    return Err(DagError::MissingParent {
                        txid: content_id,
                        parent: parent_id.clone(),
                    });
                }
            }
        }

        // I8: check for cycles (would this txid already be an ancestor of any parent?).
        if matches!(directive, Directive::Transaction(_)) {
            for parent_id in &parents {
                if !parent_id.is_empty() && self.would_create_cycle(&content_id, parent_id) {
                    return Err(DagError::CycleDetected { txid: content_id });
                }
            }
        }

        // Insert the node.
        let node = DagNode {
            directive,
            parents: parents.clone(),
            children: Vec::new(),
        };
        self.nodes.insert(content_id.clone(), node);
        self.insertion_order.push(content_id.clone());

        // Update parent→child edges and head tracking.
        if matches!(
            self.nodes.get(&content_id).unwrap().directive,
            Directive::Transaction(_)
        ) {
            // This new transaction is a head (no children yet).
            self.heads.insert(content_id.clone());

            // Parents are no longer heads (they now have a child).
            for parent_id in &parents {
                if !parent_id.is_empty() {
                    self.heads.remove(parent_id);
                    if let Some(parent_node) = self.nodes.get_mut(parent_id) {
                        parent_node.children.push(content_id.clone());
                    }
                }
            }
        }

        Ok(InsertResult::Inserted { content_id })
    }

    /// Check if adding `new_id` as a child of `parent_id` would create a cycle.
    ///
    /// A cycle exists if `new_id` is already an ancestor of `parent_id`.
    fn would_create_cycle(&self, new_id: &str, parent_id: &str) -> bool {
        // Walk ancestors of parent_id; if we find new_id, it's a cycle.
        let mut visited = HashSet::new();
        let mut stack = vec![parent_id.to_string()];

        while let Some(current) = stack.pop() {
            if current == new_id {
                return true;
            }
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(node) = self.nodes.get(&current) {
                for parent in &node.parents {
                    if !parent.is_empty() {
                        stack.push(parent.clone());
                    }
                }
            }
        }
        false
    }

    // ─── Accessors ───────────────────────────────────────────────────────

    /// The current head txids (transactions with no children).
    pub fn heads(&self) -> &HashSet<String> {
        &self.heads
    }

    /// Total number of directives in the G-Set.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the G-Set is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Get a directive by its content ID.
    pub fn get(&self, content_id: &str) -> Option<&Directive> {
        self.nodes.get(content_id).map(|n| &n.directive)
    }

    /// Iterate all directives in insertion order.
    pub fn directives(&self) -> Vec<&Directive> {
        self.insertion_order
            .iter()
            .filter_map(|id| self.nodes.get(id).map(|n| &n.directive))
            .collect()
    }

    /// Iterate only transaction directives.
    pub fn transactions(&self) -> Vec<&Transaction> {
        self.directives()
            .into_iter()
            .filter_map(|d| match d {
                Directive::Transaction(t) => Some(t),
                _ => None,
            })
            .collect()
    }

    /// Get the parent txids for a given content ID.
    pub fn parents_of(&self, content_id: &str) -> Option<&[String]> {
        self.nodes.get(content_id).map(|n| n.parents.as_slice())
    }

    /// Get the child txids for a given content ID.
    pub fn children_of(&self, content_id: &str) -> Option<&[String]> {
        self.nodes.get(content_id).map(|n| n.children.as_slice())
    }

    /// All content IDs in the G-Set.
    pub fn content_ids(&self) -> Vec<&str> {
        self.insertion_order.iter().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
impl LedgerDag {
    /// Test-only: insert a directive under a fake/tampered content ID.
    ///
    /// This bypasses the normal content-hash computation so we can test
    /// `verify_dag` detection of mismatched hashes (CT-8).
    pub fn insert_with_fake_id(
        &mut self,
        fake_id: String,
        directive: Directive,
        parents: Vec<String>,
    ) {
        let node = DagNode {
            directive,
            parents: parents.clone(),
            children: Vec::new(),
        };
        self.nodes.insert(fake_id.clone(), node);
        self.insertion_order.push(fake_id.clone());

        // Update parent→child edges.
        for parent_id in &parents {
            if !parent_id.is_empty() {
                self.heads.remove(parent_id);
                if let Some(parent_node) = self.nodes.get_mut(parent_id) {
                    parent_node.children.push(fake_id.clone());
                }
            }
        }
        self.heads.insert(fake_id);
    }
}

impl Default for LedgerDag {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    fn make_txn(narration: &str, parent_ids: &[&str]) -> Directive {
        let mut metadata = BTreeMap::new();
        let parents_str = parent_ids.join(",");
        metadata.insert("openledger-parents".to_owned(), parents_str);
        metadata.insert("openledger-author".to_owned(), "test-peer".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "1".to_owned());

        Directive::Transaction(Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some(narration.to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
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
            metadata,
        })
    }

    fn make_open(account: &str) -> Directive {
        Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: account.to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        })
    }

    // ── Basic insert ─────────────────────────────────────────────────────

    #[test]
    fn test_empty_dag() {
        let dag = LedgerDag::new();
        assert!(dag.is_empty());
        assert_eq!(dag.len(), 0);
        assert!(dag.heads().is_empty());
    }

    #[test]
    fn test_insert_non_transaction() {
        let mut dag = LedgerDag::new();
        let open = make_open("Assets:Cash");
        let result = dag.insert(open, false).unwrap();
        assert!(matches!(result, InsertResult::Inserted { .. }));
        assert_eq!(dag.len(), 1);
        // Non-transactions don't affect heads.
        assert!(dag.heads().is_empty());
    }

    #[test]
    fn test_insert_genesis_transaction() {
        let mut dag = LedgerDag::new();
        let txn = make_txn("Genesis", &[]);
        let result = dag.insert(txn, false).unwrap();
        match result {
            InsertResult::Inserted { ref content_id } => {
                assert!(dag.heads().contains(content_id));
            }
            _ => panic!("Expected Inserted"),
        }
        assert_eq!(dag.heads().len(), 1);
    }

    // ── G-Set dedup ──────────────────────────────────────────────────────

    #[test]
    fn test_duplicate_is_noop() {
        let mut dag = LedgerDag::new();
        let txn = make_txn("Dedup test", &[]);
        let first = dag.insert(txn.clone(), false).unwrap();
        let second = dag.insert(txn, false).unwrap();

        assert!(matches!(first, InsertResult::Inserted { .. }));
        assert!(matches!(second, InsertResult::Duplicate { .. }));
        assert_eq!(dag.len(), 1);
    }

    // ── Parent-child edges ───────────────────────────────────────────────

    #[test]
    fn test_parent_child_edges() {
        let mut dag = LedgerDag::new();

        // Genesis.
        let genesis = make_txn("Genesis", &[]);
        let genesis_id = match dag.insert(genesis, false).unwrap() {
            InsertResult::Inserted { content_id } => content_id,
            _ => panic!("Expected Inserted"),
        };

        // Child referencing genesis.
        let child = make_txn("Child", &[&genesis_id]);
        let child_id = match dag.insert(child, false).unwrap() {
            InsertResult::Inserted { content_id } => content_id,
            _ => panic!("Expected Inserted"),
        };

        // Genesis is no longer a head; child is.
        assert!(!dag.heads().contains(&genesis_id));
        assert!(dag.heads().contains(&child_id));
        assert_eq!(dag.heads().len(), 1);

        // Parent → child edge.
        assert!(dag.children_of(&genesis_id).unwrap().contains(&child_id));
    }

    // ── Missing parent (strict mode) ─────────────────────────────────────

    #[test]
    fn test_missing_parent_strict_rejected() {
        let mut dag = LedgerDag::new();
        let txn = make_txn("Orphan", &["nonexistent_parent_id"]);
        let err = dag.insert(txn, true).unwrap_err();
        assert!(matches!(err, DagError::MissingParent { .. }));
    }

    #[test]
    fn test_missing_parent_lenient_accepted() {
        let mut dag = LedgerDag::new();
        let txn = make_txn("Orphan", &["nonexistent_parent_id"]);
        let result = dag.insert(txn, false);
        assert!(result.is_ok());
    }

    // ── Head tracking ────────────────────────────────────────────────────

    #[test]
    fn test_multiple_heads() {
        let mut dag = LedgerDag::new();

        // Two independent genesis transactions.
        let genesis_a = make_txn("Genesis A", &[]);
        let genesis_b = make_txn("Genesis B", &[]);

        dag.insert(genesis_a, false).unwrap();
        dag.insert(genesis_b, false).unwrap();

        assert_eq!(dag.heads().len(), 2);
    }

    #[test]
    fn test_merge_reduces_heads() {
        let mut dag = LedgerDag::new();

        let genesis_a = make_txn("Genesis A", &[]);
        let id_a = match dag.insert(genesis_a, false).unwrap() {
            InsertResult::Inserted { content_id } => content_id,
            _ => panic!(),
        };

        let genesis_b = make_txn("Genesis B", &[]);
        let id_b = match dag.insert(genesis_b, false).unwrap() {
            InsertResult::Inserted { content_id } => content_id,
            _ => panic!(),
        };

        assert_eq!(dag.heads().len(), 2);

        // Merge: a transaction with both as parents.
        let merge = make_txn("Merge", &[&id_a, &id_b]);
        dag.insert(merge, false).unwrap();

        assert_eq!(dag.heads().len(), 1);
    }

    // ── Accessors ────────────────────────────────────────────────────────

    #[test]
    fn test_get_directive() {
        let mut dag = LedgerDag::new();
        let open = make_open("Assets:Cash");
        let id = compute_content_id(&open);
        dag.insert(open, false).unwrap();
        assert!(dag.get(&id).is_some());
        assert!(dag.get("nonexistent").is_none());
    }

    #[test]
    fn test_directives_returns_all() {
        let mut dag = LedgerDag::new();
        dag.insert(make_open("Assets:Cash"), false).unwrap();
        dag.insert(make_open("Equity:Opening"), false).unwrap();
        dag.insert(make_txn("Genesis", &[]), false).unwrap();

        assert_eq!(dag.directives().len(), 3);
        assert_eq!(dag.transactions().len(), 1);
    }

    #[test]
    fn test_content_ids() {
        let mut dag = LedgerDag::new();
        dag.insert(make_open("Assets:Cash"), false).unwrap();
        dag.insert(make_txn("Genesis", &[]), false).unwrap();

        let ids = dag.content_ids();
        assert_eq!(ids.len(), 2);
    }
}
