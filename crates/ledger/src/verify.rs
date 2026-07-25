//! DAG verification (FR-5 AC1).
//!
//! Walks the DAG and confirms:
//! - Every `txid` matches its content hash (I5).
//! - Every parent link resolves to a known node (I8).
//! - No cycles exist in the transaction DAG.

use crate::dag::LedgerDag;
use crate::hash::compute_content_id;

/// A single verification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Content hash mismatch: stored txid doesn't match recomputed hash.
    ContentHashMismatch {
        stored_id: String,
        computed_id: String,
    },
    /// A parent txid references a node not in the DAG.
    MissingParent { txid: String, parent: String },
    /// Cycle detected in the DAG.
    CycleDetected { txid: String },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::ContentHashMismatch {
                stored_id,
                computed_id,
            } => {
                write!(
                    f,
                    "Content hash mismatch: stored={stored_id}, computed={computed_id}"
                )
            }
            VerifyError::MissingParent { txid, parent } => {
                write!(
                    f,
                    "Missing parent: {txid} references unknown parent {parent}"
                )
            }
            VerifyError::CycleDetected { txid } => {
                write!(f, "Cycle detected involving {txid}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Result of a full DAG verification.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Whether the DAG passed all checks.
    pub ok: bool,
    /// Number of nodes checked.
    pub nodes_checked: usize,
    /// Any errors found.
    pub errors: Vec<VerifyError>,
}

/// Walk the DAG and verify all integrity constraints (FR-5 AC1).
///
/// Checks:
/// 1. Content hash of every directive matches its stored ID (I5).
/// 2. Every transaction's parent links resolve to known nodes (I8).
/// 3. The DAG is acyclic.
pub fn verify_dag(dag: &LedgerDag) -> VerifyReport {
    let mut errors = Vec::new();
    let mut nodes_checked = 0;

    let content_ids = dag.content_ids();

    for &stored_id in &content_ids {
        nodes_checked += 1;

        // 1. Content hash verification (I5).
        if let Some(directive) = dag.get(stored_id) {
            let computed_id = compute_content_id(directive);
            if computed_id != stored_id {
                errors.push(VerifyError::ContentHashMismatch {
                    stored_id: stored_id.to_owned(),
                    computed_id,
                });
            }
        }

        // 2. Parent link resolution (I8).
        if let Some(parents) = dag.parents_of(stored_id) {
            for parent in parents {
                if dag.get(parent).is_none() {
                    errors.push(VerifyError::MissingParent {
                        txid: stored_id.to_owned(),
                        parent: parent.clone(),
                    });
                }
            }
        }
    }

    // 3. Cycle detection via topological sort (Kahn's algorithm).
    // If we can't sort all transaction nodes, there's a cycle.
    let cycle_errors = detect_cycles(dag);
    errors.extend(cycle_errors);

    VerifyReport {
        ok: errors.is_empty(),
        nodes_checked,
        errors,
    }
}

/// Detect cycles in the transaction DAG using DFS coloring.
///
/// Returns any cycle errors found.
fn detect_cycles(dag: &LedgerDag) -> Vec<VerifyError> {
    use std::collections::HashMap;

    let content_ids = dag.content_ids();

    // Track visit state: 0 = unvisited, 1 = in-progress, 2 = done.
    let mut state: HashMap<&str, u8> = content_ids.iter().map(|id| (*id, 0u8)).collect();
    let mut errors = Vec::new();

    fn dfs<'a>(
        node: &'a str,
        dag: &'a LedgerDag,
        state: &mut HashMap<&'a str, u8>,
        errors: &mut Vec<VerifyError>,
    ) {
        if let Some(&s) = state.get(node) {
            if s == 2 {
                return; // Already fully processed.
            }
            if s == 1 {
                // Back edge = cycle.
                errors.push(VerifyError::CycleDetected {
                    txid: node.to_owned(),
                });
                return;
            }
        }

        state.insert(node, 1); // Mark in-progress.

        // Visit children (forward edges in the DAG).
        if let Some(children) = dag.children_of(node) {
            for child in children {
                dfs(child, dag, state, errors);
            }
        }

        state.insert(node, 2); // Mark done.
    }

    for &id in &content_ids {
        if state.get(id) == Some(&0) {
            dfs(id, dag, &mut state, &mut errors);
        }
    }

    errors
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use chrono::NaiveDate;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    fn make_txn(date: NaiveDate, narration: &str, parents: &str) -> Directive {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "test".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "1".to_owned());
        metadata.insert("openledger-parents".to_owned(), parents.to_owned());

        Directive::Transaction(Transaction {
            date,
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
            metadata,
        })
    }

    #[test]
    fn test_verify_empty_dag() {
        let dag = LedgerDag::new();
        let report = verify_dag(&dag);
        assert!(report.ok);
        assert_eq!(report.nodes_checked, 0);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn test_verify_single_genesis() {
        let mut dag = LedgerDag::new();
        let txn = make_txn(make_date(2024, 1, 1), "Genesis", "");
        dag.insert(txn, false).unwrap();

        let report = verify_dag(&dag);
        assert!(report.ok);
        assert_eq!(report.nodes_checked, 1);
    }

    #[test]
    fn test_verify_chain() {
        let mut dag = LedgerDag::new();

        let t1 = make_txn(make_date(2024, 1, 1), "First", "");
        let id1 = match dag.insert(t1, false).unwrap() {
            crate::dag::InsertResult::Inserted { content_id } => content_id,
            _ => panic!("Expected insert"),
        };

        let t2 = make_txn(make_date(2024, 1, 2), "Second", &id1);
        dag.insert(t2, false).unwrap();

        let report = verify_dag(&dag);
        assert!(report.ok);
        assert_eq!(report.nodes_checked, 2);
    }

    #[test]
    fn test_verify_content_hashes_match() {
        let mut dag = LedgerDag::new();
        let txn = make_txn(make_date(2024, 1, 1), "Test", "");
        dag.insert(txn, false).unwrap();

        // All content hashes should match in a properly constructed DAG.
        let report = verify_dag(&dag);
        assert!(
            report.ok,
            "Content hashes should match: {:?}",
            report.errors
        );
    }

    #[test]
    fn test_verify_with_non_transaction_directives() {
        let mut dag = LedgerDag::new();

        let open = Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        });
        dag.insert(open, false).unwrap();

        let txn = make_txn(make_date(2024, 1, 2), "Test", "");
        dag.insert(txn, false).unwrap();

        let report = verify_dag(&dag);
        assert!(report.ok);
        assert_eq!(report.nodes_checked, 2);
    }

    #[test]
    fn test_verify_golden_fixture() {
        let fixture = include_str!("../../../testfixtures/fixture-simple.bean");
        let directives = crate::parse::parse_file(fixture).unwrap();

        let mut dag = LedgerDag::new();
        for d in directives {
            // Use lenient mode since parents might not be in order.
            dag.insert(d, false).unwrap();
        }

        let report = verify_dag(&dag);
        assert!(report.nodes_checked > 0);

        // The fixture has a pre-baked parent hash in its second transaction
        // that doesn't match the computed content ID of the first transaction.
        // This is expected: verify correctly flags it as a missing parent.
        let missing_parent_errors: Vec<_> = report
            .errors
            .iter()
            .filter(|e| matches!(e, VerifyError::MissingParent { .. }))
            .collect();
        assert_eq!(
            missing_parent_errors.len(),
            1,
            "Golden fixture should have exactly one missing parent (pre-baked hash)"
        );

        // No content hash mismatches or cycles.
        assert!(
            !report
                .errors
                .iter()
                .any(|e| matches!(e, VerifyError::ContentHashMismatch { .. })),
            "No content hash mismatches expected"
        );
        assert!(
            !report
                .errors
                .iter()
                .any(|e| matches!(e, VerifyError::CycleDetected { .. })),
            "No cycles expected"
        );
    }

    // ── CT-8: verify detects tamper + dangling parent (I8) ───────────────

    #[test]
    fn ct8_verify_detects_tampered_txid() {
        let mut dag = LedgerDag::new();

        // Insert a legit genesis transaction.
        let legit = make_txn(make_date(2024, 1, 1), "Legit", "");
        dag.insert(legit, false).unwrap();

        // Insert a transaction under a FAKE content ID (tampered).
        let tampered = make_txn(make_date(2024, 1, 2), "Tampered narration", "");
        dag.insert_with_fake_id(
            "aaaa000000000000000000000000000000000000000000000000000000000000".to_owned(),
            tampered,
            vec![], // genesis
        );

        let report = verify_dag(&dag);
        assert!(!report.ok, "Should detect tamper");
        assert!(
            report.errors.iter().any(|e| matches!(
                e,
                VerifyError::ContentHashMismatch { stored_id, .. }
                if stored_id == "aaaa000000000000000000000000000000000000000000000000000000000000"
            )),
            "Should report content hash mismatch for tampered txid"
        );
    }

    #[test]
    fn ct8_verify_detects_dangling_parent() {
        let mut dag = LedgerDag::new();

        // Insert a genesis transaction normally.
        let t1 = make_txn(make_date(2024, 1, 1), "Genesis", "");
        let id1 = match dag.insert(t1, false).unwrap() {
            crate::dag::InsertResult::Inserted { content_id } => content_id,
            _ => panic!("Expected insert"),
        };

        // Insert a transaction that references a nonexistent parent.
        let t2 = make_txn(make_date(2024, 1, 2), "Orphan child", "");
        let t2_real_id = compute_content_id(&make_txn(make_date(2024, 1, 2), "Orphan child", ""));
        let dangling_parent = "bbbb000000000000000000000000000000000000000000000000000000000000";
        dag.insert_with_fake_id(t2_real_id, t2, vec![id1, dangling_parent.to_owned()]);

        let report = verify_dag(&dag);
        assert!(!report.ok, "Should detect dangling parent");
        assert!(
            report.errors.iter().any(|e| matches!(
                e,
                VerifyError::MissingParent { parent, .. }
                if parent == dangling_parent
            )),
            "Should report missing parent for dangling link: {:?}",
            report.errors
        );
    }
}
