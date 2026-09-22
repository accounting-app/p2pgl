//! DAG verification (FR-5 AC1).
//!
//! Walks the DAG and confirms:
//! - Every `txid` matches its content hash (I5).
//! - Every parent link resolves to a known node (I8).
//! - No cycles exist in the transaction DAG.
//!
//! It also evaluates every `balance` assertion in the ledger against the read
//! model (§3.6, M-08) and reports the results alongside the structural errors.

use crate::checkpoint::{evaluate_all_assertions, AssertionResult};
use crate::dag::LedgerDag;
use crate::hash::compute_content_id;
use crate::read_model::ReadModel;

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

/// Outcome of evaluating the ledger's `balance` assertions (§3.6, M-08).
#[derive(Debug, Clone, Default)]
pub struct BalanceAssertionSummary {
    /// How many `balance` directives were evaluated.
    pub evaluated: usize,
    /// The assertions that did **not** hold, with expected vs actual.
    pub failures: Vec<AssertionResult>,
}

impl BalanceAssertionSummary {
    /// How many assertions held.
    pub fn passed(&self) -> usize {
        self.evaluated.saturating_sub(self.failures.len())
    }

    /// Whether every evaluated assertion held (vacuously true when there are none).
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Result of a full DAG verification.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Whether the DAG passed all *structural* checks (hashes, parents, cycles).
    ///
    /// Balance-assertion failures deliberately do **not** clear this flag: an
    /// assertion is an author's claim about a balance, and any writer — a peer
    /// on the allowlist included — can seed a false one. Letting a remote claim
    /// flip the integrity verdict would hand that peer a red `verify` on every
    /// node. Callers that care about assertions read [`Self::assertions`],
    /// which reports the claims that did not hold.
    pub ok: bool,
    /// Number of nodes checked.
    pub nodes_checked: usize,
    /// Any errors found.
    pub errors: Vec<VerifyError>,
    /// Balance assertions evaluated during this verification (§3.6).
    pub assertions: BalanceAssertionSummary,
}

/// Walk the DAG and verify all integrity constraints (FR-5 AC1).
///
/// Checks:
/// 1. Content hash of every directive matches its stored ID (I5).
/// 2. Every transaction's parent links resolve to known nodes (I8).
/// 3. The DAG is acyclic.
/// 4. Every `balance` directive holds against `read_model` (§3.6, M-08).
///
/// Check 4 is **read-only reporting**. Each `balance` directive asserts that an
/// account holds a given amount of one currency on a date (transactions dated
/// on or before it — beancount asserts at the *start* of the day instead; see
/// [`crate::checkpoint::evaluate_balance_assertion`]). Failures are recorded in
/// [`VerifyReport::assertions`]; nothing is rejected, no state is touched, and
/// `pad` directives are not synthesized into balances — a gap a `pad` was meant
/// to cover still reports as a failing assertion.
///
/// `read_model` must be the model built from the same directives as `dag`
/// (`LedgerService` keeps the two in step), otherwise the assertion results
/// describe a ledger that does not exist.
///
/// # Cost (M-23)
///
/// Linear in the directive count: one hash recomputation per directive
/// (the dominant term by far), two cycle-detection walks, and **one**
/// date-ordered balance sweep that answers every assertion. Nothing here is a
/// product of two attacker-influenced counts any more.
///
/// Measured (release, `Assets`-heavy synthetic ledgers), against one
/// whole-ledger scan (`ReadModel::trial_balance`) as the unit the GraphQL
/// heavy-resolver weight is denominated in:
///
/// ```text
/// directives                one scan   verify_dag   assertion pass
///  4k txns +   4k balances    0.69ms      26.4ms          0.85ms
/// 20k txns +  20k balances    4.08ms     139.0ms          5.46ms
/// 20k txns + 100k balances    3.42ms     395.5ms         43.5ms
/// ```
///
/// The last row is the attack shape — a peer inflating the directive count
/// with cheap `balance` directives — and it now costs sub-second, linearly.
/// The GraphQL weight is sized on these numbers and pinned by
/// `gl-node`'s `graphql::query::tests::test_verify_complexity_matches_measured_cost_model`.
pub fn verify_dag(dag: &LedgerDag, read_model: &ReadModel) -> VerifyReport {
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

    // 4. Balance assertions (§3.6, M-08). Evaluated over the DAG's own
    // directives — the borrowed view, so no clone of the ledger — and reported
    // separately from the structural errors above.
    //
    // One batched date-ordered sweep answers all of them (M-23). T32 wired
    // this in as one whole-ledger balance rebuild per `balance` directive,
    // which made this call O(assertions × transactions × postings) with the
    // assertion count supplied by whoever can plant a `balance` directive —
    // any peer. Measured at 2.61 s for 4000 × 4000 and tens of minutes for a
    // plausible plant, all of it under `ledger.read()`. See
    // [`crate::checkpoint::evaluate_all_assertions`].
    let results = evaluate_all_assertions(dag.directives(), read_model);
    let assertions = BalanceAssertionSummary {
        evaluated: results.len(),
        failures: results.into_iter().filter(|result| !result.ok).collect(),
    };

    VerifyReport {
        ok: errors.is_empty(),
        nodes_checked,
        errors,
        assertions,
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

    // Iterative DFS coloring with an explicit heap work-stack (M-5). The DAG
    // depth is attacker-controlled (a long parent chain), so native recursion
    // here could overflow the process stack — an unwind-proof crash. `Enter`
    // colors a node in-progress and schedules its children; `Exit`, popped only
    // after the node's whole subtree is done, colors it done. Encountering an
    // in-progress node on `Enter` is a back edge = cycle.
    enum Step<'a> {
        Enter(&'a str),
        Exit(&'a str),
    }

    for &root in &content_ids {
        if state.get(root) != Some(&0) {
            continue;
        }
        let mut stack = vec![Step::Enter(root)];
        while let Some(step) = stack.pop() {
            match step {
                Step::Enter(node) => {
                    match state.get(node) {
                        Some(&2) => continue, // Already fully processed.
                        Some(&1) => {
                            // Back edge = cycle.
                            errors.push(VerifyError::CycleDetected {
                                txid: node.to_owned(),
                            });
                            continue;
                        }
                        _ => {}
                    }
                    state.insert(node, 1); // Mark in-progress.
                    stack.push(Step::Exit(node));
                    // Push children in reverse so they pop in forward order,
                    // matching the previous recursive traversal.
                    if let Some(children) = dag.children_of(node) {
                        for child in children.iter().rev() {
                            stack.push(Step::Enter(child));
                        }
                    }
                }
                Step::Exit(node) => {
                    state.insert(node, 2); // Mark done.
                }
            }
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
    use rust_decimal::Decimal;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    /// Build the read model that matches a DAG, the way `LedgerService::boot` does.
    fn read_model_for(dag: &LedgerDag) -> ReadModel {
        let directives: Vec<Directive> = dag.directives().into_iter().cloned().collect();
        ReadModel::build(&directives)
    }

    fn make_balance(date: NaiveDate, account: &str, number: Decimal, currency: &str) -> Directive {
        Directive::Balance(Balance {
            date,
            account: account.to_owned(),
            amount: Amount {
                number,
                currency: currency.to_owned(),
            },
            metadata: BTreeMap::new(),
        })
    }

    /// A transaction with arbitrary `(account, amount)` postings, all in USD.
    fn make_txn_with(date: NaiveDate, narration: &str, postings: &[(&str, Decimal)]) -> Directive {
        Directive::Transaction(Transaction {
            date,
            flag: Flag::Complete,
            payee: None,
            narration: Some(narration.to_owned()),
            tags: vec![],
            links: vec![],
            postings: postings
                .iter()
                .map(|(account, number)| Posting {
                    account: (*account).to_owned(),
                    amount: Some(Amount {
                        number: *number,
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                })
                .collect(),
            metadata: BTreeMap::new(),
        })
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
        let report = verify_dag(&dag, &read_model_for(&dag));
        assert!(report.ok);
        assert_eq!(report.nodes_checked, 0);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn test_verify_single_genesis() {
        let mut dag = LedgerDag::new();
        let txn = make_txn(make_date(2024, 1, 1), "Genesis", "");
        dag.insert(txn, false).unwrap();

        let report = verify_dag(&dag, &read_model_for(&dag));
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

        let report = verify_dag(&dag, &read_model_for(&dag));
        assert!(report.ok);
        assert_eq!(report.nodes_checked, 2);
    }

    #[test]
    fn test_detect_cycles_deep_chain_no_stack_overflow() {
        // M-5 regression: a long parent chain must not overflow the process
        // stack during cycle detection. The chain is built on the main thread,
        // then verified on a thread with a deliberately small (96 KiB) stack —
        // deep enough that the former recursive DFS would overflow, while the
        // iterative version (heap work-stack) completes cleanly. Chain length is
        // kept modest because building it goes through the O(n²) DAG insert (T9).
        const CHAIN_LEN: usize = 1_500;
        let mut dag = LedgerDag::new();
        let mut parent = String::new();
        for i in 0..CHAIN_LEN {
            let txn = make_txn(make_date(2024, 1, 1), &format!("n{i}"), &parent);
            parent = match dag.insert(txn, false).unwrap() {
                crate::dag::InsertResult::Inserted { content_id } => content_id,
                _ => panic!("expected insert"),
            };
        }

        // Build the read model up front so the small-stack thread runs the
        // traversal under test and nothing else.
        let read_model = read_model_for(&dag);
        let report = std::thread::Builder::new()
            .stack_size(96 * 1024)
            .spawn(move || verify_dag(&dag, &read_model))
            .expect("spawn verify thread")
            .join()
            .expect("verify thread must not overflow the stack");

        assert!(
            report.ok,
            "deep chain should verify cleanly: {:?}",
            report.errors
        );
        assert_eq!(report.nodes_checked, CHAIN_LEN);
    }

    #[test]
    fn test_verify_content_hashes_match() {
        let mut dag = LedgerDag::new();
        let txn = make_txn(make_date(2024, 1, 1), "Test", "");
        dag.insert(txn, false).unwrap();

        // All content hashes should match in a properly constructed DAG.
        let report = verify_dag(&dag, &read_model_for(&dag));
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

        let report = verify_dag(&dag, &read_model_for(&dag));
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

        let report = verify_dag(&dag, &read_model_for(&dag));
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

        let report = verify_dag(&dag, &read_model_for(&dag));
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

        let report = verify_dag(&dag, &read_model_for(&dag));
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

    // ── M-08: balance assertions are evaluated and surfaced ──────────────

    #[test]
    fn m08_verify_reports_passing_assertion() {
        // `make_txn` posts +100 USD to Assets:Cash; the assertion agrees.
        let mut dag = LedgerDag::new();
        dag.insert(make_txn(make_date(2024, 1, 1), "Genesis", ""), false)
            .unwrap();
        dag.insert(
            make_balance(make_date(2024, 2, 1), "Assets:Cash", dec!(100), "USD"),
            false,
        )
        .unwrap();

        let report = verify_dag(&dag, &read_model_for(&dag));
        assert!(
            report.ok,
            "structural checks should pass: {:?}",
            report.errors
        );
        assert_eq!(report.assertions.evaluated, 1);
        assert_eq!(report.assertions.passed(), 1);
        assert!(
            report.assertions.ok(),
            "a true assertion must not be reported as a failure: {:?}",
            report.assertions.failures
        );
    }

    #[test]
    fn m08_verify_surfaces_failing_assertion() {
        // M-08 regression: before the wiring, a `balance` directive was
        // persisted by the unvalidated catch-all and never evaluated — a false
        // claim (from a file edit or an allowlisted peer) verified clean.
        let mut dag = LedgerDag::new();
        dag.insert(make_txn(make_date(2024, 1, 1), "Genesis", ""), false)
            .unwrap();
        dag.insert(
            make_balance(make_date(2024, 2, 1), "Assets:Cash", dec!(999), "USD"),
            false,
        )
        .unwrap();

        let report = verify_dag(&dag, &read_model_for(&dag));
        assert_eq!(report.assertions.evaluated, 1);
        assert_eq!(report.assertions.passed(), 0);
        assert!(!report.assertions.ok());

        let failure = &report.assertions.failures[0];
        assert_eq!(failure.account, "Assets:Cash");
        assert_eq!(failure.date, make_date(2024, 2, 1));
        assert_eq!(failure.expected, dec!(999));
        assert_eq!(failure.actual, dec!(100));
        assert_eq!(failure.currency, "USD");
        assert!(!failure.ok);

        // The structural verdict is unaffected: a false claim by some writer is
        // not DAG corruption, and must not let that writer redden every node.
        assert!(
            report.ok,
            "a failing assertion must not flip the structural verdict: {:?}",
            report.errors
        );
        assert!(report.errors.is_empty());
    }

    #[test]
    fn m08_verify_reports_every_assertion_in_the_ledger() {
        let mut dag = LedgerDag::new();
        dag.insert(make_txn(make_date(2024, 1, 1), "Genesis", ""), false)
            .unwrap();
        for (number, account) in [
            (dec!(100), "Assets:Cash"),     // true
            (dec!(1), "Assets:Cash"),       // false
            (dec!(0), "Assets:Unknown"),    // true (no postings → zero)
            (dec!(-100), "Equity:Opening"), // true
            (dec!(100), "Equity:Opening"),  // false (sign flipped)
        ] {
            dag.insert(
                make_balance(make_date(2024, 2, 1), account, number, "USD"),
                false,
            )
            .unwrap();
        }

        let report = verify_dag(&dag, &read_model_for(&dag));
        assert_eq!(report.assertions.evaluated, 5);
        assert_eq!(report.assertions.failures.len(), 2);
        assert_eq!(report.assertions.passed(), 3);
    }

    #[test]
    fn m08_pad_directive_is_not_synthesized_into_balances() {
        // A `pad` names a source account to absorb the gap an assertion leaves.
        // Evaluation is read-only reporting: the pad is not applied, so the
        // assertion it was meant to cover still reports as failing.
        let mut dag = LedgerDag::new();
        dag.insert(make_txn(make_date(2024, 1, 1), "Genesis", ""), false)
            .unwrap();
        dag.insert(
            Directive::Pad(Pad {
                date: make_date(2024, 1, 15),
                account: "Assets:Cash".to_owned(),
                source_account: "Equity:Opening".to_owned(),
                metadata: BTreeMap::new(),
            }),
            false,
        )
        .unwrap();
        dag.insert(
            make_balance(make_date(2024, 2, 1), "Assets:Cash", dec!(500), "USD"),
            false,
        )
        .unwrap();

        let report = verify_dag(&dag, &read_model_for(&dag));
        assert_eq!(
            report.assertions.evaluated, 1,
            "the pad itself is not an assertion"
        );
        assert_eq!(report.assertions.failures.len(), 1);
        assert_eq!(report.assertions.failures[0].actual, dec!(100));
    }

    #[test]
    fn m08_extreme_assertion_values_report_cleanly() {
        // H1/T1: the read model saturates and the assertion amount is
        // caller-supplied, so both sides can sit at the Decimal extremes. The
        // comparison must report a plain failure rather than panicking, on a
        // build with overflow checks on (the release profile enables them).
        let mut dag = LedgerDag::new();
        dag.insert(
            make_txn_with(
                make_date(2024, 1, 1),
                "Extreme",
                &[
                    ("Assets:Cash", Decimal::MAX),
                    ("Equity:Opening", Decimal::MIN),
                ],
            ),
            false,
        )
        .unwrap();
        // A second saturating posting pushes the running balance past MAX.
        dag.insert(
            make_txn_with(
                make_date(2024, 1, 2),
                "Extreme again",
                &[
                    ("Assets:Cash", Decimal::MAX),
                    ("Equity:Opening", Decimal::MIN),
                ],
            ),
            false,
        )
        .unwrap();
        for (account, number) in [
            ("Assets:Cash", Decimal::MIN),
            ("Assets:Cash", Decimal::MAX),
            ("Equity:Opening", Decimal::MAX),
        ] {
            dag.insert(
                make_balance(make_date(2024, 3, 1), account, number, "USD"),
                false,
            )
            .unwrap();
        }

        let report = verify_dag(&dag, &read_model_for(&dag));
        assert_eq!(report.assertions.evaluated, 3);
        // Assets:Cash saturates at MAX, so only the MAX claim on it holds.
        assert_eq!(report.assertions.passed(), 1);
        assert_eq!(report.assertions.failures.len(), 2);
        assert!(
            report.ok,
            "extremes are not DAG corruption: {:?}",
            report.errors
        );
    }
}
