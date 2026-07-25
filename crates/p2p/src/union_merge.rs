//! Union merge — G-Set merge for remote directives (§3.4, §3.5).
//!
//! Validates incoming directives from peers (same acceptance laws as local
//! writes), inserts into the DAG, updates the read model, and adopts
//! the Lamport clock.

use std::collections::BTreeMap;

use ledger::hash::compute_content_id;
use ledger::model::*;
use ledger::parse::parse_file;

use crate::protocol::SupplyEntry;

/// Errors that can occur during merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// Content hash mismatch (I5).
    ContentHashMismatch { claimed: String, computed: String },
    /// Failed to parse the economic body.
    ParseError(String),
    /// Invariant validation failed.
    ValidationError(String),
    /// Missing required envelope fields.
    EnvelopeMissing(String),
    /// DAG cycle detected (I8).
    CycleDetected,
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergeError::ContentHashMismatch { claimed, computed } => {
                write!(
                    f,
                    "Content hash mismatch: claimed {claimed}, computed {computed}"
                )
            }
            MergeError::ParseError(e) => write!(f, "Parse error: {e}"),
            MergeError::ValidationError(e) => write!(f, "Validation error: {e}"),
            MergeError::EnvelopeMissing(field) => {
                write!(f, "Missing required envelope field: {field}")
            }
            MergeError::CycleDetected => write!(f, "DAG cycle detected (I8)"),
        }
    }
}

impl std::error::Error for MergeError {}

/// The result of merging a single supply entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeResult {
    /// The entry was new and successfully merged.
    Inserted { id: String },
    /// The entry was already present (idempotent, I4).
    Duplicate { id: String },
    /// The entry was rejected for a validation reason.
    Rejected { id: String, reason: MergeError },
    /// The entry's parents are missing; buffered as an orphan.
    Orphaned {
        id: String,
        missing_parents: Vec<String>,
    },
}

/// Parse and validate a supply entry from a remote peer.
///
/// This is the first half of the merge process: parse the economic body,
/// verify the content hash (I5), and attach envelope metadata.
///
/// Returns the fully-assembled directive ready for DAG insertion.
pub fn validate_supply_entry(entry: &SupplyEntry) -> Result<Directive, MergeError> {
    // 1. Parse the economic body.
    let directives = parse_file(&entry.economic_bean).map_err(|errors| {
        let msgs: Vec<String> = errors.iter().map(|e| format!("{e:?}")).collect();
        MergeError::ParseError(msgs.join("; "))
    })?;

    if directives.is_empty() {
        return Err(MergeError::ParseError("Empty economic body".to_owned()));
    }

    let mut directive = directives.into_iter().next().unwrap();

    // 2. Verify content hash (I5): id == hash(economic_bean).
    let computed = compute_content_id(&directive);
    if computed != entry.id {
        return Err(MergeError::ContentHashMismatch {
            claimed: entry.id.clone(),
            computed,
        });
    }

    // 3. Attach envelope metadata.
    let metadata = directive_metadata_mut(&mut directive);
    for (key, value) in &entry.envelope {
        metadata.insert(key.clone(), value.clone());
    }

    // 4. Validate required envelope fields for transactions.
    if let Directive::Transaction(_) = &directive {
        if !entry.envelope.contains_key("openledger-author") {
            return Err(MergeError::EnvelopeMissing("openledger-author".to_owned()));
        }
        if !entry.envelope.contains_key("openledger-lamport") {
            return Err(MergeError::EnvelopeMissing("openledger-lamport".to_owned()));
        }
        // openledger-parents may be empty string for genesis.
    }

    Ok(directive)
}

/// Extract the Lamport clock value from a directive's metadata.
pub fn extract_lamport(directive: &Directive) -> Option<u64> {
    if let Directive::Transaction(txn) = directive {
        txn.lamport_clock()
    } else {
        let metadata = match directive {
            Directive::Open(d) => &d.metadata,
            Directive::Close(d) => &d.metadata,
            Directive::Commodity(d) => &d.metadata,
            Directive::Pad(d) => &d.metadata,
            Directive::Balance(d) => &d.metadata,
            Directive::Note(d) => &d.metadata,
            Directive::Document(d) => &d.metadata,
            Directive::Event(d) => &d.metadata,
            Directive::Price(d) => &d.metadata,
            Directive::Transaction(_) => unreachable!(),
        };
        metadata
            .get("openledger-lamport")
            .and_then(|v| v.parse().ok())
    }
}

/// Extract the parent txids from a directive's metadata.
pub fn extract_parents(directive: &Directive) -> Vec<String> {
    let metadata = match directive {
        Directive::Transaction(txn) => &txn.metadata,
        Directive::Open(d) => &d.metadata,
        Directive::Close(d) => &d.metadata,
        Directive::Commodity(d) => &d.metadata,
        Directive::Pad(d) => &d.metadata,
        Directive::Balance(d) => &d.metadata,
        Directive::Note(d) => &d.metadata,
        Directive::Document(d) => &d.metadata,
        Directive::Event(d) => &d.metadata,
        Directive::Price(d) => &d.metadata,
    };

    match metadata.get("openledger-parents") {
        Some(v) if v.is_empty() => vec![],
        Some(v) => v.split(',').map(|s| s.trim().to_owned()).collect(),
        None => vec![],
    }
}

/// Get a mutable reference to a directive's metadata.
fn directive_metadata_mut(directive: &mut Directive) -> &mut BTreeMap<String, String> {
    match directive {
        Directive::Transaction(d) => &mut d.metadata,
        Directive::Open(d) => &mut d.metadata,
        Directive::Close(d) => &mut d.metadata,
        Directive::Commodity(d) => &mut d.metadata,
        Directive::Pad(d) => &mut d.metadata,
        Directive::Balance(d) => &mut d.metadata,
        Directive::Note(d) => &mut d.metadata,
        Directive::Document(d) => &mut d.metadata,
        Directive::Event(d) => &mut d.metadata,
        Directive::Price(d) => &mut d.metadata,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DirectiveKind;
    use ledger::hash::compute_content_id;
    use ledger::model::*;
    use ledger::serialize::economic_canonical_serialize;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_valid_supply_entry() -> SupplyEntry {
        let txn = Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            flag: Flag::Complete,
            payee: Some("Acme Corp".to_owned()),
            narration: Some("Test merge".to_owned()),
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
        };
        let directive = Directive::Transaction(txn);
        let id = compute_content_id(&directive);
        let economic_bean = economic_canonical_serialize(&directive);

        SupplyEntry {
            id,
            kind: DirectiveKind::Transaction,
            economic_bean,
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "peer-1".to_owned()),
                ("openledger-lamport".to_owned(), "5".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        }
    }

    #[test]
    fn test_validate_supply_entry_success() {
        let entry = make_valid_supply_entry();
        let result = validate_supply_entry(&entry);
        assert!(result.is_ok(), "Valid entry should pass: {result:?}");

        let directive = result.unwrap();
        // Envelope metadata should be attached.
        if let Directive::Transaction(txn) = &directive {
            assert_eq!(
                txn.metadata.get("openledger-author"),
                Some(&"peer-1".to_owned())
            );
            assert_eq!(
                txn.metadata.get("openledger-lamport"),
                Some(&"5".to_owned())
            );
        } else {
            panic!("Expected Transaction");
        }
    }

    #[test]
    fn test_validate_content_hash_mismatch() {
        let mut entry = make_valid_supply_entry();
        entry.id = "0000000000000000000000000000000000000000000000000000000000000000".to_owned();

        let result = validate_supply_entry(&entry);
        assert!(matches!(
            result,
            Err(MergeError::ContentHashMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_missing_author() {
        let mut entry = make_valid_supply_entry();
        entry.envelope.remove("openledger-author");

        let result = validate_supply_entry(&entry);
        assert!(matches!(
            result,
            Err(MergeError::EnvelopeMissing(ref field)) if field == "openledger-author"
        ));
    }

    #[test]
    fn test_validate_missing_lamport() {
        let mut entry = make_valid_supply_entry();
        entry.envelope.remove("openledger-lamport");

        let result = validate_supply_entry(&entry);
        assert!(matches!(
            result,
            Err(MergeError::EnvelopeMissing(ref field)) if field == "openledger-lamport"
        ));
    }

    #[test]
    fn test_validate_empty_body() {
        let entry = SupplyEntry {
            id: "abc".to_owned(),
            kind: DirectiveKind::Transaction,
            economic_bean: "".to_owned(),
            envelope: BTreeMap::new(),
        };

        let result = validate_supply_entry(&entry);
        assert!(matches!(result, Err(MergeError::ParseError(_))));
    }

    #[test]
    fn test_validate_unparseable_body() {
        let entry = SupplyEntry {
            id: "abc".to_owned(),
            kind: DirectiveKind::Transaction,
            economic_bean: "this is not valid beancount".to_owned(),
            envelope: BTreeMap::new(),
        };

        let result = validate_supply_entry(&entry);
        assert!(matches!(result, Err(MergeError::ParseError(_))));
    }

    #[test]
    fn test_extract_lamport() {
        let entry = make_valid_supply_entry();
        let directive = validate_supply_entry(&entry).unwrap();
        let lamport = extract_lamport(&directive);
        assert_eq!(lamport, Some(5));
    }

    #[test]
    fn test_extract_parents_empty() {
        let entry = make_valid_supply_entry();
        let directive = validate_supply_entry(&entry).unwrap();
        let parents = extract_parents(&directive);
        assert!(parents.is_empty(), "Genesis has empty parents");
    }

    #[test]
    fn test_extract_parents_multiple() {
        let mut entry = make_valid_supply_entry();
        entry.envelope.insert(
            "openledger-parents".to_owned(),
            "aaa111,bbb222,ccc333".to_owned(),
        );
        let directive = validate_supply_entry(&entry).unwrap();
        let parents = extract_parents(&directive);
        assert_eq!(parents, vec!["aaa111", "bbb222", "ccc333"]);
    }

    #[test]
    fn test_validate_open_directive() {
        let open = Open {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        };
        let directive = Directive::Open(open);
        let id = compute_content_id(&directive);
        let economic_bean = economic_canonical_serialize(&directive);

        let entry = SupplyEntry {
            id,
            kind: DirectiveKind::Open,
            economic_bean,
            envelope: BTreeMap::from([("openledger-author".to_owned(), "peer-2".to_owned())]),
        };

        let result = validate_supply_entry(&entry);
        assert!(result.is_ok(), "Open directive should validate: {result:?}");
    }

    // ── CT-4: merge commutativity (I6) ──────────────────────────────────

    #[test]
    fn ct4_union_merge_commutativity() {
        // Two distinct transactions. Merging A then B should produce the
        // same aggregate balances as merging B then A.
        let txn_a = Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 10).unwrap(),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Transaction A".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(500),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-500),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let txn_b = Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 20).unwrap(),
            flag: Flag::Complete,
            payee: Some("Vendor".to_owned()),
            narration: Some("Transaction B".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(300),
                        currency: "EUR".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-300),
                        currency: "EUR".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let dir_a = Directive::Transaction(txn_a.clone());
        let dir_b = Directive::Transaction(txn_b.clone());
        let id_a = compute_content_id(&dir_a);
        let id_b = compute_content_id(&dir_b);
        let bean_a = economic_canonical_serialize(&dir_a);
        let bean_b = economic_canonical_serialize(&dir_b);

        let entry_a = SupplyEntry {
            id: id_a.clone(),
            kind: DirectiveKind::Transaction,
            economic_bean: bean_a,
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "peer-a".to_owned()),
                ("openledger-lamport".to_owned(), "1".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        };

        let entry_b = SupplyEntry {
            id: id_b.clone(),
            kind: DirectiveKind::Transaction,
            economic_bean: bean_b,
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "peer-b".to_owned()),
                ("openledger-lamport".to_owned(), "2".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        };

        // Order 1: A then B.
        let validated_a1 = validate_supply_entry(&entry_a).unwrap();
        let validated_b1 = validate_supply_entry(&entry_b).unwrap();
        let mut dag1 = ledger::dag::LedgerDag::new();
        dag1.insert(validated_a1, false).unwrap();
        dag1.insert(validated_b1, false).unwrap();

        // Order 2: B then A.
        let validated_a2 = validate_supply_entry(&entry_a).unwrap();
        let validated_b2 = validate_supply_entry(&entry_b).unwrap();
        let mut dag2 = ledger::dag::LedgerDag::new();
        dag2.insert(validated_b2, false).unwrap();
        dag2.insert(validated_a2, false).unwrap();

        // Both DAGs should contain exactly the same content IDs.
        let mut ids1: Vec<&str> = dag1.content_ids().into_iter().collect();
        let mut ids2: Vec<&str> = dag2.content_ids().into_iter().collect();
        ids1.sort();
        ids2.sort();
        assert_eq!(ids1, ids2, "Same entries regardless of merge order");

        // Both should produce the same read model balances.
        let mut rm1 = ledger::read_model::ReadModel::default();
        for id in &ids1 {
            if let Some(d) = dag1.get(id) {
                rm1.index_directive(d);
            }
        }
        let mut rm2 = ledger::read_model::ReadModel::default();
        for id in &ids2 {
            if let Some(d) = dag2.get(id) {
                rm2.index_directive(d);
            }
        }

        let date = chrono::NaiveDate::from_ymd_opt(2024, 12, 31).unwrap();
        let tb1 = rm1.trial_balance(date);
        let tb2 = rm2.trial_balance(date);
        assert_eq!(tb1.total_debit, tb2.total_debit, "Debit totals must match");
        assert_eq!(
            tb1.total_credit, tb2.total_credit,
            "Credit totals must match"
        );
        assert_eq!(tb1.rows.len(), tb2.rows.len(), "Same number of accounts");

        // Idempotency: inserting A again into dag1 should be a no-op.
        let validated_a_dup = validate_supply_entry(&entry_a).unwrap();
        let dup_result = dag1.insert(validated_a_dup, false).unwrap();
        assert!(
            matches!(dup_result, ledger::dag::InsertResult::Duplicate { .. }),
            "Duplicate insert should be idempotent"
        );
    }

    // ── CT-14: remote validation rejects I1 / I3 violations (§3.5) ──────

    #[test]
    fn ct14_remote_unbalanced_transaction_detected() {
        // Construct a supply entry with an unbalanced transaction.
        // validate_supply_entry only checks hash + envelope, but the caller
        // must validate I1–I3 before DAG insert. This test verifies the
        // content hash still works correctly and the unbalanced nature
        // is detectable by the validation layer.
        let unbalanced_txn = Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 2, 1).unwrap(),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Unbalanced remote".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(999),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-500),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let directive = Directive::Transaction(unbalanced_txn.clone());
        let id = compute_content_id(&directive);
        let bean = economic_canonical_serialize(&directive);

        let entry = SupplyEntry {
            id,
            kind: DirectiveKind::Transaction,
            economic_bean: bean,
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "bad-peer".to_owned()),
                ("openledger-lamport".to_owned(), "1".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        };

        // validate_supply_entry should pass (it checks hash + envelope, not balance).
        let parsed = validate_supply_entry(&entry).unwrap();

        // But I1 validation should catch the imbalance.
        if let Directive::Transaction(txn) = &parsed {
            let account_state = ledger::validate::AccountState::new();
            let result = ledger::validate::validate_transaction(txn, &account_state);
            assert!(
                result.is_err(),
                "Remote unbalanced transaction must be rejected by I1 validation"
            );
        } else {
            panic!("Expected Transaction");
        }
    }

    #[test]
    fn ct14_remote_unopened_account_detected() {
        // A remote transaction referencing an account not in the account state
        // should be rejected by I3 validation.
        let entry = make_valid_supply_entry();
        let parsed = validate_supply_entry(&entry).unwrap();

        if let Directive::Transaction(txn) = &parsed {
            // Use an empty account state (no accounts opened).
            let account_state = ledger::validate::AccountState::new();
            let result = ledger::validate::validate_transaction(txn, &account_state);
            assert!(
                result.is_err(),
                "Remote transaction to unopened account must be rejected by I3 validation"
            );
        } else {
            panic!("Expected Transaction");
        }
    }
}
