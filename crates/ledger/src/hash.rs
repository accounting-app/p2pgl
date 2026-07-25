//! Content-addressed hashing for directives (§3.3.1, §3.3.2).
//!
//! `txid = SHA-256(economic_canonical_serialize(transaction))`
//! `directiveId = SHA-256(economic_canonical_serialize(non_transaction_directive))`

use sha2::{Digest, Sha256};

use crate::model::Directive;
use crate::serialize::economic_canonical_serialize;

/// Compute the content ID for any directive.
///
/// For transactions this is the `txid`; for non-transaction directives
/// it is the `directiveId`. Both are 64-character lowercase hex SHA-256 strings.
pub fn compute_content_id(directive: &Directive) -> String {
    let canonical = economic_canonical_serialize(directive);
    let hash = Sha256::digest(canonical.as_bytes());
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use chrono::NaiveDate;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    /// CT-3: Worked `txid` fixture from §3.3.3 (normative).
    #[test]
    fn test_ct3_worked_fixture_txid() {
        let txn = Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: Some("Acme Corp".to_owned()),
            narration: Some("Initial funding".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(1000.00),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening-Balances".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-1000.00),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let txid = compute_content_id(&Directive::Transaction(txn));
        assert_eq!(
            txid,
            "dd4a9ec5ec298be6edaa02c4408c0b1cb1b25eb51426599b7eda600cfc5fa88f",
            "CT-3: worked fixture txid must match §3.3.3"
        );
    }

    /// CT-3 extended: envelope metadata must not affect txid.
    #[test]
    fn test_ct3_envelope_does_not_change_txid() {
        let make_txn = |has_envelope: bool| -> Transaction {
            let mut metadata = BTreeMap::new();
            if has_envelope {
                metadata.insert("openledger-author".to_owned(), "peer-42".to_owned());
                metadata.insert("openledger-lamport".to_owned(), "99".to_owned());
                metadata.insert("openledger-parents".to_owned(), "".to_owned());
            }
            Transaction {
                date: make_date(2024, 1, 15),
                flag: Flag::Complete,
                payee: Some("Acme Corp".to_owned()),
                narration: Some("Initial funding".to_owned()),
                tags: Vec::new(),
                links: Vec::new(),
                postings: vec![
                    Posting {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(1000.00),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                    Posting {
                        account: "Equity:Opening-Balances".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-1000.00),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                ],
                metadata,
            }
        };

        let txid_bare = compute_content_id(&Directive::Transaction(make_txn(false)));
        let txid_envelope = compute_content_id(&Directive::Transaction(make_txn(true)));

        assert_eq!(
            txid_bare, txid_envelope,
            "envelope metadata must not change txid"
        );
        assert_eq!(
            txid_bare,
            "dd4a9ec5ec298be6edaa02c4408c0b1cb1b25eb51426599b7eda600cfc5fa88f"
        );
    }

    #[test]
    fn test_content_id_is_64_char_hex() {
        let open = Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        };
        let id = compute_content_id(&Directive::Open(open));
        assert_eq!(id.len(), 64, "content ID must be 64 hex characters");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "content ID must be lowercase hex"
        );
    }

    #[test]
    fn test_different_directives_different_ids() {
        let open_a = Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        });
        let open_b = Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Bank".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        });
        assert_ne!(
            compute_content_id(&open_a),
            compute_content_id(&open_b),
            "different economic bodies must produce different content IDs"
        );
    }

    #[test]
    fn test_content_id_stable_across_calls() {
        let open = Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: Vec::new(),
            metadata: BTreeMap::new(),
        };
        let id1 = compute_content_id(&Directive::Open(open.clone()));
        let id2 = compute_content_id(&Directive::Open(open));
        assert_eq!(id1, id2, "content ID must be deterministic");
    }
}
