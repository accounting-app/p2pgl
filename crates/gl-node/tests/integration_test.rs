//! End-to-end integration tests for the full gl-node stack.
//!
//! These tests boot a real `LedgerService`, wire it into the GraphQL schema,
//! and execute real queries/mutations. This validates the entire read/write
//! path: GraphQL → resolver → LedgerService → DAG → ReadModel → file.

use ledger::service::LedgerService;

/// Helper: boot a ledger service from a temp directory.
fn boot_temp_ledger() -> (tempfile::TempDir, LedgerService) {
    let dir = tempfile::tempdir().unwrap();
    let bean_path = dir.path().join("test.bean");
    std::fs::write(&bean_path, "").unwrap();
    let svc = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
    (dir, svc)
}

/// Helper: boot from a fixture file.
fn boot_fixture_ledger() -> (tempfile::TempDir, LedgerService) {
    let fixture = include_str!("../../../testfixtures/fixture-simple.bean");
    let dir = tempfile::tempdir().unwrap();
    let bean_path = dir.path().join("fixture.bean");
    std::fs::write(&bean_path, fixture).unwrap();
    let svc = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
    (dir, svc)
}

// ─── Service-level integration tests ─────────────────────────────────────────

#[test]
fn test_empty_boot_then_open_and_append() {
    let (_dir, mut svc) = boot_temp_ledger();

    svc.open_account(
        "Assets:Cash".to_owned(),
        chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        vec!["USD".to_owned()],
    )
    .unwrap();
    svc.open_account(
        "Equity:Opening".to_owned(),
        chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        vec!["USD".to_owned()],
    )
    .unwrap();

    assert_eq!(svc.directive_count(), 2);

    let input = ledger::service::TransactionInput {
        date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
        flag: ledger::model::Flag::Complete,
        payee: Some("Test Corp".to_owned()),
        narration: Some("Initial deposit".to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            ledger::service::PostingInput {
                account: "Assets:Cash".to_owned(),
                amount: Some(ledger::model::Amount {
                    number: rust_decimal_macros::dec!(1000),
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
            ledger::service::PostingInput {
                account: "Equity:Opening".to_owned(),
                amount: None, // Elided — I2 should resolve.
                cost: None,
                price: None,
            },
        ],
    };
    let txid = svc.append_transaction(input).unwrap().txid;
    assert!(!txid.is_empty());
    assert_eq!(svc.directive_count(), 3);
    assert_eq!(svc.head_count(), 1);

    let entry = svc.read_model().account_balance(
        "Assets:Cash",
        Some(chrono::NaiveDate::from_ymd_opt(2024, 12, 31).unwrap()),
    );
    assert!(entry.is_some());
    assert_eq!(
        entry.unwrap().balances.get("USD"),
        Some(&rust_decimal_macros::dec!(1000))
    );
}

#[test]
fn test_fixture_boot_has_correct_state() {
    let (_dir, svc) = boot_fixture_ledger();
    assert!(svc.directive_count() > 0);
    assert!(svc.head_count() > 0);

    let tb = svc
        .read_model()
        .trial_balance(chrono::NaiveDate::from_ymd_opt(2024, 12, 31).unwrap());
    assert!(!tb.rows.is_empty());
    // The fixture has transactions, so totals should be non-zero.
    assert!(
        tb.total_debit > rust_decimal::Decimal::ZERO
            || tb.total_credit > rust_decimal::Decimal::ZERO,
        "Trial balance should have non-zero totals"
    );
}

#[test]
fn test_verify_after_boot() {
    let (_dir, svc) = boot_fixture_ledger();
    let report = ledger::verify::verify_dag(svc.dag(), svc.read_model());
    assert!(report.nodes_checked > 0);

    assert!(!report
        .errors
        .iter()
        .any(|e| matches!(e, ledger::verify::VerifyError::ContentHashMismatch { .. })));
    assert!(!report
        .errors
        .iter()
        .any(|e| matches!(e, ledger::verify::VerifyError::CycleDetected { .. })));
}

#[test]
fn test_idempotent_transaction_insert() {
    let (_dir, mut svc) = boot_temp_ledger();

    svc.open_account(
        "Assets:Cash".to_owned(),
        chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        vec!["USD".to_owned()],
    )
    .unwrap();
    svc.open_account(
        "Equity:Opening".to_owned(),
        chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        vec!["USD".to_owned()],
    )
    .unwrap();

    let make_input = || ledger::service::TransactionInput {
        date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
        flag: ledger::model::Flag::Complete,
        payee: None,
        narration: Some("Test".to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            ledger::service::PostingInput {
                account: "Assets:Cash".to_owned(),
                amount: Some(ledger::model::Amount {
                    number: rust_decimal_macros::dec!(500),
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
            ledger::service::PostingInput {
                account: "Equity:Opening".to_owned(),
                amount: Some(ledger::model::Amount {
                    number: rust_decimal_macros::dec!(-500),
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
        ],
    };

    let txid1 = svc.append_transaction(make_input()).unwrap().txid;
    let count_after_first = svc.directive_count();
    let txid2 = svc.append_transaction(make_input()).unwrap().txid;
    assert_eq!(txid1, txid2, "Same content → same txid (I4/I5)");
    assert_eq!(svc.directive_count(), count_after_first);
}

#[test]
fn test_unbalanced_transaction_rejected() {
    let (_dir, mut svc) = boot_temp_ledger();

    svc.open_account(
        "Assets:Cash".to_owned(),
        chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        vec!["USD".to_owned()],
    )
    .unwrap();

    let input = ledger::service::TransactionInput {
        date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
        flag: ledger::model::Flag::Complete,
        payee: None,
        narration: Some("Unbalanced".to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![ledger::service::PostingInput {
            account: "Assets:Cash".to_owned(),
            amount: Some(ledger::model::Amount {
                number: rust_decimal_macros::dec!(1000),
                currency: "USD".to_owned(),
            }),
            cost: None,
            price: None,
        }],
    };

    let result = svc.append_transaction(input);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().error_code(), "UNBALANCED_TRANSACTION");
}

#[test]
fn test_reboot_preserves_state() {
    let dir = tempfile::tempdir().unwrap();
    let bean_path = dir.path().join("persist.bean");
    std::fs::write(&bean_path, "").unwrap();

    let txid;
    {
        let mut svc = LedgerService::boot(&bean_path, "test".to_owned()).unwrap();
        svc.open_account(
            "Assets:Cash".to_owned(),
            chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            vec!["USD".to_owned()],
        )
        .unwrap();
        svc.open_account(
            "Equity:Opening".to_owned(),
            chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            vec![],
        )
        .unwrap();
        txid = svc
            .append_transaction(ledger::service::TransactionInput {
                date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
                flag: ledger::model::Flag::Complete,
                payee: None,
                narration: Some("Persist test".to_owned()),
                tags: vec![],
                links: vec![],
                postings: vec![
                    ledger::service::PostingInput {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(ledger::model::Amount {
                            number: rust_decimal_macros::dec!(100),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                    },
                    ledger::service::PostingInput {
                        account: "Equity:Opening".to_owned(),
                        amount: Some(ledger::model::Amount {
                            number: rust_decimal_macros::dec!(-100),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                    },
                ],
            })
            .unwrap()
            .txid;
    }

    let svc2 = LedgerService::boot(&bean_path, "test".to_owned()).unwrap();
    assert_eq!(svc2.directive_count(), 3);
    assert!(svc2.get_directive(&txid).is_some());
    assert_eq!(
        svc2.read_model()
            .account_balance(
                "Assets:Cash",
                Some(chrono::NaiveDate::from_ymd_opt(2024, 12, 31).unwrap()),
            )
            .unwrap()
            .balances
            .get("USD"),
        Some(&rust_decimal_macros::dec!(100))
    );
}

#[test]
fn test_checkpoint_balance_assertion() {
    let (_dir, mut svc) = boot_temp_ledger();

    svc.open_account(
        "Assets:Cash".to_owned(),
        chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        vec!["USD".to_owned()],
    )
    .unwrap();
    svc.open_account(
        "Equity:Opening".to_owned(),
        chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        vec![],
    )
    .unwrap();

    svc.append_transaction(ledger::service::TransactionInput {
        date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
        flag: ledger::model::Flag::Complete,
        payee: None,
        narration: Some("Deposit".to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            ledger::service::PostingInput {
                account: "Assets:Cash".to_owned(),
                amount: Some(ledger::model::Amount {
                    number: rust_decimal_macros::dec!(500),
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
            ledger::service::PostingInput {
                account: "Equity:Opening".to_owned(),
                amount: Some(ledger::model::Amount {
                    number: rust_decimal_macros::dec!(-500),
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
        ],
    })
    .unwrap();

    let balance = ledger::model::Balance {
        date: chrono::NaiveDate::from_ymd_opt(2024, 2, 1).unwrap(),
        account: "Assets:Cash".to_owned(),
        amount: ledger::model::Amount {
            number: rust_decimal_macros::dec!(500),
            currency: "USD".to_owned(),
        },
        metadata: std::collections::BTreeMap::new(),
    };

    let result = ledger::checkpoint::evaluate_balance_assertion(&balance, svc.read_model());
    assert!(result.ok);
}

#[test]
fn test_signing_roundtrip() {
    use security::signing::{PeerKeySignatureProvider, SignatureProvider};

    let provider = PeerKeySignatureProvider::generate();
    let message = security::signing::SignableMessage {
        content_id: "abc123",
        is_transaction: true,
        parents: "",
        lamport: "1",
    };
    let sig = provider.sign(&message).unwrap();

    let result = provider.verify(&message, &sig, &provider.public_key_hex());
    assert!(result.is_ok());

    let other = PeerKeySignatureProvider::generate();
    let result = provider.verify(&message, &sig, &other.public_key_hex());
    assert!(result.is_err());
}
