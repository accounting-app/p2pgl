//! T76 (M-50) through the real wire validators: the pre-T65 fixture's `X`
//! (`Assets:Cash 1000000000000000000000 USD`, exactly `10^21`, 22 significant
//! digits) signed by a real Ed25519 key is accepted by
//! [`validate_supply_entry`] + [`verify_remote_signature`] and stages, its
//! child after it; its `balance … 1000000000000000000014 USD` line — never
//! summed, so never capped — crosses too; and a transaction amount past
//! `10^21` is refused on the wire, permanently.
//!
//! Wave brief rule 5: peer acceptance means the wire validators, not only
//! `stage_remote_directive` (which `tests/exact_balances.rs` in the ledger
//! crate already drives, alongside the wire's re-parse).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::NaiveDate;
use ledger::hash::compute_content_id;
use ledger::limits::MAX_AMOUNT_MAGNITUDE;
use ledger::model::{Amount, Balance, Directive, Flag, Posting, Transaction};
use ledger::service::LedgerService;
use ledger::verify::verify_dag;
use p2p::gossip::make_supply_entry;
use p2p::union_merge::{validate_supply_entry, verify_remote_signature, MergeError};
use rust_decimal::Decimal;
use security::signing::{PeerKeySignatureProvider, SignableMessage, SignatureProvider};

const MESH_ID: &str = "m50-wire";

/// The fixture's `X` and `C` content ids (`D4-balances/fixtures/pre_upgrade.bean`,
/// also pinned in `ledger/tests/exact_balances.rs`): the ids cover the body
/// only, so a re-signed `X` keeps the id `C` names as its parent.
const X_ID: &str = "6fe3cf8e60a0a57d08e8cfeb8ffea404cf43a0e748c42abb027dd1133f7abcd3";
const C_ID: &str = "53aba2c00f81056079896ce4c067f7ad43f72e1f42569cd6e7c4db640424d68e";

fn date(day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(2024, 1, day).expect("valid date")
}

fn key() -> PeerKeySignatureProvider {
    PeerKeySignatureProvider::from_bytes(&[0x50; 32], MESH_ID.to_owned())
}

fn usd(number: Decimal) -> Amount {
    Amount {
        number,
        currency: "USD".to_owned(),
    }
}

fn posting(account: &str, number: Decimal) -> Posting {
    Posting {
        account: account.to_owned(),
        amount: Some(usd(number)),
        cost: None,
        price: None,
        metadata: BTreeMap::new(),
    }
}

/// A transfer `Assets:Cash +amount / Equity:Opening −amount`, stamped and
/// signed by `key` at `lamport` naming `parents`.
fn signed_transfer(
    key: &PeerKeySignatureProvider,
    day: u32,
    narration: &str,
    amount: Decimal,
    parents: &str,
    lamport: u64,
) -> Directive {
    let mut transaction = Transaction {
        date: date(day),
        flag: Flag::Complete,
        payee: None,
        narration: Some(narration.to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            posting("Assets:Cash", amount),
            posting("Equity:Opening", -amount),
        ],
        metadata: BTreeMap::new(),
    };
    let content_id = compute_content_id(&Directive::Transaction(transaction.clone()));
    let lamport = lamport.to_string();
    let signature = key
        .sign(&SignableMessage {
            content_id: &content_id,
            is_transaction: true,
            parents,
            lamport: &lamport,
        })
        .expect("a peer key signs");
    for (name, value) in [
        ("openledger-author", key.public_key_hex()),
        ("openledger-lamport", lamport),
        ("openledger-parents", parents.to_owned()),
        ("openledger-signature", signature),
    ] {
        transaction.metadata.insert(name.to_owned(), value);
    }
    Directive::Transaction(transaction)
}

fn signed_balance(key: &PeerKeySignatureProvider, number: Decimal, lamport: u64) -> Directive {
    let mut balance = Balance {
        date: date(5),
        account: "Assets:Cash".to_owned(),
        amount: usd(number),
        metadata: BTreeMap::new(),
    };
    let content_id = compute_content_id(&Directive::Balance(balance.clone()));
    let lamport = lamport.to_string();
    let signature = key
        .sign(&SignableMessage {
            content_id: &content_id,
            is_transaction: false,
            parents: "",
            lamport: &lamport,
        })
        .expect("a peer key signs");
    for (name, value) in [
        ("openledger-author", key.public_key_hex()),
        ("openledger-lamport", lamport),
        ("openledger-signature", signature),
    ] {
        balance.metadata.insert(name.to_owned(), value);
    }
    Directive::Balance(balance)
}

/// `gl-node::anti_entropy_alpn::intake_refusal_is_permanent`, verbatim (it is
/// private; `convergence.rs` mirrors it the same way). Exhaustive, so a new
/// `MergeError` variant fails to compile here until it is classified.
fn intake_refusal_is_permanent(error: &MergeError) -> bool {
    match error {
        MergeError::ContentHashMismatch { .. }
        | MergeError::ParseError(_)
        | MergeError::ValidationError(_)
        | MergeError::EnvelopeMissing(_)
        | MergeError::InvalidSignature(_)
        | MergeError::ResourceLimitExceeded(_)
        | MergeError::CycleDetected
        | MergeError::InvalidEnvelope(_)
        | MergeError::BodyEnvelopeKey(_)
        | MergeError::BodyControlCharacter(_)
        | MergeError::ElidedPosting => true,
    }
}

/// The real intake's validators, in `apply_supply_entries_from`'s order
/// (the allowlist check is independent of amounts and needs a registry).
fn through_the_wire(directive: &Directive) -> Result<Directive, MergeError> {
    let entry = make_supply_entry(directive);
    let admitted = validate_supply_entry(&entry)?;
    verify_remote_signature(&admitted, true, MESH_ID)?;
    Ok(admitted)
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn scratch_ledger(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ol-m50-wire-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir.join("ledger.bean")
}

#[test]
fn m50_fixture_x_signed_by_a_real_key_is_accepted_on_the_wire_and_stages() {
    let key = key();
    let ten_pow_21 =
        Decimal::from_i128_with_scale(i128::try_from(MAX_AMOUNT_MAGNITUDE).expect("fits"), 0);
    assert_eq!(ten_pow_21.to_string(), "1000000000000000000000");

    let x = signed_transfer(&key, 2, "X pre-upgrade", ten_pow_21, "", 3);
    assert_eq!(compute_content_id(&x), X_ID, "X's id is the fixture's");
    let c = signed_transfer(&key, 3, "C child", Decimal::from(5), X_ID, 4);
    assert_eq!(compute_content_id(&c), C_ID, "C's id is the fixture's");
    let claim = signed_balance(
        &key,
        Decimal::from_str_exact("1000000000000000000014").expect("literal"),
        6,
    );
    let g = signed_transfer(&key, 4, "G grandchild", Decimal::from(9), C_ID, 5);

    let path = scratch_ledger("accept");
    let mut service = LedgerService::boot(&path, "fresh".to_owned()).expect("boot");
    for account in ["Assets:Cash", "Equity:Opening"] {
        service
            .open_account(
                account.to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                vec![],
            )
            .expect("open");
    }
    for directive in [&x, &c, &g, &claim] {
        let admitted = through_the_wire(directive).unwrap_or_else(|error| {
            panic!(
                "{} refused on the wire: {error}",
                compute_content_id(directive)
            )
        });
        service
            .stage_remote_directive(admitted)
            .unwrap_or_else(|error| {
                panic!(
                    "{} refused at staging: {error}",
                    compute_content_id(directive)
                )
            })
            .expect("new");
    }
    let cash = service
        .read_model()
        .account_balance("Assets:Cash", None)
        .expect("cash");
    assert_eq!(cash.balances["USD"].to_string(), "1000000000000000000014");
    assert!(cash.exact);
    let report = verify_dag(service.dag(), service.read_model());
    assert!(report.ok, "{:?}", report.errors);
    assert_eq!(report.assertions.evaluated, 1);
    assert!(report.assertions.ok(), "{:?}", report.assertions.failures);
    drop(service);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

#[test]
fn a_transaction_amount_past_the_cap_is_refused_on_the_wire_for_good() {
    let key = key();
    let cap = i128::try_from(MAX_AMOUNT_MAGNITUDE).expect("fits");
    for over in [
        Decimal::from_i128_with_scale(cap + 1, 0),
        Decimal::from_i128_with_scale(cap * 10_000_000 + 1, 7),
        -Decimal::MAX,
    ] {
        let directive = signed_transfer(&key, 2, "over", over, "", 3);
        let error =
            through_the_wire(&directive).expect_err(&format!("{over} must be refused on the wire"));
        assert!(
            matches!(error, MergeError::ParseError(ref message) if message.contains("H-17")),
            "{over}: expected the parser's cap refusal, got {error:?}"
        );
        assert!(
            intake_refusal_is_permanent(&error),
            "{over}: a content verdict, cached for good (L-34)"
        );
    }
    // The inclusive bound itself, at any precision, is not refused.
    for inside in ["1000000000000000000000", "-1000000000000000000000.0000000"] {
        let number = Decimal::from_str_exact(inside).expect("literal");
        through_the_wire(&signed_transfer(&key, 2, "at the cap", number, "", 3))
            .unwrap_or_else(|error| panic!("{inside} refused: {error}"));
    }
}
