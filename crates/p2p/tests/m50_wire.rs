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

// ─── A5 (0924 re-audit of T76): the wire on both caps, at every spelling ─────

use ledger::limits::MAX_CURRENCIES_PER_OPEN;
use ledger::model::{Open, Price};
use ledger::service::MAX_POSTINGS_PER_TRANSACTION;

/// A non-transaction directive (`open`, `price`) signed by `key` at `lamport`.
fn sign_directive(key: &PeerKeySignatureProvider, directive: Directive, lamport: u64) -> Directive {
    let content_id = compute_content_id(&directive);
    let lamport = lamport.to_string();
    let signature = key
        .sign(&SignableMessage {
            content_id: &content_id,
            is_transaction: false,
            parents: "",
            lamport: &lamport,
        })
        .expect("a peer key signs");
    let stamp = |metadata: &mut BTreeMap<String, String>| {
        for (name, value) in [
            ("openledger-author", key.public_key_hex()),
            ("openledger-lamport", lamport.clone()),
            ("openledger-signature", signature.clone()),
        ] {
            metadata.insert(name.to_owned(), value);
        }
    };
    match directive {
        Directive::Open(mut open) => {
            stamp(&mut open.metadata);
            Directive::Open(open)
        }
        Directive::Price(mut price) => {
            stamp(&mut price.metadata);
            Directive::Price(price)
        }
        other => other,
    }
}

fn signed_open(
    key: &PeerKeySignatureProvider,
    account: &str,
    currencies: usize,
    lamport: u64,
) -> Directive {
    sign_directive(
        key,
        Directive::Open(Open {
            date: date(1),
            account: account.to_owned(),
            currencies: (0..currencies)
                .map(|index| format!("C{index:03}"))
                .collect(),
            metadata: BTreeMap::new(),
        }),
        lamport,
    )
}

fn signed_price(key: &PeerKeySignatureProvider, number: Decimal, lamport: u64) -> Directive {
    sign_directive(
        key,
        Directive::Price(Price {
            date: date(5),
            currency: "BTC".to_owned(),
            amount: usd(number),
            metadata: BTreeMap::new(),
        }),
        lamport,
    )
}

/// A signed transfer with `count` postings (the first `count − 1` share one
/// unit each, the last balances them).
fn signed_wide_transfer(key: &PeerKeySignatureProvider, count: usize, lamport: u64) -> Directive {
    let mut postings: Vec<Posting> = (0..count - 1)
        .map(|_| posting("Assets:Cash", Decimal::ONE))
        .collect();
    postings.push(posting("Equity:Opening", -Decimal::from(count as u64 - 1)));
    let mut transaction = Transaction {
        date: date(2),
        flag: Flag::Complete,
        payee: None,
        narration: Some(format!("{count} postings")),
        tags: vec![],
        links: vec![],
        postings,
        metadata: BTreeMap::new(),
    };
    let content_id = compute_content_id(&Directive::Transaction(transaction.clone()));
    let lamport = lamport.to_string();
    let signature = key
        .sign(&SignableMessage {
            content_id: &content_id,
            is_transaction: true,
            parents: "",
            lamport: &lamport,
        })
        .expect("a peer key signs");
    for (name, value) in [
        ("openledger-author", key.public_key_hex()),
        ("openledger-lamport", lamport),
        ("openledger-parents", String::new()),
        ("openledger-signature", signature),
    ] {
        transaction.metadata.insert(name.to_owned(), value);
    }
    Directive::Transaction(transaction)
}

/// A5 (0924): `10^21` — the inclusive bound — spelled at every scale a
/// `Decimal` can hold it (0–7 fractional zeros, both signs) crosses the
/// wire signed; one unit in the last place past it at each of those scales
/// is refused as a permanent parse verdict; and the scale-8 spelling is not
/// a `Decimal` at all (29 mantissa digits past 2^96), so it is refused
/// before any cap by `from_str_exact` — on the wire and at the API alike.
#[test]
fn ten_pow_21_at_every_representable_scale_crosses_the_wire_signed() {
    let key = key();
    for scale in 0..=7u32 {
        let spelled = if scale == 0 {
            "1000000000000000000000".to_owned()
        } else {
            format!("1000000000000000000000.{}", "0".repeat(scale as usize))
        };
        for sign in ["", "-"] {
            let number = Decimal::from_str_exact(&format!("{sign}{spelled}")).expect("literal");
            assert_eq!(number.scale(), scale);
            let admitted = through_the_wire(&signed_transfer(&key, 2, "at the cap", number, "", 3))
                .unwrap_or_else(|error| panic!("{sign}{spelled} refused: {error}"));
            let Directive::Transaction(ref transaction) = admitted else {
                panic!("a transaction")
            };
            let back = transaction.postings[0]
                .amount
                .as_ref()
                .expect("explicit")
                .number;
            assert_eq!(
                back.to_string(),
                format!("{sign}{spelled}"),
                "spelling kept"
            );
        }
        // One ulp past, at this scale.
        let past = Decimal::from_i128_with_scale(
            i128::try_from(MAX_AMOUNT_MAGNITUDE).expect("fits") * 10i128.pow(scale) + 1,
            scale,
        );
        let error = through_the_wire(&signed_transfer(&key, 2, "past", past, "", 3))
            .expect_err("one ulp past the cap");
        assert!(
            matches!(error, MergeError::ParseError(ref message) if message.contains("H-17")),
            "{past}: {error:?}"
        );
        assert!(intake_refusal_is_permanent(&error));
    }
    let unrepresentable = "1000000000000000000000.00000000";
    assert!(
        Decimal::from_str_exact(unrepresentable).is_err(),
        "10^21 with eight zeros is 10^29 in the mantissa: no Decimal"
    );
    // The same string in a body: the number reader refuses it before the cap.
    let mut entry = make_supply_entry(&signed_transfer(
        &key,
        2,
        "unrepresentable",
        Decimal::ONE,
        "",
        3,
    ));
    entry.economic_bean = entry
        .economic_bean
        .replace("1 USD", &format!("{unrepresentable} USD"))
        .replace("-1 USD", &format!("-{unrepresentable} USD"));
    let error = validate_supply_entry(&entry).expect_err("no Decimal holds it");
    assert!(
        matches!(error, MergeError::ParseError(ref message) if message.contains("Invalid number")),
        "{error:?}"
    );
}

/// A5 (0924): `balance` and `price` amounts are never summed, so the cap does
/// not apply to them on the wire either — `Decimal::MAX` in each crosses
/// `validate_supply_entry` + `verify_remote_signature` signed and stages;
/// the assertion then evaluates (and fails, honestly) against the exact sum.
#[test]
fn balance_and_price_amounts_above_the_cap_cross_the_wire_signed() {
    let key = key();
    let path = scratch_ledger("uncapped");
    let mut service = LedgerService::boot(&path, "fresh".to_owned()).expect("boot");
    service
        .open_account(
            "Assets:Cash".to_owned(),
            NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            vec![],
        )
        .expect("open");
    for (label, directive) in [
        ("balance MAX", signed_balance(&key, Decimal::MAX, 6)),
        ("balance MIN", signed_balance(&key, Decimal::MIN, 7)),
        ("price MAX", signed_price(&key, Decimal::MAX, 8)),
        (
            "price 10^21 + 1",
            signed_price(
                &key,
                Decimal::from_i128_with_scale(
                    i128::try_from(MAX_AMOUNT_MAGNITUDE).expect("fits") + 1,
                    0,
                ),
                9,
            ),
        ),
    ] {
        let admitted = through_the_wire(&directive)
            .unwrap_or_else(|error| panic!("{label} refused on the wire: {error}"));
        service
            .stage_remote_directive(admitted)
            .unwrap_or_else(|error| panic!("{label} refused at staging: {error}"))
            .expect("new");
    }
    let report = verify_dag(service.dag(), service.read_model());
    assert!(report.ok, "{:?}", report.errors);
    assert_eq!(report.assertions.evaluated, 2);
    assert_eq!(
        report.assertions.failures.len(),
        2,
        "0 is neither MAX nor MIN"
    );
    for failure in &report.assertions.failures {
        assert!(failure.actual_exact);
        assert_eq!(failure.actual, Decimal::ZERO);
    }
    drop(service);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// A5 (0924), updated by T81 (M-51, decision (6)): the M-50 fixture and the
/// T75 caps together. A pre-T65 amount (`10^21`, 22 digits) crosses the wire;
/// so, since T81, does a pre-T75 `open` with one currency past
/// `MAX_CURRENCIES_PER_OPEN` — the wire holds history to the legacy ceiling —
/// and a fresh replica takes the account and the posting on it (at `3d64a16`
/// it refused the `open` and every posting was `ACCOUNT_NOT_OPEN`, the M-50
/// shape under another cap). One currency past the legacy ceiling, and one
/// posting past `MAX_POSTINGS_PER_TRANSACTION` (not a T75 cap), are still
/// refused, permanently.
#[test]
fn a_pre_t65_amount_and_pre_t75_history_cross_the_wire_up_to_the_legacy_ceilings() {
    let key = key();
    let ten_pow_21 =
        Decimal::from_i128_with_scale(i128::try_from(MAX_AMOUNT_MAGNITUDE).expect("fits"), 0);
    through_the_wire(&signed_transfer(
        &key,
        2,
        "X pre-upgrade",
        ten_pow_21,
        "",
        3,
    ))
    .expect("the pre-T65 amount is inside the magnitude cap");

    let wide_open = signed_open(&key, "Assets:Many", MAX_CURRENCIES_PER_OPEN + 1, 2);
    through_the_wire(&wide_open)
        .expect("65 currencies is pre-T75 history, inside the legacy ceiling");
    through_the_wire(&signed_open(
        &key,
        "Assets:Legacy",
        ledger::limits::MAX_CURRENCIES_PER_OPEN_LEGACY,
        2,
    ))
    .expect("the legacy ceiling is inclusive");
    let error = through_the_wire(&signed_open(
        &key,
        "Assets:Flood",
        ledger::limits::MAX_CURRENCIES_PER_OPEN_LEGACY + 1,
        2,
    ))
    .expect_err("one past the legacy ceiling");
    assert!(
        matches!(error, MergeError::ResourceLimitExceeded(_)),
        "{error:?}"
    );
    assert!(intake_refusal_is_permanent(&error));

    let wide_transfer = signed_wide_transfer(&key, MAX_POSTINGS_PER_TRANSACTION + 1, 3);
    let error = through_the_wire(&wide_transfer).expect_err("1001 postings");
    assert!(
        matches!(error, MergeError::ResourceLimitExceeded(_)),
        "{error:?}"
    );
    assert!(intake_refusal_is_permanent(&error));

    // The upgraded node boots the pre-T75 `open` as history and serves it …
    let opening = signed_open(&key, "Equity:Opening", 0, 1);
    let child = signed_transfer(&key, 3, "on the wide account", Decimal::from(5), "", 4);
    let Directive::Transaction(mut on_many) = child else {
        panic!("a transaction")
    };
    on_many.postings[0].account = "Assets:Many".to_owned();
    on_many.postings[0].amount = Some(Amount {
        number: Decimal::from(5),
        currency: "C001".to_owned(),
    });
    on_many.postings[1].amount = Some(Amount {
        number: Decimal::from(-5),
        currency: "C001".to_owned(),
    });
    let on_many = {
        // Re-sign the edited body.
        let content_id = compute_content_id(&Directive::Transaction(on_many.clone()));
        let signature = key
            .sign(&SignableMessage {
                content_id: &content_id,
                is_transaction: true,
                parents: "",
                lamport: "4",
            })
            .expect("signs");
        on_many
            .metadata
            .insert("openledger-signature".to_owned(), signature);
        Directive::Transaction(on_many)
    };
    let path = scratch_ledger("t75-history");
    std::fs::write(
        &path,
        ledger::serialize::full_file_serialize(
            &[opening.clone(), wide_open.clone(), on_many.clone()],
            &[],
        ),
    )
    .expect("write");
    let upgraded = LedgerService::boot(&path, "nodeA".to_owned()).expect("boot");
    assert_eq!(
        upgraded.quarantined_count(),
        0,
        "history over a T75 cap loads"
    );
    assert!(upgraded.contains_directive(&compute_content_id(&wide_open)));
    assert!(upgraded.contains_directive(&compute_content_id(&on_many)));

    // … and, since T81, a fresh replica takes the account and the posting.
    let fresh_path = scratch_ledger("t75-fresh");
    let mut fresh = LedgerService::boot(&fresh_path, "fresh".to_owned()).expect("boot fresh");
    let mut codes = Vec::new();
    for directive in [&opening, &wide_open, &on_many] {
        codes.push(match through_the_wire(directive) {
            Ok(admitted) => fresh
                .stage_remote_directive(admitted)
                .map(|_| "OK")
                .unwrap_or_else(|error| error.error_code()),
            Err(error) => {
                assert!(intake_refusal_is_permanent(&error));
                "WIRE_REFUSED"
            }
        });
    }
    assert_eq!(codes, vec!["OK", "OK", "OK"]);
    drop(upgraded);
    drop(fresh);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
}

/// A5-1 (0924), the wire half: an amount past `10^21` that a pre-T65 node
/// still serves (`5 × 10^22 WEI`) is refused for good on the wire, and its
/// child — inside every cap, signed, well-formed — passes the wire and then
/// waits on `MISSING_PARENT` forever. The upgraded serving node quarantines
/// the parent as text and still serves the child (`ledger/tests/exact_balances.rs`
/// pins that half, ignored); this pins what the receiving side does with it.
#[test]
fn an_over_cap_parent_a_pre_t65_node_serves_strands_its_child_on_every_fresh_replica() {
    let key = key();
    let over = Decimal::from_str_exact("50000000000000000000000").expect("5 × 10^22");
    let x = signed_transfer(&key, 2, "X pre-upgrade", over, "", 3);
    let x_id = compute_content_id(&x);
    let c = signed_transfer(&key, 3, "C child", Decimal::from(5), &x_id, 4);

    let error = through_the_wire(&x).expect_err("past the cap");
    assert!(
        matches!(error, MergeError::ParseError(ref message) if message.contains("H-17")),
        "{error:?}"
    );
    assert!(
        intake_refusal_is_permanent(&error),
        "cached for good (L-34)"
    );

    let path = scratch_ledger("stranded");
    let mut fresh = LedgerService::boot(&path, "fresh".to_owned()).expect("boot");
    for account in ["Assets:Cash", "Equity:Opening"] {
        fresh
            .open_account(
                account.to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                vec![],
            )
            .expect("open");
    }
    let admitted = through_the_wire(&c).expect("the child is inside every cap");
    let error = fresh
        .stage_remote_directive(admitted)
        .expect_err("its parent can never arrive");
    assert_eq!(error.error_code(), "MISSING_PARENT");
    assert!(!fresh.contains_directive(&compute_content_id(&c)));
    drop(fresh);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// A hand-typed transaction with `keys` directive metadata keys, as an
/// operator would append it to the `.bean` (M-55).
fn hand_transaction_with_keys(keys: usize) -> String {
    let mut block = format!("\n2024-01-20 * \"Hand\" \"keys {keys}\"\n");
    for index in 0..keys {
        block.push_str(&format!("  k{index:03}: \"v\"\n"));
    }
    block.push_str("  Assets:Cash                                         5 USD\n");
    block.push_str("  Equity:Opening                                     -5 USD\n");
    block
}

/// M-55 (0924 A4-1), closed by T81 (decision (10)): the metadata-key cap
/// counts the whole map, envelope included, and a peer counts the map it
/// receives — body keys plus author, lamport, parents and signature. The
/// file path used to count before the signature was added, so a hand
/// transaction with 97 body keys was adopted and signed here and refused by
/// every peer (101 keys), with every later write of this node naming it as a
/// parent. Now the file path counts the envelope the stored record will
/// carry: 96 body keys are adopted, signed with a real key, cross the wire
/// and stage on a second node; 97 are refused here, before anything is
/// stamped or served.
#[test]
fn a_hand_transaction_adopted_with_a_signer_is_one_every_peer_accepts() {
    let key = std::sync::Arc::new(key());
    let signing = std::sync::Arc::clone(&key);
    let path = scratch_ledger("m55");
    let mut node = LedgerService::boot(&path, key.public_key_hex()).expect("boot");
    node.set_signer(std::sync::Arc::new(
        move |content_id: &str, is_transaction: bool, parents: &str, lamport: &str| {
            signing.sign(&SignableMessage {
                content_id,
                is_transaction,
                parents,
                lamport,
            })
        },
    ));
    let sign_open = |key: std::sync::Arc<PeerKeySignatureProvider>| {
        move |content_id: &str, parents: &str, lamport: &str| {
            key.sign(&SignableMessage {
                content_id,
                is_transaction: false,
                parents,
                lamport,
            })
        }
    };
    for (account, currencies) in [
        ("Assets:Cash", vec!["USD".to_owned()]),
        ("Equity:Opening", vec![]),
    ] {
        node.open_account_signing(
            account.to_owned(),
            date(1),
            currencies,
            sign_open(std::sync::Arc::clone(&key)),
        )
        .expect("open");
    }

    let append = |text: &str| {
        let mut content = std::fs::read_to_string(&path).expect("read");
        content.push_str(text);
        std::fs::write(&path, content).expect("write");
    };
    append(&hand_transaction_with_keys(97));
    let result = node.reconcile_file().expect("reconcile");
    assert_eq!(
        result.new_directives, 0,
        "97 body keys + 4 envelope keys is over the cap"
    );
    assert_eq!(result.rejected, 1);

    append(&hand_transaction_with_keys(96));
    let result = node.reconcile_file().expect("reconcile");
    assert_eq!(result.new_directives, 1, "96 + 4 is the cap, inclusive");
    let hand = node
        .dag()
        .directives()
        .into_iter()
        .find(|directive| {
            matches!(directive, Directive::Transaction(txn)
                if txn.narration.as_deref() == Some("keys 96"))
        })
        .expect("adopted")
        .clone();
    assert_eq!(
        hand.metadata().len(),
        100,
        "96 body keys and the full envelope"
    );

    let fresh_path = scratch_ledger("m55-fresh");
    let mut fresh = LedgerService::boot(&fresh_path, "fresh".to_owned()).expect("boot fresh");
    let mut served: Vec<Directive> = node
        .dag()
        .directives()
        .into_iter()
        .filter(|directive| matches!(directive, Directive::Open(_)))
        .cloned()
        .collect();
    served.push(hand);
    for directive in &served {
        let admitted = through_the_wire(directive).expect("every peer accepts what was served");
        fresh
            .stage_remote_directive(admitted)
            .expect("and stages it");
    }
    drop(node);
    drop(fresh);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
}
