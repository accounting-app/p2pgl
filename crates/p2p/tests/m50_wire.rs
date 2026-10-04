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
    // The same string in a body: the number reader refuses it before the cap,
    // and since T83 (L-92) says why instead of "Invalid number".
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
        matches!(error, MergeError::ParseError(ref message)
            if message.contains("30 significant digits")
                && message.contains("at most 7 decimal places")
                && message.contains("(L-92)")),
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
        move |content_id: &str,
              is_transaction: bool,
              parents: &str,
              lamport: &str,
              format: ledger::hash::RecordFormat| {
            signing.sign_in(
                p2p::union_merge::signature_version(format),
                &SignableMessage {
                    content_id,
                    is_transaction,
                    parents,
                    lamport,
                },
            )
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

// ─── A3 (0925 re-audit of T81 (a)+(c)): the legacy ceilings and the as-stored count ───

use ledger::limits::{
    MAX_POSTING_METADATA_KEYS_PER_TRANSACTION, MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY,
};
use ledger::service::{
    enforce_resource_limits, enforce_resource_limits_for, ResourceRule,
    MAX_METADATA_KEYS_PER_DIRECTIVE,
};

/// A signed transfer whose two postings together carry `keys` posting-level
/// metadata keys (split evenly), the shape the legacy ceiling counts.
fn signed_transfer_with_posting_metadata(
    key: &PeerKeySignatureProvider,
    keys: usize,
    lamport: u64,
) -> Directive {
    let Directive::Transaction(mut transaction) = signed_transfer(
        key,
        2,
        &format!("{keys} posting keys"),
        Decimal::from(5),
        "",
        lamport,
    ) else {
        panic!("a transaction")
    };
    for index in 0..keys {
        transaction.postings[index % 2]
            .metadata
            .insert(format!("p{index:04}"), "v".to_owned());
    }
    // Re-sign the edited body.
    let content_id = compute_content_id(&Directive::Transaction(transaction.clone()));
    let lamport = lamport.to_string();
    let signature = key
        .sign(&SignableMessage {
            content_id: &content_id,
            is_transaction: true,
            parents: "",
            lamport: &lamport,
        })
        .expect("signs");
    transaction
        .metadata
        .insert("openledger-signature".to_owned(), signature);
    Directive::Transaction(transaction)
}

/// gl-node's verifier, built from `security::signing::verify_signature`
/// over `MESH_ID` — the check boot and the live reconcile hold a full
/// envelope to (H-20).
fn verifier() -> ledger::service::DirectiveVerifier {
    std::sync::Arc::new(
        move |content_id: &str,
              is_transaction: bool,
              parents: &str,
              lamport: &str,
              author: &str,
              signature: &str,
              format: ledger::hash::RecordFormat| {
            security::signing::verify_signature_in(
                p2p::union_merge::signature_version(format),
                &SignableMessage {
                    content_id,
                    is_transaction,
                    parents,
                    lamport,
                },
                signature,
                author,
                MESH_ID,
            )
            .is_ok()
        },
    )
}

/// A node booted over `path` under `key`'s author id, signing and verifying
/// with it — gl-node's order (`set_signer`, `set_verifier`), before any
/// operator input is finalised.
fn signing_node(path: &PathBuf, key: &std::sync::Arc<PeerKeySignatureProvider>) -> LedgerService {
    let mut node = LedgerService::boot(path, key.public_key_hex()).expect("boot");
    let signing = std::sync::Arc::clone(key);
    node.set_signer(std::sync::Arc::new(
        move |content_id: &str,
              is_transaction: bool,
              parents: &str,
              lamport: &str,
              format: ledger::hash::RecordFormat| {
            signing.sign_in(
                p2p::union_merge::signature_version(format),
                &SignableMessage {
                    content_id,
                    is_transaction,
                    parents,
                    lamport,
                },
            )
        },
    ));
    node.set_verifier(verifier());
    node
}

/// A fresh replica with the two accounts the hand fixtures post to, opened
/// by its own local API so nothing but the record under test can refuse.
fn fresh_with_accounts(label: &str) -> (LedgerService, PathBuf) {
    let path = scratch_ledger(label);
    let mut fresh = LedgerService::boot(&path, "fresh".to_owned()).expect("boot fresh");
    for account in ["Assets:Cash", "Equity:Opening"] {
        fresh
            .open_account(account.to_owned(), date(1), vec![])
            .expect("open");
    }
    (fresh, path)
}

/// A hand-typed `open` with `keys` body metadata keys (M-55, other kinds).
fn hand_open_with_keys(account: &str, keys: usize) -> String {
    let mut block = format!("\n2024-01-20 open {account}\n");
    for index in 0..keys {
        block.push_str(&format!("  k{index:03}: \"v\"\n"));
    }
    block
}

/// A3 (0925), T81 (a) / M-51 decision (6): the posting-metadata legacy
/// ceiling is exact on the wire and at staging, with a real key. 4,096
/// keys cross `validate_supply_entry` + `verify_remote_signature` and stage
/// on a fresh replica; 4,097 are refused for good as a resource limit; and
/// 101 — one past T75's authoring cap — cross and stage while
/// `enforce_resource_limits` (what this node may AUTHOR) still refuses them.
#[test]
fn the_posting_metadata_legacy_ceiling_is_exact_on_the_wire_and_at_staging() {
    let key = key();
    let (mut fresh, path) = fresh_with_accounts("pm-ceiling");

    let at_ceiling = signed_transfer_with_posting_metadata(
        &key,
        MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY,
        3,
    );
    let admitted = through_the_wire(&at_ceiling).expect("4,096 posting keys cross the wire");
    fresh
        .stage_remote_directive(admitted)
        .expect("and stage")
        .expect("new");

    let past_ceiling = signed_transfer_with_posting_metadata(
        &key,
        MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY + 1,
        4,
    );
    let error = through_the_wire(&past_ceiling).expect_err("4,097 posting keys");
    assert!(
        matches!(error, MergeError::ResourceLimitExceeded(ref message)
            if message.contains("Too many posting metadata keys")),
        "{error:?}"
    );
    assert!(
        intake_refusal_is_permanent(&error),
        "cached for good (L-34)"
    );

    let past_authoring = signed_transfer_with_posting_metadata(
        &key,
        MAX_POSTING_METADATA_KEYS_PER_TRANSACTION + 1,
        5,
    );
    assert!(
        enforce_resource_limits(&past_authoring).is_err(),
        "101 posting keys is not something this node may author"
    );
    let admitted = through_the_wire(&past_authoring).expect("but it is history: crosses");
    fresh
        .stage_remote_directive(admitted)
        .expect("and stages (M-51)")
        .expect("new");
    assert!(fresh.contains_directive(&compute_content_id(&at_ceiling)));
    assert!(fresh.contains_directive(&compute_content_id(&past_authoring)));
    assert!(!fresh.contains_directive(&compute_content_id(&past_ceiling)));
    drop(fresh);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// A3 (0925), T81 (c) / M-55 decision (10), the BOOT path with a real key:
/// operator input adopted at boot is counted as it will be stored — four
/// envelope keys on a transaction, three on anything else — so a 96-key
/// hand transaction and a 97-key hand `open` are finalised at exactly
/// `MAX_METADATA_KEYS_PER_DIRECTIVE`, cross the wire signed and stage on a
/// fresh replica, while 97 / 98 are quarantined before anything is stamped.
/// (`a_hand_transaction_adopted_with_a_signer_is_one_every_peer_accepts`
/// pins the live path for a transaction only.)
#[test]
fn hand_input_adopted_at_boot_carries_the_envelope_every_peer_counts() {
    let key = std::sync::Arc::new(key());
    let path = scratch_ledger("m55-boot");
    {
        let mut node = signing_node(&path, &key);
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
        for account in ["Assets:Cash", "Equity:Opening"] {
            node.open_account_signing(
                account.to_owned(),
                date(1),
                vec![],
                sign_open(std::sync::Arc::clone(&key)),
            )
            .expect("open");
        }
    }
    let append = |text: &str| {
        let mut content = std::fs::read_to_string(&path).expect("read");
        content.push_str(text);
        std::fs::write(&path, content).expect("write");
    };
    append(&hand_transaction_with_keys(97));
    append(&hand_transaction_with_keys(96));
    append(&hand_open_with_keys("Assets:NinetyEight", 98));
    append(&hand_open_with_keys("Assets:NinetySeven", 97));

    let mut node = signing_node(&path, &key);
    assert_eq!(node.verify_own_history(), 0, "the node's own opens verify");
    assert_eq!(
        node.finalize_operator_input(),
        2,
        "96-key transaction, 97-key open"
    );
    assert_eq!(
        node.quarantined_count(),
        2,
        "97-key transaction, 98-key open"
    );
    let served: Vec<Directive> = node
        .dag()
        .directives()
        .into_iter()
        .filter(|directive| match directive {
            Directive::Transaction(txn) => txn.narration.as_deref() == Some("keys 96"),
            Directive::Open(open) => open.account == "Assets:NinetySeven",
            _ => false,
        })
        .cloned()
        .collect();
    assert_eq!(served.len(), 2, "{served:?}");
    for directive in &served {
        assert_eq!(
            directive.metadata().len(),
            MAX_METADATA_KEYS_PER_DIRECTIVE,
            "stored at the cap, inclusive: {directive:?}"
        );
        let envelope: Vec<&str> = directive
            .metadata()
            .keys()
            .filter(|key| key.starts_with("openledger-"))
            .map(String::as_str)
            .collect();
        let expected: &[&str] = if matches!(directive, Directive::Transaction(_)) {
            &[
                "openledger-author",
                "openledger-lamport",
                "openledger-parents",
                "openledger-signature",
            ]
        } else {
            &[
                "openledger-author",
                "openledger-lamport",
                "openledger-signature",
            ]
        };
        assert_eq!(envelope, expected);
    }

    let (mut fresh, fresh_path) = fresh_with_accounts("m55-boot-fresh");
    for directive in &served {
        let admitted = through_the_wire(directive).expect("every peer accepts what was served");
        fresh
            .stage_remote_directive(admitted)
            .expect("and stages it")
            .expect("new");
    }
    drop(node);
    drop(fresh);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
}

/// A3 (0925), T81 (a)+(c) on the LIVE reconcile, each envelope shape with a
/// real key: a complete envelope pasted from another node is history and is
/// counted as it arrives — 96 body keys adopt untouched (author kept, 100
/// keys, crosses the wire), 97 are refused under the history rule; a
/// complete-but-unsigned envelope naming THIS node as author is not operator
/// input either (`is_operator_input` is "author or lamport missing"), so the
/// history count passes it at 100 — and the signature check refuses it
/// before `sign_adopted_entry` could carry it to 101. Nothing this node
/// serves is a record a peer counts past the cap.
#[test]
fn a_pasted_complete_envelope_is_counted_as_it_arrives_and_an_unsigned_own_one_is_never_signed_past_the_cap(
) {
    let a = std::sync::Arc::new(key());
    let b = PeerKeySignatureProvider::from_bytes(&[0x51; 32], MESH_ID.to_owned());
    let path = scratch_ledger("m55-live");
    let mut node = signing_node(&path, &a);
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
    for account in ["Assets:Cash", "Equity:Opening"] {
        node.open_account_signing(
            account.to_owned(),
            date(1),
            vec![],
            sign_open(std::sync::Arc::clone(&a)),
        )
        .expect("open");
    }
    let append = |text: &str| {
        let mut content = std::fs::read_to_string(&path).expect("read");
        content.push_str(text);
        std::fs::write(&path, content).expect("write");
    };
    let from_b = |keys: usize, lamport: u64| {
        let Directive::Transaction(mut txn) = signed_transfer(
            &b,
            5,
            &format!("from B {keys}"),
            Decimal::from(5),
            "",
            lamport,
        ) else {
            panic!("a transaction")
        };
        for index in 0..keys {
            txn.metadata.insert(format!("k{index:03}"), "v".to_owned());
        }
        // Body keys are content: re-sign the edited body.
        let unsigned = Transaction {
            metadata: txn
                .metadata
                .iter()
                .filter(|(name, _)| !name.starts_with("openledger-"))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            ..txn.clone()
        };
        let content_id = compute_content_id(&Directive::Transaction(unsigned));
        let lamport = lamport.to_string();
        let signature = b
            .sign(&SignableMessage {
                content_id: &content_id,
                is_transaction: true,
                parents: "",
                lamport: &lamport,
            })
            .expect("signs");
        txn.metadata
            .insert("openledger-signature".to_owned(), signature);
        Directive::Transaction(txn)
    };

    // B's complete envelope, 96 and 97 body keys.
    append(&format!(
        "\n{}",
        ledger::serialize::full_file_serialize(&[from_b(96, 50), from_b(97, 51)], &[])
    ));
    let result = node.reconcile_file().expect("reconcile");
    assert_eq!((result.new_directives, result.rejected), (1, 1));
    let adopted = node
        .dag()
        .directives()
        .into_iter()
        .find(|directive| {
            matches!(directive, Directive::Transaction(txn)
                if txn.narration.as_deref() == Some("from B 96"))
        })
        .expect("96 + 4 adopted")
        .clone();
    assert_eq!(adopted.metadata().len(), MAX_METADATA_KEYS_PER_DIRECTIVE);
    assert_eq!(
        adopted.metadata()["openledger-author"],
        b.public_key_hex(),
        "history is adopted untouched"
    );
    through_the_wire(&adopted).expect("B's record, as adopted, crosses");

    // This node's own author + lamport, no signature, 97 body keys: the
    // history count is 97 + author + lamport + stamped parents = 100.
    let mut own = String::from("\n2024-01-21 * \"Hand\" \"own unsigned\"\n");
    own.push_str(&format!(
        "  openledger-author: \"{}\"\n  openledger-lamport: \"900\"\n",
        a.public_key_hex()
    ));
    for index in 0..97 {
        own.push_str(&format!("  k{index:03}: \"v\"\n"));
    }
    own.push_str("  Assets:Cash                                         5 USD\n");
    own.push_str("  Equity:Opening                                     -5 USD\n");
    append(&own);
    let result = node.reconcile_file().expect("reconcile");
    // T90 / L-126: B's 97-key record is held in the quarantine and kept in the
    // file, as boot keeps it, so this reconcile reads and refuses it again
    // (before T90 the first re-persist deleted it).
    assert_eq!(
        (result.new_directives, result.rejected),
        (0, 2),
        "refused by the signature check (H-20), never signed to 101; B's 97 still held"
    );
    for directive in node.dag().directives() {
        assert!(
            directive.metadata().len() <= MAX_METADATA_KEYS_PER_DIRECTIVE,
            "served past the cap: {directive:?}"
        );
        assert!(
            enforce_resource_limits_for(directive, ResourceRule::History).is_ok(),
            "served but no peer admits it: {directive:?}"
        );
    }
    drop(node);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// A3-1 (0925): the one wire cap T81's history rule leaves out. A signed
/// transaction with 4,000 posting-metadata keys of 300-byte values is inside
/// every §3.12 count under the legacy ceilings and over
/// `MAX_ECONOMIC_BEAN_LENGTH` (1 MiB). Boot applies no body-size cap to
/// history — a T51 decision recorded at `validate_file_ingest_parity` — so
/// the upgraded node serves it and its child; `validate_supply_entry`
/// refuses it for good, and the child waits on `MISSING_PARENT` on every
/// fresh replica: M-51's shape, one cap over, and outside the closure that
/// T81 built for exactly this. Failed at `45014e9` on the first assertion;
/// since T85 (L-101, decision (19)) the body cap seeds boot's closure.
#[test]
fn history_over_the_wire_body_cap_is_never_served_or_always_crosses() {
    let key = key();
    let opening = sign_directive(
        &key,
        Directive::Open(Open {
            date: date(1),
            account: "Equity:Opening".to_owned(),
            currencies: vec![],
            metadata: BTreeMap::new(),
        }),
        1,
    );
    let cash = sign_directive(
        &key,
        Directive::Open(Open {
            date: date(1),
            account: "Assets:Cash".to_owned(),
            currencies: vec![],
            metadata: BTreeMap::new(),
        }),
        2,
    );
    let Directive::Transaction(mut big) = signed_transfer(&key, 2, "big", Decimal::from(5), "", 3)
    else {
        panic!("a transaction")
    };
    for index in 0..4_000 {
        big.postings[0]
            .metadata
            .insert(format!("k{index:04}"), "v".repeat(300));
    }
    let big = {
        let content_id = compute_content_id(&Directive::Transaction(big.clone()));
        let signature = key
            .sign(&SignableMessage {
                content_id: &content_id,
                is_transaction: true,
                parents: "",
                lamport: "3",
            })
            .expect("signs");
        big.metadata
            .insert("openledger-signature".to_owned(), signature);
        Directive::Transaction(big)
    };
    let big_id = compute_content_id(&big);
    assert!(
        ledger::serialize::economic_canonical_serialize(&big).len()
            > ledger::service::MAX_ECONOMIC_BEAN_LENGTH
    );
    assert!(
        enforce_resource_limits_for(&big, ResourceRule::History).is_ok(),
        "inside every count the history rule applies"
    );
    let child = signed_transfer(&key, 3, "child of big", Decimal::from(1), &big_id, 4);

    let path = scratch_ledger("a3-1");
    std::fs::write(
        &path,
        ledger::serialize::full_file_serialize(
            &[opening.clone(), cash.clone(), big.clone(), child.clone()],
            &[],
        ),
    )
    .expect("write");
    let key = std::sync::Arc::new(key);
    let mut upgraded = signing_node(&path, &key);
    assert_eq!(upgraded.verify_own_history(), 0, "signed by this node");

    let served_big = upgraded.contains_directive(&big_id);
    let crosses = through_the_wire(&big).is_ok();
    assert!(
        !served_big || crosses,
        "A3-1: boot serves {big_id} (quarantined: {:?}) but every peer refuses it: {}",
        upgraded.quarantined_ids(),
        through_the_wire(&big)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
    );
    // And what follows it must not be served either.
    let (mut fresh, fresh_path) = fresh_with_accounts("a3-1-fresh");
    let admitted = through_the_wire(&child).expect("the child is inside every cap");
    let stranded = fresh.stage_remote_directive(admitted).is_err();
    assert!(
        !upgraded.contains_directive(&compute_content_id(&child)) || !stranded,
        "the child is served here and stranded on every fresh replica"
    );
    drop(upgraded);
    drop(fresh);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
}

// ─── A2 (0926 re-audit of T85): the closure on the wire, with real keys ─────

/// A signed `open` of `account` on day 1, by `key` at `lamport`.
fn a2_open(key: &PeerKeySignatureProvider, account: &str, lamport: u64) -> Directive {
    sign_directive(
        key,
        Directive::Open(Open {
            date: date(1),
            account: account.to_owned(),
            currencies: vec![],
            metadata: BTreeMap::new(),
        }),
        lamport,
    )
}

/// `directive` with every `openledger-*` key removed — the operator's
/// "strip the envelope lines" edit, which keeps the content id.
fn a2_stripped(directive: &Directive) -> Directive {
    let mut directive = directive.clone();
    let metadata = match &mut directive {
        Directive::Transaction(txn) => &mut txn.metadata,
        Directive::Open(open) => &mut open.metadata,
        _ => panic!("a transaction or an open"),
    };
    metadata.retain(|name, _| !name.starts_with("openledger-"));
    directive
}

/// What `stage_remote_directive` made of `directive` after the real wire
/// validators: `"OK"`, `"WIRE_REFUSED"` or the staging error code.
fn a2_offer(node: &mut LedgerService, directive: &Directive) -> &'static str {
    match through_the_wire(directive) {
        Ok(admitted) => match node.stage_remote_directive(admitted) {
            Ok(_) => "OK",
            Err(error) => error.error_code(),
        },
        Err(_) => "WIRE_REFUSED",
    }
}

fn a2_served_transaction(node: &LedgerService, id: &str) -> Directive {
    node.get_directive(id)
        .unwrap_or_else(|| panic!("{id} is served"))
        .clone()
}

/// A2-1 (0926), T85 (b) × the README's own remedy: a pre-T65 mesh replicated
/// `X` (5 × 10^22, past the amount cap), its child `C` and grandchild `G` to
/// every node, so after the upgrade every node's closure holds `C` and `G`.
/// On node A the operator follows §Upgrading — restates `X` in a larger unit
/// (a new id) and "restates the chain" by stripping `C`'s and `G`'s
/// `openledger-*` lines — so A re-adopts both under their SAME content ids
/// (the id covers the body only) with parents it serves, signs them, and a
/// fresh replica stages all three. Node B holds the old copies in its
/// closure and T85's wire check refuses by content id, permanently
/// (`INVALID_INPUT`, cached per `(peer, id)` in gl-node), whatever the
/// offered copy's parents: B keeps `X2` and never `C`/`G`, across restarts —
/// two honest replicas with the same available set, different ledgers,
/// forever. Before T85 B adopted A's copies and the quarantine healed
/// (`live_quarantine`'s "a peer serving the same economic body").
#[test]
fn a2_a_restated_chain_reaches_every_node_that_held_the_old_one() {
    let author = std::sync::Arc::new(key());
    let over = Decimal::from_str_exact("50000000000000000000000").expect("5 × 10^22");
    let opening = a2_open(&author, "Equity:Opening", 1);
    let cash = a2_open(&author, "Assets:Cash", 2);
    let x = signed_transfer(&author, 2, "X pre-upgrade", over, "", 3);
    let x_id = compute_content_id(&x);
    let c = signed_transfer(&author, 3, "C child", Decimal::from(5), &x_id, 4);
    let c_id = compute_content_id(&c);
    let g = signed_transfer(&author, 4, "G grandchild", Decimal::from(9), &c_id, 5);
    let g_id = compute_content_id(&g);
    let history = ledger::serialize::full_file_serialize(
        &[
            opening.clone(),
            cash.clone(),
            x.clone(),
            c.clone(),
            g.clone(),
        ],
        &[],
    );

    // Node B: the upgraded copy of that history, untouched.
    let b_key = std::sync::Arc::new(PeerKeySignatureProvider::from_bytes(
        &[0x52; 32],
        MESH_ID.to_owned(),
    ));
    let b_path = scratch_ledger("a2-1-b");
    std::fs::write(&b_path, &history).expect("write");
    let mut b = signing_node(&b_path, &b_key);
    b.verify_own_history();
    b.finalize_operator_input();
    let held: Vec<&str> = b.quarantined_ids();
    assert!(
        held.contains(&c_id.as_str()) && held.contains(&g_id.as_str()),
        "premise: B's closure holds C and G ({held:?})"
    );

    // Node A: the operator's §Upgrading remedy, stop → edit → start.
    let x2 = {
        let Directive::Transaction(mut txn) = a2_stripped(&x) else {
            unreachable!()
        };
        for posting in &mut txn.postings {
            let amount = posting.amount.as_mut().expect("explicit");
            amount.number /= Decimal::from_str_exact("1000000000000000000000").expect("10^21");
        }
        Directive::Transaction(txn)
    };
    let x2_id = compute_content_id(&x2);
    let a_path = scratch_ledger("a2-1-a");
    std::fs::write(
        &a_path,
        ledger::serialize::full_file_serialize(
            &[
                opening.clone(),
                cash.clone(),
                x2,
                a2_stripped(&c),
                a2_stripped(&g),
            ],
            &[],
        ),
    )
    .expect("write");
    let mut a = signing_node(&a_path, &author);
    a.verify_own_history();
    assert_eq!(a.finalize_operator_input(), 3, "X2, C and G re-adopted");
    let served: Vec<Directive> = [&x2_id, &c_id, &g_id]
        .into_iter()
        .map(|id| a2_served_transaction(&a, id))
        .collect();

    // A fresh replica takes A's whole restated chain …
    let (mut fresh, fresh_path) = fresh_with_accounts("a2-1-fresh");
    let fresh_codes: Vec<&str> = served
        .iter()
        .map(|directive| a2_offer(&mut fresh, directive))
        .collect();
    assert_eq!(
        fresh_codes,
        vec!["OK", "OK", "OK"],
        "premise: a fresh replica"
    );

    // … and so must B, which holds the same available set.
    let b_codes: Vec<&str> = served
        .iter()
        .map(|directive| a2_offer(&mut b, directive))
        .collect();
    b.compact().expect("compact");
    drop(b);
    let mut b = signing_node(&b_path, &b_key);
    b.verify_own_history();
    b.finalize_operator_input();
    let after_restart: Vec<&str> = served
        .iter()
        .map(|directive| a2_offer(&mut b, directive))
        .collect();
    assert!(
        b.contains_directive(&c_id) && b.contains_directive(&g_id),
        "A2-1: B staged {b_codes:?}, after a restart {after_restart:?}; A and a fresh \
         replica serve C and G, B never will"
    );
    drop((a, b, fresh));
    for path in [&a_path, &b_path, &fresh_path] {
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
}

/// `txn`'s body re-signed by `key` at `lamport` naming `parents` (a body
/// edit changes the content id, so the old signature is void).
fn a2_resigned(
    key: &PeerKeySignatureProvider,
    txn: Transaction,
    parents: &str,
    lamport: u64,
) -> Directive {
    let Directive::Transaction(mut txn) = a2_stripped(&Directive::Transaction(txn)) else {
        unreachable!()
    };
    let content_id = compute_content_id(&Directive::Transaction(txn.clone()));
    let lamport = lamport.to_string();
    let signature = key
        .sign(&SignableMessage {
            content_id: &content_id,
            is_transaction: true,
            parents,
            lamport: &lamport,
        })
        .expect("signs");
    for (name, value) in [
        ("openledger-author", key.public_key_hex()),
        ("openledger-lamport", lamport),
        ("openledger-parents", parents.to_owned()),
        ("openledger-signature", signature),
    ] {
        txn.metadata.insert(name.to_owned(), value);
    }
    Directive::Transaction(txn)
}

fn a2_sign_open_with(
    key: std::sync::Arc<PeerKeySignatureProvider>,
) -> impl Fn(&str, &str, &str) -> Option<String> {
    move |content_id: &str, parents: &str, lamport: &str| {
        key.sign(&SignableMessage {
            content_id,
            is_transaction: false,
            parents,
            lamport,
        })
    }
}

/// A signing node under `key` with `Assets:Cash` and `Equity:Opening` opened
/// through its own API, compacted, so the next reconcile reads only what a
/// test appends.
fn a2_node_with_accounts(
    label: &str,
    key: &std::sync::Arc<PeerKeySignatureProvider>,
) -> (LedgerService, PathBuf) {
    let path = scratch_ledger(label);
    let mut node = signing_node(&path, key);
    for account in ["Assets:Cash", "Equity:Opening"] {
        node.open_account_signing(
            account.to_owned(),
            date(1),
            vec![],
            a2_sign_open_with(std::sync::Arc::clone(key)),
        )
        .expect("open");
    }
    node.compact().expect("compact");
    (node, path)
}

fn a2_append(path: &PathBuf, directives: &[Directive]) {
    let mut content = std::fs::read_to_string(path).expect("read");
    content.push('\n');
    content.push_str(&ledger::serialize::full_file_serialize(directives, &[]));
    std::fs::write(path, content).expect("write");
}

/// gl-node's boot order over `path`: boot, signer, verifier, finalise.
fn a2_restart(path: &PathBuf, key: &std::sync::Arc<PeerKeySignatureProvider>) -> LedgerService {
    let mut node = signing_node(path, key);
    node.verify_own_history();
    node.finalize_operator_input();
    node
}

/// A2 (0926), T85 (b)+(c) through the real wire validators with real keys:
/// a history record over the 1 MiB body cap (`S`, inside every count), its
/// child `C` and grandchild `G`. The node that holds them boots with all
/// three quarantined (L-101's seed and the closure); `S` is refused on the
/// wire for good (`ResourceLimitExceeded`), `C` and `G` cross
/// `validate_supply_entry` + `verify_remote_signature` and are refused at
/// staging as `INVALID_INPUT` — permanent in gl-node's
/// `stage_refusal_is_permanent` — before and after a restart; a fresh
/// replica, which never has `S`, holds neither (`MISSING_PARENT`, retried
/// for ever). So the permanent verdict agrees with every replica that lacks
/// the seed; an unrelated record by the same author stages on both.
#[test]
fn a2_the_closure_is_refused_on_the_wire_where_no_fresh_replica_could_hold_it_either() {
    let author = std::sync::Arc::new(key());
    let Directive::Transaction(mut big) =
        signed_transfer(&author, 2, "big", Decimal::from(5), "", 3)
    else {
        unreachable!()
    };
    for index in 0..4_000 {
        big.postings[0]
            .metadata
            .insert(format!("k{index:04}"), "v".repeat(300));
    }
    let s = a2_resigned(&author, big, "", 3);
    let s_id = compute_content_id(&s);
    assert!(enforce_resource_limits_for(&s, ResourceRule::History).is_ok());
    let c = signed_transfer(&author, 3, "C child", Decimal::from(1), &s_id, 4);
    let c_id = compute_content_id(&c);
    let g = signed_transfer(&author, 4, "G grandchild", Decimal::from(2), &c_id, 5);
    let unrelated = signed_transfer(&author, 5, "unrelated", Decimal::from(3), "", 6);

    let error = through_the_wire(&s).expect_err("over the body cap");
    assert!(
        matches!(error, MergeError::ResourceLimitExceeded(_)),
        "{error:?}"
    );
    assert!(intake_refusal_is_permanent(&error));

    let path = scratch_ledger("a2-closure-wire");
    std::fs::write(
        &path,
        ledger::serialize::full_file_serialize(
            &[
                a2_open(&author, "Equity:Opening", 1),
                a2_open(&author, "Assets:Cash", 2),
                s.clone(),
                c.clone(),
                g.clone(),
            ],
            &[],
        ),
    )
    .expect("write");
    let mut holder = a2_restart(&path, &author);
    for id in [&s_id, &c_id, &compute_content_id(&g)] {
        assert!(!holder.contains_directive(id), "{id} is not served");
        assert!(holder.quarantined_ids().contains(&id.as_str()), "{id} held");
    }
    let (mut fresh, fresh_path) = fresh_with_accounts("a2-closure-wire-fresh");
    for round in ["first boot", "after a restart"] {
        let codes: Vec<&str> = [&c, &g, &unrelated]
            .into_iter()
            .map(|directive| a2_offer(&mut holder, directive))
            .collect();
        assert_eq!(
            codes,
            vec!["INVALID_INPUT", "INVALID_INPUT", "OK"],
            "{round}: the closure refused permanently, the unrelated record staged"
        );
        holder.compact().expect("compact");
        drop(holder);
        holder = a2_restart(&path, &author);
    }
    let codes: Vec<&str> = [&c, &g, &unrelated]
        .into_iter()
        .map(|directive| a2_offer(&mut fresh, directive))
        .collect();
    assert_eq!(
        codes,
        vec!["MISSING_PARENT", "MISSING_PARENT", "OK"],
        "a fresh replica never holds C or G either"
    );
    drop((holder, fresh));
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
}

/// A2 (0926), T85's live hold with real keys: `D`, another node's
/// correctly signed record naming `Q`, pasted under a running node that
/// lacks `Q`. The live reconcile holds `D` (not served, kept in the file by
/// the re-persist) exactly as a boot over the same bytes does; `Q` then
/// arrives on the wire and `D` stays held until a peer's copy of it arrives
/// too, which stages and leaves the quarantine; a restart serves both, with
/// nothing held. Nothing served ever names a parent this node lacks.
#[test]
fn a2_a_pasted_record_whose_parent_is_absent_is_held_live_as_at_boot_and_returns_from_a_peer() {
    let a = std::sync::Arc::new(key());
    let b = PeerKeySignatureProvider::from_bytes(&[0x51; 32], MESH_ID.to_owned());
    let q = signed_transfer(&b, 6, "Q parent", Decimal::from(4), "", 50);
    let q_id = compute_content_id(&q);
    let d = signed_transfer(&b, 7, "D names Q", Decimal::from(1), &q_id, 51);
    let d_id = compute_content_id(&d);

    let (mut live, live_path) = a2_node_with_accounts("a2-hold-live", &a);
    let (booted, boot_path) = a2_node_with_accounts("a2-hold-boot", &a);
    drop(booted);
    a2_append(&live_path, std::slice::from_ref(&d));
    a2_append(&boot_path, std::slice::from_ref(&d));
    let result = live.reconcile_file().expect("reconcile");
    assert_eq!((result.new_directives, result.rejected), (0, 1));
    let booted = a2_restart(&boot_path, &a);
    for (label, node) in [("live", &live), ("boot", &booted)] {
        assert!(!node.contains_directive(&d_id), "{label}: D is not served");
        assert_eq!(node.quarantined_ids(), vec![d_id.as_str()], "{label}");
    }
    live.compact().expect("compact");
    assert!(
        std::fs::read_to_string(&live_path)
            .expect("read")
            .contains("D names Q"),
        "the re-persist keeps the held record in the file"
    );

    assert_eq!(a2_offer(&mut live, &q), "OK");
    assert!(
        !live.contains_directive(&d_id),
        "held until a peer's copy arrives (the stated residual)"
    );
    assert_eq!(a2_offer(&mut live, &d), "OK");
    assert!(live.contains_directive(&d_id) && live.quarantined_ids().is_empty());
    live.compact().expect("compact");
    drop((live, booted));
    let restarted = a2_restart(&live_path, &a);
    assert!(restarted.contains_directive(&q_id) && restarted.contains_directive(&d_id));
    assert!(restarted.quarantined_ids().is_empty());
    drop(restarted);
    for path in [&live_path, &boot_path] {
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
}

/// A2 (0926), T85's `reconcile_batch_ids` with real keys: `C` is dated
/// before its parent `P` and both are pasted together, so the canonical
/// (date) order adopts `C` first while `P` is still absent. A parent later
/// in the same file counts as present, so both are adopted and served; a
/// fresh replica stages both (parent first), and a restart serves the same
/// set with nothing held.
#[test]
fn a2_a_pasted_child_dated_before_its_pasted_parent_is_adopted_with_it() {
    let a = std::sync::Arc::new(key());
    let b = PeerKeySignatureProvider::from_bytes(&[0x51; 32], MESH_ID.to_owned());
    let p = signed_transfer(&b, 9, "P later-dated parent", Decimal::from(4), "", 60);
    let p_id = compute_content_id(&p);
    let c = signed_transfer(&b, 8, "C earlier-dated child", Decimal::from(1), &p_id, 61);
    let c_id = compute_content_id(&c);
    let (mut node, path) = a2_node_with_accounts("a2-batch-forward", &a);
    a2_append(&path, &[c.clone(), p.clone()]);
    let result = node.reconcile_file().expect("reconcile");
    assert_eq!((result.new_directives, result.rejected), (2, 0));
    assert!(node.contains_directive(&p_id) && node.contains_directive(&c_id));
    let (mut fresh, fresh_path) = fresh_with_accounts("a2-batch-forward-fresh");
    assert_eq!(
        [&p, &c].map(|directive| a2_offer(&mut fresh, directive)),
        ["OK", "OK"]
    );
    node.compact().expect("compact");
    drop(node);
    let restarted = a2_restart(&path, &a);
    assert!(restarted.contains_directive(&p_id) && restarted.contains_directive(&c_id));
    assert!(restarted.quarantined_ids().is_empty());
    drop((restarted, fresh));
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
}

/// Another node's correctly signed transaction on `Assets:Nowhere` (an
/// account no node opened), dated day 5 — every peer refuses it
/// (`ACCOUNT_NOT_OPEN`) — and its child dated day 4, as pasted together.
fn a2_unadmitted_parent_and_child(b: &PeerKeySignatureProvider) -> (Directive, Directive) {
    let Directive::Transaction(mut txn) =
        signed_transfer(b, 5, "P on nowhere", Decimal::from(3), "", 40)
    else {
        unreachable!()
    };
    txn.postings[0].account = "Assets:Nowhere".to_owned();
    let p = a2_resigned(b, txn, "", 40);
    let child = signed_transfer(
        b,
        4,
        "C names P",
        Decimal::from(2),
        &compute_content_id(&p),
        41,
    );
    (p, child)
}

/// A2 (0926), T85's post-loop rule with real keys: the pasted `C` is
/// adopted on the strength of its parent `P` being later in the same file,
/// and `P` is then refused (`ACCOUNT_NOT_OPEN`). `C` must not stay served
/// naming a parent no one holds: the rule after the loop holds it, and a
/// boot over the same bytes serves the same set (neither).
#[test]
fn a2_a_pasted_child_of_a_later_pasted_parent_the_accounts_refuse_is_held_live_as_at_boot() {
    let a = std::sync::Arc::new(key());
    let b = PeerKeySignatureProvider::from_bytes(&[0x51; 32], MESH_ID.to_owned());
    let (p, c) = a2_unadmitted_parent_and_child(&b);
    let (p_id, c_id) = (compute_content_id(&p), compute_content_id(&c));
    let (mut live, live_path) = a2_node_with_accounts("a2-post-loop-live", &a);
    let (booted, boot_path) = a2_node_with_accounts("a2-post-loop-boot", &a);
    drop(booted);
    a2_append(&live_path, &[p.clone(), c.clone()]);
    a2_append(&boot_path, &[p.clone(), c.clone()]);
    live.reconcile_file().expect("reconcile");
    let booted = a2_restart(&boot_path, &a);
    for (label, node) in [("live", &live), ("boot", &booted)] {
        assert!(
            !node.contains_directive(&p_id) && !node.contains_directive(&c_id),
            "{label}: neither is served"
        );
        for directive in node.dag().directives() {
            if let Directive::Transaction(txn) = directive {
                for parent in txn.parent_ids() {
                    assert!(
                        node.contains_directive(parent),
                        "{label}: dangling {parent}"
                    );
                }
            }
        }
    }
    drop((live, booted));
    for path in [&live_path, &boot_path] {
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
}

/// A2-3 (0926): the same pasted bytes, two fates in the FILE. Boot loads
/// `P` (a peer's record the accounts do not admit) and T84's rule holds it —
/// quarantined, kept in the file. The live reconcile refuses it inside
/// `adopt_file_directive` (`validate_transaction`), outside the quarantine,
/// so the canonical re-persist deletes it ("NOT adopted and the canonical
/// re-persist will drop them"), while it keeps `C`, which T85's hold put in
/// the quarantine. T85's hold covers the missing-parent arm only; T89
/// (L-109) closed this class for stray envelope keys.
#[test]
fn a2_the_live_reconcile_keeps_in_the_file_what_boot_keeps() {
    let a = std::sync::Arc::new(key());
    let b = PeerKeySignatureProvider::from_bytes(&[0x51; 32], MESH_ID.to_owned());
    let (p, c) = a2_unadmitted_parent_and_child(&b);
    let mut kept = Vec::new();
    for label in ["live", "boot"] {
        let (mut node, path) = a2_node_with_accounts(&format!("a2-3-{label}"), &a);
        if label == "boot" {
            drop(node);
            a2_append(&path, &[p.clone(), c.clone()]);
            node = a2_restart(&path, &a);
        } else {
            a2_append(&path, &[p.clone(), c.clone()]);
            node.reconcile_file().expect("reconcile");
        }
        node.compact().expect("compact");
        let text = std::fs::read_to_string(&path).expect("read");
        kept.push((
            label,
            text.contains("P on nowhere"),
            text.contains("C names P"),
        ));
        drop(node);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
    assert_eq!(
        kept,
        vec![("live", true, true), ("boot", true, true)],
        "A2-3: (path, file keeps P, file keeps C)"
    );
}

/// A2-1 (0926), the single-node shape of the same fault: the operator
/// re-enters a transaction the closure holds (`C`, child of the pre-T65
/// `X`) through the API — same body, so the same content id — and writes
/// `Y` on top. Both are signed, served and acknowledged; both go to the
/// journal. The node then stops without its stop compaction (a crash), and
/// boot reads the canonical file's quarantined `C` (parent `X`) before the
/// journal's `C` (parents it serves): the closure takes `C` by id and `Y`
/// as its child, so neither is served — and T85's wire check then refuses
/// the node's OWN copies of `C` and `Y` from every peer that adopted them,
/// for good, and with them everything the mesh writes on top.
#[test]
fn a2_a_record_reentered_through_the_api_returns_from_a_peer_after_a_crash() {
    use ledger::service::{PostingInput, TransactionInput};
    let author = std::sync::Arc::new(key());
    let over = Decimal::from_str_exact("50000000000000000000000").expect("5 × 10^22");
    let x = signed_transfer(&author, 2, "X pre-upgrade", over, "", 3);
    let c = signed_transfer(
        &author,
        3,
        "C child",
        Decimal::from(5),
        &compute_content_id(&x),
        4,
    );
    let c_id = compute_content_id(&c);
    // Past `COMPACTION_MIN_CANONICAL_BYTES`, so a write appends to the journal.
    let Directive::Transaction(mut padding) =
        signed_transfer(&author, 1, "padding", Decimal::from(1), "", 5)
    else {
        unreachable!()
    };
    for index in 0..100 {
        padding.postings[0]
            .metadata
            .insert(format!("k{index:03}"), "v".repeat(800));
    }
    let padding = a2_resigned(&author, padding, "", 5);
    let path = scratch_ledger("a2-1-api");
    std::fs::write(
        &path,
        ledger::serialize::full_file_serialize(
            &[
                a2_open(&author, "Equity:Opening", 1),
                a2_open(&author, "Assets:Cash", 2),
                padding,
                x,
                c,
            ],
            &[],
        ),
    )
    .expect("write");
    let mut node = a2_restart(&path, &author);
    node.compact().expect("the startup compaction");
    assert!(node.quarantined_ids().contains(&c_id.as_str()), "premise");

    let signing = std::sync::Arc::clone(&author);
    let sign = move |content_id: &str, parents: &str, lamport: &str| {
        signing.sign(&SignableMessage {
            content_id,
            is_transaction: true,
            parents,
            lamport,
        })
    };
    let input = |day: u32, narration: &str, amount: i64| TransactionInput {
        date: date(day),
        flag: Flag::Complete,
        payee: None,
        narration: Some(narration.to_owned()),
        tags: vec![],
        links: vec![],
        postings: ["Assets:Cash", "Equity:Opening"]
            .into_iter()
            .zip([amount, -amount])
            .map(|(account, number)| PostingInput {
                account: account.to_owned(),
                amount: Some(usd(Decimal::from(number))),
                cost: None,
                price: None,
            })
            .collect(),
    };
    node.append_transaction_signing(input(5, "warm-up", 1), sign.clone())
        .expect("the first write compacts");
    let reentered = node
        .append_transaction_signing(input(3, "C child", 5), sign.clone())
        .expect("re-entered");
    assert_eq!(reentered.txid, c_id, "the same body, the same id");
    let y = node
        .append_transaction_signing(input(6, "Y after", 7), sign)
        .expect("Y");
    assert!(
        node.journal_bytes() > 0,
        "premise: both are journal records"
    );
    let served: Vec<Directive> = [&c_id, &y.txid]
        .into_iter()
        .map(|id| a2_served_transaction(&node, id))
        .collect();
    drop(node); // no stop compaction

    let mut node = a2_restart(&path, &author);
    let back: Vec<&str> = served
        .iter()
        .map(|directive| a2_offer(&mut node, directive))
        .collect();
    assert!(
        node.contains_directive(&c_id) && node.contains_directive(&y.txid),
        "A2-1: after the crash the node serves neither its C nor its Y, held {:?}, and \
         refuses a peer's copies: {back:?}",
        node.quarantined_ids()
    );
    drop(node);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// T90 / H-24 (b), decision (36): the same crash, and no peer at all. The
/// canonical file holds `C` as the closure held it (parent `X`, a record past
/// the amount cap), the journal holds `C` as the API re-entered it (parents
/// this node serves) and `Y` on top. Boot meets two copies of one body and,
/// since T90, serves the one whose parents it holds — before the closure is
/// walked — so the node's own acknowledged `C` and `Y` are served straight
/// after the restart, with P2P off.
///
/// Bug-catch: drop `prefer_copies_whose_parents_are_served` and boot keeps
/// the file's copy: the closure takes `C` by its parent and `Y` as its child.
#[test]
fn h24_after_a_crash_the_node_serves_its_re_entered_record_and_what_it_wrote_on_top() {
    use ledger::service::{PostingInput, TransactionInput};
    let author = std::sync::Arc::new(key());
    let over = Decimal::from_str_exact("50000000000000000000000").expect("5 × 10^22");
    let x = signed_transfer(&author, 2, "X pre-upgrade", over, "", 3);
    let c = signed_transfer(
        &author,
        3,
        "C child",
        Decimal::from(5),
        &compute_content_id(&x),
        4,
    );
    let c_id = compute_content_id(&c);
    // Past `COMPACTION_MIN_CANONICAL_BYTES`, so a write appends to the journal.
    let Directive::Transaction(mut padding) =
        signed_transfer(&author, 1, "padding", Decimal::from(1), "", 5)
    else {
        unreachable!()
    };
    for index in 0..100 {
        padding.postings[0]
            .metadata
            .insert(format!("k{index:03}"), "v".repeat(800));
    }
    let padding = a2_resigned(&author, padding, "", 5);
    let path = scratch_ledger("a2-1-api");
    std::fs::write(
        &path,
        ledger::serialize::full_file_serialize(
            &[
                a2_open(&author, "Equity:Opening", 1),
                a2_open(&author, "Assets:Cash", 2),
                padding,
                x,
                c,
            ],
            &[],
        ),
    )
    .expect("write");
    let mut node = a2_restart(&path, &author);
    node.compact().expect("the startup compaction");
    assert!(node.quarantined_ids().contains(&c_id.as_str()), "premise");

    let signing = std::sync::Arc::clone(&author);
    let sign = move |content_id: &str, parents: &str, lamport: &str| {
        signing.sign(&SignableMessage {
            content_id,
            is_transaction: true,
            parents,
            lamport,
        })
    };
    let input = |day: u32, narration: &str, amount: i64| TransactionInput {
        date: date(day),
        flag: Flag::Complete,
        payee: None,
        narration: Some(narration.to_owned()),
        tags: vec![],
        links: vec![],
        postings: ["Assets:Cash", "Equity:Opening"]
            .into_iter()
            .zip([amount, -amount])
            .map(|(account, number)| PostingInput {
                account: account.to_owned(),
                amount: Some(usd(Decimal::from(number))),
                cost: None,
                price: None,
            })
            .collect(),
    };
    node.append_transaction_signing(input(5, "warm-up", 1), sign.clone())
        .expect("the first write compacts");
    let reentered = node
        .append_transaction_signing(input(3, "C child", 5), sign.clone())
        .expect("re-entered");
    assert_eq!(reentered.txid, c_id, "the same body, the same id");
    let y = node
        .append_transaction_signing(input(6, "Y after", 7), sign)
        .expect("Y");
    assert!(
        node.journal_bytes() > 0,
        "premise: both are journal records"
    );
    drop(node); // no stop compaction

    let mut node = a2_restart(&path, &author);
    assert!(
        node.contains_directive(&c_id) && node.contains_directive(&y.txid),
        "H-24 (b): after the crash C served {}, Y served {}, held {:?}",
        node.contains_directive(&c_id),
        node.contains_directive(&y.txid),
        node.quarantined_ids()
    );
    let Some(Directive::Transaction(c_served)) = node.get_directive(&c_id).cloned() else {
        panic!("C is served as a transaction");
    };
    assert!(
        c_served
            .parent_ids()
            .into_iter()
            .all(|parent| node.contains_directive(parent)),
        "the served copy of C names only parents this node serves"
    );
    node.compact().expect("compaction");
    drop(node);
    let node = a2_restart(&path, &author);
    assert!(
        node.contains_directive(&c_id) && node.contains_directive(&y.txid),
        "a fixed point across the next restart"
    );
    drop(node);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// A2-2 (0926), T85 (d) / L-110 followed as its own WARN says, under the
/// running node that printed it: this node's `open Expenses:Food` had only
/// its `openledger-lamport` edited, so boot holds it (H-20). A hand `open`
/// is refused live with "restore that record … by deleting its
/// openledger-* lines if only its envelope was edited". Doing exactly that
/// gives an operator-input `open` with the held record's content id; the
/// clause finds the held copy — the same record — and refuses it again, and
/// since the id is in the quarantine the reconcile logs that it "writes
/// them back unchanged": the compaction writes back the EDITED envelope
/// over the operator's repair, and the next boot holds it again. The
/// account stays unopened until the operator repeats the edit with the node
/// stopped.
#[test]
fn a2_the_l110_remedy_followed_under_a_running_node_opens_the_account() {
    let a = std::sync::Arc::new(key());
    let (mut node, path) = a2_node_with_accounts("a2-2", &a);
    node.open_account_signing(
        "Expenses:Food".to_owned(),
        date(1),
        vec![],
        a2_sign_open_with(std::sync::Arc::clone(&a)),
    )
    .expect("open");
    node.compact().expect("compact");
    drop(node);
    let edit_food_block = |edit: &dyn Fn(&str) -> Option<String>| {
        let text = std::fs::read_to_string(&path).expect("read");
        let mut in_food = false;
        let mut out = Vec::new();
        for line in text.lines() {
            if !line.starts_with(' ') {
                in_food = line == "2024-01-01 open Expenses:Food";
            }
            match (in_food, edit(line)) {
                (true, Some(replacement)) => out.push(replacement),
                (true, None) => {}
                (false, _) => out.push(line.to_owned()),
            }
        }
        std::fs::write(&path, out.join("\n") + "\n").expect("write");
    };
    edit_food_block(&|line| {
        Some(if line.contains("openledger-lamport") {
            "  openledger-lamport: \"99\"".to_owned()
        } else {
            line.to_owned()
        })
    });
    let mut node = a2_restart(&path, &a);
    node.compact().expect("the startup compaction");
    assert!(!node.accounts().is_open("Expenses:Food"), "premise: held");

    // The remedy for an envelope-only edit, as the WARN words it: strip the
    // envelope. (T92, decision (42) as revised 2026-09-26: the hand `open`
    // this test first typed — refused live by L-110 before T92 — is now
    // adopted, see `l121_…`; the strip is exercised on its own here.)
    edit_food_block(&|line| (!line.contains("openledger-")).then(|| line.to_owned()));
    node.reconcile_file().expect("reconcile");
    let live = node.accounts().is_open("Expenses:Food");
    node.compact().expect("compact");
    let reverted = std::fs::read_to_string(&path)
        .expect("read")
        .contains("openledger-lamport: \"99\"");
    drop(node);
    let restarted = a2_restart(&path, &a);
    assert!(
        live && restarted.accounts().is_open("Expenses:Food"),
        "A2-2: open live {live}, the compaction wrote the edited envelope back {reverted}, \
         open after a restart {}",
        restarted.accounts().is_open("Expenses:Food")
    );
    drop(restarted);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// A2-4 (0926), T84's rule × T85's post-loop call × the wire: every node
/// serves `T1` (USD on `Assets:Cash`, day 5). An allowlisted peer then
/// serves a second, correctly signed `open Assets:Cash EUR` dated day 3;
/// the wire accepts it (a peer's `open` joins the lifecycle at its own
/// date, M-09). From then on the accounts this node serves no longer admit
/// `T1` — so the next live reconcile (any hand edit) and every later boot
/// quarantine `T1` and everything that descends from it, the operator's
/// fresh hand line included: one peer directive un-serves history every
/// replica already holds, on every replica, and every write after it.
#[test]
fn a2_a_peer_open_never_unserves_history_this_node_already_serves() {
    let a = std::sync::Arc::new(key());
    let b = PeerKeySignatureProvider::from_bytes(&[0x51; 32], MESH_ID.to_owned());
    let (mut node, path) = a2_node_with_accounts("a2-4", &a);
    let t1 = signed_transfer(&b, 5, "T1 USD", Decimal::from(5), "", 10);
    let t1_id = compute_content_id(&t1);
    assert_eq!(a2_offer(&mut node, &t1), "OK");
    let second_open = sign_directive(
        &b,
        Directive::Open(Open {
            date: date(3),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["EUR".to_owned()],
            metadata: BTreeMap::new(),
        }),
        11,
    );
    assert_eq!(a2_offer(&mut node, &second_open), "OK", "premise: accepted");
    node.compact().expect("compact");
    let mut text = std::fs::read_to_string(&path).expect("read");
    text.push_str("\n2024-01-20 * \"hand\"\n  Assets:Cash  1 EUR\n  Equity:Opening  -1 EUR\n");
    std::fs::write(&path, text).expect("write");
    node.reconcile_file().expect("reconcile");
    let served_live = node.contains_directive(&t1_id);
    let held_live = node.quarantined_ids().len();
    node.compact().expect("compact");
    drop(node);
    let restarted = a2_restart(&path, &a);
    assert!(
        served_live && restarted.contains_directive(&t1_id),
        "A2-4: T1 served after the live reconcile {served_live} ({held_live} held), after a \
         restart {} (held {:?})",
        restarted.contains_directive(&t1_id),
        restarted.quarantined_ids()
    );
    drop(restarted);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// A2 (0926), T85's stated residual re-checked: "`close_account`'s own
/// body-size check is now unreachable through any public path". It is
/// reachable: account names have no length cap, and a `close` body spells
/// `close` where the `open` spells `open` — one byte longer. An `open` with
/// no currencies whose body is exactly `MAX_ECONOMIC_BEAN_LENGTH` is
/// authored, crosses the wire signed and stages on a peer; its `close` is
/// one byte over, so `close_account` refuses it on that size check without
/// moving the clock, and the wire refuses a peer's copy for good — the
/// account can never be closed anywhere.
#[test]
fn a2_close_accounts_size_check_is_reachable_through_an_open_at_the_cap() {
    use ledger::model::Close;
    use ledger::serialize::economic_canonical_serialize;
    use ledger::service::MAX_ECONOMIC_BEAN_LENGTH;
    let open_of = |account: &str| {
        Directive::Open(Open {
            date: date(1),
            account: account.to_owned(),
            currencies: vec![],
            metadata: BTreeMap::new(),
        })
    };
    let probe = economic_canonical_serialize(&open_of("Assets:A")).len();
    let account = format!("Assets:A{}", "a".repeat(MAX_ECONOMIC_BEAN_LENGTH - probe));
    assert_eq!(
        economic_canonical_serialize(&open_of(&account)).len(),
        MAX_ECONOMIC_BEAN_LENGTH,
        "premise: the open is exactly at the cap"
    );
    let close = Directive::Close(Close {
        date: date(2),
        account: account.clone(),
        metadata: BTreeMap::new(),
    });
    assert_eq!(
        economic_canonical_serialize(&close).len(),
        MAX_ECONOMIC_BEAN_LENGTH + 1
    );

    let author = std::sync::Arc::new(key());
    let path = scratch_ledger("a2-close-cap");
    let mut node = signing_node(&path, &author);
    node.open_account_signing(
        account.clone(),
        date(1),
        vec![],
        a2_sign_open_with(std::sync::Arc::clone(&author)),
    )
    .expect("an open at the cap is authored");
    let served_open = node
        .dag()
        .directives()
        .into_iter()
        .find(|directive| matches!(directive, Directive::Open(_)))
        .expect("served")
        .clone();
    let (mut fresh, fresh_path) = fresh_with_accounts("a2-close-cap-fresh");
    assert_eq!(a2_offer(&mut fresh, &served_open), "OK", "and replicates");

    let clock = node.lamport_clock();
    let error = node
        .close_account(account.clone(), date(2))
        .expect_err("one byte over");
    assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED", "{error}");
    assert_eq!(node.lamport_clock(), clock, "refused before the stamp");
    // The body cap is checked before the envelope is looked at.
    let error = validate_supply_entry(&make_supply_entry(&close)).expect_err("over the cap");
    assert!(
        matches!(error, MergeError::ResourceLimitExceeded(_)),
        "{error:?}"
    );
    drop((node, fresh));
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
}

/// A2 (0926), T85 (d) / L-110's remedy on the supported path (stop → edit
/// → start), with no peer holding the original: this node's `open
/// Expenses:Food` has its envelope edited (lamport) or its body edited
/// (date), so boot holds it (H-20). Deleting its `openledger-*` lines with
/// the node stopped turns it into operator input; the next boot adopts it,
/// signs it, and a fresh replica stages it — the operator is never stuck on
/// this path, whichever edit was made. (A2-2 pins the same remedy under a
/// running node.)
#[test]
fn a2_the_l110_remedy_works_with_the_node_stopped_for_either_edit() {
    let a = std::sync::Arc::new(key());
    for (label, from, to) in [
        (
            "envelope",
            "openledger-lamport: \"3\"",
            "openledger-lamport: \"99\"",
        ),
        (
            "body",
            "2024-01-01 open Expenses:Food",
            "2024-01-02 open Expenses:Food",
        ),
    ] {
        let (mut node, path) = a2_node_with_accounts(&format!("a2-l110-stopped-{label}"), &a);
        node.open_account_signing(
            "Expenses:Food".to_owned(),
            date(1),
            vec![],
            a2_sign_open_with(std::sync::Arc::clone(&a)),
        )
        .expect("open");
        node.compact().expect("compact");
        drop(node);
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains(from), "{label}: premise");
        std::fs::write(&path, text.replacen(from, to, 1)).expect("write");
        let mut node = a2_restart(&path, &a);
        node.compact().expect("the startup compaction");
        assert!(!node.accounts().is_open("Expenses:Food"), "{label}: held");
        drop(node);

        let text = std::fs::read_to_string(&path).expect("read");
        let mut in_food = false;
        let stripped: Vec<&str> = text
            .lines()
            .filter(|line| {
                if !line.starts_with(' ') {
                    in_food = line.contains(" open Expenses:Food");
                }
                !(in_food && line.contains("openledger-"))
            })
            .collect();
        std::fs::write(&path, stripped.join("\n") + "\n").expect("write");
        let node = a2_restart(&path, &a);
        assert!(node.accounts().is_open("Expenses:Food"), "{label}: opened");
        assert!(node.quarantined_ids().is_empty(), "{label}");
        let food = node
            .dag()
            .directives()
            .into_iter()
            .find(|directive| {
                matches!(directive, Directive::Open(open) if open.account == "Expenses:Food")
            })
            .expect("served")
            .clone();
        let (mut fresh, fresh_path) = fresh_with_accounts(&format!("a2-l110-fresh-{label}"));
        assert_eq!(a2_offer(&mut fresh, &food), "OK", "{label}");
        drop((node, fresh));
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
        let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
    }
}

// ─── A1 (0927 re-audit of T90): the duplicate-copy preference, the closure ──

/// A pre-T65 chain the closure holds, its child dated BEFORE its parent: `X`
/// (5 × 10^22, past the amount cap, day 2), `C` naming `X` (day 4) and `D`
/// naming `C` (day 3 — a parent's date says nothing about its child's). With
/// the padding that makes a later write a journal append, and the two
/// accounts, all signed by `author`. Returns the path and the ids of `C` and
/// `D`, both held by the closure at boot.
fn a1_back_dated_held_chain(
    label: &str,
    author: &std::sync::Arc<PeerKeySignatureProvider>,
) -> (PathBuf, String, String) {
    let over = Decimal::from_str_exact("50000000000000000000000").expect("5 × 10^22");
    let x = signed_transfer(author, 2, "X pre-upgrade", over, "", 3);
    let c = signed_transfer(
        author,
        4,
        "C child",
        Decimal::from(5),
        &compute_content_id(&x),
        4,
    );
    let c_id = compute_content_id(&c);
    let d = signed_transfer(author, 3, "D grandchild", Decimal::from(9), &c_id, 5);
    let d_id = compute_content_id(&d);
    // Past `COMPACTION_MIN_CANONICAL_BYTES`, so a write appends to the journal.
    let Directive::Transaction(mut padding) =
        signed_transfer(author, 1, "padding", Decimal::from(1), "", 6)
    else {
        unreachable!()
    };
    for index in 0..100 {
        padding.postings[0]
            .metadata
            .insert(format!("k{index:03}"), "v".repeat(800));
    }
    let padding = a2_resigned(author, padding, "", 6);
    let path = scratch_ledger(label);
    std::fs::write(
        &path,
        ledger::serialize::full_file_serialize(
            &[
                a2_open(author, "Equity:Opening", 1),
                a2_open(author, "Assets:Cash", 2),
                padding,
                x,
                c,
                d,
            ],
            &[],
        ),
    )
    .expect("write");
    (path, c_id, d_id)
}

/// A replica that never held anything, offered `served` through the real wire
/// validators until nothing more stages (any order: a record whose parent is
/// not there yet is `MISSING_PARENT` and offered again next round).
fn a1_fresh_replica_of(label: &str, served: &[Directive]) -> (LedgerService, PathBuf) {
    let path = scratch_ledger(label);
    let mut fresh = LedgerService::boot(&path, "fresh".to_owned()).expect("boot fresh");
    fresh.set_verifier(verifier());
    let mut waiting: Vec<&Directive> = served.iter().collect();
    loop {
        let before = waiting.len();
        waiting.retain(|directive| a2_offer(&mut fresh, directive) != "OK");
        if waiting.is_empty() || waiting.len() == before {
            break;
        }
    }
    (fresh, path)
}

/// The H-24 crash with no peer over [`a1_back_dated_held_chain`]: boot, the
/// startup compaction, a warm-up write (the compaction that makes later
/// writes journal appends), then the operator re-enters the two held
/// transactions through the API — `D` first when `d_first`, else `C` first —
/// and writes `Y` on top of the last; the process dies before its stop
/// compaction. Returns the path, the ids of `C`, `D` and `Y`, and everything
/// the node served just before the crash.
fn a1_reenter_the_chain_and_crash(
    label: &str,
    author: &std::sync::Arc<PeerKeySignatureProvider>,
    d_first: bool,
) -> (PathBuf, [String; 3], Vec<Directive>) {
    use ledger::service::{PostingInput, TransactionInput};
    let (path, c_id, d_id) = a1_back_dated_held_chain(label, author);
    let mut node = a2_restart(&path, author);
    node.compact().expect("the startup compaction");
    let held = node.quarantined_ids();
    assert!(
        held.contains(&c_id.as_str()) && held.contains(&d_id.as_str()),
        "premise: the closure holds C and D ({held:?})"
    );
    let signing = std::sync::Arc::clone(author);
    let sign = move |content_id: &str, parents: &str, lamport: &str| {
        signing.sign(&SignableMessage {
            content_id,
            is_transaction: true,
            parents,
            lamport,
        })
    };
    let input = |day: u32, narration: &str, amount: i64| TransactionInput {
        date: date(day),
        flag: Flag::Complete,
        payee: None,
        narration: Some(narration.to_owned()),
        tags: vec![],
        links: vec![],
        postings: ["Assets:Cash", "Equity:Opening"]
            .into_iter()
            .zip([amount, -amount])
            .map(|(account, number)| PostingInput {
                account: account.to_owned(),
                amount: Some(usd(Decimal::from(number))),
                cost: None,
                price: None,
            })
            .collect(),
    };
    node.append_transaction_signing(input(5, "warm-up", 1), sign.clone())
        .expect("the first write compacts");
    let entries = if d_first {
        [(3, "D grandchild", 9), (4, "C child", 5)]
    } else {
        [(4, "C child", 5), (3, "D grandchild", 9)]
    };
    for (day, narration, amount) in entries {
        let outcome = node
            .append_transaction_signing(input(day, narration, amount), sign.clone())
            .expect("re-entered");
        assert!(
            outcome.txid == c_id || outcome.txid == d_id,
            "the same body, the same id"
        );
    }
    let y = node
        .append_transaction_signing(input(6, "Y after", 7), sign)
        .expect("Y");
    assert!(node.journal_bytes() > 0, "premise: journal records");
    let served: Vec<Directive> = node.dag().directives().into_iter().cloned().collect();
    drop(node); // no stop compaction
    (path, [c_id, d_id, y.txid], served)
}

/// The `openledger-parents` line of the block in the file at `path` whose
/// header carries `narration`, one entry per copy on disk.
fn a1_parents_on_disk(path: &PathBuf, narration: &str) -> Vec<String> {
    let text = std::fs::read_to_string(path).expect("read");
    text.split("\n\n")
        .filter(|block| block.contains(&format!("\"{narration}\"")))
        .map(|block| {
            block
                .lines()
                .find_map(|line| line.trim().strip_prefix("openledger-parents: "))
                .unwrap_or("")
                .trim_matches('"')
                .to_owned()
        })
        .collect()
}

/// A1 (0927), T90 (b) on a held chain re-entered parent first: the operator
/// re-enters `C`, then `D` (so the journal's `D` names the journal's `C`),
/// writes `Y`, and the process dies before its stop compaction. Boot swaps
/// the file's `C` (parent the refused `X`) for the journal's, and the file's
/// `D` then resolves through it: `C`, `D` and `Y` are served straight after
/// the crash and after the next restart, with P2P off — the set a fresh
/// replica given what the node served before the crash holds. And in the
/// other order (`D` first, A1-1), whatever boot keeps, the startup compaction
/// never writes a parent cycle: no copy of `C` on disk names `D` while a copy
/// of `D` names `C`.
///
/// Bug-catch: drop `prefer_copies_whose_parents_are_served` and the
/// parent-first chain is held after the crash; drop its "descends from the
/// record" guard and the `D`-first crash leaves `C` and `D` naming each other
/// on disk.
#[test]
fn a1_0927_after_a_crash_a_chain_re_entered_parent_first_is_served() {
    let author = std::sync::Arc::new(key());
    let (path, [c_id, d_id, y_id], served) =
        a1_reenter_the_chain_and_crash("a1-chain-parent-first", &author, false);
    let (fresh, fresh_path) = a1_fresh_replica_of("a1-chain-parent-first-fresh", &served);
    assert!(
        [&c_id, &d_id, &y_id]
            .into_iter()
            .all(|id| fresh.contains_directive(id)),
        "premise: a fresh replica holds the chain"
    );
    let mut node = a2_restart(&path, &author);
    let after_crash = [&c_id, &d_id, &y_id].map(|id| node.contains_directive(id));
    node.compact().expect("the startup compaction");
    drop(node);
    let node = a2_restart(&path, &author);
    let next_boot = [&c_id, &d_id, &y_id].map(|id| node.contains_directive(id));
    assert_eq!(
        (after_crash, next_boot),
        ([true; 3], [true; 3]),
        "C, D, Y served after the crash, after the next restart"
    );
    drop((node, fresh));
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));

    let (path, [c_id, d_id, _], _) =
        a1_reenter_the_chain_and_crash("a1-chain-child-first", &author, true);
    let mut node = a2_restart(&path, &author);
    node.compact().expect("the startup compaction");
    drop(node);
    let c_names_d = a1_parents_on_disk(&path, "C child")
        .iter()
        .any(|parents| parents.contains(d_id.as_str()));
    let d_names_c = a1_parents_on_disk(&path, "D grandchild")
        .iter()
        .any(|parents| parents.contains(c_id.as_str()));
    assert!(
        !(c_names_d && d_names_c),
        "the compaction wrote a parent cycle: C names D and D names C on disk"
    );
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// A1-1 (0927), T90 (b) on a chain of two held records: the H-24 crash with
/// no peer, as `h24_after_a_crash_…` drives it, except that the operator
/// re-enters two records the closure holds — `D`, then `C`, in date order —
/// where `D` descends from `C` in the file. The API gives `D` the heads and
/// `C` names `D`; `Y` goes on top of `C`. All three are acknowledged journal
/// records, then the process dies before its stop compaction.
///
/// Boot meets the file's copies first. `prefer_copies_whose_parents_are_served`
/// asks "is every parent in the DAG" of the lenient, pre-closure DAG: the
/// file's `D` names `C`, which is in it (the file's `C`, about to be held), so
/// `D` counts as resolving and is kept; the journal's `C` names `D`, which
/// descends from `C` through the file's `D`, so the cycle guard keeps the
/// file's `C` too. The closure then holds `C`, `D` and `Y` — the node's own
/// acknowledged records — and the startup compaction writes only the held
/// copies back, so the journal's copies are gone from disk. A fresh replica
/// given what the node served before the crash holds all three.
#[test]
fn a1_0927_after_a_crash_a_re_entered_chain_is_served_whatever_order_it_was_re_entered_in() {
    let author = std::sync::Arc::new(key());
    let (path, [c_id, d_id, y_id], served) =
        a1_reenter_the_chain_and_crash("a1-1-api", &author, true);
    let Some(Directive::Transaction(c_before)) = served
        .iter()
        .find(|directive| compute_content_id(directive) == c_id)
        .cloned()
    else {
        panic!("C is served");
    };
    assert_eq!(
        c_before.parent_ids(),
        vec![d_id.as_str()],
        "premise: the re-entered C names the re-entered D"
    );
    // A fresh replica takes everything the node served before the crash.
    let (fresh, fresh_path) = a1_fresh_replica_of("a1-1-fresh", &served);
    assert!(
        [&d_id, &c_id, &y_id]
            .into_iter()
            .all(|id| fresh.contains_directive(id)),
        "premise: a fresh replica holds the chain"
    );

    let mut node = a2_restart(&path, &author);
    let after_crash = [&d_id, &c_id, &y_id].map(|id| node.contains_directive(id));
    node.compact().expect("the startup compaction");
    drop(node);
    let copies_of_c = a1_parents_on_disk(&path, "C child");
    let node = a2_restart(&path, &author);
    let next_boot = [&d_id, &c_id, &y_id].map(|id| node.contains_directive(id));
    assert!(
        after_crash == [true; 3] && next_boot == [true; 3],
        "A1-1: D, C, Y served after the crash {after_crash:?}, after the next restart \
         {next_boot:?}, held {:?}; the copies of C on disk after the startup compaction \
         name {copies_of_c:?}; a fresh replica holds all three",
        node.quarantined_ids()
    );
    drop((node, fresh));
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
}

/// A1-2 (0927), T90 (b)'s stated residual ("two copies that both resolve keep
/// the first") with a cause other than the closure: this node's `C` has its
/// `openledger-lamport` edited in the file, so the signature pass holds it
/// (H-20). The operator re-enters `C`'s transaction through the API — same
/// body, same id, accepted because the DAG lacks it — and writes `Y` on top;
/// the process dies before its stop compaction. Boot meets the file's edited
/// `C` first; both copies' parents resolve, so the preference keeps it, the
/// signature pass holds it again, and `Y` goes with it (H-23). The journal's
/// signed copy is dropped by the startup compaction: after the crash the node
/// serves neither of its own acknowledged records, for good with P2P off —
/// the H-24 crash T90 fixed, reached through a hold T90's preference does not
/// look at.
#[test]
fn a1_0927_after_a_crash_a_re_entered_signature_held_record_is_served() {
    use ledger::service::{PostingInput, TransactionInput};
    let author = std::sync::Arc::new(key());
    // Past `COMPACTION_MIN_CANONICAL_BYTES`, so a write appends to the journal.
    let Directive::Transaction(mut padding) =
        signed_transfer(&author, 1, "padding", Decimal::from(1), "", 3)
    else {
        unreachable!()
    };
    for index in 0..100 {
        padding.postings[0]
            .metadata
            .insert(format!("k{index:03}"), "v".repeat(800));
    }
    let padding = a2_resigned(&author, padding, "", 3);
    let Directive::Transaction(mut edited) =
        signed_transfer(&author, 3, "C edited", Decimal::from(5), "", 4)
    else {
        unreachable!()
    };
    edited
        .metadata
        .insert("openledger-lamport".to_owned(), "44".to_owned());
    let edited = Directive::Transaction(edited);
    let c_id = compute_content_id(&edited);
    let path = scratch_ledger("a1-2-api");
    std::fs::write(
        &path,
        ledger::serialize::full_file_serialize(
            &[
                a2_open(&author, "Equity:Opening", 1),
                a2_open(&author, "Assets:Cash", 2),
                padding,
                edited,
            ],
            &[],
        ),
    )
    .expect("write");
    let mut node = a2_restart(&path, &author);
    node.compact().expect("the startup compaction");
    assert!(
        node.quarantined_ids().contains(&c_id.as_str()),
        "premise: the signature pass holds the edited C"
    );

    let signing = std::sync::Arc::clone(&author);
    let sign = move |content_id: &str, parents: &str, lamport: &str| {
        signing.sign(&SignableMessage {
            content_id,
            is_transaction: true,
            parents,
            lamport,
        })
    };
    let input = |day: u32, narration: &str, amount: i64| TransactionInput {
        date: date(day),
        flag: Flag::Complete,
        payee: None,
        narration: Some(narration.to_owned()),
        tags: vec![],
        links: vec![],
        postings: ["Assets:Cash", "Equity:Opening"]
            .into_iter()
            .zip([amount, -amount])
            .map(|(account, number)| PostingInput {
                account: account.to_owned(),
                amount: Some(usd(Decimal::from(number))),
                cost: None,
                price: None,
            })
            .collect(),
    };
    node.append_transaction_signing(input(5, "warm-up", 1), sign.clone())
        .expect("the first write compacts");
    let c = node
        .append_transaction_signing(input(3, "C edited", 5), sign.clone())
        .expect("C re-entered");
    assert_eq!(c.txid, c_id, "the same body, the same id");
    let y = node
        .append_transaction_signing(input(6, "Y after", 7), sign)
        .expect("Y");
    assert!(node.journal_bytes() > 0, "premise: journal records");
    let served: Vec<Directive> = node.dag().directives().into_iter().cloned().collect();
    drop(node); // no stop compaction

    let (fresh, fresh_path) = a1_fresh_replica_of("a1-2-fresh", &served);
    assert!(
        fresh.contains_directive(&c_id) && fresh.contains_directive(&y.txid),
        "premise: a fresh replica holds C and Y"
    );
    let mut node = a2_restart(&path, &author);
    let after_crash = [&c_id, &y.txid].map(|id| node.contains_directive(id));
    node.compact().expect("the startup compaction");
    drop(node);
    let node = a2_restart(&path, &author);
    let next_boot = [&c_id, &y.txid].map(|id| node.contains_directive(id));
    assert!(
        after_crash == [true; 2] && next_boot == [true; 2],
        "A1-2: C, Y served after the crash {after_crash:?}, after the next restart \
         {next_boot:?}, held {:?}; a fresh replica holds both",
        node.quarantined_ids()
    );
    drop((node, fresh));
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
}

/// A1-3 (0927), T90 (c) / L-126's list; L-140 (T103, decision (69a)): a
/// peer's complete envelope pasted into the file whose lamport is 2^32 + 10
/// above this node's clock. The live reconcile refuses it under the adoption
/// ratchet (`LAMPORT_ADVANCE`, H-12) and the canonical re-persist drops it;
/// boot of the same bytes — the node stopped, the same paste — loads it as
/// history and serves it (the trusted-bootstrap join relies on exactly
/// that). The refusal is the running node's alone, and says so: its reason
/// names L-140 and how to keep the record (stop, put it back, start), which
/// README's live bullet documents.
///
/// Bug-catch: drop the live-only clause from the refusal and the logged
/// reason no longer tells the operator how to keep the record.
#[test]
fn a1_0927_a_pasted_record_over_the_lamport_ratchet_is_refused_live_only_and_says_how_to_keep_it() {
    let a = std::sync::Arc::new(key());
    let b = PeerKeySignatureProvider::from_bytes(&[0x51; 32], MESH_ID.to_owned());
    let jumped = signed_transfer(
        &b,
        5,
        "jumped",
        Decimal::from(5),
        "",
        ledger::service::MAX_LAMPORT_ADVANCE + 10,
    );
    let jumped_id = compute_content_id(&jumped);
    let mut kept = Vec::new();
    let mut live_log = String::new();
    for label in ["live", "boot"] {
        let (mut node, path) = a2_node_with_accounts(&format!("a1-3-{label}"), &a);
        if label == "boot" {
            drop(node);
            a2_append(&path, std::slice::from_ref(&jumped));
            node = a2_restart(&path, &a);
        } else {
            a2_append(&path, std::slice::from_ref(&jumped));
            let (result, logged) = capture_warnings(|| node.reconcile_file());
            result.expect("reconcile");
            live_log = logged;
        }
        let served = node.contains_directive(&jumped_id);
        node.compact().expect("compact");
        let in_file = std::fs::read_to_string(&path)
            .expect("read")
            .contains("\"jumped\"");
        kept.push((label, served, in_file));
        drop(node);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
    assert_eq!(
        kept,
        vec![("live", false, false), ("boot", true, true)],
        "(path, served, file keeps it)"
    );
    assert!(
        live_log.contains(&jumped_id)
            && live_log.contains("H-12 adoption ratchet")
            && live_log.contains("Refused by the running node only (L-140)")
            && live_log.contains("stop the node, put it back in the file and start it"),
        "the live refusal says it is live-only and how to keep the record: {live_log}"
    );
}

/// A1-4 (0927), T90 (d); M-73 (T103, decision (68a)): the restate remedy,
/// followed as the WARNs now give it. A pre-T65 mesh replicated `X` (5 ×
/// 10^22), its child `C` and grandchild `G`; after the upgrade every node's
/// closure holds `C` and `G`. Before T103 every node's WARN told its operator
/// to restate `X`, and operators of A and B who each did so restated one
/// deposit twice — two ids, both served, `Assets:Cash` counting the refused
/// amount once per operator. The WARN now says to restate on ONE node and
/// that the others adopt it and must NOT restate: A's operator restates
/// (`X` in a larger unit without its envelope, `C` and `G` without theirs),
/// B's does nothing. B adopts A's `X` and A's copies of `C` and `G`, and its
/// next boot's WARN for the old block says to delete it.
///
/// Bug-catch: make `warn_amount_cap_block` give the held-descendants text
/// whatever is held and B's restart never says "delete this block"; restore
/// the closure WARN's pre-T103 text and B's first boot does not say to repair
/// on one node.
#[test]
fn a1_0927_the_restate_remedy_followed_on_two_nodes_counts_the_deposit_once() {
    let author = std::sync::Arc::new(key());
    let over = Decimal::from_str_exact("50000000000000000000000").expect("5 × 10^22");
    let opening = a2_open(&author, "Equity:Opening", 1);
    let cash = a2_open(&author, "Assets:Cash", 2);
    let x = signed_transfer(&author, 2, "X pre-upgrade", over, "", 3);
    let c = signed_transfer(
        &author,
        3,
        "C child",
        Decimal::from(5),
        &compute_content_id(&x),
        4,
    );
    let g = signed_transfer(
        &author,
        4,
        "G grandchild",
        Decimal::from(9),
        &compute_content_id(&c),
        5,
    );
    let restated = {
        let Directive::Transaction(mut txn) = a2_stripped(&x) else {
            unreachable!()
        };
        for posting in &mut txn.postings {
            let amount = posting.amount.as_mut().expect("explicit");
            amount.number /= Decimal::from_str_exact("1000000000000000000000").expect("10^21");
        }
        Directive::Transaction(txn)
    };
    let files = [
        // A's operator followed the WARN: the one restatement.
        vec![
            opening.clone(),
            cash.clone(),
            restated,
            a2_stripped(&c),
            a2_stripped(&g),
        ],
        // B's operator did not restate: the pre-upgrade history, untouched.
        vec![opening.clone(), cash.clone(), x, c.clone(), g.clone()],
    ];
    let mut nodes = Vec::new();
    let mut first_boot_b = String::new();
    for ((label, seed), file) in [("a", 0x50u8), ("b", 0x52)].into_iter().zip(files) {
        let key = std::sync::Arc::new(PeerKeySignatureProvider::from_bytes(
            &[seed; 32],
            MESH_ID.to_owned(),
        ));
        let path = scratch_ledger(&format!("a1-4-{label}"));
        std::fs::write(&path, ledger::serialize::full_file_serialize(&file, &[])).expect("write");
        let (node, logged) = capture_warnings(|| a2_restart(&path, &key));
        if label == "b" {
            first_boot_b = logged;
            let held = node.quarantined_ids();
            assert!(
                held.contains(&compute_content_id(&c).as_str())
                    && held.contains(&compute_content_id(&g).as_str()),
                "premise: B's closure holds C and G ({held:?})"
            );
        } else {
            assert!(node.quarantined_ids().is_empty(), "{label}: premise");
        }
        nodes.push((node, path, key));
    }
    assert!(
        first_boot_b.contains("held names its children")
            && first_boot_b.contains("repair the chain on ONE node only")
            && first_boot_b.contains("on ONE node only")
            && first_boot_b.contains("must NOT restate")
            && !first_boot_b.contains("delete this block"),
        "M-73: B's WARNs say to restate on one node and not on the others: {first_boot_b}"
    );
    // Anti-entropy both ways, until nothing more stages.
    for _ in 0..3 {
        for (from, to) in [(0usize, 1usize), (1, 0)] {
            let served: Vec<Directive> = nodes[from]
                .0
                .dag()
                .directives()
                .into_iter()
                .cloned()
                .collect();
            for directive in &served {
                let _ = a2_offer(&mut nodes[to].0, directive);
            }
        }
    }
    let cash_on = |node: &LedgerService| {
        node.read_model()
            .account_balance("Assets:Cash", None)
            .expect("cash")
            .balances["USD"]
            .to_string()
    };
    let deposits = |node: &LedgerService| {
        node.dag()
            .directives()
            .into_iter()
            .filter(|directive| {
                matches!(directive, Directive::Transaction(txn)
                    if txn.narration.as_deref().is_some_and(|n| n.starts_with("X pre-upgrade")))
            })
            .count()
    };
    let balances: Vec<String> = nodes.iter().map(|(node, _, _)| cash_on(node)).collect();
    let counts: Vec<usize> = nodes.iter().map(|(node, _, _)| deposits(node)).collect();
    assert_eq!(
        (counts.clone(), balances.clone()),
        (vec![1, 1], vec!["64".to_owned(), "64".to_owned()]),
        "A1-4: restated deposits served per node {counts:?}, Assets:Cash {balances:?}"
    );
    // B's next boot: the old block is all that is left of X, and nothing B
    // holds descends from it any more.
    let (mut b, b_path, b_key) = nodes.pop().expect("b");
    b.compact().expect("compact");
    drop(b);
    let (b, logged) = capture_warnings(|| a2_restart(&b_path, &b_key));
    assert!(
        logged.contains("delete this block") && !logged.contains("held names its children"),
        "M-73: B's restart names the old block as a copy to delete: {logged}"
    );
    assert_eq!(
        (deposits(&b), cash_on(&b), b.quarantined_ids().len()),
        (1, "64".to_owned(), 0),
        "B after the restart"
    );
    drop(b);
    let _ = std::fs::remove_dir_all(b_path.parent().expect("dir"));
    for (node, path, _) in nodes {
        drop(node);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
}

/// A1-5 (0927), T90 (c) / L-126 × M-18: the live hold keeps in the file a
/// record of THIS node's that the reconcile refuses — here its own signed
/// record on an account this ledger has not opened (`validate_transaction`),
/// pasted back with a lamport above the running clock (from a copy newer than
/// this node's file: a peer's `.bean`, after a restore). The refusal leaves
/// the clock where it was (L-55), as it did when the rewrite deleted the
/// bytes; now the bytes stay, held, and the node's next writes stamp the
/// held record's `(author, lamport)` pair again. Boot counts a held own
/// record (`BootLamportHigh`: "ignoring its value could re-issue its pair");
/// the live hold did not. Once the account is opened by hand the held record
/// was served beside the new one that carries its pair. Since T103 (L-141,
/// decision (70a)) the live hold folds the held record's lamport into the
/// clock, as boot does.
///
/// Bug-catch: drop the fold from `hold_refused_file_entry` and two served
/// records carry the pair.
#[test]
fn a1_0927_a_held_own_record_s_lamport_is_never_re_issued() {
    let a = std::sync::Arc::new(key());
    let (mut node, path) = a2_node_with_accounts("a1-5", &a);
    let pasted_lamport = node.lamport_clock() + 3;
    let Directive::Transaction(mut txn) = signed_transfer(
        &a,
        5,
        "own, on nowhere",
        Decimal::from(3),
        "",
        pasted_lamport,
    ) else {
        unreachable!()
    };
    txn.postings[0].account = "Assets:Nowhere".to_owned();
    let pasted = a2_resigned(&a, txn, "", pasted_lamport);
    let pasted_id = compute_content_id(&pasted);
    a2_append(&path, std::slice::from_ref(&pasted));
    node.reconcile_file().expect("reconcile");
    assert!(
        node.quarantined_ids().contains(&pasted_id.as_str()),
        "premise: held live (T90 / L-126)"
    );
    let clock_after_hold = node.lamport_clock();
    let signing = std::sync::Arc::clone(&a);
    let sign = move |content_id: &str, parents: &str, lamport: &str| {
        signing.sign(&SignableMessage {
            content_id,
            is_transaction: true,
            parents,
            lamport,
        })
    };
    for day in 6..10 {
        node.append_transaction_signing(
            ledger::service::TransactionInput {
                date: date(day),
                flag: Flag::Complete,
                payee: None,
                narration: Some(format!("write {day}")),
                tags: vec![],
                links: vec![],
                postings: ["Assets:Cash", "Equity:Opening"]
                    .into_iter()
                    .zip([1i64, -1])
                    .map(|(account, number)| ledger::service::PostingInput {
                        account: account.to_owned(),
                        amount: Some(usd(Decimal::from(number))),
                        cost: None,
                        price: None,
                    })
                    .collect(),
            },
            sign.clone(),
        )
        .expect("write");
    }
    node.compact().expect("compact");
    drop(node);
    // The operator opens the account by hand; the held record is admitted.
    let mut text = std::fs::read_to_string(&path).expect("read");
    text.push_str("\n2024-01-01 open Assets:Nowhere\n");
    std::fs::write(&path, text).expect("write");
    let node = a2_restart(&path, &a);
    let pair = format!("openledger-lamport: \"{pasted_lamport}\"");
    let served_with_pair = node
        .dag()
        .directives()
        .into_iter()
        .filter(|directive| {
            directive.metadata().get("openledger-lamport") == Some(&pasted_lamport.to_string())
                && directive.metadata().get("openledger-author") == Some(&a.public_key_hex())
        })
        .count();
    let on_disk = std::fs::read_to_string(&path)
        .expect("read")
        .matches(&pair)
        .count();
    assert!(
        served_with_pair <= 1,
        "A1-5: clock {clock_after_hold} after holding a record at lamport {pasted_lamport}; \
         {on_disk} records on disk and {served_with_pair} served carry this node's pair \
         (author, {pasted_lamport})"
    );
    drop(node);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// L-141 (T103, decision (70a)), the T85 arm: this node's own complete
/// envelope pasted into the file naming a parent this node does not serve is
/// held in the quarantine on its parent (M-56, H-23) — and its lamport now
/// moves the clock, so the node's next write never stamps the held record's
/// `(author, lamport)` pair. Boot of the same bytes counts it.
///
/// Bug-catch: drop the fold from the T85 missing-parent hold and the next
/// write carries the held record's lamport.
#[test]
fn l141_a_held_own_record_on_a_missing_parent_moves_the_clock() {
    let a = std::sync::Arc::new(key());
    let (mut node, path) = a2_node_with_accounts("l141-parent", &a);
    let pasted_lamport = node.lamport_clock() + 3;
    let pasted = signed_transfer(
        &a,
        5,
        "own, on a missing parent",
        Decimal::from(3),
        &"f".repeat(64),
        pasted_lamport,
    );
    let pasted_id = compute_content_id(&pasted);
    a2_append(&path, std::slice::from_ref(&pasted));
    node.reconcile_file().expect("reconcile");
    assert!(
        node.quarantined_ids().contains(&pasted_id.as_str()),
        "premise: held on its parent (T85)"
    );
    assert!(
        node.lamport_clock() >= pasted_lamport,
        "L-141: clock {} after holding this node's record at lamport {pasted_lamport}",
        node.lamport_clock()
    );
    drop(node);
    let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
}

/// A1 (0927), T90 (a) across a held CHAIN, on both paths: the closure holds
/// `C` (its file copy names the pre-T65 `X`) and `D` (whose only copy names
/// `C`). A copy of `C` naming parents this node serves — pasted under the
/// running node, or offered by a peer — is adopted, and then `D`'s ORIGINAL
/// copy is adoptable too: its parent is in the DAG, which is all a fresh
/// replica asks of it. Live: the same reconcile adopts both, the compaction
/// writes them, the next boot serves both. Wire: `D`'s old copy, offered
/// after `C`'s restated one, stages. Either way the node ends with the set a
/// fresh replica given the same copies holds.
///
/// Bug-catch: key the parent test on closure membership alone AND drop the
/// pruning on adoption (wire and live) — each alone is covered by the other —
/// and `D`'s copy is refused on both paths, `INVALID_INPUT` for good on the
/// wire.
#[test]
fn a1_0927_a_restated_parent_frees_the_held_child_s_original_copy_live_and_on_the_wire() {
    let author = std::sync::Arc::new(key());
    let over = Decimal::from_str_exact("50000000000000000000000").expect("5 × 10^22");
    let x = signed_transfer(&author, 2, "X pre-upgrade", over, "", 3);
    let c = signed_transfer(
        &author,
        3,
        "C child",
        Decimal::from(5),
        &compute_content_id(&x),
        4,
    );
    let c_id = compute_content_id(&c);
    let d = signed_transfer(&author, 4, "D grandchild", Decimal::from(9), &c_id, 5);
    let d_id = compute_content_id(&d);
    let restated_c = signed_transfer(&author, 3, "C child", Decimal::from(5), "", 30);
    assert_eq!(compute_content_id(&restated_c), c_id, "premise: one body");
    let opens = [
        a2_open(&author, "Equity:Opening", 1),
        a2_open(&author, "Assets:Cash", 2),
    ];
    let history = ledger::serialize::full_file_serialize(
        &[opens[0].clone(), opens[1].clone(), x, c, d.clone()],
        &[],
    );
    let (fresh, fresh_path) = a1_fresh_replica_of(
        "a1-chain-fresh",
        &[
            opens[0].clone(),
            opens[1].clone(),
            restated_c.clone(),
            d.clone(),
        ],
    );
    assert!(
        fresh.contains_directive(&c_id) && fresh.contains_directive(&d_id),
        "premise: a fresh replica holds C and D"
    );
    let mut outcomes = Vec::new();
    for label in ["live", "wire"] {
        let path = scratch_ledger(&format!("a1-chain-{label}"));
        std::fs::write(&path, &history).expect("write");
        let mut node = a2_restart(&path, &author);
        node.compact().expect("the startup compaction");
        let held = node.quarantined_ids();
        assert!(
            held.contains(&c_id.as_str()) && held.contains(&d_id.as_str()),
            "{label}: premise, the closure holds C and D ({held:?})"
        );
        let codes = if label == "live" {
            a2_append(&path, std::slice::from_ref(&restated_c));
            let result = node.reconcile_file().expect("reconcile");
            vec![format!("{result:?}")]
        } else {
            [&restated_c, &d]
                .into_iter()
                .map(|directive| a2_offer(&mut node, directive).to_owned())
                .collect()
        };
        let running = [&c_id, &d_id].map(|id| node.contains_directive(id));
        node.compact().expect("compact");
        drop(node);
        let node = a2_restart(&path, &author);
        let restarted = [&c_id, &d_id].map(|id| node.contains_directive(id));
        outcomes.push((label, running, restarted, codes));
        drop(node);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
    for (label, running, restarted, codes) in &outcomes {
        assert!(
            *running == [true, true] && *restarted == [true, true],
            "{label}: C, D served while running {running:?}, after a restart {restarted:?} \
             ({codes:?})"
        );
    }
    drop(fresh);
    let _ = std::fs::remove_dir_all(fresh_path.parent().expect("dir"));
}

/// A1 (0927), T90 (c) / L-126, the held-parent arm: under a running node
/// whose closure holds `C` (its parent the pre-T65 `X`), a peer's complete
/// envelope naming `C` is pasted into the file. The live reconcile refuses it
/// on its parent, as the wire does — and keeps it in the quarantine, so the
/// compaction writes it back and a restart holds it again; boot over the same
/// bytes holds it and keeps it. Before T90 the live path refused it into the
/// tally only and the re-persist deleted it.
///
/// Bug-catch: drop `hold_refused_file_entry` from the closure arm of
/// `adopt_file_directive` and the live path's file no longer has the record.
#[test]
fn a1_0927_a_pasted_child_of_a_held_record_stays_in_the_file_as_boot_keeps_it() {
    let author = std::sync::Arc::new(key());
    let b = PeerKeySignatureProvider::from_bytes(&[0x51; 32], MESH_ID.to_owned());
    let over = Decimal::from_str_exact("50000000000000000000000").expect("5 × 10^22");
    let x = signed_transfer(&author, 2, "X pre-upgrade", over, "", 3);
    let c = signed_transfer(
        &author,
        3,
        "C child",
        Decimal::from(5),
        &compute_content_id(&x),
        4,
    );
    let c_id = compute_content_id(&c);
    let pasted = signed_transfer(&b, 4, "B on C", Decimal::from(2), &c_id, 40);
    let pasted_id = compute_content_id(&pasted);
    let history = ledger::serialize::full_file_serialize(
        &[
            a2_open(&author, "Equity:Opening", 1),
            a2_open(&author, "Assets:Cash", 2),
            x,
            c,
        ],
        &[],
    );
    let mut kept = Vec::new();
    for label in ["live", "boot"] {
        let path = scratch_ledger(&format!("a1-held-parent-{label}"));
        std::fs::write(&path, &history).expect("write");
        let mut node = a2_restart(&path, &author);
        node.compact().expect("the startup compaction");
        if label == "boot" {
            drop(node);
            a2_append(&path, std::slice::from_ref(&pasted));
            node = a2_restart(&path, &author);
        } else {
            a2_append(&path, std::slice::from_ref(&pasted));
            node.reconcile_file().expect("reconcile");
        }
        let held = node.quarantined_ids().contains(&pasted_id.as_str());
        node.compact().expect("compact");
        let in_file = std::fs::read_to_string(&path)
            .expect("read")
            .contains("\"B on C\"");
        drop(node);
        let node = a2_restart(&path, &author);
        let held_after_restart = node.quarantined_ids().contains(&pasted_id.as_str());
        kept.push((label, held, in_file, held_after_restart));
        drop(node);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
    assert_eq!(
        kept,
        vec![("live", true, true, true), ("boot", true, true, true)],
        "(path, held, file keeps it, held after a restart)"
    );
}

/// A1-1 (0927), the same fault with no API and no operator on the node that
/// loses the records: the §Upgrading remedy followed on node A over a chain
/// whose grandchild `D` is dated before its parent `C`. A adopts the stripped
/// lines in canonical (date) order, so its `D` takes the heads and its `C`
/// names `D` — the file's parenthood reversed. Node B holds the old copies
/// (closure: `C`, `D`), adopts A's restated `X`, `D` and `C` over the wire —
/// journal appends, acknowledged — and crashes before its next compaction.
/// B's boot keeps the file's copies (`D` "resolves" through the file's `C`;
/// A's `C` names a descendant of the file's `C`), so B serves neither until a
/// peer supplies them again, and the startup compaction deletes the adopted
/// copies from B's disk.
#[test]
fn a1_0927_after_a_crash_a_restated_chain_adopted_from_a_peer_is_still_served() {
    let author = std::sync::Arc::new(key());
    let over = Decimal::from_str_exact("50000000000000000000000").expect("5 × 10^22");
    let x = signed_transfer(&author, 2, "X pre-upgrade", over, "", 3);
    let c = signed_transfer(
        &author,
        4,
        "C child",
        Decimal::from(5),
        &compute_content_id(&x),
        4,
    );
    let c_id = compute_content_id(&c);
    let d = signed_transfer(&author, 3, "D grandchild", Decimal::from(9), &c_id, 5);
    let d_id = compute_content_id(&d);
    let opens = [
        a2_open(&author, "Equity:Opening", 1),
        a2_open(&author, "Assets:Cash", 2),
    ];
    // Node A: stop → restate X, strip C and D → start.
    let x2 = {
        let Directive::Transaction(mut txn) = a2_stripped(&x) else {
            unreachable!()
        };
        for posting in &mut txn.postings {
            let amount = posting.amount.as_mut().expect("explicit");
            amount.number /= Decimal::from_str_exact("1000000000000000000000").expect("10^21");
        }
        Directive::Transaction(txn)
    };
    let a_path = scratch_ledger("a1-1-peer-a");
    std::fs::write(
        &a_path,
        ledger::serialize::full_file_serialize(
            &[
                opens[0].clone(),
                opens[1].clone(),
                x2,
                a2_stripped(&c),
                a2_stripped(&d),
            ],
            &[],
        ),
    )
    .expect("write");
    let a = a2_restart(&a_path, &author);
    let Some(Directive::Transaction(a_c)) = a.get_directive(&c_id).cloned() else {
        panic!("A serves C")
    };
    assert_eq!(
        a_c.parent_ids(),
        vec![d_id.as_str()],
        "premise: A's restated C names A's restated D"
    );
    let from_a: Vec<Directive> = a.dag().directives().into_iter().cloned().collect();

    // Node B: the old copies, past the compaction threshold.
    let b_key = std::sync::Arc::new(PeerKeySignatureProvider::from_bytes(
        &[0x52; 32],
        MESH_ID.to_owned(),
    ));
    let Directive::Transaction(mut padding) =
        signed_transfer(&author, 1, "padding", Decimal::from(1), "", 6)
    else {
        unreachable!()
    };
    for index in 0..100 {
        padding.postings[0]
            .metadata
            .insert(format!("k{index:03}"), "v".repeat(800));
    }
    let padding = a2_resigned(&author, padding, "", 6);
    let b_path = scratch_ledger("a1-1-peer-b");
    std::fs::write(
        &b_path,
        ledger::serialize::full_file_serialize(
            &[opens[0].clone(), opens[1].clone(), padding, x, c, d],
            &[],
        ),
    )
    .expect("write");
    let mut b = a2_restart(&b_path, &b_key);
    b.compact().expect("the startup compaction");
    let mut waiting: Vec<&Directive> = from_a.iter().collect();
    for _ in 0..4 {
        waiting.retain(|directive| {
            let code = a2_offer(&mut b, directive);
            if let Some(pending) = b.prepare_commit().expect("prepare") {
                let receipt = pending.commit().expect("commit");
                b.finish_commit(receipt);
            }
            code != "OK"
        });
    }
    assert!(
        b.contains_directive(&c_id) && b.contains_directive(&d_id) && b.journal_bytes() > 0,
        "premise: B adopted A's C and D into its journal"
    );
    drop(b); // no stop compaction

    let mut b = a2_restart(&b_path, &b_key);
    let after_crash = [&c_id, &d_id].map(|id| b.contains_directive(id));
    let held: Vec<String> = b.quarantined_ids().into_iter().map(str::to_owned).collect();
    let resupplied: Vec<&str> = from_a
        .iter()
        .map(|directive| a2_offer(&mut b, directive))
        .collect();
    let healed = [&c_id, &d_id].map(|id| b.contains_directive(id));
    assert!(
        after_crash == [true, true],
        "A1-1: B serves C, D after the crash: {after_crash:?}, held {held:?}; A re-supplying \
         them: {resupplied:?}, then served {healed:?}"
    );
    drop((a, b));
    for path in [&a_path, &b_path] {
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
}

/// A process-wide default subscriber that records nothing but is interested in
/// every callsite (T96 / L-135). Tracing caches each callsite's interest; a
/// callsite first hit by a test with no subscriber of its own was cached as
/// "never", and a concurrent capture's rebuild could miss a registration still
/// in flight — the capturing test then lost that one line (the log checks that
/// failed in two gates, and `m51_…` beside the T85 tests, deterministically).
/// With this installed, no callsite is ever "never"; each thread's scoped
/// subscriber decides.
fn ensure_every_callsite_is_interesting() {
    struct Interested;
    impl tracing::Subscriber for Interested {
        fn register_callsite(
            &self,
            _: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            false
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, _: &tracing::Event<'_>) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let _ = tracing::subscriber::set_global_default(Interested);
        tracing::callsite::rebuild_interest_cache();
    });
}

/// Every WARN (and ERROR) `body` logs on this thread, one line per event
/// with its fields (T89; the boot fuzzer's minimal subscriber, so the test
/// needs nothing beyond `tracing`).
fn capture_warnings<T>(body: impl FnOnce() -> T) -> (T, String) {
    ensure_every_callsite_is_interesting();
    use std::fmt::Write as _;
    use std::sync::{Arc, Mutex};

    struct Fields(String);
    impl tracing::field::Visit for Fields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            let _ = write!(self.0, "{}={:?} ", field.name(), value);
        }
    }
    struct Capture(Arc<Mutex<String>>);
    impl tracing::Subscriber for Capture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= tracing::Level::WARN
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            let mut logged = self.0.lock().unwrap();
            logged.push_str(&fields.0);
            logged.push('\n');
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    let logged = Arc::new(Mutex::new(String::new()));
    let value = tracing::subscriber::with_default(Capture(Arc::clone(&logged)), body);
    let text = logged.lock().unwrap().clone();
    (value, text)
}
