//! Property / fuzz harness (T17): malformed input must never panic.
//!
//! These are randomized panic regression tests. `parse_file` runs over untrusted
//! ledger text (API callers, remote peers, external file edits), and weight
//! summation runs over untrusted amounts — neither may panic on hostile input.
//! A panic here fails the test.

use std::collections::BTreeMap;

use chrono::NaiveDate;
use ledger::model::{Amount, Directive, Flag, Open, Posting, Transaction};
use ledger::parse::parse_file;
use ledger::serialize::full_file_serialize;
use ledger::service::validate_directive_dates;
use ledger::weights::sum_weights;
use proptest::prelude::*;
use rust_decimal::Decimal;

/// Amounts that stress the checked arithmetic in `sum_weights` (T1), including
/// the extremes where a naive `+`/`*` would overflow and panic.
fn extreme_decimal() -> impl Strategy<Value = Decimal> {
    prop_oneof![
        Just(Decimal::MAX),
        Just(Decimal::MIN),
        Just(Decimal::ZERO),
        Just(Decimal::MAX / Decimal::from(2)),
        any::<i64>().prop_map(Decimal::from),
    ]
}

fn posting(number: Decimal) -> Posting {
    Posting {
        account: "Assets:X".to_owned(),
        amount: Some(Amount {
            number,
            currency: "USD".to_owned(),
        }),
        cost: None,
        price: None,
        metadata: BTreeMap::new(),
    }
}

proptest! {
    // Arbitrary text (including control chars, newlines, unicode) must parse to
    // Ok/Err, never panic or hang.
    #[test]
    fn parse_file_never_panics(input in "(?s).{0,2048}") {
        let _ = ledger::parse::parse_file(&input);
    }

    // Summing weights over extreme amounts must yield Ok/Err (overflow is a
    // checked error, T1), never a panic — even under release overflow-checks.
    #[test]
    fn sum_weights_never_panics(
        numbers in prop::collection::vec(extreme_decimal(), 0..8)
    ) {
        let postings: Vec<Posting> = numbers.into_iter().map(posting).collect();
        let _ = sum_weights(&postings);
    }
}

// ─── H-04: dates must survive serialize → parse ──────────────────────────────
//
// The serializer writes dates with chrono's `%Y`, which signs any year outside
// `0..=9999` (`+10000-01-01`, `-0001-01-01`), while the file grammar's
// `read_date` demands exactly four leading ASCII digits. A date outside the
// supported range therefore serializes into a file that can never be re-parsed:
// every later `LedgerService::boot` fails and the node is bricked. These
// properties pin both halves — the domain that round-trips, and the brick that
// justifies `validate_directive_dates` rejecting everything else.

/// Calendar dates whose year is drawn from `years`. Invalid day/month
/// combinations (e.g. Feb 30) are filtered out by `from_ymd_opt`.
fn date_in_years(years: impl Strategy<Value = i32>) -> impl Strategy<Value = NaiveDate> {
    (years, 1u32..=12, 1u32..=31).prop_filter_map("valid calendar date", |(year, month, day)| {
        NaiveDate::from_ymd_opt(year, month, day)
    })
}

/// The simplest directive that carries a date and nothing else of interest.
fn open_on(date: NaiveDate) -> Directive {
    Directive::Open(Open {
        date,
        account: "Assets:Cash".to_owned(),
        currencies: Vec::new(),
        metadata: BTreeMap::new(),
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    // Every date in the supported range survives the REAL canonical serializer
    // and the REAL file parser unchanged.
    #[test]
    fn supported_dates_round_trip_through_serialize_and_parse(
        date in date_in_years(1i32..=9999)
    ) {
        let directive = open_on(date);
        prop_assert!(validate_directive_dates(&directive).is_ok());

        let text = full_file_serialize(std::slice::from_ref(&directive), &[]);
        let parsed = parse_file(&text)
            .map_err(|errors| TestCaseError::fail(format!("{text:?} failed to parse: {errors:?}")))?;

        prop_assert_eq!(parsed.len(), 1);
        prop_assert_eq!(parsed[0].date(), date);
    }

    // Everything outside the range is refused by the service-layer validator.
    #[test]
    fn out_of_range_dates_are_rejected(
        date in prop_oneof![
            date_in_years(-9999i32..=0),
            date_in_years(10000i32..=20000),
        ]
    ) {
        prop_assert!(
            validate_directive_dates(&open_on(date)).is_err(),
            "year {} must be rejected", date.format("%Y")
        );
    }

    // The brick, demonstrated: a signed year serializes to text the ledger's own
    // parser rejects, so a single persisted directive would make the file
    // permanently unreadable. This is exactly what the validator prevents.
    #[test]
    fn signed_years_serialize_to_unparseable_text(
        date in prop_oneof![
            date_in_years(-9999i32..=-1),
            date_in_years(10000i32..=20000),
        ]
    ) {
        let directive = open_on(date);
        prop_assert!(validate_directive_dates(&directive).is_err());

        let text = full_file_serialize(std::slice::from_ref(&directive), &[]);
        prop_assert!(
            parse_file(&text).is_err(),
            "serialized {text:?} must not re-parse — persisting it would brick the ledger"
        );
    }
}

// ─── L-25: parse-side and API-side share one account/tag/link charset ────────
//
// `validate_account_name` / `validate_tag` / `validate_link` are the API-side
// validators (the service calls them on every append/open/close) *and* the ones
// the parser now calls. These properties pin both halves of the contract: every
// name the validators accept must survive the real serializer and the real
// parser unchanged, and every name carrying a non-ASCII character must be
// refused by both — so a confusable account can be planted from neither the API
// nor a hand-edited file nor a remote body (which re-parses through `parse_file`).

/// Characters `char::is_alphanumeric` waves through but ASCII does not: Cyrillic
/// а, Greek α, fullwidth s and 1, and é.
fn confusable_character() -> impl Strategy<Value = char> {
    prop::sample::select(vec![
        '\u{0430}', '\u{03B1}', '\u{FF53}', '\u{FF11}', '\u{00E9}',
    ])
}

fn amount_posting(account: &str, number: Decimal) -> Posting {
    Posting {
        account: account.to_owned(),
        amount: Some(Amount {
            number,
            currency: "USD".to_owned(),
        }),
        cost: None,
        price: None,
        metadata: BTreeMap::new(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn api_accepted_names_survive_serialize_and_parse(
        segment in "[A-Z][A-Za-z0-9-]{0,7}",
        tag in "[A-Za-z0-9_-]{1,10}",
        link in "[A-Za-z0-9_-]{1,10}",
    ) {
        let account = format!("Assets:{segment}");
        prop_assert!(ledger::parse::validate_account_name(&account).is_ok());
        prop_assert!(ledger::parse::validate_tag(&tag).is_ok());
        prop_assert!(ledger::parse::validate_link(&link).is_ok());

        let directive = Directive::Transaction(Transaction {
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            flag: Flag::Complete,
            payee: None,
            narration: Some("round trip".to_owned()),
            tags: vec![tag.clone()],
            links: vec![link.clone()],
            postings: vec![
                amount_posting(&account, Decimal::from(100)),
                amount_posting("Equity:Opening", Decimal::from(-100)),
            ],
            metadata: BTreeMap::new(),
        });

        let text = full_file_serialize(std::slice::from_ref(&directive), &[]);
        let parsed = parse_file(&text)
            .map_err(|errors| TestCaseError::fail(format!("{text:?} failed to parse: {errors:?}")))?;
        prop_assert_eq!(parsed.len(), 1);
        match &parsed[0] {
            Directive::Transaction(txn) => {
                prop_assert_eq!(&txn.postings[0].account, &account);
                prop_assert_eq!(&txn.tags, &vec![tag]);
                prop_assert_eq!(&txn.links, &vec![link]);
            }
            other => prop_assert!(false, "expected a transaction, got {:?}", other),
        }
    }

    #[test]
    fn confusable_names_are_refused_by_parser_and_validators_alike(
        segment in "[A-Z][A-Za-z0-9-]{0,7}",
        label in "[A-Za-z0-9_-]{1,10}",
        confusable in confusable_character(),
        position in 0usize..8,
    ) {
        let mut characters: Vec<char> = segment.chars().collect();
        let index = position % characters.len();
        characters[index] = confusable;
        let account = format!("Assets:{}", characters.into_iter().collect::<String>());

        prop_assert!(
            ledger::parse::validate_account_name(&account).is_err(),
            "API side must refuse {account:?}"
        );
        prop_assert!(
            parse_file(&format!("2024-01-01 open {account}\n")).is_err(),
            "parse side must refuse {account:?}"
        );

        let confusable_label = format!("{label}{confusable}");
        prop_assert!(ledger::parse::validate_tag(&confusable_label).is_err());
        prop_assert!(ledger::parse::validate_link(&confusable_label).is_err());

        let body = "  Assets:Cash 1.00 USD\n  Equity:Opening -1.00 USD\n";
        for marker in ['#', '^'] {
            let text = format!("2024-01-15 * \"x\" {marker}{confusable_label}\n{body}");
            prop_assert!(
                parse_file(&text).is_err(),
                "parse side must refuse {marker}{confusable_label}"
            );
        }
    }
}

// ─── L-15: the serializer is injective over every reachable posting shape ────
//
// `compute_content_id` hashes the canonical serialization, so two distinct
// postings that render to the same bytes give two distinct directives ONE id —
// the second is dropped as a G-Set duplicate and a signature over one body
// authenticates the other. The two known collapses are `amount: None` carrying
// a cost/price and `CostSpec { amount: None, date: Some(..) }`; both are now
// refused by `weights::posting_weight`, which every transaction ingress runs.
// These properties pin the two halves of that closure: the shapes the parser can
// actually produce are injective under the real serializer, and the two refused
// shapes are refused for every value they can take.

/// Every posting shape `parse_posting_line` can emit, as a `.bean` posting line.
///
/// Deliberately generated as TEXT and round-tripped, because the claim is about
/// what a file can hold: an elided posting always parses with no cost and no
/// price, and `{` is either immediately closed or must read an amount.
fn posting_line() -> impl Strategy<Value = String> {
    let annotation = prop_oneof![
        Just(String::new()),
        Just(" {}".to_owned()),
        (1i64..500).prop_map(|n| format!(" {{{n}.00 USD}}")),
        (1i64..500).prop_map(|n| format!(" {{{n}.00 USD, 2020-03-04}}")),
        (1i64..500).prop_map(|n| format!(" @ {n}.00 USD")),
        (1i64..500).prop_map(|n| format!(" @@ {n}.00 USD")),
    ];
    prop_oneof![
        Just("  Assets:Stock".to_owned()),
        (1i64..500, annotation)
            .prop_map(|(number, annotation)| format!("  Assets:Stock {number} AAPL{annotation}")),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Distinct posting lines must never serialize to the same bytes.
    ///
    /// Round-trips each generated line through the real parser, re-serializes
    /// with the real serializer, and asserts that equal output implies equal
    /// parsed model — which is injectivity, stated as a property.
    #[test]
    fn serializer_is_injective_over_posting_shapes(
        left in posting_line(),
        right in posting_line(),
    ) {
        let render = |line: &str| -> Result<(Posting, String), TestCaseError> {
            let text = format!("2024-01-15 * \"x\"\n{line}\n  Equity:Opening\n");
            let parsed = parse_file(&text)
                .map_err(|errors| TestCaseError::fail(format!("{text:?}: {errors:?}")))?;
            let Directive::Transaction(txn) = &parsed[0] else {
                return Err(TestCaseError::fail("expected a transaction"));
            };
            let posting = txn.postings[0].clone();
            let mut one = Transaction { postings: vec![posting.clone()], ..txn.clone() };
            one.postings.truncate(1);
            Ok((posting, full_file_serialize(&[Directive::Transaction(one)], &[])))
        };

        let (left_posting, left_text) = render(&left)?;
        let (right_posting, right_text) = render(&right)?;

        if left_text == right_text {
            prop_assert_eq!(
                left_posting.clone(), right_posting,
                "{:?} and {:?} serialize identically but are different postings",
                left, right
            );
        }

        // Nothing the parser produces may hit the L-15 shape rule: the file
        // path cannot express either collapsed shape in the first place.
        prop_assert!(sum_weights(std::slice::from_ref(&left_posting)).is_ok());
    }

    /// The two refused shapes are refused for every value they can carry.
    #[test]
    fn collapsed_posting_shapes_are_always_refused(
        number in 1i64..500,
        day in 1u32..=28,
        total_price in any::<bool>(),
    ) {
        let cost = ledger::model::CostSpec {
            amount: Some(Amount { number: Decimal::from(number), currency: "USD".to_owned() }),
            date: None,
        };
        let price_amount = Amount { number: Decimal::from(number), currency: "USD".to_owned() };
        let price = if total_price {
            ledger::model::PriceSpec::Total(price_amount)
        } else {
            ledger::model::PriceSpec::Unit(price_amount)
        };

        let elided = Posting {
            account: "Equity:Opening".to_owned(),
            amount: None,
            cost: None,
            price: None,
            metadata: BTreeMap::new(),
        };

        // (a) elided amount carrying a cost, and carrying a price.
        for shaped in [
            Posting { cost: Some(cost.clone()), ..elided.clone() },
            Posting { price: Some(price), ..elided.clone() },
        ] {
            // It is genuinely a different value from the bare elided posting…
            prop_assert_ne!(&shaped, &elided);
            // …that serializes to exactly the same bytes…
            prop_assert_eq!(
                full_file_serialize(&[one_posting_transaction(shaped.clone())], &[]),
                full_file_serialize(&[one_posting_transaction(elided.clone())], &[]),
            );
            // …so it must be refused rather than stored.
            prop_assert!(sum_weights(std::slice::from_ref(&shaped)).is_err());
        }

        // (b) `CostSpec { amount: None, date: Some(..) }`.
        let dated_empty = Posting {
            account: "Assets:Stock".to_owned(),
            amount: Some(Amount { number: Decimal::from(number), currency: "AAPL".to_owned() }),
            cost: Some(ledger::model::CostSpec {
                amount: None,
                date: NaiveDate::from_ymd_opt(2020, 3, day),
            }),
            price: None,
            metadata: BTreeMap::new(),
        };
        let undated_empty = Posting {
            cost: Some(ledger::model::CostSpec { amount: None, date: None }),
            ..dated_empty.clone()
        };
        prop_assert_ne!(&dated_empty, &undated_empty);
        prop_assert_eq!(
            full_file_serialize(&[one_posting_transaction(dated_empty.clone())], &[]),
            full_file_serialize(&[one_posting_transaction(undated_empty.clone())], &[]),
        );
        prop_assert!(sum_weights(std::slice::from_ref(&dated_empty)).is_err());
        prop_assert!(sum_weights(std::slice::from_ref(&undated_empty)).is_ok());
    }
}

/// Wrap one posting in the smallest transaction that carries it.
fn one_posting_transaction(posting: Posting) -> Directive {
    Directive::Transaction(Transaction {
        date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
        flag: Flag::Complete,
        payee: None,
        narration: Some("shape".to_owned()),
        tags: Vec::new(),
        links: Vec::new(),
        postings: vec![posting],
        metadata: BTreeMap::new(),
    })
}

/// Year 0 is the one out-of-range year that does *not* brick the file: chrono
/// formats it unsigned as `0000-01-01`, which `read_date` happily reads back.
/// It is still rejected, because Beancount (like `datetime.date`) has no year 0,
/// so admitting it would put a date in the ledger that no other tool can read.
#[test]
fn year_zero_round_trips_but_is_still_rejected() {
    let date = NaiveDate::from_ymd_opt(0, 1, 1).unwrap();
    let directive = open_on(date);

    let text = full_file_serialize(std::slice::from_ref(&directive), &[]);
    assert!(
        text.starts_with("0000-01-01 "),
        "unexpected output: {text:?}"
    );
    assert!(
        parse_file(&text).is_ok(),
        "year 0 does not brick the parser"
    );

    assert!(
        validate_directive_dates(&directive).is_err(),
        "year 0 is still outside the supported 0001..=9999 range"
    );
}
