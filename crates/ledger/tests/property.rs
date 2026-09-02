//! Property / fuzz harness (T17): malformed input must never panic.
//!
//! These are randomized panic regression tests. `parse_file` runs over untrusted
//! ledger text (API callers, remote peers, external file edits), and weight
//! summation runs over untrusted amounts — neither may panic on hostile input.
//! A panic here fails the test.

use std::collections::BTreeMap;

use chrono::NaiveDate;
use ledger::model::{Amount, Directive, Open, Posting};
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
