//! Property / fuzz harness (T17): malformed input must never panic.
//!
//! These are randomized panic regression tests. `parse_file` runs over untrusted
//! ledger text (API callers, remote peers, external file edits), and weight
//! summation runs over untrusted amounts — neither may panic on hostile input.
//! A panic here fails the test.

use std::collections::BTreeMap;

use ledger::model::{Amount, Posting};
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
