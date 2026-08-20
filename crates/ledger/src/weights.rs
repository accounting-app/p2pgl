//! Posting weight computation for balance checking (§3.5.1).
//!
//! Weights are the amounts that must sum to zero **per currency** for I1.

use rust_decimal::Decimal;
use std::collections::HashMap;

use crate::model::{Amount, CostSpec, Posting, PriceSpec};

/// A weight: an amount in a single currency that contributes to the I1 sum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Weight {
    pub amount: Decimal,
    pub currency: String,
}

/// Compute the I1 weight for a single posting (§3.5.1).
///
/// Returns `Err` if both cost and price are specified on the same posting.
pub fn posting_weight(posting: &Posting) -> Result<Option<Weight>, WeightError> {
    let amount = match &posting.amount {
        Some(a) => a,
        None => return Ok(None), // elided — resolved separately
    };

    // Reject cost + price on same posting.
    if posting.cost.is_some() && posting.price.is_some() {
        return Err(WeightError::CostAndPriceOnSamePosting {
            account: posting.account.clone(),
        });
    }

    // Cost: NUMBER × COST_NUMBER in COST_CURRENCY (sign of NUMBER preserved).
    if let Some(ref cost) = posting.cost {
        return Ok(Some(cost_weight(amount, cost)?));
    }

    // Price: @ or @@
    if let Some(ref price) = posting.price {
        return Ok(Some(price_weight(amount, price)?));
    }

    // Plain: NUMBER in CURRENCY.
    Ok(Some(Weight {
        amount: amount.number,
        currency: amount.currency.clone(),
    }))
}

/// Cost weight: `NUMBER × COST_NUMBER` in `COST_CURRENCY`.
///
/// Returns `Err(WeightError::AmountOverflow)` if the product exceeds `Decimal`'s
/// range, so untrusted amounts cannot panic the arithmetic.
fn cost_weight(amount: &Amount, cost: &CostSpec) -> Result<Weight, WeightError> {
    match &cost.amount {
        Some(cost_amount) => {
            let product =
                amount
                    .number
                    .checked_mul(cost_amount.number)
                    .ok_or_else(|| WeightError::AmountOverflow {
                        detail: format!(
                            "cost weight {} × {} overflows",
                            amount.number, cost_amount.number
                        ),
                    })?;
            Ok(Weight {
                amount: product,
                currency: cost_amount.currency.clone(),
            })
        }
        None => {
            // Empty cost `{}` — treat as the raw amount in its own currency.
            Ok(Weight {
                amount: amount.number,
                currency: amount.currency.clone(),
            })
        }
    }
}

/// Price weight: `@ NUMBER × PRICE_NUMBER` in `PRICE_CURRENCY`,
/// or `@@ TOTAL_NUMBER` in `TOTAL_CURRENCY`.
///
/// Returns `Err(WeightError::AmountOverflow)` if the unit-price product exceeds
/// `Decimal`'s range. (The total-price arm only negates/abs-es, which cannot
/// overflow a sign-magnitude `Decimal`.)
fn price_weight(amount: &Amount, price: &PriceSpec) -> Result<Weight, WeightError> {
    match price {
        PriceSpec::Unit(price_amount) => {
            let product =
                amount
                    .number
                    .checked_mul(price_amount.number)
                    .ok_or_else(|| WeightError::AmountOverflow {
                        detail: format!(
                            "price weight {} × {} overflows",
                            amount.number, price_amount.number
                        ),
                    })?;
            Ok(Weight {
                amount: product,
                currency: price_amount.currency.clone(),
            })
        }
        PriceSpec::Total(total_amount) => {
            // Sign of total follows sign of the posting amount.
            let signed = if amount.number.is_sign_negative() {
                -total_amount.number.abs()
            } else {
                total_amount.number.abs()
            };
            Ok(Weight {
                amount: signed,
                currency: total_amount.currency.clone(),
            })
        }
    }
}

/// Sum posting weights per currency. Returns `(sums, elided_count)`.
///
/// The `sums` map has the running total per currency. Elided postings are skipped.
pub fn sum_weights(postings: &[Posting]) -> Result<(HashMap<String, Decimal>, usize), WeightError> {
    let mut sums: HashMap<String, Decimal> = HashMap::new();
    let mut elided_count = 0;

    for posting in postings {
        match posting_weight(posting)? {
            Some(weight) => {
                let running = sums.entry(weight.currency).or_insert(Decimal::ZERO);
                *running =
                    running
                        .checked_add(weight.amount)
                        .ok_or_else(|| WeightError::AmountOverflow {
                            detail: "per-currency weight sum overflows".to_owned(),
                        })?;
            }
            None => {
                elided_count += 1;
            }
        }
    }

    Ok((sums, elided_count))
}

/// Resolve a single elided posting so that all per-currency weight sums become zero.
///
/// Returns the `Amount` to fill in, or an error if it cannot be resolved.
pub fn resolve_elided(sums: &HashMap<String, Decimal>) -> Result<Amount, WeightError> {
    // The elided posting must zero-out exactly one currency.
    // Filter to non-zero currencies.
    let nonzero: Vec<(&String, &Decimal)> = sums
        .iter()
        .filter(|(_, &amount)| amount != Decimal::ZERO)
        .collect();

    match nonzero.len() {
        0 => {
            // All sums are already zero — nothing to fill in. This shouldn't happen
            // if there's truly an elided posting, but treat it as zero in the first currency.
            if let Some((currency, _)) = sums.iter().next() {
                Ok(Amount {
                    number: Decimal::ZERO,
                    currency: currency.clone(),
                })
            } else {
                Err(WeightError::ElisionInvalid {
                    reason: "No currencies in transaction to resolve elision".to_owned(),
                })
            }
        }
        1 => {
            let (currency, &imbalance) = nonzero[0];
            Ok(Amount {
                number: -imbalance,
                currency: currency.clone(),
            })
        }
        _ => {
            // Multiple currencies are imbalanced — can't resolve with one posting.
            Err(WeightError::ElisionInvalid {
                reason: format!(
                    "Elided posting cannot balance multiple currencies: {:?}",
                    nonzero
                        .iter()
                        .map(|(c, a)| format!("{} {c}", a))
                        .collect::<Vec<_>>()
                ),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeightError {
    CostAndPriceOnSamePosting { account: String },
    ElisionInvalid { reason: String },
    /// Weight arithmetic (multiply or sum) exceeded `Decimal`'s representable range.
    AmountOverflow { detail: String },
}

impl std::fmt::Display for WeightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WeightError::CostAndPriceOnSamePosting { account } => {
                write!(f, "Posting on {account} has both cost and price")
            }
            WeightError::ElisionInvalid { reason } => {
                write!(f, "Cannot resolve elided posting: {reason}")
            }
            WeightError::AmountOverflow { detail } => {
                write!(f, "Amount arithmetic overflow: {detail}")
            }
        }
    }
}

impl std::error::Error for WeightError {}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn plain_posting(account: &str, number: Decimal, currency: &str) -> Posting {
        Posting {
            account: account.to_owned(),
            amount: Some(Amount {
                number,
                currency: currency.to_owned(),
            }),
            cost: None,
            price: None,
            metadata: BTreeMap::new(),
        }
    }

    fn elided_posting(account: &str) -> Posting {
        Posting {
            account: account.to_owned(),
            amount: None,
            cost: None,
            price: None,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn test_plain_weight() {
        let posting = plain_posting("Assets:Cash", dec!(100), "USD");
        let weight = posting_weight(&posting).unwrap().unwrap();
        assert_eq!(weight.amount, dec!(100));
        assert_eq!(weight.currency, "USD");
    }

    #[test]
    fn test_cost_weight() {
        let posting = Posting {
            account: "Assets:Stock".to_owned(),
            amount: Some(Amount {
                number: dec!(10),
                currency: "AAPL".to_owned(),
            }),
            cost: Some(CostSpec {
                amount: Some(Amount {
                    number: dec!(150),
                    currency: "USD".to_owned(),
                }),
                date: None,
            }),
            price: None,
            metadata: BTreeMap::new(),
        };
        let weight = posting_weight(&posting).unwrap().unwrap();
        assert_eq!(weight.amount, dec!(1500)); // 10 × 150
        assert_eq!(weight.currency, "USD");
    }

    #[test]
    fn test_unit_price_weight() {
        let posting = Posting {
            account: "Assets:Foreign".to_owned(),
            amount: Some(Amount {
                number: dec!(100),
                currency: "EUR".to_owned(),
            }),
            cost: None,
            price: Some(PriceSpec::Unit(Amount {
                number: dec!(1.10),
                currency: "USD".to_owned(),
            })),
            metadata: BTreeMap::new(),
        };
        let weight = posting_weight(&posting).unwrap().unwrap();
        assert_eq!(weight.amount, dec!(110.00)); // 100 × 1.10
        assert_eq!(weight.currency, "USD");
    }

    #[test]
    fn test_total_price_weight() {
        let posting = Posting {
            account: "Assets:Foreign".to_owned(),
            amount: Some(Amount {
                number: dec!(100),
                currency: "EUR".to_owned(),
            }),
            cost: None,
            price: Some(PriceSpec::Total(Amount {
                number: dec!(110),
                currency: "USD".to_owned(),
            })),
            metadata: BTreeMap::new(),
        };
        let weight = posting_weight(&posting).unwrap().unwrap();
        assert_eq!(weight.amount, dec!(110));
        assert_eq!(weight.currency, "USD");
    }

    #[test]
    fn test_total_price_negative_follows_posting_sign() {
        let posting = Posting {
            account: "Assets:Foreign".to_owned(),
            amount: Some(Amount {
                number: dec!(-100),
                currency: "EUR".to_owned(),
            }),
            cost: None,
            price: Some(PriceSpec::Total(Amount {
                number: dec!(110),
                currency: "USD".to_owned(),
            })),
            metadata: BTreeMap::new(),
        };
        let weight = posting_weight(&posting).unwrap().unwrap();
        assert_eq!(weight.amount, dec!(-110));
    }

    #[test]
    fn test_cost_and_price_rejected() {
        let posting = Posting {
            account: "Assets:Stock".to_owned(),
            amount: Some(Amount {
                number: dec!(10),
                currency: "AAPL".to_owned(),
            }),
            cost: Some(CostSpec {
                amount: Some(Amount {
                    number: dec!(150),
                    currency: "USD".to_owned(),
                }),
                date: None,
            }),
            price: Some(PriceSpec::Unit(Amount {
                number: dec!(160),
                currency: "USD".to_owned(),
            })),
            metadata: BTreeMap::new(),
        };
        let err = posting_weight(&posting).unwrap_err();
        assert!(matches!(err, WeightError::CostAndPriceOnSamePosting { .. }));
    }

    #[test]
    fn test_elided_weight_is_none() {
        let posting = elided_posting("Equity:Opening");
        assert!(posting_weight(&posting).unwrap().is_none());
    }

    #[test]
    fn test_sum_weights_balanced() {
        let postings = vec![
            plain_posting("Assets:Cash", dec!(100), "USD"),
            plain_posting("Equity:Opening", dec!(-100), "USD"),
        ];
        let (sums, elided) = sum_weights(&postings).unwrap();
        assert_eq!(elided, 0);
        assert_eq!(sums.get("USD"), Some(&Decimal::ZERO));
    }

    #[test]
    fn test_sum_weights_unbalanced() {
        let postings = vec![
            plain_posting("Assets:Cash", dec!(100), "USD"),
            plain_posting("Equity:Opening", dec!(-50), "USD"),
        ];
        let (sums, _) = sum_weights(&postings).unwrap();
        assert_eq!(sums.get("USD"), Some(&dec!(50)));
    }

    #[test]
    fn test_sum_weights_multi_currency() {
        let postings = vec![
            plain_posting("Assets:Cash", dec!(100), "USD"),
            plain_posting("Assets:Foreign", dec!(90), "EUR"),
            plain_posting("Equity:Opening", dec!(-100), "USD"),
            plain_posting("Equity:Opening", dec!(-90), "EUR"),
        ];
        let (sums, _) = sum_weights(&postings).unwrap();
        assert_eq!(sums.get("USD"), Some(&Decimal::ZERO));
        assert_eq!(sums.get("EUR"), Some(&Decimal::ZERO));
    }

    #[test]
    fn test_resolve_elided_single_currency() {
        let postings = vec![
            plain_posting("Assets:Cash", dec!(100), "USD"),
            elided_posting("Equity:Opening"),
        ];
        let (sums, elided) = sum_weights(&postings).unwrap();
        assert_eq!(elided, 1);
        let resolved = resolve_elided(&sums).unwrap();
        assert_eq!(resolved.number, dec!(-100));
        assert_eq!(resolved.currency, "USD");
    }

    #[test]
    fn test_resolve_elided_multi_currency_fails() {
        let postings = vec![
            plain_posting("Assets:Cash", dec!(100), "USD"),
            plain_posting("Assets:Foreign", dec!(90), "EUR"),
            elided_posting("Equity:Opening"),
        ];
        let (sums, _) = sum_weights(&postings).unwrap();
        let err = resolve_elided(&sums).unwrap_err();
        assert!(matches!(err, WeightError::ElisionInvalid { .. }));
    }

    #[test]
    fn test_sum_weights_overflow_is_error_not_panic() {
        // Two same-sign postings at Decimal::MAX overflow the per-currency sum.
        // Must surface as a clean error, not a panic (H1 regression).
        let postings = vec![
            plain_posting("Assets:A", Decimal::MAX, "USD"),
            plain_posting("Assets:B", Decimal::MAX, "USD"),
        ];
        let err = sum_weights(&postings).unwrap_err();
        assert!(matches!(err, WeightError::AmountOverflow { .. }));
    }

    #[test]
    fn test_cost_weight_overflow_is_error_not_panic() {
        // 10 AAPL {Decimal::MAX USD} overflows the cost multiply (10 × MAX).
        let posting = Posting {
            account: "Assets:Stock".to_owned(),
            amount: Some(Amount {
                number: dec!(10),
                currency: "AAPL".to_owned(),
            }),
            cost: Some(CostSpec {
                amount: Some(Amount {
                    number: Decimal::MAX,
                    currency: "USD".to_owned(),
                }),
                date: None,
            }),
            price: None,
            metadata: BTreeMap::new(),
        };
        let err = posting_weight(&posting).unwrap_err();
        assert!(matches!(err, WeightError::AmountOverflow { .. }));
    }

    #[test]
    fn test_unit_price_weight_overflow_is_error_not_panic() {
        // 10 EUR @ Decimal::MAX USD overflows the price multiply.
        let posting = Posting {
            account: "Assets:Foreign".to_owned(),
            amount: Some(Amount {
                number: dec!(10),
                currency: "EUR".to_owned(),
            }),
            cost: None,
            price: Some(PriceSpec::Unit(Amount {
                number: Decimal::MAX,
                currency: "USD".to_owned(),
            })),
            metadata: BTreeMap::new(),
        };
        let err = posting_weight(&posting).unwrap_err();
        assert!(matches!(err, WeightError::AmountOverflow { .. }));
    }

    #[test]
    fn test_negative_cost_weight() {
        // Selling stock: -10 AAPL {150 USD} → -1500 USD
        let posting = Posting {
            account: "Assets:Stock".to_owned(),
            amount: Some(Amount {
                number: dec!(-10),
                currency: "AAPL".to_owned(),
            }),
            cost: Some(CostSpec {
                amount: Some(Amount {
                    number: dec!(150),
                    currency: "USD".to_owned(),
                }),
                date: None,
            }),
            price: None,
            metadata: BTreeMap::new(),
        };
        let weight = posting_weight(&posting).unwrap().unwrap();
        assert_eq!(weight.amount, dec!(-1500));
        assert_eq!(weight.currency, "USD");
    }
}
