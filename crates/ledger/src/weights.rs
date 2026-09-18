//! Posting weight computation for balance checking (§3.5.1).
//!
//! Weights are the amounts that must sum to zero **per currency** for I1.

use rust_decimal::Decimal;
use std::collections::BTreeMap;

use crate::model::{Amount, CostSpec, Posting, PriceSpec};
use crate::parse::is_valid_cost_or_price_number;

/// A weight: an amount in a single currency that contributes to the I1 sum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Weight {
    pub amount: Decimal,
    pub currency: String,
}

/// Compute the I1 weight for a single posting (§3.5.1).
///
/// Returns `Err` if both cost and price are specified on the same posting, or if
/// a cost/price number is zero or negative (L-16).
pub fn posting_weight(posting: &Posting) -> Result<Option<Weight>, WeightError> {
    // Reject cost + price on same posting.
    if posting.cost.is_some() && posting.price.is_some() {
        return Err(WeightError::CostAndPriceOnSamePosting {
            account: posting.account.clone(),
        });
    }

    // L-15: refuse the two posting shapes the canonical serializer cannot tell
    // apart from a different one.
    check_annotation_shape(posting)?;

    // L-16: the cost/price *number* is checked before the elided early-return
    // below, deliberately. An elided posting still carries its `{...}`/`@` into
    // the file and back out of it, so the annotation has to be refused wherever
    // it appears — not only where it currently reaches the multiply.
    check_cost_and_price_numbers(posting)?;

    let amount = match &posting.amount {
        Some(a) => a,
        None => return Ok(None), // elided — resolved separately
    };

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

/// Reject the posting shapes the canonical serializer cannot distinguish (L-15).
///
/// `compute_content_id` hashes the economic serialization, so the serializer has
/// to be *injective over the shapes a directive can hold*: if two distinct
/// `Posting` values render to the same bytes, the two directives containing them
/// get one content id. In a G-Set DAG keyed by that id the second arrival is
/// silently dropped as a duplicate, and a signature made over one body
/// authenticates the other. `serialize::tests::test_l15_*` demonstrate both
/// collapses against the live serializer.
///
/// The two shapes:
///
/// * **an elided amount carrying a cost or price** — `serialize_posting` writes
///   the whole `{...}` / `@` block inside `if let Some(amount)`, so
///   `Equity:Opening` with `{150 USD}` and bare `Equity:Opening` are one line of
///   output. The shape is economically meaningless anyway: a cost or price is a
///   conversion *rate* for a number that is not there, and I2's resolution fills
///   the amount in from the imbalance without consulting either.
/// * **`CostSpec { amount: None, date: Some(..) }`** — `cost.date` is written
///   inside `if let Some(cost_amount)`, so an amount-less cost drops its date and
///   emits a bare `{}`. A lot date with no lot cost identifies nothing.
///
/// Closed by **rejection, not by a new spelling**, deliberately: the serialized
/// form is the content-hash input, so emitting (say) `{, 2020-03-04}` would
/// change no reachable id — neither shape can be constructed any more — while
/// putting every already-persisted id at risk of a format-compat mistake. The
/// parser cannot produce either shape either (an elided posting always parses
/// with `cost: None, price: None`, and `{` immediately followed by anything but
/// `}` must read an amount), so this guards the in-memory API surface, which is
/// the only way in. `property::serializer_is_injective_over_posting_shapes`
/// pins the parser half.
fn check_annotation_shape(posting: &Posting) -> Result<(), WeightError> {
    if posting.amount.is_none() && (posting.cost.is_some() || posting.price.is_some()) {
        return Err(WeightError::IndistinguishablePostingShape {
            account: posting.account.clone(),
            detail: "a posting with an elided amount must not carry a cost or price \
                     (the canonical serializer emits neither, so the annotation is \
                     invisible to the content id)",
        });
    }
    if let Some(ref cost) = posting.cost {
        if cost.amount.is_none() && cost.date.is_some() {
            return Err(WeightError::IndistinguishablePostingShape {
                account: posting.account.clone(),
                detail: "an empty cost `{}` must not carry a date (the canonical \
                         serializer emits a bare `{}`, so the date is invisible to \
                         the content id)",
            });
        }
    }
    Ok(())
}

/// Reject a zero or negative cost/price number on a posting (L-16).
///
/// A cost or price is a *conversion rate*, and the I1 identity is what makes it
/// load-bearing: the posting's own number is stated in one currency and its
/// weight is booked in another, so the rate is the only thing tying the two
/// sides together. A non-positive rate breaks that tie in a way the balance
/// check cannot see.
///
/// * `{0 USD}` / `@ 0 USD` — the posting contributes a weight of exactly zero
///   whatever its number says, so `1 AAPL {0 USD}` and `10_000_000 AAPL {0 USD}`
///   balance against the identical counter-posting. Units of the held commodity
///   are minted (or destroyed) at will while the transaction stays perfectly
///   balanced; the read model then reports the position as real holdings.
/// * a negative number — flips the weight's sign relative to the posting's, so
///   a debit books as a credit. Two postings that should have cancelled now add.
///   `@@` is worse than that: [`price_weight`]'s total arm takes the *absolute*
///   value and re-signs it from the posting, so `@@ -110 USD` and `@@ 110 USD`
///   compute the identical weight while serializing — and therefore hashing —
///   differently.
///
/// A rate of zero or below has no economic reading in a double-entry ledger, so
/// this is a refusal rather than a normalisation. A genuinely free acquisition
/// is spelled as a posting with no cost annotation at all, and a genuinely
/// negative position is spelled with a negative posting number at a positive
/// rate (which is how `test_negative_cost_weight` sells stock).
fn check_cost_and_price_numbers(posting: &Posting) -> Result<(), WeightError> {
    let reject = |label: &'static str, amount: &Amount| WeightError::NonPositiveCostOrPrice {
        account: posting.account.clone(),
        label,
        amount: amount.number,
        currency: amount.currency.clone(),
    };

    // An empty cost `{}` carries no number and is unaffected.
    if let Some(cost_amount) = posting.cost.as_ref().and_then(|cost| cost.amount.as_ref()) {
        if !is_valid_cost_or_price_number(cost_amount.number) {
            return Err(reject("cost", cost_amount));
        }
    }
    if let Some(ref price) = posting.price {
        let (label, price_amount) = match price {
            PriceSpec::Unit(amount) => ("unit price", amount),
            PriceSpec::Total(amount) => ("total price", amount),
        };
        if !is_valid_cost_or_price_number(price_amount.number) {
            return Err(reject(label, price_amount));
        }
    }
    Ok(())
}

/// Cost weight: `NUMBER × COST_NUMBER` in `COST_CURRENCY`.
///
/// Returns `Err(WeightError::AmountOverflow)` if the product exceeds `Decimal`'s
/// range, so untrusted amounts cannot panic the arithmetic.
fn cost_weight(amount: &Amount, cost: &CostSpec) -> Result<Weight, WeightError> {
    match &cost.amount {
        Some(cost_amount) => {
            let product = amount
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
            let product = amount
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
///
/// The map is a [`BTreeMap`], not a `HashMap`, and that is load-bearing (L-27):
/// [`resolve_elided`] and the I1 imbalance report both iterate it, and a
/// `HashMap`'s iteration order depends on a per-instance random hasher seed. A
/// currency picked out of that order would make the *same* logical transaction
/// resolve — and therefore hash — differently across runs, restarts and nodes.
/// Ordering by currency makes every downstream choice deterministic by
/// construction rather than by luck.
pub fn sum_weights(
    postings: &[Posting],
) -> Result<(BTreeMap<String, Decimal>, usize), WeightError> {
    let mut sums: BTreeMap<String, Decimal> = BTreeMap::new();
    let mut elided_count = 0;

    for posting in postings {
        match posting_weight(posting)? {
            Some(weight) => {
                let running = sums.entry(weight.currency).or_insert(Decimal::ZERO);
                *running = running.checked_add(weight.amount).ok_or_else(|| {
                    WeightError::AmountOverflow {
                        detail: "per-currency weight sum overflows".to_owned(),
                    }
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
///
/// # Determinism (L-27)
///
/// The resolved amount is hashed into the directive's content id, so the choice
/// of currency has to be a *function of the transaction* — never of iteration
/// order. There is therefore exactly one accepted shape: precisely one currency
/// left imbalanced, whose sign-flipped imbalance is the fill. Every other shape
/// is refused rather than guessed:
///
/// * **no imbalanced currency** — every currency already sums to zero, so an
///   amount of `0` in *any* currency present would "balance" the transaction and
///   nothing in the body says which. This used to take the first key out of a
///   randomly-seeded `HashMap`, which is precisely the bug: the same logical
///   transaction hashed to different ids on different runs, restarts and nodes.
///   Refused as ambiguous (a zero posting carries no economic information, so
///   nothing legitimate is lost — spell the currency out to keep it).
/// * **several imbalanced currencies** — one posting cannot zero two sums; the
///   I1 balance check would reject the filled transaction anyway, so the error
///   is raised here where it can name all of them.
///
/// `sums` is a [`BTreeMap`], so the currencies named in the multi-currency error
/// are listed in lexicographic order and the message is byte-stable too.
pub fn resolve_elided(sums: &BTreeMap<String, Decimal>) -> Result<Amount, WeightError> {
    // The elided posting must zero-out exactly one currency. Filter to the
    // non-zero currencies, in lexicographic order (BTreeMap iteration).
    let imbalanced: Vec<(&String, Decimal)> = sums
        .iter()
        .filter(|(_, &amount)| amount != Decimal::ZERO)
        .map(|(currency, &amount)| (currency, amount))
        .collect();

    match imbalanced.as_slice() {
        [] if sums.is_empty() => Err(WeightError::ElisionInvalid {
            reason: "No currencies in transaction to resolve elision".to_owned(),
        }),
        [] => Err(WeightError::ElisionInvalid {
            reason: format!(
                "Every currency already balances ({}), so the elided posting's \
                 currency is ambiguous — write the amount out explicitly",
                sums.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        }),
        [(currency, imbalance)] => Ok(Amount {
            number: -*imbalance,
            currency: (*currency).clone(),
        }),
        _ => {
            // Multiple currencies are imbalanced — can't resolve with one posting.
            Err(WeightError::ElisionInvalid {
                reason: format!(
                    "Elided posting cannot balance multiple currencies: {:?}",
                    imbalanced
                        .iter()
                        .map(|(currency, amount)| format!("{amount} {currency}"))
                        .collect::<Vec<_>>()
                ),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeightError {
    CostAndPriceOnSamePosting {
        account: String,
    },
    ElisionInvalid {
        reason: String,
    },
    /// Weight arithmetic (multiply or sum) exceeded `Decimal`'s representable range.
    AmountOverflow {
        detail: String,
    },
    /// §3.5.1 / L-16: a cost or price number that is zero or negative.
    ///
    /// See [`check_cost_and_price_numbers`] for why such a rate mints or
    /// destroys units through the I1 balance identity.
    NonPositiveCostOrPrice {
        account: String,
        /// `"cost"`, `"unit price"` or `"total price"`.
        label: &'static str,
        amount: Decimal,
        currency: String,
    },
    /// §3.3.2 / L-15: a posting shape the canonical serializer renders
    /// identically to a materially different one, so two distinct directives
    /// would share a content id. See [`check_annotation_shape`].
    IndistinguishablePostingShape {
        account: String,
        detail: &'static str,
    },
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
            WeightError::NonPositiveCostOrPrice {
                account,
                label,
                amount,
                currency,
            } => write!(
                f,
                "Posting on {account} has a {label} of {amount} {currency}: \
                 cost and price numbers must be greater than zero"
            ),
            WeightError::IndistinguishablePostingShape { account, detail } => {
                write!(f, "Posting on {account}: {detail}")
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

    // ── L-27: the fill must be a function of the transaction, not of iteration order ──

    #[test]
    fn test_sum_weights_is_ordered_by_currency() {
        // The map backing every downstream choice is lexicographically ordered
        // by construction, so nothing can depend on a random hasher seed.
        let postings = vec![
            plain_posting("Assets:Cash", dec!(1), "ZAR"),
            plain_posting("Assets:Cash", dec!(1), "USD"),
            plain_posting("Assets:Cash", dec!(1), "AUD"),
            plain_posting("Assets:Cash", dec!(1), "EUR"),
        ];
        let (sums, _) = sum_weights(&postings).unwrap();
        let currencies: Vec<&str> = sums.keys().map(String::as_str).collect();
        assert_eq!(currencies, ["AUD", "EUR", "USD", "ZAR"]);
    }

    #[test]
    fn test_resolve_elided_rejects_zero_imbalance() {
        // L-27: every currency already sums to zero, so a `0 USD` fill and a
        // `0 EUR` fill would both "balance" — and they hash differently. The old
        // code took whichever `HashMap::iter().next()` handed back.
        let postings = vec![
            plain_posting("Assets:Cash", dec!(100), "USD"),
            plain_posting("Expenses:Food", dec!(-100), "USD"),
            plain_posting("Assets:Foreign", dec!(50), "EUR"),
            plain_posting("Income:Salary", dec!(-50), "EUR"),
            elided_posting("Equity:Opening"),
        ];
        let (sums, elided) = sum_weights(&postings).unwrap();
        assert_eq!(elided, 1);
        let err = resolve_elided(&sums).unwrap_err();
        match err {
            WeightError::ElisionInvalid { ref reason } => {
                assert!(
                    reason.contains("EUR, USD") && reason.contains("ambiguous"),
                    "error must name the balanced currencies in order: {reason}"
                );
            }
            other => panic!("expected ElisionInvalid, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_elided_rejects_empty_sums() {
        // Nothing but elided postings: there is not even a currency to name.
        let postings = vec![elided_posting("Equity:Opening")];
        let (sums, _) = sum_weights(&postings).unwrap();
        let err = resolve_elided(&sums).unwrap_err();
        assert!(matches!(
            err,
            WeightError::ElisionInvalid { ref reason } if reason.contains("No currencies")
        ));
    }

    #[test]
    fn test_resolve_elided_is_stable_over_many_rebuilds() {
        // The fill is rebuilt from scratch 256 times — a per-instance hasher
        // seed would show up here as a currency (and therefore a content id)
        // that changes between otherwise identical transactions.
        let postings = vec![
            plain_posting("Assets:Cash", dec!(100), "USD"),
            plain_posting("Assets:Foreign", dec!(50), "EUR"),
            plain_posting("Income:Salary", dec!(-50), "EUR"),
            plain_posting("Assets:Other", dec!(7), "ZAR"),
            plain_posting("Income:Other", dec!(-7), "ZAR"),
            elided_posting("Equity:Opening"),
        ];
        for _ in 0..256 {
            let (sums, _) = sum_weights(&postings).unwrap();
            let resolved = resolve_elided(&sums).unwrap();
            assert_eq!(resolved.currency, "USD");
            assert_eq!(resolved.number, dec!(-100));
        }
    }

    #[test]
    fn test_resolve_elided_multi_currency_error_is_byte_stable() {
        // The error text is part of the API surface (it reaches GraphQL
        // callers), and a `HashMap` would shuffle the currency list per run.
        let postings = vec![
            plain_posting("Assets:Cash", dec!(100), "USD"),
            plain_posting("Assets:Foreign", dec!(90), "EUR"),
            plain_posting("Assets:Other", dec!(7), "AUD"),
            elided_posting("Equity:Opening"),
        ];
        let mut messages = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let (sums, _) = sum_weights(&postings).unwrap();
            messages.insert(resolve_elided(&sums).unwrap_err().to_string());
        }
        assert_eq!(messages.len(), 1, "message must not vary: {messages:?}");
        let message = messages.into_iter().next().unwrap();
        assert!(
            message.contains("[\"7 AUD\", \"90 EUR\", \"100 USD\"]"),
            "currencies must be listed lexicographically: {message}"
        );
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

    // ── L-15: shapes the serializer cannot distinguish are refused ───────

    #[test]
    fn test_elided_posting_with_cost_or_price_is_rejected() {
        // The shape `serialize::tests::test_l15_elided_posting_swallows_its_
        // cost_and_price` shows collapsing into a bare account line.
        let mut with_cost = elided_posting("Equity:Opening");
        with_cost.cost = Some(CostSpec {
            amount: Some(Amount {
                number: dec!(150),
                currency: "USD".to_owned(),
            }),
            date: None,
        });
        let mut with_price = elided_posting("Equity:Opening");
        with_price.price = Some(PriceSpec::Unit(Amount {
            number: dec!(1.10),
            currency: "USD".to_owned(),
        }));

        for posting in [with_cost, with_price] {
            let err = posting_weight(&posting).unwrap_err();
            assert!(
                matches!(err, WeightError::IndistinguishablePostingShape { ref account, .. }
                    if account == "Equity:Opening"),
                "got {err:?}"
            );
            assert!(err.to_string().contains("elided amount"), "{err}");
        }
    }

    #[test]
    fn test_empty_cost_with_a_date_is_rejected() {
        // `serialize::tests::test_l15_empty_cost_swallows_its_date` shows the
        // date being dropped from the emitted `{}`.
        let mut posting = posting_with_cost(dec!(1));
        posting.cost = Some(CostSpec {
            amount: None,
            date: Some(chrono::NaiveDate::from_ymd_opt(2020, 3, 4).unwrap()),
        });
        let err = posting_weight(&posting).unwrap_err();
        assert!(
            matches!(err, WeightError::IndistinguishablePostingShape { .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains("must not carry a date"), "{err}");
    }

    #[test]
    fn test_ordinary_elided_and_empty_cost_shapes_still_work() {
        // No over-rejection: a plain elided posting and a plain `{}` are the
        // legitimate neighbours of the two refused shapes, and both stay legal.
        assert!(posting_weight(&elided_posting("Equity:Opening"))
            .unwrap()
            .is_none());
        let mut empty_cost = posting_with_cost(dec!(1));
        empty_cost.cost = Some(CostSpec {
            amount: None,
            date: None,
        });
        assert_eq!(
            posting_weight(&empty_cost).unwrap().unwrap().currency,
            "AAPL"
        );
    }

    // ── L-16: a cost/price rate must be strictly positive ────────────────

    fn posting_with_cost(number: Decimal) -> Posting {
        Posting {
            account: "Assets:Stock".to_owned(),
            amount: Some(Amount {
                number: dec!(10),
                currency: "AAPL".to_owned(),
            }),
            cost: Some(CostSpec {
                amount: Some(Amount {
                    number,
                    currency: "USD".to_owned(),
                }),
                date: None,
            }),
            price: None,
            metadata: BTreeMap::new(),
        }
    }

    fn posting_with_price(price: PriceSpec) -> Posting {
        Posting {
            account: "Assets:Foreign".to_owned(),
            amount: Some(Amount {
                number: dec!(100),
                currency: "EUR".to_owned(),
            }),
            cost: None,
            price: Some(price),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn test_zero_cost_is_rejected() {
        // `10 AAPL {0 USD}` weighs 0 USD, so it balances against *nothing* —
        // and so would `10_000_000 AAPL {0 USD}`. The I1 check cannot see the
        // difference, and the read model reports the AAPL as real holdings.
        let err = posting_weight(&posting_with_cost(dec!(0))).unwrap_err();
        match err {
            WeightError::NonPositiveCostOrPrice {
                ref account,
                label,
                amount,
                ref currency,
            } => {
                assert_eq!(account, "Assets:Stock");
                assert_eq!(label, "cost");
                assert_eq!(amount, dec!(0));
                assert_eq!(currency, "USD");
            }
            other => panic!("expected NonPositiveCostOrPrice, got {other:?}"),
        }
        assert!(err.to_string().contains("must be greater than zero"));
    }

    #[test]
    fn test_negative_cost_number_is_rejected() {
        // Distinct from `test_negative_cost_weight`, which sells stock with a
        // negative POSTING number at a positive rate — that stays legal.
        let err = posting_weight(&posting_with_cost(dec!(-150))).unwrap_err();
        assert!(matches!(
            err,
            WeightError::NonPositiveCostOrPrice { label: "cost", .. }
        ));
    }

    #[test]
    fn test_zero_and_negative_prices_are_rejected() {
        for number in [dec!(0), dec!(-1.10)] {
            let err = posting_weight(&posting_with_price(PriceSpec::Unit(Amount {
                number,
                currency: "USD".to_owned(),
            })))
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    WeightError::NonPositiveCostOrPrice {
                        label: "unit price",
                        ..
                    }
                ),
                "got {err:?}"
            );
        }
    }

    #[test]
    fn test_negative_total_price_is_rejected() {
        // The sharpest case: `price_weight`'s total arm takes `.abs()` and
        // re-signs from the posting, so `@@ -110 USD` and `@@ 110 USD` produce
        // the IDENTICAL weight — two transactions that balance the same, hash
        // differently, and read differently to a human.
        let err = posting_weight(&posting_with_price(PriceSpec::Total(Amount {
            number: dec!(-110),
            currency: "USD".to_owned(),
        })))
        .unwrap_err();
        assert!(matches!(
            err,
            WeightError::NonPositiveCostOrPrice {
                label: "total price",
                ..
            }
        ));
    }

    #[test]
    fn test_elided_posting_carrying_a_cost_is_refused_outright() {
        // Both L-15 and L-16 have something to say about this shape, and L-15
        // wins: the annotation is invisible to the serializer at all, so the
        // posting is refused whatever the rate says. The L-16 check still runs
        // ahead of the elided early-return as defence in depth — if the shape
        // rule were ever relaxed, a `{0 USD}` here must not become reachable.
        for number in [dec!(0), dec!(150)] {
            let mut posting = posting_with_cost(number);
            posting.amount = None;
            assert!(matches!(
                posting_weight(&posting).unwrap_err(),
                WeightError::IndistinguishablePostingShape { .. }
            ));
        }
    }

    #[test]
    fn test_positive_costs_and_prices_still_compute() {
        // No over-rejection: the ordinary shapes are untouched, including the
        // smallest representable positive rate and an empty `{}` (no number).
        assert_eq!(
            posting_weight(&posting_with_cost(dec!(150)))
                .unwrap()
                .unwrap()
                .amount,
            dec!(1500)
        );
        assert_eq!(
            posting_weight(&posting_with_cost(dec!(0.0000000001)))
                .unwrap()
                .unwrap()
                .amount,
            dec!(0.0000000010)
        );
        assert_eq!(
            posting_weight(&posting_with_price(PriceSpec::Unit(Amount {
                number: dec!(1.10),
                currency: "USD".to_owned(),
            })))
            .unwrap()
            .unwrap()
            .amount,
            dec!(110.00)
        );
        assert_eq!(
            posting_weight(&posting_with_price(PriceSpec::Total(Amount {
                number: dec!(110),
                currency: "USD".to_owned(),
            })))
            .unwrap()
            .unwrap()
            .amount,
            dec!(110)
        );

        let mut empty_cost = posting_with_cost(dec!(1));
        empty_cost.cost = Some(CostSpec {
            amount: None,
            date: None,
        });
        assert_eq!(
            posting_weight(&empty_cost).unwrap().unwrap().currency,
            "AAPL",
            "an empty `{{}}` cost carries no number and must stay legal"
        );
    }

    #[test]
    fn test_zero_cost_transaction_balances_but_is_still_refused() {
        // The mechanism, stated as a test: with the check removed, both of
        // these sum to zero in every currency — the minting is invisible to I1.
        for units in [dec!(1), dec!(10_000_000)] {
            let postings = vec![
                Posting {
                    account: "Assets:Stock".to_owned(),
                    amount: Some(Amount {
                        number: units,
                        currency: "AAPL".to_owned(),
                    }),
                    cost: Some(CostSpec {
                        amount: Some(Amount {
                            number: dec!(0),
                            currency: "USD".to_owned(),
                        }),
                        date: None,
                    }),
                    price: None,
                    metadata: BTreeMap::new(),
                },
                plain_posting("Equity:Opening", dec!(0), "USD"),
            ];
            assert!(matches!(
                sum_weights(&postings).unwrap_err(),
                WeightError::NonPositiveCostOrPrice { .. }
            ));
        }
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
