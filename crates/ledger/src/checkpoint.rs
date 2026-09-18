//! Balance assertions and pad generation (§3.6).
//!
//! - Balance assertions are evaluated by [`crate::verify::verify_dag`] over the
//!   whole directive set, and surfaced through the GraphQL `verify` query
//!   (M-08). Before that wiring, `balance` directives were persisted by the
//!   unvalidated catch-all and never evaluated, so the file format advertised
//!   an integrity check that did nothing.
//! - Failed assertions are reported, never used to reject transactions (§3.6),
//!   and never used to mutate state: a `balance` line is an author's claim, and
//!   a claim from an allowlisted peer is no more authoritative than any other.
//! - Pad synthesis ([`generate_pad_transaction`] / [`generate_all_pads`]) is
//!   deliberately **not** wired into the verify path: it invents transactions,
//!   which is a state change rather than a report. Assertion evaluation
//!   therefore ignores pads entirely.

use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::collections::BTreeMap;

use crate::model::*;
use crate::read_model::ReadModel;

/// A balance assertion check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionResult {
    /// The date of the balance assertion.
    pub date: NaiveDate,
    /// The account being asserted.
    pub account: String,
    /// The expected balance (from the `balance` directive).
    pub expected: Decimal,
    /// The actual balance (from the read model).
    pub actual: Decimal,
    /// The currency.
    pub currency: String,
    /// Whether the assertion passed.
    pub ok: bool,
}

/// Evaluate a balance assertion against the read model.
///
/// Semantics (and how they differ from beancount):
/// - A `balance` directive asserts that `account` holds exactly
///   `amount.number` of `amount.currency` **on** `date` — the read model sums
///   every transaction with `date <= the assertion date` (see
///   `ReadModel::balances_at`). Beancount instead asserts the balance at the
///   *start* of the day, before that day's postings; an assertion dated the
///   same day as a posting therefore evaluates differently here.
/// - Only the asserted currency is compared; other currencies held by the
///   account are ignored. An account with no postings reads as `0`, so
///   `balance Assets:Unknown 0 USD` passes.
/// - Evaluation is **read-only reporting**: per §3.6 a failed assertion is
///   surfaced (see `crate::verify`), never used to reject or mutate anything.
pub fn evaluate_balance_assertion(balance: &Balance, read_model: &ReadModel) -> AssertionResult {
    let actual = read_model
        .account_balance(&balance.account, Some(balance.date))
        .and_then(|entry| entry.balances.get(&balance.amount.currency).copied())
        .unwrap_or(Decimal::ZERO);

    let ok = actual == balance.amount.number;

    AssertionResult {
        date: balance.date,
        account: balance.account.clone(),
        expected: balance.amount.number,
        actual,
        currency: balance.amount.currency.clone(),
        ok,
    }
}

/// Generate a pad transaction to reconcile a balance (§3.6).
///
/// Given a `pad` directive and a target `balance` directive, computes the delta
/// and synthesizes a transaction if needed.
///
/// Returns `None` if no adjustment is needed (delta = 0).
pub fn generate_pad_transaction(
    pad: &Pad,
    balance: &Balance,
    read_model: &ReadModel,
) -> Option<Transaction> {
    let currency = &balance.amount.currency;
    let target_amount = balance.amount.number;

    // Step 1: current balance of the account in the currency, as of just before
    // the balance date (§3.6 step 1).
    let current = read_model
        .account_balance(&pad.account, Some(balance.date))
        .and_then(|entry| entry.balances.get(currency).copied())
        .unwrap_or(Decimal::ZERO);

    // Step 2: delta = target - current. Checked (H1): both operands can sit
    // near ±Decimal::MAX (the balance amount is caller-supplied and the read
    // model saturates), and a bare `-` panics on overflow. An overflowing
    // delta means an absurd assertion; synthesize no pad rather than panic.
    let delta = target_amount.checked_sub(current)?;

    // Step 3: if delta = 0, no pad transaction.
    if delta == Decimal::ZERO {
        return None;
    }

    // Step 4: synthesize the transaction.
    Some(Transaction {
        date: pad.date,
        flag: Flag::Complete,
        payee: None,
        narration: Some(format!("Pad {}", pad.account)),
        tags: vec![],
        links: vec![],
        postings: vec![
            Posting {
                account: pad.account.clone(),
                amount: Some(Amount {
                    number: delta,
                    currency: currency.clone(),
                }),
                cost: None,
                price: None,
                metadata: BTreeMap::new(),
            },
            Posting {
                account: pad.source_account.clone(),
                amount: Some(Amount {
                    number: -delta,
                    currency: currency.clone(),
                }),
                cost: None,
                price: None,
                metadata: BTreeMap::new(),
            },
        ],
        // Envelope metadata will be stamped by the caller (author, lamport, parents).
        metadata: BTreeMap::new(),
    })
}

/// Evaluate every balance assertion in a set of directives (§3.6).
///
/// One [`AssertionResult`] per `balance` directive, in directive order, with
/// the per-assertion semantics documented on [`evaluate_balance_assertion`].
/// Directives of other kinds — `pad` included — are skipped: pads are never
/// synthesized into the read model here, so an assertion whose gap a `pad`
/// directive is meant to cover still reports as a failure.
///
/// Read-only: nothing is mutated and nothing is rejected. The caller
/// ([`crate::verify::verify_dag`]) reports the results.
///
/// Takes any iterator of directive references so the DAG's borrowed view
/// (`LedgerDag::directives()`) can be evaluated without cloning the ledger.
pub fn evaluate_all_assertions<'a, I>(directives: I, read_model: &ReadModel) -> Vec<AssertionResult>
where
    I: IntoIterator<Item = &'a Directive>,
{
    directives
        .into_iter()
        .filter_map(|d| {
            if let Directive::Balance(b) = d {
                Some(evaluate_balance_assertion(b, read_model))
            } else {
                None
            }
        })
        .collect()
}

/// Find all pad-balance pairs and generate pad transactions.
///
/// Per §3.6: a `pad` directive is followed by a `balance` directive for the
/// same account. We match them by account and generate pad transactions
/// for the first balance after each pad.
pub fn generate_all_pads(directives: &[Directive], read_model: &ReadModel) -> Vec<Transaction> {
    let mut pads_by_account: BTreeMap<String, Vec<&Pad>> = BTreeMap::new();
    let mut balances_by_account: BTreeMap<String, Vec<&Balance>> = BTreeMap::new();

    for d in directives {
        match d {
            Directive::Pad(p) => {
                pads_by_account
                    .entry(p.account.clone())
                    .or_default()
                    .push(p);
            }
            Directive::Balance(b) => {
                balances_by_account
                    .entry(b.account.clone())
                    .or_default()
                    .push(b);
            }
            _ => {}
        }
    }

    let mut pad_txns = Vec::new();

    for (account, pads) in &pads_by_account {
        if let Some(balances) = balances_by_account.get(account) {
            for pad in pads {
                // Find the first balance after this pad.
                if let Some(balance) = balances.iter().find(|b| b.date >= pad.date) {
                    if let Some(txn) = generate_pad_transaction(pad, balance, read_model) {
                        pad_txns.push(txn);
                    }
                }
            }
        }
    }

    pad_txns
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_model::ReadModel;
    use rust_decimal_macros::dec;

    fn make_date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    fn make_txn(
        date: NaiveDate,
        narration: &str,
        postings: Vec<(&str, Decimal, &str)>,
    ) -> Directive {
        Directive::Transaction(Transaction {
            date,
            flag: Flag::Complete,
            payee: None,
            narration: Some(narration.to_owned()),
            tags: vec![],
            links: vec![],
            postings: postings
                .into_iter()
                .map(|(account, number, currency)| Posting {
                    account: account.to_owned(),
                    amount: Some(Amount {
                        number,
                        currency: currency.to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                })
                .collect(),
            metadata: BTreeMap::new(),
        })
    }

    // ── Balance assertions ───────────────────────────────────────────────

    #[test]
    fn test_balance_assertion_pass() {
        let directives = vec![make_txn(
            make_date(2024, 1, 15),
            "Deposit",
            vec![
                ("Assets:Cash", dec!(1000), "USD"),
                ("Equity:Opening", dec!(-1000), "USD"),
            ],
        )];
        let model = ReadModel::build(&directives);

        let balance = Balance {
            date: make_date(2024, 2, 1),
            account: "Assets:Cash".to_owned(),
            amount: Amount {
                number: dec!(1000),
                currency: "USD".to_owned(),
            },
            metadata: BTreeMap::new(),
        };

        let result = evaluate_balance_assertion(&balance, &model);
        assert!(result.ok);
        assert_eq!(result.expected, dec!(1000));
        assert_eq!(result.actual, dec!(1000));
    }

    #[test]
    fn test_balance_assertion_fail() {
        let directives = vec![make_txn(
            make_date(2024, 1, 15),
            "Deposit",
            vec![
                ("Assets:Cash", dec!(1000), "USD"),
                ("Equity:Opening", dec!(-1000), "USD"),
            ],
        )];
        let model = ReadModel::build(&directives);

        let balance = Balance {
            date: make_date(2024, 2, 1),
            account: "Assets:Cash".to_owned(),
            amount: Amount {
                number: dec!(2000), // Wrong!
                currency: "USD".to_owned(),
            },
            metadata: BTreeMap::new(),
        };

        let result = evaluate_balance_assertion(&balance, &model);
        assert!(!result.ok);
        assert_eq!(result.expected, dec!(2000));
        assert_eq!(result.actual, dec!(1000));
    }

    #[test]
    fn test_balance_assertion_unknown_account() {
        let model = ReadModel::build(&[]);

        let balance = Balance {
            date: make_date(2024, 2, 1),
            account: "Assets:Nonexistent".to_owned(),
            amount: Amount {
                number: dec!(0),
                currency: "USD".to_owned(),
            },
            metadata: BTreeMap::new(),
        };

        let result = evaluate_balance_assertion(&balance, &model);
        assert!(result.ok, "Zero balance on unknown account should pass");
    }

    // ── Pad generation ───────────────────────────────────────────────────

    #[test]
    fn test_pad_generation_delta_positive() {
        let directives = vec![make_txn(
            make_date(2024, 1, 15),
            "Initial",
            vec![
                ("Assets:Cash", dec!(800), "USD"),
                ("Equity:Opening", dec!(-800), "USD"),
            ],
        )];
        let model = ReadModel::build(&directives);

        let pad = Pad {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            source_account: "Equity:Opening".to_owned(),
            metadata: BTreeMap::new(),
        };
        let balance = Balance {
            date: make_date(2024, 2, 1),
            account: "Assets:Cash".to_owned(),
            amount: Amount {
                number: dec!(1000),
                currency: "USD".to_owned(),
            },
            metadata: BTreeMap::new(),
        };

        let txn = generate_pad_transaction(&pad, &balance, &model);
        assert!(txn.is_some());
        let txn = txn.unwrap();

        assert_eq!(txn.narration, Some("Pad Assets:Cash".to_owned()));
        assert_eq!(txn.postings.len(), 2);
        // delta = 1000 - 800 = 200
        assert_eq!(txn.postings[0].amount.as_ref().unwrap().number, dec!(200));
        assert_eq!(txn.postings[1].amount.as_ref().unwrap().number, dec!(-200));
    }

    #[test]
    fn test_pad_generation_delta_negative() {
        let directives = vec![make_txn(
            make_date(2024, 1, 15),
            "Overfunded",
            vec![
                ("Assets:Cash", dec!(1500), "USD"),
                ("Equity:Opening", dec!(-1500), "USD"),
            ],
        )];
        let model = ReadModel::build(&directives);

        let pad = Pad {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            source_account: "Equity:Opening".to_owned(),
            metadata: BTreeMap::new(),
        };
        let balance = Balance {
            date: make_date(2024, 2, 1),
            account: "Assets:Cash".to_owned(),
            amount: Amount {
                number: dec!(1000),
                currency: "USD".to_owned(),
            },
            metadata: BTreeMap::new(),
        };

        let txn = generate_pad_transaction(&pad, &balance, &model);
        assert!(txn.is_some());
        let txn = txn.unwrap();

        // delta = 1000 - 1500 = -500
        assert_eq!(txn.postings[0].amount.as_ref().unwrap().number, dec!(-500));
        assert_eq!(txn.postings[1].amount.as_ref().unwrap().number, dec!(500));
    }

    #[test]
    fn test_pad_generation_no_delta() {
        let directives = vec![make_txn(
            make_date(2024, 1, 15),
            "Exact",
            vec![
                ("Assets:Cash", dec!(1000), "USD"),
                ("Equity:Opening", dec!(-1000), "USD"),
            ],
        )];
        let model = ReadModel::build(&directives);

        let pad = Pad {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            source_account: "Equity:Opening".to_owned(),
            metadata: BTreeMap::new(),
        };
        let balance = Balance {
            date: make_date(2024, 2, 1),
            account: "Assets:Cash".to_owned(),
            amount: Amount {
                number: dec!(1000),
                currency: "USD".to_owned(),
            },
            metadata: BTreeMap::new(),
        };

        let txn = generate_pad_transaction(&pad, &balance, &model);
        assert!(txn.is_none(), "No pad needed when delta = 0");
    }

    #[test]
    fn test_pad_generation_extreme_values_no_panic() {
        // H1: both operands of the delta can sit at the Decimal extremes — the
        // read model saturates and the asserted amount is caller-supplied — so
        // the subtraction must be checked. An overflowing delta means an absurd
        // assertion: synthesize nothing rather than panic.
        let directives = vec![make_txn(
            make_date(2024, 1, 15),
            "Saturated",
            vec![
                ("Assets:Cash", Decimal::MIN, "USD"),
                ("Equity:Opening", Decimal::MAX, "USD"),
            ],
        )];
        let model = ReadModel::build(&directives);

        let pad = Pad {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            source_account: "Equity:Opening".to_owned(),
            metadata: BTreeMap::new(),
        };
        let balance = Balance {
            date: make_date(2024, 2, 1),
            account: "Assets:Cash".to_owned(),
            amount: Amount {
                number: Decimal::MAX,
                currency: "USD".to_owned(),
            },
            metadata: BTreeMap::new(),
        };

        // MAX − MIN overflows: no pad, no panic.
        assert!(generate_pad_transaction(&pad, &balance, &model).is_none());

        // Same through the whole-ledger entry point, with the pad and balance
        // present so the pairing actually reaches the subtraction.
        let with_pad = [
            directives[0].clone(),
            Directive::Pad(pad.clone()),
            Directive::Balance(balance.clone()),
        ];
        assert!(generate_all_pads(&with_pad, &model).is_empty());

        // The assertion itself still evaluates — reporting never overflows.
        let result = evaluate_balance_assertion(&balance, &model);
        assert!(!result.ok);
        assert_eq!(result.actual, Decimal::MIN);
        assert_eq!(result.expected, Decimal::MAX);
    }

    // ── Evaluate all assertions ──────────────────────────────────────────

    #[test]
    fn test_evaluate_all_assertions() {
        let directives = vec![
            make_txn(
                make_date(2024, 1, 15),
                "Deposit",
                vec![
                    ("Assets:Cash", dec!(1000), "USD"),
                    ("Equity:Opening", dec!(-1000), "USD"),
                ],
            ),
            Directive::Balance(Balance {
                date: make_date(2024, 2, 1),
                account: "Assets:Cash".to_owned(),
                amount: Amount {
                    number: dec!(1000),
                    currency: "USD".to_owned(),
                },
                metadata: BTreeMap::new(),
            }),
            Directive::Balance(Balance {
                date: make_date(2024, 2, 1),
                account: "Assets:Cash".to_owned(),
                amount: Amount {
                    number: dec!(9999), // Wrong.
                    currency: "USD".to_owned(),
                },
                metadata: BTreeMap::new(),
            }),
        ];
        let model = ReadModel::build(&directives);

        let results = evaluate_all_assertions(&directives, &model);
        assert_eq!(results.len(), 2);
        assert!(results[0].ok, "First assertion should pass");
        assert!(!results[1].ok, "Second assertion should fail");
    }

    // ── Generate all pads ────────────────────────────────────────────────

    #[test]
    fn test_generate_all_pads() {
        let directives = vec![
            make_txn(
                make_date(2024, 1, 15),
                "Deposit",
                vec![
                    ("Assets:Cash", dec!(800), "USD"),
                    ("Equity:Opening", dec!(-800), "USD"),
                ],
            ),
            Directive::Pad(Pad {
                date: make_date(2024, 1, 1),
                account: "Assets:Cash".to_owned(),
                source_account: "Equity:Opening".to_owned(),
                metadata: BTreeMap::new(),
            }),
            Directive::Balance(Balance {
                date: make_date(2024, 2, 1),
                account: "Assets:Cash".to_owned(),
                amount: Amount {
                    number: dec!(1000),
                    currency: "USD".to_owned(),
                },
                metadata: BTreeMap::new(),
            }),
        ];
        let model = ReadModel::build(&directives);

        let pads = generate_all_pads(&directives, &model);
        assert_eq!(pads.len(), 1);
        assert_eq!(pads[0].narration, Some("Pad Assets:Cash".to_owned()));
    }

    // ── Golden fixture ───────────────────────────────────────────────────

    #[test]
    fn test_golden_fixture_assertions() {
        let fixture = include_str!("../../../testfixtures/fixture-simple.bean");
        let directives = crate::parse::parse_file(fixture).unwrap();
        let model = ReadModel::build(&directives);

        let results = evaluate_all_assertions(&directives, &model);
        // The fixture has one balance directive: "2024-02-01 balance Assets:Cash 1025.00 USD"
        assert_eq!(results.len(), 1);
        assert!(
            results[0].ok,
            "Golden fixture balance assertion should pass: expected={}, actual={}",
            results[0].expected, results[0].actual
        );
    }
}
