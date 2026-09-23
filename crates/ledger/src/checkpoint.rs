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
use crate::read_model::{AccountBalanceEntry, ExactAmount, ReadModel};

/// A balance assertion check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionResult {
    /// The date of the balance assertion.
    pub date: NaiveDate,
    /// The account being asserted.
    pub account: String,
    /// The expected balance (from the `balance` directive).
    pub expected: Decimal,
    /// The actual balance (from the read model), as reported: the exact sum
    /// whenever it fits a `Decimal` at its usual scale, else that sum rounded
    /// once ([`crate::read_model::ExactAmount::reported`]).
    pub actual: Decimal,
    /// Whether `actual` is exactly the sum (T76). When it is not, `actual` is
    /// the rounded figure and `ok` was still decided on the exact sum.
    pub actual_exact: bool,
    /// The currency.
    pub currency: String,
    /// Whether the assertion passed: the claimed amount **is** the exact sum
    /// (T76, L-79) — never merely equal to the rounded `actual`.
    pub ok: bool,
}

/// Evaluate a balance assertion against the read model.
///
/// Semantics (and how they differ from beancount):
/// - A `balance` directive asserts that `account` holds exactly
///   `amount.number` of `amount.currency` **on** `date` — the read model sums
///   every transaction with `date <= the assertion date` (see
///   `ReadModel::account_balance`). Beancount instead asserts the balance at the
///   *start* of the day, before that day's postings; an assertion dated the
///   same day as a posting therefore evaluates differently here.
/// - Only the asserted currency is compared; other currencies held by the
///   account are ignored. An account with no postings reads as `0`, so
///   `balance Assets:Unknown 0 USD` passes.
/// - Evaluation is **read-only reporting**: per §3.6 a failed assertion is
///   surfaced (see `crate::verify`), never used to reject or mutate anything.
/// - The claim is compared with the **exact** sum (T76, L-79). A sum that
///   does not fit a `Decimal` at its usual scale is *reported* rounded, but
///   `balance Assets:Cash 1000 USD` does not hold on `1000 + 10^-28` just
///   because the rounded figure prints `1000.0000000000000000000000000`.
pub fn evaluate_balance_assertion(balance: &Balance, read_model: &ReadModel) -> AssertionResult {
    let entry = read_model.account_balance(&balance.account, Some(balance.date));
    assertion_result(balance, entry.as_ref())
}

/// Build the [`AssertionResult`] for `balance` from the account's balance
/// entry on the assertion date (`None`: never posted to, which reads as `0`).
///
/// Shared by the per-assertion path ([`evaluate_balance_assertion`]) and the
/// batched one ([`evaluate_all_assertions`]) so the two cannot drift (M-23):
/// the *only* difference between them is how the entry is obtained, which is
/// what makes "the fast path answers what the slow path answered" a testable
/// claim about one lookup rather than about two copies of the comparison.
fn assertion_result(balance: &Balance, entry: Option<&AccountBalanceEntry>) -> AssertionResult {
    let sum = entry
        .and_then(|entry| entry.exact_sums.get(&balance.amount.currency))
        .copied()
        .unwrap_or(ExactAmount::ZERO);
    let (actual, actual_exact) = match sum.reported() {
        Ok(reported) => (reported.value, reported.exact),
        // Unreachable inside the amount cap; reported saturated, as the
        // entry's own figure is, and equal to no claim.
        Err(_) => (
            entry
                .and_then(|entry| entry.balances.get(&balance.amount.currency))
                .copied()
                .unwrap_or(Decimal::ZERO),
            false,
        ),
    };
    AssertionResult {
        date: balance.date,
        account: balance.account.clone(),
        expected: balance.amount.number,
        actual,
        actual_exact,
        currency: balance.amount.currency.clone(),
        ok: sum.equals(balance.amount.number),
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
    // the balance date (§3.6 step 1) — the exact sum, not its reported figure
    // (T76), so the pad makes the assertion hold exactly.
    let current = read_model
        .account_balance(&pad.account, Some(balance.date))
        .and_then(|entry| entry.exact_sums.get(currency).copied())
        .unwrap_or(ExactAmount::ZERO);

    // Step 2: delta = target - current, exactly, spelled as `Decimal`
    // subtraction spells it. A delta no `Decimal` holds exactly means an
    // absurd assertion (or a model built from amounts no ingress admits);
    // synthesize no pad rather than a pad that would not balance it (H1).
    let delta = ExactAmount::from_decimal(target_amount).plus(current.negated());
    let delta = delta
        .reported()
        .ok()
        .filter(|reported| reported.exact)?
        .value;

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
///
/// # Cost (M-23)
///
/// Every assertion is answered from **one** date-ordered sweep of the ledger
/// ([`ReadModel::balances_at_dates`]), not from a whole-ledger balance rebuild
/// per `balance` directive. T32 wired assertions in the obvious way — one
/// [`evaluate_balance_assertion`] call each — which made this, and therefore
/// [`crate::verify::verify_dag`], O(assertions × transactions × postings) while
/// holding the ledger's read lock. The assertion count is attacker-supplied
/// (a `balance` directive is ~250 bytes, needs no lifecycle check and need not
/// name an account that exists), so that product was a peer-controlled stall:
/// more than 100k assertions fit under the file cap, and against a
/// 78k-transaction ledger that is ~2×10^10 posting visits.
///
/// The batched form is linear in the ledger and no longer multiplied by the
/// assertion count. Both properties are tested, not asserted in prose — see
/// `tests::test_assertion_evaluation_is_subsecond_at_4000x4000` and
/// `tests::test_assertion_evaluation_does_not_scale_with_assertion_count`.
pub fn evaluate_all_assertions<'a, I>(directives: I, read_model: &ReadModel) -> Vec<AssertionResult>
where
    I: IntoIterator<Item = &'a Directive>,
{
    // Two passes over the directive *refs* (cheap) rather than one pass with a
    // whole-ledger rebuild inside it (not cheap): the queries have to be known
    // up front for the sweep to answer them all in one go.
    let assertions: Vec<&Balance> = directives
        .into_iter()
        .filter_map(|d| match d {
            Directive::Balance(b) => Some(b),
            _ => None,
        })
        .collect();

    let queries: Vec<(&str, NaiveDate)> = assertions
        .iter()
        .map(|balance| (balance.account.as_str(), balance.date))
        .collect();

    let batched = read_model.balances_at_dates(&queries);

    assertions
        .iter()
        .zip(batched.entries)
        .map(|(balance, entry)| {
            // `None` (account never posted to on or before the date) reads as
            // 0, so `balance Assets:Unknown 0 USD` still passes — the same
            // `unwrap_or` the per-assertion path applies.
            assertion_result(balance, entry.as_ref())
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

    // ── M-23: one date-ordered sweep for every assertion ─────────────────

    /// Wall-clock budget for the 4000 × 4000 case (M-23).
    ///
    /// The 0922 audit measured the per-assertion rebuild at **2.61 s** for this
    /// shape (release, perfect quadratic scaling: 171 ms at 1000 × 1000, 656 ms
    /// at 2000 × 2000). The batched sweep is linear, so it lands three orders of
    /// magnitude under that even in a debug build; the budget is deliberately
    /// slack so this is a *shape* check (linear vs quadratic) that no amount of
    /// CI noise can flip, not a microbenchmark. It is not `#[ignore]`d: the
    /// whole point of M-23 is that a comment did not hold the line, so this runs
    /// on every `cargo test -p ledger`.
    const ASSERTION_SWEEP_BUDGET: std::time::Duration = std::time::Duration::from_millis(900);

    /// Number of distinct accounts the load fixture spreads postings over.
    const LOAD_ACCOUNTS: usize = 64;

    /// Number of distinct dates the load fixture spreads directives over.
    const LOAD_SPREAD: i64 = 365;

    fn posting(account: &str, number: Decimal, currency: &str) -> Posting {
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

    /// The M-23 load shape: `txns` transactions and `assertions` `balance`
    /// directives over the same dates and accounts.
    ///
    /// The two counts are independent on purpose. A `balance` directive is the
    /// cheapest thing a peer can plant — `stage_remote_directive` routes it
    /// through the `_ =>` catch-all with no lifecycle check and no requirement
    /// that the account exist — so the assertion count is attacker-supplied,
    /// and it used to *multiply* the cost of a whole-ledger rebuild.
    fn assertion_load(txns: usize, assertions: usize) -> Vec<Directive> {
        let base = make_date(2024, 1, 1);
        let account = |i: usize| format!("Assets:A{:04}", i % LOAD_ACCOUNTS);
        let mut directives = Vec::with_capacity(txns + assertions);

        for i in 0..txns {
            directives.push(Directive::Transaction(Transaction {
                date: base + chrono::Duration::days(i as i64 % LOAD_SPREAD),
                flag: Flag::Complete,
                payee: None,
                // Distinct, so no two transactions share a content id and the
                // read model indexes all of them.
                narration: Some(format!("load {i}")),
                tags: vec![],
                links: vec![],
                postings: vec![
                    posting(&account(i), dec!(1), "USD"),
                    posting("Equity:Opening", dec!(-1), "USD"),
                ],
                metadata: BTreeMap::new(),
            }));
        }

        for i in 0..assertions {
            directives.push(Directive::Balance(Balance {
                date: base + chrono::Duration::days(i as i64 % LOAD_SPREAD),
                account: account(i),
                amount: Amount {
                    number: dec!(0),
                    currency: "USD".to_owned(),
                },
                metadata: BTreeMap::new(),
            }));
        }

        directives
    }

    /// M-23 regression: 4000 transactions × 4000 assertions, sub-second.
    ///
    /// Measured by the 0922 audit at 2.61 s with the per-assertion rebuild —
    /// and that was the *release* number; a debug build of the old path takes
    /// minutes. Reverting `evaluate_all_assertions` to
    /// `evaluate_balance_assertion` per directive fails this test.
    #[test]
    fn test_assertion_evaluation_is_subsecond_at_4000x4000() {
        let directives = assertion_load(4000, 4000);
        let model = ReadModel::build(&directives);

        let start = std::time::Instant::now();
        let results = evaluate_all_assertions(&directives, &model);
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 4000);
        assert!(
            elapsed < ASSERTION_SWEEP_BUDGET,
            "4000x4000 assertion evaluation took {elapsed:?}, budget is \
             {ASSERTION_SWEEP_BUDGET:?} (M-23: the per-assertion rebuild was 2.61s)"
        );
    }

    /// M-23: the ledger walk must not scale with the attacker-supplied
    /// multiplier.
    ///
    /// This is the invariant the GraphQL `verify` weight is sized on, so it is
    /// checked by **counting** rather than by timing: a wall-clock ratio at
    /// this scale measures allocator noise, and the thing that must never come
    /// back is a *multiplier*, which is exact and countable. Holding the ledger
    /// and the latest assertion date fixed, the sweep visits the same postings
    /// whether a peer planted 365 assertions or 40,960 — under the
    /// per-assertion rebuild that count was multiplied by the assertion count.
    ///
    /// Paired with `graphql::query::tests::test_verify_complexity_matches_measured_cost_model`
    /// in `gl-node`, which pins the weight to this cost model.
    #[test]
    fn test_assertion_pass_walks_the_ledger_once_regardless_of_assertion_count() {
        const TXNS: usize = 2000;
        const POSTINGS_PER_TXN: usize = 2;

        // Every count at or above the date spread reaches the ledger's last
        // date, so all three sweep the same cut and must cost the same.
        let mut counts = Vec::new();
        for assertions in [LOAD_SPREAD as usize, 4096, 40_960] {
            let directives = assertion_load(TXNS, assertions);
            let model = ReadModel::build(&directives);
            let queries: Vec<(&str, NaiveDate)> = directives
                .iter()
                .filter_map(|d| match d {
                    Directive::Balance(b) => Some((b.account.as_str(), b.date)),
                    _ => None,
                })
                .collect();
            assert_eq!(queries.len(), assertions);
            counts.push(model.balances_at_dates(&queries).postings_visited);
        }

        assert_eq!(
            counts,
            vec![TXNS * POSTINGS_PER_TXN; 3],
            "the assertion count is multiplying the ledger walk again (M-23)"
        );
    }

    /// M-23 safety property: the batched path answers exactly what the
    /// per-assertion path answered. A faster wrong answer is worse than a slow
    /// right one, so this pins T32's documented semantics directly:
    ///
    /// - assertions on the **same date** all see the same cut of the ledger;
    /// - an account with no postings reads **0** (`balance Assets:Unknown 0 USD`
    ///   passes);
    /// - the cut is `<= date` — a posting dated *on* the assertion date counts,
    ///   which is where this deliberately differs from beancount's
    ///   start-of-day rule;
    /// - only the asserted currency is compared.
    #[test]
    fn test_batched_assertions_match_per_assertion_evaluation() {
        let jan1 = make_date(2024, 1, 1);
        let jan10 = make_date(2024, 1, 10);
        let jan20 = make_date(2024, 1, 20);

        let directives = vec![
            // Two transactions on the same date, plus a later one and a
            // second currency on the same account.
            Directive::Transaction(Transaction {
                date: jan10,
                flag: Flag::Complete,
                payee: None,
                narration: Some("deposit".to_owned()),
                tags: vec![],
                links: vec![],
                postings: vec![
                    posting("Assets:Cash", dec!(1000), "USD"),
                    posting("Equity:Opening", dec!(-1000), "USD"),
                ],
                metadata: BTreeMap::new(),
            }),
            Directive::Transaction(Transaction {
                date: jan10,
                flag: Flag::Complete,
                payee: None,
                narration: Some("same-day second leg".to_owned()),
                tags: vec![],
                links: vec![],
                postings: vec![
                    posting("Assets:Cash", dec!(25), "USD"),
                    posting("Assets:Cash", dec!(7), "EUR"),
                    posting("Equity:Opening", dec!(-25), "USD"),
                    posting("Equity:Opening", dec!(-7), "EUR"),
                ],
                metadata: BTreeMap::new(),
            }),
            Directive::Transaction(Transaction {
                date: jan20,
                flag: Flag::Complete,
                payee: None,
                narration: Some("later, must not count on jan10".to_owned()),
                tags: vec![],
                links: vec![],
                postings: vec![
                    posting("Assets:Cash", dec!(500), "USD"),
                    posting("Equity:Opening", dec!(-500), "USD"),
                ],
                metadata: BTreeMap::new(),
            }),
            // Assertions, deliberately out of date order so the batch has to
            // sort them, and including two on the same date.
            balance_at(jan20, "Assets:Cash", dec!(1525), "USD"),
            balance_at(jan10, "Assets:Cash", dec!(1025), "USD"), // `<= date`: same-day postings count.
            balance_at(jan10, "Assets:Cash", dec!(7), "EUR"),    // Same date, other currency.
            balance_at(jan10, "Assets:Cash", dec!(999), "USD"),  // Same date, wrong: must fail.
            balance_at(jan1, "Assets:Cash", dec!(0), "USD"),     // Before any posting: 0.
            balance_at(jan20, "Assets:Unknown", dec!(0), "USD"), // Never posted to: 0.
            balance_at(jan20, "Assets:Unknown", dec!(1), "USD"), // ... so this fails.
        ];

        let model = ReadModel::build(&directives);

        let batched = evaluate_all_assertions(&directives, &model);
        let one_by_one: Vec<AssertionResult> = directives
            .iter()
            .filter_map(|d| match d {
                Directive::Balance(b) => Some(evaluate_balance_assertion(b, &model)),
                _ => None,
            })
            .collect();

        assert_eq!(
            batched, one_by_one,
            "the batched sweep must return exactly what the per-assertion rebuild returned"
        );

        // And pin the values themselves, so the two paths cannot agree on a
        // shared regression.
        let actual: Vec<(&str, Decimal, bool)> = batched
            .iter()
            .map(|r| (r.account.as_str(), r.actual, r.ok))
            .collect();
        assert_eq!(
            actual,
            vec![
                ("Assets:Cash", dec!(1525), true),
                ("Assets:Cash", dec!(1025), true),
                ("Assets:Cash", dec!(7), true),
                ("Assets:Cash", dec!(1025), false),
                ("Assets:Cash", dec!(0), true),
                ("Assets:Unknown", dec!(0), true),
                ("Assets:Unknown", dec!(0), false),
            ]
        );
    }

    /// M-23: the sweep walks transactions in date order, but the read model's
    /// vector is only date-sorted by `ReadModel::build` — `index_directive`
    /// appends. A backdated directive arriving after boot therefore leaves the
    /// vector out of order, and the batched path must still agree with the
    /// per-assertion one.
    #[test]
    fn test_batched_assertions_match_after_backdated_incremental_append() {
        let jan10 = make_date(2024, 1, 10);
        let jan20 = make_date(2024, 1, 20);

        let built = vec![Directive::Transaction(Transaction {
            date: jan20,
            flag: Flag::Complete,
            payee: None,
            narration: Some("booted".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                posting("Assets:Cash", dec!(500), "USD"),
                posting("Equity:Opening", dec!(-500), "USD"),
            ],
            metadata: BTreeMap::new(),
        })];
        let mut model = ReadModel::build(&built);

        // Arrives later, dated earlier: appended past the sorted prefix.
        let backdated = Directive::Transaction(Transaction {
            date: jan10,
            flag: Flag::Complete,
            payee: None,
            narration: Some("backdated".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                posting("Assets:Cash", dec!(1000), "USD"),
                posting("Equity:Opening", dec!(-1000), "USD"),
            ],
            metadata: BTreeMap::new(),
        });
        model.index_directive(&backdated);

        let assertions = vec![
            balance_at(jan20, "Assets:Cash", dec!(1500), "USD"),
            balance_at(jan10, "Assets:Cash", dec!(1000), "USD"),
        ];

        let batched = evaluate_all_assertions(&assertions, &model);
        let one_by_one: Vec<AssertionResult> = assertions
            .iter()
            .filter_map(|d| match d {
                Directive::Balance(b) => Some(evaluate_balance_assertion(b, &model)),
                _ => None,
            })
            .collect();

        assert_eq!(batched, one_by_one);
        assert!(batched.iter().all(|r| r.ok), "results: {batched:?}");
    }

    fn balance_at(date: NaiveDate, account: &str, number: Decimal, currency: &str) -> Directive {
        Directive::Balance(Balance {
            date,
            account: account.to_owned(),
            amount: Amount {
                number,
                currency: currency.to_owned(),
            },
            metadata: BTreeMap::new(),
        })
    }
}
