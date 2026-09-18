//! Ledger invariant validation (§2.4: I1, I2, I3, I9).
//!
//! These checks apply to both local writes and remote gossip inserts (§3.5).

use chrono::NaiveDate;
use rust_decimal::Decimal;

use crate::model::*;
use crate::weights::{resolve_elided, sum_weights, WeightError};

/// Account lifecycle state (M-09).
///
/// Re-exported here because `ledger::validate::AccountState` is the path every
/// caller — including other crates — already uses; the implementation moved to
/// [`crate::accounts`] when it was re-backed by an order-insensitive event
/// model.
pub use crate::accounts::AccountState;

// ─── Error types ─────────────────────────────────────────────────────────────

/// Validation error with machine-readable code matching §2.8 GraphQL error codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// I1: per-currency weights don't sum to zero.
    UnbalancedTransaction { imbalances: Vec<CurrencyImbalance> },
    /// I2: more than one elided posting, or elision can't resolve.
    InvalidElision { reason: String },
    /// I3: account not open at transaction date.
    AccountNotOpen { account: String, date: NaiveDate },
    /// I3: account closed before transaction date.
    AccountClosed {
        account: String,
        close_date: NaiveDate,
        transaction_date: NaiveDate,
    },
    /// I9: posting uses a currency not in the open directive's constraint list.
    AccountCurrencyMismatch {
        account: String,
        currency: String,
        allowed: Vec<String>,
    },
    /// §3.5.1: both cost and price on the same posting.
    InvalidPosting { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrencyImbalance {
    pub currency: String,
    pub amount: Decimal,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::UnbalancedTransaction { imbalances } => {
                let details: Vec<String> = imbalances
                    .iter()
                    .map(|i| format!("{} {}", i.amount, i.currency))
                    .collect();
                write!(f, "Unbalanced transaction: {}", details.join(", "))
            }
            ValidationError::InvalidElision { reason } => {
                write!(f, "Invalid elision: {reason}")
            }
            ValidationError::AccountNotOpen { account, date } => {
                write!(f, "Account {account} not open at {date}")
            }
            ValidationError::AccountClosed {
                account,
                close_date,
                transaction_date,
            } => {
                write!(
                    f,
                    "Account {account} closed on {close_date}, cannot post on {transaction_date}"
                )
            }
            ValidationError::AccountCurrencyMismatch {
                account,
                currency,
                allowed,
            } => {
                write!(
                    f,
                    "Account {account} does not accept {currency}; allowed: {}",
                    allowed.join(", ")
                )
            }
            ValidationError::InvalidPosting { message } => {
                write!(f, "Invalid posting: {message}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// §2.8 error code mapping.
impl ValidationError {
    pub fn error_code(&self) -> &'static str {
        match self {
            ValidationError::UnbalancedTransaction { .. } => "UNBALANCED_TRANSACTION",
            ValidationError::InvalidElision { .. } => "ELIDED_POSTING_INVALID",
            ValidationError::AccountNotOpen { .. } => "ACCOUNT_NOT_OPEN",
            ValidationError::AccountClosed { .. } => "ACCOUNT_CLOSED",
            ValidationError::AccountCurrencyMismatch { .. } => "ACCOUNT_CURRENCY_MISMATCH",
            ValidationError::InvalidPosting { .. } => "INVALID_POSTING",
        }
    }
}

// ─── Transaction validation ─────────────────────────────────────────────────

/// Validate a transaction against I1 (balance), I2 (elision), I3 (account lifecycle),
/// and I9 (currency constraint).
///
/// If the transaction has an elided posting, this resolves it in-place.
/// Returns the resolved transaction (with elided posting filled in, if any).
pub fn validate_transaction(
    txn: &Transaction,
    accounts: &AccountState,
) -> Result<Transaction, ValidationError> {
    let mut txn = txn.clone();

    // ── I2: resolve elided posting ──────────────────────────────────────
    let (sums, elided_count) = sum_weights(&txn.postings).map_err(|e| match e {
        WeightError::CostAndPriceOnSamePosting { account } => ValidationError::InvalidPosting {
            message: format!("Both cost and price on posting to {account}"),
        },
        WeightError::ElisionInvalid { reason } => ValidationError::InvalidElision { reason },
        WeightError::AmountOverflow { detail } => ValidationError::InvalidPosting {
            message: format!("Amount overflow: {detail}"),
        },
        // L-16: a `{0 USD}` or negative rate mints/destroys units through I1.
        // L-15: a shape two distinct directives would serialize identically to.
        other @ (WeightError::NonPositiveCostOrPrice { .. }
        | WeightError::IndistinguishablePostingShape { .. }) => ValidationError::InvalidPosting {
            message: other.to_string(),
        },
    })?;

    if elided_count > 1 {
        return Err(ValidationError::InvalidElision {
            reason: format!("At most 1 elided posting allowed, found {elided_count}"),
        });
    }

    if elided_count == 1 {
        let resolved_amount = resolve_elided(&sums).map_err(|e| match e {
            WeightError::ElisionInvalid { reason } => ValidationError::InvalidElision { reason },
            _ => ValidationError::InvalidElision {
                reason: e.to_string(),
            },
        })?;

        // Fill in the elided posting.
        for posting in &mut txn.postings {
            if posting.amount.is_none() {
                posting.amount = Some(resolved_amount.clone());
                break;
            }
        }
    }

    // ── I1: check balance per currency ──────────────────────────────────
    let (final_sums, _) = sum_weights(&txn.postings).map_err(|e| match e {
        WeightError::CostAndPriceOnSamePosting { account } => ValidationError::InvalidPosting {
            message: format!("Both cost and price on posting to {account}"),
        },
        WeightError::ElisionInvalid { reason } => ValidationError::InvalidElision { reason },
        WeightError::AmountOverflow { detail } => ValidationError::InvalidPosting {
            message: format!("Amount overflow: {detail}"),
        },
        // L-16: a `{0 USD}` or negative rate mints/destroys units through I1.
        // L-15: a shape two distinct directives would serialize identically to.
        other @ (WeightError::NonPositiveCostOrPrice { .. }
        | WeightError::IndistinguishablePostingShape { .. }) => ValidationError::InvalidPosting {
            message: other.to_string(),
        },
    })?;

    let imbalances: Vec<CurrencyImbalance> = final_sums
        .iter()
        .filter(|(_, &amount)| amount != Decimal::ZERO)
        .map(|(currency, &amount)| CurrencyImbalance {
            currency: currency.clone(),
            amount,
        })
        .collect();

    if !imbalances.is_empty() {
        return Err(ValidationError::UnbalancedTransaction { imbalances });
    }

    // ── I3 + I9: account lifecycle and currency constraints ─────────────
    //
    // Both checks are answered at the TRANSACTION's date (M-09): the `open` in
    // force on that date is the one that admits the posting, so it is also the
    // one whose currency list constrains it. Asking I9 about the account's
    // latest `open` instead would let a later re-open with a different currency
    // list retroactively invalidate transactions I3 had already admitted under
    // the earlier one.
    for posting in &txn.postings {
        accounts.check_account_open(&posting.account, txn.date)?;

        if let Some(ref amount) = posting.amount {
            accounts.check_currency_constraint_at(&posting.account, &amount.currency, txn.date)?;
        }
    }

    Ok(txn)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    fn simple_balanced_txn() -> Transaction {
        Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Test".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        }
    }

    fn setup_accounts() -> AccountState {
        let mut state = AccountState::new();
        state
            .open_account("Assets:Cash", make_date(2024, 1, 1), &["USD".to_owned()])
            .unwrap();
        state
            .open_account("Equity:Opening", make_date(2024, 1, 1), &[])
            .unwrap();
        state
            .open_account("Expenses:Food", make_date(2024, 1, 1), &["USD".to_owned()])
            .unwrap();
        state
    }

    // ── CT-1: I1 balance ─────────────────────────────────────────────────

    #[test]
    fn test_ct1_balanced_transaction_accepted() {
        let accounts = setup_accounts();
        let txn = simple_balanced_txn();
        let result = validate_transaction(&txn, &accounts);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ct1_unbalanced_transaction_rejected() {
        let accounts = setup_accounts();
        let mut txn = simple_balanced_txn();
        txn.postings[1].amount = Some(Amount {
            number: dec!(-50),
            currency: "USD".to_owned(),
        });
        let err = validate_transaction(&txn, &accounts).unwrap_err();
        assert!(
            matches!(err, ValidationError::UnbalancedTransaction { .. }),
            "Expected UNBALANCED_TRANSACTION, got {err:?}"
        );
        assert_eq!(err.error_code(), "UNBALANCED_TRANSACTION");
    }

    #[test]
    fn test_ct1_multi_currency_balanced() {
        let mut accounts = setup_accounts();
        accounts
            .open_account("Assets:Foreign", make_date(2024, 1, 1), &[])
            .unwrap();

        let txn = Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Multi".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-110),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
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
                },
            ],
            metadata: BTreeMap::new(),
        };
        let result = validate_transaction(&txn, &accounts);
        assert!(
            result.is_ok(),
            "Multi-currency with price should balance: {result:?}"
        );
    }

    // ── CT-2: I2 elided posting ──────────────────────────────────────────

    #[test]
    fn test_ct2_elided_posting_resolved() {
        let accounts = setup_accounts();
        let txn = Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Elided".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: None,
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let resolved = validate_transaction(&txn, &accounts).unwrap();
        let elided = &resolved.postings[1];
        assert_eq!(elided.amount.as_ref().unwrap().number, dec!(-100));
        assert_eq!(elided.amount.as_ref().unwrap().currency, "USD");
    }

    #[test]
    fn test_ct2_two_elided_rejected() {
        let accounts = setup_accounts();
        let txn = Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Double elide".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: None,
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: None,
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };
        let err = validate_transaction(&txn, &accounts).unwrap_err();
        assert_eq!(err.error_code(), "ELIDED_POSTING_INVALID");
    }

    // ── CT-7: I3 account lifecycle ───────────────────────────────────────

    #[test]
    fn test_ct7_account_not_open_rejected() {
        let accounts = AccountState::new(); // no accounts opened
        let txn = simple_balanced_txn();
        let err = validate_transaction(&txn, &accounts).unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_NOT_OPEN");
    }

    #[test]
    fn test_ct7_account_closed_before_date_rejected() {
        let mut accounts = setup_accounts();
        accounts
            .close_account("Assets:Cash", make_date(2024, 1, 10))
            .unwrap();

        let txn = simple_balanced_txn(); // date = 2024-01-15
        let err = validate_transaction(&txn, &accounts).unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_CLOSED");
    }

    #[test]
    fn test_ct7_same_day_close_allowed() {
        let mut accounts = setup_accounts();
        // Close on same day as transaction — should be allowed (close has priority 9).
        accounts
            .close_account("Assets:Cash", make_date(2024, 1, 15))
            .unwrap();

        let txn = simple_balanced_txn(); // date = 2024-01-15
        let result = validate_transaction(&txn, &accounts);
        assert!(
            result.is_ok(),
            "Same-day close should be allowed: {result:?}"
        );
    }

    #[test]
    fn test_ct7_account_opened_after_date_rejected() {
        let mut accounts = AccountState::new();
        accounts
            .open_account("Assets:Cash", make_date(2024, 2, 1), &[])
            .unwrap();
        accounts
            .open_account("Equity:Opening", make_date(2024, 1, 1), &[])
            .unwrap();

        let txn = simple_balanced_txn(); // date = 2024-01-15
        let err = validate_transaction(&txn, &accounts).unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_NOT_OPEN");
    }

    // ── I9: currency constraints ─────────────────────────────────────────

    #[test]
    fn test_i9_currency_mismatch_rejected() {
        let accounts = setup_accounts();
        // Assets:Cash allows USD only.
        let mut txn = simple_balanced_txn();
        txn.postings[0].amount = Some(Amount {
            number: dec!(100),
            currency: "EUR".to_owned(),
        });
        txn.postings[1].amount = Some(Amount {
            number: dec!(-100),
            currency: "EUR".to_owned(),
        });

        let err = validate_transaction(&txn, &accounts).unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_CURRENCY_MISMATCH");
    }

    #[test]
    fn test_i9_unconstrained_account_accepts_any() {
        let accounts = setup_accounts();
        // Equity:Opening has no currency constraint.
        let mut txn = simple_balanced_txn();
        txn.postings[0].amount = Some(Amount {
            number: dec!(100),
            currency: "USD".to_owned(),
        });
        txn.postings[1].amount = Some(Amount {
            number: dec!(-100),
            currency: "USD".to_owned(),
        });
        let result = validate_transaction(&txn, &accounts);
        assert!(result.is_ok());
    }

    // ── Account state management ─────────────────────────────────────────

    #[test]
    fn test_account_state_lifecycle() {
        let mut state = AccountState::new();
        assert!(!state.is_known("Assets:Cash"));

        state
            .open_account("Assets:Cash", make_date(2024, 1, 1), &["USD".to_owned()])
            .unwrap();
        assert!(state.is_known("Assets:Cash"));

        assert!(state
            .check_account_open("Assets:Cash", make_date(2024, 1, 1))
            .is_ok());
        assert!(state
            .check_account_open("Assets:Cash", make_date(2024, 6, 1))
            .is_ok());

        state
            .close_account("Assets:Cash", make_date(2024, 12, 31))
            .unwrap();
        // Same-day close is OK.
        assert!(state
            .check_account_open("Assets:Cash", make_date(2024, 12, 31))
            .is_ok());
        // Day after close is not.
        assert!(state
            .check_account_open("Assets:Cash", make_date(2025, 1, 1))
            .is_err());
    }

    #[test]
    fn test_currency_constraint() {
        let mut state = AccountState::new();
        state
            .open_account(
                "Assets:Cash",
                make_date(2024, 1, 1),
                &["USD".to_owned(), "EUR".to_owned()],
            )
            .unwrap();

        // Queried at a date the `open` is in force on, which is the only form
        // the validation paths use (T41 removed the date-free variant).
        let at = make_date(2024, 6, 1);
        assert!(state
            .check_currency_constraint_at("Assets:Cash", "USD", at)
            .is_ok());
        assert!(state
            .check_currency_constraint_at("Assets:Cash", "EUR", at)
            .is_ok());
        assert!(state
            .check_currency_constraint_at("Assets:Cash", "GBP", at)
            .is_err());
    }

    #[test]
    fn test_close_unknown_account_error() {
        let mut state = AccountState::new();
        let err = state
            .close_account("Assets:Cash", make_date(2024, 1, 1))
            .unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_NOT_OPEN");
    }

    // ── Cost + price same posting ────────────────────────────────────────

    #[test]
    fn test_cost_and_price_same_posting_rejected() {
        let accounts = setup_accounts();
        let txn = Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Invalid".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
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
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-1500),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };
        let err = validate_transaction(&txn, &accounts).unwrap_err();
        assert_eq!(err.error_code(), "INVALID_POSTING");
    }
}
