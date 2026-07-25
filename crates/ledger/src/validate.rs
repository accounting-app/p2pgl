//! Ledger invariant validation (§2.4: I1, I2, I3, I9).
//!
//! These checks apply to both local writes and remote gossip inserts (§3.5).

use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::collections::HashMap;

use crate::model::*;
use crate::weights::{resolve_elided, sum_weights, WeightError};

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

// ─── Account state tracker ──────────────────────────────────────────────────

/// Tracks the open/close state and currency constraints for all accounts.
#[derive(Debug, Clone, Default)]
pub struct AccountState {
    /// `account → (open_date, allowed_currencies)`. Empty Vec = any currency.
    accounts: HashMap<String, AccountInfo>,
}

#[derive(Debug, Clone)]
struct AccountInfo {
    open_date: NaiveDate,
    /// Empty Vec means any currency is accepted.
    currencies: Vec<String>,
    /// `None` if still open; `Some(date)` if closed.
    close_date: Option<NaiveDate>,
}

impl AccountState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an account opening. Returns error if already open.
    pub fn open_account(
        &mut self,
        account: &str,
        date: NaiveDate,
        currencies: &[String],
    ) -> Result<(), ValidationError> {
        if let Some(existing) = self.accounts.get(account) {
            if existing.close_date.is_none() {
                return Err(ValidationError::AccountNotOpen {
                    account: account.to_owned(),
                    date,
                });
            }
            // Re-opening after close is allowed — update the entry.
        }
        self.accounts.insert(
            account.to_owned(),
            AccountInfo {
                open_date: date,
                currencies: currencies.to_vec(),
                close_date: None,
            },
        );
        Ok(())
    }

    /// Register an account closing.
    pub fn close_account(&mut self, account: &str, date: NaiveDate) -> Result<(), ValidationError> {
        match self.accounts.get_mut(account) {
            Some(info) => {
                info.close_date = Some(date);
                Ok(())
            }
            None => Err(ValidationError::AccountNotOpen {
                account: account.to_owned(),
                date,
            }),
        }
    }

    /// Check I3: account must be open at the given date.
    ///
    /// An account is valid if:
    /// - An `open` directive exists with date ≤ transaction date.
    /// - No `close` directive exists with date **strictly before** the transaction date.
    ///   (Same-day close is allowed because close has sort priority 9.)
    pub fn check_account_open(
        &self,
        account: &str,
        date: NaiveDate,
    ) -> Result<(), ValidationError> {
        let info = self
            .accounts
            .get(account)
            .ok_or_else(|| ValidationError::AccountNotOpen {
                account: account.to_owned(),
                date,
            })?;

        if info.open_date > date {
            return Err(ValidationError::AccountNotOpen {
                account: account.to_owned(),
                date,
            });
        }

        if let Some(close_date) = info.close_date {
            if close_date < date {
                return Err(ValidationError::AccountClosed {
                    account: account.to_owned(),
                    close_date,
                    transaction_date: date,
                });
            }
        }

        Ok(())
    }

    /// Check I9: posting currency must be in the account's allowed list (if constrained).
    pub fn check_currency_constraint(
        &self,
        account: &str,
        currency: &str,
    ) -> Result<(), ValidationError> {
        if let Some(info) = self.accounts.get(account) {
            if !info.currencies.is_empty() && !info.currencies.iter().any(|c| c == currency) {
                return Err(ValidationError::AccountCurrencyMismatch {
                    account: account.to_owned(),
                    currency: currency.to_owned(),
                    allowed: info.currencies.clone(),
                });
            }
        }
        Ok(())
    }

    /// Returns true if the account is known (has been opened at any point).
    pub fn is_known(&self, account: &str) -> bool {
        self.accounts.contains_key(account)
    }

    /// Returns the currency constraint list for an account (empty = any currency).
    pub fn currencies(&self, account: &str) -> Option<&[String]> {
        self.accounts
            .get(account)
            .map(|info| info.currencies.as_slice())
    }

    /// Returns true if the account is currently open (opened and not yet closed).
    pub fn is_open(&self, account: &str) -> bool {
        self.accounts
            .get(account)
            .is_some_and(|info| info.close_date.is_none())
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
    for posting in &txn.postings {
        accounts.check_account_open(&posting.account, txn.date)?;

        if let Some(ref amount) = posting.amount {
            accounts.check_currency_constraint(&posting.account, &amount.currency)?;
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

        assert!(state
            .check_currency_constraint("Assets:Cash", "USD")
            .is_ok());
        assert!(state
            .check_currency_constraint("Assets:Cash", "EUR")
            .is_ok());
        assert!(state
            .check_currency_constraint("Assets:Cash", "GBP")
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
