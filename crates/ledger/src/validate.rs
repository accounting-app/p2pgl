//! Ledger invariant validation (§2.4: I1, I2, I3, I9).
//!
//! These checks apply to both local writes and remote gossip inserts (§3.5).

use std::ops::Bound;

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

// ─── Amount magnitude cap (H-17, T76) ────────────────────────────────────────

use crate::limits::MAX_AMOUNT_MAGNITUDE;

/// Whether `number` is inside the amount cap: `|number| ≤`
/// [`MAX_AMOUNT_MAGNITUDE`] (`10^21`), at any precision (T76).
///
/// Compared exactly on the integers: `|mantissa| ≤ 10^21 × 10^scale`. From
/// scale 8 on, `10^(21 + scale)` exceeds every mantissa a `Decimal` can hold,
/// so every such amount is inside the cap.
pub fn amount_within_cap(number: Decimal) -> bool {
    let magnitude = number.mantissa().unsigned_abs();
    match 10u128.checked_pow(number.scale()) {
        Some(unit) => match MAX_AMOUNT_MAGNITUDE.checked_mul(unit) {
            Some(bound) => magnitude <= bound,
            // `10^(21 + scale)` past `u128` is past every mantissa too.
            None => true,
        },
        None => true,
    }
}

/// An amount outside the cap, naming which amount it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmountCapError {
    /// Which amount: `"posting amount"`, `"cost"`, `"unit price"`, ….
    pub label: &'static str,
    /// The refused number, exactly as held.
    pub number: Decimal,
}

impl std::fmt::Display for AmountCapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} exceeds the amount cap: an amount that is summed into a balance must \
             have magnitude at most {MAX_AMOUNT_MAGNITUDE} (10^21) (H-17, M-50)",
            self.label, self.number
        )
    }
}

impl std::error::Error for AmountCapError {}

/// Why a well-formed decimal spelling cannot be held as an amount, when the
/// reason is its length (T83 / L-92) — `None` for anything else, so callers
/// keep their own message.
///
/// A stored amount is a `Decimal`: a 96-bit mantissa (about 7.9 × 10^28) and
/// at most 28 fractional digits. Every digit counts toward the mantissa,
/// trailing zeros included, so `1000000000000000000000.00000000` (10^21 with
/// 8 decimals, 30 digits) cannot be represented although its value is within
/// the cap — 10^21 admits at most 7 decimal places. Before T83 both ingress
/// paths said only "Invalid decimal string" / "Invalid number".
pub fn explain_unrepresentable_amount(text: &str) -> Option<String> {
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let (integer, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let digits = |part: &str| {
        part.chars()
            .filter(|c| *c != '_' && *c != ',')
            .collect::<String>()
    };
    let (integer, fraction) = (digits(integer), digits(fraction));
    if integer.is_empty() && fraction.is_empty()
        || !integer
            .chars()
            .chain(fraction.chars())
            .all(|c| c.is_ascii_digit())
    {
        return None;
    }
    if fraction.len() > 28 {
        return Some(format!(
            "amount {text} has {} fractional digits; at most 28 are kept, and more are refused \
             rather than rounded (H-17)",
            fraction.len()
        ));
    }
    // Exact: the digits, as one integer, against the 96-bit mantissa.
    let mantissa_digits = format!("{integer}{fraction}");
    let mantissa_digits = mantissa_digits.trim_start_matches('0');
    let significant = mantissa_digits.len();
    const MAX_MANTISSA: u128 = (1u128 << 96) - 1;
    let too_long = !mantissa_digits.is_empty()
        && (significant > 38
            || mantissa_digits
                .parse::<u128>()
                .map_or(true, |mantissa| mantissa > MAX_MANTISSA));
    if too_long {
        return Some(format!(
            "amount {text} has {significant} significant digits, trailing zeros included; a \
             stored amount holds at most 28 (29 below about 7.9 × 10^28), so 10^21 admits at \
             most 7 decimal places — drop trailing zeros or decimals (L-92)"
        ));
    }
    None
}

/// Refuse `number` if it is outside the amount cap.
pub fn check_amount_cap(label: &'static str, number: Decimal) -> Result<(), AmountCapError> {
    if amount_within_cap(number) {
        Ok(())
    } else {
        Err(AmountCapError { label, number })
    }
}

/// Every amount one posting stores and sums — units, cost, price — against
/// the cap.
fn check_posting_amounts(posting: &Posting) -> Result<(), AmountCapError> {
    if let Some(ref amount) = posting.amount {
        check_amount_cap("posting amount", amount.number)?;
    }
    if let Some(cost_amount) = posting.cost.as_ref().and_then(|cost| cost.amount.as_ref()) {
        check_amount_cap("cost", cost_amount.number)?;
    }
    match posting.price {
        Some(PriceSpec::Unit(ref amount)) => check_amount_cap("unit price", amount.number),
        Some(PriceSpec::Total(ref amount)) => check_amount_cap("total price", amount.number),
        None => Ok(()),
    }
}

/// Every capped amount `directive` carries: a transaction's posting units,
/// costs and prices.
///
/// `balance` and `price` directive amounts are **not** capped (T76): neither
/// is ever summed — a `balance` is compared exactly against a sum, a `price`
/// is a quote — so neither can make a total unrepresentable, and pre-T65
/// history holds `balance` lines over `10^21` that must keep loading (the M-50
/// fixture's `balance … 1000000000000000000014 USD`).
///
/// [`validate_transaction`] runs the same check for transactions on every
/// path that validates one (local API, peer ingest, reconcile and
/// operator-input adoption, boot's salvage path), and the `.bean` number
/// reader applies it to every posting amount it reads, which covers the wire
/// (`validate_supply_entry` re-parses the body), journal replay and the file
/// path, where boot quarantines the block. This `pub` form is boot's
/// directive-level quarantine arm.
pub fn check_directive_amounts(directive: &Directive) -> Result<(), AmountCapError> {
    match directive {
        Directive::Transaction(transaction) => transaction
            .postings
            .iter()
            .try_for_each(check_posting_amounts),
        Directive::Balance(_)
        | Directive::Price(_)
        | Directive::Open(_)
        | Directive::Close(_)
        | Directive::Commodity(_)
        | Directive::Pad(_)
        | Directive::Note(_)
        | Directive::Document(_)
        | Directive::Event(_) => Ok(()),
    }
}

/// The cap refusal as the I1-family error `validate_transaction` reports.
///
/// `InvalidPosting` rather than a new variant: its `INVALID_POSTING` code is
/// already what a malformed amount reports, and a new variant would break the
/// exhaustive retryability match the wire intake keeps over this enum.
fn amount_cap_violation(error: AmountCapError) -> ValidationError {
    ValidationError::InvalidPosting {
        message: error.to_string(),
    }
}

// ─── Transaction validation ─────────────────────────────────────────────────

/// Validate a transaction against I1 (balance), I2 (elision), I3 (account lifecycle),
/// and I9 (currency constraint).
///
/// If the transaction has an elided posting, this resolves it in-place.
/// Returns the resolved transaction (with elided posting filled in, if any).
///
/// Also enforces the amount cap ([`MAX_AMOUNT_MAGNITUDE`], `|amount| ≤ 10^21`
/// at any precision) on every amount the transaction carries — units, cost,
/// price — and on the resolved elided amount. Every path that admits a
/// transaction runs this function, so the cap holds on each of them without a
/// second call site.
pub fn validate_transaction(
    txn: &Transaction,
    accounts: &AccountState,
) -> Result<Transaction, ValidationError> {
    validate_transaction_under(txn, accounts, LifecycleRule::Authoring(None))
}

/// [`validate_transaction`] for DATA — a transaction a peer supplied, the
/// `.bean` holds, or the served-set rule re-judges (T98 / M-09 remainder,
/// decision (54)): I3 and I9 by [`AccountState::check_account_opened_by`] and
/// [`AccountState::check_currency_admitted_by`], so a `close` never refuses it
/// and every replica admits the same set in every arrival order. I1, I2 and
/// the amount cap are the same as for a local write.
pub fn validate_transaction_as_data(
    txn: &Transaction,
    accounts: &AccountState,
) -> Result<Transaction, ValidationError> {
    validate_transaction_under(txn, accounts, LifecycleRule::Data)
}

/// I3 for a `balance` assertion as DATA (R-15): an `open` of its account dated
/// on or before it, by the same rule a transaction is held to
/// ([`AccountState::check_account_opened_by`]). Before, every path admitted a
/// `balance` on any account at all, so one peer could add unlimited assertions
/// on accounts the ledger never opened. A peer's assertion that fails this
/// waits for the account's `open`, as a transaction does, so the admitted set
/// does not depend on arrival order.
pub fn validate_balance_as_data(
    balance: &Balance,
    accounts: &AccountState,
) -> Result<(), ValidationError> {
    accounts.check_account_opened_by(&balance.account, balance.date)
}

/// [`validate_transaction`] for THIS NODE'S OWN write (T98 / M-09 remainder,
/// decision (54)): the lifecycle fold with its `close`s, except that a `close`
/// is inert over an interval that already holds a transaction —
/// `holds_posting_in(account, interval)` answers that for the interval
/// [`AccountState::deciding_close_interval`] gives. Every replica admits such
/// a transaction as data whatever the `close` says, so refusing this node's
/// write beside it would let one peer's back-dated `close` shut the account
/// for local writes alone (the M-09 write-DoS). A `close` with nothing held
/// after it still binds: authoring stays stricter than acceptance.
pub fn validate_transaction_as_author(
    txn: &Transaction,
    accounts: &AccountState,
    holds_posting_in: HoldsPostingIn<'_>,
) -> Result<Transaction, ValidationError> {
    validate_transaction_under(
        txn,
        accounts,
        LifecycleRule::Authoring(Some(holds_posting_in)),
    )
}

/// A range of transaction dates, as `BTreeSet::range` takes it (T98).
pub type DateInterval = (Bound<NaiveDate>, Bound<NaiveDate>);

/// "Is a transaction with a posting on this account dated inside this
/// interval held?" — the read model answers it for
/// [`validate_transaction_as_author`] (T98).
pub type HoldsPostingIn<'a> = &'a dyn Fn(&str, DateInterval) -> bool;

/// Which lifecycle rule I3 and I9 apply (T98, decision (54)).
#[derive(Clone, Copy)]
enum LifecycleRule<'a> {
    /// This node's own write: the fold with its `close`s, a `close` inert
    /// where the given index holds a posting inside its interval (none given:
    /// every `close` binds — [`validate_transaction`]).
    Authoring(Option<HoldsPostingIn<'a>>),
    /// Directive-set data: any `open` at or before the date admits it.
    Data,
}

fn validate_transaction_under(
    txn: &Transaction,
    accounts: &AccountState,
    rule: LifecycleRule<'_>,
) -> Result<Transaction, ValidationError> {
    // ── H-17 / T76: the amount cap, before any arithmetic ───────────────
    //
    // First, so an over-cap amount is refused by name rather than surfacing
    // as whatever overflow the weight arithmetic below happens to hit.
    txn.postings
        .iter()
        .try_for_each(check_posting_amounts)
        .map_err(amount_cap_violation)?;

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

        // H-17 / T76: the resolved amount is stored, hashed, replicated and
        // summed into a balance like any other, and it is a SUM — of up to
        // every other posting's weight, and a weight is a unit × rate product
        // — so every posting being inside the cap does not put the fill
        // inside it. It is capped as stored: its spelling (trailing zeros
        // included) is part of the content id, and the cap is a magnitude, so
        // `-100000.0000000000000000` is as far inside it as `-100000`.
        check_amount_cap("resolved elided amount", resolved_amount.number)
            .map_err(amount_cap_violation)?;

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
    //
    // T98 / M-09 remainder, decision (54): data is judged without the
    // `close`s (see `LifecycleRule`); only this node's own write is held to
    // them.
    for posting in &txn.postings {
        let inert_close = |holds: HoldsPostingIn<'_>| {
            accounts
                .deciding_close_interval(&posting.account, txn.date)
                .is_some_and(|interval| holds(&posting.account, interval))
        };
        let rule = match rule {
            LifecycleRule::Authoring(Some(holds))
                if matches!(
                    accounts.check_account_open(&posting.account, txn.date),
                    Err(ValidationError::AccountClosed { .. })
                ) && inert_close(holds) =>
            {
                LifecycleRule::Data
            }
            other => other,
        };
        match rule {
            LifecycleRule::Authoring(_) => {
                accounts.check_account_open(&posting.account, txn.date)?;
                if let Some(ref amount) = posting.amount {
                    accounts.check_currency_constraint_at(
                        &posting.account,
                        &amount.currency,
                        txn.date,
                    )?;
                }
            }
            LifecycleRule::Data => {
                accounts.check_account_opened_by(&posting.account, txn.date)?;
                if let Some(ref amount) = posting.amount {
                    accounts.check_currency_admitted_by(
                        &posting.account,
                        &amount.currency,
                        txn.date,
                    )?;
                }
            }
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

    /// L-92 (T83): a spelling too long for a `Decimal` gets a reason, not
    /// "Invalid number" — at the value that motivated it (10^21 with 8
    /// decimals), at 28 fractional digits (fine) and 29 (refused), and never
    /// for a spelling that is malformed for another reason.
    #[test]
    fn l92_an_over_long_amount_spelling_is_explained() {
        let ten21_8 = "1000000000000000000000.00000000";
        assert!(
            rust_decimal::Decimal::from_str_exact(ten21_8).is_err(),
            "premise"
        );
        let message = explain_unrepresentable_amount(ten21_8).expect("explained");
        assert!(
            message.contains("30 significant digits") && message.contains("7 decimal places"),
            "{message}"
        );
        assert!(explain_unrepresentable_amount("1000000000000000000000.0000000").is_none());
        assert!(explain_unrepresentable_amount("-10.0000000000000000000000000000").is_some());
        assert!(explain_unrepresentable_amount(&format!("0.{}", "1".repeat(28))).is_none());
        let message = explain_unrepresentable_amount(&format!("0.{}", "1".repeat(29))).unwrap();
        assert!(message.contains("29 fractional digits"), "{message}");
        assert!(explain_unrepresentable_amount("12abc").is_none());
        assert!(explain_unrepresentable_amount("").is_none());
        assert!(explain_unrepresentable_amount("0.000").is_none());
        let parsed = crate::parse::parse_file(&format!(
            "2024-01-01 * \"x\"\n  Assets:A {ten21_8} USD\n  Equity:B\n"
        ));
        let rendered = format!("{:?}", parsed.unwrap_err());
        assert!(rendered.contains("L-92"), "{rendered}");
    }

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

    // ── H-17: the amount cap ─────────────────────────────────────────────

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

    fn pair(number: Decimal) -> Transaction {
        Transaction {
            postings: vec![
                posting("Assets:Cash", number, "USD"),
                posting("Equity:Opening", -number, "USD"),
            ],
            ..simple_balanced_txn()
        }
    }

    fn assert_cap_refusal(result: Result<Transaction, ValidationError>, what: &str) {
        let error = result.expect_err(what);
        assert_eq!(error.error_code(), "INVALID_POSTING", "{what}");
        assert!(error.to_string().contains("H-17"), "{what}: {error}");
    }

    /// `10^21 × 10^-scale`-units: the cap itself as a mantissa at `scale`.
    fn cap_mantissa_at(scale: u32) -> i128 {
        (MAX_AMOUNT_MAGNITUDE * 10u128.pow(scale)) as i128
    }

    /// T76: the boundary is a magnitude, inclusive, at any precision:
    /// `|amount| ≤ 10^21` passes and one unit in the last place beyond it does
    /// not, at every scale where the bound is below `Decimal::MAX`; from scale
    /// 8 on every `Decimal` is inside it. Trailing zeros are just precision.
    #[test]
    fn test_h17_cap_boundary() {
        let accounts = setup_accounts();
        for scale in 0u32..=7 {
            let largest = Decimal::from_i128_with_scale(cap_mantissa_at(scale), scale);
            assert!(amount_within_cap(largest) && amount_within_cap(-largest));
            validate_transaction(&pair(largest), &accounts)
                .unwrap_or_else(|e| panic!("{largest} is inside the cap: {e}"));
            let over = Decimal::from_i128_with_scale(cap_mantissa_at(scale) + 1, scale);
            assert!(
                !amount_within_cap(over) && !amount_within_cap(-over),
                "{over}"
            );
            assert_cap_refusal(validate_transaction(&pair(over), &accounts), "cap + 1 ulp");
        }
        for scale in [8u32, 21, 28] {
            let widest = Decimal::from_i128_with_scale(Decimal::MAX.mantissa(), scale);
            assert!(amount_within_cap(widest) && amount_within_cap(-widest));
            validate_transaction(&pair(widest), &accounts)
                .unwrap_or_else(|e| panic!("{widest} is below 10^21: {e}"));
        }
        // `10000000000000.00000000` is 10^13: 22 digits of mantissa are
        // precision, not magnitude (M-50's trailing-zero case).
        for padded in ["10000000000000.00000000", "1000000000000000000000.0000000"] {
            let padded: Decimal = padded.parse().unwrap();
            validate_transaction(&pair(padded), &accounts)
                .unwrap_or_else(|e| panic!("{padded} is inside the cap: {e}"));
        }
        // The B6 pair itself.
        assert_cap_refusal(validate_transaction(&pair(Decimal::MAX), &accounts), "MAX");
        assert_cap_refusal(validate_transaction(&pair(Decimal::MIN), &accounts), "MIN");
    }

    /// Cost and both price spellings are summed amounts too. The units are
    /// tiny, so the weight — and the elided leg it resolves — stays far inside
    /// the cap: only the cost / price check itself can refuse these.
    #[test]
    fn test_h17_cap_covers_cost_and_price() {
        let mut accounts = setup_accounts();
        accounts
            .open_account("Assets:Stock", make_date(2024, 1, 1), &[])
            .unwrap();
        // 10^21 + 0.01.
        let over = Amount {
            number: Decimal::from_i128_with_scale(cap_mantissa_at(2) + 1, 2),
            currency: "USD".to_owned(),
        };
        let stock = |cost: Option<CostSpec>, price: Option<PriceSpec>| Transaction {
            postings: vec![
                Posting {
                    cost,
                    price,
                    ..posting("Assets:Stock", dec!(0.000001), "AAPL")
                },
                Posting {
                    amount: None,
                    ..posting("Equity:Opening", dec!(0), "USD")
                },
            ],
            ..simple_balanced_txn()
        };
        for (what, txn) in [
            (
                "cost",
                stock(
                    Some(CostSpec {
                        amount: Some(over.clone()),
                        date: None,
                    }),
                    None,
                ),
            ),
            (
                "unit price",
                stock(None, Some(PriceSpec::Unit(over.clone()))),
            ),
            (
                "total price",
                stock(None, Some(PriceSpec::Total(over.clone()))),
            ),
        ] {
            assert_cap_refusal(validate_transaction(&txn, &accounts), what);
        }
    }

    /// The elided leg is a sum, so in-cap postings can resolve it past the
    /// cap; it is stored, replicated and summed like any other amount, so it
    /// is refused rather than stored.
    #[test]
    fn test_h17_cap_covers_the_resolved_elided_amount() {
        let accounts = setup_accounts();
        let at_cap = Decimal::from_i128_with_scale(cap_mantissa_at(0), 0);
        let mut txn = simple_balanced_txn();
        txn.postings = vec![
            posting("Assets:Cash", at_cap, "USD"),
            posting("Assets:Cash", at_cap, "USD"),
            Posting {
                amount: None,
                ..posting("Equity:Opening", dec!(0), "USD")
            },
        ];
        let error = validate_transaction(&txn, &accounts).unwrap_err();
        assert!(
            error.to_string().contains("resolved elided amount"),
            "{error}"
        );
        // One of them resolves to exactly −10^21: inside (inclusive).
        txn.postings.remove(0);
        validate_transaction(&txn, &accounts).expect("−10^21 is inside the cap");
    }

    /// T76: the check boot's quarantine arm calls caps what is summed — a
    /// transaction's amounts — and never a `balance` or `price` amount, which
    /// are compared or quoted, never summed.
    #[test]
    fn test_h17_check_directive_amounts_covers_every_summed_amount() {
        let date = make_date(2024, 1, 1);
        let amount = |number| Amount {
            number,
            currency: "USD".to_owned(),
        };
        let balance = |number| {
            Directive::Balance(Balance {
                date,
                account: "Assets:Cash".to_owned(),
                amount: amount(number),
                metadata: BTreeMap::new(),
            })
        };
        let price = |number| {
            Directive::Price(Price {
                date,
                currency: "EUR".to_owned(),
                amount: amount(number),
                metadata: BTreeMap::new(),
            })
        };
        let error =
            check_directive_amounts(&Directive::Transaction(pair(Decimal::MAX))).unwrap_err();
        assert!(error.to_string().contains("H-17"), "{error}");
        for directive in [
            balance(Decimal::MAX),
            price(-Decimal::MAX),
            balance(dec!(100.00)),
            price(dec!(1.10)),
            Directive::Transaction(pair(dec!(1))),
            Directive::Pad(Pad {
                date,
                account: "Assets:Cash".to_owned(),
                source_account: "Equity:Opening".to_owned(),
                metadata: BTreeMap::new(),
            }),
        ] {
            check_directive_amounts(&directive).unwrap();
        }
    }

    fn scratch_ledger(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "openledger-h17-{label}-{}-{nanos}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("ledger.bean")
    }

    /// The B6 shape — `±MAX` from a peer — and an over-cap amount on every
    /// other way in: the local API, peer ingest, a live reconcile of an
    /// external edit, and boot, which quarantines the block (kept in the file,
    /// out of the DAG) and loads the rest.
    #[test]
    fn test_h17_over_cap_amount_is_refused_on_every_ingress() {
        use crate::service::{LedgerService, PostingInput, TransactionInput};

        let opens = "2024-01-01 open Assets:Cash\n\n2024-01-01 open Equity:Opening\n";
        let over_cap_block =
            "2024-01-02 * \"too big\"\n  Assets:Cash 1000000000000000000000.0000001 USD\n  \
                              Equity:Opening -1000000000000000000000.0000001 USD\n";
        let honest_block = "2024-01-03 * \"honest\"\n  Assets:Cash 7 USD\n  \
                            Equity:Opening -7 USD\n";
        let cash = |svc: &LedgerService| {
            svc.read_model()
                .account_balance("Assets:Cash", None)
                .map(|entry| entry.balances["USD"])
        };

        // Local API.
        let path = scratch_ledger("local");
        let local_dir = path.parent().unwrap().to_path_buf();
        let mut svc = LedgerService::boot(&path, "h17".to_owned()).unwrap();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        let error = svc
            .append_transaction(TransactionInput {
                date: make_date(2024, 1, 2),
                flag: Flag::Complete,
                payee: None,
                narration: Some("too big".to_owned()),
                tags: vec![],
                links: vec![],
                postings: vec![
                    PostingInput {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: Decimal::MAX,
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                    },
                    PostingInput {
                        account: "Equity:Opening".to_owned(),
                        amount: None,
                        cost: None,
                        price: None,
                    },
                ],
            })
            .unwrap_err();
        assert!(error.to_string().contains("H-17"), "local: {error}");

        // Peer ingest: B6's `+MAX` later-dated / `-MAX` earlier-dated pair.
        for (day, number) in [(20, Decimal::MAX), (1, -Decimal::MAX)] {
            let mut metadata = BTreeMap::new();
            metadata.insert("openledger-author".to_owned(), "peer".to_owned());
            metadata.insert("openledger-lamport".to_owned(), format!("{}", 100 + day));
            metadata.insert("openledger-parents".to_owned(), String::new());
            let remote = Directive::Transaction(Transaction {
                date: make_date(2024, 1, day),
                metadata,
                ..pair(number)
            });
            let error = svc.stage_remote_directive(remote).unwrap_err();
            assert!(error.to_string().contains("H-17"), "remote: {error}");
        }
        assert_eq!(cash(&svc), None, "nothing over the cap reached the model");

        // Reconcile: the operator appends an over-cap record while running.
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push('\n');
        text.push_str(over_cap_block);
        std::fs::write(&path, &text).unwrap();
        let _ = svc.reconcile_file();
        assert_eq!(cash(&svc), None, "reconcile must not adopt it");
        assert_eq!(svc.read_model().over_cap_posting_count(), 0);
        drop(svc);

        let _ = std::fs::remove_dir_all(&local_dir);

        // Boot: history holding one over-cap block among honest ones.
        let path = scratch_ledger("boot");
        std::fs::write(&path, format!("{opens}\n{over_cap_block}\n{honest_block}")).unwrap();
        let svc = LedgerService::boot(&path, "h17".to_owned()).unwrap();
        assert_eq!(
            svc.unparsable_block_count(),
            1,
            "the over-cap block is quarantined"
        );
        assert_eq!(cash(&svc), Some(dec!(7)), "the rest of the file loads");
        assert_eq!(svc.read_model().over_cap_posting_count(), 0);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.contains("1000000000000000000000.0000001 USD"),
            "quarantined, not deleted (H-08)"
        );
        drop(svc);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
