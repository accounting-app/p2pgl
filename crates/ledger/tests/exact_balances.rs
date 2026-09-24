//! T76 (M-50, L-79, Info: trailing zeros) — exact balances.
//!
//! These tests defined "done" for T76 before any accumulation code changed
//! (the design is `$SCRATCH/T76-design/DESIGN.md`) and now pin what landed,
//! under the user's decision (4) as refined on 2026-09-23:
//!
//! * every `(account, currency)` balance is the **exact** sum of its amounts,
//!   in any arrival order, on every read path, through the peer path and
//!   across reboots;
//! * a total is reported as a `Decimal` **exactly** whenever it fits 96 bits at
//!   its representation scale (the pre-T76 scale rule, preserved digit for
//!   digit); otherwise it is rounded **once**, half-to-even, from the exact
//!   value, to the finest scale that fits — never the per-scale double
//!   rounding L-79 measured;
//! * a `balance` assertion is compared against the exact sum, never the
//!   rounded one;
//! * the amount cap is ONE magnitude rule on every path — `|amount| ≤ 10^21`
//!   at any precision ([`MAX_AMOUNT_MAGNITUDE`]), inclusive — for every
//!   summed amount (posting units, cost, price, the resolved elided leg);
//!   `balance` and `price` directive amounts are never summed and never
//!   capped. So the M-50 pre-T65 history (`10^21`, trailing-zero legs) loads,
//!   an amount past `10^21` is refused locally, from a peer, on the wire and
//!   at boot alike, and no total can be unrepresentable for anyone.
//!
//! # The oracle is independent
//!
//! [`oracle`] is a sign-magnitude base-10^9 big integer written for this file.
//! It never calls the ledger's arithmetic: it sums mantissas exactly per scale
//! and applies the rule above by long division. `rust_decimal` is used only to
//! read an amount's `(mantissa, scale)` and to spell an expected value. It is
//! also what checks the ledger's in-crate `i256` (`ledger::wide`), which the
//! read-time conversion runs on.
//!
//! # API adapters
//!
//! Every read of a balance goes through the `read_*` / `assertion_*` helpers
//! below, so the properties do not depend on the Rust surface.
//!
//! CT-9 (byte-identical `.bean` after partition-and-converge) is pinned by
//! `ledger::service::tests::ct9_two_nodes_converge_after_partition`; T76 must
//! leave it green and byte-identical. The stored spelling of an amount (and so
//! every content id) is pinned by `hash::tests::test_ct3_worked_fixture_txid`
//! and `service::tests::test_single_currency_elision_txid_is_pinned`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::NaiveDate;
use ledger::checkpoint::{evaluate_all_assertions, evaluate_balance_assertion};
use ledger::hash::compute_content_id;
use ledger::limits::MAX_AMOUNT_MAGNITUDE;
use ledger::model::{Amount, Balance, Directive, Flag, Open, Posting, PriceSpec, Transaction};
use ledger::parse::parse_file;
use ledger::read_model::ReadModel;
use ledger::serialize::economic_canonical_serialize;
use ledger::service::{LedgerService, PostingInput, ServiceError, TransactionInput};
use ledger::verify::verify_dag;
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;
use rust_decimal::Decimal;

// ─── The independent oracle ──────────────────────────────────────────────────

mod oracle {
    use rust_decimal::Decimal;
    use std::cmp::Ordering;
    use std::collections::BTreeMap;

    const BASE: u64 = 1_000_000_000;

    /// A signed integer of any size: little-endian base-10^9 limbs, no leading
    /// zero limb, and zero is never negative.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Big {
        negative: bool,
        limbs: Vec<u32>,
    }

    impl Big {
        pub fn zero() -> Big {
            Big {
                negative: false,
                limbs: Vec::new(),
            }
        }

        pub fn from_u128(mut value: u128) -> Big {
            let mut limbs = Vec::new();
            while value > 0 {
                limbs.push((value % u128::from(BASE)) as u32);
                value /= u128::from(BASE);
            }
            Big {
                negative: false,
                limbs,
            }
        }

        pub fn from_i128(value: i128) -> Big {
            let magnitude = Big::from_u128(value.unsigned_abs());
            if value < 0 {
                magnitude.negated()
            } else {
                magnitude
            }
        }

        pub fn is_zero(&self) -> bool {
            self.limbs.is_empty()
        }

        fn trimmed(mut self) -> Big {
            while self.limbs.last() == Some(&0) {
                self.limbs.pop();
            }
            if self.limbs.is_empty() {
                self.negative = false;
            }
            self
        }

        fn compare_magnitude(a: &[u32], b: &[u32]) -> Ordering {
            a.len()
                .cmp(&b.len())
                .then_with(|| a.iter().rev().cmp(b.iter().rev()))
        }

        fn add_magnitude(a: &[u32], b: &[u32]) -> Vec<u32> {
            let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
            let mut carry = 0u64;
            for index in 0..a.len().max(b.len()) {
                let sum = carry
                    + u64::from(*a.get(index).unwrap_or(&0))
                    + u64::from(*b.get(index).unwrap_or(&0));
                out.push((sum % BASE) as u32);
                carry = sum / BASE;
            }
            if carry > 0 {
                out.push(carry as u32);
            }
            out
        }

        /// `a − b` for `|a| ≥ |b|`.
        fn subtract_magnitude(a: &[u32], b: &[u32]) -> Vec<u32> {
            let mut out = Vec::with_capacity(a.len());
            let mut borrow = 0i64;
            for (index, &limb) in a.iter().enumerate() {
                let mut digit = i64::from(limb) - borrow - i64::from(*b.get(index).unwrap_or(&0));
                if digit < 0 {
                    digit += BASE as i64;
                    borrow = 1;
                } else {
                    borrow = 0;
                }
                out.push(digit as u32);
            }
            out
        }

        pub fn add(&self, other: &Big) -> Big {
            let result = if self.negative == other.negative {
                Big {
                    negative: self.negative,
                    limbs: Big::add_magnitude(&self.limbs, &other.limbs),
                }
            } else if Big::compare_magnitude(&self.limbs, &other.limbs) == Ordering::Less {
                Big {
                    negative: other.negative,
                    limbs: Big::subtract_magnitude(&other.limbs, &self.limbs),
                }
            } else {
                Big {
                    negative: self.negative,
                    limbs: Big::subtract_magnitude(&self.limbs, &other.limbs),
                }
            };
            result.trimmed()
        }

        pub fn negated(&self) -> Big {
            let mut result = self.clone();
            if !result.is_zero() {
                result.negative = !result.negative;
            }
            result
        }

        pub fn magnitude(&self) -> Big {
            Big {
                negative: false,
                limbs: self.limbs.clone(),
            }
        }

        fn multiply_small(&self, factor: u32) -> Big {
            let mut out = Vec::with_capacity(self.limbs.len() + 1);
            let mut carry = 0u64;
            for &limb in &self.limbs {
                let product = u64::from(limb) * u64::from(factor) + carry;
                out.push((product % BASE) as u32);
                carry = product / BASE;
            }
            while carry > 0 {
                out.push((carry % BASE) as u32);
                carry /= BASE;
            }
            Big {
                negative: self.negative,
                limbs: out,
            }
            .trimmed()
        }

        /// `self × 10^exponent`.
        pub fn times_power_of_ten(&self, mut exponent: u32) -> Big {
            let mut result = self.clone();
            while exponent >= 9 {
                if !result.is_zero() {
                    result.limbs.insert(0, 0);
                }
                exponent -= 9;
            }
            if exponent > 0 {
                result = result.multiply_small(10u32.pow(exponent));
            }
            result
        }

        /// `(⌊|self| / divisor⌋, |self| mod divisor)`, on the magnitude.
        fn divide_magnitude_small(&self, divisor: u32) -> (Big, u32) {
            let mut quotient = vec![0u32; self.limbs.len()];
            let mut remainder = 0u64;
            for index in (0..self.limbs.len()).rev() {
                let current = remainder * BASE + u64::from(self.limbs[index]);
                quotient[index] = (current / u64::from(divisor)) as u32;
                remainder = current % u64::from(divisor);
            }
            (
                Big {
                    negative: false,
                    limbs: quotient,
                }
                .trimmed(),
                remainder as u32,
            )
        }

        fn is_odd(&self) -> bool {
            self.limbs.first().is_some_and(|limb| limb % 2 == 1)
        }

        /// `self / 10^exponent` rounded half to even (sign-symmetric).
        pub fn divide_by_power_of_ten_half_even(&self, exponent: u32) -> Big {
            let mut quotient = self.magnitude();
            let mut last_dropped = 0u32;
            let mut sticky = false;
            for _ in 0..exponent {
                let (next, digit) = quotient.divide_magnitude_small(10);
                sticky |= last_dropped != 0;
                last_dropped = digit;
                quotient = next;
            }
            let round_up = last_dropped > 5 || (last_dropped == 5 && (sticky || quotient.is_odd()));
            if round_up {
                quotient = quotient.add(&Big::from_u128(1));
            }
            if self.negative {
                quotient.negated()
            } else {
                quotient
            }
        }

        /// `self / 10^exponent` when that division is exact.
        pub fn divide_by_power_of_ten_exactly(&self, exponent: u32) -> Option<Big> {
            let mut quotient = self.magnitude();
            for _ in 0..exponent {
                let (next, digit) = quotient.divide_magnitude_small(10);
                if digit != 0 {
                    return None;
                }
                quotient = next;
            }
            Some(if self.negative {
                quotient.negated()
            } else {
                quotient
            })
        }

        /// A value from a sign and little-endian base-2^64 limbs, by doubling
        /// (A5, 0924): the readout of `wide::I256`'s binary representation,
        /// sharing nothing with the operations under test.
        pub fn from_base_2_64_limbs(negative: bool, limbs: &[u64]) -> Big {
            let mut value = Big::zero();
            for &limb in limbs.iter().rev() {
                for _ in 0..64 {
                    value = value.add(&value);
                }
                value = value.add(&Big::from_u128(u128::from(limb)));
            }
            if negative {
                value.negated()
            } else {
                value
            }
        }

        pub fn is_negative(&self) -> bool {
            self.negative
        }

        /// Sign-aware comparison (A5, 0924).
        pub fn compare(&self, other: &Big) -> Ordering {
            match (self.negative, other.negative) {
                (false, true) => Ordering::Greater,
                (true, false) => Ordering::Less,
                (false, false) => Big::compare_magnitude(&self.limbs, &other.limbs),
                (true, true) => Big::compare_magnitude(&other.limbs, &self.limbs),
            }
        }

        /// The value as an `i128`, when its magnitude fits 96 bits — the
        /// mantissa range of a `Decimal`.
        pub fn to_decimal_mantissa(&self) -> Option<i128> {
            let bound = Big::from_u128((1u128 << 96) - 1);
            if Big::compare_magnitude(&self.limbs, &bound.limbs) == Ordering::Greater {
                return None;
            }
            let mut value: i128 = 0;
            for &limb in self.limbs.iter().rev() {
                value = value * i128::from(BASE as u32) + i128::from(limb);
            }
            Some(if self.negative { -value } else { value })
        }
    }

    /// What a balance must be reported as, per the T76 rule.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Expected {
        /// The exact sum fits 96 bits at its representation scale.
        Exact(Decimal),
        /// It does not: the exact sum rounded once, half to even, to the
        /// finest scale at which it fits.
        Rounded(Decimal),
        /// No `Decimal` holds it even at scale 0.
        OutOfRange,
    }

    impl Expected {
        /// The variant and the value's exact spelling. `Decimal`'s `==`
        /// compares values (`3.00 == 3`), so every oracle check compares this.
        pub fn spelled(&self) -> String {
            match self {
                Expected::Exact(value) => format!("Exact({value})"),
                Expected::Rounded(value) => format!("Rounded({value})"),
                Expected::OutOfRange => "OutOfRange".to_owned(),
            }
        }

        pub fn value(&self) -> Option<Decimal> {
            match self {
                Expected::Exact(value) | Expected::Rounded(value) => Some(*value),
                Expected::OutOfRange => None,
            }
        }
    }

    /// The exact per-scale sums of a multiset of amounts.
    #[derive(Clone, Debug, Default)]
    pub struct ExactSum {
        /// scale → exact sum of the mantissas of the amounts at that scale.
        partials: BTreeMap<u32, Big>,
    }

    /// Every amount is re-expressed at this scale for the exact total.
    const FINEST: u32 = 28;

    impl ExactSum {
        pub fn of(amounts: &[Decimal]) -> ExactSum {
            let mut sum = ExactSum::default();
            for amount in amounts {
                sum.add(*amount);
            }
            sum
        }

        pub fn add(&mut self, amount: Decimal) {
            let partial = self
                .partials
                .entry(amount.scale())
                .or_insert_with(Big::zero);
            *partial = partial.add(&Big::from_i128(amount.mantissa()));
        }

        /// The exact value in units of `10^-28`.
        pub fn value_at_finest(&self) -> Big {
            self.partials
                .iter()
                .fold(Big::zero(), |total, (&scale, partial)| {
                    total.add(&partial.times_power_of_ten(FINEST - scale))
                })
        }

        /// The scale a balance is spelled at — today's rule, which T76 keeps.
        ///
        /// Walk the per-scale partials in ascending scale: a partial sets the
        /// scale when it is non-zero, or when the running exact total before it
        /// is zero; a zero partial after a non-zero running total leaves the
        /// scale alone. (This is what `rust_decimal`'s `0 + x = x` and
        /// `x + 0 = x` fast paths make the ascending fold do: `[2, −1, 0.1,
        /// −0.1]` is `1`, `[1, −1.0, 0.00]` is `0.00`.) It is a function of
        /// the partials alone, so of the multiset — never of arrival order.
        pub fn representation_scale(&self) -> u32 {
            let mut running = Big::zero();
            let mut scale = 0;
            for (&partial_scale, partial) in &self.partials {
                if running.is_zero() || !partial.is_zero() {
                    scale = partial_scale;
                }
                running = running.add(&partial.times_power_of_ten(FINEST - partial_scale));
            }
            scale
        }

        pub fn expected(&self) -> Expected {
            let exact = self.value_at_finest();
            let scale = self.representation_scale();
            let at_scale = exact
                .divide_by_power_of_ten_exactly(FINEST - scale)
                .expect("the representation scale is at least every non-zero partial's scale");
            if let Some(mantissa) = at_scale.to_decimal_mantissa() {
                return Expected::Exact(Decimal::from_i128_with_scale(mantissa, scale));
            }
            for coarser in (0..scale).rev() {
                let rounded = exact.divide_by_power_of_ten_half_even(FINEST - coarser);
                if let Some(mantissa) = rounded.to_decimal_mantissa() {
                    return Expected::Rounded(Decimal::from_i128_with_scale(mantissa, coarser));
                }
            }
            Expected::OutOfRange
        }

        /// Whether `claim` is exactly the sum (the rule a `balance` assertion
        /// must follow).
        pub fn equals(&self, claim: Decimal) -> bool {
            let claim_at_finest =
                Big::from_i128(claim.mantissa()).times_power_of_ten(FINEST - claim.scale());
            claim_at_finest == self.value_at_finest()
        }
    }
}

use oracle::{ExactSum, Expected};

// ─── Fixtures and helpers ────────────────────────────────────────────────────

const CASH: &str = "Assets:Cash";
const OPENING: &str = "Equity:Opening";
const USD: &str = "USD";

fn date(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("valid date")
}

/// A date after every transaction the tests write.
fn far() -> NaiveDate {
    date(2030, 1, 1)
}

/// `10^21`, the amount cap's magnitude, as the signed type `Decimal` builds
/// from.
fn cap() -> i128 {
    i128::try_from(MAX_AMOUNT_MAGNITUDE).expect("the cap fits an i128")
}

/// The largest mantissa an in-cap amount at `scale` carries:
/// `min(10^21 × 10^scale, 2^96 − 1)`. From scale 8 on it is `Decimal::MAX`'s.
fn cap_mantissa(scale: u32) -> i128 {
    let max = decimal_max_mantissa();
    MAX_AMOUNT_MAGNITUDE
        .checked_mul(10u128.pow(scale))
        .and_then(|bound| i128::try_from(bound).ok())
        .map_or(max, |bound| bound.min(max))
}

/// `Decimal::MAX`'s mantissa, `2^96 − 1`: the largest an amount can carry.
fn decimal_max_mantissa() -> i128 {
    Decimal::MAX.mantissa()
}

fn envelope(author: &str, lamport: u64) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("openledger-author".to_owned(), author.to_owned()),
        ("openledger-lamport".to_owned(), lamport.to_string()),
        ("openledger-parents".to_owned(), String::new()),
    ])
}

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

/// One transaction moving `amount` from `Equity:Opening` into `Assets:Cash`.
/// `index` keeps every body distinct (and spreads the dates).
fn transfer(index: usize, amount: Decimal, metadata: BTreeMap<String, String>) -> Directive {
    Directive::Transaction(Transaction {
        date: date(2024, 1, 1 + (index % 28) as u32),
        flag: Flag::Complete,
        payee: None,
        narration: Some(format!("amount {index}")),
        tags: Vec::new(),
        links: Vec::new(),
        postings: vec![posting(CASH, amount, USD), posting(OPENING, -amount, USD)],
        metadata,
    })
}

fn open(account: &str, metadata: BTreeMap<String, String>) -> Directive {
    Directive::Open(Open {
        date: date(2020, 1, 1),
        account: account.to_owned(),
        currencies: Vec::new(),
        metadata,
    })
}

fn assertion(account: &str, number: Decimal) -> Balance {
    Balance {
        date: far(),
        account: account.to_owned(),
        amount: Amount {
            number,
            currency: USD.to_owned(),
        },
        metadata: BTreeMap::new(),
    }
}

/// A deterministic Fisher–Yates shuffle from `seed`.
fn shuffled<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
    let mut out = items.to_vec();
    let mut state = seed | 1;
    for index in (1..out.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let other = (state % (index as u64 + 1)) as usize;
        out.swap(index, other);
    }
    out
}

static SCRATCH_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh ledger path in its own temporary directory.
fn scratch_ledger(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "openledger-t76-{label}-{}-{nanos}-{}",
        std::process::id(),
        SCRATCH_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir.join("ledger.bean")
}

fn remove_scratch(path: &Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

fn reboot(service: LedgerService, path: &Path, author: &str) -> LedgerService {
    let mut service = service;
    service.persist_or_reload().expect("persist before reboot");
    drop(service);
    LedgerService::boot(path, author.to_owned()).expect("reboot")
}

// ─── API adapters (the only code T76 may need to touch) ──────────────────────

fn read_now(model: &ReadModel, account: &str) -> Option<String> {
    model
        .account_balance(account, None)
        .and_then(|entry| entry.balances.get(USD).map(Decimal::to_string))
}

/// Whether `account()`'s figures are exactly the sums (`None`: no entry).
fn read_exact_flag(model: &ReadModel, account: &str) -> Option<bool> {
    model
        .account_balance(account, None)
        .map(|entry| entry.exact)
}

fn read_at(model: &ReadModel, account: &str, at: NaiveDate) -> Option<String> {
    model
        .account_balance(account, Some(at))
        .and_then(|entry| entry.balances.get(USD).map(Decimal::to_string))
}

fn read_batched(model: &ReadModel, account: &str, at: NaiveDate) -> Option<String> {
    model.balances_at_dates(&[(account, at)]).entries[0]
        .as_ref()
        .and_then(|entry| entry.balances.get(USD).map(Decimal::to_string))
}

/// The trial balance's signed net for `account` (debit − credit, spelled as
/// the balance it came from).
fn read_trial(model: &ReadModel, account: &str, at: NaiveDate) -> Option<String> {
    let report = model.trial_balance(at);
    let row = report.rows.iter().find(|row| row.account == account)?;
    Some(if row.credit.is_zero() {
        row.debit.to_string()
    } else {
        (-row.credit).to_string()
    })
}

fn read_balance_sheet(model: &ReadModel, account: &str, at: NaiveDate) -> Option<String> {
    let report = model.balance_sheet(at);
    report
        .assets
        .iter()
        .chain(&report.liabilities)
        .chain(&report.equity)
        .find(|entry| entry.account == account)
        .and_then(|entry| entry.balances.get(USD).map(Decimal::to_string))
}

/// Every read path's answer for `account`, labelled.
fn every_path(model: &ReadModel, account: &str) -> Vec<(&'static str, Option<String>)> {
    vec![
        ("account()", read_now(model, account)),
        ("account(at:)", read_at(model, account, far())),
        ("balances_at_dates", read_batched(model, account, far())),
        ("trial_balance", read_trial(model, account, far())),
        ("balance_sheet", read_balance_sheet(model, account, far())),
    ]
}

/// `(per-assertion path, batched/verify path)` verdicts for one assertion.
fn assertion_verdicts(model: &ReadModel, claim: &Balance) -> (bool, bool) {
    let single = evaluate_balance_assertion(claim, model).ok;
    let batched_directive = Directive::Balance(claim.clone());
    let batched = evaluate_all_assertions([&batched_directive], model)[0].ok;
    (single, batched)
}

// ─── Assertion helpers shared by the properties ──────────────────────────────

/// Every path agrees with every other, for both accounts.
fn assert_paths_agree(model: &ReadModel, context: &str) -> Result<(), TestCaseError> {
    for account in [CASH, OPENING] {
        let answers = every_path(model, account);
        let first = &answers[0].1;
        for (label, answer) in &answers {
            prop_assert_eq!(
                answer,
                first,
                "{}: {} disagrees with account() for {}",
                context,
                label,
                account
            );
        }
    }
    Ok(())
}

/// Every path equals `expected` for `Assets:Cash` and its negation for
/// `Equity:Opening`, digit for digit.
fn assert_paths_equal(
    model: &ReadModel,
    expected: Decimal,
    context: &str,
) -> Result<(), TestCaseError> {
    for (account, value) in [(CASH, expected), (OPENING, negated(expected))] {
        for (label, answer) in every_path(model, account) {
            prop_assert_eq!(
                answer,
                Some(value.to_string()),
                "{}: {} for {} is not the oracle's value",
                context,
                label,
                account
            );
        }
    }
    Ok(())
}

/// `balance Assets:Cash <claim>` holds on both assertion paths exactly when
/// the claim is the exact sum.
fn assert_assertions_are_exact(
    model: &ReadModel,
    sum: &ExactSum,
    claim: Decimal,
    context: &str,
) -> Result<(), TestCaseError> {
    let (single, batched) = assertion_verdicts(model, &assertion(CASH, claim));
    let truth = sum.equals(claim);
    prop_assert_eq!(
        single,
        truth,
        "{}: evaluate_balance_assertion({}) must be {}",
        context,
        claim,
        truth
    );
    prop_assert_eq!(
        batched,
        truth,
        "{}: the batched (verify) assertion path for {} must be {}",
        context,
        claim,
        truth
    );
    Ok(())
}

/// `claim` one unit of its own last place away from `value`, when that is
/// still a `Decimal`.
fn one_ulp_above(value: Decimal) -> Option<Decimal> {
    let mantissa = value.mantissa().checked_add(1)?;
    (mantissa <= decimal_max_mantissa())
        .then(|| Decimal::from_i128_with_scale(mantissa, value.scale()))
}

/// `-value`, with zero kept positive: a balance never prints `-0`.
fn negated(value: Decimal) -> Decimal {
    if value.is_zero() {
        value
    } else {
        -value
    }
}

fn models_in_three_orders(directives: &[Directive], seed: u64) -> Vec<(&'static str, ReadModel)> {
    let mut live = ReadModel::default();
    for directive in directives {
        live.index_directive(directive);
    }
    let mut reordered = ReadModel::default();
    for directive in shuffled(directives, seed) {
        reordered.index_directive(&directive);
    }
    vec![
        ("arrival order", live),
        ("shuffled order", reordered),
        ("build()", ReadModel::build(directives)),
    ]
}

// ─── Strategies ──────────────────────────────────────────────────────────────

fn scale() -> impl Strategy<Value = u32> {
    prop_oneof![Just(0u32), Just(2), Just(8), Just(16), Just(28), 0u32..=28]
}

/// An in-cap amount whose mantissa is at most `10^21` (at any scale) — the
/// shapes the pre-T76 21-digit cap admitted, which the enabled properties and
/// the coverage guard were calibrated on.
fn in_cap_amount() -> impl Strategy<Value = Decimal> {
    let cap = cap();
    let mantissa = prop_oneof![
        Just(cap),
        Just(-cap),
        Just(1i128),
        Just(-1i128),
        -1000i128..1000,
        -cap..=cap,
        (-cap..=cap).prop_map(|value| value / 1_000_000),
    ];
    (mantissa, scale()).prop_map(|(mantissa, scale)| Decimal::from_i128_with_scale(mantissa, scale))
}

/// Vectors of in-cap amounts in three shapes, so both branches of the rule are
/// exercised (pinned by `generators_exercise_both_branches_of_the_rule`):
/// the audit's shape (full-range mantissas at random scales — the sum rarely
/// fits), small amounts at moderate scales (it usually fits), and
/// cancellation (large amounts that cancel to a small residue plus dust — the
/// shape that would expose rounding in an intermediate step).
fn in_cap_amounts() -> impl Strategy<Value = Vec<Decimal>> {
    let cap = cap();
    let small = (-1_000_000_000_000i128..=1_000_000_000_000, 0u32..=12)
        .prop_map(|(mantissa, scale)| Decimal::from_i128_with_scale(mantissa, scale));
    let cancelling = (
        prop::collection::vec((1i128..=cap, 0u32..=6), 1..12),
        prop::collection::vec((-1_000_000i128..=1_000_000, 7u32..=28), 0..12),
        -1000i128..=1000,
    )
        .prop_map(|(large, dust, residue)| {
            let mut amounts = Vec::new();
            for (mantissa, scale) in large {
                amounts.push(Decimal::from_i128_with_scale(mantissa, scale));
                amounts.push(Decimal::from_i128_with_scale(-mantissa, scale));
            }
            amounts.push(Decimal::from_i128_with_scale(residue, 0));
            amounts.extend(
                dust.into_iter()
                    .map(|(mantissa, scale)| Decimal::from_i128_with_scale(mantissa, scale)),
            );
            amounts
        });
    // Cross-scale cancellation: `x` and `-x` spelled at a finer scale (so a
    // partial, or the running total, is exactly zero part-way through the
    // fold), plus zero amounts spelled at other scales. This is where the
    // spelling rule lives; see `the_spelling_rule_is_pinned_on_its_edge_cases`.
    let respelled = prop::collection::vec(
        (
            -1_000_000i128..=1_000_000,
            0u32..=10,
            0u32..=8,
            0u32..=28,
            any::<bool>(),
        ),
        1..8,
    )
    .prop_map(|parts| {
        let mut amounts = Vec::new();
        for (mantissa, scale, extra, zero_scale, keep) in parts {
            amounts.push(Decimal::from_i128_with_scale(mantissa, scale));
            let finer = mantissa * 10i128.pow(extra);
            amounts.push(Decimal::from_i128_with_scale(-finer, scale + extra));
            if keep {
                amounts.push(Decimal::from_i128_with_scale(0, zero_scale));
            }
        }
        amounts
    });
    prop_oneof![
        prop::collection::vec(in_cap_amount(), 1..40),
        prop::collection::vec(small, 1..40),
        cancelling,
        respelled,
    ]
}

/// Amounts whose exact sum usually does NOT fit 96 bits at its scale — the
/// audit's L-79 shape, in which HEAD's per-step rounding is more than half an
/// ulp off in about a quarter of the non-fitting cases.
fn non_fitting_amounts() -> impl Strategy<Value = Vec<Decimal>> {
    prop::collection::vec(in_cap_amount(), 2..40)
}

/// Any amount inside the magnitude cap, `|amount| ≤ 10^21`, at scales 0–28,
/// weighted to the edges: exactly `±10^21` at scales 0–7 (the inclusive
/// bound, spelled with 0–7 trailing zeros) and `±(2^96 − 1)` from scale 8 on,
/// where every `Decimal` is inside the cap.
fn cap_amount() -> impl Strategy<Value = Decimal> {
    scale()
        .prop_flat_map(|scale| {
            let bound = cap_mantissa(scale);
            let mantissa = prop_oneof![
                Just(bound),
                Just(-bound),
                Just(1i128),
                Just(-1i128),
                -1000i128..1000,
                -bound..=bound,
                (-bound..=bound).prop_map(|value| value / 1_000_000),
            ];
            (mantissa, Just(scale))
        })
        .prop_map(|(mantissa, scale)| Decimal::from_i128_with_scale(mantissa, scale))
}

/// An amount just past the cap or far past it: `|amount| > 10^21`, which is
/// only possible at scales 0–7 (from scale 8 on no `Decimal` is that large).
fn over_cap_amount() -> impl Strategy<Value = Decimal> {
    (0u32..=7)
        .prop_flat_map(|scale| {
            let above = cap_mantissa(scale) + 1;
            let max = decimal_max_mantissa();
            let magnitude = prop_oneof![Just(above), Just(max), above..=max];
            (magnitude, any::<bool>(), Just(scale))
        })
        .prop_map(|(magnitude, negative, scale)| {
            Decimal::from_i128_with_scale(if negative { -magnitude } else { magnitude }, scale)
        })
}

/// No failure files in the source tree: a failing case is printed, not saved.
/// `PROPTEST_CASES` overrides every property's case count (the design asks for
/// a 100,000-case run before landing and nightly), since an explicit `cases`
/// here would otherwise shadow the environment.
fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        // The rounded-branch property rejects the cases that fit (about half).
        max_global_rejects: cases.saturating_mul(4).max(1024),
        failure_persistence: None,
        max_shrink_iters: 256,
        ..ProptestConfig::default()
    }
}

// ─── Properties over the read model ──────────────────────────────────────────

proptest! {
    #![proptest_config(config(512))]

    /// Enabled at HEAD. In-cap amounts at scales 0–28, any arrival order: every
    /// read path agrees with every other; when the exact sum fits 96 bits at
    /// its representation scale, every path equals the oracle digit for digit
    /// (value AND spelling), and both assertion paths hold on exactly the
    /// exact sum. T76 must keep all of this.
    #[test]
    fn in_cap_sums_match_the_oracle_on_every_read_path(
        amounts in in_cap_amounts(),
        seed in any::<u64>(),
    ) {
        let directives: Vec<Directive> = amounts
            .iter()
            .enumerate()
            .map(|(index, amount)| transfer(index, *amount, BTreeMap::new()))
            .collect();
        let sum = ExactSum::of(&amounts);
        let expected = sum.expected();
        let mut spellings = BTreeSet::new();
        for (order, model) in models_in_three_orders(&directives, seed) {
            assert_paths_agree(&model, order)?;
            spellings.insert(read_now(&model, CASH));
            if let Expected::Exact(value) = expected {
                assert_paths_equal(&model, value, order)?;
                assert_assertions_are_exact(&model, &sum, value, order)?;
                if let Some(off_by_one) = one_ulp_above(value) {
                    assert_assertions_are_exact(&model, &sum, off_by_one, order)?;
                }
            }
        }
        prop_assert_eq!(spellings.len(), 1, "arrival order changed a balance: {:?}", spellings);
    }
}

proptest! {
    #![proptest_config(config(256))]

    /// L-79. A total that does not fit 96 bits at its representation scale is
    /// rounded ONCE, half to even, from the exact value, to the finest scale
    /// that fits — the same figure on every path and in every arrival order,
    /// flagged inexact. The pre-T76 fold rounded at each step, so about a
    /// quarter of these were more than ½ ulp off.
    #[test]
    fn non_fitting_totals_are_rounded_once_half_to_even_on_every_path(
        amounts in non_fitting_amounts(),
        seed in any::<u64>(),
    ) {
        let sum = ExactSum::of(&amounts);
        let Expected::Rounded(rounded) = sum.expected() else {
            return Err(TestCaseError::reject("sum fits; covered by the enabled property"));
        };
        let directives = local_transfers(&amounts);
        for (order, model) in models_in_three_orders(&directives, seed) {
            assert_paths_equal(&model, rounded, order)?;
            // Flagged inexact unless only zeros were dropped.
            prop_assert_eq!(
                read_exact_flag(&model, CASH),
                Some(sum.equals(rounded)),
                "{}: the exact flag", order
            );
        }
    }

    /// T76 (rewritten from `history_amounts_up_to_decimal_max_are_summed_exactly`
    /// to decision (4) as refined: the cap is `|amount| ≤ 10^21` on every
    /// path). Every amount the cap admits — any magnitude up to `10^21`
    /// inclusive, at every scale 0–28, which from scale 8 on is every
    /// `Decimal` — is summed exactly: the reported value is the oracle's
    /// (exact when it fits, else rounded once) in every arrival order, and it
    /// is never out of range.
    #[test]
    fn amounts_up_to_the_cap_are_summed_exactly_at_every_scale(
        amounts in prop::collection::vec(cap_amount(), 1..24),
        seed in any::<u64>(),
    ) {
        let expected = ExactSum::of(&amounts).expected();
        let value = expected
            .value()
            .expect("no total of in-cap amounts can be out of range");
        let directives = local_transfers(&amounts);
        for (order, model) in models_in_three_orders(&directives, seed) {
            assert_paths_equal(&model, value, order)?;
            prop_assert_eq!(model.over_cap_posting_count(), 0);
        }
    }

    /// L-79. A `balance` assertion holds exactly when its amount IS the sum —
    /// on the per-assertion path and on the batched path `verify` uses — for
    /// small, non-fitting and cap-edge sums alike. In particular the
    /// displayed (rounded) figure of a non-fitting total is never "the
    /// balance": the pre-T76 compare against it passed.
    #[test]
    fn assertions_hold_on_exactly_the_exact_sum(
        amounts in prop_oneof![
            non_fitting_amounts(),
            prop::collection::vec(in_cap_amount(), 1..24),
            prop::collection::vec(cap_amount(), 1..24),
        ],
        seed in any::<u64>(),
    ) {
        let sum = ExactSum::of(&amounts);
        let value = sum
            .expected()
            .value()
            .expect("no total of in-cap amounts can be out of range");
        let directives = local_transfers(&amounts);
        for (order, model) in models_in_three_orders(&directives, seed) {
            assert_assertions_are_exact(&model, &sum, value, order)?;
            if let Some(off_by_one) = one_ulp_above(value) {
                assert_assertions_are_exact(&model, &sum, off_by_one, order)?;
            }
        }
    }
}

/// One local (envelope-less) transfer per amount, for the read-model properties.
fn local_transfers(amounts: &[Decimal]) -> Vec<Directive> {
    amounts
        .iter()
        .enumerate()
        .map(|(index, amount)| transfer(index, *amount, BTreeMap::new()))
        .collect()
}

// ─── Properties through the service (peer path, reboots) ─────────────────────

/// Stage `directives` from peer `"peer"` into `service`, rebooting after the
/// entries whose bit is set in `reboots`. Returns the (possibly rebooted)
/// service and the refusals.
fn stage_all(
    mut service: LedgerService,
    path: &Path,
    author: &str,
    directives: &[Directive],
    reboots: u64,
) -> (LedgerService, Vec<(usize, ServiceError)>) {
    let mut refusals = Vec::new();
    for (index, directive) in directives.iter().enumerate() {
        if let Err(error) = service.stage_remote_directive(directive.clone()) {
            refusals.push((index, error));
        }
        if reboots & (1 << (index % 64)) != 0 {
            service = reboot(service, path, author);
        }
    }
    (reboot(service, path, author), refusals)
}

/// A fresh service holding the two peer `open`s every transfer needs.
fn replica(label: &str, author: &str) -> (LedgerService, PathBuf) {
    let path = scratch_ledger(label);
    let mut service = LedgerService::boot(&path, author.to_owned()).expect("boot");
    for (lamport, account) in [(1, CASH), (2, OPENING)] {
        service
            .stage_remote_directive(open(account, envelope("peer", lamport)))
            .expect("peer open");
    }
    (service, path)
}

fn peer_transfers(amounts: &[Decimal]) -> Vec<Directive> {
    amounts
        .iter()
        .enumerate()
        .map(|(index, amount)| transfer(index, *amount, envelope("peer", 10 + index as u64)))
        .collect()
}

/// Both replicas hold the same directives, pass `verify`, and report the same
/// balance on every path; returns replica A's `Assets:Cash` balance.
fn assert_replicas_converged(
    a: &LedgerService,
    b: &LedgerService,
) -> Result<Option<String>, TestCaseError> {
    prop_assert_eq!(
        a.all_directive_ids(),
        b.all_directive_ids(),
        "DAG membership differs"
    );
    for service in [a, b] {
        let report = verify_dag(service.dag(), service.read_model());
        prop_assert!(report.ok, "verify: {:?}", report.errors);
        prop_assert_eq!(service.quarantined_count(), 0);
        assert_paths_agree(service.read_model(), "replica")?;
    }
    for account in [CASH, OPENING] {
        prop_assert_eq!(
            every_path(a.read_model(), account),
            every_path(b.read_model(), account),
            "replicas disagree on {}",
            account
        );
    }
    Ok(read_now(a.read_model(), CASH))
}

proptest! {
    #![proptest_config(config(12))]

    /// Enabled at HEAD. In-cap amounts arrive from a peer in two different
    /// orders on two replicas, each rebooting at random points: both converge
    /// to the same DAG and the same balances on every path, equal to the
    /// oracle when the sum fits, and the batched (verify) assertion holds on
    /// the exact sum after the last reboot.
    #[test]
    fn peer_arrival_order_and_reboots_do_not_change_any_balance(
        amounts in prop::collection::vec(in_cap_amount(), 1..10),
        seed in any::<u64>(),
        reboots_a in any::<u64>(),
        reboots_b in any::<u64>(),
    ) {
        let directives = peer_transfers(&amounts);
        let (a, path_a) = replica("peer-order-a", "replica-a");
        let (b, path_b) = replica("peer-order-b", "replica-b");
        let (a, refused_a) = stage_all(a, &path_a, "replica-a", &directives, reboots_a);
        let (b, refused_b) = stage_all(b, &path_b, "replica-b", &shuffled(&directives, seed), reboots_b);
        prop_assert!(refused_a.is_empty() && refused_b.is_empty(), "in-cap peer amounts refused: {:?} {:?}", refused_a, refused_b);
        let sum = ExactSum::of(&amounts);
        assert_replicas_converged(&a, &b)?;
        if let Expected::Exact(value) = sum.expected() {
            assert_paths_equal(a.read_model(), value, "replica after reboots")?;
            assert_assertions_are_exact(a.read_model(), &sum, value, "replica after reboots")?;
        }
        remove_scratch(&path_a);
        remove_scratch(&path_b);
    }

    /// T76 (rewritten from
    /// `history_amounts_from_a_peer_are_admitted_and_exact_across_reboots` to
    /// decision (4) as refined). A peer serving amounts anywhere inside the
    /// cap — up to `10^21` at every scale, including `Decimal::MAX`'s mantissa
    /// at scales 8–28 — passes the wire's re-parse and staging, and two
    /// replicas taking it in different orders across reboots converge to the
    /// oracle's value.
    #[test]
    fn amounts_up_to_the_cap_from_a_peer_are_admitted_and_exact_across_reboots(
        amounts in prop::collection::vec(cap_amount(), 1..8),
        seed in any::<u64>(),
        reboots_a in any::<u64>(),
        reboots_b in any::<u64>(),
    ) {
        let sum = ExactSum::of(&amounts);
        let value = sum
            .expected()
            .value()
            .expect("no total of in-cap amounts can be out of range");
        let directives = peer_transfers(&amounts);
        for directive in &directives {
            prop_assert!(
                parse_file(&economic_canonical_serialize(directive)).is_ok(),
                "the wire re-parse (validate_supply_entry's gate) refuses an in-cap body"
            );
        }
        let (a, path_a) = replica("cap-a", "replica-a");
        let (b, path_b) = replica("cap-b", "replica-b");
        let (a, refused_a) = stage_all(a, &path_a, "replica-a", &directives, reboots_a);
        let (b, refused_b) = stage_all(b, &path_b, "replica-b", &shuffled(&directives, seed), reboots_b);
        prop_assert!(refused_a.is_empty() && refused_b.is_empty(), "in-cap amounts refused: {:?} {:?}", refused_a, refused_b);
        assert_replicas_converged(&a, &b)?;
        assert_paths_equal(a.read_model(), value, "replica after reboots")?;
        assert_assertions_are_exact(a.read_model(), &sum, value, "replica after reboots")?;
        remove_scratch(&path_a);
        remove_scratch(&path_b);
    }

    /// T76: one rule on every path. An amount past `10^21` — one unit in the
    /// last place past it at scales 0–7, or anything up to `Decimal::MAX` —
    /// is refused by the local API, by the wire's re-parse (the gate
    /// `validate_supply_entry` applies before staging), by peer staging, and
    /// at boot, where the block is quarantined (kept in the file, out of the
    /// DAG) and the rest of the file loads.
    #[test]
    fn amounts_over_the_cap_are_refused_on_every_path(
        over in over_cap_amount(),
    ) {
        // Local API.
        let (mut local, local_path) = crypto_ledger("over-local", "author");
        let error = local.append_transaction(plain_input(over)).expect_err("local append");
        prop_assert_eq!(error.error_code(), "INVALID_POSTING");
        remove_scratch(&local_path);

        // The wire's re-parse, then peer staging of the same directive.
        let directive = transfer(0, over, envelope("peer", 10));
        prop_assert!(
            parse_file(&economic_canonical_serialize(&directive)).is_err(),
            "the wire re-parse admits {}", over
        );
        let (mut peer, peer_path) = replica("over-peer", "replica");
        let error = peer.stage_remote_directive(directive).expect_err("peer staging");
        prop_assert_eq!(error.error_code(), "INVALID_POSTING");
        prop_assert_eq!(read_now(peer.read_model(), CASH), None);
        remove_scratch(&peer_path);

        // Boot: quarantined, not loaded, not deleted.
        let path = scratch_ledger("over-boot");
        let block = format!(
            "2024-01-02 * \"over\"\n  {CASH} {over} USD\n  {OPENING} {} USD\n",
            -over
        );
        std::fs::write(
            &path,
            format!(
                "2020-01-01 open {CASH}\n\n2020-01-01 open {OPENING}\n\n{block}\n\
                 2024-01-03 * \"honest\"\n  {CASH} 7 USD\n  {OPENING} -7 USD\n"
            ),
        )
        .expect("write");
        let booted = LedgerService::boot(&path, "boot".to_owned()).expect("boot");
        prop_assert_eq!(booted.unparsable_block_count(), 1);
        prop_assert_eq!(read_now(booted.read_model(), CASH), Some("7".to_owned()));
        drop(booted);
        let on_disk = std::fs::read_to_string(&path).expect("read back");
        prop_assert!(on_disk.contains(&over.to_string()), "quarantined, not deleted");
        remove_scratch(&path);
    }
}

// ─── M-50: the pre-T65 upgrade fixture ───────────────────────────────────────

/// `D4-balances/fixtures/pre_upgrade.bean` from the 0923 audit, verbatim: a
/// history a pre-T65 node wrote. `X` carries `10^21` (22 significant digits,
/// legal before T65); `C` names `X` as its parent and `G` names `C`; the
/// `balance` line is what every pre-T65 node reported.
const PRE_UPGRADE_BEAN: &str = r#"2024-01-01 open Assets:Cash

2024-01-01 open Equity:Opening

2024-01-02 * "X pre-upgrade"
  openledger-author: "nodeA"
  openledger-lamport: "3"
  openledger-parents: ""
  Assets:Cash 1000000000000000000000 USD
  Equity:Opening -1000000000000000000000 USD

2024-01-03 * "C child"
  openledger-author: "nodeA"
  openledger-lamport: "4"
  openledger-parents: "6fe3cf8e60a0a57d08e8cfeb8ffea404cf43a0e748c42abb027dd1133f7abcd3"
  Assets:Cash 5 USD
  Equity:Opening -5 USD

2024-01-04 * "G grandchild"
  openledger-author: "nodeB"
  openledger-lamport: "5"
  openledger-parents: "53aba2c00f81056079896ce4c067f7ad43f72e1f42569cd6e7c4db640424d68e"
  Assets:Cash 9 USD
  Equity:Opening -9 USD

2024-01-05 balance Assets:Cash 1000000000000000000014 USD
"#;

const X_ID: &str = "6fe3cf8e60a0a57d08e8cfeb8ffea404cf43a0e748c42abb027dd1133f7abcd3";
const C_ID: &str = "53aba2c00f81056079896ce4c067f7ad43f72e1f42569cd6e7c4db640424d68e";
const PRE_UPGRADE_CASH: &str = "1000000000000000000014";

/// Stage `directives` into `service` as a peer's supply would arrive, retrying
/// a `MISSING_PARENT` refusal once its parent lands (the orphan buffer's job).
/// Every body must pass the wire's re-parse first. Returns what never landed.
fn sync_from_served(service: &mut LedgerService, directives: Vec<Directive>) -> Vec<String> {
    let mut pending = directives;
    let mut refused = Vec::new();
    loop {
        let before = pending.len();
        let mut waiting = Vec::new();
        for directive in pending {
            let body = economic_canonical_serialize(&directive);
            if let Err(errors) = parse_file(&body) {
                refused.push(format!("wire re-parse refuses {body:?}: {errors:?}"));
                continue;
            }
            match service.stage_remote_directive(directive.clone()) {
                Ok(_) => {}
                Err(error) if error.error_code() == "MISSING_PARENT" => waiting.push(directive),
                Err(error) => refused.push(format!(
                    "{} refused [{}]: {error}",
                    compute_content_id(&directive),
                    error.error_code()
                )),
            }
        }
        pending = waiting;
        if pending.is_empty() || pending.len() == before {
            break;
        }
    }
    refused.extend(
        pending
            .iter()
            .map(|directive| format!("{} never found its parent", compute_content_id(directive))),
    );
    refused
}

#[test]
fn m50_a_pre_t65_history_with_a_22_digit_amount_boots_whole_and_a_fresh_replica_syncs_it() {
    let path = scratch_ledger("m50-upgrade");
    std::fs::write(&path, PRE_UPGRADE_BEAN).expect("write the pre-T65 file");

    // The upgraded node boots the pre-T65 file: nothing is quarantined, the
    // chain X ← C ← G is whole, and the balance is the pre-upgrade balance.
    let upgraded = LedgerService::boot(&path, "nodeA".to_owned()).expect("boot");
    assert_eq!(
        upgraded.unparsable_block_count(),
        0,
        "a pre-T65 block is unparsable"
    );
    assert_eq!(
        upgraded.quarantined_count(),
        0,
        "a pre-T65 directive is quarantined"
    );
    assert!(
        upgraded.contains_directive(X_ID),
        "X (the 22-digit parent) is not in the DAG"
    );
    assert!(upgraded.contains_directive(C_ID), "C is not in the DAG");
    assert_eq!(
        read_now(upgraded.read_model(), CASH).as_deref(),
        Some(PRE_UPGRADE_CASH)
    );
    let report = verify_dag(upgraded.dag(), upgraded.read_model());
    assert!(report.ok, "verify after the upgrade: {:?}", report.errors);
    assert_eq!(
        report.assertions.evaluated, 1,
        "the pre-T65 balance line was not loaded"
    );
    assert!(report.assertions.ok(), "{:?}", report.assertions.failures);

    // Nothing moves on a second boot (the ids and envelopes are the file's).
    let ids = upgraded.all_directive_ids();
    let upgraded = reboot(upgraded, &path, "nodeA");
    assert_eq!(
        upgraded.all_directive_ids(),
        ids,
        "a reboot changed the directive set"
    );
    assert_eq!(upgraded.quarantined_count(), 0);

    // A fresh replica fed what the upgraded node serves — in reverse order, so
    // every child arrives before its parent — takes all of it and converges.
    let served: Vec<Directive> = upgraded
        .sorted_directive_ids()
        .iter()
        .rev()
        .map(|id| upgraded.get_directive(id).expect("served").clone())
        .collect();
    let fresh_path = scratch_ledger("m50-fresh");
    let mut fresh = LedgerService::boot(&fresh_path, "fresh".to_owned()).expect("boot fresh");
    let refused = sync_from_served(&mut fresh, served);
    assert!(
        refused.is_empty(),
        "the fresh replica could not take the history: {refused:#?}"
    );
    let fresh = reboot(fresh, &fresh_path, "fresh");
    assert_eq!(fresh.all_directive_ids(), upgraded.all_directive_ids());
    for account in [CASH, OPENING] {
        assert_eq!(
            every_path(fresh.read_model(), account),
            every_path(upgraded.read_model(), account),
            "fresh and upgraded replicas disagree on {account}"
        );
    }
    let fresh_report = verify_dag(fresh.dag(), fresh.read_model());
    assert!(fresh_report.ok, "{:?}", fresh_report.errors);
    assert!(
        fresh_report.assertions.ok(),
        "{:?}",
        fresh_report.assertions.failures
    );

    remove_scratch(&path);
    remove_scratch(&fresh_path);
}

// ─── Info: the trailing-zero purchase ────────────────────────────────────────

fn crypto_ledger(label: &str, author: &str) -> (LedgerService, PathBuf) {
    let path = scratch_ledger(label);
    let mut service = LedgerService::boot(&path, author.to_owned()).expect("boot");
    for account in ["Assets:Crypto", CASH] {
        service
            .open_account(account.to_owned(), date(2024, 1, 1), Vec::new())
            .expect("open");
    }
    (service, path)
}

fn purchase(units: &str, price: &str) -> TransactionInput {
    let number = |text: &str| Decimal::from_str_exact(text).expect("literal");
    TransactionInput {
        date: date(2024, 2, 1),
        flag: Flag::Complete,
        payee: None,
        narration: Some("buy".to_owned()),
        tags: Vec::new(),
        links: Vec::new(),
        postings: vec![
            PostingInput {
                account: "Assets:Crypto".to_owned(),
                amount: Some(Amount {
                    number: number(units),
                    currency: "BTC".to_owned(),
                }),
                cost: None,
                price: Some(PriceSpec::Unit(Amount {
                    number: number(price),
                    currency: USD.to_owned(),
                })),
            },
            PostingInput {
                account: CASH.to_owned(),
                amount: None,
                cost: None,
                price: None,
            },
        ],
    }
}

#[test]
fn trailing_zero_purchase_is_accepted() {
    let (mut author, path) = crypto_ledger("trailing-zero", "author");
    let outcome = author
        .append_transaction(purchase("1.00000000", "100000.00000000"))
        .expect("an ordinary 8-decimal purchase must be accepted: 100000 has 6 significant digits");

    // The resolved leg is STORED as resolved — `-100000.0000000000000000`,
    // scale 16 — so the content id is the one every earlier build would
    // compute for this body; only the cap's digit count ignores the zeros.
    let stored = author.get_directive(&outcome.txid).expect("stored").clone();
    let Directive::Transaction(ref transaction) = stored else {
        panic!("not a transaction");
    };
    let leg = transaction.postings[1]
        .amount
        .as_ref()
        .expect("resolved")
        .number;
    assert_eq!(leg.to_string(), "-100000.0000000000000000");
    assert_eq!(compute_content_id(&stored), outcome.txid);
    assert_eq!(
        read_now(author.read_model(), CASH).as_deref(),
        Some("-100000.0000000000000000")
    );

    // A peer accepts what this node authored (H-12), through the wire's
    // re-parse and the peer staging path.
    let (mut peer, peer_path) = crypto_ledger("trailing-zero-peer", "peer");
    let refused = sync_from_served(&mut peer, vec![stored]);
    assert!(
        refused.is_empty(),
        "a peer refuses the purchase: {refused:#?}"
    );
    assert_eq!(
        every_path(peer.read_model(), CASH),
        every_path(author.read_model(), CASH)
    );

    // And it survives the author's reboot unquarantined.
    let author = reboot(author, &path, "author");
    assert_eq!(author.quarantined_count(), 0);
    assert!(author.contains_directive(&outcome.txid));

    remove_scratch(&path);
    remove_scratch(&peer_path);
}

// ─── L-79: assertions against the exact sum ──────────────────────────────────

#[test]
fn l79_a_balance_assertion_is_checked_against_the_exact_sum() {
    let thousand = Decimal::from(1000);
    let dust = Decimal::from_i128_with_scale(1, 28);
    let directives = vec![
        transfer(0, thousand, BTreeMap::new()),
        transfer(1, dust, BTreeMap::new()),
    ];
    let model = ReadModel::build(&directives);
    // The display rule: 1000.0000000000000000000000000001 does not fit 96
    // bits at scale 28, so it is shown rounded once to scale 25 ...
    assert_eq!(
        read_now(&model, CASH).as_deref(),
        Some("1000.0000000000000000000000000")
    );
    // ... but the ledger does not hold 1000, and `balance … 1000 USD` says it does.
    let claim = assertion(CASH, thousand);
    assert_eq!(assertion_verdicts(&model, &claim), (false, false));

    // The same through the service and `verify`, with the dust from a peer.
    let (service, path) = replica("l79", "victim");
    let peer_directives = vec![
        transfer(0, thousand, envelope("peer", 10)),
        transfer(1, dust, envelope("peer", 11)),
        Directive::Balance(Balance {
            metadata: envelope("peer", 12),
            ..claim
        }),
    ];
    let (service, refused) = stage_all(service, &path, "victim", &peer_directives, 0);
    assert!(refused.is_empty(), "{refused:?}");
    let report = verify_dag(service.dag(), service.read_model());
    assert!(report.ok);
    assert_eq!(report.assertions.evaluated, 1);
    assert_eq!(
        report.assertions.failures.len(),
        1,
        "`balance Assets:Cash 1000 USD` holds on 1000 + 1e-28"
    );
    remove_scratch(&path);
}

// ─── Controls that pass at HEAD and must keep passing ────────────────────────

/// ±10^21 — the cap itself, inclusive — from a peer around an honest 7, in
/// both arrival orders and across a reboot: 7 on every path, and `balance …
/// 7 USD` holds (the H-17 shape, which exact accumulation must keep closed).
#[test]
fn in_cap_extremes_are_exact_on_every_path_in_either_order_and_after_reboot() {
    let cap = Decimal::from_i128_with_scale(cap(), 0);
    let amounts = [cap, Decimal::from(7), -cap];
    let directives = peer_transfers(&amounts);
    let sum = ExactSum::of(&amounts);
    assert_eq!(
        sum.expected().spelled(),
        Expected::Exact(Decimal::from(7)).spelled()
    );
    let (a, path_a) = replica("extremes-a", "replica-a");
    let (b, path_b) = replica("extremes-b", "replica-b");
    let (a, refused_a) = stage_all(a, &path_a, "replica-a", &directives, 0b010);
    let reversed: Vec<Directive> = directives.iter().rev().cloned().collect();
    let (b, refused_b) = stage_all(b, &path_b, "replica-b", &reversed, 0);
    assert!(refused_a.is_empty() && refused_b.is_empty());
    assert_replicas_converged(&a, &b).expect("replicas converge");
    assert_paths_equal(a.read_model(), Decimal::from(7), "extremes").expect("exact");
    assert_eq!(
        assertion_verdicts(a.read_model(), &assertion(CASH, Decimal::from(7))),
        (true, true)
    );
    remove_scratch(&path_a);
    remove_scratch(&path_b);
}

fn plain_input(amount: Decimal) -> TransactionInput {
    TransactionInput {
        date: date(2024, 2, 1),
        flag: Flag::Complete,
        payee: None,
        narration: Some("local".to_owned()),
        tags: Vec::new(),
        links: Vec::new(),
        postings: vec![
            PostingInput {
                account: "Assets:Crypto".to_owned(),
                amount: Some(Amount {
                    number: amount,
                    currency: USD.to_owned(),
                }),
                cost: None,
                price: None,
            },
            PostingInput {
                account: CASH.to_owned(),
                amount: None,
                cost: None,
                price: None,
            },
        ],
    }
}

/// T76 (rewritten from `authoring_still_refuses_a_new_amount_over_the_cap`):
/// the cap is a magnitude, inclusive, at any precision. A new posting of
/// `10^21` is accepted, and so is `10^21` spelled with seven fractional zeros
/// (`1000000000000000000000.0000000`, 29 digits of mantissa — trailing zeros
/// are precision, not magnitude); one unit in the last place past it, at
/// either spelling, is refused. The accepted amounts keep their spelling.
#[test]
fn the_cap_is_a_magnitude_inclusive_at_any_precision() {
    let (mut service, path) = crypto_ledger("magnitude-cap", "author");
    let d = |text: &str| Decimal::from_str_exact(text).expect("literal");
    for inside in ["1000000000000000000000", "1000000000000000000000.0000000"] {
        let outcome = service
            .append_transaction(plain_input(d(inside)))
            .unwrap_or_else(|error| panic!("{inside} is inside the cap: {error}"));
        let Some(Directive::Transaction(stored)) = service.get_directive(&outcome.txid) else {
            panic!("stored");
        };
        let number = stored.postings[0].amount.as_ref().expect("amount").number;
        assert_eq!(number.to_string(), inside, "the spelling is stored as sent");
    }
    for over in ["1000000000000000000001", "1000000000000000000000.0000001"] {
        let error = service
            .append_transaction(plain_input(d(over)))
            .expect_err("past 10^21");
        assert_eq!(error.error_code(), "INVALID_POSTING", "{over}");
    }
    remove_scratch(&path);
}

/// T76 (rewritten from `authoring_refuses_a_resolved_leg_with_22_significant_digits`,
/// now an ACCEPTANCE test): `12.12345678 BTC @ 45123.45678901 USD` resolves
/// its elided leg to `-547052.2781457603139878` — 22 genuinely significant
/// digits, which the 21-digit cap refused with no balanced rounded spelling
/// (I1 has no tolerance). Its magnitude is ~5.5 × 10^5, so it is accepted,
/// stored as resolved, taken by a peer, and it balances exactly.
#[test]
fn a_resolved_leg_with_22_significant_digits_is_accepted_and_balances_exactly() {
    let (mut service, path) = crypto_ledger("product-leg", "author");
    let outcome = service
        .append_transaction(purchase("12.12345678", "45123.45678901"))
        .expect("a precise product far inside the magnitude cap");
    let stored = service
        .get_directive(&outcome.txid)
        .expect("stored")
        .clone();
    let Directive::Transaction(ref transaction) = stored else {
        panic!("not a transaction");
    };
    let leg = transaction.postings[1]
        .amount
        .as_ref()
        .expect("resolved")
        .number;
    assert_eq!(leg.to_string(), "-547052.2781457603139878");
    assert_eq!(
        read_now(service.read_model(), CASH).as_deref(),
        Some("-547052.2781457603139878")
    );
    assert_eq!(read_exact_flag(service.read_model(), CASH), Some(true));
    let claim = |number: &str| Balance {
        date: far(),
        account: CASH.to_owned(),
        amount: Amount {
            number: Decimal::from_str_exact(number).expect("literal"),
            currency: USD.to_owned(),
        },
        metadata: BTreeMap::new(),
    };
    assert_eq!(
        assertion_verdicts(service.read_model(), &claim("-547052.2781457603139878")),
        (true, true)
    );
    assert_eq!(
        assertion_verdicts(service.read_model(), &claim("-547052.28")),
        (false, false)
    );

    let (mut peer, peer_path) = crypto_ledger("product-leg-peer", "peer");
    let refused = sync_from_served(&mut peer, vec![stored]);
    assert!(
        refused.is_empty(),
        "a peer refuses the purchase: {refused:#?}"
    );
    assert_eq!(
        every_path(peer.read_model(), CASH),
        every_path(service.read_model(), CASH)
    );
    let service = reboot(service, &path, "author");
    assert_eq!(service.quarantined_count(), 0);
    assert!(service.contains_directive(&outcome.txid));
    remove_scratch(&path);
    remove_scratch(&peer_path);
}

/// The oracle itself, on hand-checked cases (so a wrong oracle cannot make a
/// wrong implementation look right).
#[test]
fn oracle_self_check() {
    let d = |text: &str| Decimal::from_str_exact(text).expect("literal");
    let spelled = |amounts: &[Decimal]| ExactSum::of(amounts).expected().spelled();
    assert_eq!(
        spelled(&[d("1.50"), d("2.5")]),
        Expected::Exact(d("4.00")).spelled()
    );
    assert_eq!(
        spelled(&[d("2"), d("-1"), d("0.1"), d("-0.1")]),
        Expected::Exact(d("1")).spelled()
    );
    assert_eq!(
        spelled(&[d("1"), d("-1.0"), d("0.00")]),
        Expected::Exact(d("0.00")).spelled()
    );
    assert_eq!(
        spelled(&[d("1000"), Decimal::from_i128_with_scale(1, 28)]),
        Expected::Rounded(d("1000.0000000000000000000000000")).spelled()
    );
    // Half to even at the cut. `…334 + 0.5` needs 30 digits at scale 1, so it
    // is rounded to scale 0: the tie goes to the even neighbour, `…334`; the
    // tie on `…333.5` goes up to `…334`; `MAX + 0.5` would round up past
    // `MAX`, so no `Decimal` holds it.
    let near_max =
        |last: i128| Decimal::from_i128_with_scale(decimal_max_mantissa() - 335 + last, 0);
    assert_eq!(
        spelled(&[near_max(334), d("0.5")]),
        Expected::Rounded(near_max(334)).spelled()
    );
    assert_eq!(
        spelled(&[near_max(333), d("0.5")]),
        Expected::Rounded(near_max(334)).spelled()
    );
    assert_eq!(
        spelled(&[Decimal::MAX, d("0.5")]),
        Expected::OutOfRange.spelled()
    );
    assert_eq!(
        spelled(&[Decimal::MAX, d("-0.5")]),
        Expected::Rounded(near_max(334)).spelled()
    );
    assert_eq!(
        spelled(&[Decimal::MAX, Decimal::ONE]),
        Expected::OutOfRange.spelled()
    );
    assert_eq!(
        spelled(&[Decimal::MAX, Decimal::MAX, -Decimal::MAX]),
        Expected::Exact(Decimal::MAX).spelled()
    );
    assert!(!ExactSum::of(&[d("1000"), Decimal::from_i128_with_scale(1, 28)]).equals(d("1000")));
    assert!(ExactSum::of(&[d("1.10"), d("-0.1")]).equals(d("1")));
}

/// The spelling rule on its edge cases, every path, every order: a zero
/// partial after a non-zero running total does not change the scale; a zero
/// running total takes the next partial's scale, zero or not. Pinned so T76's
/// read-time conversion cannot change how any existing balance prints.
#[test]
fn the_spelling_rule_is_pinned_on_its_edge_cases() {
    let d = |text: &str| Decimal::from_str_exact(text).expect("literal");
    let cases: [(&[&str], &str); 10] = [
        (&["1.50", "2.5"], "4.00"),
        (&["2", "-1", "0.1", "-0.1"], "1"),
        (&["1", "-1.0", "0.00"], "0.00"),
        (&["1", "-1.0"], "0.0"),
        (&["0.00"], "0.00"),
        (&["5.00", "0.0000"], "5.00"),
        (&["0", "1.00"], "1.00"),
        (&["0.1", "-0.1", "3"], "3"),
        (&["0.1", "-0.10", "3"], "3.00"),
        (&["0.1", "-0.1", "3", "0.001"], "3.001"),
    ];
    for (amounts, spelled) in cases {
        let amounts: Vec<Decimal> = amounts.iter().map(|text| d(text)).collect();
        assert_eq!(
            ExactSum::of(&amounts).expected().spelled(),
            Expected::Exact(d(spelled)).spelled(),
            "oracle on {amounts:?}"
        );
        assert_eq!(d(spelled).to_string(), spelled);
        let directives = local_transfers(&amounts);
        for seed in 0..8 {
            for (order, model) in models_in_three_orders(&directives, seed) {
                assert_paths_equal(&model, d(spelled), order)
                    .unwrap_or_else(|error| panic!("{amounts:?}: {error}"));
            }
        }
    }
}

/// The enabled property must exercise BOTH branches of the rule — exact and
/// rounded — or it pins only one of them. Samples its generator and requires
/// each branch in at least a fifth of the cases.
#[test]
fn generators_exercise_both_branches_of_the_rule() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let strategy = in_cap_amounts();
    let samples = 2000;
    let mut exact = 0;
    for _ in 0..samples {
        let amounts = strategy.new_tree(&mut runner).expect("sample").current();
        if matches!(ExactSum::of(&amounts).expected(), Expected::Exact(_)) {
            exact += 1;
        }
    }
    assert!(
        exact * 5 >= samples && (samples - exact) * 5 >= samples,
        "exact in {exact} of {samples} samples"
    );
}

// ─── A5 (0924 re-audit of T76): wide.rs against the base-10^9 oracle ─────────

use ledger::service::MAX_LEDGER_FILE_BYTES;
use ledger::validate::{check_amount_cap, validate_transaction, AccountState};
use ledger::wide::I256;
use oracle::Big;

/// `value` read out of `I256`'s `Debug` form — the sign and the four
/// base-2^64 limbs — into the oracle's base-10^9 integer, through nothing
/// but doubling and addition. This is the readout every `I256` check below
/// compares through, so a wrong limb, carry or sign shows up as a value.
fn i256_as_big(value: I256) -> Big {
    let text = format!("{value:?}");
    let negative = text.contains("negative: true");
    let start = text.find('[').expect("limbs") + 1;
    let end = text.find(']').expect("limbs");
    let limbs: Vec<u64> = text[start..end]
        .split(',')
        .map(|limb| limb.trim().parse().expect("a u64 limb"))
        .collect();
    assert_eq!(limbs.len(), 4, "four limbs");
    Big::from_base_2_64_limbs(negative, &limbs)
}

/// `2^bits` in the oracle.
fn two_pow(bits: usize) -> Big {
    let mut limbs = vec![0u64; bits / 64];
    limbs.push(1u64 << (bits % 64));
    Big::from_base_2_64_limbs(false, &limbs)
}

/// Whether `|value| ≤ 2^256 − 1`, the magnitude `I256` holds.
fn fits_256_bits(value: &Big) -> bool {
    value.magnitude().compare(&two_pow(256)) == std::cmp::Ordering::Less
}

/// A signed `i128` (weighted to its edges and to the `Decimal` mantissa
/// bound) and a power of ten to shift it by: `2^127 × 10^38 < 2^256`, so
/// every operand fits and their sums reach past 2^255.
fn i256_operand() -> impl Strategy<Value = (i128, u32)> {
    let mantissa_max = decimal_max_mantissa();
    let mantissa = prop_oneof![
        Just(0i128),
        Just(1),
        Just(-1),
        Just(i128::MAX),
        Just(i128::MIN + 1),
        Just(mantissa_max),
        Just(-mantissa_max),
        Just(mantissa_max + 1),
        any::<i128>(),
        -1000i128..1000,
        any::<i128>().prop_map(|value| value / 1_000_000_000),
    ];
    (mantissa, 0u32..=38)
}

proptest! {
    #![proptest_config(config(512))]

    /// A5 (0924): `wide::I256` as a new bignum, every operation against the
    /// base-10^9 oracle — `from_i128`, `× 10^k`, `checked_add` (both signs,
    /// both magnitude orders, overflow exactly when the oracle passes
    /// `2^256 − 1`), negation (zero stays non-negative), `Ord`, exact and
    /// half-to-even division by `10^k` including an exact tie built on
    /// purpose in both signs, and `to_i128_within` at the `Decimal` mantissa
    /// bound. The read model's fold and Rule R stand on these.
    #[test]
    fn wide_i256_matches_the_base_ten_oracle(
        (a, shift_a) in i256_operand(),
        (b, shift_b) in i256_operand(),
        dropped in 0u32..=40,
    ) {
        let x = I256::from_i128(a).checked_mul_pow10(shift_a).expect("2^127 × 10^38 < 2^256");
        let y = I256::from_i128(b).checked_mul_pow10(shift_b).expect("fits");
        let big_x = Big::from_i128(a).times_power_of_ten(shift_a);
        let big_y = Big::from_i128(b).times_power_of_ten(shift_b);
        prop_assert_eq!(i256_as_big(x), big_x.clone(), "from_i128 × 10^k");
        prop_assert_eq!(i256_as_big(y), big_y.clone());

        // Addition: overflow exactly when the oracle's magnitude passes 2^256 − 1.
        let sum = big_x.add(&big_y);
        match x.checked_add(y) {
            Some(total) => {
                prop_assert_eq!(i256_as_big(total), sum.clone());
                prop_assert!(fits_256_bits(&sum));
            }
            None => prop_assert!(!fits_256_bits(&sum), "spurious overflow"),
        }
        prop_assert_eq!(x.checked_add(y), y.checked_add(x), "commutative");
        prop_assert_eq!(x.checked_add(x.negated()), Some(I256::ZERO), "x + (−x)");

        // Sign, zero and order.
        prop_assert_eq!(i256_as_big(x.negated()), big_x.negated());
        prop_assert!(!(x.is_zero() && x.is_negative()), "a negative zero");
        prop_assert_eq!(x.is_negative(), big_x.is_negative());
        prop_assert_eq!(x.is_zero(), big_x.is_zero());
        prop_assert_eq!(x.cmp(&y), big_x.compare(&big_y));

        // × 10^dropped, overflow exactly when the oracle says so.
        let product = big_x.times_power_of_ten(dropped);
        match x.checked_mul_pow10(dropped) {
            Some(shifted) => {
                prop_assert_eq!(i256_as_big(shifted), product.clone());
                prop_assert!(fits_256_bits(&product));
            }
            None => prop_assert!(!fits_256_bits(&product), "spurious overflow"),
        }

        // ÷ 10^dropped: exactly, and rounded half to even on the magnitude.
        prop_assert_eq!(
            x.div_pow10_exact(dropped).map(i256_as_big),
            big_x.divide_by_power_of_ten_exactly(dropped)
        );
        prop_assert_eq!(
            i256_as_big(x.div_pow10_round_half_even(dropped)),
            big_x.divide_by_power_of_ten_half_even(dropped)
        );

        // An exact tie at `dropped` digits, in x's sign: x·10^d ± 5·10^(d−1)
        // rounds to x when x is even and one away from zero past it when odd.
        if dropped >= 1 {
            let sign = if x.is_negative() { -5 } else { 5 };
            let half = I256::from_i128(sign).checked_mul_pow10(dropped - 1).expect("fits");
            if let Some(tie) = x.checked_mul_pow10(dropped).and_then(|shifted| shifted.checked_add(half)) {
                let big_tie = i256_as_big(tie);
                let rounded = tie.div_pow10_round_half_even(dropped);
                prop_assert_eq!(i256_as_big(rounded), big_tie.divide_by_power_of_ten_half_even(dropped));
                let odd = shift_a == 0 && a % 2 != 0;
                let even_neighbour = if odd {
                    let away = if x.is_negative() { -1 } else { 1 };
                    x.checked_add(I256::from_i128(away)).expect("fits")
                } else {
                    x
                };
                prop_assert_eq!(rounded, even_neighbour, "tie → even, symmetric in the sign");
            }
        }

        // The Decimal mantissa bound.
        let bound = u128::try_from(decimal_max_mantissa()).expect("positive");
        prop_assert_eq!(x.to_i128_within(bound), big_x.to_decimal_mantissa());
    }
}

// ─── A5: Rule R beyond the cap, and the ingress round trip ───────────────────

/// Any `Decimal` at all — mantissa up to `±(2^96 − 1)` at scales 0–28 — the
/// range a library caller (not an ingress) can feed the read model.
fn any_decimal() -> impl Strategy<Value = Decimal> {
    let max = decimal_max_mantissa();
    let mantissa = prop_oneof![
        Just(0i128),
        Just(1),
        Just(-1),
        Just(max),
        Just(-max),
        Just(cap()),
        Just(-cap()),
        -max..=max,
        (-max..=max).prop_map(|value| value / 1_000_000_000_000),
        -1000i128..1000,
    ];
    (mantissa, scale()).prop_map(|(mantissa, scale)| Decimal::from_i128_with_scale(mantissa, scale))
}

/// The two `open`s `validate_transaction` needs for a transfer.
fn transfer_accounts() -> AccountState {
    let mut state = AccountState::new();
    for account in [CASH, OPENING] {
        let Directive::Open(ref directive) = open(account, BTreeMap::new()) else {
            unreachable!("open() builds an Open");
        };
        state.record_open(directive, &format!("open-{account}"));
    }
    state
}

proptest! {
    #![proptest_config(config(256))]

    /// A5 (0924): Rule R against the oracle on amounts NO ingress admits —
    /// up to `±Decimal::MAX` at any scale, in any order. Exact when it fits,
    /// rounded once (flag = only zeros dropped) when it does not, and past
    /// every scale: the infallible read saturates to `±Decimal::MAX` flagged
    /// inexact, every `try_*` report refuses, and no claim holds. The
    /// property at HEAD stops at the cap; this is the library-level half the
    /// Done note's "OutOfRange … covered by unit tests" leaves to `read_model.rs`.
    #[test]
    fn rule_r_matches_the_oracle_beyond_the_cap(
        amounts in prop::collection::vec(any_decimal(), 1..24),
        seed in any::<u64>(),
    ) {
        let sum = ExactSum::of(&amounts);
        let expected = sum.expected();
        let directives = local_transfers(&amounts);
        for (order, model) in models_in_three_orders(&directives, seed) {
            assert_paths_agree(&model, order)?;
            match &expected {
                Expected::Exact(value) => {
                    assert_paths_equal(&model, *value, order)?;
                    prop_assert_eq!(read_exact_flag(&model, CASH), Some(true));
                    prop_assert!(model.try_account_balance(CASH, None).is_ok());
                    prop_assert!(model.try_trial_balance(far()).is_ok());
                    assert_assertions_are_exact(&model, &sum, *value, order)?;
                }
                Expected::Rounded(value) => {
                    assert_paths_equal(&model, *value, order)?;
                    prop_assert_eq!(read_exact_flag(&model, CASH), Some(sum.equals(*value)));
                    prop_assert!(model.try_account_balance(CASH, None).is_ok());
                    assert_assertions_are_exact(&model, &sum, *value, order)?;
                }
                Expected::OutOfRange => {
                    let saturated = if sum.value_at_finest().is_negative() {
                        Decimal::MIN
                    } else {
                        Decimal::MAX
                    };
                    prop_assert_eq!(read_now(&model, CASH), Some(saturated.to_string()), "{}", order);
                    prop_assert_eq!(read_exact_flag(&model, CASH), Some(false));
                    prop_assert!(model.try_account_balance(CASH, None).is_err());
                    prop_assert!(model.try_trial_balance(far()).is_err());
                    prop_assert!(model.try_balance_sheet(far()).is_err());
                    for claim in [Decimal::MAX, Decimal::MIN, Decimal::ZERO] {
                        prop_assert_eq!(assertion_verdicts(&model, &assertion(CASH, claim)), (false, false));
                    }
                }
            }
        }
    }

    /// A5 (0924): the ingress round trip. For any non-zero amount — in cap,
    /// past it, or anywhere a `Decimal` reaches — the GraphQL scalar's rule
    /// (`check_amount_cap`, the call `DecimalScalar::parse` makes),
    /// `validate_transaction` and the `.bean` re-parse of what the serializer
    /// writes (the wire's gate, boot, journal replay and reconcile) give ONE
    /// verdict; and when it is "accepted", the re-read amount is the original
    /// mantissa and scale under the original content id, so no node writes a
    /// record it cannot re-load and no peer sees a hash mismatch on it.
    #[test]
    fn every_ingress_gives_one_verdict_and_re_reads_the_amount_it_accepted(
        amount in prop_oneof![cap_amount(), over_cap_amount(), any_decimal()],
    ) {
        prop_assume!(!amount.is_zero());
        let stored = transfer(0, amount, envelope("peer", 10));
        let Directive::Transaction(ref transaction) = stored else {
            unreachable!("transfer() builds a transaction");
        };
        let scalar_rule = check_amount_cap("Decimal", amount).is_ok();
        let validated = validate_transaction(transaction, &transfer_accounts()).is_ok();
        let reparsed = parse_file(&economic_canonical_serialize(&stored));
        prop_assert_eq!(scalar_rule, validated, "scalar vs validate_transaction on {}", amount);
        prop_assert_eq!(scalar_rule, reparsed.is_ok(), "scalar vs the .bean re-parse on {}", amount);
        prop_assert_eq!(scalar_rule, amount.abs() <= Decimal::from_i128_with_scale(cap(), 0));
        if let Ok(directives) = reparsed {
            prop_assert_eq!(directives.len(), 1);
            let Directive::Transaction(ref back) = directives[0] else {
                unreachable!("a transaction re-parses as one");
            };
            for (index, sign) in [(0, Decimal::ONE), (1, Decimal::NEGATIVE_ONE)] {
                let number = back.postings[index].amount.as_ref().expect("explicit").number;
                let original = amount * sign;
                prop_assert_eq!(
                    (number.mantissa(), number.scale()),
                    (original.mantissa(), original.scale()),
                    "posting {} re-reads differently", index
                );
            }
            prop_assert_eq!(compute_content_id(&directives[0]), compute_content_id(&stored));
        }
    }
}

// ─── A5: deterministic edges ─────────────────────────────────────────────────

/// A5 (0924): `balance` claims spelled at a scale other than the sum's, a
/// sum whose partials cancel at one scale and not another, the largest
/// possible claim (`balance` amounts are uncapped) on a sum it is and is not,
/// and an account never posted to — the per-assertion and batched (`verify`)
/// paths agree on every one, and `actualExact` says which figure `actual` is.
#[test]
fn assertion_claims_at_other_scales_and_over_cancelling_partials_agree_on_both_paths() {
    let d = |text: &str| Decimal::from_str_exact(text).expect("literal");
    let dust = Decimal::from_i128_with_scale(1, 28);
    let cases: [(&[Decimal], Decimal, bool, &str); 9] = [
        (&[d("1000.00")], d("1000"), true, "1000.00"),
        (&[d("1000")], d("1000.00"), true, "1000"),
        (&[d("1.00"), d("-1.00"), d("7")], d("7.0000"), true, "7"),
        (&[d("1000"), d("-1000.00")], d("0"), true, "0.00"),
        (&[d("1000"), d("-1000.00")], d("-0.00"), true, "0.00"),
        (
            &[Decimal::MAX],
            Decimal::MAX,
            true,
            "79228162514264337593543950335",
        ),
        (
            &[Decimal::MAX, dust],
            Decimal::MAX,
            false,
            "79228162514264337593543950335",
        ),
        (&[dust], dust, true, "0.0000000000000000000000000001"),
        (&[], d("0.00"), true, "0"),
    ];
    for (amounts, claim, holds, printed) in cases {
        let model = ReadModel::build(&local_transfers(amounts));
        let single = evaluate_balance_assertion(&assertion(CASH, claim), &model);
        assert_eq!(
            assertion_verdicts(&model, &assertion(CASH, claim)),
            (holds, holds),
            "{amounts:?} vs claim {claim}"
        );
        assert_eq!(single.actual.to_string(), printed, "{amounts:?}: actual");
        assert_eq!(
            single.actual_exact,
            ExactSum::of(amounts).equals(single.actual),
            "{amounts:?}: actual_exact"
        );
        assert_eq!(single.expected, claim);
    }
}

/// A5 (0924): the documented residual, quantified. I1 runs on weights
/// `rust_decimal` rounds to 28 places, so a transaction whose EXACT weights
/// do not cancel is accepted when the rounded ones do — by at most half a
/// unit in the 28th place per priced leg (`0.1 X @ 1e-28 USD` has exact
/// weight `1e-29` and rounded weight `0`). Pinned as acceptance because the
/// Done note requires that any future exactness change "must not refuse
/// history"; a refusal here would be that regression.
#[test]
fn i1_accepts_an_exact_imbalance_below_the_28th_place_because_weights_are_rounded() {
    let d = |text: &str| Decimal::from_str_exact(text).expect("literal");
    let priced = |number: &str, price: &str| Posting {
        account: "Assets:Crypto".to_owned(),
        amount: Some(Amount {
            number: d(number),
            currency: "BTC".to_owned(),
        }),
        cost: None,
        price: Some(PriceSpec::Unit(Amount {
            number: d(price),
            currency: USD.to_owned(),
        })),
        metadata: BTreeMap::new(),
    };
    let mut accounts = transfer_accounts();
    let Directive::Open(ref crypto) = open("Assets:Crypto", BTreeMap::new()) else {
        unreachable!("open() builds an Open");
    };
    accounts.record_open(crypto, "open-crypto");
    let transaction = |postings: Vec<Posting>| Transaction {
        date: date(2024, 2, 1),
        flag: Flag::Complete,
        payee: None,
        narration: Some("rounded weights".to_owned()),
        tags: Vec::new(),
        links: Vec::new(),
        postings,
        metadata: BTreeMap::new(),
    };
    // Exact imbalance 1e-29 USD; rounded weight sum 0.
    let dust = transaction(vec![
        priced("0.1", "0.0000000000000000000000000001"),
        posting(CASH, Decimal::ZERO, USD),
    ]);
    validate_transaction(&dust, &accounts).expect("accepted on rounded weights");
    // Three legs: 3 × 0.333…3 (exact) + 0.1 × 1e-28 (rounds to 0) − 0.999…9.
    let three = transaction(vec![
        priced("3", "0.3333333333333333333333333333"),
        priced("0.1", "0.0000000000000000000000000001"),
        posting(CASH, d("-0.9999999999999999999999999999"), USD),
    ]);
    validate_transaction(&three, &accounts).expect("accepted on rounded weights");
    // The bound: a 1e-28 imbalance that IS representable is refused.
    let visible = transaction(vec![
        priced("1", "0.0000000000000000000000000001"),
        posting(CASH, Decimal::ZERO, USD),
    ]);
    assert!(validate_transaction(&visible, &accounts).is_err());
}

/// A5 (0924): the documented trial-balance residual, quantified. With every
/// `Assets` row `1000 + 4e-26` (inexact: rounded down to scale 25), the
/// total is the exact sum of the exact rows rounded once, so it differs from
/// the sum of the displayed rows — by one unit in the last place here, and
/// in general by at most half an ulp of the total plus half an ulp per
/// inexact row. `exact: false` on the report is the only signal.
#[test]
fn an_inexact_trial_balance_total_differs_from_its_displayed_rows_by_the_rounding() {
    let d = |text: &str| Decimal::from_str_exact(text).expect("literal");
    let mut directives = Vec::new();
    for (index, account) in ["Assets:A", "Assets:B"].into_iter().enumerate() {
        for (offset, amount) in [d("1000"), d("0.00000000000000000000000004")]
            .into_iter()
            .enumerate()
        {
            directives.push(Directive::Transaction(Transaction {
                date: date(2024, 1, 2),
                flag: Flag::Complete,
                payee: None,
                narration: Some(format!("row {index} part {offset}")),
                tags: Vec::new(),
                links: Vec::new(),
                postings: vec![
                    posting(account, amount, USD),
                    posting(OPENING, -amount, USD),
                ],
                metadata: BTreeMap::new(),
            }));
        }
    }
    let report = ReadModel::build(&directives).trial_balance(far());
    let rows: Vec<&ledger::read_model::TrialBalanceRow> = report
        .rows
        .iter()
        .filter(|row| row.account.starts_with("Assets"))
        .collect();
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.debit.to_string(), "1000.0000000000000000000000000");
        assert!(!row.exact);
    }
    let displayed: Decimal = rows.iter().map(|row| row.debit).sum();
    assert_eq!(displayed.to_string(), "2000.0000000000000000000000000");
    assert_eq!(
        report.total_debit.to_string(),
        "2000.0000000000000000000000001",
        "the total is the exact sum rounded once"
    );
    assert_eq!(report.total_debit, report.total_credit);
    assert!(!report.exact);
    assert_eq!(
        (report.total_debit - displayed).to_string(),
        "0.0000000000000000000000001",
        "one ulp of the displayed scale"
    );
}

/// A5 (0924): the arithmetic the exact fold stands on, checked in the
/// oracle rather than asserted in a comment — a partial of `2^31` postings
/// of `2^96 − 1` is below `2^127`; folding 29 such partials to scale 28 is
/// below `2^256`; and no ingress can reach `2^31` postings in one partial:
/// the densest posting line the parser accepts is 16 bytes, so the 64 MiB
/// file plus the 64 MiB journal hold under `2^24` of them.
#[test]
fn the_partial_posting_limit_is_unreachable_and_the_fold_fits_256_bits() {
    let partial_limit: u64 = 1 << 31; // read_model::PARTIAL_POSTING_LIMIT
    let mantissa_max = Big::from_i128(decimal_max_mantissa());
    let mut partial = Big::zero();
    // 2^31 × (2^96 − 1) by 31 doublings.
    partial = partial.add(&mantissa_max);
    for _ in 0..31 {
        partial = partial.add(&partial);
    }
    assert_eq!(
        partial.compare(&two_pow(127)),
        std::cmp::Ordering::Less,
        "a full partial fits an i128"
    );
    let mut fold = Big::zero();
    for _ in 0..29 {
        fold = fold.add(&two_pow(127).times_power_of_ten(28));
    }
    assert_eq!(
        fold.compare(&two_pow(256)),
        std::cmp::Ordering::Less,
        "29 partials at scale 28 fit an I256"
    );

    // The densest posting line the grammar admits, and what it costs.
    let dense = "2024-01-02 *\n  Equity:A 1 XX\n  Equity:B -1 XX\n";
    let directives = parse_file(dense).expect("the densest legal transaction parses");
    let Directive::Transaction(ref transaction) = directives[0] else {
        panic!("a transaction");
    };
    assert_eq!(transaction.postings.len(), 2);
    let bytes_per_posting = ("  Equity:A 1 XX\n".len()) as u64;
    assert_eq!(bytes_per_posting, 16);
    let most_postings = 2 * MAX_LEDGER_FILE_BYTES / bytes_per_posting;
    assert!(
        most_postings < partial_limit / 128,
        "{most_postings} postings from file + journal, limit {partial_limit}"
    );
}

/// A5 (0924): a library-built negative zero (`-Decimal` of a zero amount)
/// serializes as `-0.00`, which no reader can hand back: the parser and the
/// scalar both read it as `0.00`, so its content id changes across the
/// round trip. No ingress produces one (`from_str_exact` never does, the
/// resolved leg is never zero, costs and prices are positive), so this pins
/// the fact rather than a defect: a `Directive` built in memory with a
/// negative zero is not one the file or a peer would ever return.
#[test]
fn a_negative_zero_is_a_library_artifact_no_ingress_returns() {
    let negative_zero = -Decimal::from_i128_with_scale(0, 2);
    assert_eq!(negative_zero.to_string(), "-0.00");
    assert_eq!(negative_zero.mantissa(), 0);
    let parsed = Decimal::from_str_exact("-0.00").expect("parses");
    assert!(!parsed.is_sign_negative(), "the reader hands back +0.00");
    let built = transfer(0, Decimal::from_i128_with_scale(0, 2), BTreeMap::new());
    let body = economic_canonical_serialize(&built);
    assert!(body.contains("-0.00 USD"), "{body}");
    let reread = parse_file(&body).expect("re-parses");
    assert_ne!(
        compute_content_id(&reread[0]),
        compute_content_id(&built),
        "the id covers the spelling, and the spelling does not survive"
    );
}

// ─── A5-1: the over-cap remainder of M-50 ────────────────────────────────────

/// A5-1 (0924, EXECUTED at HEAD): M-50's shape is closed only up to `10^21`.
/// A pre-T65 history holding an amount PAST the new cap — a base-unit token
/// ledger's `50000000000000000000000 WEI` (50,000 ETH), or the `±Decimal::MAX`
/// H-17's peer could plant before T65 — is quarantined as text at boot with
/// exactly M-50's consequences: its children load with a dangling parent,
/// balances silently exclude it, `verify` reports `MissingParent` forever,
/// and a fresh replica refuses the parent for good (`INVALID_POSTING`,
/// permanent-class) and gets `MISSING_PARENT` on every descendant. The 0923
/// regression requirement — "keep the descendants' parents resolvable, or
/// refuse loudly" — is what this asserts; boot only warns with L-45's
/// Unicode-account wording. Fails at HEAD; enable when the remainder has a
/// remedy (quarantine the descendant closure, or refuse boot naming the id).
#[test]
#[ignore = "A5-1: a pre-T65 amount past 10^21 still gets M-50's dangling children and unsyncable fresh replica"]
fn over_cap_history_keeps_its_descendants_parents_resolvable_or_refuses_loudly() {
    let wei = "WEI";
    let x_amount = Decimal::from_str_exact("50000000000000000000000").expect("5 × 10^22");
    let with_currency = |account: &str, number: Decimal| Posting {
        account: account.to_owned(),
        amount: Some(Amount {
            number,
            currency: wei.to_owned(),
        }),
        cost: None,
        price: None,
        metadata: BTreeMap::new(),
    };
    let record =
        |day: u32, narration: &str, number: Decimal, author: &str, lamport: u64, parents: &str| {
            Directive::Transaction(Transaction {
                date: date(2024, 1, day),
                flag: Flag::Complete,
                payee: None,
                narration: Some(narration.to_owned()),
                tags: Vec::new(),
                links: Vec::new(),
                postings: vec![with_currency(CASH, number), with_currency(OPENING, -number)],
                metadata: BTreeMap::from([
                    ("openledger-author".to_owned(), author.to_owned()),
                    ("openledger-lamport".to_owned(), lamport.to_string()),
                    ("openledger-parents".to_owned(), parents.to_owned()),
                ]),
            })
        };
    let x = record(2, "X pre-upgrade", x_amount, "nodeA", 3, "");
    let x_id = compute_content_id(&x);
    let c = record(3, "C child", Decimal::from(5), "nodeA", 4, &x_id);
    let c_id = compute_content_id(&c);
    let g = record(4, "G grandchild", Decimal::from(9), "nodeB", 5, &c_id);
    let opens = [open(CASH, BTreeMap::new()), open(OPENING, BTreeMap::new())];
    let file = ledger::serialize::full_file_serialize(
        &[
            opens[0].clone(),
            opens[1].clone(),
            x.clone(),
            c.clone(),
            g.clone(),
        ],
        &[],
    );
    let path = scratch_ledger("a5-1-over-cap-history");
    std::fs::write(&path, &file).expect("write the pre-T65 file");

    let upgraded = LedgerService::boot(&path, "nodeA".to_owned()).expect("boot");
    let report = verify_dag(upgraded.dag(), upgraded.read_model());
    let mut served: Vec<Directive> = upgraded
        .sorted_directive_ids()
        .iter()
        .rev()
        .map(|id| upgraded.get_directive(id).expect("served").clone())
        .collect();
    // The two `open`s first (the served order is by id), then newest first.
    served.sort_by_key(|directive| !matches!(directive, Directive::Open(_)));
    let fresh_path = scratch_ledger("a5-1-fresh");
    let mut fresh = LedgerService::boot(&fresh_path, "fresh".to_owned()).expect("boot fresh");
    let refused = sync_from_served(&mut fresh, served);
    let outcome = format!(
        "upgraded: unparsable={} quarantined={} X in DAG={} C in DAG={} cash={:?} verify.ok={} errors={:?}; \
         fresh refused={refused:?}",
        upgraded.unparsable_block_count(),
        upgraded.quarantined_count(),
        upgraded.contains_directive(&x_id),
        upgraded.contains_directive(&c_id),
        upgraded
            .read_model()
            .account_balance(CASH, None)
            .and_then(|entry| entry.balances.get(wei).map(Decimal::to_string)),
        report.ok,
        report.errors
    );
    remove_scratch(&path);
    remove_scratch(&fresh_path);
    // Either the whole chain is history (X in the DAG, verify clean, a fresh
    // replica takes all of it) or none of it is served to a peer that cannot
    // take it. Serving C and G without X is neither.
    let whole = upgraded.contains_directive(&x_id) && report.ok && refused.is_empty();
    let withheld = !upgraded.contains_directive(&c_id) && refused.is_empty();
    assert!(whole || withheld, "{outcome}");
}
