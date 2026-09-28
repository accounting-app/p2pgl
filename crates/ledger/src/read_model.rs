//! In-memory read model and financial reports (§3.7).
//!
//! Built on boot, updated incrementally on append. Reports never re-parse
//! the file (FR-2 AC5).
//!
//! # Precision of a reported figure (T76, L-79)
//!
//! Every balance is held as its **exact** sum ([`ExactAmount`]). A figure is
//! reported as a `Decimal` at the scale its amounts are spelled at; when that
//! does not fit a `Decimal`'s 96-bit mantissa it is **rounded once, half to
//! even,** to the finest scale that fits, and flagged `exact: false`. `balance`
//! assertions and `verify` always compare against the exact sum, never the
//! reported figure. With every summed amount capped at
//! `|amount| ≤ 10^21` ([`crate::limits::MAX_AMOUNT_MAGNITUDE`]) every total
//! fits at scale 0, so only mixed-scale dust (`1000 + 10^-28` needs 32
//! digits) is ever rounded.
//!
//! The bound, stated (T78, L-79): an inexact figure is within **half a unit
//! in its last printed place** of the exact sum (one rounding, never two), and
//! is the same figure on every path, every replica and every arrival order.
//! What it is not is the exact value: `1000 + 10^-28` prints
//! `1000.0000000000000000000000000` (the dust is below the last place kept),
//! and a `balance` assertion of `1000` on that account **fails**, because it
//! is compared with the exact sum, not with the printed figure.

use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::hash::compute_content_id;
use crate::model::*;
use crate::validate::amount_within_cap;
use crate::wide::I256;

// ─── Core types ──────────────────────────────────────────────────────────────

/// Per-account, per-currency balance.
pub type CurrencyBalances = BTreeMap<String, Decimal>;

/// An account balance entry for report output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountBalanceEntry {
    pub account: String,
    /// Each currency's balance as reported ([`ExactAmount::reported`]): the
    /// exact sum whenever it fits a `Decimal` at its usual scale, otherwise
    /// that sum rounded once, half to even.
    pub balances: CurrencyBalances,
    /// Whether every figure in `balances` equals its exact sum (T76).
    pub exact: bool,
    /// The exact sum behind each figure in `balances` (T76) — what a `balance`
    /// assertion is compared against.
    pub exact_sums: BTreeMap<String, ExactAmount>,
}

/// A trial balance row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialBalanceRow {
    pub account: String,
    pub debit: Decimal,
    pub credit: Decimal,
    /// Whether `debit` and `credit` equal the exact sums (T76).
    pub exact: bool,
}

/// Full trial balance report.
#[derive(Debug, Clone)]
pub struct TrialBalanceReport {
    pub at: NaiveDate,
    pub rows: Vec<TrialBalanceRow>,
    pub total_debit: Decimal,
    pub total_credit: Decimal,
    /// Whether every figure in the report — each row and both totals — equals
    /// its exact sum (T76). Each total is the exact sum of the exact rows,
    /// reported once, so with an inexact figure a total can differ from the
    /// sum of the displayed rows by that rounding.
    pub exact: bool,
}

/// Balance sheet report (§3.7.1).
#[derive(Debug, Clone)]
pub struct BalanceSheetReport {
    pub at: NaiveDate,
    pub assets: Vec<AccountBalanceEntry>,
    pub liabilities: Vec<AccountBalanceEntry>,
    pub equity: Vec<AccountBalanceEntry>,
    /// Whether every figure in the report equals its exact sum (T76).
    pub exact: bool,
}

/// Income statement report.
#[derive(Debug, Clone)]
pub struct IncomeStatementReport {
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub income: Vec<AccountBalanceEntry>,
    pub expenses: Vec<AccountBalanceEntry>,
    pub net: CurrencyBalances,
    /// Whether every figure in the report, `net` included, equals its exact
    /// sum (T76).
    pub exact: bool,
}

/// Result of one batched balances-at-date sweep ([`ReadModel::balances_at_dates`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedBalances {
    /// One answer per query, in the order the queries were supplied.
    ///
    /// `None` where the account had no priced posting on or before its query
    /// date — the same thing [`ReadModel::account_balance`] returns for an
    /// account it has never seen, which callers read as a balance of `0`.
    pub entries: Vec<Option<AccountBalanceEntry>>,
    /// Postings the sweep walked, across the whole batch.
    ///
    /// This is the measured cost model the GraphQL `verify` weight is derived
    /// from (M-23), which is why it is reported rather than left implicit: the
    /// invariant that weight rests on is that this number is a property of the
    /// *ledger* (and the latest query date), not of the query count. T32 broke
    /// exactly that invariant, and a comment did not catch it — a test reading
    /// this number does. See
    /// `read_model::tests::test_batched_sweep_cost_is_independent_of_query_count`
    /// and `graphql::query::tests::test_verify_complexity_matches_measured_cost_model`.
    pub postings_visited: usize,
}

/// A transaction with its computed content ID.
#[derive(Debug, Clone)]
pub struct IndexedTransaction {
    pub txid: String,
    pub transaction: Transaction,
}

// ─── Exact accumulation (H-17, T76) ──────────────────────────────────────────

/// The largest mantissa magnitude a `Decimal` carries, `2^96 − 1`.
const DECIMAL_MANTISSA_MAX: u128 = (1 << 96) - 1;

/// The most postings one per-scale partial sum holds (T76).
///
/// Every stored amount's mantissa is below `2^96`, so a partial of at most
/// `2^31` of them is below `2^127` in magnitude **whatever order they arrive
/// in**: no prefix of the sum can overflow an `i128`, so the partial is exact
/// and order-free. The next posting marks the balance out of range instead —
/// a verdict on a count, so order-free too. Unreachable in practice: `2^31`
/// postings is over 32 GiB of posting text against a 64 MiB ledger.
const PARTIAL_POSTING_LIMIT: u32 = 1 << 31;

/// One scale's exact partial sum: the integer sum of the mantissas of every
/// amount spelled at `scale`, and how many there were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Partial {
    scale: u8,
    count: u32,
    sum: i128,
}

/// An exact, order-independent running sum of one currency's amounts (H-17,
/// T76).
///
/// # The bugs this replaces
///
/// Balances used to be one `Decimal` per `(account, currency)`, advanced with
/// `saturating_add` in arrival order — neither half associative, so two
/// `±Decimal::MAX` directives from a peer could erase an honest posting from
/// one replica's live reports while `verify` passed on it (H-17). T65 then
/// kept one `Decimal` partial per scale, exact only while every amount was
/// inside a 21-significant-digit cap, and combined the partials in a fixed
/// order that rounded at each step, so a total that did not fit was rounded
/// twice and could be more than half a unit off (L-79); and the cap counted
/// trailing zeros, so ordinary pre-T65 history was quarantined (M-50).
///
/// # Why this is exact
///
/// One [`Partial`] per scale present, each the exact `i128` sum of its
/// amounts' mantissas. `i128` addition is exact and associative while nothing
/// overflows, and [`PARTIAL_POSTING_LIMIT`] guarantees nothing does, for **any**
/// `Decimal` amount — the amount cap is not needed for exactness. So the
/// partials are a function of the multiset of amounts alone: the incremental
/// running total, `account(at:)`, every report and `verify`'s batched sweep
/// reach the same partials from any order, including after a backdated
/// [`ReadModel::index_directive`] append, and no path has to fold in a
/// canonical order to agree with another.
///
/// [`Self::exact`] turns the partials into one [`ExactAmount`] — still exact —
/// and only [`ExactAmount::reported`] rounds, once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ExactSum {
    /// Ascending by scale, one entry per scale seen.
    partials: Vec<Partial>,
    /// Set once a partial passed [`PARTIAL_POSTING_LIMIT`]; sticky.
    out_of_range: bool,
}

impl ExactSum {
    /// Add one amount into the partial for its scale.
    fn add(&mut self, number: Decimal) {
        self.add_bounded(number, PARTIAL_POSTING_LIMIT);
    }

    /// [`Self::add`] with the per-partial posting limit as a parameter, so the
    /// out-of-range arm is testable without `2^31` postings.
    fn add_bounded(&mut self, number: Decimal, limit: u32) {
        if self.out_of_range {
            return;
        }
        // `Decimal` scales are 0..=28, so the cast is lossless.
        let scale = number.scale() as u8;
        let mantissa = number.mantissa();
        match self
            .partials
            .binary_search_by_key(&scale, |partial| partial.scale)
        {
            Ok(index) => {
                let partial = &mut self.partials[index];
                let sum = (partial.count < limit)
                    .then(|| partial.sum.checked_add(mantissa))
                    .flatten();
                match sum {
                    Some(sum) => {
                        partial.sum = sum;
                        partial.count += 1;
                    }
                    None => self.out_of_range = true,
                }
            }
            Err(_) if limit == 0 => self.out_of_range = true,
            Err(index) => self.partials.insert(
                index,
                Partial {
                    scale,
                    count: 1,
                    sum: mantissa,
                },
            ),
        }
    }

    /// The exact sum, spelled at today's scale rule.
    ///
    /// The partials are combined in ascending scale with [`ExactAmount::plus`],
    /// which reproduces the scale `rust_decimal`'s own addition gives — so a
    /// balance that fits prints digit for digit as it did before T76.
    fn exact(&self) -> ExactAmount {
        let mut total = self
            .partials
            .iter()
            .fold(ExactAmount::ZERO, |total, partial| {
                total.plus(ExactAmount::of_mantissa(
                    I256::from_i128(partial.sum),
                    partial.scale,
                ))
            });
        total.out_of_range |= self.out_of_range;
        total
    }
}

/// A figure reported by rule R: the value, and whether it is exactly the sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reported {
    pub value: Decimal,
    /// `true` when `value` equals the exact sum; `false` when it was rounded.
    pub exact: bool,
}

/// A sum no `Decimal` can report even rounded to scale 0 (T76).
///
/// Unreachable for any ledger whose summed amounts are inside
/// [`crate::limits::MAX_AMOUNT_MAGNITUDE`]: every total is then below
/// `10^28 < 2^96`. It exists for the `2^31`-postings-per-partial bound
/// ([`PARTIAL_POSTING_LIMIT`]) and for a library caller that builds a model
/// from amounts no ingress would admit. The `try_*` report methods return it;
/// the infallible ones report `±Decimal::MAX` flagged inexact instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfRange;

impl std::fmt::Display for OutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a balance is too large for any Decimal to report")
    }
}

impl std::error::Error for OutOfRange {}

/// The exact value of one reported figure and the scale it is spelled at
/// (T76).
///
/// Held as an integer mantissa at the figure's own spelling scale, which is
/// always at least the scale of every non-zero amount in it, so the value is
/// exact. The spelling scale follows `rust_decimal`'s addition (see
/// [`Self::plus`]), which is how balances have always printed: `1.50 + 2.5`
/// is `4.00`, `2 − 1 + 0.1 − 0.1` is `1`, `1 − 1.0 + 0.00` is `0.00`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactAmount {
    /// The value × `10^scale`, an integer.
    mantissa: I256,
    scale: u8,
    /// The value is unknown (a partial passed [`PARTIAL_POSTING_LIMIT`], or a
    /// report-level sum passed 256 bits); `mantissa` keeps only its sign.
    out_of_range: bool,
}

impl ExactAmount {
    /// Zero at scale 0 — where every fold of balances starts.
    pub const ZERO: ExactAmount = ExactAmount {
        mantissa: I256::ZERO,
        scale: 0,
        out_of_range: false,
    };

    /// `number`, exactly, at its own scale.
    pub fn from_decimal(number: Decimal) -> ExactAmount {
        ExactAmount::of_mantissa(I256::from_i128(number.mantissa()), number.scale() as u8)
    }

    fn of_mantissa(mantissa: I256, scale: u8) -> ExactAmount {
        ExactAmount {
            mantissa,
            scale,
            out_of_range: false,
        }
    }

    /// Whether the exact value is zero.
    pub fn is_zero(&self) -> bool {
        self.mantissa.is_zero()
    }

    /// Whether the exact value is below zero.
    pub fn is_negative(&self) -> bool {
        self.mantissa.is_negative()
    }

    /// The scale the figure is spelled at when it fits.
    pub fn scale(&self) -> u32 {
        u32::from(self.scale)
    }

    /// `self + other`, exactly, with the scale `rust_decimal` gives the sum
    /// of two `Decimal`s: a zero left operand takes the right operand's scale,
    /// a zero right operand leaves the left's, and two non-zero operands take
    /// the finer of the two (`Decimal` addition's `0 + x = x` / `x + 0 = x`
    /// fast paths and its rescale). Folding per-scale partials in ascending
    /// scale with this is exactly the scale rule T65's fold printed with
    /// whenever that fold was exact, so no balance that fits changes spelling.
    pub(crate) fn plus(self, other: ExactAmount) -> ExactAmount {
        let out_of_range = self.out_of_range || other.out_of_range;
        let scale = if self.is_zero() {
            other.scale
        } else if other.is_zero() {
            self.scale
        } else {
            self.scale.max(other.scale)
        };
        let aligned = |amount: ExactAmount| {
            amount
                .mantissa
                .checked_mul_pow10(u32::from(scale.saturating_sub(amount.scale)))
        };
        // A zero operand is exactly representable at any scale, so aligning
        // it "down" (scale below its own) is still exact: it is zero.
        let sum = match (aligned(self), aligned(other)) {
            (Some(left), Some(right)) => left.checked_add(right),
            _ => None,
        };
        match sum {
            Some(mantissa) => ExactAmount {
                mantissa,
                scale,
                out_of_range,
            },
            // Past 256 bits: only a model of amounts no ingress admits, summed
            // across an absurd number of accounts. Keep a sign to saturate to.
            None => ExactAmount {
                mantissa: if self.is_negative() && other.is_negative() {
                    I256::from_i128(-1)
                } else {
                    I256::from_i128(1)
                },
                scale,
                out_of_range: true,
            },
        }
    }

    /// `-self`, spelled at the same scale (a zero stays a non-negative zero).
    pub(crate) fn negated(self) -> ExactAmount {
        ExactAmount {
            mantissa: self.mantissa.negated(),
            ..self
        }
    }

    /// Whether `claim` is exactly this value — the rule a `balance` assertion
    /// follows (T76, L-79). Scale is not compared: `100.00` claims `100`.
    pub fn equals(&self, claim: Decimal) -> bool {
        if self.out_of_range {
            return false;
        }
        let claim = ExactAmount::from_decimal(claim);
        let common = self.scale.max(claim.scale);
        let at_common = |amount: &ExactAmount| {
            amount
                .mantissa
                .checked_mul_pow10(u32::from(common - amount.scale))
        };
        match (at_common(self), at_common(&claim)) {
            (Some(ours), Some(theirs)) => ours == theirs,
            // Only `self` can overflow (a claim is a `Decimal`), and then it
            // is larger than any claim.
            _ => false,
        }
    }

    /// The figure to report for this sum — rule R (T76, L-79):
    ///
    /// 1. if the exact value fits a `Decimal` at its spelling scale, that
    ///    value, **exact**;
    /// 2. otherwise the exact value rounded **once**, half to even, at the
    ///    finest scale below it at which the result fits, flagged inexact
    ///    unless the digits dropped were all zero;
    /// 3. otherwise [`OutOfRange`].
    ///
    /// Half to even is `rust_decimal`'s own single-step rounding, so a total
    /// the old per-scale fold rounded once is unchanged; only the ones it
    /// rounded twice move, by one unit in the last place. A pure function of
    /// the exact sum, so identical on every path and every replica.
    pub fn reported(&self) -> Result<Reported, OutOfRange> {
        if self.out_of_range {
            return Err(OutOfRange);
        }
        let scale = self.scale();
        if let Some(mantissa) = self.mantissa.to_i128_within(DECIMAL_MANTISSA_MAX) {
            return Ok(Reported {
                value: Decimal::from_i128_with_scale(mantissa, scale),
                exact: true,
            });
        }
        for coarser in (0..scale).rev() {
            let dropped = scale - coarser;
            let rounded = self.mantissa.div_pow10_round_half_even(dropped);
            if let Some(mantissa) = rounded.to_i128_within(DECIMAL_MANTISSA_MAX) {
                return Ok(Reported {
                    value: Decimal::from_i128_with_scale(mantissa, coarser),
                    exact: rounded.checked_mul_pow10(dropped) == Some(self.mantissa),
                });
            }
        }
        Err(OutOfRange)
    }

    /// [`Self::reported`] for the infallible report methods: an out-of-range
    /// figure reads as `±Decimal::MAX`, inexact, and `out_of_range` is set so
    /// the `try_*` forms can refuse the report instead.
    fn figure(&self, out_of_range: &mut bool) -> Reported {
        self.reported().unwrap_or_else(|OutOfRange| {
            *out_of_range = true;
            Reported {
                value: if self.is_negative() {
                    Decimal::MIN
                } else {
                    Decimal::MAX
                },
                exact: false,
            }
        })
    }
}

/// Per-currency exact sums for one account.
type ExactBalances = BTreeMap<String, ExactSum>;

/// The exact value of each of an account's per-currency sums.
fn exact_balances(balances: &ExactBalances) -> BTreeMap<String, ExactAmount> {
    balances
        .iter()
        .map(|(currency, sum)| (currency.clone(), sum.exact()))
        .collect()
}

/// The report entry for one account's exact sums.
fn balance_entry(
    account: &str,
    exact_sums: BTreeMap<String, ExactAmount>,
    out_of_range: &mut bool,
) -> AccountBalanceEntry {
    let mut exact = true;
    let balances = exact_sums
        .iter()
        .map(|(currency, sum)| {
            let figure = sum.figure(out_of_range);
            exact &= figure.exact;
            (currency.clone(), figure.value)
        })
        .collect();
    AccountBalanceEntry {
        account: account.to_owned(),
        balances,
        exact,
        exact_sums,
    }
}

/// A report, or [`OutOfRange`] if any figure in it was.
fn in_range<T>((report, out_of_range): (T, bool)) -> Result<T, OutOfRange> {
    if out_of_range {
        Err(OutOfRange)
    } else {
        Ok(report)
    }
}
// ─── Read model ──────────────────────────────────────────────────────────────

/// The in-memory read model. Built from directives; queried by the GraphQL layer.
#[derive(Debug, Clone, Default)]
pub struct ReadModel {
    /// Per-account running balances: `account → currency → exact sum`.
    ///
    /// Advanced in arrival order by [`Self::index_directive`]; order-free by
    /// construction (see [`ExactSum`]), so it always equals a fresh fold of
    /// the whole set in any order (H-17).
    account_balances: HashMap<String, ExactBalances>,
    /// Transactions indexed by txid, sorted by (date, lamport, txid).
    transactions: Vec<IndexedTransaction>,
    /// Transaction lookup by txid.
    txid_index: HashMap<String, usize>,
    /// Postings index: `account → [txid]`.
    account_postings: HashMap<String, Vec<String>>,
    /// Transaction dates per account: `account → {txn.date}`.
    ///
    /// Maintained incrementally so the FR-3 AC2 close rule ("no transactions
    /// after the close date") is a lookup instead of a full-DAG scan on every
    /// local `close`. A set union over the same set `account_postings`
    /// indexes, so it is order-insensitive: every path that puts a
    /// transaction into the DAG also calls [`Self::index_directive`], and
    /// every path that takes one out rebuilds the read model wholesale
    /// ([`Self::build`]), so the index cannot go stale in either direction.
    posting_dates: HashMap<String, BTreeSet<NaiveDate>>,
    /// Indexed postings whose amount is outside the amount cap
    /// ([`crate::limits::MAX_AMOUNT_MAGNITUDE`]); informational — see
    /// [`Self::over_cap_posting_count`].
    over_cap_postings: usize,
}

impl ReadModel {
    /// Build the read model from a set of directives.
    pub fn build(directives: &[Directive]) -> Self {
        let mut model = ReadModel {
            account_balances: HashMap::new(),
            transactions: Vec::new(),
            txid_index: HashMap::new(),
            account_postings: HashMap::new(),
            posting_dates: HashMap::new(),
            over_cap_postings: 0,
        };

        // Sort directives by canonical order for consistent processing.
        let mut sorted: Vec<&Directive> = directives.iter().collect();
        sorted.sort_by(|a, b| {
            a.date()
                .cmp(&b.date())
                .then_with(|| a.type_priority().cmp(&b.type_priority()))
        });

        for directive in sorted {
            model.index_directive(directive);
        }

        // Sort transactions by display order (date, lamport, txid).
        model.transactions.sort_by(|a, b| {
            a.transaction
                .date
                .cmp(&b.transaction.date)
                .then_with(|| {
                    a.transaction
                        .lamport_clock()
                        .cmp(&b.transaction.lamport_clock())
                })
                .then_with(|| a.txid.cmp(&b.txid))
        });

        // Rebuild txid_index after sorting.
        model.txid_index.clear();
        for (i, indexed) in model.transactions.iter().enumerate() {
            model.txid_index.insert(indexed.txid.clone(), i);
        }

        model
    }

    /// Index a single directive into the read model (for incremental updates).
    pub fn index_directive(&mut self, directive: &Directive) {
        if let Directive::Transaction(txn) = directive {
            let txid = compute_content_id(directive);

            // Skip duplicates.
            if self.txid_index.contains_key(&txid) {
                return;
            }

            // Update running balances — exactly, so arrival order cannot
            // matter (H-17, T76; see `ExactSum`).
            for posting in &txn.postings {
                if let Some(ref amount) = posting.amount {
                    if !amount_within_cap(amount.number) {
                        self.over_cap_postings += 1;
                    }
                    // Use the raw posting amount (not weight) for account balances.
                    // Account balances track commodity units, not converted amounts.
                    self.account_balances
                        .entry(posting.account.clone())
                        .or_default()
                        .entry(amount.currency.clone())
                        .or_default()
                        .add(amount.number);
                }
            }

            // Index by account, and record the transaction's date against it
            // (see `posting_dates`).
            for posting in &txn.postings {
                self.account_postings
                    .entry(posting.account.clone())
                    .or_default()
                    .push(txid.clone());
                self.posting_dates
                    .entry(posting.account.clone())
                    .or_default()
                    .insert(txn.date);
            }

            // Store the transaction.
            let index = self.transactions.len();
            self.txid_index.insert(txid.clone(), index);
            self.transactions.push(IndexedTransaction {
                txid,
                transaction: txn.clone(),
            });
        }
    }

    /// Replace the stored copy of an already-indexed transaction with
    /// `directive` — same txid, same postings, a changed envelope (L-74).
    ///
    /// `finalize_operator_input` rewrites the envelope of a DAG directive in
    /// place after boot indexed a clone of it here, so `journal` served the
    /// hand-typed record as `author: "local"`, unsigned, until the next
    /// restart while `transaction(txid)` served the finalised copy. The body
    /// is what the txid and every balance are computed from, and the body is
    /// unchanged, so nothing but the stored copy moves: no balance, no
    /// posting index, no date index. A directive this model has not indexed,
    /// or a non-transaction, is indexed as [`Self::index_directive`] would.
    pub fn reindex_directive(&mut self, directive: &Directive) {
        let Directive::Transaction(txn) = directive else {
            return;
        };
        let txid = compute_content_id(directive);
        match self.txid_index.get(&txid) {
            Some(&index) => {
                debug_assert_eq!(
                    self.transactions[index].transaction.postings, txn.postings,
                    "reindex_directive is for an envelope change; the body is the txid"
                );
                self.transactions[index].transaction = txn.clone();
            }
            None => self.index_directive(directive),
        }
    }

    // ── Report queries ───────────────────────────────────────────────────
    //
    // Each report has an infallible form, whose signature predates T76, and a
    // `try_*` form. They compute the same figures; an out-of-range figure
    // ([`OutOfRange`], unreachable inside the amount cap) reads as
    // `±Decimal::MAX` flagged inexact in the first and refuses the report in
    // the second. Every figure is one exact sum reported once by rule R
    // ([`ExactAmount::reported`]).

    /// Trial balance at a given date (FR-2 AC1).
    ///
    /// Returns every account's debit/credit balance. For multi-currency accounts,
    /// positive amounts are debits and negative are credits (as Decimal sums).
    pub fn trial_balance(&self, at: NaiveDate) -> TrialBalanceReport {
        self.trial_balance_checked(at).0
    }

    /// [`Self::trial_balance`], refusing a report with an out-of-range figure.
    pub fn try_trial_balance(&self, at: NaiveDate) -> Result<TrialBalanceReport, OutOfRange> {
        in_range(self.trial_balance_checked(at))
    }

    fn trial_balance_checked(&self, at: NaiveDate) -> (TrialBalanceReport, bool) {
        let sums = self.sums_where(None, |date| date <= at);
        let mut out_of_range = false;
        let mut exact = true;
        let mut rows = Vec::new();
        let mut total_debit = ExactAmount::ZERO;
        let mut total_credit = ExactAmount::ZERO;

        // Collect all accounts, sorted.
        let mut accounts: Vec<&str> = sums.keys().copied().collect();
        accounts.sort();

        for account in accounts {
            // Sum all currencies into a single debit/credit per account.
            // This is a simplification — in practice, debit/credit is per currency,
            // but the GraphQL type uses a single Decimal. Exact, in currency
            // order, then reported once (T76).
            let net = sums[account]
                .values()
                .fold(ExactAmount::ZERO, |net, sum| net.plus(sum.exact()));

            let (debit, credit) = if net.is_negative() {
                (ExactAmount::ZERO, net.negated())
            } else {
                (net, ExactAmount::ZERO)
            };

            total_debit = total_debit.plus(debit);
            total_credit = total_credit.plus(credit);

            let debit = debit.figure(&mut out_of_range);
            let credit = credit.figure(&mut out_of_range);
            let row_exact = debit.exact && credit.exact;
            exact &= row_exact;
            rows.push(TrialBalanceRow {
                account: account.to_owned(),
                debit: debit.value,
                credit: credit.value,
                exact: row_exact,
            });
        }

        let total_debit = total_debit.figure(&mut out_of_range);
        let total_credit = total_credit.figure(&mut out_of_range);
        let report = TrialBalanceReport {
            at,
            rows,
            total_debit: total_debit.value,
            total_credit: total_credit.value,
            exact: exact && total_debit.exact && total_credit.exact,
        };
        (report, out_of_range)
    }

    /// Balance sheet at a given date (FR-2 AC2, §3.7.1).
    ///
    /// Includes the Net-Income closing entry into Equity.
    pub fn balance_sheet(&self, at: NaiveDate) -> BalanceSheetReport {
        self.balance_sheet_checked(at).0
    }

    /// [`Self::balance_sheet`], refusing a report with an out-of-range figure.
    pub fn try_balance_sheet(&self, at: NaiveDate) -> Result<BalanceSheetReport, OutOfRange> {
        in_range(self.balance_sheet_checked(at))
    }

    fn balance_sheet_checked(&self, at: NaiveDate) -> (BalanceSheetReport, bool) {
        let sums = self.sums_where(None, |date| date <= at);
        let mut out_of_range = false;

        let mut assets = Vec::new();
        let mut liabilities = Vec::new();
        let mut equity = Vec::new();

        // Collect Net-Income (Income − Expenses) for the closing rule.
        let mut net_income: BTreeMap<String, ExactAmount> = BTreeMap::new();

        let mut sorted_accounts: Vec<&str> = sums.keys().copied().collect();
        sorted_accounts.sort();

        for account in sorted_accounts {
            let exact_sums = exact_balances(&sums[account]);
            match account_root(account) {
                "Assets" => assets.push(balance_entry(account, exact_sums, &mut out_of_range)),
                "Liabilities" => {
                    liabilities.push(balance_entry(account, exact_sums, &mut out_of_range))
                }
                "Equity" => equity.push(balance_entry(account, exact_sums, &mut out_of_range)),
                // Income is stored as negative (credit) and expenses as
                // positive (debit): both are negated into net income.
                "Income" | "Expenses" => {
                    for (currency, amount) in exact_sums {
                        let running = net_income.entry(currency).or_insert(ExactAmount::ZERO);
                        *running = running.plus(amount.negated());
                    }
                }
                _ => {} // Other account types are not included in balance sheet.
            }
        }

        // §3.7.1: Add net_income as Equity:Net-Income (negated to credit/equity sign).
        if net_income.values().any(|amount| !amount.is_zero()) {
            let equity_sums = net_income
                .into_iter()
                .map(|(currency, amount)| (currency, amount.negated()))
                .collect();
            equity.push(balance_entry(
                "Equity:Net-Income",
                equity_sums,
                &mut out_of_range,
            ));
        }

        let exact = assets
            .iter()
            .chain(&liabilities)
            .chain(&equity)
            .all(|entry| entry.exact);
        let report = BalanceSheetReport {
            at,
            assets,
            liabilities,
            equity,
            exact,
        };
        (report, out_of_range)
    }

    /// Income statement for a date range (FR-2 AC3).
    pub fn income_statement(&self, from: NaiveDate, to: NaiveDate) -> IncomeStatementReport {
        self.income_statement_checked(from, to).0
    }

    /// [`Self::income_statement`], refusing a report with an out-of-range
    /// figure.
    pub fn try_income_statement(
        &self,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<IncomeStatementReport, OutOfRange> {
        in_range(self.income_statement_checked(from, to))
    }

    fn income_statement_checked(
        &self,
        from: NaiveDate,
        to: NaiveDate,
    ) -> (IncomeStatementReport, bool) {
        let sums = self.sums_where(None, |date| from <= date && date <= to);
        let mut out_of_range = false;

        let mut income = Vec::new();
        let mut expenses = Vec::new();
        let mut net: BTreeMap<String, ExactAmount> = BTreeMap::new();

        let mut sorted_accounts: Vec<&str> = sums.keys().copied().collect();
        sorted_accounts.sort();

        for account in sorted_accounts {
            let root = account_root(account);
            if root != "Income" && root != "Expenses" {
                continue; // Other types not included in income statement.
            }
            let exact_sums = exact_balances(&sums[account]);
            // Income is negative (credit), expenses positive (debit): both
            // are negated into net.
            for (currency, amount) in &exact_sums {
                let running = net.entry(currency.clone()).or_insert(ExactAmount::ZERO);
                *running = running.plus(amount.negated());
            }
            let entry = balance_entry(account, exact_sums, &mut out_of_range);
            if root == "Income" {
                income.push(entry);
            } else {
                expenses.push(entry);
            }
        }

        let mut exact = income.iter().chain(&expenses).all(|entry| entry.exact);
        let net = net
            .into_iter()
            .map(|(currency, amount)| {
                let figure = amount.figure(&mut out_of_range);
                exact &= figure.exact;
                (currency, figure.value)
            })
            .collect();

        let report = IncomeStatementReport {
            from,
            to,
            income,
            expenses,
            net,
            exact,
        };
        (report, out_of_range)
    }

    /// Journal of transactions, optionally filtered (FR-2 AC4).
    pub fn journal(
        &self,
        account: Option<&str>,
        from: Option<NaiveDate>,
        to: Option<NaiveDate>,
        limit: usize,
        offset: usize,
    ) -> Vec<&IndexedTransaction> {
        let filtered = self.transactions.iter().filter(|indexed| {
            // Date range filter.
            if let Some(from) = from {
                if indexed.transaction.date < from {
                    return false;
                }
            }
            if let Some(to) = to {
                if indexed.transaction.date > to {
                    return false;
                }
            }
            // Account filter.
            if let Some(account) = account {
                if !indexed
                    .transaction
                    .postings
                    .iter()
                    .any(|p| p.account == account)
                {
                    return false;
                }
            }
            true
        });

        filtered.skip(offset).take(limit).collect()
    }

    /// Look up a single transaction by txid.
    pub fn transaction(&self, txid: &str) -> Option<&IndexedTransaction> {
        self.txid_index
            .get(txid)
            .and_then(|&i| self.transactions.get(i))
    }

    /// Look up an account's balances (optionally at a specific date).
    pub fn account_balance(
        &self,
        account: &str,
        at: Option<NaiveDate>,
    ) -> Option<AccountBalanceEntry> {
        self.account_balance_checked(account, at).0
    }

    /// [`Self::account_balance`], refusing an out-of-range figure.
    pub fn try_account_balance(
        &self,
        account: &str,
        at: Option<NaiveDate>,
    ) -> Result<Option<AccountBalanceEntry>, OutOfRange> {
        in_range(self.account_balance_checked(account, at))
    }

    fn account_balance_checked(
        &self,
        account: &str,
        at: Option<NaiveDate>,
    ) -> (Option<AccountBalanceEntry>, bool) {
        let exact_sums = match at {
            // Only this account's postings are summed; the cut is the same
            // `date <= at` every date-cut report uses.
            Some(date) => self
                .sums_where(Some(account), |posted| posted <= date)
                .get(account)
                .map(exact_balances),
            None => self.account_balances.get(account).map(exact_balances),
        };
        let mut out_of_range = false;
        let entry = exact_sums.map(|sums| balance_entry(account, sums, &mut out_of_range));
        (entry, out_of_range)
    }

    /// Balances for many `(account, date)` pairs, from **one** date-ordered
    /// sweep of the ledger (M-23).
    ///
    /// Answers exactly what calling [`Self::account_balance(account,
    /// Some(date))`](Self::account_balance) once per pair answers — including
    /// `None` for an account with no priced postings on or before its date —
    /// but walks the transactions once in total instead of once per pair.
    ///
    /// # Why this exists
    ///
    /// T32 wired balance assertions into `verify` (M-08) by calling
    /// `account_balance(acct, Some(date))` per `balance` directive. Each of
    /// those calls rebuilt the **whole-ledger** balance map — every transaction,
    /// every posting, a `String` allocated per account and per currency — and
    /// then kept one entry. That made `verify`
    /// O(assertions × transactions × postings), and the assertion count is
    /// attacker-supplied: `balance` directives are ~250 bytes, carry no
    /// lifecycle check, and need not name an account that exists. The 0922
    /// audit measured perfect quadratic scaling (171 ms / 656 ms / 2.61 s at
    /// 1000², 2000², 4000²) and >100k plantable assertions under the file cap.
    ///
    /// # Shape
    ///
    /// Queries are visited in ascending date order against a cursor into the
    /// date-ordered transactions, so the running totals are only ever carried
    /// *forward*: each query's snapshot is taken after advancing the cursor
    /// through every transaction dated `<= its date`. Only accounts some query
    /// asks about are accumulated, and their keys are borrowed from the query
    /// set rather than cloned per posting.
    ///
    /// Cost is O(T·P + Q log Q + T log T) — linear in the ledger, with the
    /// assertion count no longer multiplying it. The `T log T` term is paid
    /// only when the transaction vector is actually out of date order (see
    /// [`Self::date_ordered_transactions`]).
    ///
    /// # Semantics preserved from T32 (pinned by
    /// `checkpoint::tests::test_batched_assertions_match_per_assertion_evaluation`)
    ///
    /// - **`<= date`**: a transaction dated *on* the query date is included.
    ///   This is deliberately not beancount's start-of-day rule; see
    ///   [`crate::checkpoint::evaluate_balance_assertion`].
    /// - **Same-date queries** all see the same cut: advancing the cursor for
    ///   the first one leaves nothing for the rest to advance.
    /// - **Unknown accounts** yield `None`, which callers read as `0` — so
    ///   `balance Assets:Unknown 0 USD` still passes.
    /// - Postings with no amount contribute nothing and create no entry, as in
    ///   [`Self::account_balance`] (`sums_where`).
    pub fn balances_at_dates(&self, queries: &[(&str, NaiveDate)]) -> BatchedBalances {
        let mut entries: Vec<Option<AccountBalanceEntry>> = vec![None; queries.len()];
        if queries.is_empty() {
            return BatchedBalances {
                entries,
                postings_visited: 0,
            };
        }

        // The accounts anyone asked about. Accumulating only these keeps the
        // running map bounded by the query set rather than by the ledger's
        // account count, and lets every posting reuse a key borrowed from here
        // instead of allocating a `String` (M-23).
        let wanted: HashSet<&str> = queries.iter().map(|&(account, _)| account).collect();

        // Query visit order: ascending by date. Stable, so two queries on the
        // same date keep their input order — irrelevant to the answer, but it
        // keeps the sweep deterministic.
        let mut visit: Vec<usize> = (0..queries.len()).collect();
        visit.sort_by_key(|&i| queries[i].1);

        let order = self.date_ordered_transactions();
        let mut running: HashMap<&str, ExactBalances> = HashMap::new();
        let mut cursor = 0usize;
        let mut postings_visited = 0usize;

        for &query in &visit {
            let (account, at) = queries[query];

            // Carry the running totals forward to this query's date. The
            // cursor never rewinds, which is what makes the whole batch one
            // pass rather than one pass each.
            while cursor < order.len() {
                let txn = &self.transactions[order[cursor]].transaction;
                if txn.date > at {
                    break;
                }
                for posting in &txn.postings {
                    postings_visited += 1;
                    let Some(ref amount) = posting.amount else {
                        continue;
                    };
                    // `get` rather than `contains`: it hands back the `&str`
                    // owned by `queries`, so the running map's key costs no
                    // allocation.
                    let Some(&key) = wanted.get(posting.account.as_str()) else {
                        continue;
                    };
                    // H-17: the same exact accumulator the live running
                    // totals use, so the two agree by construction.
                    add_to(running.entry(key).or_default(), amount);
                }
                cursor += 1;
            }

            // The entry carries the exact sums, so an assertion answered from
            // it is compared exactly (T76, L-79); an out-of-range figure is
            // reported saturated and can equal no claim.
            entries[query] = running
                .get(account)
                .map(|balances| balance_entry(account, exact_balances(balances), &mut false));
        }

        BatchedBalances {
            entries,
            postings_visited,
        }
    }

    /// Number of indexed transactions.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// The latest date of any transaction with a posting on `account`.
    ///
    /// `None` when the account has never been posted to. Backed by the
    /// [`posting_dates`](Self::posting_dates) index, so this is a lookup
    /// rather than a scan of every transaction.
    pub fn latest_posting_date(&self, account: &str) -> Option<NaiveDate> {
        self.posting_dates.get(account)?.last().copied()
    }

    /// Whether a transaction with a posting on `account` is dated inside
    /// `range` (T98 / M-09, decision (54): the interval a `close` closes — see
    /// [`crate::accounts::AccountState::deciding_close_interval`]).
    pub fn holds_posting_in(
        &self,
        account: &str,
        range: (std::ops::Bound<NaiveDate>, std::ops::Bound<NaiveDate>),
    ) -> bool {
        self.posting_dates
            .get(account)
            .is_some_and(|dates| dates.range(range).next().is_some())
    }

    /// Indexed postings whose amount is outside the amount cap
    /// ([`crate::limits::MAX_AMOUNT_MAGNITUDE`]).
    ///
    /// Informational. Zero whenever every directive reached the model through
    /// an ingress — the local API, peer ingest, reconcile, journal replay and
    /// the `.bean` parser at boot all refuse such an amount. Non-zero only for
    /// a model a library caller built from unvalidated directives. Balances
    /// stay exact either way ([`ExactSum`]); only such a model can hold a sum
    /// that is [`OutOfRange`].
    pub fn over_cap_posting_count(&self) -> usize {
        self.over_cap_postings
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Indices into [`Self::transactions`], ascending by transaction date (M-23).
    ///
    /// [`Self::build`] leaves the vector sorted by `(date, lamport, txid)`, but
    /// [`Self::index_directive`] — the incremental path every insert uses —
    /// appends. A backdated directive arriving after boot (a gossiped older
    /// transaction, an adopted file edit) therefore leaves the vector out of
    /// date order, and [`Self::balances_at_dates`] sweeps it with a cursor that
    /// never rewinds, so it cannot just trust the vector's order.
    ///
    /// The check is O(T) and the common case really is already sorted, so the
    /// sort is paid only when a backdated append has actually happened. The
    /// sort is stable, so ties keep the vector's own `(date, lamport, txid)`
    /// order — balances are an exact sum over the cut ([`ExactSum`], H-17), so
    /// intra-date order does not affect the answer, representation included.
    fn date_ordered_transactions(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.transactions.len()).collect();
        let already_sorted = self
            .transactions
            .windows(2)
            .all(|pair| pair[0].transaction.date <= pair[1].transaction.date);
        if !already_sorted {
            order.sort_by_key(|&i| self.transactions[i].transaction.date);
        }
        order
    }

    /// Exact per-account sums over the transactions whose date passes
    /// `included` — the one fold every date-cut report shares (H-17) — for
    /// every account, or only `account`.
    ///
    /// Walks the vector in arrival order, which is safe because the fold is
    /// exact ([`ExactSum`]): it equals the running totals and the batched
    /// sweep whatever order either of them walked.
    fn sums_where(
        &self,
        account: Option<&str>,
        included: impl Fn(NaiveDate) -> bool,
    ) -> HashMap<&str, ExactBalances> {
        let mut sums: HashMap<&str, ExactBalances> = HashMap::new();

        for indexed in &self.transactions {
            if !included(indexed.transaction.date) {
                continue;
            }
            for posting in &indexed.transaction.postings {
                if account.is_some_and(|wanted| wanted != posting.account) {
                    continue;
                }
                if let Some(ref amount) = posting.amount {
                    add_to(sums.entry(posting.account.as_str()).or_default(), amount);
                }
            }
        }
        sums
    }
}

/// Add `amount` into an account's per-currency sums; only the first sighting
/// of a currency allocates its key.
fn add_to(balances: &mut ExactBalances, amount: &Amount) {
    match balances.get_mut(&amount.currency) {
        Some(sum) => sum.add(amount.number),
        None => {
            let mut sum = ExactSum::default();
            sum.add(amount.number);
            balances.insert(amount.currency.clone(), sum);
        }
    }
}

/// Extract the root account type (e.g., "Assets" from "Assets:Cash:Checking").
fn account_root(account: &str) -> &str {
    account.split(':').next().unwrap_or(account)
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
            tags: Vec::new(),
            links: Vec::new(),
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

    fn sample_directives() -> Vec<Directive> {
        vec![
            // Jan 15: Initial funding.
            make_txn(
                make_date(2024, 1, 15),
                "Initial funding",
                vec![
                    ("Assets:Cash", dec!(1000.00), "USD"),
                    ("Equity:Opening", dec!(-1000.00), "USD"),
                ],
            ),
            // Feb 1: Rent.
            make_txn(
                make_date(2024, 2, 1),
                "Rent",
                vec![
                    ("Expenses:Rent", dec!(500.00), "USD"),
                    ("Assets:Cash", dec!(-500.00), "USD"),
                ],
            ),
            // Feb 15: Salary.
            make_txn(
                make_date(2024, 2, 15),
                "Salary",
                vec![
                    ("Assets:Cash", dec!(3000.00), "USD"),
                    ("Income:Salary", dec!(-3000.00), "USD"),
                ],
            ),
            // Mar 1: Groceries.
            make_txn(
                make_date(2024, 3, 1),
                "Groceries",
                vec![
                    ("Expenses:Food", dec!(200.00), "USD"),
                    ("Assets:Cash", dec!(-200.00), "USD"),
                ],
            ),
        ]
    }

    // ── Build ────────────────────────────────────────────────────────────

    #[test]
    fn test_build_empty() {
        let model = ReadModel::build(&[]);
        assert_eq!(model.transaction_count(), 0);
    }

    #[test]
    fn test_build_indexes_transactions() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);
        assert_eq!(model.transaction_count(), 4);
    }

    #[test]
    fn test_build_running_balances() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);

        // Assets:Cash = 1000 - 500 + 3000 - 200 = 3300
        let cash = model.account_balance("Assets:Cash", None).unwrap();
        assert_eq!(cash.balances.get("USD"), Some(&dec!(3300.00)));

        // Expenses:Rent = 500
        let rent = model.account_balance("Expenses:Rent", None).unwrap();
        assert_eq!(rent.balances.get("USD"), Some(&dec!(500.00)));
    }

    #[test]
    fn test_build_skips_non_transactions() {
        let mut directives = sample_directives();
        directives.push(Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        }));
        let model = ReadModel::build(&directives);
        assert_eq!(model.transaction_count(), 4); // Only transactions counted.
    }

    // ── Trial Balance ────────────────────────────────────────────────────

    #[test]
    fn test_trial_balance_totals_equal() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);
        let report = model.trial_balance(make_date(2024, 12, 31));

        assert_eq!(
            report.total_debit, report.total_credit,
            "FR-2 AC1: total debits == total credits"
        );
    }

    #[test]
    fn test_trial_balance_at_date() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);

        // At Jan 31: only the initial funding.
        let report = model.trial_balance(make_date(2024, 1, 31));
        assert_eq!(report.rows.len(), 2); // Assets:Cash, Equity:Opening
        assert_eq!(report.total_debit, dec!(1000.00));
        assert_eq!(report.total_credit, dec!(1000.00));
    }

    #[test]
    fn test_trial_balance_rows_sorted() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);
        let report = model.trial_balance(make_date(2024, 12, 31));

        let accounts: Vec<&str> = report.rows.iter().map(|r| r.account.as_str()).collect();
        let mut sorted = accounts.clone();
        sorted.sort();
        assert_eq!(accounts, sorted, "Rows should be alphabetically sorted");
    }

    // ── Balance Sheet (§3.7.1) ───────────────────────────────────────────

    #[test]
    fn test_balance_sheet_closing_rule() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);
        let report = model.balance_sheet(make_date(2024, 12, 31));

        // Assets = Cash: 3300 USD
        assert_eq!(report.assets.len(), 1);
        assert_eq!(report.assets[0].account, "Assets:Cash");
        assert_eq!(report.assets[0].balances.get("USD"), Some(&dec!(3300.00)));

        // Equity = Opening (-1000) + Net-Income
        // Net-Income = Income(3000) - Expenses(500+200) = 2300
        let net_income_entry = report
            .equity
            .iter()
            .find(|e| e.account == "Equity:Net-Income")
            .expect("Should have Equity:Net-Income");
        // Net-Income = -(Income - Expenses) in equity (credit) sign.
        // Income = -3000 (credit), Expenses = 700 (debit).
        // Raw net_income = 3000 - 700 = 2300, negated to equity = -2300.
        assert_eq!(
            net_income_entry.balances.get("USD"),
            Some(&dec!(-2300.00)),
            "Net-Income = -(Income - Expenses) in equity sign convention"
        );

        // Assets = Liabilities + Equity (fundamental accounting equation).
        let sum_balances = |entries: &[AccountBalanceEntry], currency: &str| -> Decimal {
            entries
                .iter()
                .map(|e| e.balances.get(currency).copied().unwrap_or(Decimal::ZERO))
                .sum()
        };

        let total_assets = sum_balances(&report.assets, "USD");
        let total_liabilities = sum_balances(&report.liabilities, "USD");
        let total_equity = sum_balances(&report.equity, "USD");

        // Fundamental accounting equation in Beancount sign convention:
        // Assets + Liabilities + Equity = 0 (credits are negative).
        // After the §3.7.1 closing entry (Net-Income), all P&L is folded into Equity.
        assert_eq!(
            total_assets + total_liabilities + total_equity,
            Decimal::ZERO,
            "Assets + Liabilities + Equity = 0 (Beancount sign convention)"
        );
    }

    #[test]
    fn test_balance_sheet_at_date() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);
        let report = model.balance_sheet(make_date(2024, 1, 31));

        // At Jan 31: only initial funding.
        assert_eq!(report.assets[0].balances.get("USD"), Some(&dec!(1000.00)));
        // No income/expenses yet, so no Equity:Net-Income entry.
        assert!(
            !report
                .equity
                .iter()
                .any(|e| e.account == "Equity:Net-Income"),
            "No Net-Income when no P&L activity"
        );
    }

    // ── Income Statement ─────────────────────────────────────────────────

    #[test]
    fn test_income_statement() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);
        let report = model.income_statement(make_date(2024, 1, 1), make_date(2024, 12, 31));

        // Income: Salary = -3000 (credit is negative in our model).
        assert_eq!(report.income.len(), 1);
        assert_eq!(report.income[0].account, "Income:Salary");

        // Expenses: Rent + Food.
        assert_eq!(report.expenses.len(), 2);

        // Net = Income - Expenses = 3000 - 700 = 2300.
        // (Income amounts are negative in our model, so net = sum(income) - sum(expenses)).
        assert_eq!(report.net.get("USD"), Some(&dec!(2300.00)));
    }

    #[test]
    fn test_income_statement_date_range() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);

        // Only February.
        let report = model.income_statement(make_date(2024, 2, 1), make_date(2024, 2, 28));

        // Income: Salary = 3000.
        assert_eq!(report.income.len(), 1);
        // Expenses: Rent = 500 (Groceries is March).
        assert_eq!(report.expenses.len(), 1);
        assert_eq!(report.expenses[0].account, "Expenses:Rent");

        assert_eq!(report.net.get("USD"), Some(&dec!(2500.00)));
    }

    // ── Journal ──────────────────────────────────────────────────────────

    #[test]
    fn test_journal_all() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);
        let journal = model.journal(None, None, None, 100, 0);
        assert_eq!(journal.len(), 4);
    }

    #[test]
    fn test_journal_by_account() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);
        let journal = model.journal(Some("Expenses:Rent"), None, None, 100, 0);
        assert_eq!(journal.len(), 1);
        assert_eq!(journal[0].transaction.narration, Some("Rent".to_owned()));
    }

    #[test]
    fn test_journal_date_range() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);
        let journal = model.journal(
            None,
            Some(make_date(2024, 2, 1)),
            Some(make_date(2024, 2, 28)),
            100,
            0,
        );
        assert_eq!(journal.len(), 2); // Rent + Salary
    }

    #[test]
    fn test_journal_pagination() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);

        let page1 = model.journal(None, None, None, 2, 0);
        let page2 = model.journal(None, None, None, 2, 2);

        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_ne!(page1[0].txid, page2[0].txid);
    }

    // ── Transaction lookup ───────────────────────────────────────────────

    #[test]
    fn test_transaction_lookup() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);

        let first = &model.journal(None, None, None, 1, 0)[0];
        let found = model.transaction(&first.txid);
        assert!(found.is_some());
        assert_eq!(found.unwrap().txid, first.txid);
    }

    #[test]
    fn test_transaction_not_found() {
        let model = ReadModel::build(&[]);
        assert!(model.transaction("nonexistent").is_none());
    }

    // ── Account balance ──────────────────────────────────────────────────

    #[test]
    fn test_account_balance_current() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);

        let balance = model.account_balance("Assets:Cash", None).unwrap();
        assert_eq!(balance.balances.get("USD"), Some(&dec!(3300.00)));
    }

    #[test]
    fn test_account_balance_at_date() {
        let directives = sample_directives();
        let model = ReadModel::build(&directives);

        // At Jan 31: only initial funding.
        let balance = model
            .account_balance("Assets:Cash", Some(make_date(2024, 1, 31)))
            .unwrap();
        assert_eq!(balance.balances.get("USD"), Some(&dec!(1000.00)));
    }

    #[test]
    fn test_account_balance_unknown() {
        let model = ReadModel::build(&[]);
        assert!(model.account_balance("Nonexistent", None).is_none());
    }

    // ── Multi-currency ───────────────────────────────────────────────────

    #[test]
    fn test_multi_currency_balances() {
        let directives = vec![
            make_txn(
                make_date(2024, 1, 15),
                "USD deposit",
                vec![
                    ("Assets:Cash", dec!(1000), "USD"),
                    ("Equity:Opening", dec!(-1000), "USD"),
                ],
            ),
            make_txn(
                make_date(2024, 1, 16),
                "EUR deposit",
                vec![
                    ("Assets:Cash", dec!(500), "EUR"),
                    ("Equity:Opening", dec!(-500), "EUR"),
                ],
            ),
        ];
        let model = ReadModel::build(&directives);

        let balance = model.account_balance("Assets:Cash", None).unwrap();
        assert_eq!(balance.balances.get("USD"), Some(&dec!(1000)));
        assert_eq!(balance.balances.get("EUR"), Some(&dec!(500)));
        assert_eq!(balance.balances.len(), 2);
    }

    // ── Incremental update ───────────────────────────────────────────────

    #[test]
    fn test_incremental_update() {
        let directives = sample_directives();
        let mut model = ReadModel::build(&directives[..2]); // First 2 txns.
        assert_eq!(model.transaction_count(), 2);

        // Add the 3rd transaction.
        model.index_directive(&directives[2]);
        assert_eq!(model.transaction_count(), 3);

        // Balance updated.
        let cash = model.account_balance("Assets:Cash", None).unwrap();
        // 1000 - 500 + 3000 = 3500
        assert_eq!(cash.balances.get("USD"), Some(&dec!(3500.00)));
    }

    #[test]
    fn test_incremental_dedup() {
        let directives = sample_directives();
        let mut model = ReadModel::build(&directives);
        let count_before = model.transaction_count();

        // Re-index an existing directive — should be a no-op.
        model.index_directive(&directives[0]);
        assert_eq!(
            model.transaction_count(),
            count_before,
            "Duplicate should be skipped"
        );
    }

    // ── Account root extraction ──────────────────────────────────────────

    #[test]
    fn test_account_root() {
        assert_eq!(account_root("Assets:Cash:Checking"), "Assets");
        assert_eq!(account_root("Liabilities:CreditCard"), "Liabilities");
        assert_eq!(account_root("Equity"), "Equity");
    }

    // ── Golden fixture ───────────────────────────────────────────────────

    #[test]
    fn test_golden_fixture_read_model() {
        let fixture = include_str!("../../../testfixtures/fixture-simple.bean");
        let directives = crate::parse::parse_file(fixture).unwrap();
        let model = ReadModel::build(&directives);

        // The fixture has 3 transactions.
        assert_eq!(
            model.transaction_count(),
            3,
            "Fixture should have 3 transactions"
        );

        // Balance sheet should satisfy the accounting equation (per currency).
        let bs = model.balance_sheet(make_date(2025, 12, 31));
        assert!(!bs.assets.is_empty(), "Should have asset accounts");

        // Journal should return all transactions.
        let journal = model.journal(None, None, None, 100, 0);
        assert_eq!(journal.len(), 3);

        // Account lookup.
        let cash = model.account_balance("Assets:Cash", None).unwrap();
        // 1000 + 25 - 1500 = -475 USD
        assert_eq!(cash.balances.get("USD"), Some(&dec!(-475.00)));
    }

    // ── M-23: batched balances-at-date ───────────────────────────────────

    /// The safety property: one batched sweep answers exactly what one
    /// `account_balance(acct, Some(date))` call per query answered.
    ///
    /// The fixture deliberately covers every case the sweep has to get right —
    /// queries out of date order, two queries on the same date, a posting dated
    /// *on* a query date (the `<= date` rule), a later transaction that must
    /// not leak backwards, a second currency on the same account, an account
    /// that exists but has nothing yet, and an account that never appears.
    #[test]
    fn test_batched_sweep_matches_account_balance_per_query() {
        let jan10 = make_date(2024, 1, 10);
        let jan20 = make_date(2024, 1, 20);
        let jan31 = make_date(2024, 1, 31);

        let directives = vec![
            make_txn(
                jan10,
                "deposit",
                vec![
                    ("Assets:Cash", dec!(1000), "USD"),
                    ("Equity:Opening", dec!(-1000), "USD"),
                ],
            ),
            make_txn(
                jan10,
                "same day, second currency",
                vec![
                    ("Assets:Cash", dec!(7), "EUR"),
                    ("Equity:Opening", dec!(-7), "EUR"),
                ],
            ),
            make_txn(
                jan20,
                "later",
                vec![
                    ("Assets:Cash", dec!(500), "USD"),
                    ("Expenses:Rent", dec!(-500), "USD"),
                ],
            ),
        ];
        let model = ReadModel::build(&directives);

        let queries = [
            ("Assets:Cash", jan31),
            ("Assets:Cash", jan10), // `<= date`: jan10's postings count.
            ("Equity:Opening", jan10),
            ("Assets:Cash", jan10),    // Same account, same date, repeated.
            ("Expenses:Rent", jan10),  // Exists later, nothing yet here.
            ("Assets:Nowhere", jan31), // Never posted to at all.
            ("Assets:Cash", jan20),
        ];

        let batched = model.balances_at_dates(&queries);
        let one_by_one: Vec<Option<AccountBalanceEntry>> = queries
            .iter()
            .map(|&(account, at)| model.account_balance(account, Some(at)))
            .collect();

        assert_eq!(batched.entries, one_by_one);

        // And pin the values, so both paths cannot regress together.
        let usd = |entry: &Option<AccountBalanceEntry>| {
            entry
                .as_ref()
                .and_then(|e| e.balances.get("USD").copied())
                .unwrap_or(Decimal::ZERO)
        };
        assert_eq!(usd(&batched.entries[0]), dec!(1500));
        assert_eq!(usd(&batched.entries[1]), dec!(1000));
        assert_eq!(usd(&batched.entries[2]), dec!(-1000));
        assert_eq!(usd(&batched.entries[3]), dec!(1000));
        assert!(
            batched.entries[4].is_none(),
            "no postings on or before jan10"
        );
        assert!(batched.entries[5].is_none(), "account never appears");
        assert_eq!(usd(&batched.entries[6]), dec!(1500));
        // The EUR leg rode along on the same sweep.
        assert_eq!(
            batched.entries[1].as_ref().unwrap().balances.get("EUR"),
            Some(&dec!(7))
        );
    }

    /// M-23: the sweep's cost is a property of the ledger, not of the query
    /// count — the invariant T32 broke and the one the GraphQL `verify` weight
    /// is sized on.
    ///
    /// Counted rather than timed: a multiplier is exact, and a wall-clock ratio
    /// on a fixture this size measures the allocator.
    #[test]
    fn test_batched_sweep_cost_is_independent_of_query_count() {
        let jan10 = make_date(2024, 1, 10);
        let jan20 = make_date(2024, 1, 20);

        let mut directives = Vec::new();
        for i in 0..500 {
            directives.push(make_txn(
                if i % 2 == 0 { jan10 } else { jan20 },
                &format!("txn {i}"),
                vec![
                    ("Assets:Cash", dec!(1), "USD"),
                    ("Equity:Opening", dec!(-1), "USD"),
                ],
            ));
        }
        let model = ReadModel::build(&directives);

        let one = [("Assets:Cash", jan20)];
        let many: Vec<(&str, NaiveDate)> = (0..20_000)
            .map(|i| {
                (
                    if i % 3 == 0 {
                        "Assets:Cash"
                    } else {
                        "Assets:Planted"
                    },
                    if i % 7 == 0 { jan10 } else { jan20 },
                )
            })
            .collect();

        let one_cost = model.balances_at_dates(&one).postings_visited;
        let many_cost = model.balances_at_dates(&many).postings_visited;

        assert_eq!(one_cost, 1000, "500 transactions x 2 postings, one pass");
        assert_eq!(
            many_cost, one_cost,
            "20,000 planted assertions must not multiply the ledger walk (M-23)"
        );
    }

    /// M-23: the sweep stops at the latest query date — work a query never
    /// needed is not done.
    #[test]
    fn test_batched_sweep_stops_at_the_latest_query_date() {
        let jan10 = make_date(2024, 1, 10);
        let jan20 = make_date(2024, 1, 20);

        let directives = vec![
            make_txn(
                jan10,
                "early",
                vec![
                    ("Assets:Cash", dec!(1), "USD"),
                    ("Equity:Opening", dec!(-1), "USD"),
                ],
            ),
            make_txn(
                jan20,
                "late",
                vec![
                    ("Assets:Cash", dec!(1), "USD"),
                    ("Equity:Opening", dec!(-1), "USD"),
                ],
            ),
        ];
        let model = ReadModel::build(&directives);

        assert_eq!(
            model
                .balances_at_dates(&[("Assets:Cash", jan10)])
                .postings_visited,
            2
        );
        assert_eq!(
            model
                .balances_at_dates(&[("Assets:Cash", jan20)])
                .postings_visited,
            4
        );
    }

    /// M-23: `index_directive` appends, so a backdated directive arriving after
    /// boot leaves `transactions` out of date order. The cursor-based sweep
    /// must re-order before walking, or it silently drops the backdated entry.
    #[test]
    fn test_batched_sweep_handles_out_of_order_transactions() {
        let jan10 = make_date(2024, 1, 10);
        let jan20 = make_date(2024, 1, 20);

        let mut model = ReadModel::build(&[make_txn(
            jan20,
            "booted",
            vec![
                ("Assets:Cash", dec!(500), "USD"),
                ("Equity:Opening", dec!(-500), "USD"),
            ],
        )]);
        model.index_directive(&make_txn(
            jan10,
            "backdated arrival",
            vec![
                ("Assets:Cash", dec!(1000), "USD"),
                ("Equity:Opening", dec!(-1000), "USD"),
            ],
        ));

        let queries = [("Assets:Cash", jan10), ("Assets:Cash", jan20)];
        let batched = model.balances_at_dates(&queries);
        let one_by_one: Vec<Option<AccountBalanceEntry>> = queries
            .iter()
            .map(|&(account, at)| model.account_balance(account, Some(at)))
            .collect();

        assert_eq!(batched.entries, one_by_one);
        assert_eq!(
            batched.entries[0].as_ref().unwrap().balances.get("USD"),
            Some(&dec!(1000))
        );
        assert_eq!(
            batched.entries[1].as_ref().unwrap().balances.get("USD"),
            Some(&dec!(1500))
        );
    }

    // ── H-17: exact, order-independent balances ─────────────────────────

    use proptest::prelude::*;

    /// The amount cap's magnitude (`10^21`), as the signed type `Decimal`
    /// builds from: the largest in-cap integer, and an in-cap mantissa at any
    /// scale.
    const CAP: i128 = crate::limits::MAX_AMOUNT_MAGNITUDE as i128;

    fn at_scale(mantissa: i128, scale: u32) -> Decimal {
        Decimal::from_i128_with_scale(mantissa, scale)
    }

    /// Balances as exact text: equal values that print differently (`1.0` vs
    /// `1.00`, `-0` vs `0`) must not count as agreement.
    fn render(entry: &Option<AccountBalanceEntry>) -> Option<Vec<(String, String)>> {
        entry.as_ref().map(|entry| {
            entry
                .balances
                .iter()
                .map(|(currency, number)| (currency.clone(), number.to_string()))
                .collect()
        })
    }

    fn render_trial_balance(report: &TrialBalanceReport) -> Vec<String> {
        let mut rendered: Vec<String> = report
            .rows
            .iter()
            .map(|row| format!("{} {} {}", row.account, row.debit, row.credit))
            .collect();
        rendered.push(format!("{} {}", report.total_debit, report.total_credit));
        rendered
    }

    /// The B6 shape, inside the cap: `+X` dated later, honest dust, `−X` dated
    /// earliest. `X` is the largest in-cap integer and the dust sits at the
    /// finest scale — both legal amounts — so `X + dust` needs 49 digits.
    ///
    /// Before T65 the balance was one `Decimal` folded in arrival order, and
    /// `X + dust` silently rounded the dust away: the replica that saw `X`
    /// before `−X` reported 0, the one that saw them the other way reported
    /// the dust, and `verify`'s date-ordered sweep disagreed with the live
    /// total on the same node (H-17).
    #[test]
    fn test_h17_in_cap_extremes_are_order_independent() {
        let big = at_scale(CAP, 0);
        let dust = at_scale(1, 28);
        let pair = |day: u32, narration: &str, number: Decimal| {
            make_txn(
                make_date(2024, 1, day),
                narration,
                vec![("Assets:A", number, "USD"), ("Assets:B", -number, "USD")],
            )
        };
        let plus_big = pair(20, "+X", big);
        let honest = pair(10, "dust", dust);
        let minus_big = pair(5, "-X", -big);

        let arrivals = [
            [plus_big.clone(), honest.clone(), minus_big.clone()],
            [minus_big.clone(), plus_big.clone(), honest.clone()],
            [honest.clone(), minus_big.clone(), plus_big.clone()],
            [plus_big.clone(), minus_big.clone(), honest.clone()],
        ];
        let far = make_date(2024, 12, 31);
        for arrival in &arrivals {
            let mut live = ReadModel::default();
            for directive in arrival {
                live.index_directive(directive);
            }
            let built = ReadModel::build(arrival);
            let batched = live.balances_at_dates(&[("Assets:A", far)]);
            for (label, entry) in [
                ("live account()", live.account_balance("Assets:A", None)),
                (
                    "live account(at:)",
                    live.account_balance("Assets:A", Some(far)),
                ),
                ("batched sweep", batched.entries[0].clone()),
                (
                    "rebooted account()",
                    built.account_balance("Assets:A", None),
                ),
            ] {
                assert_eq!(
                    entry.as_ref().map(|entry| entry.balances["USD"]),
                    Some(dust),
                    "{label}: the honest dust must survive every arrival order"
                );
            }
            let row = live
                .trial_balance(far)
                .rows
                .into_iter()
                .find(|row| row.account == "Assets:A")
                .unwrap();
            assert_eq!(row.debit, dust, "trial balance agrees");
            assert_eq!(live.over_cap_posting_count(), 0);
        }
    }

    /// An amount past the cap can only come from a caller that skipped every
    /// ingress. The model counts it, and falls back to non-panicking
    /// arithmetic rather than asserting (T17/H1's no-panic contract).
    #[test]
    fn test_h17_over_cap_amounts_are_counted_not_panicked_on() {
        let over = make_txn(
            make_date(2024, 1, 1),
            "over",
            vec![
                ("Assets:A", Decimal::MAX, "USD"),
                ("Assets:B", Decimal::MIN, "USD"),
            ],
        );
        let again = make_txn(
            make_date(2024, 1, 2),
            "again",
            vec![
                ("Assets:A", Decimal::MAX, "USD"),
                ("Assets:B", Decimal::MIN, "USD"),
            ],
        );
        let model = ReadModel::build(&[over, again]);
        assert_eq!(model.over_cap_posting_count(), 4);
        let entry = model.account_balance("Assets:A", None).unwrap();
        assert_eq!(
            entry.balances["USD"],
            Decimal::MAX,
            "2 × MAX is out of range: reported saturated, instead of panicking"
        );
        assert!(!entry.exact, "and flagged inexact (T76)");
        assert_eq!(
            model.try_account_balance("Assets:A", None),
            Err(OutOfRange),
            "the typed form refuses it (T76)"
        );
        assert_eq!(
            model.try_trial_balance(make_date(2024, 12, 31)).err(),
            Some(OutOfRange)
        );
        assert_eq!(
            model.try_balance_sheet(make_date(2024, 12, 31)).err(),
            Some(OutOfRange)
        );
        let in_cap = ReadModel::build(&sample_directives());
        assert_eq!(in_cap.over_cap_posting_count(), 0);
    }

    /// Scale is part of what a balance prints, so it must be order-free too.
    /// Before T65, `5.00 − 5.00 + 3` printed `3` (a zero left operand hands
    /// back the right one) while `3 + 5.00 − 5.00` printed `3.00`. A zero
    /// balance is `0.00`, never `-0.00`.
    #[test]
    fn test_h17_representation_is_order_independent() {
        let t = |day: u32, number: Decimal| {
            make_txn(
                make_date(2024, 1, day),
                &format!("t{day}"),
                vec![("Assets:A", number, "USD")],
            )
        };
        let a = t(1, dec!(5.00));
        let b = t(2, dec!(-5.00));
        let c = t(3, dec!(3));
        let one = ReadModel::build(&[a.clone(), b.clone(), c.clone()]);
        let mut two = ReadModel::default();
        for directive in [&c, &b, &a] {
            two.index_directive(directive);
        }
        let printed = |model: &ReadModel| {
            model.account_balance("Assets:A", None).unwrap().balances["USD"].to_string()
        };
        assert_eq!(printed(&one), printed(&two));

        let zero = ReadModel::build(&[a, b]);
        assert_eq!(
            zero.account_balance("Assets:A", None).unwrap().balances["USD"].to_string(),
            "0.00"
        );
    }

    /// Any in-cap amount at any scale, weighted towards the extremes that
    /// broke the old fold: `±CAP` at scale 0 and single units at scale 28.
    fn capped_amount() -> impl Strategy<Value = Decimal> {
        let mantissa = prop_oneof![
            Just(CAP),
            Just(-CAP),
            Just(1i128),
            Just(-1i128),
            -1_000i128..1_000,
            -CAP..=CAP,
        ];
        let scale = prop_oneof![Just(0u32), Just(2u32), Just(8u32), Just(28u32), 0u32..=28];
        (mantissa, scale).prop_map(|(mantissa, scale)| at_scale(mantissa, scale))
    }

    const PROP_ACCOUNTS: [&str; 4] = ["Assets:A", "Assets:B", "Income:C", "Expenses:D"];
    const PROP_CURRENCIES: [&str; 2] = ["USD", "BTC"];

    fn arbitrary_transaction() -> impl Strategy<Value = Directive> {
        (
            0u64..20,
            prop::collection::vec((0usize..4, capped_amount(), 0usize..2), 1..4),
            any::<u32>(),
        )
            .prop_map(|(day, postings, nonce)| {
                let date = make_date(2024, 1, 1) + chrono::Days::new(day);
                let postings = postings
                    .into_iter()
                    .map(|(account, number, currency)| {
                        (PROP_ACCOUNTS[account], number, PROP_CURRENCIES[currency])
                    })
                    .collect();
                make_txn(date, &format!("n{nonce}"), postings)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        /// H-17's regression, as the audit specified it: random arrival order
        /// vs `build` (boot) vs the batched sweep (`verify`), with values up
        /// to the cap and mixed scales, checked at EVERY prefix — including
        /// the prefixes where a backdated directive has just been appended.
        ///
        /// Agreement is checked as printed text, not only as `Decimal`
        /// equality, so a path that reaches the same value with a different
        /// scale or a `-0` fails too.
        #[test]
        fn prop_h17_balances_are_exact_and_order_independent(
            (arrival, other_arrival) in prop::collection::vec(arbitrary_transaction(), 1..20)
                .prop_flat_map(|txns| (Just(txns.clone()), Just(txns).prop_shuffle())),
            query_days in prop::collection::vec(0u64..25, 1..8),
        ) {
            let far = make_date(2030, 1, 1);
            let mut live = ReadModel::default();
            for (prefix, directive) in arrival.iter().enumerate() {
                live.index_directive(directive);
                let seen = &arrival[..=prefix];
                // Boot over the same set, and the same set in reverse arrival.
                let built = ReadModel::build(seen);
                let mut reversed = ReadModel::default();
                for directive in seen.iter().rev() {
                    reversed.index_directive(directive);
                }
                prop_assert_eq!(live.over_cap_posting_count(), 0);

                let queries: Vec<(&str, NaiveDate)> = query_days
                    .iter()
                    .flat_map(|&day| {
                        let date = make_date(2023, 12, 28) + chrono::Days::new(day);
                        PROP_ACCOUNTS.iter().map(move |&account| (account, date))
                    })
                    .chain(PROP_ACCOUNTS.iter().map(|&account| (account, far)))
                    .collect();
                let batched = live.balances_at_dates(&queries);
                let batched_built = built.balances_at_dates(&queries);
                for (index, &(account, at)) in queries.iter().enumerate() {
                    let per_query = render(&live.account_balance(account, Some(at)));
                    prop_assert_eq!(
                        &render(&batched.entries[index]), &per_query,
                        "prefix {} batched vs account(at:) for {} at {}", prefix, account, at
                    );
                    prop_assert_eq!(&render(&batched_built.entries[index]), &per_query);
                }
                for account in PROP_ACCOUNTS {
                    let running = render(&live.account_balance(account, None));
                    prop_assert_eq!(
                        &running, &render(&live.account_balance(account, Some(far))),
                        "prefix {}: live account() vs account(at:) for {}", prefix, account
                    );
                    prop_assert_eq!(&running, &render(&built.account_balance(account, None)));
                    prop_assert_eq!(&running, &render(&reversed.account_balance(account, None)));
                }
                prop_assert_eq!(
                    render_trial_balance(&live.trial_balance(far)),
                    render_trial_balance(&built.trial_balance(far))
                );
            }

            // A second replica holding the same set, received in another order.
            let mut replica = ReadModel::default();
            for directive in &other_arrival {
                replica.index_directive(directive);
            }
            for account in PROP_ACCOUNTS {
                prop_assert_eq!(
                    render(&live.account_balance(account, None)),
                    render(&replica.account_balance(account, None))
                );
            }
            prop_assert_eq!(
                render_trial_balance(&live.trial_balance(far)),
                render_trial_balance(&replica.trial_balance(far))
            );
            let sheet = |model: &ReadModel| {
                let report = model.balance_sheet(far);
                format!("{:?}{:?}{:?}", report.assets, report.liabilities, report.equity)
            };
            prop_assert_eq!(sheet(&live), sheet(&replica));
            let income = |model: &ReadModel| {
                let report = model.income_statement(make_date(2024, 1, 5), far);
                format!("{:?}{:?}{:?}", report.income, report.expenses, report.net)
            };
            prop_assert_eq!(income(&live), income(&replica));
        }
    }

    // ── T76: rule R, the spelling rule and the count bound ───────────────

    fn exact_of(amounts: &[Decimal]) -> ExactAmount {
        let mut sum = ExactSum::default();
        for amount in amounts {
            sum.add(*amount);
        }
        sum.exact()
    }

    fn reported_text(amounts: &[Decimal]) -> Result<(String, bool), OutOfRange> {
        exact_of(amounts)
            .reported()
            .map(|reported| (reported.value.to_string(), reported.exact))
    }

    /// Rule R, branch 1: a sum that fits at its spelling scale is that sum,
    /// exact, spelled as `Decimal` addition spells it.
    #[test]
    fn test_t76_rule_r_reports_a_fitting_sum_exactly() {
        for (amounts, spelled) in [
            (vec![dec!(1.50), dec!(2.5)], "4.00"),
            (vec![dec!(2), dec!(-1), dec!(0.1), dec!(-0.1)], "1"),
            (vec![dec!(1), dec!(-1.0), dec!(0.00)], "0.00"),
            (vec![dec!(0.1), dec!(-0.10), dec!(3)], "3.00"),
            (
                vec![Decimal::MAX, Decimal::MAX, -Decimal::MAX],
                "79228162514264337593543950335",
            ),
        ] {
            assert_eq!(
                reported_text(&amounts),
                Ok((spelled.to_owned(), true)),
                "{amounts:?}"
            );
        }
    }

    /// Rule R, branch 2: a sum that does not fit at its spelling scale is
    /// rounded ONCE, half to even, at the finest scale that fits — ties both
    /// ways — and flagged inexact.
    #[test]
    fn test_t76_rule_r_rounds_a_non_fitting_sum_once_half_to_even() {
        let dust = Decimal::from_i128_with_scale(1, 28);
        assert_eq!(
            reported_text(&[dec!(1000), dust]),
            Ok(("1000.0000000000000000000000000".to_owned(), false))
        );
        // A tie at the cut rounds to the even neighbour: `…334.5` → `…334`,
        // `…333.5` → `…334`.
        let near_max =
            |last: i128| Decimal::from_i128_with_scale(Decimal::MAX.mantissa() - 335 + last, 0);
        assert_eq!(
            reported_text(&[near_max(334), dec!(0.5)]),
            Ok((near_max(334).to_string(), false))
        );
        assert_eq!(
            reported_text(&[near_max(333), dec!(0.5)]),
            Ok((near_max(334).to_string(), false))
        );
        assert_eq!(
            reported_text(&[Decimal::MAX, dec!(-0.5)]),
            Ok((near_max(334).to_string(), false))
        );
        // L-79's double-rounding case: the exact sum rounds UP at the last
        // kept digit; folding per scale rounded it down first.
        let amounts = [
            Decimal::from_i128_with_scale(999_999_999_999_999_999_999, 0),
            "0.0000000163569815000000000001".parse().unwrap(),
            "-93902.1645112500000001".parse().unwrap(),
        ];
        assert_eq!(
            reported_text(&amounts),
            Ok(("999999999999999906096.8354888".to_owned(), false))
        );
        // Dropped digits that are all zero: coarser, but still the sum.
        let many = vec![Decimal::from_i128_with_scale(CAP, 0); 100];
        let mut padded = many.clone();
        padded.push(dec!(0.00000001));
        padded.push(dec!(-0.00000001));
        padded.push(dec!(0.5000000));
        padded.push(dec!(0.5000000));
        let (text, exact) = reported_text(&padded).unwrap();
        assert!(exact, "{text}: only zeros were dropped");
        assert_eq!(
            text.parse::<Decimal>().unwrap(),
            Decimal::from_i128_with_scale(100 * CAP + 1, 0)
        );
    }

    /// Rule R, branch 3: past every scale — `MAX + 0.5` rounds up past `MAX`,
    /// `MAX + 1` needs 97 bits — the sum is `OutOfRange`.
    #[test]
    fn test_t76_rule_r_refuses_a_sum_no_decimal_holds() {
        assert_eq!(reported_text(&[Decimal::MAX, dec!(0.5)]), Err(OutOfRange));
        assert_eq!(
            reported_text(&[Decimal::MAX, Decimal::ONE]),
            Err(OutOfRange)
        );
        assert_eq!(
            reported_text(&[Decimal::MIN, -Decimal::ONE]),
            Err(OutOfRange)
        );
        let mut flag = false;
        let figure = exact_of(&[Decimal::MIN, -Decimal::ONE]).figure(&mut flag);
        assert!(flag);
        assert_eq!(
            figure,
            Reported {
                value: Decimal::MIN,
                exact: false
            }
        );
    }

    /// The `2^31`-postings bound, with the limit injected: the posting past
    /// the limit marks the sum out of range (sticky, order-free: it is a count),
    /// and every posting up to it is summed exactly.
    #[test]
    fn test_t76_a_partial_past_its_posting_limit_is_out_of_range() {
        let limit = 3;
        let mut within = ExactSum::default();
        for _ in 0..limit {
            within.add_bounded(Decimal::MAX, limit);
        }
        assert!(!within.out_of_range);
        assert_eq!(within.partials[0].count, limit);
        assert_eq!(within.partials[0].sum, 3 * Decimal::MAX.mantissa());
        let mut past = within.clone();
        past.add_bounded(dec!(1.0), limit);
        assert!(
            !past.out_of_range,
            "a different scale's partial has its own count"
        );
        past.add_bounded(Decimal::ZERO, limit);
        assert!(
            past.out_of_range,
            "the fourth scale-0 posting passes the limit"
        );
        assert_eq!(past.exact().reported(), Err(OutOfRange));
        past.add_bounded(dec!(-1), limit);
        assert!(past.out_of_range, "sticky");
        // A limit of zero refuses the first posting at a new scale.
        let mut none = ExactSum::default();
        none.add_bounded(dec!(1), 0);
        assert!(none.out_of_range);
        // The real bound keeps every prefix inside an `i128`.
        assert!(
            i128::try_from(u128::from(PARTIAL_POSTING_LIMIT) * DECIMAL_MANTISSA_MAX).is_ok(),
            "2^31 × (2^96 − 1) must fit an i128"
        );
    }

    /// `ExactAmount::equals` is value equality at any scale, and a model's
    /// entries carry the exact sums behind their reported figures.
    #[test]
    fn test_t76_entries_carry_the_exact_sum_behind_each_figure() {
        let dust = Decimal::from_i128_with_scale(1, 28);
        let model = ReadModel::build(&[
            make_txn(
                make_date(2024, 1, 1),
                "big",
                vec![("Assets:A", dec!(1000), "USD")],
            ),
            make_txn(
                make_date(2024, 1, 2),
                "dust",
                vec![("Assets:A", dust, "USD")],
            ),
        ]);
        let entry = model.account_balance("Assets:A", None).unwrap();
        assert!(!entry.exact);
        let sum = entry.exact_sums["USD"];
        assert!(!sum.equals(dec!(1000)));
        assert!(
            !sum.equals(entry.balances["USD"]),
            "the rounded figure is not the sum"
        );
        assert!(ExactAmount::from_decimal(dec!(100.00)).equals(dec!(100)));
        let report = model.trial_balance(make_date(2024, 12, 31));
        assert!(!report.exact && !report.rows[0].exact);
        let sheet = model.balance_sheet(make_date(2024, 12, 31));
        assert!(!sheet.exact && !sheet.assets[0].exact);
    }

    /// No queries: no answers, and no walk.
    #[test]
    fn test_batched_sweep_with_no_queries_does_no_work() {
        let model = ReadModel::build(&[make_txn(
            make_date(2024, 1, 10),
            "txn",
            vec![
                ("Assets:Cash", dec!(1), "USD"),
                ("Equity:Opening", dec!(-1), "USD"),
            ],
        )]);
        let batched = model.balances_at_dates(&[]);
        assert!(batched.entries.is_empty());
        assert_eq!(batched.postings_visited, 0);
    }
}
