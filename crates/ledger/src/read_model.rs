//! In-memory read model and financial reports (§3.7).
//!
//! Built on boot, updated incrementally on append. Reports never re-parse
//! the file (FR-2 AC5).

use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::hash::compute_content_id;
use crate::model::*;
use crate::validate::amount_within_cap;

// ─── Core types ──────────────────────────────────────────────────────────────

/// Per-account, per-currency balance.
pub type CurrencyBalances = BTreeMap<String, Decimal>;

/// An account balance entry for report output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountBalanceEntry {
    pub account: String,
    pub balances: CurrencyBalances,
}

/// A trial balance row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialBalanceRow {
    pub account: String,
    pub debit: Decimal,
    pub credit: Decimal,
}

/// Full trial balance report.
#[derive(Debug, Clone)]
pub struct TrialBalanceReport {
    pub at: NaiveDate,
    pub rows: Vec<TrialBalanceRow>,
    pub total_debit: Decimal,
    pub total_credit: Decimal,
}

/// Balance sheet report (§3.7.1).
#[derive(Debug, Clone)]
pub struct BalanceSheetReport {
    pub at: NaiveDate,
    pub assets: Vec<AccountBalanceEntry>,
    pub liabilities: Vec<AccountBalanceEntry>,
    pub equity: Vec<AccountBalanceEntry>,
}

/// Income statement report.
#[derive(Debug, Clone)]
pub struct IncomeStatementReport {
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub income: Vec<AccountBalanceEntry>,
    pub expenses: Vec<AccountBalanceEntry>,
    pub net: CurrencyBalances,
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

// ─── Exact accumulation (H-17) ───────────────────────────────────────────────

/// An exact, order-independent running sum of one currency's amounts (H-17).
///
/// # The bug this replaces
///
/// Balances used to be one `Decimal` per `(account, currency)`, advanced with
/// `saturating_add` in whatever order the caller walked. Neither half of that
/// is associative: saturation (`MAX + 1 − MAX = 0`, `MAX − MAX + 1 = 1`), and
/// `Decimal` addition itself, which at any scale above zero does not fail on a
/// 96-bit overflow but drops a digit and rounds. The live running totals
/// folded in arrival order and `verify`'s sweep and boot in date order, so a
/// peer holding `+MAX` / `−MAX` could erase an honest posting from one
/// replica's live reports while `verify` passed on it (H-17).
///
/// # Why this is exact
///
/// One partial sum is kept **per scale** present, so every addition is between
/// two numbers of the same scale, and each partial is the exact integer sum of
/// its amounts' mantissas. Every stored amount has `|mantissa| ≤ 10^21 − 1`
/// ([`crate::validate::MAX_AMOUNT_MANTISSA`], enforced at every ingress), and
/// no partial can hold more postings than a 64 MiB ledger has bytes, so every
/// partial stays below `2^26 × 10^21 < 2^96`: no addition ever overflows, so
/// none ever rounds, so the partials are the same whatever order the amounts
/// arrived in. [`Self::total`] then combines the partials in ascending-scale
/// order — a fixed order over order-independent inputs — so the reported
/// balance, representation included, is a pure function of the set of amounts.
///
/// That is why no path has to fold in a canonical order to agree with another:
/// the incremental running total, `account(at:)`, every report and `verify`'s
/// batched sweep reach the same partials from any order, including after a
/// backdated [`ReadModel::index_directive`] append. Re-folding in canonical
/// `(date, type priority, content id)` order would have given the same answer
/// at the cost of a per-account re-sort on every backdated arrival — which a
/// gossip catch-up makes quadratic.
///
/// A single partial is also why keeping one per scale, rather than capping the
/// scale, is enough: mixing scales was the other non-associativity (`10^20 +
/// 10^-8` needs 29 digits), and here scales never meet until [`Self::total`].
///
/// # Outside the cap
///
/// An amount past the cap can only reach the read model from a caller that
/// bypassed every ingress (a library caller building one from raw directives,
/// as some overflow tests deliberately do). Such a partial falls back to the
/// pre-H-17 saturating/rounding arithmetic rather than panic — T17/H1's
/// no-panic contract — and [`ReadModel::over_cap_posting_count`] says so. The
/// fallback is a `debug_assert` failure whenever that count is zero, because
/// then it is unreachable by the arithmetic above.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ExactSum {
    /// `(scale, partial)`, ascending by scale, one entry per scale seen. The
    /// scale is the key the partial was opened under; inside the cap it is
    /// also the partial's own scale.
    partials: Vec<(u32, Decimal)>,
}

impl ExactSum {
    /// Add one amount into the partial for its scale.
    ///
    /// `exact_guaranteed` is `true` when every amount the model holds is inside
    /// the cap — then this addition cannot overflow, and a failure is a bug.
    fn add(&mut self, number: Decimal, exact_guaranteed: bool) {
        let scale = number.scale();
        match self.partials.binary_search_by_key(&scale, |&(key, _)| key) {
            Ok(index) => {
                let partial = &mut self.partials[index].1;
                *partial = add_same_scale(*partial, number, exact_guaranteed);
            }
            Err(index) => self
                .partials
                .insert(index, (scale, without_negative_zero(number))),
        }
    }

    /// The balance: the partials combined in ascending-scale order.
    ///
    /// Exact whenever the result fits 96 bits at the finest scale present —
    /// every realistic balance. Past that, `Decimal` rounds the finest digits,
    /// but in this one fixed order over order-independent partials, so every
    /// path and every replica rounds identically.
    fn total(&self, exact_guaranteed: bool) -> Decimal {
        self.partials
            .iter()
            .fold(Decimal::ZERO, |total, &(_, partial)| {
                add_in_fixed_order(total, partial, exact_guaranteed)
            })
    }
}

/// Same-scale addition that is exact or reports that it was not (H-17).
///
/// `checked_add` is not enough on its own: it returns `None` only at scale 0,
/// and at any other scale "overflow" means it quietly dropped a digit. Between
/// two operands of one scale an exact sum keeps that scale (a zero operand
/// returns the other, which has it too), so a changed scale is the rounding.
fn add_same_scale(partial: Decimal, number: Decimal, exact_guaranteed: bool) -> Decimal {
    match partial.checked_add(number) {
        Some(sum) if sum.scale() == partial.scale() => without_negative_zero(sum),
        _ => {
            debug_assert!(
                !exact_guaranteed,
                "H-17: a same-scale partial of in-cap amounts overflowed 96 bits \
                 ({partial} + {number}); MAX_AMOUNT_MANTISSA no longer bounds the sum"
            );
            partial.saturating_add(number)
        }
    }
}

/// Addition in a caller-fixed order over order-independent inputs (H-17).
///
/// Used where the operands are already reported balances — a total across
/// scales, currencies or accounts — each combined in one deterministic order
/// (ascending scale, `BTreeMap` currency order, sorted account order). Such a
/// sum may round when its operands' scales are far apart, identically
/// everywhere; it cannot overflow while every amount is inside the cap,
/// because the magnitude of any such sum is at most the sum of every posting's
/// magnitude, `< 2^26 × 10^21 × 1.12 < 2^96`.
fn add_in_fixed_order(left: Decimal, right: Decimal, exact_guaranteed: bool) -> Decimal {
    match left.checked_add(right) {
        Some(sum) => without_negative_zero(sum),
        None => {
            debug_assert!(
                !exact_guaranteed,
                "H-17: a report-level sum of in-cap balances overflowed ({left} + {right})"
            );
            left.saturating_add(right)
        }
    }
}

/// `-0` and `0` are equal but print differently; a balance must not depend on
/// which of them an addition order happened to produce.
fn without_negative_zero(mut number: Decimal) -> Decimal {
    if number.is_zero() {
        number.set_sign_positive(true);
    }
    number
}

/// Per-currency exact sums for one account.
type ExactBalances = BTreeMap<String, ExactSum>;

/// The reported form of an account's exact sums.
fn report_balances(balances: &ExactBalances, exact_guaranteed: bool) -> CurrencyBalances {
    balances
        .iter()
        .map(|(currency, sum)| (currency.clone(), sum.total(exact_guaranteed)))
        .collect()
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
    /// Latest transaction date per account: `account → max(txn.date)`.
    ///
    /// Maintained incrementally so the FR-3 AC2 close rule ("no transactions
    /// after the close date") is an O(1) lookup instead of a full-DAG scan on
    /// every local and ingested `close`. A monotone max over the same set
    /// `account_postings` indexes, so it is order-insensitive and needs no
    /// rebuild: every path that puts a transaction into the DAG also calls
    /// [`Self::index_directive`], and the DAG is grow-only (nothing is ever
    /// removed), so the index cannot go stale in either direction.
    latest_posting_dates: HashMap<String, NaiveDate>,
    /// Indexed postings whose amount is outside the H-17 cap.
    ///
    /// Zero for every model built from directives that passed an ingress; see
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
            latest_posting_dates: HashMap::new(),
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
            // matter (H-17; see `ExactSum`).
            for posting in &txn.postings {
                if let Some(ref amount) = posting.amount {
                    if !amount_within_cap(amount.number) {
                        self.over_cap_postings += 1;
                    }
                }
            }
            let exact_guaranteed = self.exact_guaranteed();
            for posting in &txn.postings {
                if let Some(ref amount) = posting.amount {
                    // Use the raw posting amount (not weight) for account balances.
                    // Account balances track commodity units, not converted amounts.
                    self.account_balances
                        .entry(posting.account.clone())
                        .or_default()
                        .entry(amount.currency.clone())
                        .or_default()
                        .add(amount.number, exact_guaranteed);
                }
            }

            // Index by account, and carry the per-account latest transaction
            // date forward with it (see `latest_posting_dates`).
            for posting in &txn.postings {
                self.account_postings
                    .entry(posting.account.clone())
                    .or_default()
                    .push(txid.clone());
                self.latest_posting_dates
                    .entry(posting.account.clone())
                    .and_modify(|latest| *latest = (*latest).max(txn.date))
                    .or_insert(txn.date);
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

    // ── Report queries ───────────────────────────────────────────────────

    /// Trial balance at a given date (FR-2 AC1).
    ///
    /// Returns every account's debit/credit balance. For multi-currency accounts,
    /// positive amounts are debits and negative are credits (as Decimal sums).
    pub fn trial_balance(&self, at: NaiveDate) -> TrialBalanceReport {
        let exact_guaranteed = self.exact_guaranteed();
        let balances = self.balances_at(at);
        let mut rows = Vec::new();
        let mut total_debit = Decimal::ZERO;
        let mut total_credit = Decimal::ZERO;

        // Collect all accounts, sorted.
        let mut accounts: Vec<&str> = balances.keys().map(|s| s.as_str()).collect();
        accounts.sort();

        for account in accounts {
            if let Some(currency_balances) = balances.get(account) {
                // Sum all currencies into a single debit/credit per account.
                // This is a simplification — in practice, debit/credit is per currency,
                // but the GraphQL type uses a single Decimal.
                let mut net = Decimal::ZERO;
                for &amount in currency_balances.values() {
                    net = add_in_fixed_order(net, amount, exact_guaranteed);
                }

                let (debit, credit) = if net >= Decimal::ZERO {
                    (net, Decimal::ZERO)
                } else {
                    (Decimal::ZERO, -net)
                };

                total_debit = add_in_fixed_order(total_debit, debit, exact_guaranteed);
                total_credit = add_in_fixed_order(total_credit, credit, exact_guaranteed);

                rows.push(TrialBalanceRow {
                    account: account.to_owned(),
                    debit,
                    credit,
                });
            }
        }

        TrialBalanceReport {
            at,
            rows,
            total_debit,
            total_credit,
        }
    }

    /// Balance sheet at a given date (FR-2 AC2, §3.7.1).
    ///
    /// Includes the Net-Income closing entry into Equity.
    pub fn balance_sheet(&self, at: NaiveDate) -> BalanceSheetReport {
        let exact_guaranteed = self.exact_guaranteed();
        let balances = self.balances_at(at);

        let mut assets = Vec::new();
        let mut liabilities = Vec::new();
        let mut equity = Vec::new();

        // Collect Net-Income (Income − Expenses) for the closing rule.
        let mut net_income: CurrencyBalances = BTreeMap::new();

        let mut sorted_accounts: Vec<&String> = balances.keys().collect();
        sorted_accounts.sort();

        for account in sorted_accounts {
            let currency_balances = &balances[account];
            let root = account_root(account);

            let entry = AccountBalanceEntry {
                account: account.clone(),
                balances: currency_balances.clone(),
            };

            match root {
                "Assets" => assets.push(entry),
                "Liabilities" => liabilities.push(entry),
                "Equity" => equity.push(entry),
                "Income" => {
                    for (currency, &amount) in currency_balances {
                        // Income is stored as negative (credit); negate to get positive contribution.
                        let running = net_income.entry(currency.clone()).or_insert(Decimal::ZERO);
                        *running = add_in_fixed_order(*running, -amount, exact_guaranteed);
                    }
                }
                "Expenses" => {
                    for (currency, &amount) in currency_balances {
                        // Expenses are stored as positive (debit); subtract from net income.
                        let running = net_income.entry(currency.clone()).or_insert(Decimal::ZERO);
                        *running = add_in_fixed_order(*running, -amount, exact_guaranteed);
                    }
                }
                _ => {} // Other account types are not included in balance sheet.
            }
        }

        // §3.7.1: Add net_income as Equity:Net-Income (negated to credit/equity sign).
        if net_income.values().any(|&v| v != Decimal::ZERO) {
            let equity_balances: CurrencyBalances = net_income
                .into_iter()
                .map(|(currency, amount)| (currency, -amount))
                .collect();
            equity.push(AccountBalanceEntry {
                account: "Equity:Net-Income".to_owned(),
                balances: equity_balances,
            });
        }

        BalanceSheetReport {
            at,
            assets,
            liabilities,
            equity,
        }
    }

    /// Income statement for a date range (FR-2 AC3).
    pub fn income_statement(&self, from: NaiveDate, to: NaiveDate) -> IncomeStatementReport {
        let exact_guaranteed = self.exact_guaranteed();
        let balances = self.balances_in_range(from, to);

        let mut income = Vec::new();
        let mut expenses = Vec::new();
        let mut net: CurrencyBalances = BTreeMap::new();

        let mut sorted_accounts: Vec<&String> = balances.keys().collect();
        sorted_accounts.sort();

        for account in sorted_accounts {
            let currency_balances = &balances[account];
            let root = account_root(account);

            let entry = AccountBalanceEntry {
                account: account.clone(),
                balances: currency_balances.clone(),
            };

            match root {
                "Income" => {
                    for (currency, &amount) in currency_balances {
                        // Income is negative (credit); negate for net.
                        let running = net.entry(currency.clone()).or_insert(Decimal::ZERO);
                        *running = add_in_fixed_order(*running, -amount, exact_guaranteed);
                    }
                    income.push(entry);
                }
                "Expenses" => {
                    for (currency, &amount) in currency_balances {
                        // Expenses are positive (debit); subtract from net.
                        let running = net.entry(currency.clone()).or_insert(Decimal::ZERO);
                        *running = add_in_fixed_order(*running, -amount, exact_guaranteed);
                    }
                    expenses.push(entry);
                }
                _ => {} // Other types not included in income statement.
            }
        }

        IncomeStatementReport {
            from,
            to,
            income,
            expenses,
            net,
        }
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
        let balances = match at {
            Some(date) => {
                let all = self.balances_at(date);
                all.get(account).cloned()?
            }
            None => report_balances(self.account_balances.get(account)?, self.exact_guaranteed()),
        };

        Some(AccountBalanceEntry {
            account: account.to_owned(),
            balances,
        })
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
    ///   [`Self::balances_at`].
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
        let exact_guaranteed = self.exact_guaranteed();
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
                    let balances = running.entry(key).or_default();
                    match balances.get_mut(&amount.currency) {
                        Some(sum) => sum.add(amount.number, exact_guaranteed),
                        // Only the first sighting of a currency allocates.
                        None => {
                            let mut sum = ExactSum::default();
                            sum.add(amount.number, exact_guaranteed);
                            balances.insert(amount.currency.clone(), sum);
                        }
                    }
                }
                cursor += 1;
            }

            entries[query] = running.get(account).map(|balances| AccountBalanceEntry {
                account: account.to_owned(),
                balances: report_balances(balances, exact_guaranteed),
            });
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
    /// [`latest_posting_dates`](Self::latest_posting_dates) index, so this is a
    /// hash lookup rather than a scan of every transaction.
    pub fn latest_posting_date(&self, account: &str) -> Option<NaiveDate> {
        self.latest_posting_dates.get(account).copied()
    }

    /// Indexed postings whose amount is outside the H-17 amount cap
    /// ([`crate::validate::MAX_AMOUNT_MANTISSA`]).
    ///
    /// Zero whenever every directive reached the model through an ingress —
    /// the local API, peer ingest, reconcile, or the `.bean` parser at boot
    /// all refuse such an amount — and then every balance and report this
    /// model returns is exact and independent of the order the directives
    /// arrived in. Non-zero only for a model a library caller built from
    /// unvalidated directives; see [`ExactSum`] for what the reports then do.
    pub fn over_cap_posting_count(&self) -> usize {
        self.over_cap_postings
    }

    /// Whether every indexed amount is inside the cap, so every accumulation
    /// is provably exact (the condition the H-17 debug assertions check).
    fn exact_guaranteed(&self) -> bool {
        self.over_cap_postings == 0
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

    /// Compute account balances at a given date (transactions with date ≤ at).
    ///
    /// Walks the vector in arrival order, which is safe because the fold is
    /// exact ([`ExactSum`], H-17): it equals the running totals and the batched
    /// sweep whatever order either of them walked.
    fn balances_at(&self, at: NaiveDate) -> HashMap<String, CurrencyBalances> {
        self.balances_where(|date| date <= at)
    }

    /// Compute account balances in a date range [from, to] inclusive.
    fn balances_in_range(
        &self,
        from: NaiveDate,
        to: NaiveDate,
    ) -> HashMap<String, CurrencyBalances> {
        self.balances_where(|date| from <= date && date <= to)
    }

    /// Exact per-account balances over the transactions whose date passes
    /// `included` — the one fold every date-cut report shares (H-17).
    fn balances_where(
        &self,
        included: impl Fn(NaiveDate) -> bool,
    ) -> HashMap<String, CurrencyBalances> {
        let exact_guaranteed = self.exact_guaranteed();
        let mut sums: HashMap<&str, ExactBalances> = HashMap::new();

        for indexed in &self.transactions {
            if !included(indexed.transaction.date) {
                continue;
            }
            for posting in &indexed.transaction.postings {
                if let Some(ref amount) = posting.amount {
                    let account_sums = sums.entry(posting.account.as_str()).or_default();
                    match account_sums.get_mut(&amount.currency) {
                        Some(sum) => sum.add(amount.number, exact_guaranteed),
                        None => {
                            let mut sum = ExactSum::default();
                            sum.add(amount.number, exact_guaranteed);
                            account_sums.insert(amount.currency.clone(), sum);
                        }
                    }
                }
            }
        }

        sums.into_iter()
            .map(|(account, balances)| {
                (
                    account.to_owned(),
                    report_balances(&balances, exact_guaranteed),
                )
            })
            .collect()
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

    use crate::validate::MAX_AMOUNT_MANTISSA;
    use proptest::prelude::*;

    /// The largest in-cap mantissa, as the signed type `Decimal` builds from.
    const CAP: i128 = MAX_AMOUNT_MANTISSA as i128;

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
        assert_eq!(
            model.account_balance("Assets:A", None).unwrap().balances["USD"],
            Decimal::MAX,
            "saturates, as before H-17, instead of panicking"
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
