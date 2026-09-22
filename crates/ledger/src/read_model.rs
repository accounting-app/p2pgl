//! In-memory read model and financial reports (§3.7).
//!
//! Built on boot, updated incrementally on append. Reports never re-parse
//! the file (FR-2 AC5).

use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::hash::compute_content_id;
use crate::model::*;

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

// ─── Read model ──────────────────────────────────────────────────────────────

/// The in-memory read model. Built from directives; queried by the GraphQL layer.
#[derive(Debug, Clone, Default)]
pub struct ReadModel {
    /// Per-account running balances: `account → currency → amount`.
    account_balances: HashMap<String, CurrencyBalances>,
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

            // Update running balances.
            for posting in &txn.postings {
                if let Some(ref amount) = posting.amount {
                    // Use the raw posting amount (not weight) for account balances.
                    // Account balances track commodity units, not converted amounts.
                    let balances = self
                        .account_balances
                        .entry(posting.account.clone())
                        .or_default();
                    let running = balances
                        .entry(amount.currency.clone())
                        .or_insert(Decimal::ZERO);
                    *running = running.saturating_add(amount.number);
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
                    net = net.saturating_add(amount);
                }

                let (debit, credit) = if net >= Decimal::ZERO {
                    (net, Decimal::ZERO)
                } else {
                    (Decimal::ZERO, -net)
                };

                total_debit = total_debit.saturating_add(debit);
                total_credit = total_credit.saturating_add(credit);

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
                        *running = running.saturating_sub(amount);
                    }
                }
                "Expenses" => {
                    for (currency, &amount) in currency_balances {
                        // Expenses are stored as positive (debit); subtract from net income.
                        let running = net_income.entry(currency.clone()).or_insert(Decimal::ZERO);
                        *running = running.saturating_sub(amount);
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
                        *running = running.saturating_sub(amount);
                    }
                    income.push(entry);
                }
                "Expenses" => {
                    for (currency, &amount) in currency_balances {
                        // Expenses are positive (debit); subtract from net.
                        let running = net.entry(currency.clone()).or_insert(Decimal::ZERO);
                        *running = running.saturating_sub(amount);
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
            None => self.account_balances.get(account).cloned()?,
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
        let mut running: HashMap<&str, CurrencyBalances> = HashMap::new();
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
                    let balances = running.entry(key).or_default();
                    match balances.get_mut(&amount.currency) {
                        Some(total) => *total = total.saturating_add(amount.number),
                        // Only the first sighting of a currency allocates.
                        None => {
                            balances.insert(amount.currency.clone(), amount.number);
                        }
                    }
                }
                cursor += 1;
            }

            entries[query] = running.get(account).map(|balances| AccountBalanceEntry {
                account: account.to_owned(),
                balances: balances.clone(),
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
    /// order — balances are a sum over the cut, so intra-date order does not
    /// affect the answer either way.
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
    fn balances_at(&self, at: NaiveDate) -> HashMap<String, CurrencyBalances> {
        let mut balances: HashMap<String, CurrencyBalances> = HashMap::new();

        for indexed in &self.transactions {
            if indexed.transaction.date > at {
                continue;
            }
            for posting in &indexed.transaction.postings {
                if let Some(ref amount) = posting.amount {
                    let account_balances = balances.entry(posting.account.clone()).or_default();
                    let running = account_balances
                        .entry(amount.currency.clone())
                        .or_insert(Decimal::ZERO);
                    *running = running.saturating_add(amount.number);
                }
            }
        }

        balances
    }

    /// Compute account balances in a date range [from, to] inclusive.
    fn balances_in_range(
        &self,
        from: NaiveDate,
        to: NaiveDate,
    ) -> HashMap<String, CurrencyBalances> {
        let mut balances: HashMap<String, CurrencyBalances> = HashMap::new();

        for indexed in &self.transactions {
            if indexed.transaction.date < from || indexed.transaction.date > to {
                continue;
            }
            for posting in &indexed.transaction.postings {
                if let Some(ref amount) = posting.amount {
                    let account_balances = balances.entry(posting.account.clone()).or_default();
                    let running = account_balances
                        .entry(amount.currency.clone())
                        .or_insert(Decimal::ZERO);
                    *running = running.saturating_add(amount.number);
                }
            }
        }

        balances
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
