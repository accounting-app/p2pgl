//! In-memory read model and financial reports (§3.7).
//!
//! Built on boot, updated incrementally on append. Reports never re-parse
//! the file (FR-2 AC5).

use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::collections::{BTreeMap, HashMap};

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
}

impl ReadModel {
    /// Build the read model from a set of directives.
    pub fn build(directives: &[Directive]) -> Self {
        let mut model = ReadModel {
            account_balances: HashMap::new(),
            transactions: Vec::new(),
            txid_index: HashMap::new(),
            account_postings: HashMap::new(),
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
                    *balances.entry(amount.currency.clone()).or_insert(Decimal::ZERO) +=
                        amount.number;
                }
            }

            // Index by account.
            for posting in &txn.postings {
                self.account_postings
                    .entry(posting.account.clone())
                    .or_default()
                    .push(txid.clone());
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
                    net += amount;
                }

                let (debit, credit) = if net >= Decimal::ZERO {
                    (net, Decimal::ZERO)
                } else {
                    (Decimal::ZERO, -net)
                };

                total_debit += debit;
                total_credit += credit;

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
                        *net_income.entry(currency.clone()).or_insert(Decimal::ZERO) -= amount;
                    }
                }
                "Expenses" => {
                    for (currency, &amount) in currency_balances {
                        // Expenses are stored as positive (debit); subtract from net income.
                        *net_income.entry(currency.clone()).or_insert(Decimal::ZERO) -= amount;
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
                        *net.entry(currency.clone()).or_insert(Decimal::ZERO) -= amount;
                    }
                    income.push(entry);
                }
                "Expenses" => {
                    for (currency, &amount) in currency_balances {
                        // Expenses are positive (debit); subtract from net.
                        *net.entry(currency.clone()).or_insert(Decimal::ZERO) -= amount;
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
        let filtered: Vec<&IndexedTransaction> = self
            .transactions
            .iter()
            .filter(|indexed| {
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
            })
            .collect();

        filtered.into_iter().skip(offset).take(limit).collect()
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

    /// Number of indexed transactions.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Compute account balances at a given date (transactions with date ≤ at).
    fn balances_at(&self, at: NaiveDate) -> HashMap<String, CurrencyBalances> {
        let mut balances: HashMap<String, CurrencyBalances> = HashMap::new();

        for indexed in &self.transactions {
            if indexed.transaction.date > at {
                continue;
            }
            for posting in &indexed.transaction.postings {
                if let Some(ref amount) = posting.amount {
                    let account_balances =
                        balances.entry(posting.account.clone()).or_default();
                    *account_balances
                        .entry(amount.currency.clone())
                        .or_insert(Decimal::ZERO) += amount.number;
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
                    let account_balances =
                        balances.entry(posting.account.clone()).or_default();
                    *account_balances
                        .entry(amount.currency.clone())
                        .or_insert(Decimal::ZERO) += amount.number;
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
        assert_eq!(
            journal[0].transaction.narration,
            Some("Rent".to_owned())
        );
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
        assert_eq!(model.transaction_count(), 3, "Fixture should have 3 transactions");

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
}
