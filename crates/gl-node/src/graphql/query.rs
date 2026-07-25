use async_graphql::{Context, Object};
use rust_decimal::Decimal;

use super::scalars::{DateScalar, DecimalScalar, TransactionId};
use super::types::{
    AccountBalance, Amount, BalanceSheet, HealthStatus, IncomeStatement, Peer, Posting,
    Transaction, TrialBalance, TrialBalanceRow, VerifyResult,
};
use super::SharedLedger;

/// GraphQL query root. Resolvers pull from `SharedLedger` when available,
/// fall back to empty defaults for introspection-only schemas.
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Trial balance at a given date (FR-2 AC1).
    async fn trial_balance(&self, ctx: &Context<'_>, at: DateScalar) -> TrialBalance {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let report = svc.read_model().trial_balance(at.0);
            TrialBalance {
                at,
                rows: report
                    .rows
                    .iter()
                    .map(|r| TrialBalanceRow {
                        account: r.account.clone(),
                        debit: DecimalScalar(r.debit),
                        credit: DecimalScalar(r.credit),
                    })
                    .collect(),
                total_debit: DecimalScalar(report.total_debit),
                total_credit: DecimalScalar(report.total_credit),
            }
        } else {
            TrialBalance {
                at,
                rows: Vec::new(),
                total_debit: DecimalScalar(Decimal::ZERO),
                total_credit: DecimalScalar(Decimal::ZERO),
            }
        }
    }

    /// Balance sheet at a given date (FR-2 AC2).
    async fn balance_sheet(&self, ctx: &Context<'_>, at: DateScalar) -> BalanceSheet {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let report = svc.read_model().balance_sheet(at.0);
            fn convert_balances(
                entries: &[ledger::read_model::AccountBalanceEntry],
            ) -> Vec<AccountBalance> {
                entries
                    .iter()
                    .map(|entry| AccountBalance {
                        account: entry.account.clone(),
                        balances: entry
                            .balances
                            .iter()
                            .map(|(currency, amount)| Amount {
                                number: DecimalScalar(*amount),
                                currency: currency.clone(),
                            })
                            .collect(),
                    })
                    .collect()
            }
            BalanceSheet {
                at,
                assets: convert_balances(&report.assets),
                liabilities: convert_balances(&report.liabilities),
                equity: convert_balances(&report.equity),
            }
        } else {
            BalanceSheet {
                at,
                assets: Vec::new(),
                liabilities: Vec::new(),
                equity: Vec::new(),
            }
        }
    }

    /// Income statement for a date range (FR-2 AC3).
    async fn income_statement(
        &self,
        ctx: &Context<'_>,
        from: DateScalar,
        to: DateScalar,
    ) -> IncomeStatement {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let report = svc.read_model().income_statement(from.0, to.0);
            fn convert_entries(
                entries: &[ledger::read_model::AccountBalanceEntry],
            ) -> Vec<AccountBalance> {
                entries
                    .iter()
                    .map(|entry| AccountBalance {
                        account: entry.account.clone(),
                        balances: entry
                            .balances
                            .iter()
                            .map(|(currency, amount)| Amount {
                                number: DecimalScalar(*amount),
                                currency: currency.clone(),
                            })
                            .collect(),
                    })
                    .collect()
            }
            IncomeStatement {
                from,
                to,
                income: convert_entries(&report.income),
                expenses: convert_entries(&report.expenses),
                net: report
                    .net
                    .iter()
                    .map(|(currency, amount)| Amount {
                        number: DecimalScalar(*amount),
                        currency: currency.clone(),
                    })
                    .collect(),
            }
        } else {
            IncomeStatement {
                from,
                to,
                income: Vec::new(),
                expenses: Vec::new(),
                net: Vec::new(),
            }
        }
    }

    /// Journal of transactions, optionally filtered (FR-2 AC4).
    async fn journal(
        &self,
        ctx: &Context<'_>,
        account: Option<String>,
        from: Option<DateScalar>,
        to: Option<DateScalar>,
        #[graphql(default = 100)] limit: i32,
        #[graphql(default = 0)] offset: i32,
    ) -> Vec<Transaction> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let entries = svc.read_model().journal(
                account.as_deref(),
                from.map(|d| d.0),
                to.map(|d| d.0),
                limit as usize,
                offset as usize,
            );
            entries
                .into_iter()
                .map(|e| domain_txn_to_graphql(&e.transaction, &svc))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Look up a single transaction by its content hash.
    async fn transaction(&self, ctx: &Context<'_>, txid: TransactionId) -> Option<Transaction> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            if let Some(ledger::model::Directive::Transaction(txn)) = svc.get_directive(&txid.0) {
                return Some(domain_txn_to_graphql(txn, &svc));
            }
        }
        None
    }

    /// Look up an account's balances.
    async fn account(
        &self,
        ctx: &Context<'_>,
        name: String,
        at: Option<DateScalar>,
    ) -> Option<AccountBalance> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            if let Some(entry) = svc.read_model().account_balance(&name, at.map(|d| d.0)) {
                return Some(AccountBalance {
                    account: name,
                    balances: entry
                        .balances
                        .iter()
                        .map(|(currency, amount)| Amount {
                            number: DecimalScalar(*amount),
                            currency: currency.clone(),
                        })
                        .collect(),
                });
            }
        }
        None
    }

    /// Verify DAG integrity (FR-5 AC1).
    async fn verify(&self, ctx: &Context<'_>) -> VerifyResult {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let report = ledger::verify::verify_dag(svc.dag());
            VerifyResult {
                ok: report.ok,
                nodes_checked: report.nodes_checked as i32,
                errors: report.errors.iter().map(|e| e.to_string()).collect(),
            }
        } else {
            VerifyResult {
                ok: true,
                nodes_checked: 0,
                errors: Vec::new(),
            }
        }
    }

    /// Node health status (§2.9 / FR-6 AC1).
    async fn health(&self, ctx: &Context<'_>) -> HealthStatus {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            HealthStatus {
                status: "ok".to_owned(),
                heads: svc.head_count() as i32,
                peers: 0, // Wired when P2P is integrated into gl-node.
                version: env!("CARGO_PKG_VERSION").to_owned(),
            }
        } else {
            HealthStatus {
                status: "ok".to_owned(),
                heads: 0,
                peers: 0,
                version: env!("CARGO_PKG_VERSION").to_owned(),
            }
        }
    }

    /// Connected peers and their heads (FR-6 AC2).
    async fn peers(&self) -> Vec<Peer> {
        Vec::new() // Wired when P2P is integrated into gl-node.
    }
}

/// Convert a domain Transaction to the GraphQL Transaction type.
pub fn domain_txn_to_graphql(
    txn: &ledger::model::Transaction,
    svc: &ledger::service::LedgerService,
) -> Transaction {
    let content_id =
        ledger::hash::compute_content_id(&ledger::model::Directive::Transaction(txn.clone()));
    Transaction {
        txid: TransactionId(content_id),
        date: DateScalar(txn.date),
        flag: match txn.flag {
            ledger::model::Flag::Complete => "*".to_owned(),
            ledger::model::Flag::Incomplete => "!".to_owned(),
        },
        payee: txn.payee.clone(),
        narration: txn.narration.clone(),
        tags: txn.tags.clone(),
        links: txn.links.clone(),
        postings: txn
            .postings
            .iter()
            .map(|p| {
                let amt = p.amount.as_ref().map(|a| Amount {
                    number: DecimalScalar(a.number),
                    currency: a.currency.clone(),
                });
                Posting {
                    account: p.account.clone(),
                    amount: amt.unwrap_or(Amount {
                        number: DecimalScalar(Decimal::ZERO),
                        currency: String::new(),
                    }),
                    cost: p.cost.as_ref().and_then(|c| {
                        c.amount.as_ref().map(|a| Amount {
                            number: DecimalScalar(a.number),
                            currency: a.currency.clone(),
                        })
                    }),
                    price: p.price.as_ref().map(|pr| match pr {
                        ledger::model::PriceSpec::Unit(a) | ledger::model::PriceSpec::Total(a) => {
                            Amount {
                                number: DecimalScalar(a.number),
                                currency: a.currency.clone(),
                            }
                        }
                    }),
                }
            })
            .collect(),
        author: txn
            .metadata
            .get("openledger-author")
            .cloned()
            .unwrap_or_default(),
        signature: txn.metadata.get("openledger-signature").cloned(),
        parents: txn
            .metadata
            .get("openledger-parents")
            .map(|p| {
                if p.is_empty() {
                    vec![]
                } else {
                    p.split(',')
                        .map(|s| TransactionId(s.trim().to_owned()))
                        .collect()
                }
            })
            .unwrap_or_default(),
    }
}
