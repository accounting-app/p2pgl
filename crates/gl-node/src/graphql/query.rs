use async_graphql::Object;
use rust_decimal::Decimal;

use super::scalars::{DateScalar, DecimalScalar, TransactionId};
use super::types::{
    AccountBalance, BalanceSheet, HealthStatus, IncomeStatement, Peer, Transaction, TrialBalance,
    VerifyResult,
};

/// GraphQL query root. All resolvers return typed placeholders until the ledger
/// service is wired in (M2+).
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Trial balance at a given date (FR-2 AC1).
    async fn trial_balance(&self, at: DateScalar) -> TrialBalance {
        TrialBalance {
            at,
            rows: Vec::new(),
            total_debit: DecimalScalar(Decimal::ZERO),
            total_credit: DecimalScalar(Decimal::ZERO),
        }
    }

    /// Balance sheet at a given date (FR-2 AC2).
    async fn balance_sheet(&self, at: DateScalar) -> BalanceSheet {
        BalanceSheet {
            at,
            assets: Vec::new(),
            liabilities: Vec::new(),
            equity: Vec::new(),
        }
    }

    /// Income statement for a date range (FR-2 AC3).
    async fn income_statement(&self, from: DateScalar, to: DateScalar) -> IncomeStatement {
        IncomeStatement {
            from,
            to,
            income: Vec::new(),
            expenses: Vec::new(),
            net: Vec::new(),
        }
    }

    /// Journal of transactions, optionally filtered (FR-2 AC4).
    async fn journal(
        &self,
        _account: Option<String>,
        _from: Option<DateScalar>,
        _to: Option<DateScalar>,
        #[graphql(default = 100)] _limit: i32,
        #[graphql(default = 0)] _offset: i32,
    ) -> Vec<Transaction> {
        Vec::new()
    }

    /// Look up a single transaction by its content hash.
    async fn transaction(&self, _txid: TransactionId) -> Option<Transaction> {
        None
    }

    /// Look up an account's balances.
    async fn account(&self, _name: String, _at: Option<DateScalar>) -> Option<AccountBalance> {
        None
    }

    /// Verify DAG integrity (FR-5 AC1).
    async fn verify(&self) -> VerifyResult {
        VerifyResult {
            ok: true,
            nodes_checked: 0,
            errors: Vec::new(),
        }
    }

    /// Node health status (§2.9 / FR-6 AC1).
    async fn health(&self) -> HealthStatus {
        HealthStatus {
            status: "ok".to_owned(),
            heads: 0,
            peers: 0,
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Connected peers and their heads (FR-6 AC2).
    async fn peers(&self) -> Vec<Peer> {
        Vec::new()
    }
}
