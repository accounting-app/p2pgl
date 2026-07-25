use async_graphql::SimpleObject;

use super::scalars::{DateScalar, DecimalScalar, TransactionId};

/// A decimal amount with a currency (e.g., `1000.00 USD`).
#[derive(SimpleObject, Debug, Clone)]
pub struct Amount {
    pub number: DecimalScalar,
    pub currency: String,
}

/// A single line in a journal entry — an account plus an amount.
#[derive(SimpleObject, Debug, Clone)]
pub struct Posting {
    pub account: String,
    pub amount: Amount,
    pub cost: Option<Amount>,
    pub price: Option<Amount>,
}

/// A complete journal entry with DAG metadata.
#[derive(SimpleObject, Debug, Clone)]
pub struct Transaction {
    pub txid: TransactionId,
    pub date: DateScalar,
    /// `"*"` (complete) or `"!"` (incomplete).
    pub flag: String,
    pub payee: Option<String>,
    pub narration: Option<String>,
    pub tags: Vec<String>,
    pub links: Vec<String>,
    pub postings: Vec<Posting>,
    /// Authoring peer's Iroh `EndpointId`.
    pub author: String,
    /// Optional Ed25519 signature (hex), present when signing is enabled.
    pub signature: Option<String>,
    /// Parent `txid`s in the DAG. Empty for genesis transactions.
    pub parents: Vec<TransactionId>,
}

/// An account and its balances (one per currency).
#[derive(SimpleObject, Debug, Clone)]
pub struct AccountBalance {
    pub account: String,
    pub balances: Vec<Amount>,
}

/// A single row in the trial balance report.
#[derive(SimpleObject, Debug, Clone)]
pub struct TrialBalanceRow {
    pub account: String,
    pub debit: DecimalScalar,
    pub credit: DecimalScalar,
}

/// Full trial balance at a point in time.
#[derive(SimpleObject, Debug, Clone)]
pub struct TrialBalance {
    pub at: DateScalar,
    pub rows: Vec<TrialBalanceRow>,
    pub total_debit: DecimalScalar,
    pub total_credit: DecimalScalar,
}

/// Balance sheet: Assets, Liabilities, Equity at a point in time.
#[derive(SimpleObject, Debug, Clone)]
pub struct BalanceSheet {
    pub at: DateScalar,
    pub assets: Vec<AccountBalance>,
    pub liabilities: Vec<AccountBalance>,
    pub equity: Vec<AccountBalance>,
}

/// Income statement for a date range.
#[derive(SimpleObject, Debug, Clone)]
pub struct IncomeStatement {
    pub from: DateScalar,
    pub to: DateScalar,
    pub income: Vec<AccountBalance>,
    pub expenses: Vec<AccountBalance>,
    pub net: Vec<Amount>,
}

/// Result of the `verify` query — DAG integrity check.
#[derive(SimpleObject, Debug, Clone)]
pub struct VerifyResult {
    pub ok: bool,
    pub nodes_checked: i32,
    pub errors: Vec<String>,
}

/// Node health status (matches REST `/health` per §2.9).
#[derive(SimpleObject, Debug, Clone)]
#[graphql(name = "Health")]
pub struct HealthStatus {
    pub status: String,
    pub heads: i32,
    pub peers: i32,
    pub version: String,
}

/// A connected peer and its advertised heads.
#[derive(SimpleObject, Debug, Clone)]
pub struct Peer {
    pub id: String,
    pub heads: Vec<TransactionId>,
}
