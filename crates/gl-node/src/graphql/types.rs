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

/// The payload of the `appendTransaction` mutation (M-10).
///
/// Every field of [`Transaction`] is flattened in, so selections written
/// against the old payload keep working unchanged; `alreadyExisted` is the
/// added interim M-10 signal.
#[derive(SimpleObject, Debug, Clone)]
pub struct AppendedTransaction {
    /// The transaction as the ledger holds it — freshly inserted, or the entry
    /// that was already there when `alreadyExisted` is `true` (note that its
    /// `author` and `signature` are then the *earlier* writer's, not yours).
    #[graphql(flatten)]
    pub transaction: Transaction,
    /// `true` means this exact economic content was **already in the ledger**
    /// — possibly appended by another author — and **nothing new was
    /// recorded** by this call (M-10).
    ///
    /// The content hash covers the economic body only; author, parents,
    /// Lamport clock and signature are excluded. So an append whose body
    /// already exists is a silent no-op that leaves the first writer's
    /// envelope in place, and the mesh attributes the event to them.
    ///
    /// Callers SHOULD treat `true` as a **warning**, not a success: this event
    /// may have been collapsed with an earlier identical one (two identical
    /// same-day coffees become a single posting), or squatted by a peer that
    /// predicted the content (recurring rent, salary) and published it first.
    /// Distinguish a genuinely distinct event by varying the body — a link, a
    /// tag, or a more specific narration.
    pub already_existed: bool,
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

/// A `balance` assertion that did not hold (§3.6, M-08).
#[derive(SimpleObject, Debug, Clone)]
pub struct BalanceAssertionFailure {
    /// The asserted account.
    pub account: String,
    /// The date the assertion is made for.
    pub date: DateScalar,
    /// The amount the `balance` directive claims.
    pub expected: DecimalScalar,
    /// The amount the ledger actually holds on that date.
    pub actual: DecimalScalar,
    /// The currency both figures are in.
    pub currency: String,
}

/// Outcome of evaluating the ledger's `balance` assertions (§3.6, M-08).
///
/// A `balance` directive asserts that an account holds an amount of one
/// currency on a date. Evaluation is read-only: failures are reported here and
/// never reject a transaction or alter a balance, and `pad` directives are not
/// synthesized into the balances an assertion is compared against.
#[derive(SimpleObject, Debug, Clone)]
pub struct BalanceAssertionReport {
    /// How many `balance` directives were evaluated.
    pub evaluated: i32,
    /// How many of them held.
    pub passed: i32,
    /// How many of them did not.
    pub failed: i32,
    /// Whether every evaluated assertion held.
    pub ok: bool,
    /// The assertions that did not hold, with expected vs actual.
    pub failures: Vec<BalanceAssertionFailure>,
}

/// Result of the `verify` query — DAG integrity check.
#[derive(SimpleObject, Debug, Clone)]
pub struct VerifyResult {
    /// Structural integrity only: content hashes (I5), parent links (I8), and
    /// acyclicity. A failed balance assertion does **not** clear this flag —
    /// it is a writer's claim, not DAG corruption — so clients that care about
    /// assertions must also read `balanceAssertions`.
    pub ok: bool,
    pub nodes_checked: i32,
    pub errors: Vec<String>,
    /// Balance assertions evaluated during this verification (§3.6, M-08).
    pub balance_assertions: BalanceAssertionReport,
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

/// A currently-connected peer.
///
/// Carried an `heads: [TxId!]!` field until the 0902 informational finding:
/// nothing ever wrote a head into the registry behind it, so the field reported
/// an empty list on every healthy mesh and read as "this peer has no history".
/// Head exchange happens over the anti-entropy ALPN session, which never
/// touches the peer registry, so the field was removed rather than papered
/// over — a client that needs remote heads needs a resolver backed by that
/// exchange, not this one returning `[]`.
#[derive(SimpleObject, Debug, Clone)]
pub struct Peer {
    pub id: String,
}
