use async_graphql::InputObject;

use super::scalars::{DateScalar, DecimalScalar};

/// Input for a monetary amount.
#[derive(InputObject, Debug, Clone)]
pub struct AmountInput {
    pub number: DecimalScalar,
    pub currency: String,
}

/// Input for a single posting line.
///
/// Exactly one posting per transaction may omit `amount` (I2 — elided posting).
#[derive(InputObject, Debug, Clone)]
pub struct PostingInput {
    pub account: String,
    pub amount: Option<AmountInput>,
    pub cost: Option<AmountInput>,
    pub price: Option<AmountInput>,
}

/// Input for creating a new journal entry (FR-1).
#[derive(InputObject, Debug, Clone)]
pub struct TransactionInput {
    pub date: DateScalar,
    /// `"*"` (complete) or `"!"` (incomplete). Defaults to `"*"`.
    #[graphql(default_with = "String::from(\"*\")")]
    pub flag: String,
    pub payee: Option<String>,
    pub narration: Option<String>,
    #[graphql(default)]
    pub tags: Vec<String>,
    #[graphql(default)]
    pub links: Vec<String>,
    /// At least 2 postings; exactly one may omit `amount` (I2).
    pub postings: Vec<PostingInput>,
}
