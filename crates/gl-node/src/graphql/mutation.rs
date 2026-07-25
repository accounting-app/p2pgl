use async_graphql::{ErrorExtensions, Object, Result};

use super::inputs::TransactionInput;
use super::scalars::DateScalar;
use super::types::Transaction;

/// GraphQL mutation root. All mutations return errors until the ledger service
/// is wired in (M2+).
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Append a balanced journal entry (FR-1, enforces I1–I3).
    async fn append_transaction(&self, _input: TransactionInput) -> Result<Transaction> {
        Err(async_graphql::Error::new("Ledger service not yet initialized")
            .extend_with(|_, extensions| extensions.set("code", "INTERNAL")))
    }

    /// Open an account (FR-3 AC1).
    async fn open_account(
        &self,
        _name: String,
        _date: DateScalar,
        _currencies: Option<Vec<String>>,
    ) -> Result<bool> {
        Err(async_graphql::Error::new("Ledger service not yet initialized")
            .extend_with(|_, extensions| extensions.set("code", "INTERNAL")))
    }

    /// Close an account (FR-3 AC2).
    async fn close_account(&self, _name: String, _date: DateScalar) -> Result<bool> {
        Err(async_graphql::Error::new("Ledger service not yet initialized")
            .extend_with(|_, extensions| extensions.set("code", "INTERNAL")))
    }
}
