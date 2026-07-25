use async_graphql::{Context, ErrorExtensions, Object, Result};

use super::broadcast::TransactionBroadcast;
use super::inputs;
use super::query::domain_txn_to_graphql;
use super::scalars::DateScalar;
use super::types::Transaction;
use super::SharedLedger;

use ledger::model::{Amount, CostSpec, Flag, PriceSpec};
use ledger::service::{PostingInput, TransactionInput};

/// GraphQL mutation root. All mutations acquire a write lock on `SharedLedger`.
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Append a balanced journal entry (FR-1, enforces I1–I3).
    async fn append_transaction(
        &self,
        ctx: &Context<'_>,
        input: inputs::TransactionInput,
    ) -> Result<Transaction> {
        let ledger = ctx.data::<SharedLedger>().map_err(|_| {
            async_graphql::Error::new("Ledger service not initialized")
                .extend_with(|_, ext| ext.set("code", "INTERNAL"))
        })?;

        let flag = match input.flag.as_str() {
            "!" => Flag::Incomplete,
            _ => Flag::Complete,
        };

        let domain_input = TransactionInput {
            date: input.date.0,
            flag,
            payee: input.payee,
            narration: input.narration,
            tags: input.tags,
            links: input.links,
            postings: input
                .postings
                .into_iter()
                .map(|p| PostingInput {
                    account: p.account,
                    amount: p.amount.map(|a| Amount {
                        number: a.number.0,
                        currency: a.currency,
                    }),
                    cost: p.cost.map(|c| CostSpec {
                        amount: Some(Amount {
                            number: c.number.0,
                            currency: c.currency,
                        }),
                        date: None,
                    }),
                    price: p.price.map(|pr| {
                        PriceSpec::Unit(Amount {
                            number: pr.number.0,
                            currency: pr.currency,
                        })
                    }),
                })
                .collect(),
        };

        let mut svc = ledger.write().await;
        let content_id = svc.append_transaction(domain_input).map_err(|e| {
            async_graphql::Error::new(e.to_string())
                .extend_with(|_, ext| ext.set("code", e.error_code()))
        })?;

        // Look up the just-inserted transaction to return it.
        let txn = svc
            .get_directive(&content_id)
            .and_then(|d| {
                if let ledger::model::Directive::Transaction(t) = d {
                    Some(domain_txn_to_graphql(t, &svc))
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                async_graphql::Error::new("Transaction inserted but not found")
                    .extend_with(|_, ext| ext.set("code", "INTERNAL"))
            })?;

        // Publish to subscribers (local + remote appends).
        if let Ok(broadcast) = ctx.data::<TransactionBroadcast>() {
            broadcast.publish(txn.clone());
        }

        Ok(txn)
    }

    /// Open an account (FR-3 AC1).
    async fn open_account(
        &self,
        ctx: &Context<'_>,
        name: String,
        date: DateScalar,
        currencies: Option<Vec<String>>,
    ) -> Result<bool> {
        let ledger = ctx.data::<SharedLedger>().map_err(|_| {
            async_graphql::Error::new("Ledger service not initialized")
                .extend_with(|_, ext| ext.set("code", "INTERNAL"))
        })?;

        let mut svc = ledger.write().await;
        svc.open_account(name, date.0, currencies.unwrap_or_default())
            .map_err(|e| {
                async_graphql::Error::new(e.to_string())
                    .extend_with(|_, ext| ext.set("code", e.error_code()))
            })?;

        Ok(true)
    }

    /// Close an account (FR-3 AC2).
    async fn close_account(
        &self,
        ctx: &Context<'_>,
        name: String,
        date: DateScalar,
    ) -> Result<bool> {
        let ledger = ctx.data::<SharedLedger>().map_err(|_| {
            async_graphql::Error::new("Ledger service not initialized")
                .extend_with(|_, ext| ext.set("code", "INTERNAL"))
        })?;

        let mut svc = ledger.write().await;
        svc.close_account(name, date.0).map_err(|e| {
            async_graphql::Error::new(e.to_string())
                .extend_with(|_, ext| ext.set("code", e.error_code()))
        })?;

        Ok(true)
    }
}
