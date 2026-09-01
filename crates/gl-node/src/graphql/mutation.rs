use async_graphql::{Context, ErrorExtensions, Object, Result};
use std::sync::Arc;

use super::broadcast::TransactionBroadcast;
use super::inputs;
use super::query::domain_txn_to_graphql;
use super::scalars::DateScalar;
use super::types::Transaction;
use super::{GossipSender, SharedLedger};

use ledger::model::{Amount, CostSpec, Flag, PriceSpec};
use ledger::service::{PostingInput, ServiceError, TransactionInput};
use security::signing::{SignableMessage, SignatureProvider};

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
            "*" => Flag::Complete,
            "!" => Flag::Incomplete,
            other => {
                return Err(async_graphql::Error::new(format!(
                    "flag must be \"*\" or \"!\", got \"{other}\""
                ))
                .extend_with(|_, ext| ext.set("code", "INVALID_FLAG")));
            }
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
        let signer = ctx.data::<Arc<dyn SignatureProvider>>().ok().cloned();
        let content_id = svc
            .append_transaction_signing(domain_input, |id, parents, lamport| {
                signer.as_ref().and_then(|provider| {
                    provider.sign(&SignableMessage {
                        content_id: id,
                        is_transaction: true,
                        parents,
                        lamport,
                    })
                })
            })
            .map_err(service_error_to_graphql)?;

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

        let to_gossip = svc.get_directive(&content_id).cloned();
        drop(svc);
        if let (Some(directive), Ok(sender)) = (to_gossip, ctx.data::<GossipSender>()) {
            let _ = sender.send(directive).await;
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
        let signer = ctx.data::<Arc<dyn SignatureProvider>>().ok().cloned();
        let _content_id = svc
            .open_account_signing(
                name,
                date.0,
                currencies.unwrap_or_default(),
                |id, parents, lamport| {
                    signer.as_ref().and_then(|provider| {
                        provider.sign(&SignableMessage {
                            content_id: id,
                            is_transaction: false,
                            parents,
                            lamport,
                        })
                    })
                },
            )
            .map_err(service_error_to_graphql)?;

        gossip_if_present(ctx, &svc, &_content_id).await;
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
        let signer = ctx.data::<Arc<dyn SignatureProvider>>().ok().cloned();
        let _content_id = svc
            .close_account_signing(name, date.0, |id, parents, lamport| {
                signer.as_ref().and_then(|provider| {
                    provider.sign(&SignableMessage {
                        content_id: id,
                        is_transaction: false,
                        parents,
                        lamport,
                    })
                })
            })
            .map_err(service_error_to_graphql)?;

        gossip_if_present(ctx, &svc, &_content_id).await;
        Ok(true)
    }
}

/// Convert a `ServiceError` into a client-facing GraphQL error.
///
/// `Io` errors can embed filesystem paths and OS details (L3), so they are
/// collapsed to a generic message and the underlying error is logged
/// server-side only. Other variants carry no sensitive data and are surfaced
/// as-is to help API callers correct their request. The machine-readable `code`
/// is preserved in every case.
fn service_error_to_graphql(error: ServiceError) -> async_graphql::Error {
    let code = error.error_code();
    let message = match &error {
        ServiceError::Io(io_error) => {
            tracing::error!(%io_error, "ledger I/O error serving mutation");
            "internal storage error".to_owned()
        }
        _ => error.to_string(),
    };
    async_graphql::Error::new(message).extend_with(|_, ext| ext.set("code", code))
}

async fn gossip_if_present(
    ctx: &Context<'_>,
    svc: &ledger::service::LedgerService,
    content_id: &str,
) {
    let Some(directive) = svc.get_directive(content_id).cloned() else {
        return;
    };
    if let Ok(sender) = ctx.data::<GossipSender>() {
        let _ = sender.send(directive).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_io_error_message_is_generic_and_hides_path() {
        // L3 regression: an I/O error must not surface the on-disk path to the
        // GraphQL caller.
        let secret_path = "/srv/private/ledger.bean.tmp";
        let error = ServiceError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{secret_path}: permission denied"),
        ));
        let gql = service_error_to_graphql(error);
        assert_eq!(gql.message, "internal storage error");
        assert!(
            !gql.message.contains(secret_path),
            "GraphQL error must not leak the filesystem path"
        );
    }

    #[test]
    fn test_non_io_error_message_is_preserved() {
        // Non-I/O errors carry no sensitive data and stay actionable for callers.
        let error = ServiceError::InvalidInput {
            message: "both cost and price on posting".to_owned(),
        };
        let gql = service_error_to_graphql(error);
        assert_eq!(gql.message, "both cost and price on posting");
    }
}
