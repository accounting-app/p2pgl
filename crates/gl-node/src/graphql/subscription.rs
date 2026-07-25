use async_graphql::{Context, Subscription};
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};

use super::broadcast::TransactionBroadcast;
use super::types::Transaction;

/// GraphQL subscription root. Fires for all appends: local, remote, and adopted.
pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Notified whenever a transaction is appended to the ledger.
    ///
    /// Publishes for local writes, remote gossip inserts, and adopted file-watcher entries.
    async fn transaction_appended(
        &self,
        ctx: &Context<'_>,
    ) -> impl Stream<Item = Transaction> {
        let broadcast = ctx.data_unchecked::<TransactionBroadcast>();
        let rx = broadcast.subscribe();
        BroadcastStream::new(rx).filter_map(|result| result.ok())
    }
}
