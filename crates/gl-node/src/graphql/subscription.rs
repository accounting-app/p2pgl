use async_graphql::Subscription;
use tokio_stream::Stream;

use super::types::Transaction;

/// GraphQL subscription root. Fires for all appends: local, remote, and adopted.
/// Stub: returns a pending stream until M5 wires in the real broadcast.
pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Notified whenever a transaction is appended to the ledger.
    async fn transaction_appended(&self) -> impl Stream<Item = Transaction> {
        tokio_stream::pending::<Transaction>()
    }
}
