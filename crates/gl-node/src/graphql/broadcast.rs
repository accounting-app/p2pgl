//! Transaction broadcast channel for GraphQL subscriptions.
//!
//! Provides a multi-producer, multi-consumer broadcast channel that the
//! LedgerService publishes to on every append (local, remote, adopted).
//! GraphQL subscription resolvers consume from this channel.

use std::sync::Arc;
use tokio::sync::broadcast;

use super::types::Transaction;

/// Default broadcast channel capacity.
const BROADCAST_CAPACITY: usize = 1024;

/// The transaction broadcast — shared between the write path and subscription resolvers.
#[derive(Clone)]
pub struct TransactionBroadcast {
    sender: Arc<broadcast::Sender<Transaction>>,
}

impl TransactionBroadcast {
    /// Create a new broadcast channel.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CAPACITY);
        TransactionBroadcast {
            sender: Arc::new(sender),
        }
    }

    /// Create with a custom capacity.
    #[allow(dead_code)]
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        TransactionBroadcast {
            sender: Arc::new(sender),
        }
    }

    /// Publish a transaction to all subscribers.
    ///
    /// Returns the number of active subscribers that received the message.
    /// Returns 0 if no subscribers are active (not an error).
    pub fn publish(&self, txn: Transaction) -> usize {
        self.sender.send(txn).unwrap_or(0)
    }

    /// Subscribe to transaction events. Returns a receiver stream.
    pub fn subscribe(&self) -> broadcast::Receiver<Transaction> {
        self.sender.subscribe()
    }

    /// Number of active subscribers.
    #[allow(dead_code)]
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for TransactionBroadcast {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql::scalars::{DateScalar, DecimalScalar, TransactionId};
    use chrono::NaiveDate;
    use rust_decimal::Decimal;

    fn make_test_txn() -> Transaction {
        Transaction {
            txid: TransactionId("test123".to_owned()),
            date: DateScalar(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap()),
            flag: "*".to_owned(),
            payee: Some("Test".to_owned()),
            narration: Some("Broadcast test".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![],
            author: "local".to_owned(),
            signature: None,
            parents: vec![],
        }
    }

    #[tokio::test]
    async fn test_broadcast_publish_subscribe() {
        let broadcast = TransactionBroadcast::new();
        let mut rx = broadcast.subscribe();

        assert_eq!(broadcast.subscriber_count(), 1);

        let txn = make_test_txn();
        let count = broadcast.publish(txn.clone());
        assert_eq!(count, 1);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.txid.0, "test123");
    }

    #[tokio::test]
    async fn test_broadcast_multiple_subscribers() {
        let broadcast = TransactionBroadcast::new();
        let mut rx1 = broadcast.subscribe();
        let mut rx2 = broadcast.subscribe();

        assert_eq!(broadcast.subscriber_count(), 2);

        broadcast.publish(make_test_txn());

        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.txid.0, r2.txid.0);
    }

    #[test]
    fn test_broadcast_no_subscribers() {
        let broadcast = TransactionBroadcast::new();
        let count = broadcast.publish(make_test_txn());
        assert_eq!(count, 0, "No subscribers → 0 deliveries (not an error)");
    }

    #[tokio::test]
    async fn test_broadcast_subscriber_dropped() {
        let broadcast = TransactionBroadcast::new();
        let rx = broadcast.subscribe();
        assert_eq!(broadcast.subscriber_count(), 1);

        drop(rx);
        assert_eq!(broadcast.subscriber_count(), 0);
    }
}
