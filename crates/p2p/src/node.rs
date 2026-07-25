//! P2P node — manages the Iroh endpoint, gossip subscription, and peer state.
//!
//! This module provides `PeerNode`, the high-level P2P service that:
//! - Creates/binds an Iroh endpoint
//! - Subscribes to the swarm topic via iroh-gossip
//! - Tracks connected peers and their advertised heads
//! - Provides methods to broadcast and receive directives

use iroh::Endpoint;
use iroh_gossip::net::Gossip;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::topic::derive_topic_id;

/// The ID of a peer (Iroh NodeId as hex string).
pub type PeerId = String;

/// Connected peer state.
#[derive(Debug, Clone)]
pub struct PeerState {
    /// Peer's Iroh NodeId (hex).
    pub id: PeerId,
    /// The peer's advertised head txids.
    pub heads: Vec<String>,
}

/// Shared peer registry — tracks connected peers and their advertised heads.
#[derive(Debug, Clone, Default)]
pub struct PeerRegistry {
    peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or update a peer's state.
    pub fn upsert(&self, id: PeerId, heads: Vec<String>) {
        let mut peers = self.peers.write().unwrap();
        peers.insert(id.clone(), PeerState { id, heads });
    }

    /// Remove a peer.
    pub fn remove(&self, id: &str) {
        let mut peers = self.peers.write().unwrap();
        peers.remove(id);
    }

    /// Get all connected peers.
    pub fn list(&self) -> Vec<PeerState> {
        let peers = self.peers.read().unwrap();
        peers.values().cloned().collect()
    }

    /// Number of connected peers.
    pub fn count(&self) -> usize {
        let peers = self.peers.read().unwrap();
        peers.len()
    }

    /// Get all unique head txids across all peers.
    pub fn all_remote_heads(&self) -> HashSet<String> {
        let peers = self.peers.read().unwrap();
        peers
            .values()
            .flat_map(|p| p.heads.iter().cloned())
            .collect()
    }
}

/// Configuration for the P2P node.
#[derive(Debug, Clone)]
pub struct PeerNodeConfig {
    /// The swarm topic string (default: "openledger/transactions").
    pub swarm_topic: String,
    /// Bootstrap peer NodeIds to connect to.
    pub bootstrap_peers: Vec<String>,
    /// Anti-entropy interval in milliseconds.
    pub anti_entropy_interval_ms: u64,
}

impl Default for PeerNodeConfig {
    fn default() -> Self {
        PeerNodeConfig {
            swarm_topic: crate::topic::DEFAULT_SWARM_TOPIC.to_owned(),
            bootstrap_peers: Vec::new(),
            anti_entropy_interval_ms: 5000,
        }
    }
}

/// The P2P node — manages endpoint, gossip, and peer state.
///
/// This struct holds the Iroh endpoint and gossip handles. The actual
/// gossip event loop is run separately via `spawn_gossip_loop`.
pub struct PeerNode {
    /// The Iroh endpoint (owns the QUIC socket and node identity).
    endpoint: Endpoint,
    /// The iroh-gossip handle.
    gossip: Gossip,
    /// Connected peer registry.
    pub registry: PeerRegistry,
    /// Configuration.
    config: PeerNodeConfig,
}

impl PeerNode {
    /// Create a new PeerNode with an already-bound endpoint.
    ///
    /// The caller is responsible for binding the endpoint (which may involve
    /// loading a persistent secret key for CAP-4 compliance).
    pub fn new(endpoint: Endpoint, gossip: Gossip, config: PeerNodeConfig) -> Self {
        PeerNode {
            endpoint,
            gossip,
            registry: PeerRegistry::new(),
            config,
        }
    }

    /// The local node's EndpointId (for openledger-author stamping).
    pub fn node_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    /// The Iroh endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The gossip handle.
    pub fn gossip(&self) -> &Gossip {
        &self.gossip
    }

    /// The configuration.
    pub fn config(&self) -> &PeerNodeConfig {
        &self.config
    }

    /// The gossip TopicId for this node's swarm.
    pub fn topic_id(&self) -> iroh_gossip::TopicId {
        derive_topic_id(&self.config.swarm_topic)
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.registry.count()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_registry_crud() {
        let registry = PeerRegistry::new();
        assert_eq!(registry.count(), 0);

        registry.upsert("peer-1".to_owned(), vec!["tx1".to_owned()]);
        assert_eq!(registry.count(), 1);

        registry.upsert("peer-2".to_owned(), vec!["tx2".to_owned()]);
        assert_eq!(registry.count(), 2);

        // Update existing.
        registry.upsert(
            "peer-1".to_owned(),
            vec!["tx1".to_owned(), "tx3".to_owned()],
        );
        assert_eq!(registry.count(), 2);

        let peers = registry.list();
        assert_eq!(peers.len(), 2);

        registry.remove("peer-1");
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_all_remote_heads() {
        let registry = PeerRegistry::new();
        registry.upsert(
            "peer-1".to_owned(),
            vec!["tx1".to_owned(), "tx2".to_owned()],
        );
        registry.upsert(
            "peer-2".to_owned(),
            vec!["tx2".to_owned(), "tx3".to_owned()],
        );

        let heads = registry.all_remote_heads();
        assert_eq!(heads.len(), 3); // tx1, tx2, tx3 (deduped)
        assert!(heads.contains("tx1"));
        assert!(heads.contains("tx2"));
        assert!(heads.contains("tx3"));
    }

    #[test]
    fn test_default_config() {
        let config = PeerNodeConfig::default();
        assert_eq!(config.swarm_topic, "openledger/transactions");
        assert!(config.bootstrap_peers.is_empty());
        assert_eq!(config.anti_entropy_interval_ms, 5000);
    }
}
