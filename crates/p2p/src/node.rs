//! P2P node — manages the Iroh endpoint, gossip subscription, and peer state.
//!
//! This module provides `PeerNode`, the high-level P2P service that:
//! - Creates/binds an Iroh endpoint
//! - Subscribes to the swarm topic via iroh-gossip
//! - Tracks which peers are currently connected
//! - Provides methods to broadcast and receive directives

use iroh::Endpoint;
use iroh_gossip::net::Gossip;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::allowlist::PeerAllowlist;
use crate::topic::derive_topic_id;

/// The ID of a peer (Iroh NodeId as hex string).
pub type PeerId = String;
/// Connected peer state.
///
/// Live-neighbor membership only. It used to carry an `advertised heads` list
/// as well, but the single writer — the gossip `NeighborUp` arm — never had
/// heads to put in it and always wrote an empty vector, so `all_remote_heads()`
/// and the GraphQL `Peer.heads` field it fed reported "no peer has any head" on
/// every healthy mesh (0902 informational). Heads are exchanged over the
/// anti-entropy ALPN session, which does not touch this registry; reporting
/// them here would mean recording that exchange, not restoring this field.
#[derive(Debug, Clone)]
pub struct PeerState {
    /// Peer's Iroh NodeId (hex).
    pub id: PeerId,
}

/// Shared peer registry — tracks which peers are currently connected.
#[derive(Debug, Clone, Default)]
pub struct PeerRegistry {
    peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or refresh a connected peer.
    pub fn upsert(&self, id: PeerId) {
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        peers.insert(id.clone(), PeerState { id });
    }

    /// Remove a peer.
    pub fn remove(&self, id: &str) {
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        peers.remove(id);
    }

    /// Get all connected peers.
    pub fn list(&self) -> Vec<PeerState> {
        let peers = self
            .peers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        peers.values().cloned().collect()
    }

    /// Number of connected peers.
    pub fn count(&self) -> usize {
        let peers = self
            .peers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        peers.len()
    }
}

/// Configuration for the P2P node.
///
/// A `bootstrap_peers: Vec<String>` field lived here until T41 and was read by
/// nothing: M-11 made anti-entropy select its targets from the [`PeerAllowlist`],
/// which is built from the very same `bootstrapEndpointIds`, so the field was a
/// second copy of the same list that no code consulted and no validation
/// covered. Pass the ids to [`PeerAllowlist::parse`] and hand the allowlist to
/// [`PeerNode::new`] — that is, and now visibly is, the only route in.
#[derive(Debug, Clone)]
pub struct PeerNodeConfig {
    /// The swarm topic string (default: "openledger/transactions").
    pub swarm_topic: String,
    /// Anti-entropy interval in milliseconds.
    ///
    /// `gl-node` refuses anything under 100 ms at config validation (L-22), but
    /// this struct is `pub` and a library caller reaches it without that check —
    /// so the consumer floors it defensively as well; see
    /// `gl_node::p2p_service::spawn_anti_entropy_loop`. Zero in particular is
    /// not merely fast: `tokio::time::interval(Duration::ZERO)` panics, and it
    /// panics inside the spawned replication task, where it kills replication
    /// without touching the process.
    pub anti_entropy_interval_ms: u64,
}

impl Default for PeerNodeConfig {
    fn default() -> Self {
        PeerNodeConfig {
            swarm_topic: crate::topic::DEFAULT_SWARM_TOPIC.to_owned(),
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
    /// Admission list for inbound `Supply` (C-4).
    allowlist: PeerAllowlist,
}

impl PeerNode {
    /// Create a new PeerNode with an already-bound endpoint.
    ///
    /// The caller is responsible for binding the endpoint (which may involve
    /// loading a persistent secret key for CAP-4 compliance) and for parsing
    /// the configured `bootstrapEndpointIds` into `allowlist`.
    pub fn new(
        endpoint: Endpoint,
        gossip: Gossip,
        config: PeerNodeConfig,
        allowlist: PeerAllowlist,
    ) -> Self {
        PeerNode {
            endpoint,
            gossip,
            registry: PeerRegistry::new(),
            config,
            allowlist,
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

    /// Admission list for inbound gossip `Supply`.
    pub fn allowlist(&self) -> &PeerAllowlist {
        &self.allowlist
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

        registry.upsert("peer-1".to_owned());
        assert_eq!(registry.count(), 1);

        registry.upsert("peer-2".to_owned());
        assert_eq!(registry.count(), 2);

        // Re-upserting an existing peer refreshes rather than duplicates.
        registry.upsert("peer-1".to_owned());
        assert_eq!(registry.count(), 2);

        let peers = registry.list();
        assert_eq!(peers.len(), 2);

        registry.remove("peer-1");
        assert_eq!(registry.count(), 1);
    }

    /// The registry tracks exactly one thing — membership — and says so.
    ///
    /// Pins what replaced `all_remote_heads()` (0902 informational): that
    /// method and the `PeerState.heads` field behind it could only ever return
    /// an empty set, because the one writer had no heads to record. What is
    /// left is the live-neighbor listing the GraphQL `peers` query actually
    /// needs.
    #[test]
    fn test_registry_tracks_membership_only() {
        let registry = PeerRegistry::new();
        registry.upsert("peer-1".to_owned());
        registry.upsert("peer-2".to_owned());

        let mut ids: Vec<String> = registry.list().into_iter().map(|peer| peer.id).collect();
        ids.sort();
        assert_eq!(ids, vec!["peer-1".to_owned(), "peer-2".to_owned()]);

        registry.remove("peer-2");
        assert_eq!(registry.count(), 1);
        assert_eq!(registry.list()[0].id, "peer-1");
    }

    #[test]
    fn test_default_config() {
        let config = PeerNodeConfig::default();
        assert_eq!(config.swarm_topic, "openledger/transactions");
        assert_eq!(config.anti_entropy_interval_ms, 5000);
    }
}
