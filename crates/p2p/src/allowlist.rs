//! Peer admission for ALPN ledger writes (C-4 / §3.9).
//!
//! Inbound ledger bodies are accepted only from configured bootstrap
//! `EndpointId`s (QUIC remote) and only when `openledger-author` is also
//! on that list. An empty allowlist admits nobody — P2P can still bind an
//! identity, but remote `Supply` is refused.

use std::collections::HashSet;
use std::str::FromStr;

use iroh::EndpointId;

/// Parsed admission list for remote gossip writes.
#[derive(Debug, Clone, Default)]
pub struct PeerAllowlist {
    admitted: HashSet<EndpointId>,
}

impl PeerAllowlist {
    /// Parse bootstrap `EndpointId` strings (hex or base32).
    ///
    /// Empty input yields an empty allowlist (no remote `Supply` is admitted).
    pub fn parse(bootstrap_endpoint_ids: &[String]) -> Result<Self, String> {
        let mut admitted = HashSet::new();
        for raw in bootstrap_endpoint_ids {
            let endpoint_id = EndpointId::from_str(raw).map_err(|error| {
                format!("invalid p2p.bootstrapEndpointIds entry \"{raw}\": {error}")
            })?;
            admitted.insert(endpoint_id);
        }
        Ok(PeerAllowlist { admitted })
    }

    /// Bootstrap peers to pass to iroh-gossip `subscribe`.
    pub fn bootstrap_peers(&self) -> Vec<EndpointId> {
        self.admitted.iter().copied().collect()
    }

    /// Whether any peer is admitted.
    pub fn is_empty(&self) -> bool {
        self.admitted.is_empty()
    }

    /// True when `delivered_from` is a configured bootstrap peer.
    ///
    /// An empty allowlist admits nobody.
    pub fn admits(&self, delivered_from: EndpointId) -> bool {
        self.admitted.contains(&delivered_from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn endpoint_id_hex() -> String {
        SecretKey::generate().public().to_string()
    }

    #[test]
    fn test_empty_allowlist_admits_nobody() {
        let allowlist = PeerAllowlist::parse(&[]).unwrap();
        assert!(allowlist.is_empty());
        let stranger = SecretKey::generate().public();
        assert!(!allowlist.admits(stranger));
    }

    #[test]
    fn test_allowlist_admits_configured_peer_only() {
        let trusted = endpoint_id_hex();
        let trusted_ids = vec![trusted.clone()];
        let allowlist = PeerAllowlist::parse(&trusted_ids).unwrap();
        let trusted_id = EndpointId::from_str(&trusted).unwrap();
        let stranger = SecretKey::generate().public();
        assert!(allowlist.admits(trusted_id));
        assert!(!allowlist.admits(stranger));
        assert_eq!(allowlist.bootstrap_peers().len(), 1);
    }

    #[test]
    fn test_invalid_bootstrap_id_rejected() {
        let error = PeerAllowlist::parse(&["not-an-endpoint-id".to_owned()]).unwrap_err();
        assert!(error.contains("bootstrapEndpointIds"));
        assert!(error.contains("not-an-endpoint-id"));
    }
}
