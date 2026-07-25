//! TopicId derivation (§3.4.3).
//!
//! ```text
//! topic_preimage = UTF-8( p2p.swarmTopic )   # default "openledger/transactions"
//! TopicId        = first 32 bytes of SHA-256( topic_preimage )
//! ```

use iroh_gossip::TopicId;
use sha2::{Digest, Sha256};

/// Default swarm topic string (§3.4.3).
pub const DEFAULT_SWARM_TOPIC: &str = "openledger/transactions";

/// Derive an iroh-gossip `TopicId` from a swarm topic string.
///
/// Uses the first 32 bytes of SHA-256 of the UTF-8 topic string.
pub fn derive_topic_id(swarm_topic: &str) -> TopicId {
    let hash = Sha256::digest(swarm_topic.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    TopicId::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_topic_id_stable() {
        let t1 = derive_topic_id(DEFAULT_SWARM_TOPIC);
        let t2 = derive_topic_id(DEFAULT_SWARM_TOPIC);
        assert_eq!(t1, t2, "Same input → same TopicId");
    }

    #[test]
    fn test_different_topics_differ() {
        let t1 = derive_topic_id("openledger/transactions");
        let t2 = derive_topic_id("openledger/other");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_topic_id_is_32_bytes() {
        let topic = derive_topic_id(DEFAULT_SWARM_TOPIC);
        // TopicId is 32 bytes — accessing its bytes confirms the size.
        let bytes = topic.as_bytes();
        assert_eq!(bytes.len(), 32);
    }
}
