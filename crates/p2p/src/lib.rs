// P2P crate — gossip, anti-entropy, wire protocol, union merge, peer management.
//
// Implements §3.4 (consistency & replication), §3.4.1 (wire protocol),
// §3.4.4 (orphan buffer), and §3.5 (remote insert validation).

pub mod anti_entropy;
pub mod gossip;
pub mod node;
pub mod orphan_buffer;
pub mod protocol;
pub mod topic;
pub mod union_merge;
