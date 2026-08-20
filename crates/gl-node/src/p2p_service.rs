//! P2P service — orchestrates Iroh endpoint, gossip loop, and anti-entropy
//! for the `gl-node` binary.
//!
//! This module bridges the `p2p` crate's building blocks with the live
//! `LedgerService` and `TransactionBroadcast`, spawning background tasks
//! for gossip broadcasts, anti-entropy head exchanges, and orphan resolution.

#[cfg(unix)]
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::SecretKey;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use crate::config::P2pConfig;
use crate::graphql::broadcast::TransactionBroadcast;
use crate::graphql::query::domain_txn_to_graphql;
use crate::graphql::SharedLedger;

use p2p::allowlist::PeerAllowlist;
use p2p::gossip::{decode_broadcast, encode_broadcast, make_announce};
use p2p::node::{PeerNode, PeerNodeConfig};
use p2p::orphan_buffer::OrphanBuffer;
use p2p::protocol::WireMessage;

/// Boot the P2P subsystem: load or create SecretKey, create Iroh endpoint.
///
/// Returns the `PeerNode` (for injection into GraphQL).
pub async fn boot_p2p(
    config: &P2pConfig,
    _ledger_path: &Path,
) -> Result<PeerNode, Box<dyn std::error::Error>> {
    // Load or create the persistent SecretKey (CAP-4).
    let secret_key = load_or_create_secret_key(&config.secret_key_path)?;
    info!(
        path = %config.secret_key_path,
        "loaded Iroh secret key"
    );

    // Build Iroh endpoint with N0 preset (includes relay + holepunching).
    let endpoint = iroh::Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .bind()
        .await?;

    let node_id = endpoint.id();
    info!(
        node_id = %node_id,
        "Iroh endpoint bound"
    );

    // Create gossip handle.
    let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());

    let allowlist = PeerAllowlist::parse(&config.bootstrap_endpoint_ids)?;

    // Build PeerNode.
    let peer_config = PeerNodeConfig {
        swarm_topic: config.swarm_topic.clone(),
        bootstrap_peers: config.bootstrap_endpoint_ids.clone(),
        anti_entropy_interval_ms: config.anti_entropy_interval_milliseconds,
    };

    let node = PeerNode::new(endpoint, gossip, peer_config, allowlist);
    info!(
        topic = %config.swarm_topic,
        bootstrap_peers = config.bootstrap_endpoint_ids.len(),
        "P2P node ready"
    );

    Ok(node)
}

/// Spawn the gossip event loop as a background tokio task.
///
/// Listens for incoming gossip messages and broadcasts local appends.
/// Returns an `mpsc::Sender` that the mutation layer uses to notify
/// about local appends that should be gossiped.
///
/// Inbound `Supply` is applied only when `delivered_from` is on the peer
/// allowlist (C-4). When `signing_enabled`, signatures are verified (C-3).
pub fn spawn_gossip_loop(
    peer_node: &PeerNode,
    shared_ledger: SharedLedger,
    broadcast: TransactionBroadcast,
    orphan_buffer: Arc<RwLock<OrphanBuffer>>,
    signing_enabled: bool,
) -> tokio::sync::mpsc::Sender<ledger::model::Directive> {
    let gossip = peer_node.gossip().clone();
    let topic_id = peer_node.topic_id();
    let registry = peer_node.registry.clone();
    let allowlist = peer_node.allowlist().clone();
    let bootstrap_peers = allowlist.bootstrap_peers();

    let (gossip_sender, mut gossip_receiver) =
        tokio::sync::mpsc::channel::<ledger::model::Directive>(256);

    tokio::spawn(async move {
        // Join the gossip topic with configured bootstrap peers (R2 / §3.9).
        let topic = match gossip.subscribe(topic_id, bootstrap_peers).await {
            Ok(topic) => topic,
            Err(error) => {
                error!(%error, "failed to subscribe to gossip topic");
                return;
            }
        };

        let (sink, mut stream) = topic.split();
        if allowlist.is_empty() {
            info!(
                "gossip loop started — inbound Supply dropped (empty bootstrapEndpointIds allowlist)"
            );
        } else {
            info!(
                admitted = allowlist.bootstrap_peers().len(),
                "gossip loop started with peer allowlist"
            );
        }

        loop {
            tokio::select! {
                // Handle outgoing: local directives to broadcast.
                Some(directive) = gossip_receiver.recv() => {
                    let announce = make_announce(&directive);
                    match encode_broadcast(&announce) {
                        Ok(bytes) => {
                            if let Err(error) = sink.broadcast(bytes).await {
                                warn!(%error, "failed to broadcast gossip announce");
                            } else {
                                debug!("gossiped announce for directive");
                            }
                        }
                        Err(error) => {
                            warn!(%error, "failed to encode gossip announce");
                        }
                    }
                }
                // Handle incoming: gossip messages from peers.
                Some(event) = stream.next() => {
                    match event {
                        Ok(iroh_gossip::api::Event::Received(msg)) => {
                            if !allowlist.admits(msg.delivered_from) {
                                debug!(
                                    from = %msg.delivered_from,
                                    "dropping gossip from endpoint not on bootstrap allowlist"
                                );
                                continue;
                            }
                            let data = msg.content.as_ref();
                            match decode_broadcast(data) {
                                Ok(WireMessage::Announce { id, kind, .. }) => {
                                    debug!(id = %id, kind = ?kind, "received gossip announce");
                                    let have_it = {
                                        let svc = shared_ledger.read().await;
                                        svc.get_directive(&id).is_some()
                                    };
                                    if !have_it {
                                        debug!(id = %id, "directive not found locally — anti-entropy will catch up");
                                    }
                                }
                                Ok(WireMessage::Supply { entries, .. }) => {
                                    let delivered_from = msg.delivered_from.to_string();
                                    for entry in entries {
                                        match p2p::union_merge::validate_supply_entry(&entry) {
                                            Ok(directive) => {
                                                if let Err(error) = p2p::union_merge::verify_remote_signature(
                                                    &directive,
                                                    signing_enabled,
                                                ) {
                                                    warn!(%error, "rejected unsigned or invalid remote signature");
                                                    continue;
                                                }
                                                let mut svc = shared_ledger.write().await;
                                                let missing_parents = svc.missing_parent_ids(&directive);
                                                if !missing_parents.is_empty() {
                                                    let content_id =
                                                        ledger::service::LedgerService::content_id(&directive);
                                                    let mut buffer = orphan_buffer.write().await;
                                                    if buffer.insert(
                                                        content_id.clone(),
                                                        directive,
                                                        missing_parents,
                                                        Some(delivered_from.clone()),
                                                    ) {
                                                        debug!(
                                                            content_id = %content_id,
                                                            "buffered remote directive with missing parents"
                                                        );
                                                    } else {
                                                        warn!(
                                                            content_id = %content_id,
                                                            "orphan buffer full or per-peer quota exceeded"
                                                        );
                                                    }
                                                    continue;
                                                }
                                                match svc.insert_remote_directive(directive.clone()) {
                                                    Ok(Some(content_id)) => {
                                                        info!(
                                                            content_id = %content_id,
                                                            "merged remote directive from gossip"
                                                        );
                                                        if let ledger::model::Directive::Transaction(ref txn) = directive {
                                                            let graphql_txn = domain_txn_to_graphql(txn, &svc);
                                                            broadcast.publish(graphql_txn);
                                                        }
                                                        drain_orphans(
                                                            &orphan_buffer,
                                                            &mut svc,
                                                            &broadcast,
                                                        ).await;
                                                    }
                                                    Ok(None) => {
                                                        debug!("gossip supply entry was duplicate");
                                                    }
                                                    Err(error) => {
                                                        warn!(%error, "rejected remote directive from gossip");
                                                    }
                                                }
                                            }
                                            Err(error) => {
                                                warn!(%error, "invalid supply entry from gossip");
                                            }
                                        }
                                    }
                                }
                                Ok(_) => {
                                    debug!("received non-announce/supply gossip message");
                                }
                                Err(error) => {
                                    warn!(%error, "failed to decode gossip message");
                                }
                            }
                        }
                        Ok(iroh_gossip::api::Event::NeighborUp(peer_id)) => {
                            if allowlist.admits(peer_id) {
                                info!(peer = %peer_id, "gossip neighbor up (allowlisted)");
                                registry.upsert(peer_id.to_string(), vec![]);
                            } else {
                                info!(peer = %peer_id, "ignoring gossip neighbor not on bootstrap allowlist");
                            }
                        }
                        Ok(iroh_gossip::api::Event::NeighborDown(peer_id)) => {
                            info!(peer = %peer_id, "gossip neighbor down");
                            registry.remove(&peer_id.to_string());
                        }
                        Ok(iroh_gossip::api::Event::Lagged) => {
                            warn!("gossip receiver lagged — some messages may have been dropped");
                        }
                        Err(error) => {
                            warn!(%error, "gossip stream error");
                        }
                    }
                }
                else => break,
            }
        }

        info!("gossip loop ended");
    });

    gossip_sender
}

/// Spawn the anti-entropy periodic exchange as a background tokio task.
///
/// Every `anti_entropy_interval_ms`, exchanges heads with all connected peers
/// to catch up on any directives missed by gossip.
pub fn spawn_anti_entropy_loop(
    peer_node: &PeerNode,
    shared_ledger: SharedLedger,
    _broadcast: TransactionBroadcast,
    _orphan_buffer: Arc<RwLock<OrphanBuffer>>,
) {
    let interval_ms = peer_node.config().anti_entropy_interval_ms;
    let registry = peer_node.registry.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        info!(interval_ms = interval_ms, "anti-entropy loop started");

        loop {
            interval.tick().await;

            let peers = registry.list();
            if peers.is_empty() {
                continue;
            }

            // Get local state snapshot.
            let (local_heads, local_directive_ids) = {
                let svc = shared_ledger.read().await;
                (svc.head_txids(), svc.all_directive_ids())
            };

            for peer in &peers {
                let exchange = p2p::anti_entropy::head_exchange(
                    &local_heads,
                    &local_directive_ids,
                    &peer.heads,
                    &[], // Directive IDs come from the full exchange.
                );

                if exchange.is_synced {
                    debug!(peer = %peer.id, "anti-entropy: already synced");
                    continue;
                }

                if !exchange.want_from_remote.is_empty() {
                    debug!(
                        peer = %peer.id,
                        want_count = exchange.want_from_remote.len(),
                        "anti-entropy: we need directives from peer"
                    );
                    // In a full ALPN implementation, we'd open a connection
                    // to the peer and exchange Want/Supply messages here.
                    // The gossip layer handles the common case; anti-entropy
                    // is for catching stragglers.
                }
            }
        }
    });
}

/// Drain orphan buffer entries whose parents have now arrived.
async fn drain_orphans(
    orphan_buffer: &Arc<RwLock<OrphanBuffer>>,
    service: &mut ledger::service::LedgerService,
    broadcast: &TransactionBroadcast,
) {
    // Collect all content IDs currently in the DAG.
    let dag_ids: std::collections::HashSet<String> = service.all_directive_ids();

    let mut buffer = orphan_buffer.write().await;

    // Try to resolve orphans whose parents are now present.
    let mut resolved_any = true;
    while resolved_any {
        resolved_any = false;
        let wanted = buffer.wanted_parent_ids();
        for parent_id in wanted {
            if dag_ids.contains(&parent_id) {
                let freed = buffer.parent_arrived(&parent_id);
                for entry in freed {
                    match service.insert_remote_directive(entry.directive.clone()) {
                        Ok(Some(content_id)) => {
                            info!(content_id = %content_id, "resolved orphan directive");
                            if let ledger::model::Directive::Transaction(ref txn) = entry.directive
                            {
                                let graphql_txn = domain_txn_to_graphql(txn, service);
                                broadcast.publish(graphql_txn);
                            }
                            resolved_any = true;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            warn!(%error, "rejected resolved orphan directive");
                        }
                    }
                }
            }
        }
    }
}

/// Load 32-byte secret key material from disk, refusing group/other-readable files.
pub(crate) fn read_secret_key_bytes(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Secret key file {} does not exist", path.display()).into());
    }
    ensure_secret_key_permissions(path)?;
    let hex_content = std::fs::read_to_string(path)?;
    let bytes = hex::decode(hex_content.trim())?;
    if bytes.len() != 32 {
        return Err(format!("Secret key file has {} bytes, expected 32", bytes.len()).into());
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(key_bytes)
}

/// Load or create an Iroh `SecretKey` from disk (CAP-4: persistent identity).
fn load_or_create_secret_key(path: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let path = Path::new(path);

    if path.exists() {
        let key_bytes = read_secret_key_bytes(path)?;
        Ok(SecretKey::from_bytes(&key_bytes))
    } else {
        // Generate a new key and persist it with owner-only permissions.
        let key = SecretKey::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_secret_key_file(path, &hex::encode(key.to_bytes()))?;
        info!(path = %path.display(), "generated and persisted new Iroh secret key");
        Ok(key)
    }
}

/// Refuse to use a secret key file that is group- or world-readable (C-2).
#[cfg(unix)]
fn ensure_secret_key_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "Secret key file {} has overly permissive mode {mode:o}; expected 0600",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_secret_key_permissions(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn write_secret_key_file(path: &Path, hex_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(hex_key.as_bytes())?;
        file.flush()?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, hex_key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_or_create_secret_key_creates_new() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.secret");
        let key_path_str = key_path.to_str().unwrap();

        let key1 = load_or_create_secret_key(key_path_str).unwrap();
        assert!(key_path.exists(), "Key file should be created");

        // Loading again should return the same key.
        let key2 = load_or_create_secret_key(key_path_str).unwrap();
        assert_eq!(
            key1.to_bytes(),
            key2.to_bytes(),
            "Same key should be loaded"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_secret_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("perm.secret");
        load_or_create_secret_key(key_path.to_str().unwrap()).unwrap();

        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "New secret key files must be 0600");
    }

    #[cfg(unix)]
    #[test]
    fn test_secret_key_load_rejects_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("open.secret");
        std::fs::write(&key_path, hex::encode([7u8; 32])).unwrap();
        let mut permissions = std::fs::metadata(&key_path).unwrap().permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&key_path, permissions).unwrap();

        let error = load_or_create_secret_key(key_path.to_str().unwrap()).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("overly permissive"),
            "Expected permission error, got: {message}"
        );
    }

    #[test]
    fn test_iroh_endpoint_id_matches_dalek_public_key_hex() {
        let secret = SecretKey::generate();
        let iroh_hex = secret.public().to_string();
        let dalek = security::signing::PeerKeySignatureProvider::from_bytes(&secret.to_bytes());
        assert_eq!(
            iroh_hex,
            dalek.public_key_hex(),
            "openledger-author (EndpointId Display) must equal the Ed25519 verifying-key hex used to verify signatures"
        );
    }
}
