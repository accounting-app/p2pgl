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
use iroh::protocol::Router;
use iroh::SecretKey;
use iroh_gossip::net::GOSSIP_ALPN;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use crate::anti_entropy_alpn::{exchange_with_peer, fetch_want, AntiEntropyHandler};
use crate::config::P2pConfig;
use crate::fetch_coordinator::FetchCoordinator;

use p2p::allowlist::PeerAllowlist;
use p2p::gossip::{decode_broadcast, encode_broadcast, make_announce};
use p2p::node::{PeerNode, PeerNodeConfig};
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

    let builder = match config.relay_mode.as_str() {
        "n0" => {
            warn!("p2p.relayMode is n0 — endpoint uses public Iroh relays and discovery");
            iroh::Endpoint::builder(presets::N0)
        }
        "disabled" => {
            info!("p2p.relayMode is disabled — direct addresses only");
            iroh::Endpoint::builder(presets::Minimal)
        }
        other => {
            return Err(
                format!("p2p.relayMode must be \"n0\" or \"disabled\", got \"{other}\"").into(),
            );
        }
    };
    let endpoint = builder.secret_key(secret_key).bind().await?;

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

/// Route gossip and anti-entropy ALPNs. The returned `Router` must be kept alive.
pub fn spawn_router(peer_node: &PeerNode, handler: AntiEntropyHandler) -> Router {
    Router::builder(peer_node.endpoint().clone())
        .accept(GOSSIP_ALPN, peer_node.gossip().clone())
        .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler)
        .spawn()
}

/// Spawn the gossip event loop as a background tokio task.
///
/// Listens for incoming gossip messages and broadcasts local appends.
/// Returns an `mpsc::Sender` that the mutation layer uses to notify
/// about local appends that should be gossiped.
///
/// Inbound gossip is Announce-only. `Supply` bodies are fetched over ALPN
/// from an allowlisted peer (C-4). When `signing_enabled`, signatures are
/// verified on the ALPN path (C-3 / H-14).
pub fn spawn_gossip_loop(
    peer_node: &PeerNode,
    handler: AntiEntropyHandler,
) -> tokio::sync::mpsc::Sender<ledger::model::Directive> {
    let gossip = peer_node.gossip().clone();
    let topic_id = peer_node.topic_id();
    let registry = peer_node.registry.clone();
    let allowlist = peer_node.allowlist().clone();
    let bootstrap_peers = allowlist.bootstrap_peers();
    let endpoint = peer_node.endpoint().clone();

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
            info!("gossip loop started — Announce only; ALPN Supply requires bootstrapEndpointIds");
        } else {
            info!(
                admitted = allowlist.bootstrap_peers().len(),
                "gossip loop started (Announce only; bodies over ALPN)"
            );
        }

        // Bounds the fetches that untrusted gossip announces can trigger
        // (M-07 / M-12): concurrency cap, in-flight dedup, and a negative cache
        // for ids that fail or are not yet available. Anti-entropy remains the
        // correctness backstop, so a dropped hint never loses data.
        let coordinator = Arc::new(FetchCoordinator::with_defaults());

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
                            // `delivered_from` is the peer that RELAYED this
                            // message to us (the last hop), NOT its origin
                            // (M-12): plumtree forwards every first-seen message
                            // to neighbors, so a relayed announce carries an
                            // allowlisted relay's id regardless of who authored
                            // it. `admits(relay)` is therefore only a cheap
                            // first-hop filter against DIRECT strangers — it is
                            // NOT origin authentication. Gossip content is an
                            // untrusted hint; the real security boundary is the
                            // ALPN fetch path (author-allowlist + signature),
                            // which is unchanged. Below we merely bound the work
                            // any hint can trigger (M-07).
                            let relay = msg.delivered_from;
                            if !allowlist.admits(relay) {
                                debug!(
                                    relay = %relay,
                                    "dropping gossip relayed by endpoint not on bootstrap allowlist"
                                );
                                continue;
                            }
                            let data = msg.content.as_ref();
                            match decode_broadcast(data) {
                                Ok(WireMessage::Announce { id, kind, .. }) => {
                                    debug!(id = %id, kind = ?kind, "received gossip announce");
                                    let have_it = {
                                        let svc = handler.ledger.read().await;
                                        svc.get_directive(&id).is_some()
                                    };
                                    if !have_it {
                                        // Untrusted hint: bound the fetch it
                                        // triggers (M-07). Drop the hint if the
                                        // id is in flight, recently failed, or
                                        // the concurrency cap is saturated.
                                        let Some(mut guard) = coordinator.try_begin(&id) else {
                                            debug!(id = %id, "skipping announce fetch: in-flight, recently failed, or fetch limit reached (M-07)");
                                            continue;
                                        };
                                        let endpoint = endpoint.clone();
                                        let handler = handler.clone();
                                        let fetch_id = id.clone();
                                        // `relay` is the EndpointId we fetch
                                        // from; it is `Copy`, so the `move`
                                        // block copies it in.
                                        tokio::spawn(async move {
                                            fetch_want(&endpoint, relay, vec![fetch_id.clone()], &handler).await;
                                            // Success = we actually have it now;
                                            // otherwise the guard's Drop
                                            // negative-caches the id so a
                                            // re-announce flood cannot re-trigger
                                            // a fetch every round.
                                            if handler.ledger.read().await.get_directive(&fetch_id).is_some() {
                                                guard.mark_succeeded();
                                            }
                                            drop(guard);
                                        });
                                    }
                                }
                                Ok(WireMessage::Supply { .. }) => {
                                    warn!(
                                        relay = %relay,
                                        "ignoring gossip Supply; ledger writes are ALPN-only"
                                    );
                                }
                                Ok(_) => {
                                    debug!("received non-announce gossip message");
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
/// Every `anti_entropy_interval_ms`, opens an ALPN session with each
/// configured bootstrap peer and pulls missing directives.
pub fn spawn_anti_entropy_loop(peer_node: &PeerNode, handler: AntiEntropyHandler) {
    let interval_ms = peer_node.config().anti_entropy_interval_ms;
    let endpoint = peer_node.endpoint().clone();
    let allowlist = peer_node.allowlist().clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        info!(interval_ms = interval_ms, "anti-entropy loop started");

        loop {
            interval.tick().await;

            // Targets come from the ALLOWLIST, not from the live peer registry
            // (M-11). The registry is filled exclusively by allowlist-gated
            // gossip `NeighborUp` events and drained by `NeighborDown`, but
            // gossip overlay membership is open: anyone holding the swarm-topic
            // string plus one member id can join the topic and occupy a node's
            // neighbor slots. An eclipsed node therefore had an EMPTY registry,
            // the `is_empty()` guard skipped every tick, and replication stopped
            // silently and permanently — with no peer left to pull from, nothing
            // could ever repopulate the registry either.
            //
            // The registry is now irrelevant for target selection, because the
            // union it was meant to contribute to is redundant: `NeighborUp` only
            // ever inserts admitted peers, so registry ⊆ allowlist, and
            // `bootstrap_peers()` returns the ENTIRE admitted set (the allowlist
            // IS the configured `bootstrapEndpointIds`). "Live neighbors ∪
            // bootstrap ids" is therefore just the allowlist, so iterating it
            // directly is a superset of the old behaviour and cannot be starved
            // by overlay membership. It also removes the parse and `admits`
            // re-check below: these are already-parsed, already-admitted
            // `EndpointId`s. The registry itself stays — the GraphQL peer
            // listing reads it as live-neighbor state.
            //
            // Cost when a bootstrap peer is offline: one connect attempt per
            // tick, bounded by the T24 connect timeout (10s default), run
            // concurrently in the `JoinSet` below and drained before the next
            // tick — so an unreachable peer cannot make ticks pile up.
            let targets = allowlist.bootstrap_peers();
            if targets.is_empty() {
                // No bootstrap peers configured: nothing to sync with.
                continue;
            }

            // Run every peer's exchange concurrently (M-06): a peer that accepts
            // a connection and then stalls must not block replication with the
            // healthy peers, as it did when this loop awaited each exchange
            // inline. Each spawned exchange is itself bounded by the connect and
            // I/O timeouts on the handler, so the drain below cannot hang.
            let mut set = tokio::task::JoinSet::new();
            for peer_id in targets {
                let endpoint = endpoint.clone();
                let handler = handler.clone();
                set.spawn(async move {
                    exchange_with_peer(&endpoint, peer_id, &handler).await;
                });
            }

            // Drain this tick's exchanges before the next tick so ticks do not
            // pile up. Bounded by the per-exchange timeouts above (M-06).
            while set.join_next().await.is_some() {}
        }
    });
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

    use iroh::address_lookup::memory::MemoryLookup;
    use tokio::sync::RwLock;

    use crate::anti_entropy_alpn::tests::{
        bind_direct_endpoint, make_handler, make_handler_with_timeouts, wait_until_dialable,
        write_open_directive_ledger, NET_TEST_LOCK,
    };
    use crate::anti_entropy_alpn::AntiEntropyTimeouts;
    use crate::graphql::SharedLedger;

    /// M-11: an ECLIPSED node — zero gossip neighbors, empty peer registry —
    /// must still replicate from its configured `bootstrapEndpointIds`.
    ///
    /// This drives the real `spawn_anti_entropy_loop`. The client never joins a
    /// gossip topic, so no `NeighborUp` ever fires and `registry` stays empty
    /// for the whole test — exactly the state Sybil neighbors produce when they
    /// occupy every gossip slot. Before the fix the loop's `peers.is_empty()`
    /// guard skipped every tick here and the client never converged.
    ///
    /// The client endpoint carries a `MemoryLookup` address lookup pre-loaded
    /// with the server's `EndpointAddr`, so the loop's bare-`EndpointId` dial
    /// resolves without a relay or a discovery service (direct-only, like the
    /// rest of the network tests).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn eclipsed_node_still_syncs_from_bootstrap_peers() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_server = bind_direct_endpoint().await;
        let server_id = endpoint_server.id();

        let address_lookup = MemoryLookup::new();
        let endpoint_client = iroh::Endpoint::builder(presets::Minimal)
            .alpns(vec![p2p::protocol::ANTI_ENTROPY_ALPN.to_vec()])
            .address_lookup(address_lookup.clone())
            .bind()
            .await
            .expect("bind client endpoint with memory address lookup");
        let client_id = endpoint_client.id();

        let allow_server =
            PeerAllowlist::parse(&[client_id.to_string()]).expect("server allowlist");
        let allow_client =
            PeerAllowlist::parse(&[server_id.to_string()]).expect("client allowlist");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let server_path = temp_dir.path().join("server.bean");
        write_open_directive_ledger(&server_path, 5, &server_id.to_string());

        let ledger_server: SharedLedger = Arc::new(RwLock::new(
            ledger::service::LedgerService::boot(server_path, server_id.to_string())
                .expect("boot server ledger"),
        ));
        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            ledger::service::LedgerService::boot(
                temp_dir.path().join("client.bean"),
                client_id.to_string(),
            )
            .expect("boot client ledger"),
        ));

        let source_count = ledger_server.read().await.directive_count();
        assert_eq!(source_count, 5, "server ledger boot count");
        assert_eq!(
            ledger_client.read().await.directive_count(),
            0,
            "client starts empty"
        );

        let handler_server = make_handler(ledger_server.clone(), allow_server);
        // Short timeouts so a dial that cannot resolve fails fast and the next
        // tick retries, instead of parking the test behind the 10s default.
        let handler_client = make_handler_with_timeouts(
            ledger_client.clone(),
            allow_client.clone(),
            AntiEntropyTimeouts {
                connect: Duration::from_secs(2),
                io: Duration::from_secs(5),
            },
        );

        let router_server = Router::builder(endpoint_server.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_server)
            .spawn();

        wait_until_dialable(&endpoint_server).await;
        wait_until_dialable(&endpoint_client).await;

        // Teach the client where the server lives. The loop itself only ever
        // holds the bare `EndpointId` from the allowlist.
        address_lookup.add_endpoint_info(endpoint_server.addr());

        // A gossip handle that never subscribes to anything: no topic, no
        // neighbors, no `NeighborUp` — the registry cannot be populated.
        let gossip_client = iroh_gossip::net::Gossip::builder().spawn(endpoint_client.clone());
        let client_node = PeerNode::new(
            endpoint_client,
            gossip_client,
            PeerNodeConfig {
                swarm_topic: "openledger/m11-eclipse".to_owned(),
                bootstrap_peers: vec![server_id.to_string()],
                anti_entropy_interval_ms: 200,
            },
            allow_client,
        );
        assert_eq!(
            client_node.peer_count(),
            0,
            "M-11 precondition: the eclipsed node has no gossip neighbors"
        );

        spawn_anti_entropy_loop(&client_node, handler_client);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let count = ledger_client.read().await.directive_count();
            if count == source_count {
                break;
            }
            assert_eq!(
                client_node.peer_count(),
                0,
                "the registry must stay empty: the sync has to come from the allowlist alone"
            );
            if tokio::time::Instant::now() > deadline {
                let _ = router_server.shutdown().await;
                panic!(
                    "M-11: eclipsed node never synced from its bootstrap peer: server={source_count} client={count}"
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        assert_eq!(
            client_node.peer_count(),
            0,
            "the registry must stay empty: the sync has to come from the allowlist alone"
        );

        let _ = router_server.shutdown().await;
    }

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
        let dalek = security::signing::PeerKeySignatureProvider::from_bytes(
            &secret.to_bytes(),
            String::new(),
        );
        assert_eq!(
            iroh_hex,
            dalek.public_key_hex(),
            "openledger-author (EndpointId Display) must equal the Ed25519 verifying-key hex used to verify signatures"
        );
    }
}
