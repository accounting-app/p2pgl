//! P2P service — orchestrates Iroh endpoint, gossip loop, and anti-entropy
//! for the `gl-node` binary.
//!
//! This module bridges the `p2p` crate's building blocks with the live
//! `LedgerService` and `TransactionBroadcast`, spawning background tasks
//! for gossip broadcasts, anti-entropy head exchanges, and orphan resolution.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::SecretKey;
use iroh_gossip::net::GOSSIP_ALPN;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::anti_entropy_alpn::{exchange_with_peer, fetch_want, AntiEntropyHandler};
use crate::config::P2pConfig;
use crate::fetch_coordinator::FetchCoordinator;

use p2p::allowlist::PeerAllowlist;
use p2p::gossip::{decode_broadcast, encode_broadcast, make_announce};
use p2p::node::{PeerNode, PeerNodeConfig};
use p2p::orphan_buffer::{OrphanBuffer, ORPHAN_EVICTION_INTERVAL};
use p2p::protocol::WireMessage;

/// Boot the P2P subsystem: create the Iroh endpoint from the node's key.
///
/// The key material is loaded by `main` and handed in (L-04) rather than read
/// here, so the QUIC identity and the directive signer provably derive from a
/// single read of a single open file descriptor.
///
/// Returns the `PeerNode` (for injection into GraphQL).
pub async fn boot_p2p(
    config: &P2pConfig,
    node_secret_key: &NodeSecretKey,
) -> Result<PeerNode, Box<dyn std::error::Error>> {
    let secret_key = node_secret_key.iroh_secret_key();

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
        // The bootstrap ids reach the node through `allowlist` (built from the
        // same `bootstrapEndpointIds` a few lines up) and nowhere else — the
        // duplicate `PeerNodeConfig::bootstrap_peers` field it used to be copied
        // into was read by nothing and was removed in T41.
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

/// Floor on the anti-entropy tick, applied at the point of use (L-22, T41).
///
/// The same 100 ms `NodeConfig` validation refuses at boot. That check covers
/// every `gl-node` process, but `p2p::node::PeerNodeConfig` is a `pub` struct a
/// library embedder constructs directly, and `0` there is not merely a fast
/// loop: `tokio::time::interval(Duration::ZERO)` panics, and it does so inside
/// the spawned replication task — which kills replication while the process
/// carries on looking healthy, which is exactly L-22's failure mode.
const MIN_ANTI_ENTROPY_INTERVAL_MS: u64 = 100;

/// Clamp an anti-entropy interval to [`MIN_ANTI_ENTROPY_INTERVAL_MS`], warning
/// when it had to (T41).
///
/// Clamp rather than refuse: this is defence in depth behind config validation,
/// reached only by a caller that bypassed it, and killing replication outright
/// would be a worse answer than running it at a sane cadence and saying so.
fn floor_anti_entropy_interval(interval_ms: u64) -> u64 {
    if interval_ms < MIN_ANTI_ENTROPY_INTERVAL_MS {
        warn!(
            configured_ms = interval_ms,
            floor_ms = MIN_ANTI_ENTROPY_INTERVAL_MS,
            "anti-entropy interval below the supported floor; clamping"
        );
        return MIN_ANTI_ENTROPY_INTERVAL_MS;
    }
    interval_ms
}

/// Attempts `spawn_gossip_loop` makes at joining the gossip topic (T41).
///
/// Eight attempts at a backoff doubling from 500 ms to a 30 s ceiling is a
/// little over two minutes of trying — long enough to ride out discovery and
/// relay warm-up at boot, short enough that a genuinely misconfigured mesh says
/// so while an operator is still watching the log.
const GOSSIP_SUBSCRIBE_MAX_ATTEMPTS: u32 = 8;

/// First delay between gossip subscribe attempts; doubles each time (T41).
const GOSSIP_SUBSCRIBE_BASE_BACKOFF: Duration = Duration::from_millis(500);

/// Ceiling on the doubling gossip-subscribe backoff (T41).
const GOSSIP_SUBSCRIBE_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Join the gossip topic, retrying a failure with a bounded backoff (T41).
///
/// A failed `subscribe` used to end the gossip task outright: one `error!` at
/// boot and the process ran with NO gossip for its entire life. That failure is
/// exactly the kind that is transient — no route yet, the relay not reachable,
/// discovery still warming up — and it presented as a healthy node, because
/// anti-entropy still converged the ledger on its own timer. All that was
/// actually lost was announce-driven catch-up, which is invisible from the
/// outside: replication just became as slow as the anti-entropy interval.
///
/// Bounded rather than infinite on purpose. A wrong topic or an unreachable
/// relay is a configuration error, and a task retrying it forever at 30 s
/// intervals produces a log nobody reads instead of a verdict. Returning `None`
/// after the cap reproduces the old outcome — no gossip — but only after the
/// transient window has been given a real chance, and it says plainly what the
/// node degrades to.
///
/// Generic over the join operation purely so the retry policy is testable
/// without standing up a real `Gossip` — the production call passes
/// `gossip.subscribe(..)` and nothing else ever will.
async fn subscribe_with_retry<T, E, F, Fut>(mut subscribe: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut backoff = GOSSIP_SUBSCRIBE_BASE_BACKOFF;
    for attempt in 1..=GOSSIP_SUBSCRIBE_MAX_ATTEMPTS {
        match subscribe().await {
            Ok(topic) => {
                if attempt > 1 {
                    info!(attempt, "subscribed to the gossip topic after a retry");
                }
                return Some(topic);
            }
            Err(error) => {
                warn!(
                    %error,
                    attempt,
                    max_attempts = GOSSIP_SUBSCRIBE_MAX_ATTEMPTS,
                    retry_in_ms = backoff.as_millis(),
                    "failed to subscribe to the gossip topic; retrying"
                );
            }
        }
        if attempt < GOSSIP_SUBSCRIBE_MAX_ATTEMPTS {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(GOSSIP_SUBSCRIBE_MAX_BACKOFF);
        }
    }
    error!(
        attempts = GOSSIP_SUBSCRIBE_MAX_ATTEMPTS,
        "could not join the gossip topic; this node will replicate by anti-entropy only \
         (announce-driven catch-up is disabled until restart)"
    );
    None
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
        let Some(topic) =
            subscribe_with_retry(|| gossip.subscribe(topic_id, bootstrap_peers.clone())).await
        else {
            return;
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
                                registry.upsert(peer_id.to_string());
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
    let interval_ms = floor_anti_entropy_interval(peer_node.config().anti_entropy_interval_ms);
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

/// Spawn the orphan-buffer TTL sweep as a background tokio task (L-20).
///
/// Before this, `OrphanBuffer::evict_expired` ran only as a side effect of an
/// insert, so expiry was conditional on the very traffic that expiry exists to
/// make room for: a mesh that went quiet — a stalled bootstrap peer, a lull, a
/// node whose allowlisted peers are all down — retained every expired orphan
/// and the budget it holds for as long as the quiet lasted. Nothing else in the
/// node ever touched the buffer.
///
/// The cadence is [`ORPHAN_EVICTION_INTERVAL`], derived from the TTL rather
/// than configured — how often a policy is applied is not itself a policy, and
/// a knob here would be one more thing to set to zero (L-22).
///
/// Unlike the T24 anti-entropy loop this needs no `JoinSet`: there is one
/// sweep, not a fan-out over peers, and it is a bounded in-memory pass under a
/// lock the ALPN batch path holds only briefly.
pub fn spawn_orphan_eviction_loop(orphan_buffer: Arc<tokio::sync::RwLock<OrphanBuffer>>) {
    spawn_orphan_eviction_loop_with(orphan_buffer, ORPHAN_EVICTION_INTERVAL, Instant::now);
}

/// [`spawn_orphan_eviction_loop`] with the cadence and the clock injected.
///
/// Production passes the real interval and `Instant::now`. Tests pass a short
/// interval and a clock that reads an hour ahead, which is the only way to
/// exercise the spawned loop against a one-hour TTL without sleeping for one.
fn spawn_orphan_eviction_loop_with<F>(
    orphan_buffer: Arc<tokio::sync::RwLock<OrphanBuffer>>,
    interval_period: Duration,
    now: F,
) where
    F: Fn() -> Instant + Send + 'static,
{
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_period);
        info!(
            interval_seconds = interval_period.as_secs(),
            "orphan buffer TTL sweep started"
        );

        loop {
            interval.tick().await;

            let (evicted, remaining, cost_bytes) = {
                let mut buffer = orphan_buffer.write().await;
                let evicted = buffer.evict_expired(now());
                (evicted, buffer.len(), buffer.total_cost_bytes())
            };

            if evicted.is_empty() {
                continue;
            }
            // Ids are content hashes; a full list on a large sweep is noise, so
            // name a bounded sample and count the rest.
            let sample: Vec<&str> = evicted.iter().take(8).map(String::as_str).collect();
            info!(
                evicted = evicted.len(),
                remaining,
                cost_bytes,
                ?sample,
                "evicted expired orphans"
            );
        }
    });
}

/// The node's Ed25519 secret key, read from disk exactly once (L-04).
///
/// The same 32 bytes are both the iroh QUIC identity and the directive-signing
/// key — `EndpointId` *is* the Ed25519 verifying key, which is why
/// `openledger-author` can be verified against a peer's endpoint id at all (see
/// `test_iroh_endpoint_id_matches_dalek_public_key_hex`). Before L-04 the file
/// was opened twice, once per consumer, with a third path-based `stat` for the
/// permission check: a swap between any two of those steps left the node signing
/// with one key while announcing another, and the permission check applied to
/// whatever the path resolved to at check time rather than to the bytes actually
/// used. Loading once and handing this value to both consumers removes both.
///
/// The bytes are wrapped in [`Zeroizing`] so the copy this struct owns is wiped
/// when the node shuts down. That is best effort: `iroh::SecretKey` and
/// `ed25519_dalek::SigningKey` keep their own expansions, and nothing here can
/// reach copies the allocator or the kernel made along the way.
pub(crate) struct NodeSecretKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl NodeSecretKey {
    /// The iroh QUIC identity derived from this key.
    pub(crate) fn iroh_secret_key(&self) -> SecretKey {
        SecretKey::from_bytes(&self.bytes)
    }

    /// Raw key material for the Ed25519 directive signer.
    ///
    /// ## Why one key serves two roles, and what a derived subkey would buy
    /// (T41 — documented residual, not a change)
    ///
    /// These same 32 bytes are the node's QUIC transport identity
    /// ([`Self::iroh_secret_key`]) **and** the Ed25519 key it signs directives
    /// with. That is not an accident of implementation: it is the design
    /// `openledger-author` rests on. The author field carries an
    /// `EndpointId` — the QUIC public key — and `verify_remote_signature`
    /// verifies the directive signature *against that same value*. One key is
    /// what makes "the peer that connected" and "the peer that authored"
    /// checkable as one claim, without a second key-distribution channel.
    ///
    /// The cost is the usual one for key reuse: a single key is used by two
    /// protocols with different lifetimes and different exposure. The QUIC
    /// identity is used constantly, online, against unauthenticated dialers; the
    /// signing key authenticates the permanent ledger history. Compromise of
    /// either is compromise of both, and the signing key can never be rotated
    /// independently of the node's network identity — rotating it changes the
    /// `EndpointId` every peer's allowlist names.
    ///
    /// The standard remedy is a **derived signing subkey**: keep this value as
    /// the long-term root, derive the signing key with a domain-separated KDF
    /// (`HKDF(root, "openledger/sig/v1")`), and publish the derived public key
    /// in the envelope instead of the `EndpointId`.
    ///
    /// It is not done here, and the reason is not effort — it is that the
    /// derived public key would have to travel somewhere. `openledger-author`
    /// would stop being an `EndpointId`, so: the allowlist (`EndpointId`s) and
    /// the author check would no longer speak the same language, H-14's
    /// "`openledger-author` must also be on the allowlist" rule would need a
    /// new mapping to enforce, every persisted signature would verify against a
    /// key nobody has yet, and the envelope would need a field to carry the
    /// derived key or its certificate. That is a coordinated format and
    /// key-distribution change of exactly the kind M-10 and L-06 are already
    /// waiting on, and it belongs in that bump — not bolted onto key loading.
    ///
    /// Until then the mitigation is operational and already in place: the file
    /// is 0600, created `O_EXCL`, read through a single `fstat`ed handle
    /// (L-04/L-32), zeroized here, and never logged (see the `Debug` impl
    /// below).
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Redacted: a derived `Debug` would print the secret key into any log line or
/// test failure that formats a value containing one.
impl std::fmt::Debug for NodeSecretKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeSecretKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// What a single open-and-read of the key file found.
enum KeyFileState {
    /// No such file. The caller creates one if it is allowed to.
    Missing,
    /// The file exists but holds no key — the artifact of a write that died
    /// between `create_new` and `write_all`. Treated as [`Missing`] by the
    /// create path (L-32) so a crash cannot brick the node permanently.
    ///
    /// [`Missing`]: KeyFileState::Missing
    Empty,
    /// 32 bytes of key material.
    Material(Zeroizing<[u8; 32]>),
}

/// Open the key file **once** and read the key out of that same handle (L-04).
///
/// Every check below is made against the open file description — the permission
/// check `fstat`s the handle, the bytes come off the handle — so nothing between
/// here and the parsed key can be swapped underneath us by relinking the path.
///
/// The permission check runs *before* the emptiness check on purpose. A
/// zero-length file carries no key to leak, so the order is not about
/// confidentiality — it is that an unexpected mode at the key path is a signal
/// worth stopping on, whoever left it, and the artifact this function is
/// tolerant of (a crashed `write_secret_key_file`) is 0600 by construction.
fn read_secret_key_file(path: &Path) -> Result<KeyFileState, Box<dyn std::error::Error>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(KeyFileState::Missing)
        }
        Err(error) => {
            return Err(format!(
                "Secret key file {} could not be opened: {error}",
                path.display()
            )
            .into())
        }
    };

    ensure_secret_key_permissions(&file, path)?;

    let mut hex_content = Zeroizing::new(String::new());
    file.read_to_string(&mut hex_content)?;
    let trimmed = hex_content.trim();
    if trimmed.is_empty() {
        return Ok(KeyFileState::Empty);
    }

    let decoded = Zeroizing::new(hex::decode(trimmed)?);
    if decoded.len() != 32 {
        return Err(format!("Secret key file has {} bytes, expected 32", decoded.len()).into());
    }
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    key_bytes.copy_from_slice(&decoded);
    Ok(KeyFileState::Material(key_bytes))
}

/// Load the node's secret key, requiring the file to already exist.
///
/// Used when `signing.enabled` without `p2p.enabled`: a signing-only node has no
/// identity to bootstrap, so a missing key is an operator error, not something to
/// paper over by inventing one.
pub(crate) fn load_secret_key(path: &Path) -> Result<NodeSecretKey, Box<dyn std::error::Error>> {
    match read_secret_key_file(path)? {
        KeyFileState::Material(bytes) => Ok(NodeSecretKey { bytes }),
        KeyFileState::Missing => {
            Err(format!("Secret key file {} does not exist", path.display()).into())
        }
        KeyFileState::Empty => Err(format!(
            "Secret key file {} is empty (a crashed write?); remove it and let a p2p-enabled boot regenerate it",
            path.display()
        )
        .into()),
    }
}

/// Load or create the node's secret key (CAP-4: persistent identity).
pub(crate) fn load_or_create_secret_key(
    path: &Path,
) -> Result<NodeSecretKey, Box<dyn std::error::Error>> {
    match read_secret_key_file(path)? {
        KeyFileState::Material(bytes) => {
            info!(path = %path.display(), "loaded Iroh secret key");
            return Ok(NodeSecretKey { bytes });
        }
        KeyFileState::Missing => {}
        KeyFileState::Empty => {
            // L-32: `write_secret_key_file` creates the file and only then fills
            // it, so a crash in that window leaves a zero-length key file behind.
            // Failing on it forever would turn one unlucky power cut into manual
            // intervention; the file demonstrably carries no identity to lose, so
            // regenerate — loudly, because on a node that *had* an identity this
            // is also what a truncating third party leaves behind.
            warn!(
                path = %path.display(),
                "secret key file is empty — treating it as absent and generating a new identity; \
                 this node's EndpointId changes, so peers must be re-told about it"
            );
            std::fs::remove_file(path)?;
        }
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let key = SecretKey::generate();
    let bytes = Zeroizing::new(key.to_bytes());
    let hex_key = Zeroizing::new(hex::encode(*bytes));
    write_secret_key_file(path, &hex_key)?;
    info!(path = %path.display(), "generated and persisted new Iroh secret key");
    Ok(NodeSecretKey { bytes })
}

/// Refuse to use a secret key file that is group- or world-readable (C-2).
///
/// Takes the **open handle**, not the path: `File::metadata` is `fstat(2)` on the
/// descriptor we are about to read, so the mode reported is the mode of the inode
/// whose bytes become the key. A path-based `stat` would leave the classic
/// check-then-use window, where the mode of one file licenses reading another
/// (L-04).
#[cfg(unix)]
fn ensure_secret_key_permissions(
    file: &File,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file.metadata()?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "Secret key file {} has overly permissive mode {mode:o}; expected 0600",
            path.display()
        )
        .into());
    }
    Ok(())
}

/// Non-Unix: there is no mode to check, so say so instead of returning `Ok(())`
/// and letting the caller believe C-2 was enforced (L-05).
#[cfg(not(unix))]
fn ensure_secret_key_permissions(
    _file: &File,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    warn!(
        path = %path.display(),
        "secret key file permissions are NOT verified on this platform (non-Unix); the C-2 \
         owner-only check is a no-op here — restrict access to this file with the platform's \
         own ACLs, as a readable key is a full node identity"
    );
    Ok(())
}

/// Create and fill the secret key file, owner-only, durably (L-32).
///
/// `create_new` (`O_CREAT|O_EXCL`) is the point of this function: it refuses to
/// open anything that already exists at the path, so a pre-planted symlink is
/// never traversed and the key is never written through it to an attacker-chosen
/// destination. This mirrors the ledger's `persist_atomically` temp-file
/// hardening. The caller is responsible for the path being free — the only
/// caller unlinks an empty leftover first, and a genuine race loses the `open`
/// rather than writing to the wrong file.
fn write_secret_key_file(path: &Path, hex_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(hex_key.as_bytes())?;
    // The key is the node's identity: a boot that reported success and then lost
    // the file to a power cut would come back as a different peer. fsync the file
    // and the directory entry, exactly as `persist_atomically` does.
    file.sync_all()?;

    #[cfg(unix)]
    {
        // `mode(0o600)` is masked by the process umask, which can only *clear*
        // bits — restore 0600 through the handle (`fchmod`), never by path.
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)?;
    }

    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if let Ok(directory_file) = File::open(directory) {
        let _ = directory_file.sync_all();
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

    // ─── T41: defensive interval floor (L-22 defence in depth) ─────────────

    /// `NodeConfig` refuses an interval under 100 ms at boot, but
    /// `PeerNodeConfig` is `pub` and a library embedder constructs it directly.
    /// `0` there reaches `tokio::time::interval(Duration::ZERO)`, which panics
    /// inside the spawned replication task: replication dies and the process
    /// keeps serving, which is L-22's failure mode exactly.
    #[tokio::test]
    async fn anti_entropy_interval_is_floored_defensively() {
        assert_eq!(floor_anti_entropy_interval(0), MIN_ANTI_ENTROPY_INTERVAL_MS);
        assert_eq!(floor_anti_entropy_interval(1), MIN_ANTI_ENTROPY_INTERVAL_MS);
        assert_eq!(
            floor_anti_entropy_interval(MIN_ANTI_ENTROPY_INTERVAL_MS - 1),
            MIN_ANTI_ENTROPY_INTERVAL_MS
        );
        // At and above the floor the configured value is used unchanged — this
        // is a floor, not a rewrite.
        assert_eq!(
            floor_anti_entropy_interval(MIN_ANTI_ENTROPY_INTERVAL_MS),
            MIN_ANTI_ENTROPY_INTERVAL_MS
        );
        assert_eq!(floor_anti_entropy_interval(5_000), 5_000);

        // And the floored value is one `Duration::from_millis` can actually
        // build an interval from — the panic this exists to prevent.
        let _interval =
            tokio::time::interval(Duration::from_millis(floor_anti_entropy_interval(0)));
    }

    // ─── T41: a failed gossip subscribe retries instead of ending the task ──

    /// A transient subscribe failure must not be fatal. Before this, the FIRST
    /// `Err` returned from `subscribe` ended the gossip task for the life of the
    /// process — and because anti-entropy kept converging the ledger on its own
    /// timer, the node looked entirely healthy while announce-driven catch-up
    /// was gone.
    ///
    /// Clock-paused, so the real backoff schedule runs without the test waiting
    /// through it.
    #[tokio::test(start_paused = true)]
    async fn gossip_subscribe_retries_a_transient_failure() {
        let mut attempts = 0u32;
        let joined = subscribe_with_retry(|| {
            attempts += 1;
            let attempt = attempts;
            async move {
                if attempt < 3 {
                    Err("no route to the relay yet")
                } else {
                    Ok("topic")
                }
            }
        })
        .await;

        assert_eq!(joined, Some("topic"), "a retried subscribe must succeed");
        assert_eq!(
            attempts, 3,
            "it must have retried, not given up at the first error"
        );
    }

    /// And the retry is BOUNDED: a permanently broken mesh gets a verdict, not
    /// an infinite loop writing a log nobody reads.
    #[tokio::test(start_paused = true)]
    async fn gossip_subscribe_gives_up_after_the_attempt_cap() {
        let mut attempts = 0u32;
        let joined: Option<&str> = subscribe_with_retry(|| {
            attempts += 1;
            async { Err::<&str, _>("wrong topic") }
        })
        .await;

        assert!(
            joined.is_none(),
            "a permanently failing subscribe must give up"
        );
        assert_eq!(
            attempts, GOSSIP_SUBSCRIBE_MAX_ATTEMPTS,
            "it must make exactly the capped number of attempts"
        );
    }

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

    // ── L-20: the spawned TTL sweep ──────────────────────────────────────

    /// The spawned loop evicts an expired orphan with NO insert of any kind.
    ///
    /// Drives the real `spawn_orphan_eviction_loop_with` — the same body the
    /// production entry point runs — with the cadence shortened and the clock
    /// reading one TTL ahead, because the alternative is a one-hour test. The
    /// buffer is touched exactly once, before the loop starts; every subsequent
    /// change to it comes from the timer. Before L-20 nothing but an insert
    /// could remove an expired entry, so this loop did not exist and the entry
    /// would sit there for as long as the mesh stayed quiet.
    #[tokio::test]
    async fn orphan_eviction_loop_drains_expired_entries_without_an_insert() {
        use ledger::model::*;
        use rust_decimal_macros::dec;
        use std::collections::BTreeMap;

        let directive = Directive::Transaction(Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            flag: Flag::Complete,
            payee: None,
            narration: Some("expiring orphan".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        });

        let buffer = Arc::new(tokio::sync::RwLock::new(OrphanBuffer::new()));
        buffer.write().await.insert(
            "orphan-1".to_owned(),
            directive,
            vec!["missing-parent".to_owned()],
            Some("peer-a".to_owned()),
        );
        assert_eq!(buffer.read().await.len(), 1);

        // A clock one TTL plus a margin ahead: everything already in the buffer
        // is expired as far as the loop is concerned.
        spawn_orphan_eviction_loop_with(buffer.clone(), Duration::from_millis(20), || {
            Instant::now() + p2p::orphan_buffer::MAX_ORPHAN_AGE + Duration::from_secs(60)
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            {
                let held = buffer.read().await;
                if held.is_empty() {
                    assert_eq!(
                        held.total_cost_bytes(),
                        0,
                        "the sweep must refund the budget it freed"
                    );
                    break;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the TTL sweep never ran: the expired orphan is still buffered"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The production entry point uses the TTL-derived cadence, so the sweep
    /// cannot be left running at a period unrelated to the TTL it enforces.
    #[test]
    fn orphan_eviction_cadence_is_the_ttl_quarter() {
        assert_eq!(
            ORPHAN_EVICTION_INTERVAL,
            p2p::orphan_buffer::MAX_ORPHAN_AGE / 4
        );
    }

    #[test]
    fn test_load_or_create_secret_key_creates_new() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.secret");

        let key1 = load_or_create_secret_key(&key_path).unwrap();
        assert!(key_path.exists(), "Key file should be created");

        // Loading again should return the same key.
        let key2 = load_or_create_secret_key(&key_path).unwrap();
        assert_eq!(key1.bytes(), key2.bytes(), "Same key should be loaded");
    }

    #[cfg(unix)]
    #[test]
    fn test_secret_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("perm.secret");
        load_or_create_secret_key(&key_path).unwrap();

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

        let error = load_or_create_secret_key(&key_path).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("overly permissive"),
            "Expected permission error, got: {message}"
        );
    }

    // ── L-32: key-file write hardening ───────────────────────────────────

    /// A pre-planted symlink at the key path must NOT be written through.
    ///
    /// `create_new` is `O_CREAT|O_EXCL`, which fails on an existing directory
    /// entry — symlink included, dangling or not — so the key can never be
    /// written to a destination someone else chose (the same property the
    /// ledger's `persist_atomically` temp file relies on). The old
    /// `create(true).truncate(true)` followed the link and created/overwrote the
    /// target with a fresh 32-byte identity.
    #[cfg(unix)]
    #[test]
    fn test_secret_key_write_refuses_to_follow_a_planted_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("planted.secret");
        let attacker_target = dir.path().join("attacker-owned");
        std::os::unix::fs::symlink(&attacker_target, &key_path).expect("plant symlink");

        let error = load_or_create_secret_key(&key_path)
            .expect_err("a planted symlink at the key path must not be written through");

        assert!(
            !attacker_target.exists(),
            "the key must not have been written to the symlink's target: {}",
            attacker_target.display()
        );
        let message = error.to_string();
        assert!(
            message.contains("exists"),
            "expected an O_EXCL 'already exists' failure, got: {message}"
        );
    }

    /// An empty key file — what a write that died between `create_new` and
    /// `write_all` leaves behind — is treated as absent and regenerated, rather
    /// than failing every boot from then on.
    ///
    /// The artifact is reproduced by running the real writer with no content, so
    /// the file has exactly the mode and shape a crashed `write_secret_key_file`
    /// leaves (0600, zero bytes) rather than a hand-made approximation.
    #[cfg(unix)]
    #[test]
    fn test_empty_secret_key_file_is_regenerated() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("crashed.secret");
        write_secret_key_file(&key_path, "").expect("simulate a write that died before write_all");
        assert_eq!(std::fs::metadata(&key_path).unwrap().len(), 0);

        let key = load_or_create_secret_key(&key_path)
            .expect("an empty key file must be regenerated, not fatal");

        assert_ne!(
            key.bytes(),
            &[0u8; 32],
            "the regenerated key must be real material"
        );
        let on_disk = std::fs::read_to_string(&key_path).expect("key file must exist again");
        assert_eq!(
            on_disk.trim(),
            hex::encode(key.bytes()),
            "the regenerated key must be what was persisted"
        );
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the regenerated key file must be 0600");

        // And it is stable from here on: the next boot loads it rather than
        // regenerating again.
        let reloaded = load_or_create_secret_key(&key_path).expect("reload");
        assert_eq!(key.bytes(), reloaded.bytes());
    }

    /// Whitespace-only is empty too — a crashed write can leave a stray newline.
    #[test]
    fn test_whitespace_only_secret_key_file_is_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("whitespace.secret");
        write_secret_key_file(&key_path, "\n").expect("write whitespace-only key file");

        let key =
            load_or_create_secret_key(&key_path).expect("whitespace-only must count as empty");
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().trim(),
            hex::encode(key.bytes())
        );
    }

    /// The signing-only loader never invents an identity: an empty (or missing)
    /// key file is an operator error there, because a node with no mesh has
    /// nothing to bootstrap a new key into.
    #[test]
    fn test_load_secret_key_refuses_to_invent_a_key() {
        let dir = tempfile::tempdir().unwrap();

        let missing = dir.path().join("absent.secret");
        let error = load_secret_key(&missing).expect_err("missing key must be fatal");
        assert!(error.to_string().contains("does not exist"), "got: {error}");
        assert!(
            !missing.exists(),
            "the load-only path must not create a key"
        );

        let empty = dir.path().join("empty.secret");
        write_secret_key_file(&empty, "").unwrap();
        let error = load_secret_key(&empty).expect_err("empty key must be fatal");
        assert!(error.to_string().contains("is empty"), "got: {error}");
    }

    // ── L-04: one open, one fstat, one read, both consumers ──────────────

    /// The permission check stats the **open handle**, not the path.
    ///
    /// The file is opened, and only then is the *path* relinked to a
    /// world-readable impostor. A path-based `stat` would now report 0644 and
    /// reject — which is exactly the check-then-use window, run in reverse: the
    /// mode being consulted would belong to a file whose bytes are not the ones
    /// being read. `fstat` on the descriptor reports the 0600 inode we hold.
    #[cfg(unix)]
    #[test]
    fn test_permission_check_stats_the_open_handle_not_the_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("swapped.secret");
        std::fs::write(&key_path, hex::encode([3u8; 32])).unwrap();
        let mut permissions = std::fs::metadata(&key_path).unwrap().permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&key_path, permissions).unwrap();

        let file = File::open(&key_path).expect("open the 0600 key file");

        // Swap what the path resolves to, leaving our descriptor on the old inode.
        std::fs::remove_file(&key_path).unwrap();
        std::fs::write(&key_path, hex::encode([9u8; 32])).unwrap();
        let mut permissions = std::fs::metadata(&key_path).unwrap().permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&key_path, permissions).unwrap();

        ensure_secret_key_permissions(&file, &key_path).expect(
            "the check must apply to the open descriptor, not to whatever the path now names",
        );
    }

    /// One load feeds both consumers: the iroh QUIC identity and the Ed25519
    /// directive signer are the same key, byte for byte.
    #[test]
    fn test_one_load_backs_both_the_iroh_identity_and_the_signer() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("shared.secret");

        let material = load_or_create_secret_key(&key_path).expect("create key");

        let endpoint_identity = material.iroh_secret_key().public().to_string();
        let signer = security::signing::PeerKeySignatureProvider::from_bytes(
            material.bytes(),
            "openledger/test-mesh".to_owned(),
        );

        assert_eq!(
            endpoint_identity,
            signer.public_key_hex(),
            "the endpoint identity and the signer must derive from the one loaded key"
        );
    }

    /// `NodeSecretKey`'s `Debug` must not print key material.
    #[test]
    fn test_node_secret_key_debug_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("redacted.secret");
        let material = load_or_create_secret_key(&key_path).unwrap();

        let rendered = format!("{material:?}");
        assert!(rendered.contains("redacted"), "got: {rendered}");
        assert!(
            !rendered.contains(&hex::encode(material.bytes())),
            "Debug must never render the key"
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
