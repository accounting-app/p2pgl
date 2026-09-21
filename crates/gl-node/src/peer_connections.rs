//! Per-peer ALPN connection reuse for OUTBOUND anti-entropy (T42).
//!
//! Before this, `fetch_want` and `exchange_with_peer` each called
//! `endpoint.connect(...)` fresh, so every gossip-driven fetch and every
//! anti-entropy tick paid a full QUIC handshake — and a node whose gossip is
//! busy runs many of those against the SAME allowlisted peer within a few
//! hundred milliseconds. This cache gives both call sites one shared per-peer
//! connection to multiplex their bi-streams over.
//!
//! It is an optimization and nothing more: every timeout, every limit, and
//! every allowlist check upstream of it is unchanged, and a cache that returned
//! `None` for everything would leave behaviour exactly as it was.
//!
//! # Shape
//!
//! * A global map `EndpointId -> Arc<PeerSlot>`, behind a [`std::sync::Mutex`]
//!   held only long enough to look a slot up (never across a dial).
//! * Each slot holds `tokio::sync::Mutex<Option<Connection>>`. The async mutex
//!   is what DEDUPES CONCURRENT DIALS: the first caller to a cold peer holds it
//!   across its `endpoint.connect(...)`, so a second caller arriving mid-dial
//!   waits and then finds the finished connection rather than starting a second
//!   handshake of its own.
//! * `Connection` is `Arc`-backed, so a "cached connection" is a cheap clone of
//!   one live QUIC connection and concurrent `open_bi()` calls on those clones
//!   are native QUIC stream multiplexing, not a queue.
//!
//! # Liveness and the ONE re-dial
//!
//! A pooled connection is checked with `close_reason()` before it is handed
//! out, and a closed one is replaced by a fresh dial inside the same
//! [`acquire`](PeerConnectionCache::acquire). That check is not a guarantee —
//! a connection can die between the check and the caller's `open_bi()` — so the
//! caller re-dials ONCE when opening a stream on a REUSED connection fails
//! (see `anti_entropy_alpn::open_peer_session`).
//!
//! That retry sits strictly at the dial/`open_bi` boundary, BEFORE any frame is
//! written or read. Anti-entropy is idempotent, so replaying a whole exchange
//! would be *safe*, but it would also be a silent doubling of work and of the
//! server's per-connection request budget, and it would make a mid-stream
//! failure indistinguishable from a stale-pool failure. So: a connection that
//! dies mid-stream is invalidated (so the NEXT operation does not inherit it)
//! and the operation fails, exactly as it failed before T42. An operation that
//! fails twice at the dial boundary fails, exactly as a failed dial fails.
//!
//! # Interplay with the server's idle close — what the reuse actually buys
//!
//! `serve_anti_entropy` bounds its wait for the peer's next bi-stream with the
//! I/O timeout (T41), and that bound applies to EVERY stream on a connection,
//! not just the first. A pooled connection that has been idle longer than that
//! has therefore typically already been closed by the server, and the next
//! `acquire` sees `close_reason()` set and dials again.
//!
//! So the win is WITHIN a burst, not across a quiet period:
//!
//! * a multi-chunk fetch or a paginated catch-up (already one connection, now
//!   also one connection when the chunks are split across operations),
//! * gossip fetches that overlap each other and an anti-entropy tick against
//!   the same relay — the common case, since T23 lets up to 16 fetches run at
//!   once and they all target allowlisted peers,
//! * ticks that land closer together than the server's idle bound.
//!
//! Across a long idle gap the cache saves nothing, and that is deliberate: the
//! server's timeouts are a security boundary (a parked serve task holds an
//! M-16 `ConnectionLimiter` slot), so nothing here widens them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId};

use p2p::allowlist::PeerAllowlist;

/// One peer's cached connection, behind the async mutex that dedupes dials.
///
/// The `Option` is empty when the peer has never been dialled, when its
/// connection was found closed, or when an operation invalidated it.
#[derive(Default)]
struct PeerSlot {
    connection: tokio::sync::Mutex<Option<Connection>>,
}

/// Shared per-peer connection cache for the anti-entropy ALPN.
///
/// Cloning shares one cache: the slot map lives behind an `Arc`, so every clone
/// of `AntiEntropyHandler` — the gossip loop's, the anti-entropy tick's, the
/// router's — reuses the same connections. See the module docs.
#[derive(Clone, Default)]
pub struct PeerConnectionCache {
    slots: Arc<Mutex<HashMap<EndpointId, Arc<PeerSlot>>>>,
}

/// Whether [`PeerConnectionCache::acquire`] may hand back a pooled connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reuse {
    /// Reuse the pooled connection if it is still open — the normal path.
    IfLive,
    /// Ignore whatever is pooled and dial. This is the ONE re-dial a stale
    /// pooled connection earns, so it must not find the stale entry again.
    Never,
}

/// A connection ready for `open_bi()`, plus where it came from.
pub(crate) struct Acquired {
    pub(crate) connection: Connection,
    /// True when this came out of the pool. Only a REUSED connection earns a
    /// re-dial when `open_bi` fails on it: a freshly dialled connection that
    /// cannot open a stream is a real failure, and retrying it would be a new
    /// behaviour (two dials where there used to be one).
    pub(crate) reused: bool,
}

/// Why acquiring a connection failed.
///
/// The two variants are exactly the two dial failures the call sites reported
/// before T42 (`connect failed` / `connect timed out`), so their logs are
/// unchanged.
pub(crate) enum AcquireError {
    Dial(String),
    Timeout,
}

impl PeerConnectionCache {
    /// An empty cache. One per node; clones share it.
    pub fn new() -> Self {
        Self::default()
    }

    /// The slot for `peer`, creating it if needed, and — on the same access —
    /// dropping the slots of peers that are no longer allowlisted.
    ///
    /// Piggybacking the cleanup on lookup is what keeps the cache bounded
    /// without a background task or a config knob: the map can only ever hold
    /// one slot per allowlisted peer, because every insert is preceded by this
    /// prune and every caller has already checked `admits(peer)`. Dropping a
    /// slot drops its `Connection` handle, which closes the connection once the
    /// last clone goes.
    ///
    /// The global lock is released before the caller touches the slot, so it is
    /// never held across a dial.
    fn slot_for(&self, peer: EndpointId, allowlist: &PeerAllowlist) -> Arc<PeerSlot> {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        slots.retain(|cached, _| allowlist.admits(*cached));
        Arc::clone(slots.entry(peer).or_default())
    }

    /// Hand back a connection to `addr`, reusing the pooled one when `reuse`
    /// allows it and it is still open, and dialling otherwise.
    ///
    /// The WHOLE acquire — including the wait for another task's in-flight dial
    /// to the same peer — is bounded by one `connect_timeout`, so a caller that
    /// arrives behind a dial can never spend two of them; a caller that times
    /// out waiting reports the same "connect timed out" it reported before T42.
    pub(crate) async fn acquire(
        &self,
        endpoint: &Endpoint,
        addr: EndpointAddr,
        allowlist: &PeerAllowlist,
        connect_timeout: Duration,
        reuse: Reuse,
    ) -> Result<Acquired, AcquireError> {
        let slot = self.slot_for(addr.id, allowlist);
        let acquired = tokio::time::timeout(connect_timeout, async move {
            let mut pooled = slot.connection.lock().await;
            let live = match reuse {
                Reuse::IfLive => pooled
                    .as_ref()
                    .filter(|connection| connection.close_reason().is_none())
                    .cloned(),
                Reuse::Never => None,
            };
            if let Some(connection) = live {
                return Ok(Acquired {
                    connection,
                    reused: true,
                });
            }
            // Absent, closed, or explicitly refused: drop whatever is pooled
            // (this is the only place a dead connection is replaced) and dial.
            // The slot lock is held across the dial on purpose — that is what
            // makes a concurrent caller wait for this handshake instead of
            // starting a second one.
            *pooled = None;
            let connection = endpoint
                .connect(addr, p2p::protocol::ANTI_ENTROPY_ALPN)
                .await
                .map_err(|error| AcquireError::Dial(error.to_string()))?;
            *pooled = Some(connection.clone());
            Ok(Acquired {
                connection,
                reused: false,
            })
        })
        .await;
        match acquired {
            Ok(result) => result,
            Err(_elapsed) => Err(AcquireError::Timeout),
        }
    }

    /// Forget the pooled connection for `peer` IF it is still the one the
    /// caller was using.
    ///
    /// Called when an operation fails on a connection: the next operation must
    /// not inherit it. The identity check matters because another task may have
    /// already replaced the entry with a fresh connection, which must survive.
    ///
    /// This only drops the cache's handle. Other tasks mid-operation on their
    /// own clones of the same `Connection` keep it alive and are unaffected —
    /// one operation's failure never tears down another's transfer.
    ///
    /// `try_lock`, not `lock().await`: the slot lock is held across dials, and
    /// a failure path must not wait on one. Losing the race is harmless — the
    /// task holding the lock is installing a connection of its own, and any
    /// dead entry that does survive is caught by the `close_reason()` check on
    /// the next acquire.
    pub(crate) fn invalidate(&self, peer: EndpointId, connection: &Connection) {
        let slot = {
            let slots = self
                .slots
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            slots.get(&peer).map(Arc::clone)
        };
        let Some(slot) = slot else {
            return;
        };
        let Ok(mut pooled) = slot.connection.try_lock() else {
            return;
        };
        if pooled
            .as_ref()
            .is_some_and(|cached| cached.stable_id() == connection.stable_id())
        {
            *pooled = None;
        }
    }

    /// The pooled connection for `peer`, if any (tests only).
    #[cfg(test)]
    pub(crate) async fn pooled(&self, peer: EndpointId) -> Option<Connection> {
        let slot = {
            let slots = self
                .slots
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            slots.get(&peer).map(Arc::clone)
        }?;
        let pooled = slot.connection.lock().await;
        pooled.clone()
    }

    /// How many peers have a slot (tests only).
    #[cfg(test)]
    pub(crate) fn slot_count(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    /// Bounded state (T42): the map holds a slot per ALLOWLISTED peer and no
    /// more — a peer that leaves the allowlist has its slot dropped by the next
    /// access, with no background task and no new configuration.
    #[test]
    fn slots_are_pruned_for_peers_that_left_the_allowlist() {
        let peer_one = SecretKey::generate().public();
        let peer_two = SecretKey::generate().public();
        let both = PeerAllowlist::parse(&[peer_one.to_string(), peer_two.to_string()])
            .expect("allowlist with both peers");

        let cache = PeerConnectionCache::new();
        let slot_one = cache.slot_for(peer_one, &both);
        cache.slot_for(peer_two, &both);
        assert_eq!(cache.slot_count(), 2, "one slot per allowlisted peer");

        // Repeat access does not grow the map: a peer has exactly one slot, and
        // it is the SAME slot (which is what dedupes concurrent dials).
        let slot_one_again = cache.slot_for(peer_one, &both);
        assert_eq!(cache.slot_count(), 2, "re-access must not add a slot");
        assert!(
            Arc::ptr_eq(&slot_one, &slot_one_again),
            "a peer's slot must be stable, or two dials could run in parallel"
        );

        // Drop peer two from the allowlist: the next access prunes its slot.
        let only_one = PeerAllowlist::parse(&[peer_one.to_string()]).expect("narrowed allowlist");
        cache.slot_for(peer_one, &only_one);
        assert_eq!(
            cache.slot_count(),
            1,
            "a peer that left the allowlist must not keep a cached connection"
        );
    }

    /// And the prune really DROPS the slot rather than keeping it keyed: a peer
    /// that leaves and rejoins the allowlist gets a new slot, so nothing it was
    /// connected over survives its absence.
    #[test]
    fn a_pruned_peer_gets_a_fresh_slot_when_it_returns() {
        let peer = SecretKey::generate().public();
        let other = SecretKey::generate().public();
        let admits_peer = PeerAllowlist::parse(&[peer.to_string()]).expect("allowlist");
        let admits_other = PeerAllowlist::parse(&[other.to_string()]).expect("allowlist");

        let cache = PeerConnectionCache::new();
        let before = cache.slot_for(peer, &admits_peer);

        // An access under an allowlist without `peer` prunes its slot.
        cache.slot_for(other, &admits_other);
        assert_eq!(
            cache.slot_count(),
            1,
            "the de-allowlisted peer's slot must be gone, leaving only `other`"
        );

        let after = cache.slot_for(peer, &admits_peer);
        assert!(
            !Arc::ptr_eq(&before, &after),
            "a returning peer must get a fresh slot, not the pruned one"
        );
    }
}
