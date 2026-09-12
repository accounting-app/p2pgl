//! Inbound ALPN connection admission control (M-16, T24).
//!
//! iroh's `Router` spawns an unbounded task per inbound connection with no
//! per-peer cap, so one peer — or a handful — can open connections without
//! bound. Each accepted anti-entropy session also drives CBOR decodes that
//! transiently buffer far more than the bytes on the wire (see the M-16 note in
//! `anti_entropy_alpn::read_message`), so the number of *concurrent* accepted
//! connections directly bounds peak transient memory. `ConnectionLimiter` caps
//! both the global concurrent-connection count and the per-peer count.
//!
//! The limiter is cloneable and `Arc`-backed: every clone of the handler the
//! router accepts on enforces one shared budget.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use iroh::EndpointId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Concurrency and request limits for inbound anti-entropy sessions (M-16, T24).
///
/// The defaults are deliberately generous: the goal is bounding a runaway peer,
/// not tightly rate-limiting honest ones. A single honest peer runs only a
/// handful of concurrent anti-entropy exchanges (T23 caps a node's outbound
/// gossip fetches at 16, plus periodic head exchanges), so a per-peer cap of 32
/// never trips on a legitimate burst, and 100_000 requests on one connection is
/// far past any real catch-up (paginated `HaveHeads` + thousands of `Want`
/// chunks + re-`Want`s for a 64 MiB ledger). These get a config surface in T38.
#[derive(Clone, Copy, Debug)]
pub struct AntiEntropyLimits {
    /// Max concurrent inbound anti-entropy connections across all peers.
    pub max_total_connections: usize,
    /// Max concurrent inbound anti-entropy connections from one peer.
    pub max_connections_per_peer: usize,
    /// Max messages handled on one connection before it is closed (T24).
    pub max_requests_per_connection: usize,
}

impl Default for AntiEntropyLimits {
    fn default() -> Self {
        Self {
            max_total_connections: 256,
            max_connections_per_peer: 32,
            max_requests_per_connection: 100_000,
        }
    }
}

/// Shared admission control for inbound anti-entropy connections (M-16).
///
/// Cloning shares one budget: the global [`Semaphore`] and the per-peer count
/// map live behind an `Arc`. A [`std::sync::Mutex`] guards the per-peer map so
/// [`ConnectionGuard`]'s `Drop` can decrement without awaiting.
#[derive(Clone)]
pub struct ConnectionLimiter {
    inner: Arc<LimiterInner>,
}

struct LimiterInner {
    /// Global concurrent-connection budget.
    global: Arc<Semaphore>,
    /// Live connection count per peer. Entries at 0 are removed, never leaked.
    per_peer: Mutex<HashMap<EndpointId, usize>>,
    max_connections_per_peer: usize,
}

impl ConnectionLimiter {
    /// Build a limiter enforcing `limits`' connection caps.
    pub fn new(limits: AntiEntropyLimits) -> Self {
        Self {
            inner: Arc::new(LimiterInner {
                global: Arc::new(Semaphore::new(limits.max_total_connections)),
                per_peer: Mutex::new(HashMap::new()),
                max_connections_per_peer: limits.max_connections_per_peer,
            }),
        }
    }

    /// Try to admit one inbound connection from `peer`.
    ///
    /// Returns a guard that must be held for the connection's lifetime, or
    /// `None` when either the global or the per-peer budget is exhausted. On
    /// `None` no state changes: the global permit taken for the check is
    /// released and no per-peer entry is created (a rejected peer never leaves a
    /// spurious 0-count entry behind).
    pub fn try_acquire(&self, peer: EndpointId) -> Option<ConnectionGuard> {
        // Global budget first: an owned permit released by the guard's `Drop`.
        let permit = Arc::clone(&self.inner.global).try_acquire_owned().ok()?;
        // Per-peer budget under the mutex. Check before incrementing.
        {
            let mut per_peer = self
                .inner
                .per_peer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let current = per_peer.get(&peer).copied().unwrap_or(0);
            if current >= self.inner.max_connections_per_peer {
                // `permit` drops here, returning the global slot we just took.
                return None;
            }
            per_peer.insert(peer, current + 1);
        }
        Some(ConnectionGuard {
            inner: Arc::clone(&self.inner),
            peer,
            _permit: permit,
        })
    }
}

/// RAII guard held for the lifetime of one admitted connection. Its `Drop`
/// releases the global permit and decrements (and prunes) the per-peer count.
pub struct ConnectionGuard {
    inner: Arc<LimiterInner>,
    peer: EndpointId,
    /// Released on drop, returning the slot to the global [`Semaphore`].
    _permit: OwnedSemaphorePermit,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut per_peer = self
            .inner
            .per_peer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = per_peer.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                per_peer.remove(&self.peer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn limits(total: usize, per_peer: usize) -> AntiEntropyLimits {
        AntiEntropyLimits {
            max_total_connections: total,
            max_connections_per_peer: per_peer,
            max_requests_per_connection: 1,
        }
    }

    /// A: the per-peer cap admits exactly `max_connections_per_peer`, refuses the
    /// next, and frees a slot when a guard drops — and prunes empty entries.
    #[test]
    fn per_peer_cap_admits_then_refuses_then_frees() {
        let limiter = ConnectionLimiter::new(limits(100, 2));
        let peer = SecretKey::generate().public();

        let guard_one = limiter.try_acquire(peer).expect("1st acquire admitted");
        let guard_two = limiter.try_acquire(peer).expect("2nd acquire admitted");
        assert!(
            limiter.try_acquire(peer).is_none(),
            "3rd acquire for the same peer must be refused by the per-peer cap"
        );

        // Dropping one frees exactly one slot.
        drop(guard_one);
        let guard_three = limiter
            .try_acquire(peer)
            .expect("after a drop, a slot is free again");
        assert!(
            limiter.try_acquire(peer).is_none(),
            "still capped at 2 after the replacement acquire"
        );

        // Dropping all guards prunes the peer's map entry (no empty-entry leak).
        drop(guard_two);
        drop(guard_three);
        assert!(
            limiter.inner.per_peer.lock().unwrap().is_empty(),
            "per-peer map must not leak a 0-count entry"
        );
    }

    /// A: the per-peer cap is independent across peers.
    #[test]
    fn per_peer_cap_is_independent_across_peers() {
        let limiter = ConnectionLimiter::new(limits(100, 1));
        let peer_x = SecretKey::generate().public();
        let peer_y = SecretKey::generate().public();

        let _x = limiter.try_acquire(peer_x).expect("peer x admitted");
        assert!(limiter.try_acquire(peer_x).is_none(), "peer x capped at 1");
        // peer y has its own budget.
        let _y = limiter.try_acquire(peer_y).expect("peer y admitted");
    }

    /// A: the global cap bounds the total across distinct peers, independent of
    /// the per-peer cap.
    #[test]
    fn global_cap_bounds_total_across_peers() {
        let limiter = ConnectionLimiter::new(limits(2, 100));
        let peer_a = SecretKey::generate().public();
        let peer_b = SecretKey::generate().public();
        let peer_c = SecretKey::generate().public();

        let _a = limiter.try_acquire(peer_a).expect("global slot 1");
        let _b = limiter.try_acquire(peer_b).expect("global slot 2");
        assert!(
            limiter.try_acquire(peer_c).is_none(),
            "global cap of 2 must refuse a 3rd distinct peer"
        );
    }

    /// A rejected acquire must not leave a spurious per-peer entry behind.
    #[test]
    fn refused_acquire_leaves_no_entry() {
        let limiter = ConnectionLimiter::new(limits(0, 100));
        let peer = SecretKey::generate().public();
        assert!(
            limiter.try_acquire(peer).is_none(),
            "global cap of 0 refuses everything"
        );
        assert!(
            limiter.inner.per_peer.lock().unwrap().is_empty(),
            "a refused acquire must not create a per-peer entry"
        );
    }
}
