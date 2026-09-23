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
//!
//! Counting connections bounds memory only up to the size of what each one may
//! have in flight, and that is up to a 16 MiB frame body: 256 connections of
//! legitimately-shaped frames is 4–8 GiB (L-39). So the limiter also carries a
//! BYTE budget for in-flight inbound frame bodies — global and per peer — that
//! the frame reader draws on as bytes arrive; see [`FrameReservation`].

use std::collections::HashMap;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// Max inbound frame-body bytes in flight across all connections (L-39).
    ///
    /// The count caps above bound CONNECTIONS; this bounds what they hold.
    /// Honest inbound traffic is small — a peer sends `HaveHeads` pages
    /// (≤ ~540 KiB), `Want`s (≤ ~68 KiB) and nothing larger, and a connection
    /// serves one frame at a time — so 256 MiB is past every honest connection
    /// sending its largest page at once, while turning the 4–8 GiB the finding
    /// measured into a fixed ceiling. What only an attacker sends is a frame
    /// claiming the `Supply` discriminator at up to 16 MiB; this is what it
    /// runs into.
    pub max_frame_bytes_in_flight: usize,
    /// Max inbound frame-body bytes in flight from ONE peer (L-39).
    ///
    /// Two maximum-size frames. Without it a single peer could take the whole
    /// global budget and starve every other peer's frames — the per-peer
    /// connection cap's reasoning, applied to bytes.
    pub max_frame_bytes_in_flight_per_peer: usize,
}

impl Default for AntiEntropyLimits {
    fn default() -> Self {
        Self {
            max_total_connections: 256,
            max_connections_per_peer: 32,
            max_requests_per_connection: 100_000,
            max_frame_bytes_in_flight: 256 * 1024 * 1024,
            max_frame_bytes_in_flight_per_peer: 32 * 1024 * 1024,
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
    /// CUMULATIVE count of admitted connections, as opposed to the concurrent
    /// counts above — the seam T42's reuse tests read to tell "the peer opened
    /// one connection and multiplexed over it" from "the peer dialled again".
    ///
    /// Test-only: it bounds nothing, so it does not exist in a real build.
    #[cfg(test)]
    accepted_total: AtomicUsize,
    /// In-flight inbound frame-body bytes, globally and per peer (L-39).
    ///
    /// One mutex for both counts so a reservation is charged to both or to
    /// neither — two atomics could leave a refused grow charged to one. The
    /// critical section is a few integer operations per 64 KiB chunk.
    frame_bytes: Mutex<FrameBytes>,
    max_frame_bytes: usize,
    max_frame_bytes_per_peer: usize,
}

/// The byte counts behind [`FrameReservation`] (L-39).
#[derive(Default)]
struct FrameBytes {
    total: usize,
    /// Entries at 0 are removed, never leaked (same rule as `per_peer`).
    per_peer: HashMap<EndpointId, usize>,
    /// High-water mark of `total`, the observable the L-39 tests assert on.
    #[cfg(test)]
    peak: usize,
}

impl ConnectionLimiter {
    /// Build a limiter enforcing `limits`' connection caps.
    pub fn new(limits: AntiEntropyLimits) -> Self {
        Self {
            inner: Arc::new(LimiterInner {
                global: Arc::new(Semaphore::new(limits.max_total_connections)),
                per_peer: Mutex::new(HashMap::new()),
                max_connections_per_peer: limits.max_connections_per_peer,
                #[cfg(test)]
                accepted_total: AtomicUsize::new(0),
                frame_bytes: Mutex::new(FrameBytes::default()),
                max_frame_bytes: limits.max_frame_bytes_in_flight,
                max_frame_bytes_per_peer: limits.max_frame_bytes_in_flight_per_peer,
            }),
        }
    }

    /// An empty frame-body reservation charged to `peer` (L-39).
    ///
    /// Holds nothing until the frame reader grows it; see [`FrameReservation`].
    pub fn frame_reservation(&self, peer: EndpointId) -> FrameReservation {
        FrameReservation {
            metered: Some((Arc::clone(&self.inner), peer)),
            held: 0,
        }
    }

    /// Inbound frame-body bytes currently reserved across all peers (L-39).
    #[cfg(test)]
    pub(crate) fn frame_bytes_in_flight(&self) -> usize {
        self.inner.lock_frame_bytes().total
    }

    /// The most frame-body bytes ever reserved at once (L-39).
    #[cfg(test)]
    pub(crate) fn frame_bytes_peak(&self) -> usize {
        self.inner.lock_frame_bytes().peak
    }

    /// How many connections this limiter has admitted since it was built.
    ///
    /// Observability for tests only; see [`LimiterInner::accepted_total`].
    #[cfg(test)]
    pub(crate) fn accepted_total(&self) -> usize {
        self.inner.accepted_total.load(Ordering::Relaxed)
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
        #[cfg(test)]
        self.inner.accepted_total.fetch_add(1, Ordering::Relaxed);
        Some(ConnectionGuard {
            inner: Arc::clone(&self.inner),
            peer,
            _permit: permit,
        })
    }
}

impl LimiterInner {
    fn lock_frame_bytes(&self) -> std::sync::MutexGuard<'_, FrameBytes> {
        self.frame_bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// RAII claim on the inbound frame-body byte budget, for ONE frame (L-39).
///
/// The frame reader grows it as the body's buffer grows — BEFORE allocating —
/// rather than charging the length prefix up front. Charging the claim would let
/// a peer that announces 16 MiB and then trickles bytes pin 16 MiB of budget it
/// never sent; charging what is actually buffered means a stalled frame costs
/// only what it delivered, which is the L-19 property carried over to the
/// budget.
///
/// A grow that cannot be covered FAILS rather than waits. Waiting would be the
/// H-10 wedge again: every frame holding part of the budget while parked for
/// more, with nothing that ever releases it. Refusing tears the frame (and so
/// the session) down, the peer retries on its next tick, and anti-entropy is
/// idempotent.
///
/// Release is by `Drop`, so no path — a decode error, a read timeout, a torn
/// stream, the serve future being dropped — can leak budget. The serve loop
/// keeps the reservation alive until the decoded message has been handled,
/// using the body's size as the stand-in for what the decoded message holds.
pub struct FrameReservation {
    /// `None` for an unmetered reservation (outbound reads; see [`Self::unmetered`]).
    metered: Option<(Arc<LimiterInner>, EndpointId)>,
    held: usize,
}

impl FrameReservation {
    /// A reservation that meters nothing and never refuses.
    ///
    /// For the OUTBOUND side, whose frames are replies to requests this node
    /// chose to make and whose concurrency is bounded by its own loops (one
    /// exchange per peer per tick, `FetchCoordinator`'s 16 fetches). Charging
    /// them to the inbound budget would let inbound peers starve this node's own
    /// replication.
    pub fn unmetered() -> Self {
        Self {
            metered: None,
            held: 0,
        }
    }

    /// Bytes this reservation currently holds.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.held
    }

    /// Grow the reservation to `target` bytes in total.
    ///
    /// Returns false — holding exactly what it held before — when the global or
    /// the per-peer budget cannot cover the difference. A `target` at or below
    /// what is held is a no-op that succeeds.
    pub fn grow_to(&mut self, target: usize) -> bool {
        if target <= self.held {
            return true;
        }
        let Some((inner, peer)) = &self.metered else {
            self.held = target;
            return true;
        };
        let extra = target - self.held;
        let mut bytes = inner.lock_frame_bytes();
        let peer_held = bytes.per_peer.get(peer).copied().unwrap_or(0);
        let total = bytes.total.saturating_add(extra);
        let peer_total = peer_held.saturating_add(extra);
        if total > inner.max_frame_bytes || peer_total > inner.max_frame_bytes_per_peer {
            return false;
        }
        bytes.total = total;
        bytes.per_peer.insert(*peer, peer_total);
        #[cfg(test)]
        {
            bytes.peak = bytes.peak.max(total);
        }
        self.held = target;
        true
    }
}

impl Drop for FrameReservation {
    fn drop(&mut self) {
        let Some((inner, peer)) = &self.metered else {
            return;
        };
        if self.held == 0 {
            return;
        }
        let mut bytes = inner.lock_frame_bytes();
        bytes.total = bytes.total.saturating_sub(self.held);
        if let Some(count) = bytes.per_peer.get_mut(peer) {
            *count = count.saturating_sub(self.held);
            if *count == 0 {
                bytes.per_peer.remove(peer);
            }
        }
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
            ..AntiEntropyLimits::default()
        }
    }

    fn byte_limits(total: usize, per_peer: usize) -> AntiEntropyLimits {
        AntiEntropyLimits {
            max_frame_bytes_in_flight: total,
            max_frame_bytes_in_flight_per_peer: per_peer,
            ..AntiEntropyLimits::default()
        }
    }

    /// L-39: reservations are charged to both budgets, refused past either,
    /// and a refused grow leaves the reservation (and the counts) unchanged.
    #[test]
    fn frame_reservations_respect_global_and_per_peer_budgets() {
        let limiter = ConnectionLimiter::new(byte_limits(1000, 600));
        let peer_a = SecretKey::generate().public();
        let peer_b = SecretKey::generate().public();

        let mut a1 = limiter.frame_reservation(peer_a);
        assert!(a1.grow_to(400));
        let mut a2 = limiter.frame_reservation(peer_a);
        assert!(!a2.grow_to(300), "peer a would hold 700 > its 600");
        assert_eq!(a2.held(), 0, "a refused grow holds nothing new");
        assert!(a2.grow_to(200), "up to the per-peer budget is fine");

        let mut b1 = limiter.frame_reservation(peer_b);
        assert!(!b1.grow_to(500), "global would be 1100 > 1000");
        assert!(b1.grow_to(400));
        assert_eq!(limiter.frame_bytes_in_flight(), 1000);
        assert!(!b1.grow_to(401), "the global budget is exactly spent");
        assert_eq!(b1.held(), 400);
        assert!(b1.grow_to(100), "shrinking targets are no-ops");
        assert_eq!(b1.held(), 400);

        drop(a1);
        assert_eq!(limiter.frame_bytes_in_flight(), 600);
        assert!(b1.grow_to(600), "a release frees budget for others");
        drop(a2);
        drop(b1);
        assert_eq!(limiter.frame_bytes_in_flight(), 0);
        assert!(
            limiter.inner.lock_frame_bytes().per_peer.is_empty(),
            "per-peer byte map must not leak 0 entries"
        );
        assert_eq!(limiter.frame_bytes_peak(), 1000, "never above the budget");
    }

    /// L-39: an unmetered reservation (the outbound side) never refuses and
    /// never touches the inbound counts.
    #[test]
    fn unmetered_reservation_is_free() {
        let limiter = ConnectionLimiter::new(byte_limits(0, 0));
        let mut outbound = FrameReservation::unmetered();
        assert!(outbound.grow_to(16 * 1024 * 1024));
        assert_eq!(limiter.frame_bytes_in_flight(), 0);
        let mut inbound = limiter.frame_reservation(SecretKey::generate().public());
        assert!(!inbound.grow_to(1), "a zero budget refuses everything");
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
