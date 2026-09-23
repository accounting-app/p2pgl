//! Bounds gossip-triggered fetches so an announce flood cannot amplify into
//! unbounded work (M-07 / M-12).
//!
//! Gossip content is an *untrusted hint*, not authenticated data. The gossip
//! allowlist gate (`admits(delivered_from)`) authenticates only the last hop —
//! the relay that forwarded the message — not the origin (M-12), and plumtree
//! relays every first-seen message to neighbors before the app sees it. So the
//! announce id in an inbound gossip message can be anything a stranger ≥2 hops
//! away chose to inject. The real security boundary is the ALPN fetch path
//! (`fetch_want` -> `validate_supply_entry` -> author-allowlist + signature),
//! which is unchanged and sound; this coordinator's only job is to bound the
//! work each hint can trigger:
//!
//! * a concurrency cap on in-flight fetches (the semaphore),
//! * in-flight dedup so duplicate announces of one id don't race in parallel,
//! * a negative cache that rate-limits retries of ids that failed or are not
//!   yet available, so a re-announce flood can't re-trigger a fetch every round.
//!
//! Anti-entropy (the periodic interval loop) remains the correctness backstop:
//! dropping a hint under saturation, or negative-caching a not-yet-available
//! id, never loses data — it only declines to *chase* it via gossip for a
//! bounded window. The next anti-entropy round pulls anything genuinely missing.
//!
//! The coordinator is network-free and unit-testable in isolation. It uses
//! `std::sync::Mutex` for its two maps (the critical sections are tiny and hold
//! no `.await`, so the guard's `Drop` can lock synchronously) and tokio's
//! `Semaphore` for the concurrency permit.
//!
//! Every lock recovers from poisoning rather than panicking (L-38), matching the
//! rest of the tree. These run inside the gossip-loop task and inside
//! `FetchGuard::drop`: a panic anywhere while a map is held would otherwise turn
//! every later `try_begin` — and every later guard drop, i.e. every in-flight
//! fetch's cleanup — into a second panic, ending announce-driven catch-up for
//! the life of the process. Both maps stay consistent across a poisoning panic:
//! each critical section is a single insert, remove or lookup, so there is no
//! half-applied update for the recovered guard to observe.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Maximum number of gossip-triggered fetches allowed in flight at once. A
/// flood of unique announce ids can spawn at most this many concurrent QUIC
/// dials; further hints are dropped until a permit frees.
pub const MAX_CONCURRENT_FETCHES: usize = 16;

/// How long an id that failed to fetch (or was unavailable) stays in the
/// negative cache before gossip is allowed to chase it again.
pub const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Upper bound on distinct ids held in the negative cache. Keeps memory bounded
/// even under a flood of unique failing ids; the oldest entry is evicted once
/// this is reached.
pub const NEGATIVE_CACHE_CAPACITY: usize = 4096;

/// TTL-bounded, capacity-bounded set of ids that recently failed to fetch.
///
/// An id is inserted when a fetch guard drops without `mark_succeeded`, i.e. we
/// still don't have the directive after attempting the fetch. `contains_fresh`
/// reports membership only within the TTL, so retries resume automatically once
/// an entry ages out.
struct NegativeCache {
    ttl: Duration,
    entries: HashMap<String, Instant>,
}

impl NegativeCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: HashMap::new(),
        }
    }

    /// Drop entries older than the TTL. O(n) over the (capacity-bounded) map.
    fn evict_expired(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl;
        self.entries
            .retain(|_, inserted| now.duration_since(*inserted) < ttl);
    }

    /// Record `id` as recently-failed. Evicts expired entries first, then, if
    /// inserting a new id would exceed `NEGATIVE_CACHE_CAPACITY`, evicts the
    /// oldest entries so the map size never exceeds the cap.
    fn insert(&mut self, id: String) {
        self.evict_expired();
        if !self.entries.contains_key(&id) {
            while self.entries.len() >= NEGATIVE_CACHE_CAPACITY {
                let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, inserted)| **inserted)
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(id, Instant::now());
    }

    /// True only if `id` is present and within the TTL.
    fn contains_fresh(&self, id: &str) -> bool {
        match self.entries.get(id) {
            Some(inserted) => Instant::now().duration_since(*inserted) < self.ttl,
            None => false,
        }
    }
}

/// Bounds the concurrent fetches that untrusted gossip announces can trigger.
///
/// See the module docs for the threat model (M-07 / M-12). Construct one per
/// gossip loop with [`FetchCoordinator::with_defaults`], wrap it in an `Arc`,
/// and call [`try_begin`](FetchCoordinator::try_begin) before spawning a fetch.
pub struct FetchCoordinator {
    in_flight: Mutex<HashSet<String>>,
    negative_cache: Mutex<NegativeCache>,
    semaphore: Arc<Semaphore>,
}

impl FetchCoordinator {
    /// Construct with an explicit concurrency cap and negative-cache TTL.
    ///
    /// The TTL is a field (rather than the module constant) so tests can make
    /// negative-cache behavior deterministic without sleeping.
    pub fn new(max_concurrent: usize, negative_cache_ttl: Duration) -> Self {
        Self {
            in_flight: Mutex::new(HashSet::new()),
            negative_cache: Mutex::new(NegativeCache::new(negative_cache_ttl)),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    /// Construct with the production constants
    /// ([`MAX_CONCURRENT_FETCHES`], [`NEGATIVE_CACHE_TTL`]).
    pub fn with_defaults() -> Self {
        Self::new(MAX_CONCURRENT_FETCHES, NEGATIVE_CACHE_TTL)
    }

    /// Try to reserve a fetch slot for `id`.
    ///
    /// Returns `Some(FetchGuard)` if the caller may proceed to fetch, or `None`
    /// if the hint should be dropped because `id` is negative-cached, already
    /// in flight, or the concurrency cap is saturated. The permit is acquired
    /// synchronously (never `.await`ed) so a saturated coordinator drops the
    /// hint immediately rather than parking a task.
    pub fn try_begin(self: &Arc<Self>, id: &str) -> Option<FetchGuard> {
        // 1. Negative cache: rate-limit retries of ids that recently failed.
        {
            let mut cache = self
                .negative_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.evict_expired();
            if cache.contains_fresh(id) {
                return None;
            }
        }

        // 2. In-flight dedup: don't race duplicate announces of one id.
        {
            let mut in_flight = self
                .in_flight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if in_flight.contains(id) {
                return None;
            }
            in_flight.insert(id.to_owned());
        }

        // 3. Concurrency permit LAST. Undo the in-flight insert on failure so
        //    the two structures stay consistent.
        match Arc::clone(&self.semaphore).try_acquire_owned() {
            Ok(permit) => Some(FetchGuard {
                id: id.to_owned(),
                coordinator: Arc::clone(self),
                permit: Some(permit),
                succeeded: false,
            }),
            Err(_) => {
                self.in_flight
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(id);
                None
            }
        }
    }
}

impl Default for FetchCoordinator {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// RAII slot for one in-flight fetch, returned by
/// [`FetchCoordinator::try_begin`].
///
/// While it is alive the id counts against the concurrency cap and is deduped.
/// On `Drop` the id leaves the in-flight set and — unless
/// [`mark_succeeded`](FetchGuard::mark_succeeded) was called — is added to the
/// negative cache so a re-announce flood cannot re-trigger a fetch every round.
pub struct FetchGuard {
    id: String,
    coordinator: Arc<FetchCoordinator>,
    /// Held only for its `Drop` side effect (releasing the concurrency permit);
    /// taken in `FetchGuard::drop`.
    permit: Option<OwnedSemaphorePermit>,
    succeeded: bool,
}

impl FetchGuard {
    /// Mark the fetch as successful (we now have the directive), so the id is
    /// NOT negative-cached when the guard drops.
    pub fn mark_succeeded(&mut self) {
        self.succeeded = true;
    }
}

impl Drop for FetchGuard {
    fn drop(&mut self) {
        {
            let mut in_flight = self
                .coordinator
                .in_flight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            in_flight.remove(&self.id);
        }
        if !self.succeeded {
            let mut cache = self
                .coordinator
                .negative_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.insert(self.id.clone());
        }
        // Release the concurrency permit back to the semaphore (reading the
        // field also keeps it from tripping the dead-code lint).
        let _ = self.permit.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TTL: Duration = Duration::from_secs(60);

    #[test]
    fn dedup_blocks_second_begin_while_first_is_live() {
        let coordinator = Arc::new(FetchCoordinator::new(8, TEST_TTL));
        let mut guard = coordinator
            .try_begin("dir-1")
            .expect("first begin succeeds");
        // Second begin for the same id is deduped while the first guard lives.
        assert!(
            coordinator.try_begin("dir-1").is_none(),
            "duplicate id must be deduped while in flight"
        );
        // After a successful fetch drops the guard, the id is fetchable again
        // (it was NOT negative-cached because it succeeded).
        guard.mark_succeeded();
        drop(guard);
        assert!(
            coordinator.try_begin("dir-1").is_some(),
            "succeeded id must be fetchable again after the guard drops"
        );
    }

    #[test]
    fn failed_fetch_is_negative_cached_until_ttl() {
        let coordinator = Arc::new(FetchCoordinator::new(8, TEST_TTL));
        // Drop WITHOUT mark_succeeded => negative-cached.
        {
            let _guard = coordinator.try_begin("dir-2").expect("begin succeeds");
        }
        assert!(
            coordinator.try_begin("dir-2").is_none(),
            "a failed id must be negative-cached (fresh) and blocked"
        );
    }

    #[test]
    fn negative_cache_entry_expires_after_ttl() {
        // Deterministic TTL check without sleeping: inject an old Instant.
        let mut cache = NegativeCache::new(TEST_TTL);
        cache.insert("old".to_owned());
        assert!(cache.contains_fresh("old"), "just-inserted id is fresh");

        let stale = Instant::now()
            .checked_sub(TEST_TTL + Duration::from_secs(1))
            .expect("instant subtraction");
        *cache.entries.get_mut("old").expect("entry present") = stale;

        assert!(
            !cache.contains_fresh("old"),
            "an entry older than the TTL must not be fresh"
        );
        cache.evict_expired();
        assert!(
            !cache.entries.contains_key("old"),
            "evict_expired must drop the stale entry"
        );
    }

    #[test]
    fn saturation_caps_live_guards() {
        let coordinator = Arc::new(FetchCoordinator::new(2, TEST_TTL));
        let guard_a = coordinator.try_begin("a").expect("a begins");
        let mut guard_b = coordinator.try_begin("b").expect("b begins");
        // Cap of 2 reached: a third distinct id is refused.
        assert!(
            coordinator.try_begin("c").is_none(),
            "third fetch must be refused while the cap is saturated"
        );
        // Freeing one slot (successfully) lets a new id proceed.
        guard_b.mark_succeeded();
        drop(guard_b);
        assert!(
            coordinator.try_begin("c").is_some(),
            "a new id proceeds once a slot frees"
        );
        drop(guard_a);
    }

    /// L-38: a panic while a coordinator lock is held must not make every later
    /// `try_begin` — and every guard drop — panic too.
    #[test]
    fn poisoned_locks_do_not_panic_the_gossip_loop() {
        let coordinator = Arc::new(FetchCoordinator::new(8, TEST_TTL));
        let live = coordinator
            .try_begin("live")
            .expect("begin before poisoning");
        let poisons: [fn(&FetchCoordinator); 2] = [
            |c: &FetchCoordinator| {
                let _held = c.in_flight.lock().unwrap();
                panic!("poison the in-flight set");
            },
            |c: &FetchCoordinator| {
                let _held = c.negative_cache.lock().unwrap();
                panic!("poison the negative cache");
            },
        ];
        for poison in poisons {
            let target = Arc::clone(&coordinator);
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poison(&target)));
            assert!(outcome.is_err(), "the helper must actually panic");
        }
        assert!(coordinator.in_flight.is_poisoned());
        assert!(coordinator.negative_cache.is_poisoned());

        // Dropping a live guard locks both maps; it must clean up, not panic.
        drop(live);
        assert!(
            coordinator.try_begin("live").is_none(),
            "the failed fetch was still negative-cached through the poisoned lock"
        );
        let mut guard = coordinator
            .try_begin("fresh")
            .expect("a new id still proceeds after poisoning");
        assert!(
            coordinator.try_begin("fresh").is_none(),
            "dedup still works"
        );
        guard.mark_succeeded();
        drop(guard);
        assert!(coordinator.try_begin("fresh").is_some());
    }

    #[test]
    fn negative_cache_never_exceeds_capacity() {
        let overshoot = 500usize;
        let mut cache = NegativeCache::new(TEST_TTL);
        for index in 0..(NEGATIVE_CACHE_CAPACITY + overshoot) {
            cache.insert(format!("id-{index}"));
            assert!(
                cache.entries.len() <= NEGATIVE_CACHE_CAPACITY,
                "negative cache exceeded capacity at index {index}: len={}",
                cache.entries.len()
            );
        }
        assert_eq!(
            cache.entries.len(),
            NEGATIVE_CACHE_CAPACITY,
            "cache should be pinned at capacity after an overshoot of distinct ids"
        );
    }

    // Bug-catch proof (M-07): dedup + saturation are exactly what the
    // coordinator provides. Without it, N announces of one id each proceed to
    // spawn a fetch; with it, exactly one does until the guard resolves.
    #[test]
    fn one_thousand_duplicate_begins_yield_exactly_one_proceed() {
        let coordinator = Arc::new(FetchCoordinator::new(MAX_CONCURRENT_FETCHES, TEST_TTL));
        let mut guards = Vec::new();
        let mut proceeds = 0usize;
        for _ in 0..1000 {
            if let Some(guard) = coordinator.try_begin("hot-id") {
                proceeds += 1;
                guards.push(guard);
            }
        }
        assert_eq!(
            proceeds, 1,
            "exactly one of 1000 duplicate try_begin calls may proceed"
        );
    }

    #[test]
    fn at_most_max_concurrent_guards_are_live() {
        let coordinator = Arc::new(FetchCoordinator::new(MAX_CONCURRENT_FETCHES, TEST_TTL));
        let mut guards = Vec::new();
        for index in 0..(MAX_CONCURRENT_FETCHES * 4) {
            if let Some(guard) = coordinator.try_begin(&format!("id-{index}")) {
                guards.push(guard);
            }
        }
        assert_eq!(
            guards.len(),
            MAX_CONCURRENT_FETCHES,
            "no more than MAX_CONCURRENT_FETCHES guards can be live at once"
        );
    }
}
