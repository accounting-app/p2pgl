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
//!
//! Counting CONCURRENT connections does not bound how OFTEN a peer may open
//! them, and a fresh connection is not free: it costs a QUIC handshake, and its
//! first `HaveHeads{more:false}` costs a full O(N) local advert under the ledger
//! read lock (M-40). So admission also runs a per-peer accept token bucket — see
//! [`AntiEntropyLimits::accept_burst`].

use std::collections::HashMap;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
/// chunks + re-`Want`s for a 64 MiB ledger). The request budget and the accept
/// bucket have a config surface (`p2p.antiEntropyMaxSessionFrames`,
/// `p2p.antiEntropyAcceptBurst`, `p2p.antiEntropyAcceptRefillMilliseconds`;
/// R-7), built by `P2pConfig::anti_entropy_limits`.
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
    ///
    /// # What it charges, and what it does not (L-65)
    ///
    /// It charges the frame BODY only — exactly: `grow_to` reserves what the
    /// reader then `reserve_exact`s, with no growth-policy slack. What the body
    /// turns into while its [`FrameReservation`] is alive is not charged:
    ///
    /// ```text
    /// body (charged)                                          1×
    /// decoded message (e.g. Vec<SupplyEntry>)                ~1×
    /// ciborium `Content` buffering (internally-tagged
    ///   enum decode, R-4; transient, before phase 1)          up to 4×
    /// Supply phase 1 (validate, then stage), measured (T75):
    ///   a frame of entries over a §3.12 count — refused
    ///     inside the parser, nothing staged                   < 0.1×
    ///     (before T75: 20–42× per body, 34.7× a frame)
    ///   one entry with a 1 MiB token (narration, metadata
    ///     value: the parser's 4 B/char scan)                  ≤ 6.5× that body
    /// Supply phase 1, held for staging (T77): at most one
    ///   `PHASE_ONE_WEIGHT_BUDGET` (16 MiB) of parsed weight
    ///   per frame, then staged; densest in-cap frame
    ///   (256 × ~19 KB bodies, ~70 MB parsed)                  ≤ 16 MiB + one entry
    ///     (before T77: the whole frame, ~13×, ≈ 63 MB)
    /// ```
    ///
    /// Since T77 the held weight is also CHARGED: a pushed `Supply`'s phase 1
    /// grows the frame's reservation by the resident weight
    /// (`p2p::anti_entropy::resident_weight`, conservative against a counting
    /// allocator) of every directive it holds, stages what it holds whenever
    /// the budget cannot cover the next one, and gives the weight back after
    /// each chunk. So this budget now bounds bodies AND the parsed directives
    /// waiting on them; what stays uncharged is the decode transient above
    /// (≤ ~4× a body, before phase 1) and one directive per connection when
    /// the budget is exhausted. Outbound (`Want`ed) frames are bounded by the
    /// same 16 MiB per exchange and by the node's own loops. Before T77 the
    /// staged directives were bounded per frame only by `MAX_SUPPLY_ENTRIES` ×
    /// the §3.12 caps, so the ceiling under the 256 MiB default was ≈ 3.5 GiB
    /// (~14×) of densest in-cap frames from one allowlisted peer. The budget
    /// is still a ceiling on what is charged, not an exact resident figure;
    /// size a host against the decode multiple, not the nominal figure.
    pub max_frame_bytes_in_flight: usize,
    /// Max inbound frame-body bytes in flight from ONE peer (L-39).
    ///
    /// Two maximum-size frames. Without it a single peer could take the whole
    /// global budget and starve every other peer's frames — the per-peer
    /// connection cap's reasoning, applied to bytes.
    pub max_frame_bytes_in_flight_per_peer: usize,
    /// NEW connections one peer may open back to back before the accept rate
    /// applies (M-40): the capacity of its accept token bucket.
    ///
    /// The concurrent caps above bound what a peer HOLDS, not how often it may
    /// open and drop. Every fresh connection costs a handshake, and its first
    /// 40-byte `HaveHeads{more:false}` costs a full O(N) local advert under the
    /// ledger read lock (~36 MB out on a 300k-directive ledger) — L-01's frame
    /// budget bounds that per connection, which a free reconnect resets.
    ///
    /// Sized against the honest pattern, which is small because outbound
    /// connections are POOLED (T42, `peer_connections.rs`): one connection per
    /// peer carries every anti-entropy tick and all of the up-to-16
    /// (`MAX_CONCURRENT_FETCHES`) gossip fetches as bi-streams, concurrent
    /// callers share one in-flight dial, and a peer redials only when the pooled
    /// connection is gone — the server's idle close (`io`, 30 s), its session
    /// deadline (300 s), a failed operation, or a restart. The worst honest
    /// burst is a stale-pool redial plus the fresh dial behind it (≈ 2), or a
    /// restart of both ends at once (a handful). Eight is several times that.
    pub accept_burst: u32,
    /// One accept token is returned to a peer's bucket per this interval (M-40).
    ///
    /// Two seconds admits a sustained 30 connections a minute per peer, against
    /// an honest steady state of ONE per `io` idle close (≤ 2/min at the 30 s
    /// default) or one per session deadline (0.2/min) — 15× headroom — while
    /// capping a reconnect loop at a sustained ~0.5 handshakes + adverts per
    /// second per allowlisted peer instead of however many the network allows.
    pub accept_refill_interval: Duration,
    /// Max OUTBOUND anti-entropy exchanges this node runs at once, across all
    /// peers (R-5). Read by `p2p_service::spawn_anti_entropy_loop`; the fields
    /// above bound what OTHER nodes may make this one do, this bounds what
    /// this node's own scheduler starts.
    ///
    /// The loop fans out one exchange per allowlisted peer per tick, and the
    /// per-peer in-flight guard (H-10) stops only a peer getting two. Each
    /// exchange against a hostile peer can hold ≈ 130–150 MiB resident at its
    /// worst (a 1M-id advert in a `Vec` + `HashSet` + the `compute_want`
    /// clone, plus one 16 MiB `Supply` and its decode), so without a cross-peer
    /// bound the ceiling was that × the allowlist size.
    ///
    /// Eight caps it at ≈ 1.0–1.2 GiB whatever the allowlist, while leaving
    /// honest catch-up its parallelism: a mesh of up to eight bootstrap peers
    /// (the usual deployment) never meets the bound, and convergence needs only
    /// ONE honest exchange to run — peers past the bound queue FIFO for the
    /// next free slot (see the loop), so a set of stalled peers can delay an
    /// honest one by at most one exchange's session deadline, never starve it.
    /// Values below 1 are treated as 1.
    pub max_concurrent_outbound_exchanges: usize,
}

impl Default for AntiEntropyLimits {
    fn default() -> Self {
        Self {
            max_total_connections: 256,
            max_connections_per_peer: 32,
            max_requests_per_connection: 100_000,
            max_frame_bytes_in_flight: 256 * 1024 * 1024,
            max_frame_bytes_in_flight_per_peer: 32 * 1024 * 1024,
            accept_burst: DEFAULT_ACCEPT_BURST,
            accept_refill_interval: DEFAULT_ACCEPT_REFILL_INTERVAL,
            max_concurrent_outbound_exchanges: DEFAULT_MAX_CONCURRENT_OUTBOUND_EXCHANGES,
        }
    }
}

/// Default [`AntiEntropyLimits::max_concurrent_outbound_exchanges`] (R-5); see
/// there for the sizing.
pub const DEFAULT_MAX_CONCURRENT_OUTBOUND_EXCHANGES: usize = 8;

/// Default [`AntiEntropyLimits::accept_burst`] (M-40); see there for the sizing.
pub const DEFAULT_ACCEPT_BURST: u32 = 8;

/// Default [`AntiEntropyLimits::accept_refill_interval`] (M-40).
pub const DEFAULT_ACCEPT_REFILL_INTERVAL: Duration = Duration::from_secs(2);

/// How often ONE refusal source may produce a `warn!` (M-40, T77).
///
/// The same ten seconds as the HTTP side's `PER_IP_REFUSAL_LOG_INTERVAL`, for
/// the same reason: a refusal is cheap to provoke, so logging each one would
/// hand a reconnect loop an unbounded log stream the limiter exists to deny it.
/// Refusals in between are counted and reported when the window closes — see
/// [`KeyedRefusalLog`].
pub(crate) const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Most refusal sources a [`KeyedRefusalLog`] tracks at once (T77).
///
/// Past it, every further source shares one overflow window, so the log is
/// bounded at `MAX_REFUSAL_LOG_SOURCES + 1` first lines (plus as many expiry
/// summaries) per [`REFUSAL_LOG_INTERVAL`] however many sources an attacker
/// controls — ~13 lines a second at the ceiling, against the 100–190 MB/s one
/// client produced before M-41. Sixty-four is past any honest allowlist's
/// peers × refusal kinds and any honest set of misconfigured HTTP clients.
pub(crate) const MAX_REFUSAL_LOG_SOURCES: usize = 64;

/// Who a limiter refusal is logged against (T77) — the key of
/// [`ConnectionLimiter::should_log_refusal`].
///
/// An allowlisted peer is keyed by `(peer, reason)`: the allowlist bounds the
/// peers, and one peer's reconnect loop must not hide another peer's refusal,
/// nor a rate refusal hide a full-slot one. A NOT-allowlisted dialer is
/// keyed as one class, deliberately not by its `EndpointId`: identities are
/// free to mint, so a per-identity key would give every fresh key its own
/// first line — exactly the per-handshake log stream L-72 is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefusalSource {
    /// An allowlisted peer refused by one of the limiter's budgets.
    Peer(EndpointId, Refusal),
    /// Any peer not on the bootstrap allowlist (L-72).
    NotAllowlisted,
}

/// A refusal-log throttle keyed by source, with the count of what it swallowed
/// reported when each source's window closes (M-40, M-41, T77).
///
/// # What changed, and why
///
/// Both throttles this replaces — the limiter's and the HTTP request guard's —
/// were ONE window per process: the first refusal of any kind in ten seconds
/// was logged and every other one, from anyone, was counted. So one noisy
/// source hid every other source for as long as it kept going (the audit's
/// "process-wide throttles hide other sources"), and the count was printed only
/// by the *next* refusal — a flood of 999 that then stopped was never reported
/// at all. Here:
///
/// * **Keyed.** Each source (a client IP bucket, an allowlisted
///   `(peer, reason)`, the not-allowlisted class) has its own window, so each
///   gets its own first line.
/// * **Bounded the way `accept_rate` is.** A new source first prunes every
///   window that has closed and owes no report — state an absent entry already
///   describes. Past [`MAX_REFUSAL_LOG_SOURCES`] live windows, new sources
///   share one overflow window instead of growing the map.
/// * **Reported at expiry.** The first refusal a window swallows schedules a
///   report for the moment the window closes (a task on the current Tokio
///   runtime, when there is one): it calls the throttle's `report` function
///   with the count and forgets the window, so the next refusal from that
///   source opens a fresh one and is logged with `suppressed = 0`. Outside a
///   runtime nothing is scheduled and the count rides on the source's next
///   logged line, as before.
///
/// A report and a late refusal cannot double-count: the report only takes the
/// count of the window it was scheduled for, and a refusal that arrives after
/// the window closed but before the report ran carries the count on its own
/// line and opens a new window, which the report then leaves alone.
pub(crate) struct KeyedRefusalLog<K> {
    state: Arc<Mutex<RefusalWindows<K>>>,
    interval: Duration,
    max_sources: usize,
    /// Emits the expiry summary for a source (`None` = the overflow window).
    report: fn(Option<&K>, u64),
}

struct RefusalWindows<K> {
    /// `None` is the overflow window shared by sources past the cap.
    windows: HashMap<Option<K>, RefusalWindow>,
}

#[derive(Clone, Copy)]
struct RefusalWindow {
    opened: Instant,
    suppressed: u64,
    /// An expiry report is scheduled for this window.
    report_armed: bool,
}

impl<K> KeyedRefusalLog<K>
where
    K: Clone + Eq + std::hash::Hash + Send + 'static,
{
    /// A throttle allowing one line per source per `interval`, tracking at
    /// most `max_sources` sources, and reporting swallowed counts through
    /// `report` when a window closes.
    pub(crate) fn new(interval: Duration, max_sources: usize, report: fn(Option<&K>, u64)) -> Self {
        Self {
            state: Arc::new(Mutex::new(RefusalWindows {
                windows: HashMap::new(),
            })),
            interval,
            max_sources,
            report,
        }
    }

    /// Note one refusal from `source` at `now`. `Some(suppressed)` means "log
    /// this one; this many from the same source were swallowed and not yet
    /// reported"; `None` means stay quiet (the count is kept for the report).
    pub(crate) fn note(&self, source: K, now: Instant) -> Option<u64> {
        let mut state = self.lock();
        let key = self.resolve(&mut state, source, now);
        let interval = self.interval;
        match state.windows.get_mut(&key) {
            Some(window) if now.saturating_duration_since(window.opened) < interval => {
                window.suppressed = window.suppressed.saturating_add(1);
                if !window.report_armed {
                    window.report_armed = self.schedule_report(key.clone(), window.opened);
                }
                None
            }
            Some(window) => {
                // The window closed and its report has not run (or there is no
                // runtime to run it): this line carries the count instead.
                let carried = std::mem::take(&mut window.suppressed);
                *window = RefusalWindow {
                    opened: now,
                    suppressed: 0,
                    report_armed: false,
                };
                Some(carried)
            }
            None => {
                state.windows.insert(
                    key,
                    RefusalWindow {
                        opened: now,
                        suppressed: 0,
                        report_armed: false,
                    },
                );
                Some(0)
            }
        }
    }

    /// The map key `source` is counted under: its own, or the overflow
    /// window's once [`Self::max_sources`] live windows exist.
    fn resolve(&self, state: &mut RefusalWindows<K>, source: K, now: Instant) -> Option<K> {
        let key = Some(source);
        if state.windows.contains_key(&key) {
            return key;
        }
        let interval = self.interval;
        // `accept_rate`'s discipline: a closed window that owes no report is
        // indistinguishable from an absent one, so drop them all first.
        state.windows.retain(|_, window| {
            window.report_armed || now.saturating_duration_since(window.opened) < interval
        });
        let tracked = state.windows.keys().filter(|key| key.is_some()).count();
        if tracked >= self.max_sources {
            None
        } else {
            key
        }
    }

    /// Schedule the expiry report for the window of `key` opened at `opened`.
    /// Returns whether one was scheduled (there is a runtime to run it on).
    fn schedule_report(&self, key: Option<K>, opened: Instant) -> bool {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return false;
        };
        let state = Arc::clone(&self.state);
        let deadline = opened + self.interval;
        let report = self.report;
        runtime.spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            let owed = {
                let mut state = state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match state.windows.get(&key) {
                    Some(window) if window.opened == opened => {
                        let owed = window.suppressed;
                        state.windows.remove(&key);
                        owed
                    }
                    // A later refusal already carried the count and opened a
                    // new window; that window is not this report's.
                    _ => 0,
                }
            };
            if owed > 0 {
                report(key.as_ref(), owed);
            }
        });
        true
    }

    /// Sources with a live or report-pending window, overflow included (tests).
    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.lock().windows.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RefusalWindows<K>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The limiter's expiry summary (T77): one line per source whose window
/// swallowed refusals.
fn report_limiter_refusals(source: Option<&RefusalSource>, suppressed: u64) {
    match source {
        Some(RefusalSource::Peer(peer, reason)) => tracing::warn!(
            peer = %peer,
            reason = ?reason,
            suppressed,
            "anti-entropy connections refused and not logged in the last window"
        ),
        Some(RefusalSource::NotAllowlisted) => tracing::warn!(
            suppressed,
            "anti-entropy connections from peers not on the bootstrap allowlist refused and \
             not logged in the last window"
        ),
        None => tracing::warn!(
            suppressed,
            "anti-entropy connections refused and not logged in the last window (sources past \
             the per-source log table)"
        ),
    }
}

/// Why [`ConnectionLimiter::try_acquire`] refused a connection (M-16, M-40).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The global concurrent-connection budget is spent.
    Global,
    /// This peer already holds `max_connections_per_peer` connections.
    PerPeer,
    /// This peer is opening connections faster than its accept bucket refills.
    AcceptRate,
}

impl Refusal {
    /// The QUIC application close code the refused connection is closed with.
    ///
    /// The two concurrency refusals keep the code they always had (2); the rate
    /// refusal gets its own so a peer — and a test — can tell "come back when a
    /// slot frees" from "slow down".
    pub fn close_code(self) -> u32 {
        match self {
            Self::Global | Self::PerPeer => 2,
            Self::AcceptRate => 6,
        }
    }

    /// The close reason sent alongside [`Self::close_code`].
    pub fn close_reason(self) -> &'static [u8] {
        match self {
            Self::Global | Self::PerPeer => b"connection-limit",
            Self::AcceptRate => b"accept-rate-limit",
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
    /// Per-peer accept buckets (M-40), as a GCRA "theoretical arrival time":
    /// the instant at which the peer's bucket is full again. Admitting advances
    /// it by one refill interval; a peer is admitted while doing so leaves it no
    /// more than `burst` intervals ahead of now. One `Instant` per peer, no
    /// floating point, and "bucket full" is simply `tat <= now`.
    ///
    /// Deliberately NOT pruned when the peer's connection count drops to 0,
    /// unlike `per_peer`: forgetting the bucket on disconnect would hand a
    /// reconnect loop a full bucket every time. Entries whose bucket is full are
    /// indistinguishable from absent ones and are pruned on insert instead, so
    /// the map holds only peers that connected within the last
    /// `burst × interval` — and every caller has already checked the allowlist.
    accept_rate: Mutex<HashMap<EndpointId, Instant>>,
    accept_burst: u32,
    accept_refill_interval: Duration,
    /// Throttle for the refusal `warn!`s, per [`RefusalSource`] (M-40, T77).
    refusal_log: KeyedRefusalLog<RefusalSource>,
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
                accept_rate: Mutex::new(HashMap::new()),
                accept_burst: limits.accept_burst,
                accept_refill_interval: limits.accept_refill_interval,
                refusal_log: KeyedRefusalLog::new(
                    REFUSAL_LOG_INTERVAL,
                    MAX_REFUSAL_LOG_SOURCES,
                    report_limiter_refusals,
                ),
            }),
        }
    }

    /// Whether a refusal of `source` happening now should be logged (M-40,
    /// T77), and if so how many from the same source were swallowed and not
    /// yet reported.
    ///
    /// At most one `Some` per [`REFUSAL_LOG_INTERVAL`] per [`RefusalSource`]
    /// (and at most [`MAX_REFUSAL_LOG_SOURCES`] + 1 sources), so a reconnect
    /// loop's log cost is fixed however fast it loops, and one peer's loop no
    /// longer hides another's refusals. What a window swallowed is reported by
    /// its own line when the window closes — see [`KeyedRefusalLog`].
    pub fn should_log_refusal(&self, source: RefusalSource, now: Instant) -> Option<u64> {
        self.inner.refusal_log.note(source, now)
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
    /// Returns a guard that must be held for the connection's lifetime, or the
    /// [`Refusal`] naming which budget is exhausted: the global or per-peer
    /// concurrency cap (M-16), or the peer's accept rate (M-40). Refusal is
    /// all-or-nothing — the global permit taken for the check is released, no
    /// per-peer entry is created (a rejected peer never leaves a spurious
    /// 0-count entry behind) and no accept token is spent, so a peer refused
    /// for a full slot does not also lose rate it never used.
    pub fn try_acquire(&self, peer: EndpointId) -> Result<ConnectionGuard, Refusal> {
        self.try_acquire_at(peer, Instant::now())
    }

    /// [`Self::try_acquire`] against an explicit clock, so the bucket's
    /// arithmetic is testable without sleeping.
    pub(crate) fn try_acquire_at(
        &self,
        peer: EndpointId,
        now: Instant,
    ) -> Result<ConnectionGuard, Refusal> {
        // Global budget first: an owned permit released by the guard's `Drop`.
        let permit = Arc::clone(&self.inner.global)
            .try_acquire_owned()
            .map_err(|_| Refusal::Global)?;
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
                return Err(Refusal::PerPeer);
            }
            // M-40: the accept rate, checked LAST so that only a connection
            // every other budget would admit spends a token. Lock order is
            // always `per_peer` then `accept_rate`, and nothing else takes both.
            self.inner.take_accept_token(peer, now)?;
            per_peer.insert(peer, current + 1);
        }
        #[cfg(test)]
        self.inner.accepted_total.fetch_add(1, Ordering::Relaxed);
        Ok(ConnectionGuard {
            inner: Arc::clone(&self.inner),
            peer,
            _permit: permit,
        })
    }

    /// Peers with a partly drained accept bucket (M-40), for the bound test.
    #[cfg(test)]
    pub(crate) fn accept_buckets_tracked(&self) -> usize {
        self.inner
            .accept_rate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

impl LimiterInner {
    /// Spend one of `peer`'s accept tokens at `now`, or refuse without changing
    /// anything (M-40). GCRA: see [`LimiterInner::accept_rate`].
    fn take_accept_token(&self, peer: EndpointId, now: Instant) -> Result<(), Refusal> {
        let interval = self.accept_refill_interval;
        let horizon = interval.saturating_mul(self.accept_burst);
        let mut buckets = self
            .accept_rate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tat = buckets.get(&peer).copied().map_or(now, |tat| tat.max(now));
        let next = tat + interval;
        if next.saturating_duration_since(now) > horizon {
            return Err(Refusal::AcceptRate);
        }
        if !buckets.contains_key(&peer) {
            // A new entry: first drop every bucket that has refilled to full,
            // which is state an absent entry already describes.
            buckets.retain(|_, tat| *tat > now);
        }
        buckets.insert(peer, next);
        Ok(())
    }

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
///
/// That stand-in is a 1× charge for a 2–6× footprint (L-65): the decoded
/// message and ciborium's `Content` buffering (up to 4×) live under the
/// reservation uncharged. A `Supply` batch's parsed directives are charged on
/// top since T77 ([`Self::shrink_to`]). See
/// [`AntiEntropyLimits::max_frame_bytes_in_flight`] for the measured multiples.
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

    /// Shrink the reservation to `target` bytes, returning the difference to
    /// the global and per-peer budgets (T77). A `target` at or above what is
    /// held is a no-op.
    ///
    /// For the one reservation that is charged for something other than a
    /// frame body: `apply_supply_entries_from`'s phase 1 charges the resident
    /// weight of the directives it holds for staging, and gives it back each
    /// time a chunk has been staged and dropped.
    pub fn shrink_to(&mut self, target: usize) {
        if target >= self.held {
            return;
        }
        let released = self.held - target;
        self.held = target;
        let Some((inner, peer)) = &self.metered else {
            return;
        };
        let mut bytes = inner.lock_frame_bytes();
        bytes.total = bytes.total.saturating_sub(released);
        if let Some(count) = bytes.per_peer.get_mut(peer) {
            *count = count.saturating_sub(released);
            if *count == 0 {
                bytes.per_peer.remove(peer);
            }
        }
    }
}

impl Drop for FrameReservation {
    fn drop(&mut self) {
        self.shrink_to(0);
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
            limiter.try_acquire(peer).is_err(),
            "3rd acquire for the same peer must be refused by the per-peer cap"
        );

        // Dropping one frees exactly one slot.
        drop(guard_one);
        let guard_three = limiter
            .try_acquire(peer)
            .expect("after a drop, a slot is free again");
        assert!(
            limiter.try_acquire(peer).is_err(),
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
        assert!(limiter.try_acquire(peer_x).is_err(), "peer x capped at 1");
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
            limiter.try_acquire(peer_c).is_err(),
            "global cap of 2 must refuse a 3rd distinct peer"
        );
    }

    /// A rejected acquire must not leave a spurious per-peer entry behind.
    #[test]
    fn refused_acquire_leaves_no_entry() {
        let limiter = ConnectionLimiter::new(limits(0, 100));
        let peer = SecretKey::generate().public();
        assert!(
            limiter.try_acquire(peer).is_err(),
            "global cap of 0 refuses everything"
        );
        assert!(
            limiter.inner.per_peer.lock().unwrap().is_empty(),
            "a refused acquire must not create a per-peer entry"
        );
    }

    fn rate_limits(burst: u32, refill: Duration) -> AntiEntropyLimits {
        AntiEntropyLimits {
            accept_burst: burst,
            accept_refill_interval: refill,
            ..AntiEntropyLimits::default()
        }
    }

    /// M-40: a reconnect loop gets exactly `burst` admissions at once, then one
    /// per refill interval — and a full `burst` again once it has been quiet
    /// for `burst` intervals. Dropping the guards (the loop's connections
    /// ending) does not refill anything: the bucket outlives the connections.
    #[test]
    fn accept_bucket_admits_burst_then_the_refill_rate() {
        let limiter = ConnectionLimiter::new(rate_limits(3, Duration::from_secs(2)));
        let peer = SecretKey::generate().public();
        let start = Instant::now();

        for attempt in 0..3 {
            drop(
                limiter
                    .try_acquire_at(peer, start)
                    .unwrap_or_else(|refusal| panic!("burst admit {attempt}: {refusal:?}")),
            );
        }
        assert_eq!(
            limiter.try_acquire_at(peer, start).err(),
            Some(Refusal::AcceptRate),
            "the 4th back-to-back connection is over the burst"
        );
        assert_eq!(
            limiter
                .try_acquire_at(peer, start + Duration::from_millis(1999))
                .err(),
            Some(Refusal::AcceptRate),
            "no token before a full refill interval"
        );
        drop(
            limiter
                .try_acquire_at(peer, start + Duration::from_secs(2))
                .expect("one token back after one interval"),
        );
        assert_eq!(
            limiter
                .try_acquire_at(peer, start + Duration::from_secs(2))
                .err(),
            Some(Refusal::AcceptRate),
            "and only one"
        );
        // Quiet for burst × interval: the whole burst is available again.
        let later = start + Duration::from_secs(2 + 6);
        for _ in 0..3 {
            drop(limiter.try_acquire_at(peer, later).expect("refilled burst"));
        }
        assert!(limiter.try_acquire_at(peer, later).is_err());
        assert_eq!(limiter.accepted_total(), 3 + 1 + 3);
    }

    /// M-40: a rate refusal is all-or-nothing like the other two — it returns
    /// the global permit and creates no per-peer entry — and a refusal by a
    /// concurrency cap spends no accept token.
    #[test]
    fn accept_rate_refusals_change_nothing_and_cap_refusals_spend_no_token() {
        let limiter = ConnectionLimiter::new(AntiEntropyLimits {
            max_total_connections: 8,
            max_connections_per_peer: 1,
            ..rate_limits(2, Duration::from_secs(60))
        });
        let peer = SecretKey::generate().public();
        let now = Instant::now();

        let held = limiter.try_acquire_at(peer, now).expect("first admit");
        // Refused by the per-peer cap, repeatedly: none of these may spend the
        // peer's second token.
        for _ in 0..5 {
            assert_eq!(
                limiter.try_acquire_at(peer, now).err(),
                Some(Refusal::PerPeer),
                "the peer's single slot is held"
            );
        }
        drop(held);
        drop(
            limiter
                .try_acquire_at(peer, now)
                .expect("the second token was never spent by the cap refusals"),
        );
        assert_eq!(
            limiter.try_acquire_at(peer, now).err(),
            Some(Refusal::AcceptRate)
        );
        assert!(
            limiter.inner.per_peer.lock().unwrap().is_empty(),
            "a rate refusal must not leave a per-peer entry"
        );
        assert_eq!(
            limiter.inner.global.available_permits(),
            8,
            "a rate refusal must return the global permit it took"
        );
    }

    /// M-40: buckets are per peer, and the map holds only peers whose bucket
    /// is not full — a peer that has been quiet for `burst × interval` is
    /// forgotten on the next insert, so the map cannot grow without bound.
    #[test]
    fn accept_buckets_are_per_peer_and_pruned_once_full() {
        let limiter = ConnectionLimiter::new(rate_limits(1, Duration::from_secs(2)));
        let now = Instant::now();
        let peer_a = SecretKey::generate().public();
        let peer_b = SecretKey::generate().public();

        drop(limiter.try_acquire_at(peer_a, now).expect("a admitted"));
        assert!(limiter.try_acquire_at(peer_a, now).is_err(), "a is spent");
        drop(
            limiter
                .try_acquire_at(peer_b, now)
                .expect("b has its own bucket"),
        );
        assert_eq!(limiter.accept_buckets_tracked(), 2);

        let later = now + Duration::from_secs(2);
        let peer_c = SecretKey::generate().public();
        drop(limiter.try_acquire_at(peer_c, later).expect("c admitted"));
        assert_eq!(
            limiter.accept_buckets_tracked(),
            1,
            "a and b refilled to full and were pruned when c was inserted"
        );
    }

    /// M-40: refusals log at most once per interval, and the line that does
    /// log carries how many were swallowed since the last one.
    #[test]
    fn refusal_logging_is_rate_limited_and_counts_what_it_suppressed() {
        let limiter = ConnectionLimiter::new(AntiEntropyLimits::default());
        let peer = SecretKey::generate().public();
        let source = RefusalSource::Peer(peer, Refusal::AcceptRate);
        let now = Instant::now();
        assert_eq!(limiter.should_log_refusal(source, now), Some(0));
        for step in 1..=5 {
            assert_eq!(
                limiter.should_log_refusal(source, now + Duration::from_secs(step)),
                None
            );
        }
        assert_eq!(
            limiter.should_log_refusal(source, now + REFUSAL_LOG_INTERVAL),
            Some(5),
            "outside a runtime, the next logged line reports the five suppressed refusals"
        );
        assert_eq!(
            limiter.should_log_refusal(source, now + REFUSAL_LOG_INTERVAL),
            None
        );
    }

    // ── T77: per-source refusal throttles ───────────────────────────────

    /// T77 (Info): each source has its own window. Two allowlisted peers — and
    /// two reasons for one peer — each get their own first line inside the
    /// same ten seconds, and the not-allowlisted class is ONE source however
    /// many identities dial.
    ///
    /// Bug-catch: key the throttle by nothing (one process-wide window) and
    /// the second source's first refusal is swallowed.
    #[test]
    fn refusal_logging_is_per_source() {
        let limiter = ConnectionLimiter::new(AntiEntropyLimits::default());
        let (one, two) = (
            SecretKey::generate().public(),
            SecretKey::generate().public(),
        );
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let rate = |peer| RefusalSource::Peer(peer, Refusal::AcceptRate);
        assert_eq!(limiter.should_log_refusal(rate(one), now), Some(0));
        assert_eq!(limiter.should_log_refusal(rate(one), later), None);
        assert_eq!(
            limiter.should_log_refusal(rate(two), later),
            Some(0),
            "another peer's first refusal is not hidden by the first peer's window"
        );
        assert_eq!(
            limiter.should_log_refusal(RefusalSource::Peer(one, Refusal::PerPeer), later),
            Some(0),
            "another reason from the same peer is its own source"
        );
        assert_eq!(
            limiter.should_log_refusal(RefusalSource::NotAllowlisted, later),
            Some(0)
        );
        for _ in 0..50 {
            assert_eq!(
                limiter.should_log_refusal(RefusalSource::NotAllowlisted, later),
                None,
                "every not-allowlisted dialer shares one window"
            );
        }
    }

    /// T77: the table is bounded. Past `MAX_REFUSAL_LOG_SOURCES` live
    /// windows, new sources share ONE overflow window (one line, then
    /// quiet), and a closed window that owes no report is pruned when the
    /// next new source arrives.
    #[test]
    fn refusal_log_sources_are_bounded_and_pruned() {
        fn ignore(_: Option<&u32>, _: u64) {}
        let log = KeyedRefusalLog::<u32>::new(REFUSAL_LOG_INTERVAL, 4, ignore);
        let now = Instant::now();
        for source in 0..4 {
            assert_eq!(log.note(source, now), Some(0));
        }
        assert_eq!(
            log.note(100, now),
            Some(0),
            "the overflow window's first line"
        );
        for source in 101..200 {
            assert_eq!(
                log.note(source, now),
                None,
                "overflow sources share one window"
            );
        }
        assert_eq!(log.tracked(), 5, "four sources plus the overflow window");
        let after = now + REFUSAL_LOG_INTERVAL;
        assert_eq!(
            log.note(7, after),
            Some(0),
            "closed windows are pruned, so a new source is tracked again"
        );
        assert_eq!(log.tracked(), 1);
    }

    /// T77 (Info): what a window swallowed is reported when the window
    /// closes, by the window's own line — not only by the source's next
    /// refusal, which may never come. After the report the source starts a
    /// fresh window whose first line carries 0 (nothing counted twice).
    ///
    /// Bug-catch: drop the scheduled report and nothing is reported until the
    /// source's next refusal.
    #[tokio::test]
    async fn suppressed_refusals_are_reported_when_the_window_closes() {
        static REPORTS: Mutex<Vec<(Option<u32>, u64)>> = Mutex::new(Vec::new());
        fn record(source: Option<&u32>, suppressed: u64) {
            REPORTS.lock().unwrap().push((source.copied(), suppressed));
        }
        let interval = Duration::from_millis(200);
        let log = KeyedRefusalLog::<u32>::new(interval, 8, record);
        let start = Instant::now();
        assert_eq!(log.note(1, start), Some(0));
        assert_eq!(log.note(2, start), Some(0));
        for _ in 0..999 {
            assert_eq!(log.note(1, start), None);
        }
        for _ in 0..3 {
            assert_eq!(log.note(2, start), None);
        }
        tokio::time::sleep(interval * 3).await;
        let mut reports = REPORTS.lock().unwrap().clone();
        reports.sort_unstable();
        assert_eq!(
            reports,
            vec![(Some(1), 999), (Some(2), 3)],
            "each source's swallowed count is reported once, at expiry"
        );
        assert_eq!(
            log.note(1, Instant::now()),
            Some(0),
            "the reported count is not carried again"
        );
    }
}
