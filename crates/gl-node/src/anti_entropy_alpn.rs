//! ALPN anti-entropy — authenticated Want/Supply over Iroh QUIC (§3.4.1, R3).
//!
//! Gossip carries Announce only. Ledger bodies are fetched from an allowlisted
//! peer whose QUIC `EndpointId` is the connection remote. `openledger-author`
//! must also be on the same allowlist (H-14).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{
    Connection, ConnectionError, ReadError, ReadExactError, RecvStream, SendStream,
};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::EndpointId;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::connection_limiter::{
    AntiEntropyLimits, ConnectionLimiter, FrameReservation, RefusalSource,
};
use crate::graphql::broadcast::TransactionBroadcast;
use crate::graphql::query::txn_to_graphql;
use crate::graphql::types::Transaction as GraphqlTransaction;
use crate::graphql::SharedLedger;
use crate::peer_connections::{AcquireError, PeerConnectionCache, Reuse};

use ledger::service::ServiceError;
use ledger::validate::ValidationError;
use p2p::allowlist::PeerAllowlist;
use p2p::anti_entropy::RecordEstimate;
use p2p::gossip::make_supply_entry;
use p2p::orphan_buffer::{OrphanBuffer, OrphanInsert};
use p2p::protocol::{
    is_content_id, WireMessage, CONTENT_ID_LEN, MAX_HAVE_HEADS, MAX_MESSAGE_SIZE,
    MAX_SUPPLY_ENTRIES,
};
use p2p::union_merge::{
    validate_supply_entry, verify_author_allowlisted, verify_remote_signature, MergeError,
};

/// Cap on DISTINCT ids accumulated across one peer's paginated `HaveHeads`
/// advert (H-02).
///
/// Pagination lets an honest peer advertise a ledger of any size, but it also
/// lets a malicious one stream pages forever. A million ids is far past any
/// ledger the 64 MiB file cap permits, so honest peers never approach it.
///
/// Counted per distinct id since T41 — see [`read_have_heads_advert`] for why
/// counting repeats instead made the cap answer the wrong question.
const MAX_ACCUMULATED_HAVE_HEADS: usize = 1_048_576;

/// Default cap on the PAGES one peer's advert may span (H-10, M-26).
///
/// Derived, not chosen. `paginate_have_heads` fills every page but the last, so
/// advertising the `MAX_ACCUMULATED_HAVE_HEADS` ids the count cap already allows
/// takes exactly `MAX_ACCUMULATED_HAVE_HEADS / MAX_HAVE_HEADS` pages. Doubling
/// that is headroom for a sender that pages less tightly than ours does; ours
/// never needs it, because it pages the longer list and lets the shorter run dry.
///
/// This is the bound T41 removed without meaning to. Counting DISTINCT ids made
/// `MAX_ACCUMULATED_HAVE_HEADS` mean what its rustdoc says — but it was also the
/// only thing that ended the `more: true` loop, and a page that repeats ids, or
/// carries none at all, advances a distinct-id count by zero. Pages are the
/// right quantity to count precisely because a peer cannot make one free: every
/// page is a frame it had to send, whatever is in it.
const MAX_ADVERT_PAGES: usize = 2 * MAX_ACCUMULATED_HAVE_HEADS.div_ceil(MAX_HAVE_HEADS);

/// Default cap on the bytes of DISTINCT advertised id text one exchange retains
/// (M-26).
///
/// `MAX_ACCUMULATED_HAVE_HEADS` bounds a COUNT, and until T49 nothing anywhere
/// bounded an advertised id's LENGTH — so a million 255-byte ids put ~1.7 GB
/// live behind that count, and pages of a single ~1 MiB "id" (comfortably under
/// `NON_SUPPLY_FRAME_CAP`) cost ~2 MiB resident each while barely moving it. The
/// anti-entropy loop runs one exchange per allowlisted peer, so whatever one
/// peer can pin, N peers pin N times.
///
/// Sized off the form rule rather than guessed: [`check_advert_ids`] refuses
/// anything but a 64-lowercase-hex content id, so `MAX_ACCUMULATED_HAVE_HEADS`
/// ids is exactly 64 MiB of id text. Charged once per distinct id across BOTH
/// lists, which makes it strictly tighter than the per-list count cap it backs
/// up — deliberately, because heads are a subset of directive ids (L-21), so an
/// honest advert is about one id per directive rather than two. A ledger at the
/// file-size cap holds a few hundred thousand directives (each carries an
/// author, a lamport and a 128-hex signature on disk), i.e. ~15 MiB of id text:
/// several times inside this.
///
/// Stated in bytes rather than left implied by the form rule, because it is the
/// bound that still holds if the form rule is ever relaxed — which Format v2
/// (T45) may well do. Live cost is a small multiple of it: `absorb_page` keeps
/// each id in both the accumulator and the dedup set, and `compute_want` clones
/// again.
const MAX_ADVERT_ID_BYTES: usize = MAX_ACCUMULATED_HAVE_HEADS * CONTENT_ID_LEN;

/// Byte cap for any inbound frame that is not a `Supply` (M-16).
///
/// Only `Supply` legitimately reaches multi-MiB. The largest `HaveHeads` page
/// is ~4096 + 4096 ids × ~66 B ≈ 540 KiB, a full `Want` is ≤ ~68 KiB, and an
/// `Announce` is tiny. 1 MiB leaves generous headroom for all of those while
/// letting `read_message` reject a bloated `Want`/`HaveHeads` vector from a
/// ~13-byte peek — before allocating its body or letting serde's
/// internally-tagged decode buffer ~16.7M ids into a `Content` tree.
const NON_SUPPLY_FRAME_CAP: usize = 1024 * 1024;

/// How long a closing session waits for the peer to acknowledge what it was
/// already sent (T41).
///
/// Bounds the tidy-close drain in `serve_anti_entropy`. Short on purpose: it is
/// spent holding a serve task and an M-16 `ConnectionLimiter` slot, and nothing
/// is lost if it expires — anti-entropy is idempotent, so a reply the peer never
/// finished receiving is simply re-Wanted on the next exchange.
const CLOSE_DRAIN: Duration = Duration::from_secs(5);

/// Application close code for an inbound session ended by its deadline (M-40).
///
/// Distinct from the others this module sends (1 not allowlisted, 2 connection
/// limit, 3 `accept_bi` timeout, 4 request budget, 6 accept rate — see
/// [`crate::connection_limiter::Refusal`]) so a peer, and a test, can tell a
/// session that ran out of wall-clock from every other ending.
const SESSION_DEADLINE_CLOSE_CODE: u32 = 5;

/// Close reason sent with [`SESSION_DEADLINE_CLOSE_CODE`].
const SESSION_DEADLINE_CLOSE_REASON: &[u8] = b"session-deadline";

/// Chunk size for the incremental body read (L-19).
///
/// The body is appended chunk by chunk so a stalled stream pins only the bytes
/// actually received, never `vec![0u8; len]` reserved up front.
const READ_CHUNK: usize = 64 * 1024;

/// How long a peer's `Supply` is not applied after one of its batches was
/// deferred because it would not fit under the ledger's size cap (M-39, T69).
///
/// Long enough that a node at the cap stops re-pulling, re-validating and —
/// before T69 — re-booting its whole ledger once per tick per peer; short
/// enough that the node resumes on its own within a minute of an operator
/// making room (an archive and restart, or the next compaction folding a
/// journal). One tick of the default interval costs a head exchange, which the
/// backoff does not suppress: the advert is still sent and read, only the
/// Want/Supply half is skipped.
///
/// The DEFAULT of [`AntiEntropyTimeouts::supply_backoff`]; since T71
/// `p2p.antiEntropySupplyBackoffSeconds` sets the value a node runs under
/// (floor 5 s, ceiling 1 h — see `config.rs`).
pub const SUPPLY_HEADROOM_BACKOFF: Duration = Duration::from_secs(60);

/// Upper bound on [`SupplyBackoff`]'s per-peer entries (each of its maps).
/// Keys are allowlisted peers (the only ones whose `Supply` is ever applied),
/// so this is never reached by an honest configuration; it exists so that the
/// maps are bounded by construction rather than by the allowlist's size.
const SUPPLY_BACKOFF_MAX_PEERS: usize = 4_096;

/// Upper bound on ratchet-deferred ids remembered per peer (T72 / L-69).
///
/// The audit's measured shape was 4,096 manufactured refusals per hostile
/// peer; at one 64-hex id plus a `u64` each this is ~400 KiB per peer at the
/// cap, and past it a peer's further refusals are simply re-fetched as before
/// (bounded degradation, no eviction of what is already known).
const RATCHET_DEFERRED_MAX_IDS_PER_PEER: usize = 4_096;

/// One "rejected remote directive" warn line per peer per this interval
/// (T72 / L-69) — the M-40 rule (`ConnectionLimiter::should_log_refusal`)
/// applied to stage refusals, which a peer can manufacture at will.
const STAGE_REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Transient, per-peer "do not apply this peer's `Supply` yet" (M-39, T69).
///
/// Near the 64 MiB cap a peer's batch cannot be made durable: the append arm's
/// projection refuses it deterministically. Before T69 every such batch was
/// staged, failed its prepare, and was rolled back by a full reload under the
/// write lock; nothing was remembered, so the next tick re-Wanted the same ids
/// and did it again, forever. `apply_supply_entries_from` now asks the service
/// for its [`ledger::service::LedgerService::append_headroom`] before staging
/// and, when the batch cannot fit, defers it and arms this backoff for the
/// peer that served it.
///
/// T77 / L-70 widened what arms it: a pre-stage deferral (the chunk's exact
/// journal record does not fit), a drain that had to leave freed orphans
/// unstaged for want of room, and ANY prepare or commit refused by the cap —
/// so no near-cap path can cost a reload per tick.
///
/// Deliberately **not** the L-34 refusal cache: nothing about these entries is
/// wrong, and the condition clears the moment the operator makes room. An
/// entry in the refusal cache is a verdict on an id; this is a verdict on the
/// ledger's current size, so it is keyed by peer, expires on its own, and
/// records no id.
///
/// # Two more per-peer deferrals live here (T72 / L-69)
///
/// Same shape — transient, per peer, not a verdict on the directive — so they
/// share the type rather than adding fields to [`AntiEntropyHandler`]:
///
/// * **The ratchet short-circuit** ([`Self::defer_ratcheted`],
///   [`Self::retain_not_ratcheted`]). `ServiceError::LamportAdvance` is
///   state-dependent, so the L-34 cache must not hold it — but it is a pure
///   function of `(remote lamport, local clock)`: refused iff `remote − local
///   ≥ MAX_LAMPORT_ADVANCE`, and the local clock only rises. So the verdict
///   for an id this peer served cannot change until the clock reaches
///   `remote − MAX_LAMPORT_ADVANCE + 1`, and until then re-Wanting it buys
///   nothing but the fetch, parse, verify and validate it cost the first time
///   (the audit measured 32 × 1 MiB manufactured refusals at 2.73 s per tick
///   plus 30 MiB of transfer, per hostile peer, indefinitely). Each refused id
///   is remembered with that clock threshold and dropped from the Want while
///   the clock is below it. This is exact, not a heuristic: a node climbing
///   through a history re-Wants each id on the first tick at which it can be
///   adopted. Keyed by peer for the L-34 reason (a different peer's copy can
///   carry a different envelope).
/// * **The stage-refusal warn throttle** ([`Self::should_log_stage_refusal`]).
///   One line per peer per [`STAGE_REFUSAL_LOG_INTERVAL`], carrying the count
///   suppressed since the last — the M-40 rule, since a peer can manufacture
///   refusals as fast as it can serve them.
#[derive(Clone, Debug, Default)]
pub struct SupplyBackoff {
    until: Arc<std::sync::Mutex<std::collections::HashMap<EndpointId, std::time::Instant>>>,
    /// L-69: per peer, id → the local clock at which the ratchet verdict can
    /// change (`remote − MAX_LAMPORT_ADVANCE + 1`).
    ratcheted: Arc<std::sync::Mutex<std::collections::HashMap<EndpointId, RatchetDeferred>>>,
    /// L-69: per peer, the stage-refusal warn throttle.
    refusal_log: Arc<std::sync::Mutex<std::collections::HashMap<EndpointId, StageRefusalLog>>>,
}

/// Per-peer state behind [`SupplyBackoff::defer_ratcheted`].
type RatchetDeferred = std::collections::HashMap<String, u64>;

/// Per-peer state behind [`SupplyBackoff::should_log_stage_refusal`].
#[derive(Debug, Default)]
struct StageRefusalLog {
    last_logged: Option<std::time::Instant>,
    suppressed: u64,
}

impl SupplyBackoff {
    /// Whether `peer`'s `Supply` is currently deferred.
    pub fn is_active(&self, peer: EndpointId, now: std::time::Instant) -> bool {
        self.lock().get(&peer).is_some_and(|until| *until > now)
    }

    /// Remember that `peer`'s copy of `id` was refused by the adoption ratchet
    /// against `remote_lamport` (T72 / L-69): it is not worth re-Wanting until
    /// the local clock reaches `remote_lamport − MAX_LAMPORT_ADVANCE + 1`.
    ///
    /// Exact by construction: adoption refuses iff `remote − local ≥
    /// MAX_LAMPORT_ADVANCE` (`ledger::service::check_lamport_advance`), so the
    /// first clock at which it can succeed is that threshold. Bounded per peer
    /// by [`RATCHET_DEFERRED_MAX_IDS_PER_PEER`] and across peers by
    /// [`SUPPLY_BACKOFF_MAX_PEERS`]; at either cap nothing is recorded, which
    /// only costs the re-fetch this exists to avoid.
    pub fn defer_ratcheted(&self, peer: EndpointId, id: String, remote_lamport: u64) {
        let acceptable_at = remote_lamport
            .saturating_sub(ledger::service::MAX_LAMPORT_ADVANCE)
            .saturating_add(1);
        let mut peers = self.lock_ratcheted();
        if peers.len() >= SUPPLY_BACKOFF_MAX_PEERS && !peers.contains_key(&peer) {
            return;
        }
        let deferred = peers.entry(peer).or_default();
        if deferred.len() >= RATCHET_DEFERRED_MAX_IDS_PER_PEER && !deferred.contains_key(&id) {
            return;
        }
        deferred.insert(id, acceptable_at);
    }

    /// Drop from `want` every id whose ratchet refusal from `peer` cannot yet
    /// have changed at `local_clock` (T72 / L-69), returning how many were
    /// dropped. Entries the clock has reached are forgotten here, so an id
    /// becomes Wantable on the first tick at which it is adoptable.
    pub fn retain_not_ratcheted(
        &self,
        peer: EndpointId,
        want: &mut Vec<String>,
        local_clock: u64,
    ) -> usize {
        let mut peers = self.lock_ratcheted();
        let Some(deferred) = peers.get_mut(&peer) else {
            return 0;
        };
        deferred.retain(|_, acceptable_at| *acceptable_at > local_clock);
        if deferred.is_empty() {
            peers.remove(&peer);
            return 0;
        }
        let before = want.len();
        want.retain(|id| !deferred.contains_key(id));
        before - want.len()
    }

    /// How many ids `peer`'s ratchet short-circuit currently holds (tests).
    #[cfg(test)]
    fn ratcheted_count(&self, peer: EndpointId) -> usize {
        self.lock_ratcheted()
            .get(&peer)
            .map_or(0, |deferred| deferred.len())
    }

    /// Whether a stage refusal from `peer` happening at `now` should be logged
    /// (T72 / L-69), and if so how many were swallowed since the last logged
    /// one. One line per peer per [`STAGE_REFUSAL_LOG_INTERVAL`].
    pub fn should_log_stage_refusal(
        &self,
        peer: EndpointId,
        now: std::time::Instant,
    ) -> Option<u64> {
        let mut logs = self
            .refusal_log
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if logs.len() >= SUPPLY_BACKOFF_MAX_PEERS && !logs.contains_key(&peer) {
            // Unreachable with any real allowlist; an unthrottled peer at the
            // cap is one line per refusal, which is what M-40 accepted before.
            return Some(0);
        }
        let log = logs.entry(peer).or_default();
        match log.last_logged {
            Some(previous)
                if now.saturating_duration_since(previous) < STAGE_REFUSAL_LOG_INTERVAL =>
            {
                log.suppressed = log.suppressed.saturating_add(1);
                None
            }
            _ => {
                log.last_logged = Some(now);
                Some(std::mem::take(&mut log.suppressed))
            }
        }
    }

    fn lock_ratcheted(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<EndpointId, RatchetDeferred>> {
        self.ratcheted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Defer `peer`'s `Supply` for `backoff` from `now` — the handler's
    /// [`AntiEntropyTimeouts::supply_backoff`], [`SUPPLY_HEADROOM_BACKOFF`] by
    /// default (T71: configurable, so the map records a deadline, not a rule).
    fn arm(&self, peer: EndpointId, now: std::time::Instant, backoff: Duration) {
        let mut until = self.lock();
        until.retain(|_, expires| *expires > now);
        if until.len() >= SUPPLY_BACKOFF_MAX_PEERS && !until.contains_key(&peer) {
            // Unreachable with any real allowlist; refuse to grow rather than
            // evict, since a missed backoff costs one deferred batch.
            return;
        }
        until.insert(peer, now + backoff);
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<EndpointId, std::time::Instant>> {
        self.until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The bounds ONE outbound anti-entropy session runs under (M-06, H-10, M-26,
/// M-27, M-28).
///
/// Without the two original timeouts a peer that accepts a connection and then
/// never sends stalls the session — and, before the loop was made concurrent,
/// all replication (M-06). The four bounds T49 added answer the opposite shape:
/// a peer that is never silent, and holds a session open frame by frame
/// forever. `io` cannot see that peer at all, because every frame refreshes it.
///
/// The type name predates those four and is kept deliberately. Read it as "the
/// settings one outbound session runs under", of which two happen to be
/// timeouts; renaming would touch construction sites in `main.rs` and buy
/// nothing this doc comment does not.
///
/// Defaults are deliberately generous — a full 16 MiB `Supply` frame transfers
/// well within 30s on any real link, and every count below is an order of
/// magnitude past what an honest peer at the ledger's own size limits needs.
/// They are struct fields rather than constants for the reason T24/T26's limits
/// are: tests drive them now, config drives them later (T38).
#[derive(Clone, Copy, Debug)]
pub struct AntiEntropyTimeouts {
    /// Cap on establishing a QUIC connection to a peer.
    pub connect: Duration,
    /// Cap on a single frame read or write.
    pub io: Duration,
    /// Cap on opening one bi-stream on an ALREADY-established connection (M-27).
    ///
    /// Its own knob rather than a reuse of `connect` or `io`, because it bounds
    /// a third resource: QUIC bidirectional-stream credit, which the REMOTE
    /// grants. `open_bi` pends on `stream_budget_available[Bi]` (verified in
    /// vendored `noq-1.1.0/src/connection.rs:1007-1046`), so a peer advertising
    /// `initial_max_streams_bidi = 0` — the default is 100 — and then holding
    /// the connection open with keep-alives parks the caller forever, with no
    /// dial and no frame in flight for either of the other two to bound.
    pub open_stream: Duration,
    /// Cap on ONE whole exchange, start to finish (H-10, M-28).
    ///
    /// The bound `io` is not. `io` is per-frame and every frame refreshes it, so
    /// any peer willing to keep answering — even with ~40 bytes of empty
    /// `HaveHeads` page — holds a session indefinitely without ever once
    /// "stalling".
    ///
    /// Enforced as a DEADLINE that the session's own reads and writes are
    /// clamped against, never as a `timeout()` wrapped around the exchange
    /// future. That distinction is load-bearing: `apply_supply_entries` commits
    /// through `ledger_commit::commit_pending`, and dropping that future
    /// mid-commit is exactly H-11's wedge — the `spawn_blocking` write still
    /// lands while the bookkeeping that clears `commit_in_flight` never runs. A
    /// deadline checked at I/O boundaries can only end a session BETWEEN frames,
    /// where there is nothing half-done to leave behind.
    ///
    /// T50 closed H-11, so that constraint no longer binds: the commit owns the
    /// write permit and detaches rather than cancels, and the in-flight flag is
    /// released by a `Drop` guard, so dropping an exchange future mid-commit
    /// leaves nothing half-done either. The deadline is kept in this shape
    /// anyway — it is strictly the gentler of the two, it ends a session at a
    /// point where the peer's next frame is the only thing lost, and a
    /// `timeout()` would now be a tightening rather than a fix. T49's residual
    /// 3 is what to reopen if that tightening is ever wanted.
    ///
    /// Five minutes is far past any honest exchange (a catch-up of the whole
    /// file-size cap is tens of seconds of transfer), and cutting one short
    /// costs nothing anyway: anti-entropy is idempotent and incremental, so the
    /// next tick resumes where this one stopped.
    ///
    /// Since T70 it bounds the INBOUND side too (M-40): `serve_anti_entropy`
    /// builds a [`SessionBudget`] from this at accept, and every `accept_bi`
    /// wait and every frame it reads or writes runs under `min(io, time left)`.
    /// Before that the server had only the per-frame `io` and the frame budget,
    /// so one ~30-byte `Announce` every 29 s held a serve task and an M-16 slot
    /// for 100,000 × 29 s ≈ 34 days, and eight peers could pin all 256 slots.
    /// One value for both sides, so "the client mirrors the server" (M-28) holds
    /// in both directions; `p2p.antiEntropySessionSeconds` sets it (R-7).
    pub session: Duration,
    /// Pages one peer's `HaveHeads` advert may span — see [`MAX_ADVERT_PAGES`].
    pub max_advert_pages: usize,
    /// Distinct advertised id bytes one exchange may retain — see
    /// [`MAX_ADVERT_ID_BYTES`].
    pub max_advert_id_bytes: usize,
    /// Frames one outbound session may read or write (M-28).
    ///
    /// The client-side mirror of the server's `max_requests_per_connection`,
    /// taken from it below so the two cannot drift, and a backstop rather than a
    /// tight limit for the same reason T24 gives. The client had NO such bound,
    /// which is what let a peer advertising a million ids drive 4,096 `Want`
    /// chunks of up to 256 rounds each — every round comfortably inside its
    /// per-frame timeout, the whole thing days long, and (before the drain fix)
    /// holding every other peer's replication hostage while it ran.
    ///
    /// An honest full catch-up at the accumulation cap spends ~8,700 frames: 256
    /// advert pages each way, then one `Want` and one `Supply` per 256-id chunk.
    pub max_session_frames: usize,
    /// How long a peer's `Supply` stays deferred after one of its batches did
    /// not fit under the ledger's size cap (M-39) — see
    /// [`SUPPLY_HEADROOM_BACKOFF`] for the default's reasoning. A field rather
    /// than the constant so `p2p.antiEntropySupplyBackoffSeconds` can set it
    /// (T71); it applies to every Supply this node applies, fetched or pushed.
    pub supply_backoff: Duration,
}

impl Default for AntiEntropyTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            io: Duration::from_secs(30),
            open_stream: Duration::from_secs(10),
            session: Duration::from_secs(300),
            max_advert_pages: MAX_ADVERT_PAGES,
            max_advert_id_bytes: MAX_ADVERT_ID_BYTES,
            // Read off the server-side limit rather than restated, so "mirrors
            // the server's budget" stays true by construction (M-28).
            max_session_frames: AntiEntropyLimits::default().max_requests_per_connection,
            supply_backoff: SUPPLY_HEADROOM_BACKOFF,
        }
    }
}

/// What one outbound exchange has left to spend (H-10, M-28).
///
/// Built once per session and threaded through every frame it reads or writes,
/// so the session's total time and total frames are bounded even though no
/// single frame ever exceeds its own limit. [`Self::charge_frame`] is the only
/// way to obtain a timeout on this path, which is what makes the accounting
/// unskippable: a new read or write that forgets to charge does not compile.
///
/// Deliberately NOT a `tokio::time::timeout` around the whole exchange — see
/// [`AntiEntropyTimeouts::session`] for why cancelling this future mid-commit is
/// the wrong shape (H-11).
struct SessionBudget {
    /// When this session must be over, whatever it is in the middle of.
    deadline: tokio::time::Instant,
    /// Frames left to read or write (M-28).
    frames_left: usize,
    /// Per-frame cap; every timeout handed out is `min(io, time left)`.
    io: Duration,
    /// Advert page cap, carried so the advert reader needs one argument (M-26).
    max_advert_pages: usize,
    /// Advert id-byte cap, likewise (M-26).
    max_advert_id_bytes: usize,
}

impl SessionBudget {
    fn new(timeouts: &AntiEntropyTimeouts) -> Self {
        Self {
            deadline: tokio::time::Instant::now() + timeouts.session,
            frames_left: timeouts.max_session_frames,
            io: timeouts.io,
            max_advert_pages: timeouts.max_advert_pages,
            max_advert_id_bytes: timeouts.max_advert_id_bytes,
        }
    }

    /// Charge one frame and return the timeout it is allowed to run under.
    ///
    /// `min(io, time left)`, never a bare `io`: a frame started a millisecond
    /// before the deadline must not receive a fresh thirty seconds, which is
    /// precisely the shape H-10 exploited — every frame refreshing the only
    /// bound there was.
    fn charge_frame(&mut self) -> Result<Duration, String> {
        let Some(timeout) = self.clamped_io() else {
            return Err("anti-entropy session deadline reached".to_owned());
        };
        if self.frames_left == 0 {
            return Err("anti-entropy session frame budget exhausted".to_owned());
        }
        self.frames_left -= 1;
        Ok(timeout)
    }

    /// `min(io, time left)` WITHOUT charging a frame, or `None` once the
    /// deadline has passed.
    ///
    /// The one place the clamp is computed: [`Self::charge_frame`] uses it, and
    /// so does the server (M-40), which counts frames against its own T24/L-01
    /// request budget rather than `frames_left` — charging both would count
    /// every inbound frame twice against two limits meant to be one.
    fn clamped_io(&self) -> Option<Duration> {
        let remaining = self
            .deadline
            .saturating_duration_since(tokio::time::Instant::now());
        (!remaining.is_zero()).then(|| self.io.min(remaining))
    }

    /// True once the deadline has passed (M-40).
    fn expired(&self) -> bool {
        self.clamped_io().is_none()
    }
}

/// Shared handler registered on `openledger/anti-entropy/1`.
#[derive(Clone)]
pub struct AntiEntropyHandler {
    pub ledger: SharedLedger,
    pub broadcast: TransactionBroadcast,
    pub orphan_buffer: Arc<RwLock<OrphanBuffer>>,
    pub allowlist: PeerAllowlist,
    pub signing_enabled: bool,
    /// This node's mesh identity, bound into every signature check (L2, L-23).
    ///
    /// The value `main` resolved once from `p2p.meshId`, falling back to
    /// `p2p.swarmTopic`. Named for what it *is* rather than where it usually
    /// comes from: a verifier reconstructs the signed message with this string,
    /// so it must be the same value the local signer was built with, and
    /// nothing on this path may re-derive it from the gossip topic.
    pub mesh_id: String,
    /// Per-operation connect and I/O timeouts (M-06).
    pub timeouts: AntiEntropyTimeouts,
    /// Inbound connection + per-connection request limits (M-16, T24).
    ///
    /// `limits` and `limiter` are built from the same [`AntiEntropyLimits`] at
    /// construction; the loop reads `limits.max_requests_per_connection` while
    /// `accept` enforces the connection caps through the shared `limiter`.
    pub limits: AntiEntropyLimits,
    /// Shared connection admission control (M-16); clones share one budget.
    pub limiter: ConnectionLimiter,
    /// OUTBOUND per-peer connection reuse (T42); clones share one cache.
    ///
    /// Purely an optimization on the dial path: `fetch_want` and
    /// `exchange_with_peer` take their connection from here instead of dialling
    /// fresh every time. It has no bearing on the inbound side, which keeps
    /// every limit `limiter` and `limits` enforce.
    pub connections: PeerConnectionCache,
    /// Peers whose `Supply` is deferred because the ledger is at its size cap
    /// (M-39, T69); clones share one map. See [`SupplyBackoff`].
    pub supply_backoff: SupplyBackoff,
}

impl std::fmt::Debug for AntiEntropyHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AntiEntropyHandler")
            .field("signing_enabled", &self.signing_enabled)
            .finish_non_exhaustive()
    }
}

impl ProtocolHandler for AntiEntropyHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        if !self.allowlist.admits(remote) {
            // L-72: the refusal every dialer on a public bind can provoke, as
            // fast as it can handshake — so it is throttled like the limiter's
            // (one line per window for the whole not-allowlisted class, since
            // identities are free to mint; the count is reported when the
            // window closes) and it returns `Ok`, for the reason given below:
            // `Err` made iroh's router log a second, unthrottled line.
            connection.close(1u32.into(), b"not-allowlisted");
            if let Some(suppressed) = self
                .limiter
                .should_log_refusal(RefusalSource::NotAllowlisted, std::time::Instant::now())
            {
                warn!(
                    peer = %remote,
                    suppressed,
                    "rejecting anti-entropy connection not on bootstrap allowlist"
                );
            }
            return Ok(());
        }
        // M-16: bound concurrent inbound connections, globally and per peer;
        // M-40: and how often one peer may open them (the accept bucket). The
        // guard is held for the whole serve duration; its `Drop` releases the
        // global permit and decrements the per-peer count.
        //
        // A refusal must cost nothing past the handshake iroh already did: no
        // stream accepted, no byte read, no serve future, and — because a
        // reconnect loop can provoke refusals as fast as it can dial — no
        // per-refusal log line either. So it closes with the refusal's own code
        // and returns `Ok`: returning `Err` would make iroh's router emit an
        // unthrottled `warn!` for every refused connection, which is exactly
        // the log stream the throttle below exists to deny.
        let _connection_guard = match self.limiter.try_acquire(remote) {
            Ok(guard) => guard,
            Err(refusal) => {
                connection.close(refusal.close_code().into(), refusal.close_reason());
                // T77: throttled per `(peer, reason)`, so one peer's reconnect
                // loop does not hide another peer's refusal.
                if let Some(suppressed) = self.limiter.should_log_refusal(
                    RefusalSource::Peer(remote, refusal),
                    std::time::Instant::now(),
                ) {
                    warn!(
                        peer = %remote,
                        reason = ?refusal,
                        suppressed,
                        "rejecting anti-entropy connection: inbound limit reached"
                    );
                }
                return Ok(());
            }
        };
        if let Err(error) = serve_anti_entropy(self, connection, remote).await {
            warn!(peer = %remote, error = %log_error(&error), "anti-entropy inbound session failed");
            return Err(AcceptError::from_err(std::io::Error::other(error)));
        }
        Ok(())
    }
}

async fn serve_anti_entropy(
    handler: &AntiEntropyHandler,
    connection: Connection,
    remote: EndpointId,
) -> Result<(), String> {
    // M-40: the session's wall-clock bound, started at accept. `io` alone is
    // per-frame and every frame refreshes it, so before this a peer that never
    // stalled — one ~30-byte `Announce` every `io - 1` — held this task and its
    // M-16 slot for 100,000 frames × `io` ≈ 34 days. Every wait below (the
    // `accept_bi` for the next stream, each frame read, each reply written) now
    // runs under `min(io, time left)` from this budget, exactly as the client's
    // frames do via `charge_frame`, and a whole frame read is additionally cut
    // AT the deadline — see the read below. Its frame counter is unused here:
    // `requests_handled` is this side's frame budget (T24/L-01).
    //
    // Local work between I/O (`collect_supply`, the advert build, applying a
    // pushed `Supply`) is not interrupted — it is bounded by its own caps, and
    // ending a session only at an I/O boundary is the gentler shape
    // `AntiEntropyTimeouts::session` explains — so the worst case is the
    // deadline, plus one piece of that local work, plus `CLOSE_DRAIN`.
    let session = SessionBudget::new(&handler.timeouts);
    // T24: bound how many messages one connection may issue. This is a backstop
    // against an infinite/absurd flood on a single stream, not a tight limit —
    // the default (100_000) is far past any legitimate catch-up. A peer cut off
    // here can simply reconnect and anti-entropy resumes (it is idempotent).
    //
    // L-01: the budget counts every frame this connection causes — the ones it
    // sends AND the ones we send back — not just the ones it sends. Counting
    // only inbound frames left the read path disproportionate: a bare
    // `HaveHeads` advert is about thirty bytes and draws back our ENTIRE id
    // list, one page per `MAX_HAVE_HEADS` ids, and cost exactly one unit of
    // budget however many pages that was. On a million-directive ledger that is
    // ~245 pages (tens of MB) per thirty-byte request, repeatable 100,000 times
    // over one connection. Charging per frame written makes the reply's cost
    // scale with the reply, which is the only accounting under which the ratio
    // is bounded. Honest traffic is unaffected: a catch-up sends its advert
    // once, and 245 units out of 100,000 is noise.
    let mut requests_handled: usize = 0;
    // T42: a peer may now run SEVERAL operations over one connection, each on
    // its own bi-stream, so this serves streams until the connection ends
    // instead of serving exactly one and closing. Nothing above changes shape
    // for it: `requests_handled` stays a PER-CONNECTION budget spanning every
    // stream (making it per-stream would relax T24's cap by however many
    // streams a peer chose to open), and every read is still bounded by the
    // same I/O timeout.
    //
    // Streams are served one at a time, deliberately. Concurrency here would
    // multiply the M-16 memory bound: `ConnectionLimiter` caps concurrent
    // accepted CONNECTIONS precisely because each one can have a multi-MiB
    // `Supply` decode in flight, and N concurrent streams per connection would
    // make that N × the cap. The cost is head-of-line blocking between a peer's
    // own overlapping operations, which is bounded by their I/O timeouts and
    // which each peer inflicts only on itself.
    let mut streams_served: usize = 0;
    // The most recently finished send half, held for the tidy-close drain
    // below. Earlier streams were finished (their FIN is queued and their data
    // keeps flowing while the connection lives) and their peer had already read
    // every reply it asked for before it closed its half, so the stream that
    // can still have unacknowledged bytes when we close is the last one.
    let mut last_send: Option<SendStream> = None;
    // T41: how this session ended, so the close frame can say so. Returning from
    // `accept` used to just DROP the `Connection`, which closes it with a zero
    // code and no reason and does not wait for anything already written to be
    // acknowledged — the last Supply could be truncated on the wire. Harmless in
    // itself (anti-entropy is idempotent and the peer re-Wants on reconnect),
    // but it also meant a budget cut-off and an ordinary end of session looked
    // identical from the other end.
    //
    // Both ways out of the loop below name themselves, so the loop yields the
    // code and reason rather than defaulting to one: since T42 a peer ends a
    // connection it is done with by CLOSING it (handled above, nothing left for
    // us to say) or by leaving it idle, so there is no third "session complete"
    // ending left to describe.
    let (close_code, close_reason): (u32, &[u8]) = 'streams: loop {
        // T41: bound the wait for the peer's next bi-stream. `accept_bi()` has
        // no deadline of its own, so a peer that completes the QUIC handshake
        // and then opens nothing parked this serve task forever — and with it
        // the M-16 `ConnectionLimiter` guard held by `accept`, which is a
        // per-peer AND a global slot. Thirty-two such connections from one
        // allowlisted peer exhausted its share and starved every genuine
        // session from it, at the cost of a handshake each.
        //
        // Reusing the I/O timeout rather than the connect one: this is a wait
        // for the peer to say something on an established connection, which is
        // the same shape as a frame read, and the same value applies to it
        // (M-06). Since T42 the same bound applies to every SUBSEQUENT stream
        // too, which is what stops a reused connection from being parked
        // indefinitely — and what makes a pooled connection idle for longer
        // than this one dead on the client's next use of it.
        //
        // M-40: clamped to the session's time left. A deadline reached HERE,
        // between streams, is routine — see `session_deadline_between_streams`.
        let Some(accept_wait) = session.clamped_io() else {
            break session_deadline_between_streams(remote, streams_served);
        };
        let (mut send, mut recv) = match tokio::time::timeout(accept_wait, connection.accept_bi())
            .await
        {
            Ok(Ok(streams)) => streams,
            Ok(Err(error)) => {
                if streams_served == 0 {
                    return Err(error.to_string());
                }
                // The peer served its operations and then closed the
                // connection. That is an ordinary end of session, not a
                // failure, and there is nothing left to close.
                return Ok(());
            }
            Err(_elapsed) if session.expired() => {
                break session_deadline_between_streams(remote, streams_served);
            }
            Err(_elapsed) => {
                if streams_served == 0 {
                    // Close explicitly so the peer learns why rather than
                    // waiting out its own idle timeout, and so the limiter slot
                    // is released against a connection that is actually gone.
                    connection.close(3u32.into(), b"accept-bi-timeout");
                    return Err("anti-entropy peer opened no stream before the timeout".to_owned());
                }
                // A connection that DID serve work and then went idle is a
                // pooled connection its peer has finished with (T42). The same
                // timeout still fires and still closes it — only the verdict
                // differs, because reporting an error for every reused
                // connection's ordinary expiry would bury the T41 case above in
                // routine noise.
                break (3u32, b"accept-bi-timeout".as_slice());
            }
        };
        streams_served += 1;
        // The stream itself costs one budget unit (T42 review). Frames are
        // charged inside the loop below, but a stream that carries NO frame
        // would otherwise be free — and an endless supply of empty bi-streams,
        // each accepted within the timeout above, would hold this connection,
        // its serve task, and its M-16 limiter slot alive forever without the
        // T24 budget ever advancing. Honest cost is noise: one unit per
        // operation on top of that operation's own frames, against a budget of
        // 100,000.
        requests_handled = requests_handled.saturating_add(1);
        // How this stream ended the CONNECTION, if it did: the request budget
        // (T24) or the session deadline (M-40). `None` is an ordinary end of
        // stream, after which the peer may open another.
        let mut ended: Option<(u32, &[u8])> = None;
        'frames: loop {
            if requests_handled >= handler.limits.max_requests_per_connection {
                warn!(
                    peer = %remote,
                    limit = handler.limits.max_requests_per_connection,
                    "anti-entropy request budget exhausted; closing connection"
                );
                ended = Some((4u32, b"request-budget-exhausted".as_slice()));
                break;
            }
            // M-40: no new frame once the deadline has passed.
            let Some(frame_timeout) = session.clamped_io() else {
                ended = Some(session_deadline_mid_stream(handler, remote, streams_served));
                break;
            };
            // L-39: this frame's claim on the inbound byte budget. Held until
            // the end of this iteration — i.e. until the decoded message has
            // been handled — and released by `Drop` on every way out, including
            // the error returns below.
            let mut reservation = handler.limiter.frame_reservation(remote);
            // M-40: `frame_timeout` bounds each wait INSIDE the read (the length
            // prefix, the peek, every 64 KiB chunk), so on its own a frame
            // trickled one chunk per `io - 1` could outlive the deadline by up
            // to (1 MiB / 64 KiB) × `io` for a non-`Supply`, or 256 × `io` for a
            // `Supply`. `timeout_at` makes the deadline hard for the frame as a
            // whole. Dropping a half-read frame is safe — it is pure I/O into a
            // local buffer, its byte reservation is released by `Drop`, and the
            // connection is closed straight after — which is not true of the
            // handling below, and is why only the read is wrapped.
            let read = tokio::time::timeout_at(
                session.deadline,
                read_message(&mut recv, frame_timeout, &mut reservation),
            )
            .await;
            let message = match read {
                Ok(Ok(message)) => message,
                // T41: a typed clean shutdown, not a substring match on a
                // formatted error — see `FrameError` and `classify_read_error`.
                // Since T42 this ends the STREAM, not the connection: the peer
                // may open another one for its next operation.
                Ok(Err(FrameError::Eof)) => break,
                // A read timeout that the deadline clamp caused, or the deadline
                // itself, is the session ending — not a stalled peer.
                Err(_elapsed) => {
                    ended = Some(session_deadline_mid_stream(handler, remote, streams_served));
                    break;
                }
                Ok(Err(FrameError::Timeout)) if session.expired() => {
                    ended = Some(session_deadline_mid_stream(handler, remote, streams_served));
                    break;
                }
                Ok(Err(error)) => return Err(error.to_string()),
            };
            requests_handled += 1;
            match message {
                // A non-final page of the peer's advert (H-02): its content is
                // not used — we always answer with our own full state — so wait
                // for the final page and reply exactly once per advert, keeping
                // the session lockstep.
                WireMessage::HaveHeads { more: true, .. } => {}
                WireMessage::HaveHeads { .. } => {
                    let pages = local_have_heads_pages(&handler.ledger).await;
                    // L-01: charge for the whole advert before writing it.
                    requests_handled = requests_handled.saturating_add(pages.len());
                    for page in pages {
                        if !write_within_session(&mut send, &page, &session).await? {
                            ended =
                                Some(session_deadline_mid_stream(handler, remote, streams_served));
                            break 'frames;
                        }
                    }
                }
                WireMessage::Want { ids, .. } => {
                    // One Supply per Want, trimmed to what the requester can
                    // decode (H-02); it re-Wants any tail we could not fit.
                    // Already 1:1, so the L-01 charge below is the same unit the
                    // read already took. Trimmed WHILE collecting (L-33).
                    let reply = collect_supply(&handler.ledger, &ids).await;
                    requests_handled = requests_handled.saturating_add(1);
                    if !write_within_session(&mut send, &reply, &session).await? {
                        ended = Some(session_deadline_mid_stream(handler, remote, streams_served));
                        break 'frames;
                    }
                }
                WireMessage::Supply { entries, .. } => {
                    // A PUSHED Supply: this node Wanted none of it. Applied,
                    // but its refusals are never remembered (L-60) — see
                    // `SupplyOrigin::Pushed`.
                    apply_supply_entries_from(
                        handler,
                        entries,
                        remote,
                        SupplyOrigin::Pushed,
                        &mut reservation,
                    )
                    .await;
                }
                WireMessage::Announce { .. } => {
                    debug!(peer = %remote, "ignoring announce on anti-entropy ALPN");
                }
            }
        }
        // This stream is done. Finish our half before anything else so a reply
        // written under the last of the budget is not reset out from under the
        // peer, then go back for the peer's next operation (or, on a cut-off,
        // straight to the close below).
        let _ = send.finish();
        last_send = Some(send);
        if let Some(ending) = ended {
            break 'streams ending;
        }
    };
    // Give the peer a BOUNDED window to acknowledge what we already wrote, then
    // close explicitly with a code and a reason (T41). The drain is deliberately
    // its own short budget rather than `io_timeout`: a peer that stops reading
    // must not be able to hold the serve task — and the M-16 limiter slot with
    // it — for a full I/O timeout on the way out, which is the very thing the
    // `accept_bi` timeout above exists to prevent.
    //
    // Unchanged by the session deadline (M-40): a session that ran out of time
    // gets the same short drain after it, which is what bounds the whole serve
    // at `session + CLOSE_DRAIN` plus one piece of local work.
    if let Some(send) = last_send {
        let _ = tokio::time::timeout(CLOSE_DRAIN, send.stopped()).await;
    }
    connection.close(close_code.into(), close_reason);
    Ok(())
}

/// The session deadline ended an inbound session while it waited for the
/// peer's next stream (M-40): log it and name the close.
///
/// `debug!` only. This is where an honest pooled connection meets the deadline
/// — a tick interval shorter than `io` keeps it from ever idling out, so it
/// lives until the deadline and is closed here between operations — and the
/// peer's pool simply redials on its next use (T42). Nothing to warn about.
fn session_deadline_between_streams(
    remote: EndpointId,
    streams_served: usize,
) -> (u32, &'static [u8]) {
    debug!(
        peer = %remote,
        streams_served,
        "anti-entropy session deadline reached between streams; closing connection"
    );
    (SESSION_DEADLINE_CLOSE_CODE, SESSION_DEADLINE_CLOSE_REASON)
}

/// The session deadline ended an inbound session in the middle of a stream
/// (M-40): log it and name the close.
///
/// `warn!` rather than the `debug!` a deadline between streams gets, because an
/// honest operation is seconds long and meets the deadline mid-stream only by
/// the bad luck of straddling it, while a peer holding a stream open frame by
/// frame always does. Bounded twice: the fields are fixed-size, and one line per
/// connection at most, so its rate is at most `max_total_connections / session`.
fn session_deadline_mid_stream(
    handler: &AntiEntropyHandler,
    remote: EndpointId,
    streams_served: usize,
) -> (u32, &'static [u8]) {
    warn!(
        peer = %remote,
        session_secs = handler.timeouts.session.as_secs(),
        streams_served,
        "anti-entropy session deadline reached mid-stream; closing connection"
    );
    (SESSION_DEADLINE_CLOSE_CODE, SESSION_DEADLINE_CLOSE_REASON)
}

/// Write one reply under the inbound session's deadline (M-40).
///
/// `Ok(true)` once written; `Ok(false)` when the session deadline ended it —
/// before it started, or by the clamped timeout (or a failure that coincided
/// with the deadline) part way through — so the caller closes with the session
/// code rather than reporting a failed session; `Err` for any other failure,
/// exactly as `write_message` reported it before.
async fn write_within_session(
    send: &mut SendStream,
    message: &WireMessage,
    session: &SessionBudget,
) -> Result<bool, String> {
    let Some(timeout) = session.clamped_io() else {
        return Ok(false);
    };
    match write_message(send, message, timeout).await {
        Ok(()) => Ok(true),
        Err(_) if session.expired() => Ok(false),
        Err(error) => Err(error),
    }
}

/// One outbound operation's stream pair, plus the connection it runs over.
///
/// The connection is carried alongside so a failure mid-protocol can invalidate
/// exactly the connection it happened on (T42) — never a newer one another task
/// has since pooled for the same peer.
struct PeerSession {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
}

/// Why an outbound session could not be started (T42).
///
/// The variants exist to keep the pre-T42 log surfaces intact: a dial failure
/// and a dial timeout were reported differently by each call site, and a failure
/// to open the stream was reported as a session failure. Pooling changes which
/// of these can happen, not what any of them says.
enum SessionOpenError {
    Dial(String),
    DialTimeout,
    OpenStream(String),
}

impl From<AcquireError> for SessionOpenError {
    fn from(error: AcquireError) -> Self {
        match error {
            AcquireError::Dial(message) => Self::Dial(message),
            AcquireError::Timeout => Self::DialTimeout,
        }
    }
}

/// Take a connection to `addr` from the per-peer cache (dialling if needed) and
/// open this operation's bi-stream on it (T42).
///
/// The ONE re-dial an operation gets lives here, and only here: if opening the
/// stream fails on a connection that came OUT OF THE POOL, that connection is
/// stale, so it is invalidated and dialled again — once. A freshly dialled
/// connection that cannot open a stream is a genuine failure and is reported as
/// one, exactly as before T42; retrying it would turn one dial into two against
/// a peer that is simply unreachable.
///
/// The retry sits entirely BEFORE any frame is written or read, which is the
/// property that makes it safe to describe as transparent: no request has been
/// issued yet, so nothing can be issued twice. A connection that dies once the
/// protocol is under way is invalidated by the caller and the operation FAILS —
/// anti-entropy is idempotent and would survive a replay, but a silent replay
/// would double the work and the peer's request budget, and would hide a real
/// mid-transfer fault behind a retry.
async fn open_peer_session(
    endpoint: &iroh::Endpoint,
    handler: &AntiEntropyHandler,
    addr: iroh::EndpointAddr,
) -> Result<PeerSession, SessionOpenError> {
    let peer = addr.id;
    let acquired = handler
        .connections
        .acquire(
            endpoint,
            addr.clone(),
            &handler.allowlist,
            handler.timeouts.connect,
            Reuse::IfLive,
        )
        .await?;
    let open_error = match open_bi_bounded(&acquired.connection, handler.timeouts.open_stream).await
    {
        Ok((send, recv)) => {
            return Ok(PeerSession {
                connection: acquired.connection,
                send,
                recv,
            })
        }
        Err(error) => error,
    };
    if !acquired.reused {
        return Err(SessionOpenError::OpenStream(open_error));
    }
    handler.connections.invalidate(peer, &acquired.connection);
    debug!(
        peer = %peer,
        error = %open_error,
        "pooled anti-entropy connection was stale; re-dialing once"
    );
    let fresh = handler
        .connections
        .acquire(
            endpoint,
            addr,
            &handler.allowlist,
            handler.timeouts.connect,
            Reuse::Never,
        )
        .await?;
    match open_bi_bounded(&fresh.connection, handler.timeouts.open_stream).await {
        Ok((send, recv)) => Ok(PeerSession {
            connection: fresh.connection,
            send,
            recv,
        }),
        Err(error) => {
            handler.connections.invalidate(peer, &fresh.connection);
            Err(SessionOpenError::OpenStream(error))
        }
    }
}

/// Open one bi-stream, bounded by `open_stream` (M-27).
///
/// Both call sites above were bare `open_bi().await`. `open_bi` pends on the
/// REMOTE's bidirectional-stream credit — verified in vendored
/// `noq-1.1.0/src/connection.rs:1007-1046`, where `poll_open` waits on
/// `stream_budget_available[Bi]` — so a peer advertising
/// `initial_max_streams_bidi = 0` and then keeping the connection alive parks
/// the caller forever, with no dial in progress for `connect` to bound and no
/// frame in flight for `io` to bound. On the exchange path that was a second
/// route into H-10's wedge; on the gossip catch-up path the parked task never
/// reached its `drop(guard)`, leaking a `FetchCoordinator` permit and in-flight
/// entry permanently — sixteen such peers end announce-driven catch-up.
///
/// A timeout here is reported like any other open failure, which means a POOLED
/// connection that hits it is invalidated and re-dialled once (the caller's
/// existing rule). That is the right reading: a live connection whose peer will
/// not grant a stream is indistinguishable from a stale one, and a fresh
/// connection that does the same thing fails outright rather than retrying.
async fn open_bi_bounded(
    connection: &Connection,
    open_stream: Duration,
) -> Result<(SendStream, RecvStream), String> {
    match tokio::time::timeout(open_stream, connection.open_bi()).await {
        Ok(Ok(streams)) => Ok(streams),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_elapsed) => {
            Err("anti-entropy open_bi timed out: peer granted no stream credit".to_owned())
        }
    }
}

/// Fetch missing ids from an allowlisted peer (gossip Announce catch-up).
pub async fn fetch_want(
    endpoint: &iroh::Endpoint,
    peer: impl Into<iroh::EndpointAddr>,
    ids: Vec<String>,
    handler: &AntiEntropyHandler,
) {
    let peer_addr = peer.into();
    let peer = peer_addr.id;
    if ids.is_empty() || !handler.allowlist.admits(peer) {
        return;
    }
    // H-10/M-28: the session's clock and frame budget start HERE, before the
    // dial, so establishing the connection is spent out of the exchange's own
    // time rather than being free.
    let mut budget = SessionBudget::new(&handler.timeouts);
    let session = match open_peer_session(endpoint, handler, peer_addr).await {
        Ok(session) => session,
        Err(SessionOpenError::Dial(error)) => {
            warn!(peer = %peer, error = %log_error(&error), "anti-entropy connect failed");
            return;
        }
        Err(SessionOpenError::DialTimeout) => {
            warn!(peer = %peer, "anti-entropy connect timed out");
            return;
        }
        Err(SessionOpenError::OpenStream(error)) => {
            warn!(peer = %peer, error = %log_error(&error), "anti-entropy want session failed");
            return;
        }
    };
    let PeerSession {
        connection,
        mut send,
        mut recv,
    } = session;
    if let Err(error) =
        run_want_session(&mut send, &mut recv, ids, handler, peer, &mut budget).await
    {
        // The connection may be the reason this failed; either way the next
        // operation must not inherit it (T42). This drops only the cache's
        // handle — a concurrent operation on the same connection keeps running.
        handler.connections.invalidate(peer, &connection);
        warn!(peer = %peer, error = %log_error(&error), "anti-entropy want session failed");
    }
}

/// Periodic head exchange with one allowlisted peer.
pub async fn exchange_with_peer(
    endpoint: &iroh::Endpoint,
    peer: impl Into<iroh::EndpointAddr>,
    handler: &AntiEntropyHandler,
) {
    let peer_addr = peer.into();
    let peer = peer_addr.id;
    if !handler.allowlist.admits(peer) {
        return;
    }
    // H-10/M-28: see `fetch_want` — the budget covers the dial too.
    let mut budget = SessionBudget::new(&handler.timeouts);
    let session = match open_peer_session(endpoint, handler, peer_addr).await {
        Ok(session) => session,
        Err(SessionOpenError::Dial(error)) => {
            debug!(peer = %peer, %error, "anti-entropy exchange connect failed");
            return;
        }
        Err(SessionOpenError::DialTimeout) => {
            debug!(peer = %peer, "anti-entropy exchange connect timed out");
            return;
        }
        Err(SessionOpenError::OpenStream(error)) => {
            warn!(peer = %peer, error = %log_error(&error), "anti-entropy head exchange failed");
            return;
        }
    };
    let PeerSession {
        connection,
        mut send,
        mut recv,
    } = session;
    if let Err(error) = run_head_exchange(&mut send, &mut recv, handler, peer, &mut budget).await {
        handler.connections.invalidate(peer, &connection);
        warn!(peer = %peer, error = %log_error(&error), "anti-entropy head exchange failed");
    }
}

async fn run_want_session(
    send: &mut SendStream,
    recv: &mut RecvStream,
    ids: Vec<String>,
    handler: &AntiEntropyHandler,
    remote: EndpointId,
    budget: &mut SessionBudget,
) -> Result<(), String> {
    for chunk in ids.chunks(MAX_SUPPLY_ENTRIES) {
        fetch_want_chunk(send, recv, chunk, handler, remote, budget).await?;
    }
    // Finishing our half is what tells the server this operation is over, so it
    // can move on to the next stream on this connection (T42) instead of
    // waiting out its I/O timeout.
    let _ = send.finish();
    Ok(())
}

async fn run_head_exchange(
    send: &mut SendStream,
    recv: &mut RecvStream,
    handler: &AntiEntropyHandler,
    remote: EndpointId,
    budget: &mut SessionBudget,
) -> Result<(), String> {
    for page in local_have_heads_pages(&handler.ledger).await {
        let io = budget.charge_frame()?;
        write_message(send, &page, io).await?;
    }
    let (head_txids, directive_ids) = read_have_heads_advert(recv, remote, budget).await?;
    // M-39: a peer backed off at the size cap is not asked for anything; the
    // advert above still ran, so it still learns our heads.
    if handler
        .supply_backoff
        .is_active(remote, std::time::Instant::now())
    {
        debug!(peer = %remote, "not wanting from a peer backed off at the ledger size cap");
        let _ = send.finish();
        return Ok(());
    }
    // L-35 / R-19: membership, not two cloned sets. `all_directive_ids()`
    // cloned every id in the DAG into a fresh `HashSet` here, per peer per
    // tick, under the read lock; `contains_directive` is an O(1) lookup. And
    // a remote head is now checked against the whole DAG rather than our
    // heads alone (the T59 note), so a head we hold as an interior directive
    // is no longer re-wanted.
    let (mut want, local_clock) = {
        let svc = handler.ledger.read().await;
        (
            p2p::anti_entropy::compute_want_by_membership(
                |id| svc.contains_directive(id),
                &head_txids,
                &directive_ids,
            ),
            svc.lamport_clock(),
        )
    };
    // L-34: `compute_want` only diffs, so a directive this peer serves that we
    // refused FOR GOOD would otherwise be re-wanted, re-sent and re-validated on
    // every tick. Taken after the ledger guard is dropped, and only for a read.
    let suppressed = handler.orphan_buffer.read().await.refusals().retain_wanted(
        &remote.to_string(),
        &mut want,
        std::time::Instant::now(),
    );
    if suppressed > 0 {
        debug!(peer = %remote, suppressed, "not re-wanting directives this peer served that were refused for good");
    }
    // T88 / L-106: nor what can only wait on such a record — the buffered
    // descendants of a directive this peer served and this node refused for
    // good. Their missing parent is retried, never refused, so without this
    // the whole subtree was re-sent, re-parsed and re-verified every round.
    let doomed = handler.orphan_buffer.read().await.retain_not_doomed(
        &remote.to_string(),
        &mut want,
        std::time::Instant::now(),
    );
    if doomed > 0 {
        debug!(peer = %remote, doomed, "not re-wanting directives that can only wait on one this peer served and was refused for good");
    }
    // T72 / L-69: likewise for ids the adoption ratchet refused, while the
    // clock read above has not reached the point where that verdict can
    // change. Read under the same guard as the diff, so the two agree.
    let ratcheted = handler
        .supply_backoff
        .retain_not_ratcheted(remote, &mut want, local_clock);
    if ratcheted > 0 {
        debug!(peer = %remote, ratcheted, local_clock, "not re-wanting directives this peer served that the adoption ratchet refused at this clock");
    }
    // T83 / L-95: ask for known ancestors before their descendants, so a
    // chain longer than the orphan buffer arrives parent before child and
    // stages as it lands instead of crawling a few directives per round.
    {
        let buffer = handler.orphan_buffer.read().await;
        p2p::anti_entropy::order_want_ancestors_first(&mut want, |id| {
            buffer.known_missing_parents(id)
        });
    }
    for chunk in want.chunks(MAX_SUPPLY_ENTRIES) {
        fetch_want_chunk(send, recv, chunk, handler, remote, budget).await?;
    }
    // See `run_want_session`: the FIN is what releases the server's stream.
    let _ = send.finish();
    Ok(())
}

/// Append the ids of one advert page that have not been seen before (T41).
///
/// Order-preserving (first occurrence wins) so the accumulated advert is still
/// in the order the peer sent it, matching the dedup `compute_supply`'s
/// `compute_want` does downstream (L-21).
///
/// Returns the bytes of id text this page ADDED, which is what
/// [`read_have_heads_advert`] charges against `max_advert_id_bytes` (M-26). A
/// repeat costs nothing because it retains nothing — the same reasoning that
/// makes the distinct-id cap correct, applied to bytes.
fn absorb_page(into: &mut Vec<String>, seen: &mut HashSet<String>, page: Vec<String>) -> usize {
    let mut retained = 0usize;
    for id in page {
        if seen.insert(id.clone()) {
            retained = retained.saturating_add(id.len());
            into.push(id);
        }
    }
    retained
}

/// Refuse an advert page carrying anything that is not a content id (M-26, L-53).
///
/// Every id a peer can legitimately advertise is a SHA-256 content id:
/// `ledger::hash::compute_content_id` returns 64 lowercase hex characters, and
/// nothing else ever reaches `head_txids()` or `all_directive_ids()`. So this is
/// the rule `openledger-parents` has had since L-29, applied to the other place
/// a peer hands us ids — and it is also what turns `max_advert_id_bytes` from a
/// guess into arithmetic.
///
/// Refuses the whole advert rather than filtering the offending ids. A peer that
/// advertises a non-id is not a peer with one bad row, and filtering would leave
/// the exchange looking successful while the two nodes silently disagree about
/// what was offered. An honest peer cannot produce one.
///
/// The offending id is NOT logged — only its length. It is attacker-chosen and
/// may be most of a megabyte; the same reasoning as `protocol`'s decode-error
/// elision.
fn check_advert_ids(remote: EndpointId, ids: &[String]) -> Result<(), String> {
    match ids.iter().find(|id| !is_content_id(id)) {
        Some(malformed) => Err(format!(
            "peer {remote} advertised a malformed id: {} bytes (expected {CONTENT_ID_LEN} lowercase hex)",
            malformed.len()
        )),
        None => Ok(()),
    }
}

/// Read one peer's `HaveHeads` advert, following `more` pages (H-02).
///
/// Returns the accumulated head txids and directive ids, **deduplicated**
/// across pages, preserving first-occurrence order.
///
/// T41: accumulation used to be a plain `extend`, so `MAX_ACCUMULATED_HAVE_HEADS`
/// counted duplicates. That made the cap answer the wrong question in both
/// directions. A peer could replay one page — even one id — indefinitely and be
/// cut off at a million *repeats* rather than a million distinct ids, so the cap
/// bounded nothing about how much state it was actually advertising; and an
/// honest peer with a large ledger whose pages happened to overlap could be
/// refused for advertising far fewer than a million real ids. Deduping at
/// accumulation makes the cap mean what its rustdoc says, and `compute_want`
/// downstream is unaffected — it deduped already (L-21), which is why this was
/// harmless rather than a live bug.
///
/// H-10: it was not harmless. That fix also removed the loop's ONLY bound. The
/// exits were `more == false`, a read error, and the distinct-id cap — and a
/// peer replying `HaveHeads { head_txids: [], directive_ids: [], more: true }`
/// (about forty CBOR bytes, decoding cleanly because both fields are
/// `#[serde(default)]`) grows neither accumulator, so the cap never fires.
/// Infinite loop, for ~40 bytes, repeatable forever. `io` did not rescue it:
/// it is per-frame, and every frame refreshed it. And the blast radius was the
/// whole subsystem, not one peer — `run_head_exchange` never returned, so the
/// tick's `JoinSet` drain never returned, so no further tick ever ran.
///
/// The loop now carries four bounds, three of which a repeated page cannot
/// dodge because none of them is a function of the ids it carries: the session
/// deadline and frame budget ([`SessionBudget`]) and `max_advert_pages`. The
/// fourth, `max_advert_id_bytes`, together with the 64-hex form check, bounds
/// what the ids themselves can cost (M-26, L-53).
async fn read_have_heads_advert(
    recv: &mut RecvStream,
    remote: EndpointId,
    budget: &mut SessionBudget,
) -> Result<(Vec<String>, Vec<String>), String> {
    let mut head_txids: Vec<String> = Vec::new();
    let mut directive_ids: Vec<String> = Vec::new();
    let mut seen_heads: HashSet<String> = HashSet::new();
    let mut seen_directives: HashSet<String> = HashSet::new();
    let mut pages: usize = 0;
    let mut retained_bytes: usize = 0;
    loop {
        let io_timeout = budget.charge_frame()?;
        let WireMessage::HaveHeads {
            head_txids: page_heads,
            directive_ids: page_directives,
            more,
            ..
        } = read_message(recv, io_timeout, &mut FrameReservation::unmetered())
            .await
            .map_err(|error| error.to_string())?
        else {
            return Err("expected HaveHeads from peer".to_owned());
        };
        // H-10: charged BEFORE anything looks at the page's contents, so an
        // empty page costs exactly as much as a full one. This is the bound
        // that a peer sending nothing cannot avoid paying.
        pages += 1;
        if pages > budget.max_advert_pages {
            return Err(format!(
                "peer {remote} sent more than {} HaveHeads pages in one advert",
                budget.max_advert_pages
            ));
        }
        check_advert_ids(remote, &page_heads)?;
        check_advert_ids(remote, &page_directives)?;
        retained_bytes = retained_bytes
            .saturating_add(absorb_page(&mut head_txids, &mut seen_heads, page_heads))
            .saturating_add(absorb_page(
                &mut directive_ids,
                &mut seen_directives,
                page_directives,
            ));
        if retained_bytes > budget.max_advert_id_bytes {
            return Err(format!(
                "peer {remote} advertised more than {} bytes of distinct ids",
                budget.max_advert_id_bytes
            ));
        }
        if head_txids.len() > MAX_ACCUMULATED_HAVE_HEADS
            || directive_ids.len() > MAX_ACCUMULATED_HAVE_HEADS
        {
            return Err(format!(
                "peer {remote} advertised more than {MAX_ACCUMULATED_HAVE_HEADS} distinct ids"
            ));
        }
        if !more {
            return Ok((head_txids, directive_ids));
        }
    }
}

/// Request one chunk of ids and drain the peer's replies (H-02).
///
/// A `Supply` may be a strict prefix of what was asked — the peer trims to its
/// frame budget — so re-`Want` whatever did not arrive until a round makes no
/// progress. Progress is measured against the ids the peer *served*, not the
/// ones we accepted: an entry we reject as invalid must end the loop, not spin
/// it forever.
async fn fetch_want_chunk(
    send: &mut SendStream,
    recv: &mut RecvStream,
    chunk: &[String],
    handler: &AntiEntropyHandler,
    remote: EndpointId,
    budget: &mut SessionBudget,
) -> Result<(), String> {
    let mut remaining: Vec<String> = chunk.to_vec();
    while !remaining.is_empty() {
        // M-39: once a batch from this peer has been deferred at the size
        // cap, stop pulling: the next round (or chunk) would be deferred too,
        // after transferring up to a full Supply frame for nothing.
        if handler
            .supply_backoff
            .is_active(remote, std::time::Instant::now())
        {
            return Ok(());
        }
        // M-28: the round loop below makes progress by construction, but only
        // one id per round in the worst case — 256 rounds per chunk, 4,096
        // chunks for an advert at the accumulation cap. Charging every frame
        // puts the whole of that under one budget and one deadline.
        let io_timeout = budget.charge_frame()?;
        write_message(send, &WireMessage::want(remaining.clone()), io_timeout).await?;
        let io_timeout = budget.charge_frame()?;
        let entries = match read_message(recv, io_timeout, &mut FrameReservation::unmetered())
            .await
            .map_err(|error| error.to_string())?
        {
            WireMessage::Supply { entries, .. } => entries,
            other => {
                // M-41: the variant, never the frame — `?other` rendered a
                // 4,096-id advert page into one log line the peer wrote.
                warn!(peer = %remote, frame = other.variant_name(), "expected Supply after Want");
                return Ok(());
            }
        };
        // L-60: only what this round asked for is served, validated, or
        // remembered. Progress is measured against the WANTED ids the peer
        // served — an unsolicited entry is not progress on anything.
        let outstanding: HashSet<&str> = remaining.iter().map(String::as_str).collect();
        let (entries, unsolicited) = retain_wanted_entries(entries, &outstanding);
        if unsolicited > 0 {
            warn!(
                peer = %remote,
                unsolicited,
                "dropped Supply entries this node did not Want"
            );
        }
        let served: HashSet<&str> = entries.iter().map(|entry| entry.id.as_str()).collect();
        let next: Vec<String> = remaining
            .iter()
            .filter(|id| !served.contains(id.as_str()))
            .cloned()
            .collect();
        let stalled = next.len() == remaining.len();
        apply_supply_entries_from(
            handler,
            entries,
            remote,
            SupplyOrigin::Wanted,
            &mut FrameReservation::unmetered(),
        )
        .await;
        if stalled {
            // The peer served none of what we asked for: it does not have them,
            // or the reply was empty. Another round would ask the same thing.
            return Ok(());
        }
        remaining = next;
    }
    Ok(())
}

/// This node's advert, as lazily built `HaveHeads` pages.
///
/// L-35 / R-19: the read lock is held for an `Arc` clone of the ledger's
/// sorted id snapshot (rebuilt only when the DAG has grown since the last
/// call) and a clone of the heads — not for an O(N) clone of every id into a
/// `HashSet` followed by a second copy into a `Vec` to sort. The pages are
/// byte-identical to the old `paginate_have_heads` output and are produced
/// one at a time as they are written, so at most one page of ids is copied
/// out at once.
async fn local_have_heads_pages(ledger: &SharedLedger) -> p2p::anti_entropy::HaveHeadsPages {
    let (heads, directive_ids) = {
        let svc = ledger.read().await;
        (svc.head_txids(), svc.sorted_directive_ids())
    };
    let mut heads: Vec<String> = heads.into_iter().collect();
    heads.sort_unstable();
    p2p::anti_entropy::paginate_have_heads_sorted(heads, directive_ids)
}

/// Answer one `Want` from the local ledger: the `Supply` frame to send back.
async fn collect_supply(ledger: &SharedLedger, ids: &[String]) -> WireMessage {
    let svc = ledger.read().await;
    supply_for_want(&svc, ids, make_supply_entry)
}

/// [`collect_supply`]'s body, with the serializer injected so tests can count
/// what it produces.
///
/// L-01 / L-33: this used to serialize and hash EVERY matched directive of a
/// Want of up to 1,024 ids — all under the ledger read lock — and only then
/// hand the batch to `truncate_supply`, which kept at most 256 entries / 15 MiB.
/// A ~68 KiB request frame could cost up to ~64 MiB of allocation, and 32
/// connections per peer could sustain that concurrently. `build_supply` stops
/// producing at the entry cap and at the first entry past the byte budget, so
/// the work is bounded by what the reply can carry.
///
/// The reply itself is unchanged, byte for byte — same L-21 dedup (each
/// distinct id once, first occurrence wins, so the requester does not
/// re-validate a body per copy), same skipping of ids we lack, same prefix rule.
/// That is what keeps the requester's re-`Want` loop (`fetch_want_chunk`)
/// making progress: every round serves a non-empty prefix of what it still
/// lacks and we hold, until nothing we hold is left.
fn supply_for_want<F>(
    svc: &ledger::service::LedgerService,
    ids: &[String],
    mut serialize: F,
) -> WireMessage
where
    F: FnMut(&ledger::model::Directive) -> p2p::protocol::SupplyEntry,
{
    p2p::anti_entropy::build_supply(ids, |id| svc.get_directive(id).map(&mut serialize))
}

/// Tally of what `apply_supply_entries` did with one `Supply` batch (M-14).
///
/// Every entry lands in exactly one bucket, so the fields partition the batch.
/// Longest rendering of a peer-derived error on the intake/drain path (M-41).
///
/// One number with `p2p::protocol::MAX_DECODE_ERROR_CHARS`: the `MergeError`s
/// that reach `warn!` here wrap text the peer wrote — an id, a key, a parse
/// message — and since T66 every one is formatted through [`log_error`], so a
/// 16 MiB frame cannot become a 16 MiB log line whichever arm refuses it.
const MAX_LOG_ERROR_CHARS: usize = p2p::protocol::MAX_DECODE_ERROR_CHARS;

/// Render `error` for a `warn!` field, bounded (M-41).
///
/// `%error` on a `MergeError` used to render the whole thing; a 1 MiB body's
/// parse error was measured at 55 MB on one line (H-18). The bound is applied
/// as the value is FORMATTED, so nothing downstream holds the full rendering.
fn log_error(error: &impl std::fmt::Display) -> String {
    p2p::protocol::bounded_display(error, MAX_LOG_ERROR_CHARS)
}

/// Where a `Supply` batch came from, which decides whether its refusals may be
/// remembered (L-60).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupplyOrigin {
    /// The reply to a `Want` this node sent, already filtered to the ids it
    /// asked for by [`retain_wanted_entries`]. Every refusal is a verdict on
    /// something this node chose to ask this peer for, so it is recorded (L-34).
    Wanted,
    /// A frame the peer sent on its own, on the serve side. Nothing in it was
    /// Wanted, so nothing in it may be recorded: before T66 a peer could fill
    /// its own 4,096-entry refusal quota with junk ids it invented, and four
    /// such peers reached the 16,384 global cap and FIFO-evicted everyone
    /// else's honest entries (L-60). The entries are still applied — a pushed
    /// frame is how a peer hands over what it knows we lack without waiting
    /// for our next advert — but a refusal here is a fact about what the peer
    /// chose to push, not about what this node will ever ask for.
    Pushed,
}

/// Keep only the entries whose id is in `wanted`; return them and how many
/// were dropped (L-60).
///
/// A `Supply` answering a `Want` may carry anything the peer likes. Before T66
/// every entry was validated and, when refused, recorded against the peer's
/// refusal quota — whether or not it had been asked for. Filtering to the
/// outstanding set first means an unsolicited entry costs the receiver a hash
/// lookup and nothing else: no parse, no signature check, no cache slot.
fn retain_wanted_entries(
    entries: Vec<p2p::protocol::SupplyEntry>,
    wanted: &HashSet<&str>,
) -> (Vec<p2p::protocol::SupplyEntry>, usize) {
    let before = entries.len();
    let kept: Vec<_> = entries
        .into_iter()
        .filter(|entry| wanted.contains(entry.id.as_str()))
        .collect();
    let dropped = before - kept.len();
    (kept, dropped)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SupplyOutcome {
    /// M-14 fast path: `entry.id` was already in the DAG, so validation was skipped.
    pub skipped_present: usize,
    /// Validated and newly merged into the DAG.
    pub merged: usize,
    /// Parents missing, or an account not open at the entry's date (M-09);
    /// took the orphan-buffer path.
    pub buffered: usize,
    /// `insert_remote_directive` returned `Ok(None)` (present at insert time).
    pub duplicate: usize,
    /// Invalid body / author / signature / insert error.
    pub rejected: usize,
    /// Not applied because the ledger is at its size cap: either this batch
    /// would not fit under [`ledger::service::LedgerService::append_headroom`],
    /// or the serving peer's [`SupplyBackoff`] was already armed (M-39), or —
    /// since T77 — an orphan this batch freed would not have fit beside it
    /// (L-70). Nothing was staged or recorded for these; they are re-Wanted
    /// once the backoff expires.
    pub deferred: usize,
}

/// Resident weight ([`p2p::anti_entropy::resident_weight`]) phase 1 of
/// [`apply_supply_entries_from`] may hold for staging before it stages what
/// it holds (T77, the T75 residual).
///
/// Phase 1 used to keep every validated directive of a frame until phase 2,
/// and a parsed directive is far larger than its text: the densest body inside
/// every §3.12 cap holds ~14× its bytes, so a 5 MB frame of them held ~63 MB
/// (12.7× the frame) per slot, and an allowlisted peer filling the 256 MiB
/// inbound budget with such frames held ~3.5 GiB. Now phase 1 stages and
/// commits a chunk whenever the next directive would carry what it holds past
/// this weight, so a slot holds at most one frame's worth of parsed
/// directives, whatever the frame's density. One frame's size is the natural
/// unit: an honest maximal frame (256 × 1000-posting transactions) is ~5
/// chunks, i.e. ~5 journal records instead of one; the pushed path also
/// charges the same weight to the connection limiter's byte budget (see
/// [`apply_supply_entries_from`]).
const PHASE_ONE_WEIGHT_BUDGET: usize = p2p::protocol::MAX_MESSAGE_SIZE as usize;

/// The most parsed weight phase 1 holds on one connection beyond what the
/// connection limiter's byte budget covers (T88 / M-62, decision (26)): 1 MiB.
///
/// T83 (L-90) stopped a failed byte charge from flushing a one-directive
/// chunk, so a peer whose budget was spent no longer cost a commit and fsync
/// per directive — but what the budget could not cover was then held
/// uncharged up to [`PHASE_ONE_WEIGHT_BUDGET`] (16 MiB) per connection:
/// ~460–512 MiB per peer over its 32 connections, 4 GiB across the global
/// connection cap, against documented budgets of 32 MiB and 256 MiB. Past
/// this residue the chunk is staged, as before T83 but per ~1 MiB of weight,
/// not per directive; a peer's uncharged hold is then at most its connection
/// count in MiB — about its own byte budget again — and one directive of
/// weight above that (the pre-T83 residual).
const UNCHARGED_RESIDUE_CAP: usize = 1024 * 1024;

#[cfg(test)]
thread_local! {
    /// The most parsed weight phase 1 held uncharged on this thread since the
    /// last reset (T88 tests; the unit tests drive phase 1 on a current-thread
    /// runtime, so a thread-local is exact and isolated from other tests).
    static PHASE_ONE_MAX_UNCHARGED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// What phase 1 holds for phase 2: validated directives in arrival order, each
/// with its serialized length, plus the exact record they would become and
/// their resident weight (T77).
#[derive(Default)]
struct PhaseOneChunk {
    directives: Vec<(ledger::model::Directive, u64)>,
    record: RecordEstimate,
    weight: usize,
}

impl PhaseOneChunk {
    fn push(&mut self, directive: ledger::model::Directive, bytes: u64, weight: usize) {
        self.record.add(bytes);
        self.weight = self.weight.saturating_add(weight);
        self.directives.push((directive, bytes));
    }

    fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }
}

/// How one phase-2 chunk ended (T77).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkVerdict {
    /// Staged and committed (or nothing needed committing): its stage
    /// verdicts were reached against state that is still there (L-34).
    Durable,
    /// Not staged: it would not fit under the size cap (M-39).
    Deferred,
    /// Staged, but the commit did not land; see the log line for whether the
    /// chunk was rolled back or stays staged.
    NotDurable,
}

/// Apply one `Supply` batch: validate off the lock, then stage + persist.
///
/// M-15: the previous shape took the ledger write lock and ran a full-file
/// `full_file_serialize` + `sync_all` fsync once PER entry (and again per
/// resolved orphan). Catch-up of M directives on an N-directive ledger was then
/// O(M×N) serializations + fsyncs, all under the write lock — the gossip loop
/// blocked on `ledger.read()`, its channel filled, and GraphQL mutations
/// blocked. This is now two phases: phase 1 does all the expensive parse/verify
/// work with NO write lock; phase 2 takes the write lock once per chunk,
/// stages the chunk in memory, drains any orphans it unblocks, and persists a
/// single time for the chunk + drained orphans. A frame is one chunk unless
/// its parsed directives outweigh [`PHASE_ONE_WEIGHT_BUDGET`] (T77).
///
/// Tests' shorthand for the Wanted path — a batch the caller has already
/// filtered to the ids it `Want`ed ([`SupplyOrigin::Wanted`]), metered by
/// nothing. Production has two callers and both state their origin through
/// [`apply_supply_entries_from`]: `fetch_want_chunk` (Wanted, after
/// [`retain_wanted_entries`]) and the serve loop's pushed-`Supply` arm
/// (Pushed), so no caller can apply a frame without saying whether its
/// refusals may be remembered (L-60).
#[cfg(test)]
async fn apply_supply_entries(
    handler: &AntiEntropyHandler,
    entries: Vec<p2p::protocol::SupplyEntry>,
    remote: EndpointId,
) -> SupplyOutcome {
    apply_supply_entries_from(
        handler,
        entries,
        remote,
        SupplyOrigin::Wanted,
        &mut FrameReservation::unmetered(),
    )
    .await
}

/// [`apply_supply_entries`] with the batch's origin stated (L-60) and the
/// reservation phase 1's staged weight is charged to (T77).
///
/// The origin changes exactly one thing: whether permanent refusals are
/// recorded in the peer's [`p2p::anti_entropy::RefusalCache`] quota. A
/// `Wanted` batch was asked for id by id, so every refusal is a fact about
/// something this node will otherwise ask for again; a `Pushed` batch was not,
/// so recording its refusals would let the peer spend — and, across peers,
/// exhaust — a cache that exists to protect this node's own Wants.
///
/// `weight` is the frame's own [`FrameReservation`] on the inbound (pushed)
/// path and an unmetered one on the outbound path. Phase 1 grows it by the
/// resident weight of every directive it holds and shrinks it back each time
/// a chunk has been staged, so the connection limiter's byte budget — which
/// until T77 charged the frame body 1× for a footprint of up to ~14× — also
/// covers what phase 1 holds; when the budget cannot cover the next directive,
/// the chunk held so far is staged first. The outbound side is bounded by
/// [`PHASE_ONE_WEIGHT_BUDGET`] alone, like the inbound one, and by its own
/// loops' concurrency as before.
async fn apply_supply_entries_from(
    handler: &AntiEntropyHandler,
    entries: Vec<p2p::protocol::SupplyEntry>,
    remote: EndpointId,
    origin: SupplyOrigin,
    weight: &mut FrameReservation,
) -> SupplyOutcome {
    let from_peer = remote.to_string();
    let mut outcome = SupplyOutcome::default();
    // M-39: a peer whose last batch did not fit under the size cap is not
    // re-validated, re-staged or re-rolled-back until its backoff expires.
    if handler
        .supply_backoff
        .is_active(remote, std::time::Instant::now())
    {
        outcome.deferred = entries.len();
        debug!(peer = %remote, deferred = outcome.deferred, "ALPN supply deferred: peer is backed off at the ledger size cap");
        return outcome;
    }
    // L-34: ids refused for good, by phase. Intake verdicts are pure functions
    // of the served bytes and are recorded unconditionally; stage and drain
    // verdicts read ledger state, so they are recorded only once the chunk they
    // were reached against is durable (see `flush` below). L-60: neither is
    // recorded at all for a pushed batch — see `SupplyOrigin`.
    let mut intake_refused: Vec<String> = Vec::new();
    let mut stage_refused: Vec<(String, String)> = Vec::new();
    // T72 / L-69: `(id, remote lamport)` of every entry the adoption ratchet
    // refused, for the per-peer short-circuit — see `SupplyBackoff`.
    let mut ratcheted: Vec<(String, u64)> = Vec::new();

    // ── Phase 1: validate off the ledger write lock (M-15) ──────────────
    //
    // Parsing, re-serializing, hashing, and Ed25519-verifying every entry is
    // the expensive work, and none of it needs the write lock. Staging it here
    // means each chunk takes the write lock exactly once, in phase 2.
    //
    // T77: what is held for phase 2 is bounded by weight, not by count — see
    // `PHASE_ONE_WEIGHT_BUDGET` — and each held directive carries its exact
    // share of the journal record it will become (`RecordEstimate`), which is
    // what phase 2 checks against the headroom. The pre-T77 per-entry wire
    // estimate over-counted ~150–190 B an entry, so in the last ~40 KB before
    // the cap a batch that fit was deferred forever.
    let base = weight.held();
    let mut chunk = PhaseOneChunk::default();
    let mut deferring = false;
    for entry in entries {
        // M-39 / L-70: once a chunk of this frame has been deferred at the
        // cap (or its commit was refused by the cap), the peer is backed off
        // and the rest of the frame is deferred with it, unvalidated.
        if deferring {
            outcome.deferred += 1;
            continue;
        }
        // M-14: dedup BEFORE validate. `validate_supply_entry` parses up to 1 MiB
        // of beancount, re-serializes, hashes, and Ed25519-verifies every entry
        // before anything checks whether `entry.id` is already in the DAG — the
        // G-Set dedup only happens later under the write lock. So an allowlisted
        // peer can replay the same Supply in a loop, paying full parse+verify per
        // entry to change nothing.
        //
        // Skipping validation for an id we already hold is state-preserving:
        // `entry.id` is content-addressed and is re-checked authoritatively under
        // the write lock in phase 2, which returns `Ok(None)` for a present id
        // without overwriting. A forged entry claiming a present id either (a)
        // hashes to that id — it IS that content, a genuine duplicate — or (b)
        // does not, in which case `validate_supply_entry` would reject it. In case
        // (b) the entry is discarded whether we skip it here or reject it below,
        // so it is never stored either way. Thus this fast path changes no state;
        // it only avoids wasted CPU and a log line. The read guard is a temporary
        // dropped at the end of this statement, so no lock is held into validation.
        if handler
            .ledger
            .read()
            .await
            .get_directive(&entry.id)
            .is_some()
        {
            outcome.skipped_present += 1;
            continue;
        }
        let directive = match validate_supply_entry(&entry) {
            Ok(directive) => directive,
            Err(error) => {
                // H-18/M-41: bounded — this is the line that was 55 MB.
                warn!(error = %log_error(&error), peer = %remote, "invalid ALPN supply entry");
                outcome.rejected += 1;
                note_intake_refusal(&mut intake_refused, &entry.id, &error);
                continue;
            }
        };
        if let Err(error) = verify_author_allowlisted(&directive, &handler.allowlist) {
            warn!(error = %log_error(&error), peer = %remote, "rejected ALPN supply: author not allowlisted");
            outcome.rejected += 1;
            note_intake_refusal(&mut intake_refused, &entry.id, &error);
            continue;
        }
        if let Err(error) =
            verify_remote_signature(&directive, handler.signing_enabled, &handler.mesh_id)
        {
            warn!(error = %log_error(&error), peer = %remote, "rejected ALPN supply: signature");
            outcome.rejected += 1;
            note_intake_refusal(&mut intake_refused, &entry.id, &error);
            continue;
        }
        drop(entry);
        let resident = p2p::anti_entropy::resident_weight(&directive);
        let bytes = RecordEstimate::directive_bytes(&directive);
        // T77: stage what is held before holding more than the budget — or
        // more than the limiter's byte budget will cover — at once.
        // T83 / L-90: the chunk flushes on the WEIGHT budget only. A failed
        // charge used to flush too, and once a peer's share of the byte
        // budget was exhausted every directive failed its charge, so each
        // 256-entry frame became 256 commits and fsyncs under the write
        // permit. Now the charge below is best effort: what it cannot cover
        // is held uncharged — since T88 at most `UNCHARGED_RESIDUE_CAP` per
        // connection (M-62) — and only connections whose frame body WAS
        // charged get here.
        let fits = chunk.weight.saturating_add(resident) <= PHASE_ONE_WEIGHT_BUDGET;
        if !fits && !chunk.is_empty() {
            let verdict = stage_and_commit_batch(
                handler,
                std::mem::take(&mut chunk),
                remote,
                &mut outcome,
                &mut stage_refused,
                &mut ratcheted,
            )
            .await;
            weight.shrink_to(base);
            if verdict != ChunkVerdict::Durable
                && handler
                    .supply_backoff
                    .is_active(remote, std::time::Instant::now())
            {
                deferring = true;
                outcome.deferred += 1;
                continue;
            }
        }
        // Charge what the chunk now holds, as far as the budget allows (see
        // above). T88 / M-62: and never hold more than
        // `UNCHARGED_RESIDUE_CAP` beyond what the budget covered — stage the
        // chunk first when adding this directive would.
        let target = base + chunk.weight.saturating_add(resident);
        if !weight.grow_to(target)
            && target.saturating_sub(weight.held()) > UNCHARGED_RESIDUE_CAP
            && !chunk.is_empty()
        {
            let verdict = stage_and_commit_batch(
                handler,
                std::mem::take(&mut chunk),
                remote,
                &mut outcome,
                &mut stage_refused,
                &mut ratcheted,
            )
            .await;
            weight.shrink_to(base);
            if verdict != ChunkVerdict::Durable
                && handler
                    .supply_backoff
                    .is_active(remote, std::time::Instant::now())
            {
                deferring = true;
                outcome.deferred += 1;
                continue;
            }
            let _ = weight.grow_to(base + resident);
        }
        // Preserve arrival order so an open/parent earlier in the batch is
        // visible to a later child's checks in phase 2.
        chunk.push(directive, bytes, resident);
        #[cfg(test)]
        PHASE_ONE_MAX_UNCHARGED.with(|max| {
            max.set(
                max.get()
                    .max((base + chunk.weight).saturating_sub(weight.held())),
            );
        });
    }

    // ── Phase 2: one ledger write lock per chunk (M-15) ─────────────────
    if !chunk.is_empty() {
        stage_and_commit_batch(
            handler,
            chunk,
            remote,
            &mut outcome,
            &mut stage_refused,
            &mut ratcheted,
        )
        .await;
    }
    weight.shrink_to(base);

    // L-60: a pushed batch was never Wanted, so none of its verdicts may
    // occupy the cache — see `SupplyOrigin::Pushed`. (`RefusalCache::record`
    // also refuses any id that is not a content id, so even a Wanted batch —
    // filtered to form-checked advert ids — can only ever record 64-hex ids.)
    if origin == SupplyOrigin::Pushed {
        intake_refused.clear();
        stage_refused.clear();
        ratcheted.clear();
    }
    // T72 / L-69: a ratchet verdict survives a rolled-back batch — the reload
    // can only lower the clock, and the verdict is monotone in it — so it is
    // recorded whether or not the batch was durable.
    for (id, remote_lamport) in ratcheted {
        handler
            .supply_backoff
            .defer_ratcheted(remote, id, remote_lamport);
    }
    if !intake_refused.is_empty() || !stage_refused.is_empty() {
        let now = std::time::Instant::now();
        let mut buffer = handler.orphan_buffer.write().await;
        let refusals = buffer.refusals_mut();
        for id in &intake_refused {
            refusals.record(&from_peer, id, now);
        }
        for (peer, id) in &stage_refused {
            refusals.record(peer, id, now);
        }
    }

    debug!(
        peer = %remote,
        skipped_present = outcome.skipped_present,
        merged = outcome.merged,
        buffered = outcome.buffered,
        duplicate = outcome.duplicate,
        rejected = outcome.rejected,
        deferred = outcome.deferred,
        "applied ALPN supply batch"
    );
    outcome
}

/// Phase 2 of [`apply_supply_entries_from`], for one chunk: take the permit
/// and the write lock once, check the chunk fits, stage it, drain the orphans
/// it frees as far as they fit, commit once (M-15, T44), and only then
/// announce what it staged to GraphQL subscribers (T77 / L-70).
///
/// The chunk's stage verdicts are appended to `stage_refused` only when the
/// chunk ends [`ChunkVerdict::Durable`] — i.e. when they were reached against
/// state that is still there (L-34). A chunk deferred for headroom (M-39)
/// staged nothing.
///
/// # The size cap, end to end (M-39, L-70)
///
/// * **Before staging**: the chunk's exact record ([`RecordEstimate`]) against
///   [`ledger::service::LedgerService::append_headroom`], under the permit so
///   nothing moves the answer. A chunk that cannot fit is deferred and the
///   peer backed off, without staging or a reload.
/// * **While draining**: every orphan the chunk frees is checked against the
///   record the ACTUAL staged set (what staged, plus the orphans drained so
///   far) has become, before it is staged. Before T77 the drain staged up to
///   16 MiB per peer after the pre-stage check, the prepare then refused the
///   whole set, and the rollback cost a full reload — once per two ticks,
///   forever, for a peer alternating adverts. An orphan that would not fit is
///   dropped from the buffer (re-Wanted by membership once the backoff lifts)
///   and the peer is backed off; the chunk and the orphans that fit commit.
/// * **Any cap-refused prepare or commit** arms the backoff too, whatever the
///   estimate said (a hand edit that grew the file since the last commit is
///   invisible to `append_headroom`), so no path can pay one reload per tick.
///
/// Lock-ordering discipline is unchanged inside the write lock: the
/// orphan_buffer lock is only ever acquired under it (here and inside
/// `drain_orphans`). T44 adds one lock ABOVE it — the single-writer commit
/// permit — taken before the write lock on every write path and released
/// only once the batch is durable.
async fn stage_and_commit_batch(
    handler: &AntiEntropyHandler,
    chunk: PhaseOneChunk,
    remote: EndpointId,
    outcome: &mut SupplyOutcome,
    stage_refused: &mut Vec<(String, String)>,
    ratcheted: &mut Vec<(String, u64)>,
) -> ChunkVerdict {
    let from_peer = remote.to_string();
    let permit = crate::ledger_commit::acquire_write_permit(&handler.ledger).await;
    let mut svc = handler.ledger.write().await;
    // M-39: will the chunk fit? Asked under the permit, so no other writer can
    // move the answer between here and the prepare. A chunk that cannot fit is
    // KNOWN to fail the prepare's cap projection; staging it anyway is what
    // used to cost a full ledger reload per tick per peer. T77: the chunk's
    // exact record, not a per-entry wire estimate.
    let headroom = svc.append_headroom();
    let estimated_bytes = chunk.record.record_bytes();
    if estimated_bytes > headroom {
        drop(svc);
        drop(permit);
        let backoff = handler.timeouts.supply_backoff;
        handler
            .supply_backoff
            .arm(remote, std::time::Instant::now(), backoff);
        outcome.deferred += chunk.directives.len();
        // Bounded: fixed-width numbers and the peer id, and at most once per
        // peer per backoff window.
        warn!(
            peer = %remote,
            entries = chunk.directives.len(),
            estimated_bytes,
            headroom_bytes = headroom,
            backoff_secs = backoff.as_secs(),
            "ALPN supply batch deferred: it would not fit under the ledger size cap \
             (MAX_LEDGER_FILE_BYTES); not applying this peer's Supply until the backoff \
             expires. Reads and compaction are unaffected; archive or split the ledger to \
             make room (M-39)"
        );
        return ChunkVerdict::Deferred;
    }
    // L-34: this chunk's stage verdicts, kept only if the chunk is durable.
    let mut refused_here: Vec<(String, String)> = Vec::new();
    // T77 / L-70: the record the staged set has become, for the drain's
    // re-checks, and what to announce once — and only once — it is durable.
    let mut staged = RecordEstimate::new();
    let mut announce: Vec<GraphqlTransaction> = Vec::new();
    let mut inserted_any = false;
    for (directive, bytes) in chunk.directives {
        // Re-check dedup authoritatively under the write lock: an id may have
        // arrived earlier in this same batch, or via a drained orphan.
        let content_id = ledger::service::LedgerService::content_id(&directive);
        if svc.get_directive(&content_id).is_some() {
            outcome.duplicate += 1;
            continue;
        }
        let missing_parents = svc.missing_parent_ids(&directive);
        if !missing_parents.is_empty() {
            let mut buffer = handler.orphan_buffer.write().await;
            match buffer.insert(
                content_id.clone(),
                directive,
                missing_parents,
                Some(from_peer.clone()),
            ) {
                OrphanInsert::Buffered => {
                    debug!(content_id = %content_id, "buffered ALPN directive with missing parents");
                }
                // L-20: at a full buffer this used to be reported as a
                // capacity refusal. It is ordinary redelivery.
                OrphanInsert::Duplicate => {
                    debug!(content_id = %content_id, "ALPN directive already in the orphan buffer");
                }
                OrphanInsert::BudgetExhausted => {
                    warn!(content_id = %content_id, "orphan buffer full or per-peer quota exceeded");
                }
            }
            outcome.buffered += 1;
            continue;
        }
        // Stage into memory only (NO persist) — persist happens once below.
        match svc.stage_remote_directive(directive.clone()) {
            Ok(Some(content_id)) => {
                info!(content_id = %content_id, peer = %remote, "merged remote directive from ALPN");
                outcome.merged += 1;
                inserted_any = true;
                staged.add(bytes);
                if let ledger::model::Directive::Transaction(ref txn) = directive {
                    // M-45: the id is in hand; converting must not re-hash.
                    // T77 / L-70: announced after the commit, not here.
                    announce.push(txn_to_graphql(txn, content_id, true));
                }
            }
            Ok(None) => {
                debug!("ALPN supply entry was duplicate");
                outcome.duplicate += 1;
            }
            Err(error) => {
                // M-09: a transaction turned away only because an account
                // it posts to is not open at its date is not invalid — the
                // `open` may simply be later in this peer's arrival order.
                // Buffer it exactly like a parent-missing entry and let the
                // post-batch drain retry it when that `open` lands. Any
                // other rejection is a real one.
                match account_wait_target(&error) {
                    Some(account) => {
                        let mut buffer = handler.orphan_buffer.write().await;
                        match buffer.insert_awaiting_accounts(
                            content_id.clone(),
                            directive,
                            vec![account.clone()],
                            Some(from_peer.clone()),
                        ) {
                            OrphanInsert::Buffered => {
                                debug!(content_id = %content_id, %account, "buffered ALPN directive awaiting an open");
                            }
                            OrphanInsert::Duplicate => {
                                debug!(content_id = %content_id, %account, "ALPN directive already in the orphan buffer");
                            }
                            OrphanInsert::BudgetExhausted => {
                                warn!(content_id = %content_id, "orphan buffer full or per-peer quota exceeded");
                            }
                        }
                        outcome.buffered += 1;
                    }
                    None => note_stage_refusal(
                        handler,
                        remote,
                        &from_peer,
                        &content_id,
                        &error,
                        outcome,
                        &mut refused_here,
                        ratcheted,
                    ),
                }
            }
        }
    }

    if !inserted_any {
        drop(svc);
        stage_refused.append(&mut refused_here);
        return ChunkVerdict::Durable;
    }

    // Drain orphans this chunk unblocked, then persist ONCE for the whole
    // chunk plus the drained orphans (M-15). `drain_orphans` stages (no
    // persist), so this single commit covers everything. T77 / L-70: each
    // freed orphan is checked against the record the staged set has become
    // before it is staged — see `DrainBudget`.
    let mut budget = DrainBudget { headroom, staged };
    let drained = drain_orphans(
        &handler.orphan_buffer,
        &mut svc,
        handler.signing_enabled,
        &handler.allowlist,
        &handler.mesh_id,
        &mut budget,
    )
    .await;
    refused_here.extend(drained.permanent);
    // T72 / L-69: a freed orphan the ratchet refused is dropped from the
    // buffer and would be re-Wanted by membership next tick; only the
    // ones this peer delivered are this peer's to short-circuit.
    ratcheted.extend(
        drained
            .ratcheted
            .into_iter()
            .filter(|(peer, _, _)| *peer == from_peer)
            .map(|(_, id, remote_lamport)| (id, remote_lamport)),
    );
    announce.extend(drained.announce);
    if drained.deferred > 0 {
        // L-70: the orphans that fit are staged; the rest wait for room.
        let backoff = handler.timeouts.supply_backoff;
        handler
            .supply_backoff
            .arm(remote, std::time::Instant::now(), backoff);
        outcome.deferred += drained.deferred;
        warn!(
            peer = %remote,
            orphans = drained.deferred,
            staged_record_bytes = budget.staged.record_bytes(),
            headroom_bytes = headroom,
            backoff_secs = backoff.as_secs(),
            "ALPN supply: orphans this batch freed would not fit under the ledger size cap \
             beside it; the batch is committed, those orphans wait, and this peer's Supply is \
             deferred until the backoff expires (L-70)"
        );
    }
    // T44: prepare under the lock, commit off it. For a catch-up batch
    // on a ledger past the compaction threshold this is a single
    // journal record for the whole batch — O(batch), not O(ledger) —
    // and the fsync runs on a blocking thread with the write lock
    // already released, so a peer streaming history no longer parks
    // GraphQL readers on the disk.
    // M-39: a failed prepare drops the write lock before its reload, so
    // the rollback no longer queues every reader behind a ledger boot.
    let prepared =
        crate::ledger_commit::prepare_or_recover(&handler.ledger, svc, false, permit).await;
    let failure = match prepared {
        // H-11: the permit is handed to the commit, so a dropped
        // exchange future cannot release the single-writer slot while
        // the batch is still being written.
        Ok((svc, pending, permit)) => {
            drop(svc);
            crate::ledger_commit::commit_pending(&handler.ledger, pending, permit)
                .await
                .err()
                .map(|error| (error, CommitStage::Commit))
        }
        Err(error) => Some((error, CommitStage::Prepare)),
    };
    let Some((error, stage)) = failure else {
        // T77 / L-70: durable — only now is it true to tell a subscriber.
        for transaction in announce {
            handler.broadcast.publish(transaction);
        }
        stage_refused.append(&mut refused_here);
        return ChunkVerdict::Durable;
    };
    if matches!(error, ServiceError::ResourceLimitExceeded { .. }) {
        // L-70: any cap-refused prepare or commit backs the peer off, not
        // only the pre-stage deferral — otherwise a refusal the estimate
        // did not predict is paid for with a reload per tick.
        handler.supply_backoff.arm(
            remote,
            std::time::Instant::now(),
            handler.timeouts.supply_backoff,
        );
    }
    // The tallies above describe what was attempted, not what is stored;
    // nothing was announced and the stage verdicts are discarded (L-34).
    match (stage, &error) {
        // T77: the two prepare refusals that do NOT reload — see
        // `ledger_commit::prepare_or_recover` — leave the batch staged in
        // memory, served, and written by the next commit that succeeds.
        (CommitStage::Prepare, ServiceError::CommitInFlight | ServiceError::Parse(_)) => {
            warn!(error = %log_error(&error), peer = %remote, "failed to persist ALPN supply batch; it stays staged in memory and is written by the next successful commit (not rolled back)");
        }
        // L-13: every other failure already reloaded from disk, so the batch
        // is rolled back in memory (memory == disk again) and anti-entropy
        // will re-pull it.
        _ => {
            warn!(error = %log_error(&error), peer = %remote, "failed to persist ALPN supply batch; rolled back in memory, will re-pull");
        }
    }
    ChunkVerdict::NotDurable
}

/// Which half of the T44 sequence refused a batch — it decides whether the
/// batch was rolled back (see `stage_and_commit_batch`'s log lines).
#[derive(Clone, Copy)]
enum CommitStage {
    Prepare,
    Commit,
}

/// Log, tally and record one stage refusal of a supplied directive (L-34,
/// T72 / L-69).
#[allow(clippy::too_many_arguments)]
fn note_stage_refusal(
    handler: &AntiEntropyHandler,
    remote: EndpointId,
    from_peer: &str,
    content_id: &str,
    error: &ServiceError,
    outcome: &mut SupplyOutcome,
    refused_here: &mut Vec<(String, String)>,
    ratcheted: &mut Vec<(String, u64)>,
) {
    // T72 / L-69: one line per peer per interval; the rest are counted and
    // reported on the next line.
    match handler
        .supply_backoff
        .should_log_stage_refusal(remote, std::time::Instant::now())
    {
        Some(suppressed) => {
            warn!(error = %log_error(error), peer = %remote, suppressed, "rejected remote directive from ALPN");
        }
        None => {
            debug!(error = %log_error(error), peer = %remote, "rejected remote directive from ALPN (warn throttled)");
        }
    }
    outcome.rejected += 1;
    if let ServiceError::LamportAdvance { remote, .. } = error {
        ratcheted.push((content_id.to_owned(), *remote));
    }
    if stage_refusal_is_permanent(error) {
        refused_here.push((from_peer.to_owned(), content_id.to_owned()));
    }
}

/// The re-validation context a freed orphan is put back through.
///
/// Bundled so [`restage_freed_entry`] stays inside clippy's argument budget.
struct DrainContext<'a> {
    signing_enabled: bool,
    allowlist: &'a PeerAllowlist,
    mesh_id: &'a str,
}

/// How much record a drain may add (T77 / L-70): the headroom the chunk was
/// checked against, and the record the staged set has become so far.
#[derive(Clone, Copy, Debug)]
pub struct DrainBudget {
    /// [`ledger::service::LedgerService::append_headroom`] under the permit.
    pub headroom: u64,
    /// The exact record of everything staged under this permit so far.
    pub staged: RecordEstimate,
}

impl DrainBudget {
    /// Room for one more directive of `bytes` serialized bytes?
    fn admits(&self, bytes: u64) -> bool {
        self.staged.with(bytes).record_bytes() <= self.headroom
    }
}

/// Record an intake refusal of `id` if it was a permanent one (L-34).
fn note_intake_refusal(refused: &mut Vec<String>, id: &str, error: &MergeError) {
    if intake_refusal_is_permanent(error) {
        refused.push(id.to_owned());
    }
}

/// Whether a refusal at INTAKE — `validate_supply_entry`, the author allowlist,
/// the signature — is permanent for the peer that served the entry (L-34).
///
/// All of them are. Every intake check is a pure function of the bytes the
/// peer served and of this process's fixed configuration (allowlist, signing
/// flag, mesh id — none of which change at runtime), and a peer serves the
/// same bytes for an id every time: its store is a G-Set keyed by that id.
/// Asking again cannot produce a different answer.
///
/// That only holds PER PEER, which is why the cache is keyed by (peer, id): the
/// content id covers the economic body alone, so a different peer's copy can
/// carry a different envelope and pass where this one failed.
///
/// Spelled out as an exhaustive match, not `true`, so a new `MergeError`
/// variant has to be classified before this compiles — the classification is
/// the part of L-34 that silently loses data if it is wrong.
fn intake_refusal_is_permanent(error: &MergeError) -> bool {
    match error {
        MergeError::ContentHashMismatch { .. }
        | MergeError::ParseError(_)
        | MergeError::ValidationError(_)
        | MergeError::EnvelopeMissing(_)
        | MergeError::InvalidSignature(_)
        | MergeError::ResourceLimitExceeded(_)
        | MergeError::CycleDetected
        | MergeError::InvalidEnvelope(_)
        | MergeError::BodyEnvelopeKey(_)
        | MergeError::BodyControlCharacter(_)
        | MergeError::ElidedPosting => true,
    }
}

/// Whether a refusal from `stage_remote_directive` is permanent (L-34).
///
/// Permanent means content-determined: a verdict on the directive (body or
/// envelope) that no later arrival can change. Everything that CAN change is
/// excluded, because caching it would suppress a directive that was about to
/// become acceptable — a delay the TTL bounds, but a loss for that long:
///
/// * the account-lifecycle verdicts ([`account_wait_target`]) — an `open` can
///   still arrive; those entries are buffered, not refused, and are excluded
///   here too as a second line;
/// * `ServiceError::AccountNotOpen` / `AccountAlreadyOpen` — lifecycle again;
/// * `Dag` — a cycle verdict depends on a DAG that is still growing, and L-40
///   shows one that clears once another transaction lands; a missing parent is
///   an orphan and is buffered before staging is ever tried;
/// * `LamportCeiling` — reached against THIS node's clock, not the directive;
/// * `LamportAdvance` (T63 / H-12, the adoption ratchet) — judged against this
///   node's clock, which rises as the intervening history arrives; caching it
///   would stop a node that is catching up from ever adopting the top of the
///   history it is climbing toward. It is not re-fetched pointlessly either:
///   the verdict is a pure function of `(remote, local clock)`, so
///   [`SupplyBackoff::defer_ratcheted`] holds the id out of the Want exactly
///   until the clock can change it (T72 / L-69);
/// * there is no per-author head bound any more — T64's `UnmergedHeadLimit`
///   was judged against this replica's heads and made DAG membership depend
///   on delivery order (T72 / H-21);
/// * `Io`, `Journal`, `CommitInFlight`, `Parse` — transient or not a verdict on
///   the directive at all.
///
/// `AccountHasLaterTransactions` — the backdated close, the M-09 residual this
/// cache exists for — reads ledger state but is monotone in it: the later
/// posting that refutes the close is in a G-Set DAG and can never leave, so the
/// close can never become acceptable.
fn stage_refusal_is_permanent(error: &ServiceError) -> bool {
    match error {
        ServiceError::Validation(validation) => match validation {
            ValidationError::UnbalancedTransaction { .. }
            | ValidationError::InvalidElision { .. }
            | ValidationError::InvalidPosting { .. } => true,
            ValidationError::AccountNotOpen { .. }
            | ValidationError::AccountClosed { .. }
            | ValidationError::AccountCurrencyMismatch { .. } => false,
        },
        ServiceError::AccountHasLaterTransactions { .. }
        | ServiceError::ResourceLimitExceeded { .. }
        | ServiceError::InvalidAccountName { .. }
        | ServiceError::InvalidCurrency { .. }
        | ServiceError::InvalidTag { .. }
        | ServiceError::InvalidLink { .. }
        | ServiceError::InvalidInput { .. }
        | ServiceError::DateOutOfRange { .. }
        | ServiceError::BodyEnvelopeKey { .. } => true,
        ServiceError::AccountNotOpen { .. }
        | ServiceError::AccountAlreadyOpen { .. }
        | ServiceError::Dag(_)
        | ServiceError::LamportCeiling { .. }
        | ServiceError::LamportAdvance { .. }
        | ServiceError::Io(_)
        | ServiceError::Journal { .. }
        | ServiceError::CommitInFlight
        | ServiceError::Parse(_) => false,
    }
}

/// The account a rejected remote directive is waiting on, when the rejection
/// was purely an account-lifecycle verdict (M-09).
///
/// All three variants are answers to the SAME deterministic query — "which
/// `open` is in force for this account at this date, and what does it allow" —
/// and all three can be flipped by an `open` for that account arriving later:
///
/// * `AccountNotOpen` — no lifecycle event in force at the date yet;
/// * `AccountClosed` — a `close` decides at the date, which a later-dated
///   `open` can supersede;
/// * `AccountCurrencyMismatch` — the constraint list comes from the `open` in
///   force at the date, so a not-yet-seen `open` can be the one that allows it.
///
/// Everything else (unbalanced, elided, malformed, resource limits, the
/// backdated-close guard) is a verdict on the directive itself and stays a
/// rejection.
fn account_wait_target(error: &ServiceError) -> Option<String> {
    let ServiceError::Validation(validation) = error else {
        return None;
    };
    match validation {
        ValidationError::AccountNotOpen { account, .. }
        | ValidationError::AccountClosed { account, .. }
        | ValidationError::AccountCurrencyMismatch { account, .. } => Some(account.clone()),
        _ => None,
    }
}

/// What became of one freed orphan put back through validation.
enum Restaged {
    /// Merged into the DAG; the transaction to announce once the commit
    /// covering it is durable (T77 / L-70), if it is one.
    Staged {
        announce: Option<Box<GraphqlTransaction>>,
    },
    /// Still blocked; back in the buffer waiting on this account (M-09).
    Rebuffered { account: String },
    /// Not in the buffer and not in the DAG, for a reason that can change — a
    /// full buffer, or it was already present.
    Dropped,
    /// Not in the buffer and not in the DAG, refused for good (L-34).
    Refused,
    /// Not in the buffer and not in the DAG, refused by the adoption ratchet
    /// against this remote lamport — re-fetching it is pointless until the
    /// clock reaches it (T72 / L-69). Otherwise as `Dropped`.
    Ratcheted { remote_lamport: u64 },
    /// Not staged: the record the staged set has become has no room for it
    /// under the size cap (T77 / L-70). Otherwise as `Dropped` — it is
    /// re-Wanted by membership once the caller's backoff lifts.
    Deferred,
}

/// Re-validate one freed orphan and stage it — if it fits (T77 / L-70).
///
/// A freed entry that is still blocked on an account lifecycle query goes back
/// into the buffer under its NEW blocking account (M-09) rather than being
/// dropped — a transaction can post to several accounts, and validation reports
/// only the first one that fails, so one release can uncover the next.
///
/// Before it is staged, its exact share of the journal record is checked
/// against `budget`: the record the staged set has ALREADY become (the chunk's
/// staged directives plus every orphan drained before this one) plus this one
/// must still fit under the headroom the chunk was checked against. Before
/// T77 nothing here looked at the size cap at all.
fn restage_freed_entry(
    buffer: &mut OrphanBuffer,
    service: &mut ledger::service::LedgerService,
    context: &DrainContext<'_>,
    entry: p2p::orphan_buffer::OrphanEntry,
    budget: &mut DrainBudget,
) -> Restaged {
    if let Err(error) = verify_author_allowlisted(&entry.directive, context.allowlist) {
        warn!(error = %log_error(&error), "rejected resolved orphan: author");
        return refused_if_permanent(intake_refusal_is_permanent(&error));
    }
    if let Err(error) =
        verify_remote_signature(&entry.directive, context.signing_enabled, context.mesh_id)
    {
        warn!(error = %log_error(&error), "rejected resolved orphan: signature");
        return refused_if_permanent(intake_refusal_is_permanent(&error));
    }
    let bytes = RecordEstimate::directive_bytes(&entry.directive);
    if !budget.admits(bytes) {
        debug!(content_id = %entry.id, bytes, "resolved orphan deferred: no room under the size cap");
        return Restaged::Deferred;
    }
    match service.stage_remote_directive(entry.directive.clone()) {
        Ok(Some(content_id)) => {
            info!(content_id = %content_id, "resolved orphan directive");
            budget.staged.add(bytes);
            let announce = match entry.directive {
                // M-45: the id is in hand; converting must not re-hash.
                ledger::model::Directive::Transaction(ref txn) => {
                    Some(Box::new(txn_to_graphql(txn, content_id, true)))
                }
                _ => None,
            };
            Restaged::Staged { announce }
        }
        Ok(None) => Restaged::Dropped,
        Err(error) => {
            let Some(account) = account_wait_target(&error) else {
                warn!(error = %log_error(&error), "rejected resolved orphan directive");
                if let ServiceError::LamportAdvance { remote, .. } = &error {
                    return Restaged::Ratcheted {
                        remote_lamport: *remote,
                    };
                }
                return refused_if_permanent(stage_refusal_is_permanent(&error));
            };
            match buffer.insert_awaiting_accounts(
                entry.id.clone(),
                entry.directive,
                vec![account.clone()],
                entry.from_peer,
            ) {
                // The entry was removed from the buffer to be retried, so
                // `Duplicate` here would mean a concurrent re-buffer of the same
                // id; either way it is resident and waiting on `account`.
                outcome if outcome.accepted() => {
                    debug!(content_id = %entry.id, %account, "re-buffered orphan awaiting an open");
                    Restaged::Rebuffered { account }
                }
                _ => {
                    warn!(content_id = %entry.id, "orphan buffer full; dropped re-buffered entry");
                    Restaged::Dropped
                }
            }
        }
    }
}

fn refused_if_permanent(permanent: bool) -> Restaged {
    if permanent {
        Restaged::Refused
    } else {
        Restaged::Dropped
    }
}

/// Drain orphans whose parents have arrived, or whose account is now open
/// (M-09), as far as they fit under the size cap (T77 / L-70). Re-checks
/// signature and author.
///
/// M-15: this STAGES each resolved orphan into memory only (no persist per
/// orphan). The caller persists once, after the drain, covering the whole batch
/// plus every orphan resolved here. Parent presence is a DAG lookup (L-35), so
/// the drain clones no id set at all.
///
/// T77 / L-70: `budget` carries the record the caller's staged set has become;
/// each freed orphan is staged only if the set plus it still fits the
/// headroom, and the budget grows by what was staged, so the commit that
/// follows cannot be refused by the cap projection for anything this drain
/// did. An orphan with no room is dropped from the buffer and counted in
/// [`DrainOutcome::deferred`]; the caller backs the peer off.
///
/// T77 / L-70: nothing is announced to GraphQL subscribers from here — the
/// staged transactions ride back in [`DrainOutcome::announce`] and the caller
/// publishes them once its commit is durable.
///
/// The loop terminates. Another pass runs only on real progress, which is
/// either (a) a directive staged — monotone in a DAG this call grows only by
/// staging — or (b) a buffered entry moving to a blocking account it has not
/// been tried against yet in this call, which `attempted` counts at most once
/// per (entry, account) pair.
///
/// Returns the `(delivering peer, id)` of every freed entry that was then
/// refused for good (L-34), for the caller to record once the batch is durable,
/// and the `(delivering peer, id, remote lamport)` of every one the adoption
/// ratchet refused (T72 / L-69). An entry buffered without a known peer is not
/// returned: both records are keyed by peer.
pub async fn drain_orphans(
    orphan_buffer: &Arc<RwLock<OrphanBuffer>>,
    service: &mut ledger::service::LedgerService,
    signing_enabled: bool,
    allowlist: &PeerAllowlist,
    mesh_id: &str,
    budget: &mut DrainBudget,
) -> DrainOutcome {
    let context = DrainContext {
        signing_enabled,
        allowlist,
        mesh_id,
    };
    // L-35 / R-19: parent presence is asked of the DAG directly. The cloned
    // `all_directive_ids()` set this used to keep in step with its own stages
    // was an O(N) copy per drain; `contains_directive` is exact under the
    // write lock held here, since a staged directive is in the DAG the moment
    // it is staged.
    let mut buffer = orphan_buffer.write().await;
    let mut attempted: HashSet<(String, String)> = HashSet::new();
    let mut drained = DrainOutcome::default();
    let mut resolved_any = true;
    while resolved_any {
        resolved_any = false;

        for parent_id in buffer.wanted_parent_ids() {
            if !service.contains_directive(&parent_id) {
                continue;
            }
            for entry in buffer.parent_arrived(&parent_id) {
                let entry_id = entry.id.clone();
                let from_peer = entry.from_peer.clone();
                let outcome = restage_freed_entry(&mut buffer, service, &context, entry, budget);
                note_drain_refusal(&outcome, from_peer, &entry_id, &mut drained);
                resolved_any |= made_progress(outcome, entry_id, &mut attempted, &mut drained);
            }
        }

        // M-09: an `open` for a waited-on account may have landed in this
        // batch, or via an orphan resolved just above.
        for account in buffer.wanted_accounts() {
            if !service.accounts().has_open(&account) {
                continue;
            }
            for entry in buffer.account_opened(&account) {
                let entry_id = entry.id.clone();
                let from_peer = entry.from_peer.clone();
                let outcome = restage_freed_entry(&mut buffer, service, &context, entry, budget);
                note_drain_refusal(&outcome, from_peer, &entry_id, &mut drained);
                resolved_any |= made_progress(outcome, entry_id, &mut attempted, &mut drained);
            }
        }
    }
    drained
}

/// What [`drain_orphans`] reports back for the caller's per-peer records.
#[derive(Default)]
pub struct DrainOutcome {
    /// `(delivering peer, id)` refused for good (L-34).
    pub permanent: Vec<(String, String)>,
    /// `(delivering peer, id, remote lamport)` refused by the ratchet (L-69).
    pub ratcheted: Vec<(String, String, u64)>,
    /// Freed orphans not staged for want of room under the cap (T77 / L-70).
    pub deferred: usize,
    /// Staged transactions, to announce once the caller's commit is durable
    /// (T77 / L-70).
    pub announce: Vec<GraphqlTransaction>,
}

/// Collect a drained entry that was refused for good (L-34) or by the
/// adoption ratchet (L-69).
fn note_drain_refusal(
    outcome: &Restaged,
    from_peer: Option<String>,
    entry_id: &str,
    refused: &mut DrainOutcome,
) {
    match (outcome, from_peer) {
        (Restaged::Refused, Some(peer)) => refused.permanent.push((peer, entry_id.to_owned())),
        (Restaged::Ratcheted { remote_lamport }, Some(peer)) => {
            refused
                .ratcheted
                .push((peer, entry_id.to_owned(), *remote_lamport));
        }
        _ => {}
    }
}

/// Whether a restage attempt justifies another drain pass (see
/// [`drain_orphans`]); also files a staged transaction for announcement and
/// counts a deferral.
fn made_progress(
    outcome: Restaged,
    entry_id: String,
    attempted: &mut HashSet<(String, String)>,
    drained: &mut DrainOutcome,
) -> bool {
    match outcome {
        Restaged::Staged { announce } => {
            drained
                .announce
                .extend(announce.map(|transaction| *transaction));
            true
        }
        // A new (entry, blocking account) pair means the release uncovered a
        // different unmet dependency — worth one more pass. A pair already seen
        // means the entry is going in circles, and does not.
        Restaged::Rebuffered { account } => attempted.insert((entry_id, account)),
        Restaged::Deferred => {
            drained.deferred += 1;
            false
        }
        Restaged::Dropped | Restaged::Refused | Restaged::Ratcheted { .. } => false,
    }
}

async fn write_message(
    send: &mut SendStream,
    message: &WireMessage,
    io_timeout: Duration,
) -> Result<(), String> {
    let bytes = message.to_wire()?;
    match tokio::time::timeout(io_timeout, send.write_all(&bytes)).await {
        Ok(result) => result.map_err(|error| error.to_string()),
        // A stalled write is a torn-down session, not a clean shutdown, so this
        // error string deliberately avoids "early eof"/"closed" (M-06).
        Err(_elapsed) => Err("anti-entropy write timed out".to_owned()),
    }
}

/// Decide, from a frame's length and leading peek bytes alone, whether it can be
/// rejected without reading or buffering the rest (M-16).
///
/// `peek` is the frame's leading bytes: the CBOR map header at `peek[0]` (whose
/// value depends on the variant's field count) followed by the `"type"` map
/// entry. Because serde emits the internal tag first (see
/// `protocol::SUPPLY_TYPE_DISCRIMINATOR`), a genuine `Supply` carries the Supply
/// discriminator at `peek[1..]`; anything else there is a `Want`/`HaveHeads`/
/// `Announce`, and if it is also over `NON_SUPPLY_FRAME_CAP` it is a bloated
/// vector we refuse before allocating its body.
///
/// A frame within the cap is never rejectable here (only `Supply` legitimately
/// exceeds it). A frame over the cap whose peek is too short to hold the
/// discriminator is rejectable — it cannot be a well-formed `Supply`.
fn frame_is_rejectable(len: usize, peek: &[u8]) -> bool {
    if len <= NON_SUPPLY_FRAME_CAP {
        return false;
    }
    // The offset rule (map header at peek[0], tag entry after it) is stated once,
    // in `protocol`, so this gate and T43's pre-scan gate cannot drift apart.
    !p2p::protocol::carries_supply_discriminator(peek)
}

/// Why a frame read ended (T41).
///
/// Replaces the `error.contains("early eof") || error.contains("closed")`
/// classification `serve_anti_entropy` used to run on a formatted string. That
/// was fragile in both directions: a peer-supplied or transport-supplied message
/// that happened to contain the word "closed" broke the session loop as if the
/// peer had hung up cleanly, and any rewording of an upstream error silently
/// reclassified a clean shutdown as a failure. The distinction is now carried in
/// the type, and [`classify_read_error`] is the ONE place that derives it — from
/// iroh's error enum, by variant, not by text.
#[derive(Debug)]
enum FrameError {
    /// The peer finished the stream, or closed the connection, between frames.
    ///
    /// A clean end of session: the serve loop breaks out of it rather than
    /// reporting a failure.
    Eof,
    /// A read or write exceeded its I/O timeout (M-06).
    ///
    /// Deliberately distinct from [`Self::Eof`]: a stall is a torn-down session,
    /// not a clean break, and must never be mistaken for one. (This is what the
    /// old code achieved by hand-picking timeout message wording that avoided
    /// the matched substrings — a constraint that no longer has to be
    /// remembered.)
    Timeout,
    /// Framing, decode, or a transport failure mid-frame.
    Protocol(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => write!(formatter, "peer ended the anti-entropy stream"),
            Self::Timeout => write!(formatter, "anti-entropy read timed out"),
            Self::Protocol(message) => write!(formatter, "{message}"),
        }
    }
}

/// Classify one [`ReadExactError`] from an iroh [`RecvStream`] (T41).
///
/// The single point where a transport error becomes an [`FrameError::Eof`] or
/// not, and it does so **by variant**:
///
/// * `FinishedEarly(0)` — the peer called `finish()` and we were between frames.
///   `FinishedEarly(n > 0)` is a *truncated* frame and stays a protocol error.
/// * `ClosedStream` — this stream is done.
/// * `ConnectionLost(ApplicationClosed | LocallyClosed)` — the peer (or we) shut
///   the connection down deliberately, which is how a session ends when the
///   other side hits its request budget.
///
/// Everything else — a reset, a timed-out connection, a transport error — is a
/// real failure and is reported as one. No string matching is involved, so this
/// does not have to be revisited when an upstream error message is reworded.
fn classify_read_error(error: ReadExactError) -> FrameError {
    match error {
        ReadExactError::FinishedEarly(0) => FrameError::Eof,
        ReadExactError::ReadError(ReadError::ClosedStream) => FrameError::Eof,
        ReadExactError::ReadError(ReadError::ConnectionLost(
            ConnectionError::ApplicationClosed(_) | ConnectionError::LocallyClosed,
        )) => FrameError::Eof,
        other => FrameError::Protocol(other.to_string()),
    }
}

/// Re-label an end-of-stream that arrives PART WAY THROUGH a frame.
///
/// A clean break can only happen between frames. Once the length prefix has
/// been read, the peer has promised `len` more bytes, so its finishing the
/// stream is a truncated frame — a protocol error — not a clean shutdown, and
/// must not break the serve loop as if it were one.
fn truncated_mid_frame(error: FrameError) -> FrameError {
    match error {
        FrameError::Eof => {
            FrameError::Protocol("anti-entropy frame truncated: peer ended mid-frame".to_owned())
        }
        other => other,
    }
}

/// "Read exactly `buf.len()` bytes" abstraction (M-16, L-19).
///
/// Lets `read_frame`'s framing logic be exercised by an in-memory reader in
/// tests while production reads from an iroh [`RecvStream`] via its inherent
/// `read_exact` — deliberately NOT tokio's `AsyncReadExt::read_exact`, whose
/// `AsyncRead` impl on `RecvStream` does not drive the QUIC stream the way the
/// inherent method does.
trait ExactReader {
    fn read_exact_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = Result<(), FrameError>>;
}

impl ExactReader for RecvStream {
    async fn read_exact_bytes(&mut self, buf: &mut [u8]) -> Result<(), FrameError> {
        self.read_exact(buf).await.map_err(classify_read_error)
    }
}

/// Read one frame, charging its body to `reservation` (L-39).
///
/// Inbound (serve-side) reads pass a reservation from the handler's
/// `ConnectionLimiter`; outbound reads pass [`FrameReservation::unmetered`] —
/// see there for why the client side is not charged to the inbound budget.
async fn read_message(
    recv: &mut RecvStream,
    io_timeout: Duration,
    reservation: &mut FrameReservation,
) -> Result<WireMessage, FrameError> {
    read_frame(recv, io_timeout, reservation).await
}

/// Read one length-prefixed CBOR frame, applying the M-16 oversized-frame gate
/// and the L-19 incremental body read.
///
/// Generic over [`ExactReader`] so the framing logic is unit-testable with an
/// in-memory reader; production always passes an iroh [`RecvStream`].
///
/// The M-16 residual this used to carry — a frame that *does* open with the
/// `Supply` discriminator but then claims millions of fake entries, which serde
/// `Content`-buffers in full before `MAX_SUPPLY_ENTRIES` can reject it — is
/// closed by T43. `decode_checked` now runs a bounded CBOR header scan
/// (`p2p::cbor_scan`) over any `Supply`-discriminator frame and refuses an
/// `entries` array header claiming more than the cap **before** handing the
/// bytes to serde. Nothing changes at this call site: the gate lives at the
/// shared inbound choke point so the gossip-side decode is covered by the same
/// code.
async fn read_frame<R>(
    recv: &mut R,
    io_timeout: Duration,
    reservation: &mut FrameReservation,
) -> Result<WireMessage, FrameError>
where
    R: ExactReader,
{
    // 1. Length prefix. This is the only position at which a clean end of
    //    session can occur — between frames — so a `FrameError::Eof` from here
    //    is propagated as-is for `serve_anti_entropy` to break on (M-06). An Eof
    //    anywhere BELOW this point is a half-delivered frame and is reported as
    //    the truncation it is.
    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(io_timeout, recv.read_exact_bytes(&mut len_buf)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(_elapsed) => return Err(FrameError::Timeout),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE as usize {
        return Err(FrameError::Protocol(format!(
            "anti-entropy frame too large: {len}"
        )));
    }

    // 2. Oversized-frame gate (M-16). Only `Supply` legitimately exceeds
    //    NON_SUPPLY_FRAME_CAP. For an oversized frame, peek just the map header
    //    byte + the "type" entry: if it is not the `Supply` discriminator,
    //    reject now — WITHOUT reading or allocating the remaining `len` bytes.
    //    This tears down a ~670 MiB `Want`/`HaveHeads` vector after ~13 bytes.
    let discriminator = p2p::protocol::SUPPLY_TYPE_DISCRIMINATOR;
    let peek_len = 1 + discriminator.len();
    let mut body: Vec<u8> = Vec::new();
    if len > NON_SUPPLY_FRAME_CAP {
        let mut peek = vec![0u8; peek_len];
        match tokio::time::timeout(io_timeout, recv.read_exact_bytes(&mut peek)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(truncated_mid_frame(error)),
            Err(_elapsed) => return Err(FrameError::Timeout),
        }
        if frame_is_rejectable(len, &peek) {
            return Err(FrameError::Protocol(format!(
                "oversized non-supply frame: {len} bytes"
            )));
        }
        // Claims to be `Supply`: carry the peeked bytes forward as the body head.
        body = peek;
    }

    // 3. Incremental body read (L-19): grow the buffer chunk by chunk so a
    //    stalled stream pins only the bytes actually received — never `len`
    //    bytes reserved up front. Each chunk read is bounded by the I/O timeout.
    //
    //    L-39: every growth of the buffer's CAPACITY is charged to the inbound
    //    byte budget before it is allocated, so what is charged is what is
    //    actually held (the chunk is read straight into the buffer's tail, so
    //    there is no second per-chunk allocation to account for). Capacity
    //    doubles, capped at `len`, which keeps the copying linear and the charge
    //    within 2× of the bytes received plus one chunk. A grow the budget
    //    cannot cover tears the frame down at once — never waits for budget,
    //    which would be H-10's wedge — and `reservation`'s owner releases it.
    while body.len() < len {
        let want = (len - body.len()).min(READ_CHUNK);
        let filled = body.len() + want;
        if filled > body.capacity() {
            let capacity = body.capacity().saturating_mul(2).clamp(filled, len);
            if !reservation.grow_to(capacity) {
                return Err(FrameError::Protocol(format!(
                    "anti-entropy frame refused: in-flight frame byte budget exhausted \
                     ({len}-byte frame)"
                )));
            }
            body.reserve_exact(capacity - body.len());
        }
        let start = body.len();
        body.resize(filled, 0);
        match tokio::time::timeout(io_timeout, recv.read_exact_bytes(&mut body[start..])).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(truncated_mid_frame(error)),
            Err(_elapsed) => return Err(FrameError::Timeout),
        }
    }

    // 4. Size + version + cardinality gates (H-7). Even a frame that passed the
    //    `Supply` discriminator gate is still bounded here.
    WireMessage::decode_checked(&body).map_err(|error| FrameError::Protocol(error.to_string()))
}

/// Test-only scaffolding. `pub(crate)` so the `p2p_service` network tests can
/// reuse the endpoint/handler/ledger helpers instead of duplicating them; the
/// module is `#[cfg(test)]`, so nothing here exists in a real build.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::Duration;

    use chrono::NaiveDate;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{Endpoint, TransportAddr};
    use ledger::model::{Amount, Flag};
    use ledger::service::{LedgerService, PostingInput, TransactionInput};
    use rust_decimal_macros::dec;

    /// The crate-wide network-test lock (T41). Re-exported here so the
    /// `p2p_service` tests that already import this module's helpers keep one
    /// import, and so no test module owns the lock the others depend on.
    pub(crate) use crate::test_support::NET_TEST_LOCK;

    /// T63 (H-12): the ratchet's refusal is judged against THIS node's clock,
    /// so the L-34 refusal cache must not keep it — caching it would stop a
    /// node that is climbing through a history from ever adopting its top.
    /// (T64's head bound, once listed here too, is gone: T72 / H-21.)
    #[test]
    fn test_state_dependent_stage_refusals_are_not_cached() {
        for error in [
            ServiceError::LamportAdvance {
                remote: 1 << 40,
                local: 0,
                author: Some("peer".to_owned()),
            },
            ServiceError::LamportCeiling {
                next: ledger::service::LAMPORT_CEILING,
                author: None,
            },
        ] {
            assert!(!stage_refusal_is_permanent(&error), "{error}");
        }
    }

    pub(crate) async fn bind_direct_endpoint() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .alpns(vec![p2p::protocol::ANTI_ENTROPY_ALPN.to_vec()])
            .bind()
            .await
            .expect("bind direct-only Iroh endpoint")
    }

    pub(crate) async fn wait_until_dialable(endpoint: &Endpoint) {
        for _ in 0..50 {
            if endpoint.addr().addrs.iter().any(TransportAddr::is_ip) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "endpoint {} never advertised an IP address: {:?}",
            endpoint.id(),
            endpoint.addr()
        );
    }

    fn balanced_funding_input() -> TransactionInput {
        TransactionInput {
            date: NaiveDate::from_ymd_opt(2024, 1, 15).expect("valid date"),
            flag: Flag::Complete,
            payee: Some("Acme".to_owned()),
            narration: Some("Funding".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        }
    }

    pub(crate) fn make_handler(
        ledger: SharedLedger,
        allowlist: PeerAllowlist,
    ) -> AntiEntropyHandler {
        make_handler_with_timeouts(ledger, allowlist, AntiEntropyTimeouts::default())
    }

    pub(crate) fn make_handler_with_timeouts(
        ledger: SharedLedger,
        allowlist: PeerAllowlist,
        timeouts: AntiEntropyTimeouts,
    ) -> AntiEntropyHandler {
        make_handler_full(ledger, allowlist, timeouts, AntiEntropyLimits::default())
    }

    fn make_handler_with_limits(
        ledger: SharedLedger,
        allowlist: PeerAllowlist,
        limits: AntiEntropyLimits,
    ) -> AntiEntropyHandler {
        make_handler_full(ledger, allowlist, AntiEntropyTimeouts::default(), limits)
    }

    fn make_handler_full(
        ledger: SharedLedger,
        allowlist: PeerAllowlist,
        timeouts: AntiEntropyTimeouts,
        limits: AntiEntropyLimits,
    ) -> AntiEntropyHandler {
        AntiEntropyHandler {
            ledger,
            broadcast: TransactionBroadcast::new(),
            orphan_buffer: Arc::new(RwLock::new(OrphanBuffer::new())),
            allowlist,
            signing_enabled: false,
            mesh_id: String::new(),
            timeouts,
            limits,
            limiter: ConnectionLimiter::new(limits),
            connections: PeerConnectionCache::new(),
            supply_backoff: SupplyBackoff::default(),
        }
    }

    // ─── M-16 / L-19 read_frame gate (deterministic, no network) ───────────

    /// In-memory [`ExactReader`] over a byte slice. `read_frame` reading past the
    /// slice fails like an early EOF — which lets the oversized-frame test prove
    /// the gate fires WITHOUT the (absent) body ever being present to read.
    struct SliceReader<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl ExactReader for SliceReader<'_> {
        async fn read_exact_bytes(&mut self, buf: &mut [u8]) -> Result<(), FrameError> {
            let end = self.pos + buf.len();
            if end > self.data.len() {
                return Err(FrameError::Eof);
            }
            buf.copy_from_slice(&self.data[self.pos..end]);
            self.pos = end;
            Ok(())
        }
    }

    fn slice_reader(data: &[u8]) -> SliceReader<'_> {
        SliceReader { data, pos: 0 }
    }

    /// B: the pure oversized-frame decision. Within the cap nothing is
    /// rejectable; over the cap only a non-`Supply` (or a peek too short to be a
    /// well-formed `Supply`) is.
    #[test]
    fn frame_is_rejectable_gate() {
        let discriminator = p2p::protocol::SUPPLY_TYPE_DISCRIMINATOR;
        let mut supply_peek = vec![0xA3u8];
        supply_peek.extend_from_slice(discriminator);
        let want_peek = WireMessage::want(vec!["x".to_owned()]).to_cbor().unwrap();

        let over = NON_SUPPLY_FRAME_CAP + 1;

        // Within the cap: never rejectable here, whatever the content.
        assert!(!frame_is_rejectable(NON_SUPPLY_FRAME_CAP, &want_peek));
        assert!(!frame_is_rejectable(NON_SUPPLY_FRAME_CAP, &supply_peek));
        // Over the cap + non-supply discriminator: rejectable.
        assert!(frame_is_rejectable(over, &want_peek));
        // Over the cap + Supply discriminator: NOT rejectable (a real big Supply).
        assert!(!frame_is_rejectable(over, &supply_peek));
        // Over the cap + peek too short to hold the discriminator: rejectable.
        assert!(frame_is_rejectable(over, &[0xA3]));
    }

    /// B / L-19: an oversized frame whose head is NOT the `Supply` discriminator
    /// is rejected from the ~13-byte peek — `read_frame` returns the rejection
    /// error and never even attempts to read the claimed multi-MiB body (which
    /// is absent from the slice, so an attempt would surface a different error).
    #[tokio::test]
    async fn read_frame_rejects_oversized_non_supply_without_reading_body() {
        // Frame a Want-shaped CBOR head with a length prefix claiming a ~2 MiB
        // body (> NON_SUPPLY_FRAME_CAP). The body itself is never provided.
        let want_head = WireMessage::want(vec!["x".to_owned()]).to_cbor().unwrap();
        let claimed_len = (NON_SUPPLY_FRAME_CAP + 1_000_000) as u32;
        let mut framed = claimed_len.to_be_bytes().to_vec();
        framed.extend_from_slice(&want_head);

        let mut reader = slice_reader(&framed);
        let error = read_frame(
            &mut reader,
            Duration::from_secs(1),
            &mut FrameReservation::unmetered(),
        )
        .await
        .expect_err("oversized non-supply frame must be rejected");
        assert!(
            matches!(&error, FrameError::Protocol(message) if message.contains("oversized non-supply")),
            "expected the oversized-frame gate to fire, got: {error:?}"
        );
    }

    /// B: a genuine `Supply` larger than the non-supply cap (but within
    /// `MAX_MESSAGE_SIZE` and `MAX_SUPPLY_ENTRIES`) is accepted — no false
    /// rejection — exercising the peek-carry-forward + chunked body read.
    #[tokio::test]
    async fn read_frame_accepts_genuine_large_supply() {
        let entries: Vec<p2p::protocol::SupplyEntry> = (0..12)
            .map(|index| p2p::protocol::SupplyEntry {
                id: format!("{index:064x}"),
                kind: p2p::protocol::DirectiveKind::Open,
                economic_bean: "x".repeat(120 * 1024),
                envelope: std::collections::BTreeMap::new(),
            })
            .collect();
        let message = WireMessage::supply(entries);
        let wire = message.to_wire().expect("frame large supply");
        let body_len = wire.len() - 4;
        assert!(
            body_len > NON_SUPPLY_FRAME_CAP,
            "test frame must exceed the non-supply cap: {body_len}"
        );
        assert!(
            body_len <= MAX_MESSAGE_SIZE as usize,
            "and stay within 16 MiB"
        );

        let mut reader = slice_reader(&wire);
        let decoded = read_frame(
            &mut reader,
            Duration::from_secs(5),
            &mut FrameReservation::unmetered(),
        )
        .await
        .expect("a genuine large Supply must be accepted");
        assert_eq!(decoded, message, "round-trip mismatch on large Supply");
    }

    /// Small frames of every variant still round-trip through the incremental
    /// (`len <= cap`, no peek) read path.
    #[tokio::test]
    async fn read_frame_roundtrips_small_frames() {
        let messages = [
            WireMessage::want(vec!["a".to_owned(), "b".to_owned()]),
            WireMessage::have_heads(vec!["tx".to_owned()], vec!["dir".to_owned()]),
            WireMessage::announce("id".to_owned(), p2p::protocol::DirectiveKind::Open),
            WireMessage::supply(vec![]),
        ];
        for message in messages {
            let wire = message.to_wire().expect("frame");
            let mut reader = slice_reader(&wire);
            let decoded = read_frame(
                &mut reader,
                Duration::from_secs(2),
                &mut FrameReservation::unmetered(),
            )
            .await
            .expect("read small frame");
            assert_eq!(decoded, message);
        }
    }

    /// R6 / SPEC M6: three direct-only endpoints converge over ALPN (no N0 relay).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn three_node_alpn_convergence() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_zero = bind_direct_endpoint().await;
        let endpoint_one = bind_direct_endpoint().await;
        let endpoint_two = bind_direct_endpoint().await;

        let id_zero = endpoint_zero.id();
        let id_one = endpoint_one.id();
        let id_two = endpoint_two.id();

        let allow_zero = PeerAllowlist::parse(&[id_one.to_string(), id_two.to_string()])
            .expect("allowlist zero");
        let allow_one = PeerAllowlist::parse(&[id_zero.to_string(), id_two.to_string()])
            .expect("allowlist one");
        let allow_two = PeerAllowlist::parse(&[id_zero.to_string(), id_one.to_string()])
            .expect("allowlist two");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_zero: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("zero.bean"), id_zero.to_string())
                .expect("boot ledger zero"),
        ));
        let ledger_one: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("one.bean"), id_one.to_string())
                .expect("boot ledger one"),
        ));
        let ledger_two: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("two.bean"), id_two.to_string())
                .expect("boot ledger two"),
        ));

        {
            let mut service = ledger_zero.write().await;
            service
                .open_account(
                    "Assets:Cash".to_owned(),
                    NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                    vec!["USD".to_owned()],
                )
                .expect("open cash");
            service
                .open_account(
                    "Equity:Opening".to_owned(),
                    NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                    Vec::new(),
                )
                .expect("open equity");
            service
                .append_transaction(balanced_funding_input())
                .expect("append funding");
        }
        let source_count = ledger_zero.read().await.directive_count();
        assert_eq!(
            source_count, 3,
            "source node should have two opens and one txn"
        );

        let handler_zero = make_handler(ledger_zero.clone(), allow_zero);
        let handler_one = make_handler(ledger_one.clone(), allow_one);
        let handler_two = make_handler(ledger_two.clone(), allow_two);

        let router_zero = Router::builder(endpoint_zero.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_zero.clone())
            .spawn();
        let router_one = Router::builder(endpoint_one.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_one.clone())
            .spawn();
        let router_two = Router::builder(endpoint_two.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_two.clone())
            .spawn();

        // Wait for real addresses instead of a fixed sleep: on a loaded machine
        // 200 ms is not always enough for the endpoints to advertise an IP, and
        // the first dial then fails for a reason the retry loop cannot see.
        wait_until_dialable(&endpoint_zero).await;
        wait_until_dialable(&endpoint_one).await;
        wait_until_dialable(&endpoint_two).await;

        let addr_zero = endpoint_zero.addr();
        let addr_one = endpoint_one.addr();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            exchange_with_peer(&endpoint_one, addr_zero.clone(), &handler_one).await;
            exchange_with_peer(&endpoint_two, addr_one.clone(), &handler_two).await;
            let count_one = ledger_one.read().await.directive_count();
            let count_two = ledger_two.read().await.directive_count();
            if count_one == source_count && count_two == source_count {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let probe = endpoint_one
                    .connect(addr_zero.clone(), p2p::protocol::ANTI_ENTROPY_ALPN)
                    .await;
                let _ = router_zero.shutdown().await;
                let _ = router_one.shutdown().await;
                let _ = router_two.shutdown().await;
                panic!(
                    "R6: three-node ALPN cluster did not converge: zero={source_count} one={count_one} two={count_two}; probe={probe:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let _ = router_zero.shutdown().await;
        let _ = router_one.shutdown().await;
        let _ = router_two.shutdown().await;
    }

    /// Write a `.bean` file holding `count` distinct `open` directives.
    ///
    /// Built as text so the source node can boot a large ledger in one shot;
    /// `openledger-author` is required on the receive path (H-14), and is not
    /// part of the economic body, so every directive still hashes distinctly by
    /// its account name alone.
    pub(crate) fn write_open_directive_ledger(path: &std::path::Path, count: usize, author: &str) {
        use std::fmt::Write as _;

        let mut content = String::new();
        for index in 0..count {
            writeln!(content, "2024-01-01 open Assets:Acct{index:05}").expect("write to String");
            writeln!(content, "  openledger-author: \"{author}\"").expect("write to String");
            content.push('\n');
        }
        std::fs::write(path, content).expect("write source ledger");
    }

    /// One-way catch-up of a ledger too big for a single frame of any kind.
    ///
    /// The source serves; the sink starts empty and pulls until it matches.
    async fn run_catchup_beyond_caps(directive_count: usize, timeout: Duration) {
        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_sink = bind_direct_endpoint().await;

        let id_source = endpoint_source.id();
        let id_sink = endpoint_sink.id();

        let allow_source = PeerAllowlist::parse(&[id_sink.to_string()]).expect("allowlist source");
        let allow_sink = PeerAllowlist::parse(&[id_source.to_string()]).expect("allowlist sink");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let source_path = temp_dir.path().join("source.bean");
        write_open_directive_ledger(&source_path, directive_count, &id_source.to_string());

        let ledger_source: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(source_path, id_source.to_string()).expect("boot source ledger"),
        ));
        let ledger_sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), id_sink.to_string())
                .expect("boot sink ledger"),
        ));

        let source_count = ledger_source.read().await.directive_count();
        assert_eq!(source_count, directive_count, "source ledger boot count");
        assert_eq!(
            ledger_sink.read().await.directive_count(),
            0,
            "sink starts empty"
        );

        let handler_source = make_handler(ledger_source.clone(), allow_source);
        let handler_sink = make_handler(ledger_sink.clone(), allow_sink);

        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_source.clone())
            .spawn();

        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_sink).await;
        let addr_source = endpoint_source.addr();

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            exchange_with_peer(&endpoint_sink, addr_source.clone(), &handler_sink).await;
            let count = ledger_sink.read().await.directive_count();
            if count == source_count {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let _ = router_source.shutdown().await;
                panic!("H-02: sink never caught up: source={source_count} sink={count}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = router_source.shutdown().await;
    }

    /// H-02: 1_500 directives is past both the 256-entry `Supply` cap and the
    /// 1_024-id `Want` cap, so the pre-fix senders wedge here — the server
    /// answered a 1_024-id `Want` with one oversized `Supply` that the client's
    /// own `decode_checked` then rejected, forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_node_catchup_beyond_caps() {
        let _serialized = NET_TEST_LOCK.lock().await;
        run_catchup_beyond_caps(1_500, Duration::from_secs(180)).await;
    }

    /// H-02: 4_300 directives additionally crosses `MAX_HAVE_HEADS` (4_096), so
    /// the head advert itself has to paginate.
    ///
    /// Formerly `#[ignore]`d: the receiving side re-serialized and fsynced the
    /// whole `.bean` file on every single insert, making catch-up O(M×N) IO
    /// (~102 s here). T27 (M-15) batches the persist — one full-file write per
    /// Supply batch instead of one per entry — so this now completes in ~2 s and
    /// runs as regular suite coverage. The 180 s deadline is a generous CI
    /// safety net, not the expected runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_node_catchup_beyond_have_heads_cap() {
        let _serialized = NET_TEST_LOCK.lock().await;
        run_catchup_beyond_caps(4_300, Duration::from_secs(180)).await;
    }

    /// Short timeouts so the M-06 tests trip their read caps in milliseconds.
    fn short_timeouts() -> AntiEntropyTimeouts {
        AntiEntropyTimeouts {
            connect: Duration::from_millis(500),
            io: Duration::from_millis(500),
            ..AntiEntropyTimeouts::default()
        }
    }

    /// Seed `ledger` with two `open`s and one balanced transaction (3 directives).
    async fn seed_funding_ledger(ledger: &SharedLedger) -> usize {
        let mut service = ledger.write().await;
        service
            .open_account(
                "Assets:Cash".to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                vec!["USD".to_owned()],
            )
            .expect("open cash");
        service
            .open_account(
                "Equity:Opening".to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                Vec::new(),
            )
            .expect("open equity");
        service
            .append_transaction(balanced_funding_input())
            .expect("append funding");
        service.directive_count()
    }

    /// An ALPN server that accepts a connection and then never replies — the
    /// M-06 stall vector. Used to prove the client's per-frame read timeout
    /// fires instead of the session hanging forever.
    #[derive(Debug, Clone)]
    struct TarpitHandler;

    impl ProtocolHandler for TarpitHandler {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            // Accept the client's bi-stream, then hang forever without ever
            // replying: the client must tear the session down on its own timer.
            let _streams = connection.accept_bi().await;
            std::future::pending::<Result<(), AcceptError>>().await
        }
    }

    /// M-06 core vector: a peer that accepts a connection and then never replies
    /// (a "tarpit") must not hang the client. The per-frame read timeout tears
    /// the session down; `exchange_with_peer` RETURNS well within a generous
    /// bound. The assertion is that the OUTER guard timeout does NOT fire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tarpit_peer_read_times_out() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_tarpit = bind_direct_endpoint().await;

        let id_client = endpoint_client.id();
        let id_tarpit = endpoint_tarpit.id();

        let router_tarpit = Router::builder(endpoint_tarpit.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, TarpitHandler)
            .spawn();

        let allow_client =
            PeerAllowlist::parse(&[id_tarpit.to_string()]).expect("allowlist client");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));

        let handler_client =
            make_handler_with_timeouts(ledger_client, allow_client, short_timeouts());

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_tarpit).await;
        let addr_tarpit = endpoint_tarpit.addr();

        // 4×io is a generous bound: the exchange should return at ~io (500 ms)
        // once the read against the silent peer times out.
        let outcome = tokio::time::timeout(
            Duration::from_millis(2_000),
            exchange_with_peer(&endpoint_client, addr_tarpit, &handler_client),
        )
        .await;

        let _ = router_tarpit.shutdown().await;
        assert!(
            outcome.is_ok(),
            "M-06: exchange_with_peer hung against a tarpit peer instead of timing out"
        );
    }

    /// M-06 money test: one healthy peer + one tarpit, exchanged CONCURRENTLY
    /// (the pattern `spawn_anti_entropy_loop` now uses). The healthy peer's
    /// directives must still be pulled despite the tarpit, and the whole tick
    /// must finish within a bounded time — proving a hung peer no longer blocks
    /// a healthy one, which it did when the loop awaited each exchange inline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hung_peer_does_not_block_healthy_peer() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_tarpit = bind_direct_endpoint().await;

        let id_client = endpoint_client.id();
        let id_source = endpoint_source.id();
        let id_tarpit = endpoint_tarpit.id();

        // Seed the healthy source with independent `open`s (no parent chain), so
        // one exchange round transfers and applies the whole set with no orphan
        // buffering — the single-tick convergence here is deterministic, unlike a
        // transaction that depends on its parents arriving first.
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let source_path = temp_dir.path().join("source.bean");
        write_open_directive_ledger(&source_path, 5, &id_source.to_string());
        let ledger_source: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(source_path, id_source.to_string()).expect("boot source ledger"),
        ));
        let source_count = ledger_source.read().await.directive_count();
        assert_eq!(source_count, 5, "seed: five independent opens");

        let allow_source =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist source");
        let handler_source = make_handler(ledger_source.clone(), allow_source);
        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_source.clone())
            .spawn();

        let router_tarpit = Router::builder(endpoint_tarpit.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, TarpitHandler)
            .spawn();

        let allow_client = PeerAllowlist::parse(&[id_source.to_string(), id_tarpit.to_string()])
            .expect("allowlist client");
        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));
        let handler_client =
            make_handler_with_timeouts(ledger_client.clone(), allow_client, short_timeouts());

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_tarpit).await;

        let addr_source = endpoint_source.addr();
        let addr_tarpit = endpoint_tarpit.addr();

        // Each tick runs BOTH peers' exchanges concurrently, exactly as
        // `spawn_anti_entropy_loop` now does: spawn into a JoinSet and drain
        // before the next tick (M-06). Driving the drain pattern directly avoids
        // standing up a PeerNode/registry while exercising the isolation
        // property. If a hung peer blocked a healthy one (the pre-fix serial
        // loop), a single drain would exceed its bound and the client would
        // never converge.
        let run_concurrent_tick = || {
            let addr_source = addr_source.clone();
            let addr_tarpit = addr_tarpit.clone();
            let endpoint_client = endpoint_client.clone();
            let handler_client = handler_client.clone();
            async move {
                let mut set = tokio::task::JoinSet::new();
                for addr in [addr_source, addr_tarpit] {
                    let endpoint = endpoint_client.clone();
                    let handler = handler_client.clone();
                    set.spawn(async move {
                        exchange_with_peer(&endpoint, addr, &handler).await;
                    });
                }
                while set.join_next().await.is_some() {}
            }
        };

        // Converge with the healthy peer despite the tarpit. Every tick is bounded
        // by the tarpit's ~io read timeout (500 ms), so both the per-tick guard
        // and the overall deadline are generous multiples of that (M-06).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let count_client = loop {
            let tick_started = tokio::time::Instant::now();
            let tick_outcome =
                tokio::time::timeout(Duration::from_millis(2_000), run_concurrent_tick()).await;
            assert!(
                tick_outcome.is_ok(),
                "M-06: a concurrent tick exceeded 4x io ({:?}) — the tarpit blocked the drain",
                tick_started.elapsed()
            );

            let count = ledger_client.read().await.directive_count();
            if count == source_count {
                break count;
            }
            if tokio::time::Instant::now() > deadline {
                break count;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        let _ = router_source.shutdown().await;
        let _ = router_tarpit.shutdown().await;

        assert_eq!(
            count_client, source_count,
            "M-06: healthy peer's directives were not pulled despite the tarpit"
        );
    }

    /// M-06 guard: the timeouts must not break a legitimate transfer. Two real
    /// handlers on SHORT timeouts still converge — proving the caps are not so
    /// tight that they trip on a normal exchange.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn happy_path_short_timeouts_converges() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_source = bind_direct_endpoint().await;

        let id_client = endpoint_client.id();
        let id_source = endpoint_source.id();

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_source: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("source.bean"), id_source.to_string())
                .expect("boot source ledger"),
        ));
        let source_count = seed_funding_ledger(&ledger_source).await;

        let allow_source =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist source");
        let allow_client =
            PeerAllowlist::parse(&[id_source.to_string()]).expect("allowlist client");

        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));

        let handler_source =
            make_handler_with_timeouts(ledger_source.clone(), allow_source, short_timeouts());
        let handler_client =
            make_handler_with_timeouts(ledger_client.clone(), allow_client, short_timeouts());

        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_source.clone())
            .spawn();

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_source).await;
        let addr_source = endpoint_source.addr();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            exchange_with_peer(&endpoint_client, addr_source.clone(), &handler_client).await;
            if ledger_client.read().await.directive_count() == source_count {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let _ = router_source.shutdown().await;
                panic!("M-06 happy path: client did not converge under short timeouts");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = router_source.shutdown().await;
    }

    /// L-21: a `Want` listing the same id N times yields exactly ONE `SupplyEntry`.
    #[tokio::test]
    async fn collect_supply_dedups_repeated_ids() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("led.bean"), "author".to_owned())
                .expect("boot ledger"),
        ));
        let id = {
            let mut svc = ledger.write().await;
            svc.open_account(
                "Assets:Cash".to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                vec!["USD".to_owned()],
            )
            .expect("open account")
        };

        let reply = collect_supply(&ledger, &[id.clone(), id.clone(), id.clone()]).await;
        let WireMessage::Supply { entries, .. } = reply else {
            panic!("a Want is answered with a Supply");
        };
        assert_eq!(
            entries.len(),
            1,
            "one directive → one entry, however many copies the Want listed"
        );
        assert_eq!(entries[0].id, id);
    }

    /// M-14: an entry whose id is already in the DAG is skipped BEFORE
    /// `validate_supply_entry`, even when its body would fail validation.
    #[tokio::test]
    async fn apply_supply_entries_skips_present_id_without_validating() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("led.bean"), "author".to_owned())
                .expect("boot ledger"),
        ));
        let present_id = {
            let mut svc = ledger.write().await;
            svc.open_account(
                "Assets:Cash".to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                vec!["USD".to_owned()],
            )
            .expect("open account")
        };
        assert_eq!(ledger.read().await.directive_count(), 1);

        // Same id (D's kind is Open), but a body that WOULD fail
        // `validate_supply_entry`. With the fast path this is never parsed
        // (skipped_present); without it, it reaches validate and is counted
        // rejected instead.
        let entry = p2p::protocol::SupplyEntry {
            id: present_id.clone(),
            kind: p2p::protocol::DirectiveKind::Open,
            economic_bean: "this is not valid beancount".to_owned(),
            envelope: std::collections::BTreeMap::new(),
        };

        let handler = make_handler(
            ledger.clone(),
            PeerAllowlist::parse(&[]).expect("allowlist"),
        );
        let remote = iroh::SecretKey::generate().public();
        let outcome = apply_supply_entries(&handler, vec![entry], remote).await;

        assert_eq!(
            outcome.skipped_present, 1,
            "a present id must take the M-14 fast path"
        );
        assert_eq!(outcome.merged, 0);
        assert_eq!(
            outcome.rejected, 0,
            "the garbage body must never reach validation"
        );

        // Ledger unchanged: still exactly D.
        let svc = ledger.read().await;
        assert_eq!(svc.directive_count(), 1);
        assert!(svc.get_directive(&present_id).is_some());
    }

    /// M-14 does not over-skip: a genuinely new, valid entry still merges.
    #[tokio::test]
    async fn apply_supply_entries_merges_genuinely_new_entry() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        // A source ledger authored by `author`: its `open` is stamped with
        // `openledger-author` = an allowlisted id, so the served entry passes
        // `verify_author_allowlisted`.
        let mut source = LedgerService::boot(temp_dir.path().join("src.bean"), author.to_string())
            .expect("boot source");
        let open_id = source
            .open_account(
                "Assets:Cash".to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                vec!["USD".to_owned()],
            )
            .expect("open account");
        let entry = make_supply_entry(source.get_directive(&open_id).expect("directive present"));

        // A sink ledger that has never seen this id.
        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), "sink".to_owned())
                .expect("boot sink"),
        ));
        let handler = make_handler(sink.clone(), allow);
        let remote = iroh::SecretKey::generate().public();

        let outcome = apply_supply_entries(&handler, vec![entry], remote).await;
        assert_eq!(
            outcome.skipped_present, 0,
            "a genuinely new id must NOT be skipped by the fast path"
        );
        assert_eq!(outcome.merged, 1, "a new valid entry must merge");
        assert_eq!(outcome.rejected, 0);
        assert_eq!(sink.read().await.directive_count(), 1);
    }

    // ─── M-39 (T69): the near-cap Supply path ──────────────────────────────

    /// `count` opens authored by `author`, served as Supply entries.
    fn remote_open_entries(
        dir: &std::path::Path,
        author: &str,
        count: usize,
    ) -> Vec<p2p::protocol::SupplyEntry> {
        let mut source =
            LedgerService::boot(dir.join("m39-source.bean"), author.to_owned()).expect("boot");
        let day = NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date");
        let ids: Vec<String> = (0..count)
            .map(|index| {
                source
                    .open_account_staged(
                        format!("Assets:Remote{index:04}"),
                        day,
                        vec!["USD".to_owned()],
                        |_, _, _| None,
                    )
                    .expect("stage open")
            })
            .collect();
        source.compact().expect("source commit");
        ids.iter().map(|id| entry_for(&source, id)).collect()
    }

    /// M-39 KEY TEST: near the size cap, one 256-entry Supply batch never
    /// holds the ledger `RwLock` for more than 100 ms (a concurrent timed
    /// `read()` probe runs across it), is deferred without being staged, arms
    /// the serving peer's transient backoff, and a second batch from that
    /// peer inside the backoff is not even validated. Reads and a compaction
    /// still work afterwards.
    ///
    /// Bug-catch 1: drop the headroom check in `stage_and_commit_batch` and
    /// the batch is staged, fails its prepare and is reloaded — `deferred` is
    /// 0 and `merged` is 256. Bug-catch 2: drop the backoff gate at the top of
    /// `apply_supply_entries_from` and the second call re-validates: the
    /// planted invalid entry is `rejected` again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn m39_a_batch_that_cannot_fit_is_deferred_without_staging_or_a_reload() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut entries = remote_open_entries(temp_dir.path(), &author.to_string(), 256);
        // One entry that fails intake, so a re-validation is observable.
        let mut invalid = entries[0].clone();
        invalid.economic_bean = "2024-01-01 open\n".to_owned();
        invalid.id = format!("{:064x}", 0xbad);
        entries.push(invalid);

        let ledger = crate::ledger_commit::near_cap::near_cap_ledger(
            &temp_dir.path().join("m39.bean"),
            16 * 1024,
        );
        let handler = make_handler(Arc::clone(&ledger), allow);
        let remote = iroh::SecretKey::generate().public();
        let bystander = iroh::SecretKey::generate().public();

        let (stop, probe) = crate::ledger_commit::near_cap::spawn_read_latency_probe(&ledger);
        let started = std::time::Instant::now();
        let first = apply_supply_entries(&handler, entries.clone(), remote).await;
        let first_took = started.elapsed();
        stop.send(()).unwrap();
        let (worst_read_wait, samples) = probe.await.unwrap();
        eprintln!(
            "m39 supply: 256-entry batch deferred in {first_took:?}; worst read wait \
             {worst_read_wait:?} over {samples} samples; outcome {first:?}"
        );

        assert_eq!(
            first.deferred, 256,
            "the whole valid batch is deferred: {first:?}"
        );
        assert_eq!((first.merged, first.buffered, first.duplicate), (0, 0, 0));
        assert_eq!(first.rejected, 1, "intake still ran on the first batch");
        assert!(
            worst_read_wait < Duration::from_millis(100),
            "M-39: a reader waited {worst_read_wait:?} while a near-cap batch was applied"
        );
        {
            let service = ledger.read().await;
            assert_eq!(service.directive_count(), 0, "nothing was staged");
            assert_eq!(service.uncommitted_count(), 0);
            assert_eq!(service.append_headroom(), 16 * 1024, "nothing was written");
        }
        let now = std::time::Instant::now();
        assert!(
            handler.supply_backoff.is_active(remote, now),
            "the peer is backed off"
        );
        assert!(
            !handler.supply_backoff.is_active(bystander, now),
            "the backoff is per peer"
        );

        // Inside the backoff: not validated, not staged, not reloaded.
        let second = apply_supply_entries(&handler, entries, remote).await;
        assert_eq!(
            second,
            SupplyOutcome {
                deferred: 257,
                ..SupplyOutcome::default()
            },
            "a backed-off peer's batch is not re-validated or re-staged"
        );
        assert_eq!(ledger.read().await.directive_count(), 0);

        // Near the cap the node still serves reads and still compacts.
        crate::ledger_commit::compact(&ledger)
            .await
            .expect("near the cap the node still accepts a compaction");
        assert_eq!(ledger.read().await.append_headroom(), 16 * 1024);
    }

    /// A batch that fits under the headroom is applied as before — the check
    /// defers only what is known to fail.
    #[tokio::test]
    async fn m39_a_batch_that_fits_is_applied_and_arms_no_backoff() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let entries = remote_open_entries(temp_dir.path(), &author.to_string(), 8);
        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), "sink".to_owned())
                .expect("boot sink"),
        ));
        let handler = make_handler(sink.clone(), allow);
        let remote = iroh::SecretKey::generate().public();
        let outcome = apply_supply_entries(&handler, entries, remote).await;
        assert_eq!((outcome.merged, outcome.deferred), (8, 0));
        assert!(!handler
            .supply_backoff
            .is_active(remote, std::time::Instant::now()));
        assert_eq!(sink.read().await.directive_count(), 8);
    }

    /// T71: the deferral lasts `timeouts.supply_backoff` — what
    /// `p2p.antiEntropySupplyBackoffSeconds` sets — not the built-in 60 s.
    ///
    /// Bug-catch: arm with `SUPPLY_HEADROOM_BACKOFF` instead of the handler's
    /// value and the peer is still backed off 6 s in, past its configured 5 s.
    #[tokio::test]
    async fn t71_a_deferred_batch_backs_off_for_the_configured_duration() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let entries = remote_open_entries(temp_dir.path(), &author.to_string(), 8);
        let ledger =
            crate::ledger_commit::near_cap::near_cap_ledger(&temp_dir.path().join("t71.bean"), 64);
        let configured = Duration::from_secs(5);
        let handler = make_handler_with_timeouts(
            Arc::clone(&ledger),
            allow,
            AntiEntropyTimeouts {
                supply_backoff: configured,
                ..AntiEntropyTimeouts::default()
            },
        );
        let remote = iroh::SecretKey::generate().public();
        let armed_before = std::time::Instant::now();
        let outcome = apply_supply_entries(&handler, entries, remote).await;
        let armed_after = std::time::Instant::now();
        assert_eq!(outcome.deferred, 8, "the batch cannot fit: {outcome:?}");
        assert!(
            handler
                .supply_backoff
                .is_active(remote, armed_after + configured - Duration::from_secs(1)),
            "still deferred just inside the configured backoff"
        );
        assert!(
            !handler
                .supply_backoff
                .is_active(remote, armed_before + configured + Duration::from_secs(1)),
            "the configured backoff, not the 60 s default, decides when it lifts"
        );
        assert_eq!(
            AntiEntropyTimeouts::default().supply_backoff,
            SUPPLY_HEADROOM_BACKOFF,
            "an absent key keeps today's 60 s"
        );
    }

    // ─── M-16 / T24 connection + request limits (network) ───────────────────

    /// Dial the anti-entropy ALPN with a generous per-attempt timeout (matching
    /// the default connect timeout the convergence tests rely on), retrying a
    /// few times. Panics if no dial succeeds. A short per-attempt timeout is
    /// wrong here: cancelling a dial that merely needs a little longer and
    /// retrying never lets one complete.
    async fn connect_retry(endpoint: &Endpoint, addr: iroh::EndpointAddr) -> Connection {
        let mut last_error = String::new();
        for _ in 0..3 {
            match tokio::time::timeout(
                Duration::from_secs(10),
                endpoint.connect(addr.clone(), p2p::protocol::ANTI_ENTROPY_ALPN),
            )
            .await
            {
                Ok(Ok(conn)) => return conn,
                Ok(Err(error)) => last_error = error.to_string(),
                Err(_elapsed) => last_error = "connect timed out".to_owned(),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("connect_retry: no dial succeeded ({last_error})");
    }

    /// Open a connection and put the server into its read loop (holding its
    /// `ConnectionGuard`), returning the live handles so the caller keeps it
    /// open. A non-final `HaveHeads` page draws no reply but keeps the server
    /// looping on the next read.
    async fn open_and_hold(
        endpoint: &Endpoint,
        addr: iroh::EndpointAddr,
    ) -> (Connection, SendStream, RecvStream) {
        let conn = connect_retry(endpoint, addr).await;
        let (mut send, recv) = conn.open_bi().await.expect("open_bi");
        write_message(
            &mut send,
            &WireMessage::have_heads_page(vec!["tx".to_owned()], vec![], true),
            Duration::from_secs(5),
        )
        .await
        .expect("write have_heads page");
        (conn, send, recv)
    }

    /// One refusal probe against `addr`. Returns `Some(true)` when the peer is
    /// refused (the handler closed it or the exchange never completes),
    /// `Some(false)` when it is admitted (a `HaveHeads` reply comes back), and
    /// `None` when the dial timed out transiently (inconclusive — retry).
    async fn probe_refused(endpoint: &Endpoint, addr: iroh::EndpointAddr) -> Option<bool> {
        let conn = match tokio::time::timeout(
            Duration::from_secs(10),
            endpoint.connect(addr, p2p::protocol::ANTI_ENTROPY_ALPN),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            // A dial that errors (closed/reset) is a refusal; one that times out
            // is a transient stall we cannot conclude from.
            Ok(Err(_)) => return Some(true),
            Err(_) => return None,
        };
        // Admitted sessions answer a final `HaveHeads` with the server's advert;
        // a refused connection is closed, so open_bi / write / read fails.
        let exchanged = async {
            let (mut send, mut recv) = conn.open_bi().await.ok()?;
            write_message(
                &mut send,
                &WireMessage::have_heads(vec!["tx".to_owned()], vec![]),
                Duration::from_secs(2),
            )
            .await
            .ok()?;
            read_message(
                &mut recv,
                Duration::from_secs(2),
                &mut FrameReservation::unmetered(),
            )
            .await
            .ok()
        }
        .await;
        Some(exchanged.is_none())
    }

    // ─── T70 / M-40: server session deadline and accept rate (network) ─────

    /// One allowlisting server under `timeouts`/`limits` and a client endpoint
    /// that can dial it. The `TempDir` holds the server's ledger alive.
    struct ServePair {
        router: Router,
        client: Endpoint,
        addr: iroh::EndpointAddr,
        handler: AntiEntropyHandler,
        _dir: tempfile::TempDir,
    }

    async fn serve_pair(timeouts: AntiEntropyTimeouts, limits: AntiEntropyLimits) -> ServePair {
        let endpoint_server = bind_direct_endpoint().await;
        let client = bind_direct_endpoint().await;
        let allow_server =
            PeerAllowlist::parse(&[client.id().to_string()]).expect("allowlist server");
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_server: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(
                dir.path().join("server.bean"),
                endpoint_server.id().to_string(),
            )
            .expect("boot server ledger"),
        ));
        let handler = make_handler_full(ledger_server, allow_server, timeouts, limits);
        let router = Router::builder(endpoint_server.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler.clone())
            .spawn();
        wait_until_dialable(&endpoint_server).await;
        wait_until_dialable(&client).await;
        ServePair {
            router,
            client,
            addr: endpoint_server.addr(),
            handler,
            _dir: dir,
        }
    }

    /// A short session over a short `io`, so the M-40 tests finish in seconds.
    fn short_session() -> AntiEntropyTimeouts {
        AntiEntropyTimeouts {
            connect: Duration::from_secs(5),
            io: Duration::from_millis(600),
            session: Duration::from_secs(2),
            ..AntiEntropyTimeouts::default()
        }
    }

    /// M-40: a peer that is never silent — one tiny `Announce` every `io / 2`,
    /// each refreshing the per-frame timeout — is closed by the server's
    /// session deadline, with the session's own close code, and the slot it
    /// held is released. Before T70 nothing but the 100,000-frame budget ended
    /// this session: with the default `io` that is ~34 days.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn announce_every_half_io_is_closed_at_the_session_deadline() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let timeouts = short_session();
        let limits = AntiEntropyLimits {
            max_connections_per_peer: 1,
            ..AntiEntropyLimits::default()
        };
        let pair = serve_pair(timeouts, limits).await;

        let conn = connect_retry(&pair.client, pair.addr.clone()).await;
        let started = tokio::time::Instant::now();
        let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
        let announce = WireMessage::announce("a".repeat(64), p2p::protocol::DirectiveKind::Open);
        let writer = async {
            // Up to 6 s of announces — three times the session — then stop;
            // the assertion below is on the close, not on this loop.
            let give_up = started + Duration::from_secs(6);
            while tokio::time::Instant::now() < give_up {
                if write_message(&mut send, &announce, Duration::from_secs(2))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(timeouts.io / 2).await;
            }
        };
        let ((), reason) = tokio::join!(writer, async {
            tokio::time::timeout(Duration::from_secs(20), conn.closed()).await
        });
        let elapsed = started.elapsed();
        let reason = reason.expect("the server must end a never-silent session");
        assert!(
            format!("{reason}").contains("session-deadline"),
            "the close must carry the session code, got: {reason}"
        );
        assert!(
            elapsed >= timeouts.session - Duration::from_millis(200),
            "closed before the session ran out ({elapsed:?})"
        );
        assert!(
            elapsed < timeouts.session + CLOSE_DRAIN + Duration::from_secs(4),
            "the close must come at session + CLOSE_DRAIN, not later ({elapsed:?})"
        );
        drop(conn);

        // The slot is back: with a per-peer cap of 1, a fresh session from the
        // same peer completes an advert exchange.
        let mut admitted = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while tokio::time::Instant::now() < deadline {
            if let Some(refused) = probe_refused(&pair.client, pair.addr.clone()).await {
                admitted = !refused;
                if admitted {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let _ = pair.router.shutdown().await;
        assert!(
            admitted,
            "the expired session's connection slot was never released"
        );
    }

    /// M-40: the deadline is hard for a frame as a whole, not only between
    /// frames. A 1,000,000-byte frame (under the non-`Supply` cap, so it is
    /// read in full) trickled one 64 KiB chunk every `io / 2` refreshes every
    /// sub-read's timeout and would take 16 × 300 ms ≈ 4.8 s — more than twice
    /// the 2 s session. It must be cut at the deadline with the session code,
    /// not read to the end and then failed as an undecodable frame.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_frame_trickled_past_the_deadline_is_cut_at_the_deadline() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let timeouts = short_session();
        let pair = serve_pair(timeouts, AntiEntropyLimits::default()).await;

        let conn = connect_retry(&pair.client, pair.addr.clone()).await;
        let started = tokio::time::Instant::now();
        let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
        let frame_len: u32 = 1_000_000;
        let writer = async {
            if send.write_all(&frame_len.to_be_bytes()).await.is_err() {
                return;
            }
            let chunk = vec![0u8; READ_CHUNK];
            let mut sent = 0usize;
            while sent < frame_len as usize {
                let take = (frame_len as usize - sent).min(chunk.len());
                if send.write_all(&chunk[..take]).await.is_err() {
                    return;
                }
                sent += take;
                tokio::time::sleep(timeouts.io / 2).await;
            }
        };
        let ((), reason) = tokio::join!(writer, async {
            tokio::time::timeout(Duration::from_secs(20), conn.closed()).await
        });
        let elapsed = started.elapsed();
        let _ = pair.router.shutdown().await;
        let reason = reason.expect("the server must close the connection");
        assert!(
            format!("{reason}").contains("session-deadline"),
            "a frame straddling the deadline must end the session with its code, got: {reason}"
        );
        assert!(
            elapsed < timeouts.session + CLOSE_DRAIN + Duration::from_secs(4),
            "cut at the deadline, not after the whole frame ({elapsed:?})"
        );
    }

    /// M-40: a peer reconnecting in a tight loop is admitted at the accept
    /// bucket's rate and no faster, every refused connection is closed with
    /// the rate code, and a refused connection never reaches the serve loop —
    /// the limiter's admission count is exactly the client's admitted count,
    /// so no guard, no serve future and no stream was spent on the rest. The
    /// bucket then refills and the same peer is admitted again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_tight_reconnect_loop_is_admitted_only_at_the_bucket_rate() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let burst = 3u32;
        let refill = Duration::from_secs(3);
        let limits = AntiEntropyLimits {
            accept_burst: burst,
            accept_refill_interval: refill,
            ..AntiEntropyLimits::default()
        };
        let pair = serve_pair(short_timeouts(), limits).await;

        // Ask for a verdict on one fresh connection: `true` when the server
        // refused it for rate. An admitted connection is left open by the
        // server (it waits for a stream), so no close within the window means
        // admitted; the client then closes it itself.
        async fn dial_verdict(pair: &ServePair) -> bool {
            let conn = connect_retry(&pair.client, pair.addr.clone()).await;
            match tokio::time::timeout(Duration::from_millis(400), conn.closed()).await {
                Ok(reason) => {
                    assert!(
                        format!("{reason}").contains("accept-rate-limit"),
                        "the only refusal in play is the rate, got: {reason}"
                    );
                    true
                }
                Err(_still_open) => {
                    conn.close(0u32.into(), b"done");
                    false
                }
            }
        }

        let attempts = 12;
        let started = tokio::time::Instant::now();
        let mut admitted = 0usize;
        let mut refused = 0usize;
        for _ in 0..attempts {
            if dial_verdict(&pair).await {
                refused += 1;
            } else {
                admitted += 1;
            }
        }
        let elapsed = started.elapsed();
        let refills = (elapsed.as_secs_f64() / refill.as_secs_f64()).ceil() as usize;
        assert!(
            admitted >= burst as usize,
            "the burst must be admitted ({admitted} of {attempts})"
        );
        assert!(
            admitted <= burst as usize + refills,
            "admitted {admitted} in {elapsed:?}: more than burst {burst} + {refills} refills"
        );
        assert!(refused > 0, "a tight loop must hit the bucket");
        assert_eq!(
            pair.handler.limiter.accepted_total(),
            admitted,
            "only admitted connections may reach the serve loop"
        );

        tokio::time::sleep(refill).await;
        assert!(
            !dial_verdict(&pair).await,
            "after a refill interval the peer is admitted again"
        );
        let _ = pair.router.shutdown().await;
    }

    // ─── T41: EOF classification is by variant, not by substring ───────────

    /// `serve_anti_entropy` used to decide "clean shutdown" with
    /// `error.contains("early eof") || error.contains("closed")` over a
    /// formatted string. [`classify_read_error`] now decides it from iroh's
    /// error enum, which is what this pins — in particular the two cases the
    /// substring rule got wrong.
    #[test]
    fn read_errors_are_classified_by_variant() {
        // A clean finish between frames is the only EOF.
        assert!(matches!(
            classify_read_error(ReadExactError::FinishedEarly(0)),
            FrameError::Eof
        ));
        assert!(matches!(
            classify_read_error(ReadExactError::ReadError(ReadError::ClosedStream)),
            FrameError::Eof
        ));

        // A PARTIAL frame is a truncation, not a clean break — the old rule saw
        // "stream finished early (7 bytes read)" and, at the length prefix,
        // treated it as EOF because the caller had prefixed "early eof: ".
        assert!(matches!(
            classify_read_error(ReadExactError::FinishedEarly(7)),
            FrameError::Protocol(_)
        ));

        // A reset is a failure. Its text ("stream reset by peer: error 42")
        // never contained the matched substrings either, so the old rule only
        // got this right below the length prefix.
        assert!(matches!(
            classify_read_error(ReadExactError::ReadError(ReadError::Reset(42u32.into()))),
            FrameError::Protocol(_)
        ));

        // And a stall stays a stall: T24 had to pick timeout wording that
        // avoided the matched substrings by hand. Now it is a variant.
        assert!(!matches!(FrameError::Timeout, FrameError::Eof));
    }

    // ─── T41: advert accumulation counts DISTINCT ids ──────────────────────

    /// The cap `read_have_heads_advert` applies is `MAX_ACCUMULATED_HAVE_HEADS`
    /// DISTINCT ids, not a million repeats of one. Pure, no network: the
    /// accumulation step is the whole behaviour under test.
    #[test]
    fn advert_accumulation_counts_distinct_ids_and_keeps_first_occurrence_order() {
        let mut accumulated: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // A peer replaying one page 10,000 times advertises ONE id, not 10,000.
        // T49: and retains bytes only the FIRST time, which is what makes
        // `max_advert_id_bytes` a bound on live memory rather than on traffic.
        let mut retained = 0usize;
        for _ in 0..10_000 {
            retained += absorb_page(
                &mut accumulated,
                &mut seen,
                vec!["aa".to_owned(), "bb".to_owned()],
            );
        }
        assert_eq!(retained, 4, "9,999 replays of the same page retain nothing");
        assert_eq!(
            accumulated,
            vec!["aa".to_owned(), "bb".to_owned()],
            "repeated pages must not inflate the accumulated advert"
        );

        // New ids append after the ones already seen; repeats among them are
        // dropped wherever they appear.
        assert_eq!(
            absorb_page(
                &mut accumulated,
                &mut seen,
                vec!["cc".to_owned(), "aa".to_owned(), "dd".to_owned()],
            ),
            4,
            "only the two NEW ids are charged"
        );
        assert_eq!(
            accumulated,
            vec![
                "aa".to_owned(),
                "bb".to_owned(),
                "cc".to_owned(),
                "dd".to_owned()
            ],
            "first-occurrence order must be preserved"
        );

        // Duplicates within a single page are deduped too.
        assert_eq!(
            absorb_page(
                &mut accumulated,
                &mut seen,
                vec!["ee".to_owned(), "ee".to_owned(), "ee".to_owned()],
            ),
            2,
            "a page that repeats one id is charged for it once"
        );
        assert_eq!(accumulated.len(), 5);
    }

    // ─── T49: session bounds (H-10, M-26, M-27, M-28) ──────────────────────

    /// An ALPN server that answers every session with `HaveHeads { [], [],
    /// more: true }` forever — the ~40-byte frame at the centre of H-10.
    ///
    /// Both list fields are `#[serde(default)]`, so the frame decodes cleanly
    /// while advertising nothing; `absorb_page` dedups it to nothing, so the
    /// distinct-id cap never advances. Pre-T49 this was an infinite loop inside
    /// `read_have_heads_advert` for as long as the peer kept answering.
    ///
    /// Paced at one page per millisecond so a test that (correctly) bounds the
    /// flood by TIME does not have to read millions of frames to get there. The
    /// pacing is generosity toward the attacker's CPU, not a bound: nothing in
    /// the client depends on it.
    #[derive(Debug, Clone)]
    pub(crate) struct EmptyPageFloodHandler;

    impl ProtocolHandler for EmptyPageFloodHandler {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let Ok((mut send, _recv)) = connection.accept_bi().await else {
                return Ok(());
            };
            let page = WireMessage::have_heads_page(Vec::new(), Vec::new(), true);
            loop {
                if write_message(&mut send, &page, Duration::from_secs(5))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    /// An ALPN server whose advert carries ids that are not content ids (M-26),
    /// counting the `Want`s the client sends afterwards.
    ///
    /// 2,048 ids of 255 bytes: ~528 KiB, comfortably inside
    /// `NON_SUPPLY_FRAME_CAP`, so the M-16 frame gate passes it and the form
    /// rule is the only thing that can refuse it. A client that ACCEPTS the
    /// advert immediately asks for all 2,048 — which is the observable
    /// difference the assertion reads.
    #[derive(Debug, Clone)]
    struct BloatedAdvertHandler {
        wants_seen: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ProtocolHandler for BloatedAdvertHandler {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                return Ok(());
            };
            let ids: Vec<String> = (0..2_048).map(|index| format!("{index:0255x}")).collect();
            let page = WireMessage::have_heads_page(ids, Vec::new(), false);
            if write_message(&mut send, &page, Duration::from_secs(5))
                .await
                .is_err()
            {
                return Ok(());
            }
            // The client's own advert arrives first; anything AFTER it that is a
            // `Want` means the client acted on the 255-byte ids.
            while let Ok(message) = read_message(
                &mut recv,
                Duration::from_secs(2),
                &mut FrameReservation::unmetered(),
            )
            .await
            {
                if matches!(message, WireMessage::Want { .. }) {
                    self.wants_seen
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            Ok(())
        }
    }

    /// The advert form rule is the parents rule (L-29), applied to adverts.
    ///
    /// Pure; the shapes are the ones M-26 and L-53 name.
    #[test]
    fn advert_ids_must_be_content_ids() {
        // `check_advert_ids` only needs an id to name in the message; no
        // endpoint is bound, so this stays a pure test.
        let remote = iroh::SecretKey::generate().public();

        let good: Vec<String> = (0..4).map(|index| format!("{index:064x}")).collect();
        assert!(check_advert_ids(remote, &good).is_ok());
        assert!(check_advert_ids(remote, &[]).is_ok());

        // The M-26 shapes: 255-byte ids, and a ~1 MiB single "id".
        for bad in [
            "0".repeat(255),
            "a".repeat(1024 * 1024),
            String::new(),
            "0".repeat(63),
            "0".repeat(65),
            // Uppercase resolves to nothing and must be refused, for L-29's reason.
            format!("{:063x}A", 0),
            // Non-hex, and a multi-byte character that would make a `chars()`
            // length test and a `len()` byte test disagree.
            format!("{:063x}z", 0),
            format!("{:062x}é", 0),
        ] {
            let error = check_advert_ids(remote, std::slice::from_ref(&bad))
                .expect_err("a non-content-id must be refused");
            assert!(
                error.contains(&bad.len().to_string()),
                "the refusal must name the id's LENGTH: {error}"
            );
            assert!(
                !error.contains(&bad) || bad.is_empty(),
                "the refusal must not echo the attacker's id back into a log"
            );
        }

        // One bad id anywhere poisons the page — it is not filtered out.
        let mut mixed = good.clone();
        mixed.push("0".repeat(255));
        assert!(check_advert_ids(remote, &mixed).is_err());
    }

    /// H-10 / M-26: an empty-page flood must abort the exchange rather than
    /// loop, and it must do so on TIME even with every count bound disabled.
    ///
    /// `max_advert_pages` and `max_session_frames` are set to `usize::MAX` on
    /// purpose: this test is about the session DEADLINE, which is the bound that
    /// holds no matter what shape a peer's frames take. The page cap gets its
    /// own test below.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn empty_page_flood_is_ended_by_the_session_deadline() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_flood = bind_direct_endpoint().await;
        let id_client = endpoint_client.id();
        let id_flood = endpoint_flood.id();

        let router_flood = Router::builder(endpoint_flood.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, EmptyPageFloodHandler)
            .spawn();

        let allow_client = PeerAllowlist::parse(&[id_flood.to_string()]).expect("allowlist client");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));
        let handler_client = make_handler_with_timeouts(
            ledger_client,
            allow_client,
            AntiEntropyTimeouts {
                connect: Duration::from_secs(5),
                io: Duration::from_secs(5),
                session: Duration::from_secs(2),
                // Every COUNT bound off, so only the clock can end this.
                max_advert_pages: usize::MAX,
                max_session_frames: usize::MAX,
                ..AntiEntropyTimeouts::default()
            },
        );

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_flood).await;
        let addr_flood = endpoint_flood.addr();

        let started = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            exchange_with_peer(&endpoint_client, addr_flood, &handler_client),
        )
        .await;
        let elapsed = started.elapsed();

        let _ = router_flood.shutdown().await;

        assert!(
            outcome.is_ok(),
            "H-10: exchange_with_peer never returned against a peer replying \
             `more: true` with empty pages"
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "H-10: the exchange should end at its ~2s session deadline, took {elapsed:?}"
        );
    }

    /// M-26: the page counter ends the same flood long before the deadline.
    ///
    /// The deadline is set to a minute here, so a return in seconds can only
    /// come from `max_advert_pages`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn empty_page_flood_is_ended_by_the_page_cap() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_flood = bind_direct_endpoint().await;
        let id_client = endpoint_client.id();
        let id_flood = endpoint_flood.id();

        let router_flood = Router::builder(endpoint_flood.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, EmptyPageFloodHandler)
            .spawn();

        let allow_client = PeerAllowlist::parse(&[id_flood.to_string()]).expect("allowlist client");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));
        let handler_client = make_handler_with_timeouts(
            ledger_client,
            allow_client,
            AntiEntropyTimeouts {
                connect: Duration::from_secs(5),
                io: Duration::from_secs(5),
                session: Duration::from_secs(60),
                max_advert_pages: 8,
                ..AntiEntropyTimeouts::default()
            },
        );

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_flood).await;
        let addr_flood = endpoint_flood.addr();

        let started = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            exchange_with_peer(&endpoint_client, addr_flood, &handler_client),
        )
        .await;
        let elapsed = started.elapsed();

        let _ = router_flood.shutdown().await;

        assert!(outcome.is_ok(), "M-26: the page cap never fired");
        assert!(
            elapsed < Duration::from_secs(20),
            "M-26: eight pages must end the advert well inside the 60s session \
             deadline, took {elapsed:?}"
        );
    }

    /// M-26: an advert of 255-byte ids is refused, and — the consequence that
    /// matters — the client never acts on those ids.
    ///
    /// Rejection rather than resident bytes, because rejection is the stronger
    /// statement: nothing is retained *and* nothing is requested. A client that
    /// accepted the advert would immediately `Want` all 2,048 of them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn oversized_advert_ids_are_refused_and_never_wanted() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_liar = bind_direct_endpoint().await;
        let id_client = endpoint_client.id();
        let id_liar = endpoint_liar.id();

        let wants_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let router_liar = Router::builder(endpoint_liar.clone())
            .accept(
                p2p::protocol::ANTI_ENTROPY_ALPN,
                BloatedAdvertHandler {
                    wants_seen: wants_seen.clone(),
                },
            )
            .spawn();

        let allow_client = PeerAllowlist::parse(&[id_liar.to_string()]).expect("allowlist client");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));
        let handler_client =
            make_handler_with_timeouts(ledger_client.clone(), allow_client, short_timeouts());

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_liar).await;
        let addr_liar = endpoint_liar.addr();

        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            exchange_with_peer(&endpoint_client, addr_liar, &handler_client),
        )
        .await;

        // Give the liar's read loop a moment to observe anything the client
        // sent before its stream was torn down.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let wants = wants_seen.load(std::sync::atomic::Ordering::SeqCst);
        let _ = router_liar.shutdown().await;

        assert!(outcome.is_ok(), "the exchange must return, not hang");
        assert_eq!(
            wants, 0,
            "M-26: the client acted on an advert of 255-byte ids ({wants} Wants)"
        );
        assert_eq!(
            ledger_client.read().await.directive_count(),
            0,
            "nothing may be merged from a refused advert"
        );
    }

    /// M-26: the BYTE budget is a live bound, not a restatement of the form rule.
    ///
    /// A/B against the same source: a client whose id-byte budget is four ids
    /// wide refuses a twenty-directive advert and pulls nothing; the same sink,
    /// with the default budget, converges. Without the A half, a byte budget
    /// sized off `CONTENT_ID_LEN` would be untestable and could silently become
    /// unreachable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn advert_byte_budget_refuses_before_the_count_cap_would() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_sink = bind_direct_endpoint().await;
        let id_source = endpoint_source.id();
        let id_sink = endpoint_sink.id();

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let source_path = temp_dir.path().join("source.bean");
        write_open_directive_ledger(&source_path, 20, &id_source.to_string());
        let ledger_source: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(source_path, id_source.to_string()).expect("boot source ledger"),
        ));
        let source_count = ledger_source.read().await.directive_count();
        assert_eq!(source_count, 20);

        let allow_source = PeerAllowlist::parse(&[id_sink.to_string()]).expect("allowlist source");
        let router_source = Router::builder(endpoint_source.clone())
            .accept(
                p2p::protocol::ANTI_ENTROPY_ALPN,
                make_handler(ledger_source, allow_source),
            )
            .spawn();

        let allow_sink = PeerAllowlist::parse(&[id_source.to_string()]).expect("allowlist sink");
        let ledger_sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), id_sink.to_string())
                .expect("boot sink ledger"),
        ));

        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_sink).await;
        let addr_source = endpoint_source.addr();

        // A: four ids' worth of budget against a twenty-id advert.
        let starved = make_handler_with_timeouts(
            ledger_sink.clone(),
            allow_sink.clone(),
            AntiEntropyTimeouts {
                max_advert_id_bytes: 4 * CONTENT_ID_LEN,
                ..short_timeouts()
            },
        );
        exchange_with_peer(&endpoint_sink, addr_source.clone(), &starved).await;
        assert_eq!(
            ledger_sink.read().await.directive_count(),
            0,
            "M-26: the advert exceeded the id-byte budget and must have been refused"
        );

        // B: the same sink, the same source, the default budget — it converges,
        // so A's zero is the budget's doing and not a broken fixture.
        let healthy = make_handler_with_timeouts(ledger_sink.clone(), allow_sink, short_timeouts());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            exchange_with_peer(&endpoint_sink, addr_source.clone(), &healthy).await;
            if ledger_sink.read().await.directive_count() == source_count {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "control arm never converged: the fixture, not the budget, is broken"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = router_source.shutdown().await;
    }

    /// M-27: a peer that grants NO bidirectional-stream credit must not park the
    /// caller in `open_bi`.
    ///
    /// The server's transport config sets `max_concurrent_bidi_streams` to 0
    /// (the default is 100) while iroh's own keep-alive holds the connection
    /// open, so the client's `open_bi` pends on `stream_budget_available[Bi]`
    /// with nothing else in flight: no dial for `connect` to bound, no frame for
    /// `io` to bound. The assertion is simply that the call RETURNS.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn peer_granting_no_stream_credit_does_not_hang_the_caller() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_stingy = iroh::Endpoint::builder(presets::Minimal)
            .alpns(vec![p2p::protocol::ANTI_ENTROPY_ALPN.to_vec()])
            .transport_config(
                iroh::endpoint::QuicTransportConfig::builder()
                    .max_concurrent_bidi_streams(0u32.into())
                    .build(),
            )
            .bind()
            .await
            .expect("bind a peer that grants no bidi stream credit");

        let id_client = endpoint_client.id();
        let id_stingy = endpoint_stingy.id();

        // A handler is still registered so the ALPN is accepted and the
        // connection is established — the refusal is purely stream credit.
        let router_stingy = Router::builder(endpoint_stingy.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, TarpitHandler)
            .spawn();

        let allow_client =
            PeerAllowlist::parse(&[id_stingy.to_string()]).expect("allowlist client");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));
        let handler_client = make_handler_with_timeouts(
            ledger_client,
            allow_client,
            AntiEntropyTimeouts {
                connect: Duration::from_secs(5),
                io: Duration::from_secs(5),
                open_stream: Duration::from_millis(500),
                ..AntiEntropyTimeouts::default()
            },
        );

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_stingy).await;
        let addr_stingy = endpoint_stingy.addr();

        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            exchange_with_peer(&endpoint_client, addr_stingy, &handler_client),
        )
        .await;

        let _ = router_stingy.shutdown().await;

        assert!(
            outcome.is_ok(),
            "M-27: open_bi parked forever against a peer advertising \
             initial_max_streams_bidi = 0"
        );
    }

    // ─── T41: `accept_bi` timeout + tidy close ─────────────────────────────

    /// A peer that completes the QUIC handshake and then opens NO stream must be
    /// timed out, told why, and — the point of the fix — must give its
    /// `ConnectionLimiter` slot back.
    ///
    /// Asserted two ways, because the slot is the consequence that matters and
    /// the close code is the direct evidence: the client sees an
    /// application close carrying `accept-bi-timeout`, and with the per-peer cap
    /// set to 1 a second connection from the same peer is admitted afterwards —
    /// which it could never be while the parked serve task held the only slot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn silent_peer_is_timed_out_and_releases_its_connection_slot() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_server = bind_direct_endpoint().await;
        let endpoint_client = bind_direct_endpoint().await;

        let id_server = endpoint_server.id();
        let id_client = endpoint_client.id();
        let allow_server =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist server");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_server: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("server.bean"), id_server.to_string())
                .expect("boot server ledger"),
        ));

        // One slot per peer, so the parked session is provably the thing
        // occupying it; a short I/O timeout so the test does not wait 30s.
        let limits = AntiEntropyLimits {
            max_total_connections: 256,
            max_connections_per_peer: 1,
            max_requests_per_connection: 100_000,
            ..AntiEntropyLimits::default()
        };
        let timeouts = AntiEntropyTimeouts {
            connect: Duration::from_secs(5),
            io: Duration::from_millis(600),
            ..AntiEntropyTimeouts::default()
        };
        let handler_server = make_handler_full(ledger_server, allow_server, timeouts, limits);
        let router_server = Router::builder(endpoint_server.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_server.clone())
            .spawn();

        wait_until_dialable(&endpoint_server).await;
        wait_until_dialable(&endpoint_client).await;
        let addr_server = endpoint_server.addr();

        // Connect and open nothing at all.
        let silent = connect_retry(&endpoint_client, addr_server.clone()).await;
        let reason = tokio::time::timeout(Duration::from_secs(15), silent.closed())
            .await
            .expect("the server must close a silent connection, not park on it forever");
        assert!(
            format!("{reason}").contains("accept-bi-timeout"),
            "the close must say why it happened, got: {reason}"
        );
        drop(silent);

        // The slot the parked session held is back: a fresh session from the
        // same peer completes a full advert exchange.
        let mut admitted = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while tokio::time::Instant::now() < deadline {
            if let Some(refused) = probe_refused(&endpoint_client, addr_server.clone()).await {
                admitted = !refused;
                if admitted {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = router_server.shutdown().await;
        assert!(
            admitted,
            "the silent peer's ConnectionLimiter slot was never released"
        );
    }

    /// T41: a budget cut-off closes the connection with an explicit code and
    /// reason instead of dropping it, so the peer can tell a cut-off from an
    /// ordinary end of session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn request_budget_close_names_its_reason() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_server = bind_direct_endpoint().await;
        let endpoint_client = bind_direct_endpoint().await;

        let id_server = endpoint_server.id();
        let id_client = endpoint_client.id();
        let allow_server =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist server");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_server: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("server.bean"), id_server.to_string())
                .expect("boot server ledger"),
        ));

        // A budget of two: one Want in, one Supply out, then the next loop turn
        // trips the cut-off.
        let limits = AntiEntropyLimits {
            max_total_connections: 256,
            max_connections_per_peer: 32,
            max_requests_per_connection: 2,
            ..AntiEntropyLimits::default()
        };
        let handler_server = make_handler_with_limits(ledger_server, allow_server, limits);
        let router_server = Router::builder(endpoint_server.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_server.clone())
            .spawn();

        wait_until_dialable(&endpoint_server).await;
        wait_until_dialable(&endpoint_client).await;
        let addr_server = endpoint_server.addr();

        let conn = connect_retry(&endpoint_client, addr_server.clone()).await;
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        write_message(
            &mut send,
            &WireMessage::want(vec!["nope".to_owned()]),
            Duration::from_secs(5),
        )
        .await
        .expect("write want");
        // The one reply the budget allows arrives intact — this is the drain
        // the tidy close exists to protect.
        assert!(
            matches!(
                read_message(
                    &mut recv,
                    Duration::from_secs(5),
                    &mut FrameReservation::unmetered()
                )
                .await,
                Ok(WireMessage::Supply { .. })
            ),
            "the budgeted reply must arrive before the connection closes"
        );

        let reason = tokio::time::timeout(Duration::from_secs(15), conn.closed())
            .await
            .expect("the server must close once its budget is spent");
        assert!(
            format!("{reason}").contains("request-budget-exhausted"),
            "a budget cut-off must name itself, got: {reason}"
        );

        let _ = router_server.shutdown().await;
    }

    /// A (integration smoke test): a server capped at 2 connections per peer
    /// refuses a 3rd concurrent connection from the same client. The
    /// deterministic coverage is in `connection_limiter`'s unit tests; this
    /// proves the cap is wired into `ProtocolHandler::accept`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn per_peer_connection_cap_refuses_third_connection() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_server = bind_direct_endpoint().await;
        let endpoint_client = bind_direct_endpoint().await;

        let id_server = endpoint_server.id();
        let id_client = endpoint_client.id();

        let allow_server =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist server");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_server: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("server.bean"), id_server.to_string())
                .expect("boot server ledger"),
        ));

        // Per-peer cap of 2; default (generous) I/O timeouts so the first two
        // guards stay held (the server's read blocks well past this test) while
        // we probe the third slot.
        let limits = AntiEntropyLimits {
            max_total_connections: 256,
            max_connections_per_peer: 2,
            max_requests_per_connection: 100_000,
            ..AntiEntropyLimits::default()
        };
        let handler_server = make_handler_with_limits(ledger_server, allow_server, limits);
        let router_server = Router::builder(endpoint_server.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_server.clone())
            .spawn();

        wait_until_dialable(&endpoint_server).await;
        wait_until_dialable(&endpoint_client).await;
        let addr_server = endpoint_server.addr();

        // Establish and hold two connections; connectivity is proven here (these
        // panic if the path never comes up), so a later refusal is the cap, not
        // a dead network.
        let held_one = open_and_hold(&endpoint_client, addr_server.clone()).await;
        let held_two = open_and_hold(&endpoint_client, addr_server.clone()).await;

        // Let the server accept both and enter their read loops (guards held).
        tokio::time::sleep(Duration::from_millis(500)).await;

        // The 3rd slot must be refused. Retry only transient dial stalls
        // (`None`); a conclusive admit (`Some(false)`) means the cap is broken.
        let mut refused = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while tokio::time::Instant::now() < deadline {
            match probe_refused(&endpoint_client, addr_server.clone()).await {
                Some(result) => {
                    refused = result;
                    break;
                }
                None => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }

        // Hold the first two open through the probe so their guards were live the
        // whole time.
        drop(held_one);
        drop(held_two);
        let _ = router_server.shutdown().await;

        assert!(
            refused,
            "M-16: the per-peer cap did not refuse the 3rd concurrent connection"
        );
    }

    /// C (integration): a connection budgeted for three Want/Supply *round
    /// trips* answers exactly three and then closes, even though the client
    /// sends five. The 4th read on the client side then fails (the server
    /// finished its send side).
    ///
    /// The budget is six, not three, because L-01 made it charge for frames
    /// written as well as frames read — a Want/Supply exchange is two frames.
    /// The T24 property under test is unchanged: the ceiling is hard.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn request_budget_closes_connection_after_limit() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_server = bind_direct_endpoint().await;
        let endpoint_client = bind_direct_endpoint().await;

        let id_server = endpoint_server.id();
        let id_client = endpoint_client.id();

        let allow_server =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist server");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_server: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("server.bean"), id_server.to_string())
                .expect("boot server ledger"),
        ));

        let limits = AntiEntropyLimits {
            max_total_connections: 256,
            max_connections_per_peer: 32,
            max_requests_per_connection: 6,
            ..AntiEntropyLimits::default()
        };
        let handler_server = make_handler_with_limits(ledger_server, allow_server, limits);
        let router_server = Router::builder(endpoint_server.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_server.clone())
            .spawn();

        wait_until_dialable(&endpoint_server).await;
        wait_until_dialable(&endpoint_client).await;
        let addr_server = endpoint_server.addr();

        let conn = connect_retry(&endpoint_client, addr_server.clone()).await;
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");

        // Send 5 Wants for an unknown id, interleaving each with its reply (the
        // protocol's own request/response cadence). Each Want draws exactly one
        // (empty) Supply reply while the budget lasts; once the server has spent
        // its six frames it closes, and the next read fails.
        let mut replies = 0;
        for _ in 0..5 {
            if write_message(
                &mut send,
                &WireMessage::want(vec!["nope".to_owned()]),
                Duration::from_secs(5),
            )
            .await
            .is_err()
            {
                break;
            }
            match read_message(
                &mut recv,
                Duration::from_secs(5),
                &mut FrameReservation::unmetered(),
            )
            .await
            {
                Ok(WireMessage::Supply { .. }) => replies += 1,
                Ok(_) => {}
                Err(_) => break,
            }
        }

        let _ = router_server.shutdown().await;

        // The budget is a hard ceiling: the server breaks at the 4th message, so
        // the client can NEVER see more than 3 replies (without the budget it
        // would see all 5). The 3rd reply races the server's post-budget
        // connection close and may be truncated, so 2 or 3 both prove the cap —
        // the point is it stopped well short of 5.
        assert!(
            (2..=3).contains(&replies),
            "T24: server must answer at most the 3 round trips its budget allows then close, got {replies}"
        );
    }

    /// T42 review: a flood of EMPTY bi-streams must not hold a connection —
    /// and its M-16 limiter slot — outside the request budget.
    ///
    /// A zero-byte finished stream reaches `accept_bi`, reads as a clean EOF
    /// (`FinishedEarly(0)`), and carries no frame — so before the per-stream
    /// budget charge it advanced `requests_handled` by nothing at all, and a
    /// peer could loop it forever. With the charge, each accepted stream costs
    /// one unit and the budget closes the connection on schedule.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn empty_streams_cannot_hold_a_connection_outside_the_budget() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_server = bind_direct_endpoint().await;
        let endpoint_client = bind_direct_endpoint().await;

        let id_server = endpoint_server.id();
        let id_client = endpoint_client.id();

        let allow_server =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist server");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_server: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("server.bean"), id_server.to_string())
                .expect("boot server ledger"),
        ));

        let limits = AntiEntropyLimits {
            max_total_connections: 256,
            max_connections_per_peer: 32,
            max_requests_per_connection: 6,
            ..AntiEntropyLimits::default()
        };
        let handler_server = make_handler_with_limits(ledger_server, allow_server, limits);
        let router_server = Router::builder(endpoint_server.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_server.clone())
            .spawn();

        wait_until_dialable(&endpoint_server).await;
        wait_until_dialable(&endpoint_client).await;
        let addr_server = endpoint_server.addr();

        let conn = connect_retry(&endpoint_client, addr_server.clone()).await;

        // Open zero-byte streams until the server's budget closes the
        // connection. Each stream is finished immediately so it reaches the
        // server as a clean EOF with no frame ever sent.
        let mut opened = 0usize;
        let mut refused = false;
        for _ in 0..50 {
            let Ok((mut send, _recv)) =
                tokio::time::timeout(Duration::from_secs(5), conn.open_bi())
                    .await
                    .map_err(|_| ())
                    .and_then(|r| r.map_err(|_| ()))
            else {
                refused = true;
                break;
            };
            if send.finish().is_err() {
                refused = true;
                break;
            }
            opened += 1;
            // Yield so the server can drain the stream and advance its budget;
            // without this the client can race dozens of opens ahead of the
            // server ever seeing one.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let _ = router_server.shutdown().await;

        assert!(
            refused,
            "T42: the server must close a connection fed only empty streams; \
             all 50 were accepted — the budget never advanced"
        );
        assert!(
            opened <= 20,
            "T42: with a budget of 6, the empty-stream flood must be cut off \
             promptly, got {opened} accepted streams"
        );
    }

    /// L-01: a client looping over one connection cannot extract bytes out of
    /// proportion to what it sends.
    ///
    /// The Want arm was already bounded three ways — `MAX_WANT_IDS` (1,024) caps
    /// the ids one request may name, `truncate_supply` caps the reply at
    /// `MAX_SUPPLY_ENTRIES` / `SUPPLY_FRAME_BUDGET_BYTES`, and T26's budget caps
    /// requests per connection. The **advert** arm was not: a thirty-byte
    /// `HaveHeads` drew back the whole id list, however many pages that took,
    /// for one unit of budget. This drives both arms in a tight loop and asserts
    /// the connection dies at the budget with the bytes it yielded bounded by
    /// it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tight_loop_over_one_connection_is_bounded_by_the_request_budget() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_server = bind_direct_endpoint().await;
        let endpoint_client = bind_direct_endpoint().await;
        let id_server = endpoint_server.id();
        let id_client = endpoint_client.id();
        let allow_server =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist server");

        // A ledger with enough directives that one advert needs several pages —
        // which is exactly the shape the old accounting charged one unit for.
        const PAGES_PER_ADVERT: usize = 3;
        let directives = p2p::protocol::MAX_HAVE_HEADS * (PAGES_PER_ADVERT - 1) + 1;
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let bean_path = temp_dir.path().join("server.bean");
        // Written as a file and booted, not built through `open_account`: each
        // append re-serializes and fsyncs the whole ledger (T44), so 4,097 of
        // them would make the fixture quadratic on its own.
        let mut content = String::new();
        for index in 0..directives {
            content.push_str(&format!("2024-01-01 open Assets:A{index}\n"));
        }
        std::fs::write(&bean_path, &content).expect("write fixture ledger");
        let service =
            LedgerService::boot(&bean_path, id_server.to_string()).expect("boot server ledger");
        assert_eq!(service.directive_count(), directives);
        let advert_pages = p2p::anti_entropy::paginate_have_heads(
            &service.head_txids(),
            &service.all_directive_ids(),
        )
        .len();
        assert!(
            advert_pages >= 2,
            "the fixture must need more than one advert page, got {advert_pages}"
        );
        let ledger_server: SharedLedger = Arc::new(RwLock::new(service));

        // Budget deliberately smaller than the number of frames the client will
        // try to draw out.
        const BUDGET: usize = 12;
        let limits = AntiEntropyLimits {
            max_total_connections: 256,
            max_connections_per_peer: 32,
            max_requests_per_connection: BUDGET,
            ..AntiEntropyLimits::default()
        };
        let handler_server = make_handler_with_limits(ledger_server, allow_server, limits);
        let router_server = Router::builder(endpoint_server.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_server.clone())
            .spawn();

        wait_until_dialable(&endpoint_server).await;
        wait_until_dialable(&endpoint_client).await;
        let addr_server = endpoint_server.addr();

        let conn = connect_retry(&endpoint_client, addr_server.clone()).await;
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");

        // 40 bare adverts — each one used to cost the server a full multi-page
        // id dump and the client thirty bytes.
        let mut frames_received = 0usize;
        let mut adverts_sent = 0usize;
        for _ in 0..40 {
            let advert = WireMessage::HaveHeads {
                v: 1,
                head_txids: Vec::new(),
                directive_ids: Vec::new(),
                more: false,
            };
            if write_message(&mut send, &advert, Duration::from_secs(5))
                .await
                .is_err()
            {
                break;
            }
            adverts_sent += 1;
            let mut drained = 0;
            loop {
                match read_message(
                    &mut recv,
                    Duration::from_secs(2),
                    &mut FrameReservation::unmetered(),
                )
                .await
                {
                    Ok(WireMessage::HaveHeads { more, .. }) => {
                        frames_received += 1;
                        drained += 1;
                        if !more {
                            break;
                        }
                    }
                    Ok(_) => break,
                    Err(_) => break,
                }
            }
            if drained == 0 {
                break; // server closed — budget spent
            }
        }

        let _ = router_server.shutdown().await;

        // Each advert costs 1 (read) + `advert_pages` (written). The server can
        // therefore serve at most `BUDGET / (1 + advert_pages)` of them before
        // it closes, whatever the client asks for.
        let max_adverts = BUDGET / (1 + advert_pages);
        assert!(
            frames_received <= BUDGET,
            "the connection yielded {frames_received} frames against a {BUDGET}-frame budget"
        );
        assert!(
            frames_received <= max_adverts * advert_pages,
            "L-01: {adverts_sent} adverts drew {frames_received} frames; the budget allows at \
             most {max_adverts} adverts ({advert_pages} pages each)"
        );
        assert!(
            adverts_sent < 40,
            "the server must have closed the connection before the client ran out of adverts"
        );
    }

    /// Guard: small connection limits must not break a legitimate exchange. Two
    /// real handlers on tight caps (per-peer 4, total 8) still converge — the
    /// caps bound runaways, not honest traffic. Uses default (generous) timeouts
    /// like `three_node_alpn_convergence`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn happy_path_small_limits_converges() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_source = bind_direct_endpoint().await;

        let id_client = endpoint_client.id();
        let id_source = endpoint_source.id();

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_source: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("source.bean"), id_source.to_string())
                .expect("boot source ledger"),
        ));
        let source_count = seed_funding_ledger(&ledger_source).await;

        let allow_source =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist source");
        let allow_client =
            PeerAllowlist::parse(&[id_source.to_string()]).expect("allowlist client");

        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));

        // Tight connection caps, generous request budget (a catch-up needs many
        // messages on one stream but only a handful of concurrent connections).
        let limits = AntiEntropyLimits {
            max_total_connections: 8,
            max_connections_per_peer: 4,
            max_requests_per_connection: 100_000,
            ..AntiEntropyLimits::default()
        };
        let handler_source = make_handler_with_limits(ledger_source.clone(), allow_source, limits);
        let handler_client = make_handler_with_limits(ledger_client.clone(), allow_client, limits);

        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_source.clone())
            .spawn();

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_source).await;
        let addr_source = endpoint_source.addr();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            exchange_with_peer(&endpoint_client, addr_source.clone(), &handler_client).await;
            if ledger_client.read().await.directive_count() == source_count {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let _ = router_source.shutdown().await;
                panic!("small limits broke a legitimate exchange: client did not converge");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = router_source.shutdown().await;
    }

    // ─── T42: per-peer connection reuse (network) ─────────────────────────

    /// A mutually-allowlisted client/server pair, the server already serving a
    /// seeded ledger over the anti-entropy ALPN.
    ///
    /// The T42 tests all need the same three things: a client that dials
    /// through the cache, a server whose `ConnectionLimiter` counts what it
    /// ADMITTED (the observable that separates "reused one connection" from
    /// "dialled again"), and a ledger difference so an operation's success is
    /// visible in the data rather than only in the absence of a log line.
    struct ReusePair {
        endpoint_client: Endpoint,
        handler_client: AntiEntropyHandler,
        handler_server: AntiEntropyHandler,
        router_server: Router,
        addr_server: iroh::EndpointAddr,
        server_id: EndpointId,
        ledger_server: SharedLedger,
        ledger_client: SharedLedger,
        _temp_dir: tempfile::TempDir,
    }

    impl ReusePair {
        /// Connections the server has admitted since it started. One per dial —
        /// the number T42 is supposed to stop growing with the operation count.
        fn accepted(&self) -> usize {
            self.handler_server.limiter.accepted_total()
        }

        /// Wait until the server has admitted at least `at_least` connections.
        ///
        /// `accept` runs on the SERVER's task, so a dial returning on the
        /// client side does not yet mean the limiter has counted it. A baseline
        /// taken before that lands is off by one, and the assertion that
        /// follows it reads as a reuse failure when nothing failed.
        async fn wait_for_accepted(&self, at_least: usize) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while self.accepted() < at_least {
                assert!(
                    tokio::time::Instant::now() <= deadline,
                    "T42 fixture: the server never admitted {at_least} connection(s), saw {}",
                    self.accepted()
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        async fn client_count(&self) -> usize {
            self.ledger_client.read().await.directive_count()
        }

        async fn server_count(&self) -> usize {
            self.ledger_server.read().await.directive_count()
        }

        /// Append one directive to the server so a LATER operation has
        /// something to carry, and return its id.
        async fn append_to_server(&self, account: &str) -> String {
            self.ledger_server
                .write()
                .await
                .open_account(
                    account.to_owned(),
                    NaiveDate::from_ymd_opt(2024, 2, 1).expect("valid date"),
                    vec!["USD".to_owned()],
                )
                .expect("open an account on the server")
        }

        async fn exchange(&self) {
            exchange_with_peer(
                &self.endpoint_client,
                self.addr_server.clone(),
                &self.handler_client,
            )
            .await;
        }

        async fn fetch(&self, ids: Vec<String>) {
            fetch_want(
                &self.endpoint_client,
                self.addr_server.clone(),
                ids,
                &self.handler_client,
            )
            .await;
        }

        /// Run exchanges until the client has caught up, so the reuse
        /// assertions that follow start from a settled, connected state.
        ///
        /// A cold path can need more than one dial on a loaded machine (every
        /// other network test here loops or retries for the same reason), so
        /// the reuse tests assert a DELTA from after this point rather than
        /// pinning the very first dial — a distinction that costs nothing,
        /// since reverting the cache makes the delta grow with every operation.
        async fn converge(&self) {
            let target = self.server_count().await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                self.exchange().await;
                if self.client_count().await == target {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() <= deadline,
                    "T42 fixture: the client never caught up with the server"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        async fn shutdown(self) {
            let _ = self.router_server.shutdown().await;
        }
    }

    /// Stand up a [`ReusePair`] whose server holds `directives` independent
    /// `open`s (no parent chain, so one exchange transfers the lot).
    async fn reuse_pair(directives: usize, server_io: Duration) -> ReusePair {
        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_server = bind_direct_endpoint().await;

        let client_id = endpoint_client.id();
        let server_id = endpoint_server.id();

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let server_path = temp_dir.path().join("server.bean");
        write_open_directive_ledger(&server_path, directives, &server_id.to_string());

        let ledger_server: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(server_path, server_id.to_string()).expect("boot server ledger"),
        ));
        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), client_id.to_string())
                .expect("boot client ledger"),
        ));

        let allow_server =
            PeerAllowlist::parse(&[client_id.to_string()]).expect("server allowlist");
        let allow_client =
            PeerAllowlist::parse(&[server_id.to_string()]).expect("client allowlist");

        let handler_server = make_handler_with_timeouts(
            ledger_server.clone(),
            allow_server,
            AntiEntropyTimeouts {
                io: server_io,
                ..AntiEntropyTimeouts::default()
            },
        );
        let handler_client = make_handler(ledger_client.clone(), allow_client);

        let router_server = Router::builder(endpoint_server.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_server.clone())
            .spawn();

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_server).await;
        let addr_server = endpoint_server.addr();

        ReusePair {
            endpoint_client,
            handler_client,
            handler_server,
            router_server,
            addr_server,
            server_id,
            ledger_server,
            ledger_client,
            _temp_dir: temp_dir,
        }
    }

    /// T42 (reuse): successive operations against one peer — exchange, exchange
    /// AND a fetch — run over a single accepted server connection.
    ///
    /// Before the cache each of them dialled, so the server's admitted count
    /// climbed by one per operation; now it does not move at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sequential_operations_reuse_one_pooled_connection() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let pair = reuse_pair(4, Duration::from_secs(30)).await;

        pair.converge().await;
        let settled = pair.accepted();
        assert!(
            settled >= 1,
            "the server must have admitted the connection the client caught up over"
        );

        // Two more exchanges: both must ride the pooled connection.
        pair.exchange().await;
        pair.exchange().await;
        assert_eq!(
            pair.accepted(),
            settled,
            "T42: two further exchanges must reuse the pooled connection, not dial"
        );

        // And a FETCH — the other call site — shares the same pooled connection
        // as the exchanges, which is the point of keying the cache by peer
        // rather than giving each call site its own.
        let new_id = pair.append_to_server("Assets:Fetched").await;
        pair.fetch(vec![new_id.clone()]).await;
        assert_eq!(
            pair.accepted(),
            settled,
            "T42: a fetch must reuse the connection the exchanges pooled"
        );
        assert!(
            pair.ledger_client
                .read()
                .await
                .get_directive(&new_id)
                .is_some(),
            "the fetch had to actually transfer the directive over that connection"
        );

        pair.shutdown().await;
    }

    /// T42 (transparent re-dial): a pooled connection that has died is replaced
    /// without the caller seeing anything.
    ///
    /// The connection is closed outright — the same state the client finds when
    /// the server's idle timeout has closed it — and the next operation must
    /// still do its work, over a NEW connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_dead_pooled_connection_is_redialed_transparently() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let pair = reuse_pair(4, Duration::from_secs(30)).await;

        pair.converge().await;
        let settled = pair.accepted();

        let pooled = pair
            .handler_client
            .connections
            .pooled(pair.server_id)
            .await
            .expect("T42: a successful exchange must leave a connection pooled");
        pooled.close(9u32.into(), b"test-killed-the-pooled-connection");
        assert!(
            pooled.close_reason().is_some(),
            "the fixture must really have killed the pooled connection"
        );

        // Something new to carry, so "the operation succeeded" is a fact about
        // the ledger and not just the absence of an error.
        let after_death = pair.append_to_server("Assets:AfterDeath").await;
        pair.exchange().await;

        assert!(
            pair.ledger_client
                .read()
                .await
                .get_directive(&after_death)
                .is_some(),
            "T42: the operation after a dead pooled connection must still succeed"
        );
        assert_eq!(
            pair.accepted(),
            settled + 1,
            "T42: exactly one re-dial — no more, and not zero"
        );

        pair.shutdown().await;
    }

    /// T42 (dial dedup): a fetch and an exchange started CONCURRENTLY against a
    /// peer with nothing pooled share one dial.
    ///
    /// The path is warmed with a throwaway probe connection first (so a cold
    /// dial cannot flake the count) but the CACHE is left cold, which is what
    /// makes this a test of the per-peer slot: without it both operations dial
    /// and the server admits two.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_fetch_and_exchange_share_one_dial() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let pair = reuse_pair(4, Duration::from_secs(30)).await;

        // Warm the path only — this connection never enters the cache.
        let probe = connect_retry(&pair.endpoint_client, pair.addr_server.clone()).await;
        drop(probe);
        pair.wait_for_accepted(1).await;
        let warmed = pair.accepted();

        let target = pair.server_count().await;
        let ids: Vec<String> = pair
            .ledger_server
            .read()
            .await
            .all_directive_ids()
            .into_iter()
            .collect();

        // Both call sites at once, from a cold cache.
        tokio::join!(pair.fetch(ids), pair.exchange());

        assert_eq!(
            pair.accepted(),
            warmed + 1,
            "T42: concurrent operations to one peer must share a single dial"
        );
        assert_eq!(
            pair.client_count().await,
            target,
            "both concurrent operations must complete — no corrupted shared state"
        );

        pair.shutdown().await;
    }

    /// T42 (stale after idle): the server closes a pooled connection that has
    /// been idle past its `accept_bi` bound, and the client treats it as dead
    /// and re-dials rather than failing.
    ///
    /// This is the honest limit of the optimization, pinned as a test: reuse
    /// wins WITHIN a burst, and the server's idle close — which nothing here
    /// touches — ends the burst.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_pooled_connection_idle_past_the_server_bound_is_redialed() {
        let _serialized = NET_TEST_LOCK.lock().await;
        // A server whose I/O timeout — and so whose wait for the next stream —
        // is short, so its idle close lands inside the test rather than in 30s.
        let pair = reuse_pair(4, Duration::from_millis(400)).await;

        pair.converge().await;
        let settled = pair.accepted();

        let pooled = pair
            .handler_client
            .connections
            .pooled(pair.server_id)
            .await
            .expect("T42: a successful exchange must leave a connection pooled");

        // Wait for the SERVER's own idle close rather than sleeping past a
        // guess at it: this is the interplay the module docs describe.
        let reason = tokio::time::timeout(Duration::from_secs(10), pooled.closed())
            .await
            .expect("the server must close a pooled connection left idle past its bound");
        assert!(
            format!("{reason}").contains("accept-bi-timeout"),
            "the idle close must still name itself, got: {reason}"
        );

        let after_idle = pair.append_to_server("Assets:AfterIdle").await;
        pair.exchange().await;

        assert!(
            pair.ledger_client
                .read()
                .await
                .get_directive(&after_idle)
                .is_some(),
            "T42: the exchange after the server's idle close must still succeed"
        );
        assert_eq!(
            pair.accepted(),
            settled + 1,
            "T42: the client must re-dial exactly once after the idle close"
        );

        pair.shutdown().await;
    }

    // ─── T27: batched apply_supply_entries (M-15) ────────────────────────

    /// Content ids of a `.bean`-authored source ledger's directives, plus the
    /// live source, so a test can turn any of them into a `SupplyEntry`.
    struct SeededSource {
        source: LedgerService,
        open_cash: String,
        open_equity: String,
        open_food: String,
        txn1: String,
        txn2: String,
    }

    /// Seed a source ledger authored by `author` with 3 opens and 2 balanced
    /// transactions; `txn2` references `txn1` as its DAG parent.
    fn seed_mixed_source(dir: &std::path::Path, author: &str) -> SeededSource {
        let mut source =
            LedgerService::boot(dir.join("source.bean"), author.to_owned()).expect("boot source");
        let day = NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date");
        let open_cash = source
            .open_account("Assets:Cash".to_owned(), day, vec!["USD".to_owned()])
            .expect("open cash");
        let open_equity = source
            .open_account("Equity:Opening".to_owned(), day, Vec::new())
            .expect("open equity");
        let open_food = source
            .open_account("Expenses:Food".to_owned(), day, vec!["USD".to_owned()])
            .expect("open food");
        let txn1 = source
            .append_transaction(balanced_funding_input())
            .expect("append txn1")
            .txid;
        let txn2 = source
            .append_transaction(TransactionInput {
                date: NaiveDate::from_ymd_opt(2024, 1, 20).expect("valid date"),
                flag: Flag::Complete,
                payee: Some("Cafe".to_owned()),
                narration: Some("Lunch".to_owned()),
                tags: Vec::new(),
                links: Vec::new(),
                postings: vec![
                    PostingInput {
                        account: "Expenses:Food".to_owned(),
                        amount: Some(Amount {
                            number: dec!(25),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                    },
                    PostingInput {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-25),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                    },
                ],
            })
            .expect("append txn2")
            .txid;
        SeededSource {
            source,
            open_cash,
            open_equity,
            open_food,
            txn1,
            txn2,
        }
    }

    fn entry_for(source: &LedgerService, id: &str) -> p2p::protocol::SupplyEntry {
        make_supply_entry(source.get_directive(id).expect("directive present"))
    }

    /// T27 KEY TEST — determinism/equivalence. Applying the same set of
    /// directives via the BATCHED `apply_supply_entries` path and via the
    /// per-entry `insert_remote_directive` path must yield BYTE-IDENTICAL
    /// `.bean` files and the same directive-id set. This proves batching the
    /// persist (M-15) changed nothing observable: `full_file_serialize` sorts
    /// and serializes each directive independently, so the on-disk snapshot is
    /// the same however many persists produced it.
    #[tokio::test]
    async fn batch_path_is_byte_identical_to_per_entry_path() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let seeded = seed_mixed_source(temp_dir.path(), &author.to_string());

        // A realistic mix: opens shuffled among themselves (independent), with
        // both transactions after their parents (so the per-entry path, which
        // has no orphan buffer, can also insert every one).
        let ordered_ids = [
            &seeded.open_food,
            &seeded.open_cash,
            &seeded.open_equity,
            &seeded.txn1,
            &seeded.txn2,
        ];
        let entries: Vec<p2p::protocol::SupplyEntry> = ordered_ids
            .iter()
            .map(|id| entry_for(&seeded.source, id))
            .collect();

        // ── Batch path: one Supply, one persist. ──
        let batch_path = temp_dir.path().join("batch.bean");
        let batch_ledger: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(batch_path.clone(), "sink".to_owned()).expect("boot batch"),
        ));
        let batch_handler = make_handler(batch_ledger.clone(), allow.clone());
        let remote = iroh::SecretKey::generate().public();
        let outcome = apply_supply_entries(&batch_handler, entries.clone(), remote).await;
        assert_eq!(outcome.merged, 5, "all five directives merge in one batch");
        assert_eq!(
            outcome.buffered, 0,
            "no orphan buffering: parents precede children"
        );
        assert_eq!(outcome.duplicate, 0);
        assert_eq!(outcome.rejected, 0);

        // ── Per-entry path: insert_remote_directive one at a time (persist each). ──
        let per_entry_path = temp_dir.path().join("per_entry.bean");
        let per_entry_ledger: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(per_entry_path.clone(), "sink".to_owned()).expect("boot per-entry"),
        ));
        {
            let mut svc = per_entry_ledger.write().await;
            for entry in &entries {
                let directive = validate_supply_entry(entry).expect("valid entry");
                svc.insert_remote_directive(directive).expect("insert");
            }
        }

        let batch_bytes = std::fs::read(&batch_path).expect("read batch file");
        let per_entry_bytes = std::fs::read(&per_entry_path).expect("read per-entry file");
        assert_eq!(
            batch_bytes, per_entry_bytes,
            "batched and per-entry .bean files must be byte-identical"
        );

        let batch_ids = batch_ledger.read().await.all_directive_ids();
        let per_entry_ids = per_entry_ledger.read().await.all_directive_ids();
        assert_eq!(
            batch_ids, per_entry_ids,
            "batched and per-entry directive-id sets must match"
        );
        assert_eq!(batch_ids.len(), 5);
    }

    /// T27: intra-batch dependency — an open followed by a transaction on that
    /// account, both in one batch, both merge (the open staged earlier is
    /// visible to the transaction's validation).
    #[tokio::test]
    async fn batch_open_then_txn_on_that_account_both_merge() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let seeded = seed_mixed_source(temp_dir.path(), &author.to_string());
        // opens + txn1 (genesis), all in one batch, opens before the txn.
        let entries = vec![
            entry_for(&seeded.source, &seeded.open_cash),
            entry_for(&seeded.source, &seeded.open_equity),
            entry_for(&seeded.source, &seeded.txn1),
        ];

        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), "sink".to_owned())
                .expect("boot sink"),
        ));
        let handler = make_handler(sink.clone(), allow);
        let remote = iroh::SecretKey::generate().public();

        let outcome = apply_supply_entries(&handler, entries, remote).await;
        assert_eq!(
            outcome.merged, 3,
            "open + open + txn all merge in one batch"
        );
        assert_eq!(outcome.buffered, 0);
        assert_eq!(outcome.rejected, 0);
        assert_eq!(sink.read().await.directive_count(), 3);
        assert!(sink.read().await.get_directive(&seeded.txn1).is_some());
    }

    /// T27: a transaction whose DAG parent appears LATER in the same batch is
    /// orphan-buffered when first seen, then resolved by the single post-batch
    /// drain — so the final state still contains it.
    #[tokio::test]
    async fn batch_child_before_parent_resolves_via_drain() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let seeded = seed_mixed_source(temp_dir.path(), &author.to_string());
        // txn2 (child of txn1) arrives BEFORE txn1 in the batch.
        let entries = vec![
            entry_for(&seeded.source, &seeded.open_cash),
            entry_for(&seeded.source, &seeded.open_equity),
            entry_for(&seeded.source, &seeded.open_food),
            entry_for(&seeded.source, &seeded.txn2),
            entry_for(&seeded.source, &seeded.txn1),
        ];

        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), "sink".to_owned())
                .expect("boot sink"),
        ));
        let handler = make_handler(sink.clone(), allow);
        let remote = iroh::SecretKey::generate().public();

        let outcome = apply_supply_entries(&handler, entries, remote).await;
        // txn2 is buffered on first sight; the 3 opens + txn1 merge directly.
        assert_eq!(outcome.merged, 4, "3 opens + txn1 merge directly");
        assert_eq!(
            outcome.buffered, 1,
            "txn2 is buffered until its parent arrives"
        );
        assert_eq!(outcome.rejected, 0);

        // The post-batch drain resolved txn2, so the final state has all five.
        let svc = sink.read().await;
        assert_eq!(
            svc.directive_count(),
            5,
            "the drain resolved the buffered child; final state has all five"
        );
        assert!(
            svc.get_directive(&seeded.txn2).is_some(),
            "the once-buffered child is present after the drain"
        );
    }

    /// L-35 / R-19 (T69): after every insert path — boot, a local write, a
    /// remote batch, an orphan drain, a hand-edit reconcile and an L-13
    /// reload — the advert the node sends is identical, page for page and
    /// byte for byte, to the old `paginate_have_heads(head_txids(),
    /// all_directive_ids())`, and the Want it computes against a peer's
    /// advert is the old Want minus the ids it already holds (the T59 fix;
    /// identical wherever the old rule was right).
    ///
    /// Bug-catch: key the sorted snapshot on anything that does not change
    /// on one of these paths and the advert goes stale — the page comparison
    /// fails at that step.
    #[tokio::test]
    async fn l35_advert_and_want_match_the_cloned_set_versions_after_every_insert_path() {
        async fn check(ledger: &SharedLedger, source: &LedgerService, step: &str) {
            let new_pages: Vec<WireMessage> = local_have_heads_pages(ledger).await.collect();
            let svc = ledger.read().await;
            let old_pages =
                p2p::anti_entropy::paginate_have_heads(&svc.head_txids(), &svc.all_directive_ids());
            assert_eq!(new_pages, old_pages, "advert after {step}");
            for (new_page, old_page) in new_pages.iter().zip(&old_pages) {
                assert_eq!(
                    new_page.to_wire().unwrap(),
                    old_page.to_wire().unwrap(),
                    "{step}"
                );
            }

            let mut remote_heads: Vec<String> = source.head_txids().into_iter().collect();
            remote_heads.sort();
            let remote_ids: Vec<String> = source.sorted_directive_ids().to_vec();
            let old = p2p::anti_entropy::compute_want(
                &svc.head_txids(),
                &svc.all_directive_ids(),
                &remote_heads,
                &remote_ids,
            );
            let new = p2p::anti_entropy::compute_want_by_membership(
                |id| svc.contains_directive(id),
                &remote_heads,
                &remote_ids,
            );
            let old_minus_held: Vec<String> = old
                .into_iter()
                .filter(|id| !svc.contains_directive(id))
                .collect();
            assert_eq!(new, old_minus_held, "want after {step}");
        }

        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let seeded = seed_mixed_source(temp_dir.path(), &author.to_string());
        let sink_path = temp_dir.path().join("sink.bean");
        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(&sink_path, "sink".to_owned()).expect("boot sink"),
        ));
        check(&sink, &seeded.source, "boot").await;

        sink.write()
            .await
            .open_account(
                "Assets:Local".to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                Vec::new(),
            )
            .expect("local open");
        check(&sink, &seeded.source, "a local write").await;

        // A remote batch whose child arrives before its parent: staged, then
        // drained.
        let handler = make_handler(sink.clone(), allow);
        let entries = vec![
            entry_for(&seeded.source, &seeded.open_cash),
            entry_for(&seeded.source, &seeded.open_equity),
            entry_for(&seeded.source, &seeded.txn2),
            entry_for(&seeded.source, &seeded.open_food),
            entry_for(&seeded.source, &seeded.txn1),
        ];
        let outcome =
            apply_supply_entries(&handler, entries, iroh::SecretKey::generate().public()).await;
        assert_eq!(
            (outcome.merged, outcome.buffered),
            (4, 1),
            "premise: one drain"
        );
        assert_eq!(sink.read().await.directive_count(), 6);
        check(&sink, &seeded.source, "a remote batch and its orphan drain").await;

        let mut content = std::fs::read_to_string(&sink_path).unwrap();
        content.push_str("\n2024-02-01 open Assets:Typed USD\n");
        std::fs::write(&sink_path, content).unwrap();
        let reconciled = sink.write().await.reconcile_file().expect("reconcile");
        assert_eq!(
            reconciled.new_directives, 1,
            "premise: the hand edit adopted"
        );
        check(&sink, &seeded.source, "a reconcile").await;

        sink.write().await.recover_failed_commit();
        assert_eq!(sink.read().await.directive_count(), 7);
        check(&sink, &seeded.source, "an L-13 reload").await;
    }

    /// T27: a duplicate entry within one batch is tallied `duplicate`, not
    /// `merged`, and lands only once.
    #[tokio::test]
    async fn batch_duplicate_entry_tallies_duplicate() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let seeded = seed_mixed_source(temp_dir.path(), &author.to_string());
        // The same open twice in one batch.
        let entries = vec![
            entry_for(&seeded.source, &seeded.open_cash),
            entry_for(&seeded.source, &seeded.open_cash),
        ];

        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), "sink".to_owned())
                .expect("boot sink"),
        ));
        let handler = make_handler(sink.clone(), allow);
        let remote = iroh::SecretKey::generate().public();

        let outcome = apply_supply_entries(&handler, entries, remote).await;
        assert_eq!(outcome.merged, 1, "the first copy merges");
        assert_eq!(
            outcome.duplicate, 1,
            "the second copy is a duplicate, not a merge"
        );
        assert_eq!(outcome.rejected, 0);
        assert_eq!(sink.read().await.directive_count(), 1);
    }

    // ─── T29 / M-09 — deterministic account lifecycle ─────────────────────

    /// A balanced `account`/`Equity:Opening` transaction.
    fn lifecycle_txn(
        account: &str,
        on: NaiveDate,
        amount: rust_decimal::Decimal,
    ) -> TransactionInput {
        TransactionInput {
            date: on,
            flag: Flag::Complete,
            payee: Some("Acme".to_owned()),
            narration: Some(format!("{account} {on}")),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                PostingInput {
                    account: account.to_owned(),
                    amount: Some(Amount {
                        number: amount,
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: -amount,
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        }
    }

    fn day(month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2024, month, day).expect("valid date")
    }

    /// The M-09 permutation fixture, built entirely through the LOCAL write API
    /// so every directive in it is one an honest node would actually produce.
    ///
    /// It covers each shape the finding names:
    /// * `Assets:Cash` — opened, transacted, closed, then re-opened and
    ///   re-closed: TWO conflicting open/close pairs on one account, each with
    ///   its own date and its own Lamport stamp.
    /// * `Assets:Bank` — a second account interleaved with the first, with its
    ///   own transaction between its open and its close.
    /// * `Equity:Opening` — open for the whole window, posted to by both
    ///   transactions.
    /// * The transactions are the ones whose `open` can arrive LATER: an
    ///   `open` is never a DAG head (see `LedgerDag::insert`), so it is never a
    ///   transaction's parent, and the orphan buffer's parent index cannot help
    ///   here. That is precisely the M-09 gap.
    ///
    /// Every `close` is dated at or after every transaction on its account, so
    /// the backdated-close guard can never fire — which keeps this set free of
    /// the documented directive-set residual and lets the test demand an
    /// IDENTICAL accepted set from every order.
    fn seed_lifecycle_source(dir: &std::path::Path, author: &str) -> (LedgerService, Vec<String>) {
        let mut source = LedgerService::boot(dir.join("lifecycle-source.bean"), author.to_owned())
            .expect("boot lifecycle source");
        // Creation order IS the canonical (date, type-priority) order.
        let ids = vec![
            source
                .open_account("Equity:Opening".to_owned(), day(1, 1), Vec::new())
                .expect("open equity"),
            source
                .open_account("Assets:Cash".to_owned(), day(1, 1), vec!["USD".to_owned()])
                .expect("open cash"),
            source
                .open_account("Assets:Bank".to_owned(), day(1, 1), vec!["USD".to_owned()])
                .expect("open bank"),
            source
                .append_transaction(lifecycle_txn("Assets:Cash", day(1, 15), dec!(100)))
                .expect("cash txn")
                .txid,
            source
                .close_account("Assets:Cash".to_owned(), day(2, 1))
                .expect("close cash"),
            source
                .open_account("Assets:Cash".to_owned(), day(3, 1), vec!["USD".to_owned()])
                .expect("re-open cash"),
            source
                .close_account("Assets:Cash".to_owned(), day(4, 1))
                .expect("re-close cash"),
            source
                .append_transaction(lifecycle_txn("Assets:Bank", day(6, 1), dec!(250)))
                .expect("bank txn")
                .txid,
            source
                .close_account("Assets:Bank".to_owned(), day(12, 31))
                .expect("close bank"),
        ];

        (source, ids)
    }

    /// Everything a replica must agree on, whatever order it saw the set in.
    #[derive(Debug, PartialEq, Eq)]
    struct ConvergedState {
        directive_ids: Vec<String>,
        /// `(account, probe date, open?)` over a probe grid, plus the account's
        /// "currently open" verdict at the sentinel date `9999-12-31`.
        lifecycle: Vec<(String, NaiveDate, bool)>,
        balances: Vec<(String, Option<ledger::read_model::AccountBalanceEntry>)>,
        file_bytes: Vec<u8>,
    }

    const PROBE_ACCOUNTS: [&str; 3] = ["Assets:Cash", "Assets:Bank", "Equity:Opening"];

    async fn converged_state(ledger: &SharedLedger, path: &std::path::Path) -> ConvergedState {
        let svc = ledger.read().await;
        let mut directive_ids: Vec<String> = svc.all_directive_ids().into_iter().collect();
        directive_ids.sort();

        let mut lifecycle = Vec::new();
        let mut balances = Vec::new();
        for account in PROBE_ACCOUNTS {
            for month in 1..=12u32 {
                let probe = day(month, 10);
                lifecycle.push((
                    account.to_owned(),
                    probe,
                    svc.accounts().is_open_at(account, probe),
                ));
            }
            // The date-free "currently open" verdict the local guards ask for.
            lifecycle.push((
                account.to_owned(),
                NaiveDate::from_ymd_opt(9999, 12, 31).expect("sentinel"),
                svc.accounts().is_open(account),
            ));
            balances.push((
                account.to_owned(),
                svc.read_model().account_balance(account, None),
            ));
        }

        ConvergedState {
            directive_ids,
            lifecycle,
            balances,
            file_bytes: std::fs::read(path).expect("read sink file"),
        }
    }

    /// Apply one arrival order through the real remote path and snapshot it.
    async fn apply_order(
        dir: &std::path::Path,
        label: &str,
        allow: &PeerAllowlist,
        entries: Vec<p2p::protocol::SupplyEntry>,
    ) -> ConvergedState {
        let path = dir.join(format!("sink-{label}.bean"));
        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(path.clone(), "sink".to_owned()).expect("boot sink"),
        ));
        let handler = make_handler(sink.clone(), allow.clone());
        let remote = iroh::SecretKey::generate().public();
        apply_supply_entries(&handler, entries, remote).await;
        converged_state(&sink, &path).await
    }

    /// Deterministic xorshift64* — a seeded shuffle with no extra dependency,
    /// so a failing permutation is reproducible from the seed alone.
    struct Xorshift(u64);

    impl Xorshift {
        fn next_below(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % bound as u64) as usize
        }

        fn shuffle<T>(&mut self, items: &mut [T]) {
            for index in (1..items.len()).rev() {
                let other = self.next_below(index + 1);
                items.swap(index, other);
            }
        }
    }

    /// T29 MONEY TEST (M-09) — permutation convergence.
    ///
    /// The same directive set, delivered through the real remote path
    /// (`apply_supply_entries`: validate → stage → buffer → drain → one
    /// persist) in many different arrival orders, must leave every replica with
    /// the same accepted directive set, the same account lifecycle verdicts at
    /// every probe date, the same balances, and a BYTE-IDENTICAL `.bean` file.
    ///
    /// Before T29 this failed: a transaction whose account's `open` had not
    /// arrived yet was rejected outright and never retried (the orphan buffer
    /// only ever waited on parents, and an `open` is never a parent), so the
    /// accepted set depended on arrival order and stayed different forever.
    #[tokio::test]
    async fn lifecycle_converges_under_every_arrival_order() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let (source, ids) = seed_lifecycle_source(temp_dir.path(), &author.to_string());
        let sorted: Vec<p2p::protocol::SupplyEntry> =
            ids.iter().map(|id| entry_for(&source, id)).collect();
        assert_eq!(sorted.len(), 9, "the fixture shape is what the test claims");

        // The canonical (creation) order is the reference every other order
        // must match.
        let reference = apply_order(temp_dir.path(), "sorted", &allow, sorted.clone()).await;
        assert_eq!(
            reference.directive_ids.len(),
            9,
            "the reference order must accept the whole set"
        );

        let mut orders: Vec<(String, Vec<p2p::protocol::SupplyEntry>)> = Vec::new();
        let mut reversed = sorted.clone();
        reversed.reverse();
        orders.push(("reversed".to_owned(), reversed));
        // 64 seeded shuffles: 9! = 362,880 orders is too many to enumerate, and
        // the seeds make any failure reproducible.
        for seed in 1..=64u64 {
            let mut shuffled = sorted.clone();
            Xorshift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1).shuffle(&mut shuffled);
            orders.push((format!("seed-{seed}"), shuffled));
        }

        for (label, entries) in orders {
            let state = apply_order(temp_dir.path(), &label, &allow, entries).await;
            assert_eq!(
                state.directive_ids, reference.directive_ids,
                "order {label}: accepted directive set diverged"
            );
            assert_eq!(
                state.lifecycle, reference.lifecycle,
                "order {label}: account lifecycle state diverged"
            );
            assert_eq!(
                state.balances, reference.balances,
                "order {label}: balances diverged"
            );
            assert_eq!(
                state.file_bytes, reference.file_bytes,
                "order {label}: persisted .bean file is not byte-identical"
            );
        }
    }

    /// T29 (M-09) — a transaction whose account `open` arrives LATER in the
    /// batch is buffered, then drained to ACCEPTANCE by the post-batch drain.
    ///
    /// An `open` is never a DAG head, so it is never a transaction's parent:
    /// before T29 nothing buffered this entry and it was rejected outright.
    #[tokio::test]
    async fn txn_before_its_account_open_is_buffered_then_drained() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let seeded = seed_mixed_source(temp_dir.path(), &author.to_string());
        // The genesis transaction first, its accounts' opens after it.
        let entries = vec![
            entry_for(&seeded.source, &seeded.txn1),
            entry_for(&seeded.source, &seeded.open_cash),
            entry_for(&seeded.source, &seeded.open_equity),
        ];

        let sink_path = temp_dir.path().join("sink.bean");
        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(sink_path, "sink".to_owned()).expect("boot sink"),
        ));
        let handler = make_handler(sink.clone(), allow);
        let remote = iroh::SecretKey::generate().public();

        let outcome = apply_supply_entries(&handler, entries, remote).await;
        assert_eq!(
            outcome.buffered, 1,
            "the transaction waits for its account's open, it is not rejected"
        );
        assert_eq!(outcome.rejected, 0, "nothing is rejected");
        assert_eq!(outcome.merged, 2, "the two opens merge directly");

        let svc = sink.read().await;
        assert!(
            svc.get_directive(&seeded.txn1).is_some(),
            "the drain accepted the once-buffered transaction"
        );
        assert_eq!(svc.directive_count(), 3);
        assert!(
            handler.orphan_buffer.read().await.is_empty(),
            "nothing is left waiting"
        );
    }

    /// T29 (M-09) — the write-DoS. A remote `close` dated before transactions
    /// already on that account is REJECTED, and local appends keep working.
    ///
    /// Before T29 the close was applied unconditionally with its error
    /// swallowed (`let _ =`), which shut the account on every replica and made
    /// every subsequent local append to it fail forever.
    #[tokio::test]
    async fn backdated_remote_close_is_rejected_and_appends_keep_working() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");

        // The victim: opens + a 2024-01-15 transaction on Assets:Cash.
        let seeded = seed_mixed_source(temp_dir.path(), &author.to_string());
        let sink_path = temp_dir.path().join("sink.bean");
        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(sink_path, "sink".to_owned()).expect("boot sink"),
        ));
        let handler = make_handler(sink.clone(), allow);
        let remote = iroh::SecretKey::generate().public();
        let seeded_entries = vec![
            entry_for(&seeded.source, &seeded.open_cash),
            entry_for(&seeded.source, &seeded.open_equity),
            entry_for(&seeded.source, &seeded.open_food),
            entry_for(&seeded.source, &seeded.txn1),
        ];
        assert_eq!(
            apply_supply_entries(&handler, seeded_entries, remote)
                .await
                .merged,
            4
        );

        // The attacker: a node holding no transactions can legitimately close
        // Assets:Cash at 1970-01-01 through its own local API — that is what
        // makes this reachable with one allowlisted peer and no forgery.
        let mut attacker =
            LedgerService::boot(temp_dir.path().join("attacker.bean"), author.to_string())
                .expect("boot attacker");
        attacker
            .open_account(
                "Assets:Cash".to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                vec!["USD".to_owned()],
            )
            .expect("attacker opens cash");
        let poison = attacker
            .close_account(
                "Assets:Cash".to_owned(),
                NaiveDate::from_ymd_opt(1970, 1, 1).expect("valid date"),
            )
            .expect("attacker's own close is legal on its own ledger");

        let outcome =
            apply_supply_entries(&handler, vec![entry_for(&attacker, &poison)], remote).await;
        assert_eq!(outcome.rejected, 1, "the backdated close is rejected");
        assert_eq!(outcome.merged, 0);
        assert_eq!(outcome.buffered, 0, "a bad close is not buffered for retry");

        let mut svc = sink.write().await;
        assert!(
            svc.get_directive(&poison).is_none(),
            "the rejected close never reaches the DAG"
        );
        assert!(
            svc.accounts().is_open("Assets:Cash"),
            "the account is still open"
        );
        // The M-09 consequence that mattered: local writes still work.
        svc.append_transaction(lifecycle_txn(
            "Assets:Cash",
            NaiveDate::from_ymd_opt(2024, 2, 1).expect("valid date"),
            dec!(42),
        ))
        .expect("local append after the poison close must still succeed");
    }

    /// T29 (M-09) — a remote close that does NOT predate the account's
    /// transactions is still accepted. The guard is targeted, not a blanket
    /// refusal of remote closes.
    #[tokio::test]
    async fn forward_dated_remote_close_is_accepted() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let mut source =
            LedgerService::boot(temp_dir.path().join("source.bean"), author.to_string())
                .expect("boot source");
        let open_equity = source
            .open_account("Equity:Opening".to_owned(), day(1, 1), Vec::new())
            .expect("open equity");
        let open_cash = source
            .open_account("Assets:Cash".to_owned(), day(1, 1), vec!["USD".to_owned()])
            .expect("open cash");
        let txn = source
            .append_transaction(lifecycle_txn("Assets:Cash", day(1, 15), dec!(100)))
            .expect("txn")
            .txid;
        let close = source
            .close_account("Assets:Cash".to_owned(), day(6, 1))
            .expect("close cash");

        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), "sink".to_owned())
                .expect("boot sink"),
        ));
        let handler = make_handler(sink.clone(), allow);
        let remote = iroh::SecretKey::generate().public();
        let entries = [&open_equity, &open_cash, &txn, &close]
            .iter()
            .map(|id| entry_for(&source, id))
            .collect();

        let outcome = apply_supply_entries(&handler, entries, remote).await;
        assert_eq!(outcome.merged, 4, "a well-dated close merges");
        assert_eq!(outcome.rejected, 0);
        let svc = sink.read().await;
        assert!(!svc.accounts().is_open("Assets:Cash"));
        assert!(
            svc.accounts().is_open_at("Assets:Cash", day(1, 15)),
            "the close does not retroactively invalidate the earlier transaction"
        );
    }

    // ─── T58 / L-33: budget the Supply while collecting it ─────────────────

    /// L-33 KEY TEST. A full 1,024-id `Want` against a ledger holding every one
    /// of them serializes exactly the 256 entries one `Supply` can carry — not
    /// 1,024 — and serves them as a prefix of the `Want`, which is what the
    /// requester's re-`Want` loop needs. Counted, not timed: the serializer is
    /// the production one, wrapped.
    #[tokio::test]
    async fn collect_supply_serializes_only_what_one_reply_can_carry() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let path = temp_dir.path().join("server.bean");
        write_open_directive_ledger(&path, p2p::protocol::MAX_WANT_IDS, "author");
        let svc = LedgerService::boot(path, "author".to_owned()).expect("boot ledger");
        let mut want: Vec<String> = svc.all_directive_ids().into_iter().collect();
        want.sort();
        assert_eq!(want.len(), p2p::protocol::MAX_WANT_IDS);

        let mut serialized = 0usize;
        let reply = supply_for_want(&svc, &want, |directive| {
            serialized += 1;
            make_supply_entry(directive)
        });
        let WireMessage::Supply { entries, .. } = &reply else {
            panic!("a Want is answered with a Supply");
        };
        assert_eq!(
            serialized,
            MAX_SUPPLY_ENTRIES,
            "L-33: a {}-id Want must serialize only the {MAX_SUPPLY_ENTRIES} entries one \
             Supply can carry",
            want.len()
        );
        let served: Vec<&str> = entries.iter().map(|entry| entry.id.as_str()).collect();
        let prefix: Vec<&str> = want[..MAX_SUPPLY_ENTRIES]
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(served, prefix, "the reply is a prefix of the Want");
        reply.to_wire().expect("the reply frames");
    }

    /// `write_open_directive_ledger`, but each `open` carries a `memo` of
    /// `memo_bytes` — so a handful of directives exceed the 15 MiB Supply byte
    /// budget long before the 256-entry cap.
    fn write_large_open_ledger(
        path: &std::path::Path,
        count: usize,
        memo_bytes: usize,
        author: &str,
    ) {
        use std::fmt::Write as _;

        let memo = "m".repeat(memo_bytes);
        let mut content = String::new();
        for index in 0..count {
            writeln!(content, "2024-01-01 open Assets:Big{index:03}").expect("write to String");
            writeln!(content, "  memo: \"{memo}\"").expect("write to String");
            writeln!(content, "  openledger-author: \"{author}\"").expect("write to String");
            content.push('\n');
        }
        std::fs::write(path, content).expect("write source ledger");
    }

    /// L-33 end to end, on the BYTE budget: 20 directives of ~900 KiB is ~18
    /// MiB, so the first reply is cut by the byte budget (not the entry cap)
    /// and the client must re-`Want` the tail. It converges, and the server's
    /// per-reply serialization stays within one entry of what it sends.
    /// L-95 (T83): a fresh node catching up a chain longer than the per-peer
    /// orphan budget, over real loopback QUIC through the Want session. The
    /// first round buffers what it can and drops the rest; the buffer keeps
    /// the parent links of what it dropped, and the next round's Want asks for
    /// ancestors first, so the chain arrives parent before child and stages
    /// as it lands. The audit measured 30 rounds for a 1,300-chain.
    ///
    /// Bug-catch: drop the `order_want_ancestors_first` call from the Want
    /// session and the sink needs tens of rounds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn l95_a_chain_longer_than_the_orphan_budget_catches_up_in_a_few_rounds() {
        const CHAIN: usize = p2p::orphan_buffer::MAX_ORPHANS_PER_PEER + 300;
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_sink = bind_direct_endpoint().await;
        let id_source = endpoint_source.id();
        let id_sink = endpoint_sink.id();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut source =
            LedgerService::boot(temp_dir.path().join("source.bean"), id_source.to_string())
                .expect("boot source");
        let day = NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date");
        source
            .open_account("Assets:Cash".to_owned(), day, vec![])
            .expect("open");
        source
            .open_account("Equity:Opening".to_owned(), day, vec![])
            .expect("open");
        for index in 0..CHAIN {
            source
                .append_transaction_staged(
                    ledger::service::TransactionInput {
                        date: day,
                        flag: ledger::model::Flag::Complete,
                        payee: None,
                        narration: Some(format!("link {index}")),
                        tags: vec![],
                        links: vec![],
                        postings: vec![
                            ledger::service::PostingInput {
                                account: "Assets:Cash".to_owned(),
                                amount: Some(ledger::model::Amount {
                                    number: rust_decimal::Decimal::from(1),
                                    currency: "USD".to_owned(),
                                }),
                                cost: None,
                                price: None,
                            },
                            ledger::service::PostingInput {
                                account: "Equity:Opening".to_owned(),
                                amount: Some(ledger::model::Amount {
                                    number: rust_decimal::Decimal::from(-1),
                                    currency: "USD".to_owned(),
                                }),
                                cost: None,
                                price: None,
                            },
                        ],
                    },
                    |_, _, _| None,
                )
                .expect("append");
        }
        source.persist_or_reload().expect("persist");
        let total = source.directive_count();

        let ledger_source: SharedLedger = Arc::new(RwLock::new(source));
        let ledger_sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), id_sink.to_string())
                .expect("boot sink"),
        ));
        let handler_source = make_handler(
            ledger_source,
            PeerAllowlist::parse(&[id_sink.to_string()]).expect("allowlist source"),
        );
        let handler_sink = make_handler(
            ledger_sink.clone(),
            PeerAllowlist::parse(&[id_source.to_string()]).expect("allowlist sink"),
        );
        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_source)
            .spawn();
        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_sink).await;

        let mut rounds = 0usize;
        loop {
            exchange_with_peer(&endpoint_sink, endpoint_source.addr(), &handler_sink).await;
            rounds += 1;
            let count = ledger_sink.read().await.directive_count();
            if count == total {
                break;
            }
            if rounds >= 8 {
                let _ = router_source.shutdown().await;
                panic!("L-95: {count} of {total} after {rounds} rounds");
            }
        }
        eprintln!("l95: a {CHAIN}-transaction chain caught up in {rounds} rounds");
        let _ = router_source.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn catchup_converges_when_the_byte_budget_cuts_each_reply() {
        const COUNT: usize = 20;
        const MEMO: usize = 900 * 1024;
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_sink = bind_direct_endpoint().await;
        let id_source = endpoint_source.id();
        let id_sink = endpoint_sink.id();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let source_path = temp_dir.path().join("source.bean");
        write_large_open_ledger(&source_path, COUNT, MEMO, &id_source.to_string());
        let source = LedgerService::boot(source_path, id_source.to_string()).expect("boot source");

        // Deterministic half first: the byte budget, not the entry cap, cuts it.
        let mut want: Vec<String> = source.all_directive_ids().into_iter().collect();
        want.sort();
        let mut serialized = 0usize;
        let first = supply_for_want(&source, &want, |directive| {
            serialized += 1;
            make_supply_entry(directive)
        });
        let WireMessage::Supply { entries, .. } = &first else {
            panic!("a Want is answered with a Supply");
        };
        assert!(
            !entries.is_empty() && entries.len() < COUNT,
            "the byte budget must cut the reply: {} of {COUNT}",
            entries.len()
        );
        assert_eq!(
            serialized,
            entries.len() + 1,
            "one entry past the budget, no more"
        );
        first.to_wire().expect("the cut reply frames");

        let ledger_source: SharedLedger = Arc::new(RwLock::new(source));
        let ledger_sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), id_sink.to_string())
                .expect("boot sink"),
        ));
        let handler_source = make_handler(
            ledger_source,
            PeerAllowlist::parse(&[id_sink.to_string()]).expect("allowlist source"),
        );
        let handler_sink = make_handler(
            ledger_sink.clone(),
            PeerAllowlist::parse(&[id_source.to_string()]).expect("allowlist sink"),
        );
        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_source)
            .spawn();
        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_sink).await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        loop {
            exchange_with_peer(&endpoint_sink, endpoint_source.addr(), &handler_sink).await;
            let count = ledger_sink.read().await.directive_count();
            if count == COUNT {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let _ = router_source.shutdown().await;
                panic!("L-33: sink never caught up under the byte budget: {count} of {COUNT}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = router_source.shutdown().await;
    }

    // ─── T58 / L-34: the anti-entropy refusal cache ─────────────────────────

    /// A seeded source, a sink holding its opens for Cash/Equity plus `txn1`,
    /// and the three shapes L-34 must tell apart:
    ///
    /// * `poison` — a close of Assets:Cash dated 1970, before `txn1`: the M-09
    ///   backdated close, refused FOR GOOD;
    /// * `txn2` — posts to Expenses:Food, whose `open` the sink lacks: an
    ///   ACCOUNT WAIT, acceptable the moment that open arrives;
    /// * `txn3` — a child of `txn2`: an ORPHAN, acceptable once `txn2` lands.
    struct RefusalFixture {
        seeded: SeededSource,
        poison: p2p::protocol::SupplyEntry,
        txn3: String,
        allow: PeerAllowlist,
    }

    fn refusal_fixture(
        dir: &std::path::Path,
        author: &str,
        extra_allow: &[String],
    ) -> RefusalFixture {
        let mut seeded = seed_mixed_source(dir, author);
        let txn3 = seeded
            .source
            .append_transaction(lifecycle_txn("Assets:Cash", day(1, 25), dec!(5)))
            .expect("append txn3 (child of txn2)")
            .txid;
        let mut attacker = LedgerService::boot(dir.join("attacker.bean"), author.to_owned())
            .expect("boot attacker");
        attacker
            .open_account("Assets:Cash".to_owned(), day(1, 1), vec!["USD".to_owned()])
            .expect("attacker opens cash");
        let poison_id = attacker
            .close_account(
                "Assets:Cash".to_owned(),
                NaiveDate::from_ymd_opt(1970, 1, 1).expect("valid date"),
            )
            .expect("attacker's own close is legal on its own ledger");
        let mut allowed = vec![author.to_owned()];
        allowed.extend_from_slice(extra_allow);
        RefusalFixture {
            poison: entry_for(&attacker, &poison_id),
            seeded,
            txn3,
            allow: PeerAllowlist::parse(&allowed).expect("allowlist"),
        }
    }

    /// Boot a sink already holding Cash/Equity opens and `txn1`.
    async fn refusal_sink(dir: &std::path::Path, fixture: &RefusalFixture) -> AntiEntropyHandler {
        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(dir.join("sink.bean"), "sink".to_owned()).expect("boot sink"),
        ));
        let handler = make_handler(sink, fixture.allow.clone());
        let seeded = &fixture.seeded;
        let seed = vec![
            entry_for(&seeded.source, &seeded.open_cash),
            entry_for(&seeded.source, &seeded.open_equity),
            entry_for(&seeded.source, &seeded.txn1),
        ];
        let seeder = iroh::SecretKey::generate().public();
        assert_eq!(apply_supply_entries(&handler, seed, seeder).await.merged, 3);
        handler
    }

    /// L-34 KEY TEST (classification). Of one batch, only the permanent
    /// refusals are cached — the backdated close and a body that fails intake —
    /// while the account-wait and the orphan are NOT, and both still converge
    /// once their dependency arrives. The cache is per peer.
    #[tokio::test]
    async fn only_permanent_refusals_are_cached_and_waits_still_converge() {
        let author = iroh::SecretKey::generate().public();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let fixture = refusal_fixture(temp_dir.path(), &author.to_string(), &[]);
        let handler = refusal_sink(temp_dir.path(), &fixture).await;
        let seeded = &fixture.seeded;
        let remote = iroh::SecretKey::generate().public();
        let peer = remote.to_string();

        // An intake failure under a well-formed id: permanent for this peer.
        let garbage_id = format!("{:064x}", 0xdead_beefu64);
        let garbage = p2p::protocol::SupplyEntry {
            id: garbage_id.clone(),
            kind: p2p::protocol::DirectiveKind::Open,
            economic_bean: "this is not valid beancount".to_owned(),
            envelope: std::collections::BTreeMap::new(),
        };
        let batch = vec![
            fixture.poison.clone(),
            entry_for(&seeded.source, &seeded.txn2),
            entry_for(&seeded.source, &fixture.txn3),
            garbage,
        ];
        let outcome = apply_supply_entries(&handler, batch, remote).await;
        assert_eq!(
            outcome.rejected, 2,
            "the backdated close and the garbage body"
        );
        assert_eq!(outcome.buffered, 2, "the account-wait and the orphan");

        let now = std::time::Instant::now();
        {
            let buffer = handler.orphan_buffer.read().await;
            let refusals = buffer.refusals();
            assert!(
                refusals.is_refused(&peer, &fixture.poison.id, now),
                "the backdated close is refused for good"
            );
            assert!(refusals.is_refused(&peer, &garbage_id, now));
            assert!(
                !refusals.is_refused(&peer, &seeded.txn2, now),
                "an ACCOUNT-WAIT must never be cached: its open may still arrive"
            );
            assert!(
                !refusals.is_refused(&peer, &fixture.txn3, now),
                "an ORPHAN must never be cached: its parent may still arrive"
            );
            assert_eq!(refusals.len(), 2);
            assert!(
                !refusals.is_refused(
                    &iroh::SecretKey::generate().public().to_string(),
                    &fixture.poison.id,
                    now
                ),
                "another peer's copy is not suppressed"
            );
        }

        // The dependency arrives: the account-wait drains, which frees the
        // orphan — both land, and the cache is unchanged.
        let outcome = apply_supply_entries(
            &handler,
            vec![entry_for(&seeded.source, &seeded.open_food)],
            remote,
        )
        .await;
        assert_eq!(outcome.merged, 1);
        let svc = handler.ledger.read().await;
        assert!(
            svc.get_directive(&seeded.txn2).is_some(),
            "the account-wait converged"
        );
        assert!(
            svc.get_directive(&fixture.txn3).is_some(),
            "the orphan converged"
        );
        assert!(svc.get_directive(&fixture.poison.id).is_none());
        drop(svc);
        let buffer = handler.orphan_buffer.read().await;
        assert!(buffer.is_empty(), "nothing is left waiting");
        assert_eq!(buffer.refusals().len(), 2);
    }

    // ─── T72 / L-69: the ratchet short-circuit and the refusal warn throttle ──

    /// The unit: an id refused against `remote` is held out of the Want while
    /// the clock is below `remote − MAX_LAMPORT_ADVANCE + 1`, is released on
    /// exactly that clock (the first at which adoption succeeds), is keyed by
    /// peer, and is bounded per peer.
    #[test]
    fn ratchet_deferral_holds_an_id_exactly_until_the_clock_can_adopt_it() {
        let backoff = SupplyBackoff::default();
        let peer = iroh::SecretKey::generate().public();
        let other = iroh::SecretKey::generate().public();
        let id = format!("{:064x}", 0x1u64);
        let remote = ledger::service::MAX_LAMPORT_ADVANCE + 10;
        // Refused at local clock 5 (remote − local = 2^32 + 5 ≥ 2^32).
        backoff.defer_ratcheted(peer, id.clone(), remote);

        let want_at = |clock: u64, who: EndpointId| {
            let mut want = vec![id.clone()];
            let dropped = backoff.retain_not_ratcheted(who, &mut want, clock);
            (dropped, want.len())
        };
        assert_eq!(want_at(5, peer), (1, 0), "held at the refusing clock");
        assert_eq!(
            want_at(10, peer),
            (1, 0),
            "held at remote − 2^32: still refused"
        );
        assert_eq!(want_at(5, other), (0, 1), "keyed by peer");
        // At clock 11, remote − local = 2^32 − 1 < 2^32: adoptable, so wanted.
        assert_eq!(
            want_at(11, peer),
            (0, 1),
            "released on the first adoptable clock"
        );
        assert_eq!(backoff.ratcheted_count(peer), 0, "and forgotten");
        assert_eq!(want_at(5, peer), (0, 1), "not re-held once forgotten");

        // Bounded per peer: the cap stops recording, never evicts.
        for n in 0..(RATCHET_DEFERRED_MAX_IDS_PER_PEER + 5) {
            backoff.defer_ratcheted(peer, format!("{n:064x}"), remote);
        }
        assert_eq!(
            backoff.ratcheted_count(peer),
            RATCHET_DEFERRED_MAX_IDS_PER_PEER
        );
        let mut want = vec![format!("{:064x}", RATCHET_DEFERRED_MAX_IDS_PER_PEER + 1)];
        assert_eq!(backoff.retain_not_ratcheted(peer, &mut want, 5), 0);
    }

    /// The throttle: one line per peer per `STAGE_REFUSAL_LOG_INTERVAL`, the
    /// next line carrying the suppressed count; peers are independent.
    #[test]
    fn stage_refusal_warn_is_one_line_per_peer_per_interval_with_a_count() {
        let backoff = SupplyBackoff::default();
        let peer = iroh::SecretKey::generate().public();
        let other = iroh::SecretKey::generate().public();
        let start = std::time::Instant::now();
        assert_eq!(backoff.should_log_stage_refusal(peer, start), Some(0));
        for i in 1..=5 {
            assert_eq!(
                backoff.should_log_stage_refusal(peer, start + Duration::from_secs(i)),
                None,
                "inside the interval"
            );
        }
        assert_eq!(
            backoff.should_log_stage_refusal(other, start + Duration::from_secs(3)),
            Some(0),
            "another peer has its own line"
        );
        assert_eq!(
            backoff.should_log_stage_refusal(peer, start + STAGE_REFUSAL_LOG_INTERVAL),
            Some(5),
            "the next line carries the suppressed count"
        );
        assert_eq!(
            backoff.should_log_stage_refusal(peer, start + 2 * STAGE_REFUSAL_LOG_INTERVAL),
            Some(0)
        );
    }

    /// The property, end to end (the audit's L-69 shape): a peer advertising
    /// a directive `2^32` above this node's clock is asked for it ONCE; the
    /// following exchanges do not re-fetch it while the clock has not moved,
    /// and it is still not in the L-34 cache (the verdict is not permanent).
    /// Then the history the node needs arrives from the same peer, the clock
    /// climbs, and the same id is Wanted and adopted — the short-circuit
    /// never turns a delay into a loss.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ratchet_refused_directive_is_wanted_once_until_the_clock_moves() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_sink = bind_direct_endpoint().await;
        let author = iroh::SecretKey::generate().public();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let fixture = refusal_fixture(
            temp_dir.path(),
            &author.to_string(),
            &[endpoint_source.id().to_string()],
        );
        let handler_sink = refusal_sink(temp_dir.path(), &fixture).await;
        let seeded = &fixture.seeded;
        let local = handler_sink.ledger.read().await.lamport_clock();

        // The jump: the source's `open_food`, re-enveloped one ratchet step
        // above the sink's clock (signing is off in this harness, so the
        // envelope needs no signature; the author is allowlisted).
        let jump_lamport = local + ledger::service::MAX_LAMPORT_ADVANCE;
        let mut jump = seeded
            .source
            .get_directive(&seeded.open_food)
            .expect("open food")
            .clone();
        let ledger::model::Directive::Open(open) = &mut jump else {
            panic!("open_food is an open")
        };
        open.metadata
            .insert("openledger-lamport".to_owned(), jump_lamport.to_string());
        let jump_entry = make_supply_entry(&jump);
        // A bridge the sink can adopt, at exactly the largest legal step, so
        // that once it lands the jump is within reach.
        let mut bridge = seeded
            .source
            .get_directive(&seeded.open_equity)
            .expect("open equity")
            .clone();
        let ledger::model::Directive::Open(open) = &mut bridge else {
            panic!("open_equity is an open")
        };
        open.account = "Assets:Bridge".to_owned();
        open.metadata.insert(
            "openledger-lamport".to_owned(),
            (local + ledger::service::MAX_LAMPORT_ADVANCE - 1).to_string(),
        );
        let bridge_entry = make_supply_entry(&bridge);

        let source = RecordingSource {
            entries: Arc::new(std::sync::Mutex::new(vec![jump_entry.clone()])),
            wanted: Arc::new(std::sync::Mutex::new(Vec::new())),
            unsolicited: Vec::new(),
        };
        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, source.clone())
            .spawn();
        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_sink).await;
        let times_wanted = |id: &str| {
            source
                .wanted
                .lock()
                .expect("wanted")
                .iter()
                .filter(|wanted| wanted.as_str() == id)
                .count()
        };

        for _ in 0..3 {
            exchange_with_peer(&endpoint_sink, endpoint_source.addr(), &handler_sink).await;
        }
        assert_eq!(
            times_wanted(&jump_entry.id),
            1,
            "L-69: a ratchet-refused directive is fetched once while the clock has not moved"
        );
        {
            let svc = handler_sink.ledger.read().await;
            assert!(svc.get_directive(&jump_entry.id).is_none());
            assert_eq!(svc.lamport_clock(), local, "the refusal moved nothing");
        }
        assert_eq!(
            handler_sink.orphan_buffer.read().await.refusals().len(),
            0,
            "not a permanent verdict: the L-34 cache holds nothing"
        );
        assert_eq!(
            handler_sink
                .supply_backoff
                .ratcheted_count(endpoint_source.id()),
            1
        );

        // The bridge appears; the clock climbs; the jump is Wanted again and
        // adopted on the very next exchange.
        source
            .entries
            .lock()
            .expect("entries")
            .push(bridge_entry.clone());
        exchange_with_peer(&endpoint_sink, endpoint_source.addr(), &handler_sink).await;
        {
            let svc = handler_sink.ledger.read().await;
            assert!(
                svc.get_directive(&bridge_entry.id).is_some(),
                "the bridge landed"
            );
            assert!(
                svc.lamport_clock() > jump_lamport - ledger::service::MAX_LAMPORT_ADVANCE,
                "the clock is now within one step of the jump"
            );
        }
        exchange_with_peer(&endpoint_sink, endpoint_source.addr(), &handler_sink).await;
        let _ = router_source.shutdown().await;
        assert!(
            times_wanted(&jump_entry.id) >= 2,
            "re-Wanted once the clock could adopt it: {}",
            times_wanted(&jump_entry.id)
        );
        let svc = handler_sink.ledger.read().await;
        assert!(
            svc.get_directive(&jump_entry.id).is_some(),
            "the short-circuit delayed nothing the node could adopt"
        );
        assert_eq!(
            handler_sink
                .supply_backoff
                .ratcheted_count(endpoint_source.id()),
            0,
            "forgotten once the clock reached it"
        );
    }

    /// T66 / L-60 (unit): the wanted-set filter keeps exactly the entries whose
    /// id was outstanding, in arrival order, and counts the rest.
    #[test]
    fn retain_wanted_entries_keeps_only_the_outstanding_ids() {
        let entry = |id: &str| p2p::protocol::SupplyEntry {
            id: id.to_owned(),
            kind: p2p::protocol::DirectiveKind::Open,
            economic_bean: String::new(),
            envelope: std::collections::BTreeMap::new(),
        };
        let a = format!("{:064x}", 0xau64);
        let b = format!("{:064x}", 0xbu64);
        let junk = format!("{:064x}", 0xdead_beefu64);
        let wanted: HashSet<&str> = [a.as_str(), b.as_str()].into_iter().collect();
        let (kept, dropped) = retain_wanted_entries(
            vec![entry(&junk), entry(&b), entry("not-even-an-id"), entry(&a)],
            &wanted,
        );
        assert_eq!(dropped, 2);
        assert_eq!(
            kept.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            vec![b.as_str(), a.as_str()]
        );
        let (kept, dropped) = retain_wanted_entries(Vec::new(), &wanted);
        assert!(kept.is_empty());
        assert_eq!(dropped, 0);
    }

    /// T66 / L-60 (pushed arm): the same batch as
    /// `only_permanent_refusals_are_cached_and_waits_still_converge`, applied
    /// as a PUSHED frame, records nothing — neither the backdated close nor
    /// the garbage body — while it is still applied (the waits are buffered).
    #[tokio::test]
    async fn a_pushed_supply_records_no_refusals() {
        let author = iroh::SecretKey::generate().public();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let fixture = refusal_fixture(temp_dir.path(), &author.to_string(), &[]);
        let handler = refusal_sink(temp_dir.path(), &fixture).await;
        let seeded = &fixture.seeded;
        let remote = iroh::SecretKey::generate().public();
        let peer = remote.to_string();

        let garbage_id = format!("{:064x}", 0xdead_beefu64);
        let garbage = p2p::protocol::SupplyEntry {
            id: garbage_id.clone(),
            kind: p2p::protocol::DirectiveKind::Open,
            economic_bean: "this is not valid beancount".to_owned(),
            envelope: std::collections::BTreeMap::new(),
        };
        let batch = vec![
            fixture.poison.clone(),
            entry_for(&seeded.source, &seeded.txn2),
            entry_for(&seeded.source, &fixture.txn3),
            garbage,
        ];
        let outcome = apply_supply_entries_from(
            &handler,
            batch,
            remote,
            SupplyOrigin::Pushed,
            &mut FrameReservation::unmetered(),
        )
        .await;
        assert_eq!(outcome.rejected, 2, "still refused");
        assert_eq!(outcome.buffered, 2, "still applied: the waits are buffered");

        let now = std::time::Instant::now();
        let buffer = handler.orphan_buffer.read().await;
        let refusals = buffer.refusals();
        assert!(
            refusals.is_empty(),
            "a pushed frame must not occupy the refusal cache: {}",
            refusals.len()
        );
        assert!(!refusals.is_refused(&peer, &fixture.poison.id, now));
        assert!(!refusals.is_refused(&peer, &garbage_id, now));
        drop(buffer);

        // The Wanted path, for contrast, records both (the L-34 test proper).
        let wanted = vec![fixture.poison.clone()];
        apply_supply_entries_from(
            &handler,
            wanted,
            remote,
            SupplyOrigin::Wanted,
            &mut FrameReservation::unmetered(),
        )
        .await;
        let buffer = handler.orphan_buffer.read().await;
        assert!(buffer.refusals().is_refused(&peer, &fixture.poison.id, now));
    }

    /// A stand-in peer that serves a fixed set of entries over the real wire
    /// protocol and RECORDS every id it is asked for — the observable L-34's
    /// end-to-end test counts. Serves streams until the connection ends, so
    /// the client's pooled connection is reused across exchanges (T42).
    #[derive(Clone)]
    struct RecordingSource {
        entries: Arc<std::sync::Mutex<Vec<p2p::protocol::SupplyEntry>>>,
        wanted: Arc<std::sync::Mutex<Vec<String>>>,
        /// Appended to EVERY `Supply` reply whether or not they were Wanted
        /// (L-60). Empty for an honest peer.
        unsolicited: Vec<p2p::protocol::SupplyEntry>,
    }

    impl std::fmt::Debug for RecordingSource {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("RecordingSource")
                .finish_non_exhaustive()
        }
    }

    impl ProtocolHandler for RecordingSource {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let io = Duration::from_secs(5);
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                while let Ok(message) =
                    read_message(&mut recv, io, &mut FrameReservation::unmetered()).await
                {
                    let reply = match message {
                        WireMessage::HaveHeads { more: false, .. } => {
                            let held = self.entries.lock().expect("entries").clone();
                            let ids = held.iter().map(|entry| entry.id.clone()).collect();
                            WireMessage::have_heads_page(Vec::new(), ids, false)
                        }
                        WireMessage::Want { ids, .. } => {
                            self.wanted
                                .lock()
                                .expect("wanted")
                                .extend(ids.iter().cloned());
                            let held = self.entries.lock().expect("entries").clone();
                            let mut reply = p2p::anti_entropy::build_supply(&ids, |id| {
                                held.iter().find(|entry| entry.id == id).cloned()
                            });
                            if let WireMessage::Supply { entries, .. } = &mut reply {
                                entries.extend(self.unsolicited.iter().cloned());
                            }
                            reply
                        }
                        _ => continue,
                    };
                    if write_message(&mut send, &reply, io).await.is_err() {
                        break;
                    }
                }
                let _ = send.finish();
            }
            Ok(())
        }
    }

    /// L-34 KEY TEST (end to end). A peer advertising a directive this node
    /// refuses for good is asked for it ONCE; the next exchanges, inside the
    /// TTL, do not ask again. The account-wait and the orphan from the same
    /// advert ARE asked for again every exchange — they are not cached — and
    /// both converge once the missing `open` appears in the peer's advert.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn refused_directive_is_wanted_once_but_waits_are_rewanted_until_they_land() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_sink = bind_direct_endpoint().await;
        let author = iroh::SecretKey::generate().public();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let fixture = refusal_fixture(
            temp_dir.path(),
            &author.to_string(),
            &[endpoint_source.id().to_string()],
        );
        let handler_sink = refusal_sink(temp_dir.path(), &fixture).await;
        let seeded = &fixture.seeded;

        let held: Vec<p2p::protocol::SupplyEntry> = vec![
            entry_for(&seeded.source, &seeded.open_cash),
            entry_for(&seeded.source, &seeded.open_equity),
            entry_for(&seeded.source, &seeded.txn1),
            fixture.poison.clone(),
            entry_for(&seeded.source, &seeded.txn2),
            entry_for(&seeded.source, &fixture.txn3),
        ];
        let source = RecordingSource {
            entries: Arc::new(std::sync::Mutex::new(held)),
            wanted: Arc::new(std::sync::Mutex::new(Vec::new())),
            unsolicited: Vec::new(),
        };
        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, source.clone())
            .spawn();
        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_sink).await;
        let times_wanted = |id: &str| {
            source
                .wanted
                .lock()
                .expect("wanted")
                .iter()
                .filter(|wanted| wanted.as_str() == id)
                .count()
        };

        for _ in 0..3 {
            exchange_with_peer(&endpoint_sink, endpoint_source.addr(), &handler_sink).await;
        }
        assert_eq!(
            times_wanted(&fixture.poison.id),
            1,
            "L-34: a directive refused for good is wanted once, not once per tick"
        );
        assert_eq!(
            times_wanted(&seeded.txn2),
            3,
            "an account-wait is re-wanted"
        );
        assert_eq!(times_wanted(&fixture.txn3), 3, "an orphan is re-wanted");

        // The missing open appears; the waits land on the next exchange.
        source
            .entries
            .lock()
            .expect("entries")
            .push(entry_for(&seeded.source, &seeded.open_food));
        exchange_with_peer(&endpoint_sink, endpoint_source.addr(), &handler_sink).await;
        let _ = router_source.shutdown().await;

        assert_eq!(times_wanted(&fixture.poison.id), 1, "still not re-wanted");
        let svc = handler_sink.ledger.read().await;
        assert!(svc.get_directive(&seeded.open_food).is_some());
        assert!(
            svc.get_directive(&seeded.txn2).is_some(),
            "the account-wait converged"
        );
        assert!(
            svc.get_directive(&fixture.txn3).is_some(),
            "the orphan converged"
        );
        assert!(svc.get_directive(&fixture.poison.id).is_none());
    }

    /// L-106 (T88, decision (27)) KEY TEST, end to end over QUIC. A peer
    /// serves X — a transaction with an amount past the cap, refused for good
    /// at intake — and X's child C and grandchild G. L-34 stops the Want of X
    /// after the first exchange; before T88, C and G (buffered, MISSING a
    /// parent, which is retried) were asked for, re-sent, re-parsed and
    /// re-verified on every exchange, forever (X2 `r3`: 50 a round). They can
    /// only wait on X, so they are asked for once. Nothing is staged.
    ///
    /// Bug-catch: drop the `retain_not_doomed` call in the Want session and C
    /// and G are wanted three times.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn l106_the_subtree_under_a_record_refused_for_good_is_wanted_once() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_sink = bind_direct_endpoint().await;
        let author = iroh::SecretKey::generate().public();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let fixture = refusal_fixture(
            temp_dir.path(),
            &author.to_string(),
            &[endpoint_source.id().to_string()],
        );
        let handler_sink = refusal_sink(temp_dir.path(), &fixture).await;

        let hand_entry = |body: String, lamport: u64, parents: &str, identify: bool| {
            let limits = if identify {
                ledger::parse::ParseLimits::IDENTIFY
            } else {
                ledger::parse::ParseLimits::UNLIMITED
            };
            let parsed = ledger::parse::parse_file_bounded(&body, 0, limits)
                .expect("parses")
                .remove(0);
            p2p::protocol::SupplyEntry {
                id: ledger::hash::compute_content_id(&parsed),
                kind: p2p::protocol::DirectiveKind::Transaction,
                economic_bean: body,
                envelope: std::collections::BTreeMap::from([
                    ("openledger-author".to_owned(), author.to_string()),
                    ("openledger-lamport".to_owned(), lamport.to_string()),
                    ("openledger-parents".to_owned(), parents.to_owned()),
                ]),
            }
        };
        let x = hand_entry(
            "2024-01-20 * \"X past the cap\"\n  Assets:Cash 50000000000000000000000 USD\n  \
             Equity:Opening -50000000000000000000000 USD\n"
                .to_owned(),
            50,
            "",
            true,
        );
        let c = hand_entry(
            "2024-01-21 * \"C child of X\"\n  Assets:Cash 1 USD\n  Equity:Opening -1 USD\n"
                .to_owned(),
            51,
            &x.id,
            false,
        );
        let g = hand_entry(
            "2024-01-22 * \"G grandchild\"\n  Assets:Cash 2 USD\n  Equity:Opening -2 USD\n"
                .to_owned(),
            52,
            &c.id,
            false,
        );
        let source = RecordingSource {
            entries: Arc::new(std::sync::Mutex::new(vec![x.clone(), c.clone(), g.clone()])),
            wanted: Arc::new(std::sync::Mutex::new(Vec::new())),
            unsolicited: Vec::new(),
        };
        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, source.clone())
            .spawn();
        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_sink).await;
        let times_wanted = |id: &str| {
            source
                .wanted
                .lock()
                .expect("wanted")
                .iter()
                .filter(|wanted| wanted.as_str() == id)
                .count()
        };

        for _ in 0..3 {
            exchange_with_peer(&endpoint_sink, endpoint_source.addr(), &handler_sink).await;
        }
        let _ = router_source.shutdown().await;
        assert_eq!(times_wanted(&x.id), 1, "L-34: the refused record itself");
        assert_eq!(
            (times_wanted(&c.id), times_wanted(&g.id)),
            (1, 1),
            "the subtree that can only wait on it is wanted once, not once per exchange"
        );
        let svc = handler_sink.ledger.read().await;
        for id in [&x.id, &c.id, &g.id] {
            assert!(svc.get_directive(id).is_none());
        }
    }

    /// T66 / L-60 KEY TEST (end to end). A peer that pads every `Supply` reply
    /// with entries this node never Wanted — 200 garbage bodies under fresh,
    /// well-formed ids (with the four honest ones, under the 256-entry frame
    /// cap) — gets none of them validated or remembered: after the exchange
    /// the refusal cache holds exactly the ONE refusal the node earned by
    /// asking (the backdated close), not 201, and no garbage id is in it.
    /// Before T66 each such frame cost 200 parses and 200 cache slots, and
    /// about twenty of them filled the peer's whole 4,096 quota (L-60).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unsolicited_supply_entries_are_dropped_before_validation_and_never_cached() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_sink = bind_direct_endpoint().await;
        let author = iroh::SecretKey::generate().public();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let fixture = refusal_fixture(
            temp_dir.path(),
            &author.to_string(),
            &[endpoint_source.id().to_string()],
        );
        let handler_sink = refusal_sink(temp_dir.path(), &fixture).await;
        let seeded = &fixture.seeded;

        let held: Vec<p2p::protocol::SupplyEntry> = vec![
            entry_for(&seeded.source, &seeded.open_food),
            fixture.poison.clone(),
            entry_for(&seeded.source, &seeded.txn2),
            entry_for(&seeded.source, &fixture.txn3),
        ];
        let unsolicited: Vec<p2p::protocol::SupplyEntry> = (0..200u64)
            .map(|index| p2p::protocol::SupplyEntry {
                id: format!("{:064x}", 0xdead_0000u64 + index),
                kind: p2p::protocol::DirectiveKind::Open,
                economic_bean: "this is not valid beancount".to_owned(),
                envelope: std::collections::BTreeMap::new(),
            })
            .collect();
        let unsolicited_ids: Vec<String> = unsolicited.iter().map(|e| e.id.clone()).collect();
        let source = RecordingSource {
            entries: Arc::new(std::sync::Mutex::new(held)),
            wanted: Arc::new(std::sync::Mutex::new(Vec::new())),
            unsolicited,
        };
        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, source.clone())
            .spawn();
        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_sink).await;

        for _ in 0..2 {
            exchange_with_peer(&endpoint_sink, endpoint_source.addr(), &handler_sink).await;
        }
        let _ = router_source.shutdown().await;

        // The Wanted entries converged as usual.
        let svc = handler_sink.ledger.read().await;
        assert!(svc.get_directive(&seeded.open_food).is_some());
        assert!(svc.get_directive(&seeded.txn2).is_some());
        assert!(svc.get_directive(&fixture.txn3).is_some());
        assert!(svc.get_directive(&fixture.poison.id).is_none());
        drop(svc);

        // The refusal cache holds the one earned refusal and nothing unwanted.
        let now = std::time::Instant::now();
        let peer = endpoint_source.id().to_string();
        let buffer = handler_sink.orphan_buffer.read().await;
        let refusals = buffer.refusals();
        assert!(refusals.is_refused(&peer, &fixture.poison.id, now));
        assert_eq!(
            refusals.len(),
            1,
            "L-60: unsolicited entries must not occupy the refusal cache"
        );
        for id in &unsolicited_ids {
            assert!(!refusals.is_refused(&peer, id, now), "{id} was recorded");
        }
        // And they were never asked for — the sink's Wants name only advert ids.
        let wanted = source.wanted.lock().expect("wanted");
        for id in &unsolicited_ids {
            assert!(!wanted.contains(id));
        }
    }

    // ─── T58 / L-39: the inbound frame byte budget ──────────────────────────

    /// An [`ExactReader`] that delivers the first `stall_at` bytes of `data` and
    /// then never delivers another — a peer that stopped mid-frame.
    struct StallingReader {
        data: Vec<u8>,
        pos: usize,
        stall_at: usize,
    }

    impl ExactReader for StallingReader {
        async fn read_exact_bytes(&mut self, buf: &mut [u8]) -> Result<(), FrameError> {
            let end = self.pos + buf.len();
            if end > self.stall_at.min(self.data.len()) {
                std::future::pending::<()>().await;
            }
            buf.copy_from_slice(&self.data[self.pos..end]);
            self.pos = end;
            Ok(())
        }
    }

    /// A genuine `Supply` frame of about `entries × 120 KiB`.
    fn supply_frame(entries: usize) -> Vec<u8> {
        let entries = (0..entries)
            .map(|index| p2p::protocol::SupplyEntry {
                id: format!("{index:064x}"),
                kind: p2p::protocol::DirectiveKind::Open,
                economic_bean: "x".repeat(120 * 1024),
                envelope: std::collections::BTreeMap::new(),
            })
            .collect();
        WireMessage::supply(entries)
            .to_wire()
            .expect("frame supply")
    }

    fn byte_budget_limiter(total: usize, per_peer: usize) -> ConnectionLimiter {
        ConnectionLimiter::new(AntiEntropyLimits {
            max_frame_bytes_in_flight: total,
            max_frame_bytes_in_flight_per_peer: per_peer,
            ..AntiEntropyLimits::default()
        })
    }

    fn is_budget_refusal(error: &FrameError) -> bool {
        matches!(error, FrameError::Protocol(message) if message.contains("byte budget exhausted"))
    }

    /// L-39: a frame body is charged to the budget while it is held and
    /// released when its reservation drops; a frame the budget cannot cover is
    /// refused, not waited for, and leaves nothing charged behind.
    #[tokio::test]
    async fn frame_bodies_are_charged_while_held_and_refused_past_the_budget() {
        let peer = iroh::SecretKey::generate().public();
        let wire = supply_frame(12); // ~1.4 MiB: over the non-supply cap too
        let limiter = byte_budget_limiter(4 * 1024 * 1024, 4 * 1024 * 1024);

        let mut reservation = limiter.frame_reservation(peer);
        let message = read_frame(
            &mut slice_reader(&wire),
            Duration::from_secs(5),
            &mut reservation,
        )
        .await
        .expect("a frame within the budget is read");
        assert!(matches!(message, WireMessage::Supply { .. }));
        let body = wire.len() - 4;
        let charged = limiter.frame_bytes_in_flight();
        assert!(
            charged >= body && charged <= 2 * body,
            "the body is charged while held: charged {charged} for a {body}-byte body"
        );
        assert_eq!(reservation.held(), charged);
        drop(reservation);
        assert_eq!(
            limiter.frame_bytes_in_flight(),
            0,
            "released with the reservation"
        );

        // A per-peer budget smaller than the frame: refused mid-read, released.
        let tight = byte_budget_limiter(4 * 1024 * 1024, 512 * 1024);
        let mut reservation = tight.frame_reservation(peer);
        let error = read_frame(
            &mut slice_reader(&wire),
            Duration::from_secs(5),
            &mut reservation,
        )
        .await
        .expect_err("a frame past the per-peer budget is refused");
        assert!(is_budget_refusal(&error), "got {error:?}");
        assert!(tight.frame_bytes_peak() <= 512 * 1024);
        drop(reservation);
        assert_eq!(tight.frame_bytes_in_flight(), 0);
    }

    /// L-39 KEY TEST. Six peers' frames stall mid-body at once against a 1 MiB
    /// budget. Together they never hold more than the budget — the frames that
    /// cannot get budget are refused immediately rather than waiting for it —
    /// and once the stalled ones time out, every byte is released. Paused
    /// time makes the timeouts deterministic.
    #[tokio::test(start_paused = true)]
    async fn concurrent_frames_cannot_exceed_the_byte_budget_and_release_it_all() {
        const BUDGET: usize = 1024 * 1024;
        const FRAMES: usize = 6;
        let limiter = byte_budget_limiter(BUDGET, BUDGET);
        let wire = supply_frame(5); // ~600 KiB
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..FRAMES {
            let limiter = limiter.clone();
            let data = wire.clone();
            tasks.spawn(async move {
                let peer = iroh::SecretKey::generate().public();
                let mut reader = StallingReader {
                    data,
                    pos: 0,
                    stall_at: 4 + 300 * 1024,
                };
                let mut reservation = limiter.frame_reservation(peer);
                read_frame(&mut reader, Duration::from_secs(30), &mut reservation).await
            });
        }
        let (mut refused, mut timed_out) = (0, 0);
        while let Some(outcome) = tasks.join_next().await {
            match outcome.expect("task") {
                Err(error) if is_budget_refusal(&error) => refused += 1,
                Err(FrameError::Timeout) => timed_out += 1,
                other => panic!("a stalled frame cannot complete: {other:?}"),
            }
        }
        assert!(refused >= 1, "frames past the budget must be refused");
        assert!(timed_out >= 1, "frames within it stall until their timeout");
        assert_eq!(refused + timed_out, FRAMES);
        let peak = limiter.frame_bytes_peak();
        assert!(peak > 0, "the stalled frames were charged");
        assert!(
            peak <= BUDGET,
            "L-39: {peak} bytes in flight exceeds the {BUDGET} budget"
        );
        assert_eq!(
            limiter.frame_bytes_in_flight(),
            0,
            "every byte is released after refusals and timeouts"
        );
    }

    /// L-39 wiring: the SERVE loop charges inbound frames to the handler's
    /// budget. A peer sending one legitimately-shaped ~540 KiB advert page to a
    /// node whose budget is 256 KiB has its frame refused and its connection
    /// closed, and nothing stays charged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn serve_loop_refuses_frames_past_the_byte_budget_and_releases_them() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_server = bind_direct_endpoint().await;
        let endpoint_client = bind_direct_endpoint().await;
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("server.bean"), "server".to_owned())
                .expect("boot ledger"),
        ));
        let limits = AntiEntropyLimits {
            max_frame_bytes_in_flight: 256 * 1024,
            max_frame_bytes_in_flight_per_peer: 256 * 1024,
            ..AntiEntropyLimits::default()
        };
        let handler = make_handler_with_limits(
            ledger,
            PeerAllowlist::parse(&[endpoint_client.id().to_string()]).expect("allowlist"),
            limits,
        );
        let router = Router::builder(endpoint_server.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler.clone())
            .spawn();
        wait_until_dialable(&endpoint_server).await;
        wait_until_dialable(&endpoint_client).await;

        let connection = connect_retry(&endpoint_client, endpoint_server.addr()).await;
        let (mut send, _recv) = connection.open_bi().await.expect("open stream");
        let ids: Vec<String> = (0..MAX_HAVE_HEADS)
            .map(|index| format!("{index:064x}"))
            .collect();
        let page = WireMessage::have_heads_page(ids.clone(), ids, false);
        write_message(&mut send, &page, Duration::from_secs(5))
            .await
            .expect("send the page");
        let closed = tokio::time::timeout(Duration::from_secs(20), connection.closed()).await;
        let _ = router.shutdown().await;

        assert!(closed.is_ok(), "the server must tear the connection down");
        let peak = handler.limiter.frame_bytes_peak();
        assert!(peak > 0, "the serve loop charged the frame");
        assert!(peak <= 256 * 1024, "never past the budget: {peak}");
        assert_eq!(
            handler.limiter.frame_bytes_in_flight(),
            0,
            "nothing stays charged"
        );
    }

    // ─── T77: near-cap and edge cost bounds ───────────────────────────────

    /// A log sink the capture subscribers write into (T77).
    #[derive(Clone, Default)]
    pub(crate) struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
        type Writer = LogBuffer;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl LogBuffer {
        pub(crate) fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
        }
    }

    /// Capture every event on this thread (and so every task of a
    /// current-thread runtime) twice: `raw`, unfiltered at `WARN` and above,
    /// and `filtered`, through the node's default `EnvFilter`
    /// ([`crate::DEFAULT_LOG_FILTER`]) — what an operator without `RUST_LOG`
    /// actually gets. Held until the guard drops.
    pub(crate) fn capture_logs() -> (tracing::subscriber::DefaultGuard, LogBuffer, LogBuffer) {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Layer;
        let raw = LogBuffer::default();
        let filtered = LogBuffer::default();
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(raw.clone())
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
            )
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(filtered.clone())
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::EnvFilter::new(
                        crate::DEFAULT_LOG_FILTER,
                    )),
            );
        (tracing::subscriber::set_default(subscriber), raw, filtered)
    }

    /// `WARN` lines of `text` whose target is `target`.
    fn warn_lines<'a>(text: &'a str, target: &str) -> Vec<&'a str> {
        let marker = format!(" {target}:");
        text.lines()
            .filter(|line| line.contains(" WARN ") && line.contains(&marker))
            .collect()
    }

    /// L-72 KEY TEST, over real iroh on loopback: 50 dials from a peer NOT on
    /// the allowlist and 50 dials naming an unknown ALPN, under a `tracing`
    /// capture. This node logs at most one own line for the whole
    /// not-allowlisted class per window; iroh's router logs no
    /// "ended with error" line for them at all (the arm returns `Ok`); and
    /// under the default filter NOTHING from `iroh::protocol` reaches the log
    /// — the bad-ALPN handshakes included, which die before any handler runs.
    ///
    /// Before T77 the 100 dials wrote ~150 WARN lines (~75 KB): our own
    /// unthrottled line plus iroh's per `Err` for every not-allowlisted dial,
    /// and iroh's per failed handshake for every bad ALPN.
    ///
    /// Bug-catch: (a) restore the unthrottled `warn!` + `Err` — 50 own lines
    /// and 50 iroh "ended with error" lines in `raw`; (b) default the filter
    /// back to `info` — the bad-ALPN lines reach `filtered`.
    #[tokio::test]
    async fn l72_refused_dials_on_a_public_bind_cost_at_most_one_line() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let (guard, raw, filtered) = capture_logs();
        let pair = serve_pair(short_timeouts(), AntiEntropyLimits::default()).await;
        let stranger = bind_direct_endpoint().await;
        wait_until_dialable(&stranger).await;

        let started = std::time::Instant::now();
        let mut connected = 0usize;
        for _ in 0..50 {
            let dial = tokio::time::timeout(
                Duration::from_secs(5),
                stranger.connect(pair.addr.clone(), p2p::protocol::ANTI_ENTROPY_ALPN),
            )
            .await;
            if let Ok(Ok(connection)) = dial {
                connected += 1;
                let reason =
                    tokio::time::timeout(Duration::from_secs(3), connection.closed()).await;
                if let Ok(reason) = reason {
                    assert!(
                        format!("{reason}").contains("not-allowlisted"),
                        "refused as not allowlisted: {reason}"
                    );
                }
            }
        }
        let mut refused_alpn = 0usize;
        for _ in 0..50 {
            let dial = tokio::time::timeout(
                Duration::from_secs(5),
                stranger.connect(pair.addr.clone(), b"t77/not-a-protocol/0"),
            )
            .await;
            if !matches!(dial, Ok(Ok(_))) {
                refused_alpn += 1;
            }
        }
        let elapsed = started.elapsed();
        // Let the server's accept tasks finish logging.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = pair.router.shutdown().await;
        drop(guard);

        let raw = raw.text();
        let filtered = filtered.text();
        eprintln!(
            "l72: {connected}/50 not-allowlisted handshakes, {refused_alpn}/50 bad-ALPN \
             refusals in {elapsed:?}; raw WARN bytes {}, filtered bytes {}",
            raw.len(),
            filtered.len()
        );
        // Loopback QUIC can lose a handshake to a slow machine (or LuLu);
        // the bound below is about the ones that complete.
        assert!(
            connected >= 25,
            "loopback QUIC must complete most handshakes: {connected}/50"
        );
        assert_eq!(refused_alpn, 50, "an unknown ALPN never connects");
        let windows =
            1 + (elapsed.as_secs() / crate::connection_limiter::REFUSAL_LOG_INTERVAL.as_secs());
        let own = raw
            .lines()
            .filter(|line| {
                line.contains("rejecting anti-entropy connection not on bootstrap allowlist")
            })
            .count();
        assert!(
            own as u64 <= windows,
            "{own} own refusal lines for 50 dials in {elapsed:?}:\n{raw}"
        );
        let iroh_err = raw
            .lines()
            .filter(|line| {
                line.contains("iroh::protocol")
                    && line.contains("Handling incoming connection ended with error")
            })
            .count();
        assert_eq!(iroh_err, 0, "the refusal arm must return Ok:\n{raw}");
        let iroh_filtered = warn_lines(&filtered, "iroh::protocol");
        assert!(
            iroh_filtered.is_empty(),
            "the default filter must silence iroh's per-handshake warns:\n{}",
            iroh_filtered.join("\n")
        );
    }

    /// The source-side history for the L-70 shape: the two opens a
    /// transaction needs, a short transaction B, and a long transaction O
    /// whose parents name B — authored by `author`, served as entries.
    struct OrphanFixture {
        opens: Vec<p2p::protocol::SupplyEntry>,
        parent: p2p::protocol::SupplyEntry,
        child: p2p::protocol::SupplyEntry,
        opens_bytes: Vec<u64>,
        parent_bytes: u64,
        child_bytes: u64,
    }

    fn narrated(narration_len: usize, day: u32) -> TransactionInput {
        TransactionInput {
            date: NaiveDate::from_ymd_opt(2024, 1, day).expect("valid date"),
            flag: Flag::Complete,
            payee: None,
            narration: Some("n".repeat(narration_len)),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-5),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Expenses:Food".to_owned(),
                    amount: Some(Amount {
                        number: dec!(5),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        }
    }

    fn orphan_fixture(dir: &std::path::Path, author: &str) -> OrphanFixture {
        let mut source =
            LedgerService::boot(dir.join("t77-source.bean"), author.to_owned()).expect("boot");
        let day = NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date");
        let opens: Vec<String> = ["Assets:Cash", "Expenses:Food"]
            .iter()
            .map(|account| {
                source
                    .open_account_staged(
                        (*account).to_owned(),
                        day,
                        vec!["USD".to_owned()],
                        |_, _, _| None,
                    )
                    .expect("open")
            })
            .collect();
        let parent = source
            .append_transaction_staged(narrated(200, 2), |_, _, _| None)
            .expect("parent")
            .txid;
        let child = source
            .append_transaction_staged(narrated(700, 3), |_, _, _| None)
            .expect("child")
            .txid;
        source.compact().expect("source commit");
        let names = |id: &str| {
            source
                .get_directive(id)
                .expect("present")
                .metadata()
                .get("openledger-parents")
                .cloned()
        };
        assert!(
            names(&child).is_some_and(|parents| parents.contains(&parent)),
            "the child names the parent"
        );
        let bytes = |id: &str| RecordEstimate::directive_bytes(source.get_directive(id).unwrap());
        OrphanFixture {
            opens: opens.iter().map(|id| entry_for(&source, id)).collect(),
            opens_bytes: opens.iter().map(|id| bytes(id)).collect(),
            parent_bytes: bytes(&parent),
            child_bytes: bytes(&child),
            parent: entry_for(&source, &parent),
            child: entry_for(&source, &child),
        }
    }

    /// L-70 KEY TEST — `x3probe orphan`, through the real ALPN apply path.
    /// Near the cap, a peer's child transaction O arrives first and is
    /// buffered; then its parent B, which fits by itself. B frees O, and B + O
    /// together do NOT fit. Now: B is staged and committed, O is deferred (not
    /// staged), the peer is backed off, and there is no reload — B is still
    /// there, durable, and the headroom dropped by exactly B's record.
    ///
    /// Before T77 the drain staged O after the pre-stage check, the prepare's
    /// projection refused B + O, the L-13 reload rolled BOTH back, and no
    /// backoff was armed — so the peer re-served them next tick, forever.
    ///
    /// Bug-catch: drop the drain's budget check — the prepare is refused, the
    /// reload removes B, and `deferred` is 0.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn l70_drained_orphans_that_do_not_fit_are_deferred_without_a_reload() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let fixture = orphan_fixture(temp_dir.path(), &author.to_string());

        let mut opens_record = RecordEstimate::new();
        for bytes in &fixture.opens_bytes {
            opens_record.add(*bytes);
        }
        let parent_alone = RecordEstimate::new()
            .with(fixture.parent_bytes)
            .record_bytes();
        let both = RecordEstimate::new()
            .with(fixture.parent_bytes)
            .with(fixture.child_bytes)
            .record_bytes();
        // B fits, and so does O (it must be buffered first, and a batch is
        // checked before anything in it is known to be an orphan); B + O
        // does not.
        let child_alone = RecordEstimate::new()
            .with(fixture.child_bytes)
            .record_bytes();
        let headroom = opens_record.record_bytes()
            + parent_alone.max(child_alone)
            + fixture.parent_bytes.min(fixture.child_bytes) / 2;
        assert!(
            headroom - opens_record.record_bytes() < both,
            "fixture: B + O must not fit"
        );
        let ledger = crate::ledger_commit::near_cap::near_cap_ledger(
            &temp_dir.path().join("t77-orphan.bean"),
            headroom,
        );
        let handler = make_handler(Arc::clone(&ledger), allow);
        let remote = iroh::SecretKey::generate().public();

        let opened = apply_supply_entries(&handler, fixture.opens.clone(), remote).await;
        assert_eq!(opened.merged, 2, "{opened:?}");
        let buffered = apply_supply_entries(&handler, vec![fixture.child.clone()], remote).await;
        assert_eq!(buffered.buffered, 1, "O waits on B: {buffered:?}");
        let before = ledger.read().await.append_headroom();
        assert_eq!(before, headroom - opens_record.record_bytes());

        let outcome = apply_supply_entries(&handler, vec![fixture.parent.clone()], remote).await;
        assert_eq!(outcome.merged, 1, "B is staged: {outcome:?}");
        assert_eq!(outcome.deferred, 1, "O is deferred: {outcome:?}");
        assert!(
            handler
                .supply_backoff
                .is_active(remote, std::time::Instant::now()),
            "a drain that ran out of room backs the peer off"
        );
        let service = ledger.read().await;
        assert!(
            service.contains_directive(&fixture.parent.id),
            "no reload: B is still there"
        );
        assert!(
            !service.contains_directive(&fixture.child.id),
            "O was not staged"
        );
        assert_eq!(service.uncommitted_count(), 0, "B is durable");
        assert_eq!(
            service.append_headroom(),
            before - parent_alone,
            "the journal grew by exactly B's record — the estimate is the record"
        );
    }

    /// T77 (Info) KEY TEST: 40 KB below the cap, a 256-entry batch whose
    /// journal record is ~38 KB is admitted. The pre-T77 estimate added a
    /// 128-byte framing allowance and the 64-byte id per entry — ~85 KB for
    /// this batch — so the batch was deferred, the peer backed off, and the
    /// same thing happened every backoff window, forever.
    ///
    /// Bug-catch: check the headroom against the sum of
    /// `estimated_entry_bytes` again and the batch is deferred.
    #[tokio::test]
    async fn t77_a_fitting_batch_in_the_last_40kb_is_admitted() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let entries = remote_open_entries(temp_dir.path(), &author.to_string(), 256);
        let headroom = 40 * 1024;
        let mut record = RecordEstimate::new();
        for entry in &entries {
            record.add(RecordEstimate::directive_bytes(
                &validate_supply_entry(entry).expect("valid"),
            ));
        }
        let wire_estimate: u64 = entries
            .iter()
            .map(|entry| p2p::anti_entropy::estimated_entry_bytes(entry) as u64)
            .sum();
        assert!(
            record.record_bytes() <= headroom && wire_estimate > headroom,
            "fixture: record {} and wire estimate {wire_estimate} around {headroom}",
            record.record_bytes()
        );

        let ledger = crate::ledger_commit::near_cap::near_cap_ledger(
            &temp_dir.path().join("t77-40k.bean"),
            headroom,
        );
        let handler = make_handler(Arc::clone(&ledger), allow);
        let remote = iroh::SecretKey::generate().public();
        let outcome = apply_supply_entries(&handler, entries, remote).await;
        assert_eq!((outcome.merged, outcome.deferred), (256, 0), "{outcome:?}");
        assert!(!handler
            .supply_backoff
            .is_active(remote, std::time::Instant::now()));
        let service = ledger.read().await;
        assert_eq!(service.uncommitted_count(), 0);
        assert_eq!(
            service.append_headroom(),
            headroom - record.record_bytes(),
            "the record written is exactly the estimate"
        );
    }

    /// L-70: GraphQL subscribers hear about a supplied transaction only once
    /// it is durable. A batch whose commit fails (the ledger's directory is
    /// read-only, so the compaction cannot create its temp file) announces
    /// nothing; the same batch once the directory is writable again is
    /// announced.
    ///
    /// Bug-catch: publish at stage time again and the subscriber receives the
    /// transaction the failed commit rolled back.
    #[cfg(unix)]
    #[tokio::test]
    async fn l70_subscribers_hear_nothing_from_a_batch_whose_commit_failed() {
        use std::os::unix::fs::PermissionsExt;
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let source_dir = tempfile::tempdir().expect("temp dir");
        let fixture = orphan_fixture(source_dir.path(), &author.to_string());
        let mut batch = fixture.opens.clone();
        batch.push(fixture.parent.clone());

        let sink_dir = tempfile::tempdir().expect("temp dir");
        let path = sink_dir.path().join("sink.bean");
        std::fs::write(&path, "").expect("seed file");
        let ledger: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(&path, "sink".to_owned()).expect("boot sink"),
        ));
        let handler = make_handler(Arc::clone(&ledger), allow);
        let mut subscriber = handler.broadcast.subscribe();
        let remote = iroh::SecretKey::generate().public();

        let writable = std::fs::metadata(sink_dir.path()).unwrap().permissions();
        std::fs::set_permissions(sink_dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(sink_dir.path().join("probe"), "").is_ok() {
            std::fs::set_permissions(sink_dir.path(), writable).unwrap();
            eprintln!("skipped: a read-only directory is writable here (root?)");
            return;
        }
        let failed = apply_supply_entries(&handler, batch.clone(), remote).await;
        std::fs::set_permissions(sink_dir.path(), writable).unwrap();
        assert_eq!(failed.merged, 3, "the batch was staged: {failed:?}");
        assert!(
            !ledger.read().await.contains_directive(&fixture.parent.id),
            "the failed commit was rolled back"
        );
        assert!(
            matches!(
                subscriber.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "a subscriber must not hear about a transaction that never became durable"
        );

        let landed = apply_supply_entries(&handler, batch, remote).await;
        assert_eq!(landed.merged, 3, "{landed:?}");
        let announced = subscriber
            .try_recv()
            .expect("the durable transaction is announced");
        assert_eq!(announced.txid.0, fixture.parent.id);
        assert!(subscriber.try_recv().is_err(), "announced once");
    }

    /// A per-thread counting allocator for the phase-1 residency test (T77).
    ///
    /// Counts only on a thread that has armed it, so the rest of this test
    /// binary — hundreds of tests on other threads — is neither measured nor
    /// measurably slowed (one thread-local read per allocation). A `const`
    /// thread-local of `Cell`s has no destructor and allocates nothing, so it
    /// is safe to touch from inside the allocator.
    mod thread_counting {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        thread_local! {
            static ARMED: Cell<bool> = const { Cell::new(false) };
            static LIVE: Cell<isize> = const { Cell::new(0) };
            static PEAK: Cell<isize> = const { Cell::new(0) };
        }

        pub(crate) struct ThreadCounting;

        fn note(delta: isize) {
            let _ = ARMED.try_with(|armed| {
                if armed.get() {
                    let live = LIVE.get() + delta;
                    LIVE.set(live);
                    if live > PEAK.get() {
                        PEAK.set(live);
                    }
                }
            });
        }

        // SAFETY: forwards every call unchanged to `System`; the bookkeeping
        // touches only allocation-free thread-locals.
        unsafe impl GlobalAlloc for ThreadCounting {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                // SAFETY: the caller's layout, forwarded unchanged.
                let pointer = unsafe { System.alloc(layout) };
                if !pointer.is_null() {
                    note(layout.size() as isize);
                }
                pointer
            }

            unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
                note(-(layout.size() as isize));
                // SAFETY: pointer and layout come from a matching `alloc`.
                unsafe { System.dealloc(pointer, layout) }
            }
        }

        /// Run `call` on this thread with the counter armed, and return the
        /// peak live bytes above the level at entry (frees of memory that
        /// existed before count against it, as in `decode_memory.rs`).
        pub(crate) fn peak_during<T>(call: impl FnOnce() -> T) -> (T, usize) {
            LIVE.set(0);
            PEAK.set(0);
            ARMED.set(true);
            let value = call();
            ARMED.set(false);
            (value, usize::try_from(PEAK.get()).unwrap_or(0))
        }
    }

    #[global_allocator]
    static THREAD_COUNTING: thread_counting::ThreadCounting = thread_counting::ThreadCounting;

    /// The densest body inside every §3.12 cap (T75's `in-cap max` shape):
    /// 100 tags, 100 links, 100 directive metadata keys, 1,000 postings of
    /// which 100 carry a metadata key — ~19 KB of text, ~278 KB parsed. The
    /// postings do not balance, so staging refuses it (I1) and nothing it
    /// holds outlives phase 2.
    fn densest_in_cap_entry(index: usize, author: &str) -> p2p::protocol::SupplyEntry {
        let mut body = format!("2024-01-02 * \"{index:03}\"");
        for tag in 0..100 {
            body.push_str(&format!(" #t{tag}"));
        }
        for link in 0..100 {
            body.push_str(&format!(" ^l{link}"));
        }
        body.push('\n');
        for key in 0..100 {
            body.push_str(&format!("  m{key}: \"\"\n"));
        }
        for posting in 0..ledger::service::MAX_POSTINGS_PER_TRANSACTION {
            body.push_str("  Assets:A 1 AB\n");
            if posting < 100 {
                body.push_str(&format!("    p{posting}: \"\"\n"));
            }
        }
        let parsed = ledger::parse::parse_file(&body).expect("the shape parses");
        let mut envelope = std::collections::BTreeMap::new();
        envelope.insert("openledger-author".to_owned(), author.to_owned());
        envelope.insert("openledger-lamport".to_owned(), "2".to_owned());
        envelope.insert("openledger-parents".to_owned(), String::new());
        p2p::protocol::SupplyEntry {
            id: ledger::hash::compute_content_id(&parsed[0]),
            kind: p2p::protocol::DirectiveKind::from_directive(&parsed[0]),
            economic_bean: body,
            envelope,
        }
    }

    /// T77 (the T75 residual) KEY TEST: phase 1 of a `Supply` of the densest
    /// in-cap bodies — 256 of them, a ~5 MB frame that held ~71 MB (12.7× the
    /// frame, T75) before anything was staged — now holds at most
    /// `PHASE_ONE_WEIGHT_BUDGET` of parsed directives (plus one entry's
    /// transient), measured with a counting allocator on the applying thread.
    /// Every entry is still validated and refused at stage, exactly as before.
    ///
    /// Bug-catch: drop the weight check in phase 1 (one chunk per frame) and
    /// the peak is the whole frame's parsed weight, ~70 MB.
    #[test]
    fn t77_phase_one_holds_at_most_its_weight_budget_of_the_densest_frame() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger: SharedLedger = Arc::new(RwLock::new({
            let mut service =
                LedgerService::boot(temp_dir.path().join("t77-dense.bean"), "sink".to_owned())
                    .expect("boot");
            service
                .open_account(
                    "Assets:A".to_owned(),
                    NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                    vec!["AB".to_owned()],
                )
                .expect("open");
            service
        }));
        let handler = make_handler(Arc::clone(&ledger), allow);
        let remote = iroh::SecretKey::generate().public();
        let entries: Vec<_> = (0..MAX_SUPPLY_ENTRIES)
            .map(|index| densest_in_cap_entry(index, &author.to_string()))
            .collect();
        let frame = WireMessage::supply(entries.clone())
            .to_cbor()
            .expect("encode")
            .len();
        assert!(frame <= MAX_MESSAGE_SIZE as usize);
        let weight: usize = entries
            .iter()
            .map(|entry| p2p::anti_entropy::resident_weight(&validate_supply_entry(entry).unwrap()))
            .sum();

        let (outcome, peak) = thread_counting::peak_during(|| {
            runtime.block_on(apply_supply_entries(&handler, entries, remote))
        });
        let bound = PHASE_ONE_WEIGHT_BUDGET + 4 * 1024 * 1024;
        eprintln!(
            "t77 phase 1: frame {frame} B, parsed weight {weight} B ({:.1}× frame); peak {peak} B \
             ({:.2}× frame), bound {bound} B; {outcome:?}",
            weight as f64 / frame as f64,
            peak as f64 / frame as f64,
        );
        assert_eq!(
            outcome.rejected, MAX_SUPPLY_ENTRIES,
            "every dense entry is validated and refused at stage: {outcome:?}"
        );
        assert!(
            weight > 2 * bound,
            "fixture: the frame must outweigh the bound by far ({weight} vs {bound})"
        );
        assert!(
            peak <= bound,
            "phase 1 held {peak} B for a {frame} B frame, past {bound} B"
        );
    }

    /// T77: the pushed path charges phase 1's held weight to the connection
    /// limiter's byte budget and gives it back — nothing stays charged, and
    /// the budget's high-water mark saw the weight on top of the frame.
    /// L-90 (0924 A4-2), closed by T83: two connections from the same peer
    /// hold its whole 32 MiB byte budget, and a third applies a 256-entry
    /// frame. Before T83 every directive then failed its weight charge, and a
    /// failed charge flushed the chunk, so the frame took one commit (journal
    /// record and fsync) per directive — 256 against 4 for the same frame with
    /// the budget free. T83 flushed on the weight budget only, so the frame
    /// took no more commits than the control — and held its whole weight
    /// uncharged (M-62). Since T88 (decision (26)) at most
    /// `UNCHARGED_RESIDUE_CAP` is held uncharged, so the frame is staged per
    /// ~1 MiB of weight: several directives a commit (64 here), never one
    /// each. Both ledgers are 44 MiB-canonical so every commit is an append
    /// and journal records count commits exactly.
    #[test]
    fn l90_an_exhausted_byte_budget_does_not_split_a_frame_into_one_commit_per_directive() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let remote = iroh::SecretKey::generate().public();
        let entries: Vec<_> = (0..MAX_SUPPLY_ENTRIES)
            .map(|index| {
                let mut body = format!("2024-01-01 * \"honest {index:03}\"\n");
                for _ in 0..999 {
                    body.push_str("  Assets:A 1 USD\n");
                }
                body.push_str("  Equity:O -999 USD\n");
                let parsed = ledger::parse::parse_file(&body).expect("parses");
                p2p::protocol::SupplyEntry {
                    id: ledger::hash::compute_content_id(&parsed[0]),
                    kind: p2p::protocol::DirectiveKind::Transaction,
                    economic_bean: body,
                    envelope: std::collections::BTreeMap::from([
                        ("openledger-author".to_owned(), author.to_string()),
                        (
                            "openledger-lamport".to_owned(),
                            (index as u64 + 1).to_string(),
                        ),
                        ("openledger-parents".to_owned(), String::new()),
                    ]),
                }
            })
            .collect();
        let entries_weight_max = entries
            .iter()
            .map(|entry| p2p::anti_entropy::resident_weight(&validate_supply_entry(entry).unwrap()))
            .max()
            .unwrap_or(0);
        let records = |path: &std::path::Path| -> usize {
            std::fs::read_to_string(ledger::journal::journal_path_for(path))
                .map(|text| {
                    text.lines()
                        .filter(|line| line.starts_with(";;olj "))
                        .count()
                })
                .unwrap_or(0)
        };
        let make = |name: &str| -> (SharedLedger, std::path::PathBuf) {
            let bean = temp_dir.path().join(name);
            let ledger = crate::ledger_commit::near_cap::near_cap_ledger(&bean, 20 * 1024 * 1024);
            runtime.block_on(async {
                let mut service = ledger.write().await;
                let day = NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date");
                service
                    .open_account("Assets:A".to_owned(), day, vec![])
                    .expect("open");
                service
                    .open_account("Equity:O".to_owned(), day, vec![])
                    .expect("open");
            });
            (ledger, bean)
        };

        // Control: the same frame with the budget free.
        let (ledger, bean) = make("a4-onechunk-control.bean");
        let handler = make_handler(Arc::clone(&ledger), allow.clone());
        let mut free = handler.limiter.frame_reservation(remote);
        assert!(free.grow_to(4 * 1024 * 1024), "the frame body");
        let before = records(&bean);
        let control_started = std::time::Instant::now();
        let outcome = runtime.block_on(apply_supply_entries_from(
            &handler,
            entries.clone(),
            remote,
            SupplyOrigin::Pushed,
            &mut free,
        ));
        let control_took = control_started.elapsed();
        let control_records = records(&bean) - before;
        drop(free);
        assert_eq!(outcome.merged, MAX_SUPPLY_ENTRIES, "{outcome:?}");

        // Attack: two other connections from the SAME peer hold 16 MiB each
        // (the per-peer budget is 32 MiB), then this frame is applied.
        let (ledger, bean) = make("a4-onechunk-attack.bean");
        let handler = make_handler(Arc::clone(&ledger), allow);
        let mut other_a = handler.limiter.frame_reservation(remote);
        let mut other_b = handler.limiter.frame_reservation(remote);
        assert!(other_a.grow_to(MAX_MESSAGE_SIZE as usize));
        assert!(other_b.grow_to(MAX_MESSAGE_SIZE as usize));
        let mut reservation = handler.limiter.frame_reservation(remote);
        let ok = reservation.grow_to(4 * 1024 * 1024);
        let before = records(&bean);
        PHASE_ONE_MAX_UNCHARGED.with(|max| max.set(0));
        let started = std::time::Instant::now();
        let outcome = runtime.block_on(apply_supply_entries_from(
            &handler,
            entries,
            remote,
            SupplyOrigin::Pushed,
            &mut reservation,
        ));
        let took = started.elapsed();
        let attack_records = records(&bean) - before;
        let max_uncharged = PHASE_ONE_MAX_UNCHARGED.with(std::cell::Cell::get);
        eprintln!(
            "l90: body grow_to ok={ok}; control frame → {control_records} journal records in {control_took:?}; \
             budget-exhausted frame → {attack_records} journal records in {took:?}; max uncharged \
             {max_uncharged} B; {outcome:?}"
        );
        assert_eq!(outcome.merged, MAX_SUPPLY_ENTRIES, "{outcome:?}");
        // T88 / M-62, decision (26): the exhausted budget now bounds what is
        // held uncharged (`UNCHARGED_RESIDUE_CAP`), so the frame is staged
        // per ~1 MiB of weight — several directives a commit, never one each
        // (L-90's property) — where T83 held it all uncharged and committed it
        // as the control does.
        assert!(
            attack_records * 4 <= MAX_SUPPLY_ENTRIES,
            "an exhausted budget must not split the frame one directive per commit: \
             {attack_records} commits for {MAX_SUPPLY_ENTRIES} directives (control {control_records})"
        );
        let largest = entries_weight_max;
        assert!(
            max_uncharged <= UNCHARGED_RESIDUE_CAP + largest,
            "M-62: {max_uncharged} B held uncharged, over the {UNCHARGED_RESIDUE_CAP} B cap plus \
             one directive ({largest} B)"
        );
    }

    #[test]
    fn t77_phase_one_weight_is_charged_to_the_inbound_budget() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let entries = remote_open_entries(temp_dir.path(), &author.to_string(), 64);
        let weight: usize = entries
            .iter()
            .map(|entry| p2p::anti_entropy::resident_weight(&validate_supply_entry(entry).unwrap()))
            .sum();
        let ledger: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("t77-charge.bean"), "sink".to_owned())
                .expect("boot"),
        ));
        let handler = make_handler(ledger, allow);
        let remote = iroh::SecretKey::generate().public();
        let mut reservation = handler.limiter.frame_reservation(remote);
        assert!(reservation.grow_to(1000), "the frame body's charge");
        let outcome = runtime.block_on(apply_supply_entries_from(
            &handler,
            entries,
            remote,
            SupplyOrigin::Pushed,
            &mut reservation,
        ));
        assert_eq!(outcome.merged, 64, "{outcome:?}");
        assert_eq!(reservation.held(), 1000, "the weight is given back");
        assert_eq!(handler.limiter.frame_bytes_peak(), 1000 + weight);
        drop(reservation);
        assert_eq!(handler.limiter.frame_bytes_in_flight(), 0);
    }
}
