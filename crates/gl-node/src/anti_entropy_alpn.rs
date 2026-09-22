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

use crate::connection_limiter::{AntiEntropyLimits, ConnectionLimiter};
use crate::graphql::broadcast::TransactionBroadcast;
use crate::graphql::query::domain_txn_to_graphql;
use crate::graphql::SharedLedger;
use crate::peer_connections::{AcquireError, PeerConnectionCache, Reuse};

use ledger::validate::ValidationError;
use p2p::allowlist::PeerAllowlist;
use p2p::gossip::make_supply_entry;
use p2p::orphan_buffer::{OrphanBuffer, OrphanInsert};
use p2p::protocol::{
    is_content_id, WireMessage, CONTENT_ID_LEN, MAX_HAVE_HEADS, MAX_MESSAGE_SIZE,
    MAX_SUPPLY_ENTRIES,
};
use p2p::union_merge::{validate_supply_entry, verify_author_allowlisted, verify_remote_signature};

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

/// Chunk size for the incremental body read (L-19).
///
/// The body is appended chunk by chunk so a stalled stream pins only the bytes
/// actually received, never `vec![0u8; len]` reserved up front.
const READ_CHUNK: usize = 64 * 1024;

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
        let remaining = self
            .deadline
            .saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("anti-entropy session deadline reached".to_owned());
        }
        if self.frames_left == 0 {
            return Err("anti-entropy session frame budget exhausted".to_owned());
        }
        self.frames_left -= 1;
        Ok(self.io.min(remaining))
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
            warn!(peer = %remote, "rejecting anti-entropy connection not on bootstrap allowlist");
            connection.close(1u32.into(), b"not-allowlisted");
            return Err(AcceptError::from_err(std::io::Error::other(
                "anti-entropy peer not allowlisted",
            )));
        }
        // M-16: bound concurrent inbound connections, globally and per peer.
        // The guard is held for the whole serve duration; its `Drop` releases
        // the global permit and decrements the per-peer count. Rejecting closes
        // the connection with a distinct code, matching the not-allowlisted
        // branch's shape (warn, close, return `Err`).
        let Some(_connection_guard) = self.limiter.try_acquire(remote) else {
            warn!(peer = %remote, "rejecting anti-entropy connection: inbound connection limit reached");
            connection.close(2u32.into(), b"connection-limit");
            return Err(AcceptError::from_err(std::io::Error::other(
                "anti-entropy inbound connection limit reached",
            )));
        };
        if let Err(error) = serve_anti_entropy(self, connection, remote).await {
            warn!(peer = %remote, %error, "anti-entropy inbound session failed");
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
    let io_timeout = handler.timeouts.io;
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
    let (close_code, close_reason): (u32, &[u8]) = loop {
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
        let (mut send, mut recv) = match tokio::time::timeout(io_timeout, connection.accept_bi())
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
        let mut budget_exhausted = false;
        loop {
            if requests_handled >= handler.limits.max_requests_per_connection {
                warn!(
                    peer = %remote,
                    limit = handler.limits.max_requests_per_connection,
                    "anti-entropy request budget exhausted; closing connection"
                );
                budget_exhausted = true;
                break;
            }
            let message = match read_message(&mut recv, io_timeout).await {
                Ok(message) => message,
                // T41: a typed clean shutdown, not a substring match on a
                // formatted error — see `FrameError` and `classify_read_error`.
                // Since T42 this ends the STREAM, not the connection: the peer
                // may open another one for its next operation.
                Err(FrameError::Eof) => break,
                Err(error) => return Err(error.to_string()),
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
                        write_message(&mut send, &page, io_timeout).await?;
                    }
                }
                WireMessage::Want { ids, .. } => {
                    // One Supply per Want, trimmed to what the requester can
                    // decode (H-02); it re-Wants any tail we could not fit.
                    // Already 1:1, so the L-01 charge below is the same unit the
                    // read already took.
                    let entries = collect_supply(&handler.ledger, &ids).await;
                    let reply = p2p::anti_entropy::truncate_supply(entries);
                    requests_handled = requests_handled.saturating_add(1);
                    write_message(&mut send, &reply, io_timeout).await?;
                }
                WireMessage::Supply { entries, .. } => {
                    apply_supply_entries(handler, entries, remote).await;
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
        if budget_exhausted {
            break (4u32, b"request-budget-exhausted".as_slice());
        }
    };
    // Give the peer a BOUNDED window to acknowledge what we already wrote, then
    // close explicitly with a code and a reason (T41). The drain is deliberately
    // its own short budget rather than `io_timeout`: a peer that stops reading
    // must not be able to hold the serve task — and the M-16 limiter slot with
    // it — for a full I/O timeout on the way out, which is the very thing the
    // `accept_bi` timeout above exists to prevent.
    if let Some(send) = last_send {
        let _ = tokio::time::timeout(CLOSE_DRAIN, send.stopped()).await;
    }
    connection.close(close_code.into(), close_reason);
    Ok(())
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
            warn!(peer = %peer, %error, "anti-entropy connect failed");
            return;
        }
        Err(SessionOpenError::DialTimeout) => {
            warn!(peer = %peer, "anti-entropy connect timed out");
            return;
        }
        Err(SessionOpenError::OpenStream(error)) => {
            warn!(peer = %peer, %error, "anti-entropy want session failed");
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
        warn!(peer = %peer, %error, "anti-entropy want session failed");
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
            warn!(peer = %peer, %error, "anti-entropy head exchange failed");
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
        warn!(peer = %peer, %error, "anti-entropy head exchange failed");
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
    let want = {
        let svc = handler.ledger.read().await;
        p2p::anti_entropy::compute_want(
            &svc.head_txids(),
            &svc.all_directive_ids(),
            &head_txids,
            &directive_ids,
        )
    };
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
        } = read_message(recv, io_timeout)
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
        // M-28: the round loop below makes progress by construction, but only
        // one id per round in the worst case — 256 rounds per chunk, 4,096
        // chunks for an advert at the accumulation cap. Charging every frame
        // puts the whole of that under one budget and one deadline.
        let io_timeout = budget.charge_frame()?;
        write_message(send, &WireMessage::want(remaining.clone()), io_timeout).await?;
        let io_timeout = budget.charge_frame()?;
        let entries = match read_message(recv, io_timeout)
            .await
            .map_err(|error| error.to_string())?
        {
            WireMessage::Supply { entries, .. } => entries,
            other => {
                warn!(peer = %remote, ?other, "expected Supply after Want");
                return Ok(());
            }
        };
        let served: HashSet<&str> = entries.iter().map(|entry| entry.id.as_str()).collect();
        let next: Vec<String> = remaining
            .iter()
            .filter(|id| !served.contains(id.as_str()))
            .cloned()
            .collect();
        let stalled = next.len() == remaining.len();
        apply_supply_entries(handler, entries, remote).await;
        if stalled {
            // The peer served none of what we asked for: it does not have them,
            // or the reply was empty. Another round would ask the same thing.
            return Ok(());
        }
        remaining = next;
    }
    Ok(())
}

async fn local_have_heads_pages(ledger: &SharedLedger) -> Vec<WireMessage> {
    let svc = ledger.read().await;
    p2p::anti_entropy::paginate_have_heads(&svc.head_txids(), &svc.all_directive_ids())
}

async fn collect_supply(ledger: &SharedLedger, ids: &[String]) -> Vec<p2p::protocol::SupplyEntry> {
    let svc = ledger.read().await;
    // L-21: a Want may list the same id more than once (every missing head is
    // also a directive id upstream, so `compute_want` used to want it twice).
    // Serve each distinct id at most once — preserving first-occurrence order —
    // so the requester does not re-validate the same body per copy. Composes
    // with `truncate_supply` (T18), which trims the deduped batch to the frame.
    let mut seen: HashSet<&str> = HashSet::new();
    ids.iter()
        .filter(|id| seen.insert(id.as_str()))
        .filter_map(|id| svc.get_directive(id).map(make_supply_entry))
        .collect()
}

/// Tally of what `apply_supply_entries` did with one `Supply` batch (M-14).
///
/// Every entry lands in exactly one bucket, so the fields partition the batch.
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
}

/// Apply one `Supply` batch: validate off the lock, then stage + persist once.
///
/// M-15: the previous shape took the ledger write lock and ran a full-file
/// `full_file_serialize` + `sync_all` fsync once PER entry (and again per
/// resolved orphan). Catch-up of M directives on an N-directive ledger was then
/// O(M×N) serializations + fsyncs, all under the write lock — the gossip loop
/// blocked on `ledger.read()`, its channel filled, and GraphQL mutations
/// blocked. This is now two phases: phase 1 does all the expensive parse/verify
/// work with NO write lock; phase 2 takes the write lock exactly once, stages
/// the whole batch in memory, drains any orphans it unblocks, and persists a
/// single time for the batch + drained orphans.
async fn apply_supply_entries(
    handler: &AntiEntropyHandler,
    entries: Vec<p2p::protocol::SupplyEntry>,
    remote: EndpointId,
) -> SupplyOutcome {
    let from_peer = remote.to_string();
    let mut outcome = SupplyOutcome::default();

    // ── Phase 1: validate off the ledger write lock (M-15) ──────────────
    //
    // Parsing, re-serializing, hashing, and Ed25519-verifying every entry is
    // the expensive work, and none of it needs the write lock. Staging it here
    // means the whole batch takes the write lock exactly once, in phase 2.
    let mut staged: Vec<ledger::model::Directive> = Vec::new();
    for entry in entries {
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
        match validate_supply_entry(&entry) {
            Ok(directive) => {
                if let Err(error) = verify_author_allowlisted(&directive, &handler.allowlist) {
                    warn!(%error, peer = %remote, "rejected ALPN supply: author not allowlisted");
                    outcome.rejected += 1;
                    continue;
                }
                if let Err(error) =
                    verify_remote_signature(&directive, handler.signing_enabled, &handler.mesh_id)
                {
                    warn!(%error, peer = %remote, "rejected ALPN supply: signature");
                    outcome.rejected += 1;
                    continue;
                }
                // Preserve arrival order so an open/parent earlier in the batch is
                // visible to a later child's checks in phase 2.
                staged.push(directive);
            }
            Err(error) => {
                warn!(%error, "invalid ALPN supply entry");
                outcome.rejected += 1;
            }
        }
    }

    // ── Phase 2: one ledger write lock for the whole batch (M-15) ───────
    //
    // Lock-ordering discipline is unchanged inside the write lock: the
    // orphan_buffer lock is only ever acquired under it (here and inside
    // `drain_orphans`). T44 adds one lock ABOVE it — the single-writer commit
    // permit — taken before the write lock on every write path and released
    // only once the batch is durable.
    if !staged.is_empty() {
        let permit = crate::ledger_commit::acquire_write_permit(&handler.ledger).await;
        let mut svc = handler.ledger.write().await;
        let mut inserted_any = false;
        for directive in staged {
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
                    if let ledger::model::Directive::Transaction(ref txn) = directive {
                        let graphql_txn = domain_txn_to_graphql(txn, &svc);
                        handler.broadcast.publish(graphql_txn);
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
                        None => {
                            warn!(%error, "rejected remote directive from ALPN");
                            outcome.rejected += 1;
                        }
                    }
                }
            }
        }

        if inserted_any {
            // Drain orphans this batch unblocked, then persist ONCE for the whole
            // batch plus the drained orphans (M-15). `drain_orphans` stages
            // (no persist), so this single commit covers everything.
            drain_orphans(
                &handler.orphan_buffer,
                &mut svc,
                &handler.broadcast,
                handler.signing_enabled,
                &handler.allowlist,
                &handler.mesh_id,
            )
            .await;
            // T44: prepare under the lock, commit off it. For a catch-up batch
            // on a ledger past the compaction threshold this is a single
            // journal record for the whole batch — O(batch), not O(ledger) —
            // and the fsync runs on a blocking thread with the write lock
            // already released, so a peer streaming history no longer parks
            // GraphQL readers on the disk.
            let prepared = crate::ledger_commit::prepare_or_recover(&mut svc, false);
            drop(svc);
            let commit = match prepared {
                // H-11: the permit is handed to the commit, so a dropped
                // exchange future cannot release the single-writer slot while
                // the batch is still being written.
                Ok(pending) => {
                    crate::ledger_commit::commit_pending(&handler.ledger, pending, permit).await
                }
                Err(error) => Err(error),
            };
            if let Err(error) = commit {
                // L-13: the failure path already reloaded from disk, so the
                // batch is rolled back in memory (memory==disk again) and
                // anti-entropy will re-pull it. The tallies above describe what
                // was attempted, not what is stored; we return them without
                // panicking.
                warn!(%error, peer = %remote, "failed to persist ALPN supply batch; rolled back in memory, will re-pull");
            }
        } else {
            drop(svc);
        }
    }

    debug!(
        peer = %remote,
        skipped_present = outcome.skipped_present,
        merged = outcome.merged,
        buffered = outcome.buffered,
        duplicate = outcome.duplicate,
        rejected = outcome.rejected,
        "applied ALPN supply batch"
    );
    outcome
}

/// The re-validation context a freed orphan is put back through.
///
/// Bundled so [`restage_freed_entry`] stays inside clippy's argument budget.
struct DrainContext<'a> {
    broadcast: &'a TransactionBroadcast,
    signing_enabled: bool,
    allowlist: &'a PeerAllowlist,
    mesh_id: &'a str,
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
fn account_wait_target(error: &ledger::service::ServiceError) -> Option<String> {
    let ledger::service::ServiceError::Validation(validation) = error else {
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
    /// Merged into the DAG.
    Staged,
    /// Still blocked; back in the buffer waiting on this account (M-09).
    Rebuffered { account: String },
    /// Not in the buffer and not in the DAG.
    Dropped,
}

/// Re-validate one freed orphan and stage it.
///
/// A freed entry that is still blocked on an account lifecycle query goes back
/// into the buffer under its NEW blocking account (M-09) rather than being
/// dropped — a transaction can post to several accounts, and validation reports
/// only the first one that fails, so one release can uncover the next.
fn restage_freed_entry(
    buffer: &mut OrphanBuffer,
    service: &mut ledger::service::LedgerService,
    context: &DrainContext<'_>,
    entry: p2p::orphan_buffer::OrphanEntry,
    dag_ids: &mut HashSet<String>,
) -> Restaged {
    if let Err(error) = verify_author_allowlisted(&entry.directive, context.allowlist) {
        warn!(%error, "rejected resolved orphan: author");
        return Restaged::Dropped;
    }
    if let Err(error) =
        verify_remote_signature(&entry.directive, context.signing_enabled, context.mesh_id)
    {
        warn!(%error, "rejected resolved orphan: signature");
        return Restaged::Dropped;
    }
    match service.stage_remote_directive(entry.directive.clone()) {
        Ok(Some(content_id)) => {
            info!(content_id = %content_id, "resolved orphan directive");
            dag_ids.insert(content_id);
            if let ledger::model::Directive::Transaction(ref txn) = entry.directive {
                let graphql_txn = domain_txn_to_graphql(txn, service);
                context.broadcast.publish(graphql_txn);
            }
            Restaged::Staged
        }
        Ok(None) => Restaged::Dropped,
        Err(error) => {
            let Some(account) = account_wait_target(&error) else {
                warn!(%error, "rejected resolved orphan directive");
                return Restaged::Dropped;
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

/// Drain orphans whose parents have arrived, or whose account is now open
/// (M-09). Re-checks signature and author.
///
/// M-15: this STAGES each resolved orphan into memory only (no persist per
/// orphan). The caller persists once, after the drain, covering the whole batch
/// plus every orphan resolved here. The incremental `dag_ids` set is cloned once
/// per drain call (which is now once per batch, not once per entry).
///
/// The loop terminates. Another pass runs only on real progress, which is
/// either (a) a directive staged — monotone in a DAG this call grows only by
/// staging — or (b) a buffered entry moving to a blocking account it has not
/// been tried against yet in this call, which `attempted` counts at most once
/// per (entry, account) pair.
pub async fn drain_orphans(
    orphan_buffer: &Arc<RwLock<OrphanBuffer>>,
    service: &mut ledger::service::LedgerService,
    broadcast: &TransactionBroadcast,
    signing_enabled: bool,
    allowlist: &PeerAllowlist,
    mesh_id: &str,
) {
    let context = DrainContext {
        broadcast,
        signing_enabled,
        allowlist,
        mesh_id,
    };
    let mut dag_ids = service.all_directive_ids();
    let mut buffer = orphan_buffer.write().await;
    let mut attempted: HashSet<(String, String)> = HashSet::new();
    let mut resolved_any = true;
    while resolved_any {
        resolved_any = false;

        for parent_id in buffer.wanted_parent_ids() {
            if !dag_ids.contains(&parent_id) {
                continue;
            }
            for entry in buffer.parent_arrived(&parent_id) {
                let entry_id = entry.id.clone();
                let outcome =
                    restage_freed_entry(&mut buffer, service, &context, entry, &mut dag_ids);
                resolved_any |= made_progress(outcome, entry_id, &mut attempted);
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
                let outcome =
                    restage_freed_entry(&mut buffer, service, &context, entry, &mut dag_ids);
                resolved_any |= made_progress(outcome, entry_id, &mut attempted);
            }
        }
    }
}

/// Whether a restage attempt justifies another drain pass. See [`drain_orphans`].
fn made_progress(
    outcome: Restaged,
    entry_id: String,
    attempted: &mut HashSet<(String, String)>,
) -> bool {
    match outcome {
        Restaged::Staged => true,
        // A new (entry, blocking account) pair means the release uncovered a
        // different unmet dependency — worth one more pass. A pair already seen
        // means the entry is going in circles, and does not.
        Restaged::Rebuffered { account } => attempted.insert((entry_id, account)),
        Restaged::Dropped => false,
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

async fn read_message(
    recv: &mut RecvStream,
    io_timeout: Duration,
) -> Result<WireMessage, FrameError> {
    read_frame(recv, io_timeout).await
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
async fn read_frame<R>(recv: &mut R, io_timeout: Duration) -> Result<WireMessage, FrameError>
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
    while body.len() < len {
        let want = (len - body.len()).min(READ_CHUNK);
        let mut chunk = vec![0u8; want];
        match tokio::time::timeout(io_timeout, recv.read_exact_bytes(&mut chunk)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(truncated_mid_frame(error)),
            Err(_elapsed) => return Err(FrameError::Timeout),
        }
        body.extend_from_slice(&chunk);
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
        let error = read_frame(&mut reader, Duration::from_secs(1))
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
        let decoded = read_frame(&mut reader, Duration::from_secs(5))
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
            let decoded = read_frame(&mut reader, Duration::from_secs(2))
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

        let entries = collect_supply(&ledger, &[id.clone(), id.clone(), id.clone()]).await;
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
            read_message(&mut recv, Duration::from_secs(2)).await.ok()
        }
        .await;
        Some(exchanged.is_none())
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
            while let Ok(message) = read_message(&mut recv, Duration::from_secs(2)).await {
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
                read_message(&mut recv, Duration::from_secs(5)).await,
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
            match read_message(&mut recv, Duration::from_secs(5)).await {
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
                match read_message(&mut recv, Duration::from_secs(2)).await {
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
}
