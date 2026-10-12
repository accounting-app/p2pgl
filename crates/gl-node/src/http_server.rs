//! Hardened HTTP serve loop for the GraphQL surface (M-13).
//!
//! `axum::serve` spawns one task per accepted connection and configures the
//! hyper connection with nothing: no timer (so hyper's *default* 30s
//! `header_read_timeout` degrades to a warning and a no-op), no request
//! timeout, no HTTP/2 keep-alive probes and no ceiling on concurrent
//! connections. Three cheap, pre-auth, pre-rate-limit attacks follow from that,
//! because all of them are spent before a single byte reaches the router:
//!
//! * **Slowloris** — dribble a request head one byte at a time and the
//!   connection task lives forever.
//! * **Slow body** — send a complete head plus `Content-Length`, then stall;
//!   `async-graphql` reads the body *inside* the handler, so the handler task
//!   parks indefinitely.
//! * **Idle keep-alive hoarding** — complete one cheap request, then hold the
//!   connection open and never send another head.
//!
//! Each holds a live task and a file descriptor, so a few thousand sockets
//! exhaust the process regardless of how well the router above is hardened.
//!
//! This module replaces `axum::serve` with the documented manual-hyper pattern
//! and adds the missing bounds: a header-read timeout (which hyper re-arms
//! before every request head, so it also bounds idle keep-alive), a whole-request
//! timeout, a semaphore-backed connection ceiling, and a per-IP share of that
//! ceiling (M-33).
//!
//! It also speaks **HTTP/1.1 only** (M-22). hyper-util's `auto` builder sniffs
//! the `PRI * HTTP/2.0` preface and would otherwise serve cleartext HTTP/2
//! (h2c) on this port — a whole second protocol implementation reachable
//! pre-auth, below the router where the API key, Host guard and limiter live,
//! and the cleanest request-cancel primitive there is (`RST_STREAM`, T50). No
//! client of this node needs it: the terminator speaks HTTP/1.1 upstream, and
//! loopback clients are curl, GraphiQL and the health probe.
//!
//! **These are the backend's own backstops, not the primary control.** Public
//! binds are required to sit behind a TLS-terminating reverse proxy (§ TLS
//! `terminated` mode), and that proxy must enforce equivalent header, body,
//! request and connection limits of its own. Nothing here relieves it of that:
//! the limits below exist so a node is not defenceless when the proxy is
//! misconfigured, bypassed, or absent on a loopback bind.

use axum::http::StatusCode;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::Service;
use tower_http::timeout::TimeoutLayer;
use tracing::{debug, info, warn};

/// How long a client may take to deliver a complete request head.
const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Wall-clock ceiling on a single request, body read and GraphQL execution included.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Concurrent connections this process will hold open.
const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Concurrent connections one client address may hold (M-33).
///
/// A sixteenth of the default global cap, so one address can never be the
/// reason nobody else is served. It is not tight for anything legitimate that
/// reaches the node directly: a browser opens six per host, the health probe
/// one, and a client pool beyond 64 concurrent requests would be refused by
/// the 60-per-minute rate limit long before it needed the sockets. A reverse
/// proxy fans *everyone* in through one address, which is why the configured
/// trusted proxies are exempt (see [`serve_hardened`]).
///
/// **What "one address" means bounds what this cap bounds (L-61).** The key is
/// [`crate::rate_limit::bucket_key`]: an IPv4 address, or an IPv6 **/64** —
/// the rate limiter's M-04b rule, so rotating inside one allocation buys
/// nothing. But IPv6 is routed in larger blocks than that: one routed /48 is
/// 65,536 distinct /64 keys, each with its own 64 slots, far past the global
/// [`DEFAULT_MAX_CONNECTIONS`] of 1,024. So this cap stops a single IPv4
/// address or a single /64 from taking every slot, and nothing wider; an
/// attacker holding a /48 meets only the global cap, exactly as before M-33.
/// Bounding per-prefix fan-in beyond a /64 is the upstream proxy's or the
/// host firewall's job (e.g. an nftables meter keyed on the /48).
///
/// Refused connections get no admission cooldown: the refusal already reads
/// nothing and spawns nothing, and what a reconnect loop costs is the kernel's
/// accept-and-close, which a user-space cooldown cannot avoid (L-61 residual,
/// see `docs/audits/OUTSTANDING_TASKS_09_22_v2.md` T71).
const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 64;

/// Minimum gap between "per-IP cap reached" warnings, so a client hammering
/// the cap costs one log line per interval rather than one per connection.
const PER_IP_REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Largest HTTP/1 request head hyper will buffer before answering 431 (M-41).
///
/// hyper's default is 417,792 bytes (`hyper-1.11.0 proto/h1/io.rs:23`,
/// `8192 + 4096 × 100`), and `serve_hardened` never lowered it — so a single
/// `Host`, `Origin` or `Content-Type` header could carry ~400 KB, all of which
/// the request guard then echoed into one `warn!` line (the measured 100–190
/// MB/s of log from one client). The node's own requests are a JSON body
/// behind a handful of short headers; the largest honest head is a `Cookie`-
/// less browser request under 2 KiB. 64 KiB matches what nginx (`8k × 4`
/// `large_client_header_buffers`) and Apache (`LimitRequestFieldSize 8190`
/// per field) admit, and is 8× hyper's floor of 8,192 (`MINIMUM_MAX_BUFFER_SIZE`,
/// below which `max_buf_size` panics). The same value caps hyper's write
/// buffer coalescing: responses larger than this are written as separate
/// buffers rather than copied, which is not a limit on response size.
///
/// It is a ceiling on the order of magnitude, not an exact byte: hyper reads
/// into the whole spare capacity of its `BytesMut` (`poll_read_from_io`), and
/// `reserve` doubles, so a head that arrives in one burst can land up to
/// ~1.75× this value (114,688 bytes here) before the `len >= max` check runs
/// — measured: a 100 KiB `Host` parses, a 200 KiB one is 431'd. What bounds
/// the LOG LINE is therefore the guard's 128-character excerpt
/// (`request_guard::MAX_ECHOED_HEADER_CHARS`); this bounds what the guard can
/// ever be handed, and what an idle connection can make hyper hold.
pub(crate) const HTTP1_MAX_BUF_SIZE: usize = 64 * 1024;

/// How long graceful shutdown waits for in-flight connections to drain.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause after a failed `accept()` so a persistent error (`EMFILE`) cannot spin the loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Connection-level limits applied by [`serve_hardened`] (M-13).
///
/// Populated from the optional `http` config section; see
/// `NodeConfig::http_server_settings`. [`Default`] is the single source of the
/// shipped values, so an absent config section and this struct cannot disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpServerSettings {
    /// Time a client gets to send a complete request head. Re-armed per head,
    /// so it doubles as the idle keep-alive bound.
    pub header_read_timeout: Duration,
    /// Time a single request gets end to end, including body read and execution.
    pub request_timeout: Duration,
    /// Ceiling on concurrently served connections.
    pub max_connections: usize,
    /// Ceiling on concurrently served connections from one client address
    /// (M-33). Effective value is `min(this, max_connections)`.
    pub max_connections_per_ip: usize,
}

impl Default for HttpServerSettings {
    fn default() -> Self {
        Self {
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
        }
    }
}

/// Live connection count per client address (M-33) — the HTTP analogue of
/// the ALPN side's per-peer cap in `connection_limiter`.
///
/// Keyed on [`crate::rate_limit::bucket_key`], so "one client" means the same
/// thing here as it does to the rate limiter: an IPv4 address (v4-mapped
/// spellings folded in, M-30) or an IPv6 /64. Rotating addresses inside one
/// allocation does not buy extra slots — but a routed /48 is 65,536 such keys,
/// so this bounds one address or one /64, not one network (L-61; see
/// [`DEFAULT_MAX_CONNECTIONS_PER_IP`]).
struct PerIpConnections {
    counts: Mutex<HashMap<IpAddr, usize>>,
    max_per_ip: usize,
    /// Canonical addresses never counted: the configured trusted proxies.
    exempt: HashSet<IpAddr>,
    /// When the last refusal was logged at `warn`.
    last_refusal_log: Mutex<Option<Instant>>,
}

/// One admitted connection's share of its address's budget. Dropping it gives
/// the share back; an exempt peer's slot counts nothing and releases nothing.
struct PerIpSlot {
    table: Arc<PerIpConnections>,
    key: Option<IpAddr>,
}

impl PerIpConnections {
    fn new(max_per_ip: usize, exempt: HashSet<IpAddr>) -> Arc<Self> {
        Arc::new(Self {
            counts: Mutex::new(HashMap::new()),
            max_per_ip: max_per_ip.max(1),
            exempt: exempt
                .into_iter()
                .map(crate::rate_limit::canonical_ip)
                .collect(),
            last_refusal_log: Mutex::new(None),
        })
    }

    /// Admit one connection from `peer`, or `None` when its address already
    /// holds `max_per_ip`. A refusal changes nothing.
    fn try_admit(self: &Arc<Self>, peer: IpAddr) -> Option<PerIpSlot> {
        if self.exempt.contains(&crate::rate_limit::canonical_ip(peer)) {
            return Some(PerIpSlot {
                table: Arc::clone(self),
                key: None,
            });
        }
        let key = crate::rate_limit::bucket_key(peer);
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = counts.get(&key).copied().unwrap_or(0);
        if current >= self.max_per_ip {
            return None;
        }
        counts.insert(key, current + 1);
        Some(PerIpSlot {
            table: Arc::clone(self),
            key: Some(key),
        })
    }

    /// Whether a refusal right now should be logged at `warn` (rate-limited).
    fn should_log_refusal(&self, now: Instant) -> bool {
        let mut last = self
            .last_refusal_log
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *last {
            Some(previous) if now.duration_since(previous) < PER_IP_REFUSAL_LOG_INTERVAL => false,
            _ => {
                *last = Some(now);
                true
            }
        }
    }
}

impl Drop for PerIpSlot {
    fn drop(&mut self) {
        let Some(key) = self.key else {
            return;
        };
        let mut counts = self
            .table
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = counts.get_mut(&key) {
            *count -= 1;
            if *count == 0 {
                // Entries at 0 are removed, so the map is bounded by the
                // number of live connections, never by addresses ever seen.
                counts.remove(&key);
            }
        }
    }
}

/// Serve `application` on `listener` until `shutdown` resolves (M-13).
///
/// Drop-in replacement for
/// `axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
/// .with_graceful_shutdown(shutdown)`, with the connection-level limits that
/// call never had. `ConnectInfo<SocketAddr>` is still inserted per connection,
/// so the per-IP rate limiter keeps seeing real peer addresses.
///
/// `per_ip_exempt` lists addresses the per-IP cap does not apply to (M-33) —
/// in production, the configured trusted proxies, which carry every client
/// behind them through one address. They remain bound by the global cap.
pub async fn serve_hardened<S>(
    listener: TcpListener,
    application: Router,
    settings: HttpServerSettings,
    per_ip_exempt: HashSet<IpAddr>,
    shutdown: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    // Bound the whole request, not just the head. async-graphql reads the body
    // inside the handler, so this is what covers a stalled body — and it is
    // also the first wall-clock bound GraphQL execution has ever had.
    // `TimeoutLayer::new` is deprecated in tower-http 0.6.7+; the explicit
    // constructor yields the same 408 Request Timeout.
    let application = application.layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        settings.request_timeout,
    ));
    let mut make_service = application.into_make_service_with_connect_info::<SocketAddr>();

    // A zero cap would silently accept nothing; treat it as "one at a time".
    let max_connections = settings.max_connections.max(1);
    let connection_slots = Arc::new(Semaphore::new(max_connections));
    let max_connections_per_ip = settings.max_connections_per_ip.clamp(1, max_connections);
    let per_ip = PerIpConnections::new(max_connections_per_ip, per_ip_exempt);
    let graceful = GracefulShutdown::new();

    // M-22: HTTP/1.1 only, and — the part that actually does it — served with
    // `serve_connection`, NOT `serve_connection_with_upgrades`.
    //
    // ⚠ `http1_only()` ALONE IS A SILENT NO-OP. hyper-util documents it as
    // "does not do anything if used with `serve_connection_with_upgrades`",
    // and the vendored source agrees: `serve_connection` matches on the
    // configured version, while `serve_connection_with_upgrades` goes
    // unconditionally to `ReadVersion`, sniffs the h2 preface and serves h2c.
    // The two changes only work together; the `h2_prior_knowledge_preface_is_
    // refused` test fails if either is reverted.
    //
    // ⚠ WHOEVER ADDS A WEBSOCKET (GraphQL subscription) ENDPOINT: dropping the
    // `_with_upgrades` variant dropped HTTP upgrade support, which is safe
    // today only because nothing upgrades — the routes are `/graphql` and
    // `/health`, and `SubscriptionRoot` is not exposed. Restoring
    // `serve_connection_with_upgrades` for WebSockets RE-ENABLES CLEARTEXT
    // HTTP/2 on this port regardless of `http1_only()`; if you need upgrades,
    // keep the sniffing builder and refuse the h2 preface explicitly instead,
    // and keep that test passing.
    let mut builder = auto::Builder::new(TokioExecutor::new()).http1_only();
    // The timer is not optional: without one hyper logs
    // "timeout `header_read_timeout` has default, but no timer set" and drops
    // the timeout entirely, which is exactly how `axum::serve` ships. hyper
    // re-arms this timer in `poll_read_head` for every head it is about to
    // read (`proto/h1/conn.rs`: the running flag is cleared once a head parses),
    // so it bounds the gap between keep-alive requests as well as the first one.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(settings.header_read_timeout)
        .max_buf_size(HTTP1_MAX_BUF_SIZE);
    // No `.http2()` configuration: with HTTP/2 unreachable (M-22) its
    // keep-alive probes would be dead settings that read as live protection.

    info!(
        header_read_timeout_ms = settings.header_read_timeout.as_millis(),
        request_timeout_ms = settings.request_timeout.as_millis(),
        max_connections,
        max_connections_per_ip,
        per_ip_exempt = per_ip.exempt.len(),
        "serving HTTP/1.1 with connection limits (M-13, M-22, M-33)"
    );

    let mut shutdown = pin!(shutdown);

    loop {
        let (stream, remote_address, permit) = tokio::select! {
            accepted = accept_with_permit(&listener, &connection_slots) => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(%error, "accept failed — continuing to serve");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            },
            () = shutdown.as_mut() => {
                info!("shutdown signalled — no longer accepting connections");
                break;
            }
        };

        // M-33: the per-IP share, checked *after* accept because it has to be
        // — the peer address does not exist until then. The global permit
        // above was still taken first, so a flood still waits in the kernel
        // backlog rather than becoming process state; what this adds is that
        // one address cannot be the reason nobody else gets a permit. An
        // over-cap connection is closed on the spot: nothing is read from it,
        // no task is spawned, and dropping `permit` hands its global slot
        // straight back to the accept loop.
        let Some(ip_slot) = per_ip.try_admit(remote_address.ip()) else {
            if per_ip.should_log_refusal(Instant::now()) {
                warn!(
                    peer = %remote_address,
                    max_connections_per_ip,
                    "refusing connection: this client already holds its per-IP share of \
                     connections (M-33); further refusals are logged at most every 10s"
                );
            } else {
                debug!(peer = %remote_address, "refusing connection: per-IP cap reached (M-33)");
            }
            drop(stream);
            drop(permit);
            continue;
        };

        // `IntoMakeServiceWithConnectInfo` is what inserts the
        // `ConnectInfo<SocketAddr>` extension the rate limiter reads. Its
        // `poll_ready` is unconditionally ready and its error is `Infallible`,
        // so there is nothing to await or handle before calling it.
        let connection_service = Service::<SocketAddr>::call(&mut make_service, remote_address)
            .await
            .expect("connect-info make service is infallible");

        // `serve_connection`, never `_with_upgrades` — see the M-22 note above.
        let connection = builder
            .serve_connection(
                TokioIo::new(stream),
                TowerToHyperService::new(connection_service),
            )
            .into_owned();
        let watched = graceful.watch(connection);

        tokio::spawn(async move {
            if let Err(error) = watched.await {
                debug!(%error, peer = %remote_address, "connection closed with error");
            }
            // Frees the per-IP share and then the global slot.
            drop(ip_slot);
            drop(permit);
        });
    }

    // Stop holding the port before draining so a restart can rebind promptly.
    drop(listener);

    if tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown())
        .await
        .is_err()
    {
        warn!(
            drain_timeout_secs = DRAIN_TIMEOUT.as_secs(),
            "graceful drain timed out — dropping remaining connections"
        );
    } else {
        info!("all connections drained");
    }

    Ok(())
}

/// Take a connection slot *before* accepting (M-13).
///
/// Permit-then-accept is the ordering that matters: a burst past the cap stays
/// in the kernel's listen backlog (or is refused by the kernel) instead of
/// becoming process state, so the node never holds more than `max_connections`
/// sockets and tasks. Accepting first and then waiting for a permit would let
/// the flood in and merely delay serving it.
///
/// Cancelling this future (the shutdown branch of the select) drops the permit,
/// which is correct: nothing was accepted.
async fn accept_with_permit(
    listener: &TcpListener,
    connection_slots: &Arc<Semaphore>,
) -> std::io::Result<(TcpStream, SocketAddr, OwnedSemaphorePermit)> {
    let permit = Arc::clone(connection_slots)
        .acquire_owned()
        .await
        .map_err(std::io::Error::other)?;
    let (stream, remote_address) = listener.accept().await?;
    Ok((stream, remote_address, permit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthState;
    use crate::config::NodeConfig;
    use crate::graphql::broadcast::TransactionBroadcast;
    use crate::graphql::{build_schema_with_service, SharedLedger};
    use crate::health::HealthState;
    use crate::request_guard::RequestGuardState;
    use axum::extract::ConnectInfo;
    use axum::routing::{get, post};
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use tokio::sync::RwLock;
    use tower_http::cors::CorsLayer;

    /// The crate-wide network-test lock (T41): these bind real listeners and
    /// assert on wall-clock deadlines measured in hundreds of milliseconds, so
    /// they must exclude the QUIC convergence tests too, not just each other.
    use crate::test_support::NET_TEST_LOCK;

    /// Since M-22 the header-read timer starts at *accept*, not at the first
    /// byte (see `silent_connection_is_closed_by_header_read_timeout`), so it
    /// also bounds the gap between a test client's `connect` and its first
    /// `write`. On a heavily loaded machine that gap alone has exceeded 300ms,
    /// so the shared value is 1s: still far below the 30s production default,
    /// and every "is it bounded at all" assertion keeps its 4x margin.
    const HEADER_TIMEOUT: Duration = Duration::from_millis(1000);
    const REQUEST_TIMEOUT: Duration = Duration::from_millis(500);

    /// Deadlines are asserted at 4x the configured timeout: the point is that
    /// the bound exists at all, not that it fires to the millisecond.
    fn tolerant(timeout: Duration) -> Duration {
        timeout * 4
    }

    fn short_settings() -> HttpServerSettings {
        HttpServerSettings {
            header_read_timeout: HEADER_TIMEOUT,
            request_timeout: REQUEST_TIMEOUT,
            max_connections: 8,
            max_connections_per_ip: 8,
        }
    }

    /// For tests that assert a request is *served*, not that a timeout fires:
    /// the head timer runs from accept (M-22), and on a saturated machine a
    /// test client's `connect().await` has been observed resuming 2.7s after
    /// the server accepted — so these give the head a budget no scheduler
    /// stall reaches.
    fn serving_settings() -> HttpServerSettings {
        HttpServerSettings {
            header_read_timeout: Duration::from_secs(10),
            ..short_settings()
        }
    }

    /// Minimal router: enough surface for each limit without dragging the
    /// GraphQL stack into timing-sensitive tests.
    fn test_router() -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route(
                "/peer",
                get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
            )
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    "slow-ok"
                }),
            )
            // Consumes the body, the way async-graphql's extractor does.
            .route(
                "/graphql",
                post(|body: axum::body::Bytes| async move { format!("read {} bytes", body.len()) }),
            )
    }

    struct TestServer {
        address: SocketAddr,
        shutdown: Option<oneshot::Sender<()>>,
        handle: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    /// Absorb a host's per-process first-connection stall before any test
    /// measures anything.
    ///
    /// Some development hosts run a per-process network filter — observed: the
    /// LuLu network extension on the maintainer's Mac — that holds the FIRST
    /// connection a freshly linked test binary makes while it reaches a
    /// verdict. Measured at 1.5–27 s, once per process, keyed on the
    /// executable's path (the identical binary copied elsewhere is not held).
    ///
    /// Before M-22 that stall was invisible: the sniffing builder parked a new
    /// connection in `ReadVersion` with no timer, so the server simply waited.
    /// The head timer now starts at accept — correctly; that is the
    /// silent-socket fix — so a test whose first connection is held past its
    /// head timeout was closed as a silent socket and failed with an empty
    /// response, but only when it happened to be the first network test in the
    /// process (a single-test run). One throwaway loopback connection per
    /// process takes the stall instead. It asserts nothing and serves nothing,
    /// so it cannot mask a server defect; CI hosts without such a filter pay a
    /// sub-millisecond connect.
    async fn warm_up_loopback() {
        // Once a connect completes this fast, the host is no longer holding
        // this process's connections, and the tests' own head timeouts (1 s
        // and up) are safe. On a host with no filter the first iteration
        // passes and this costs one loopback connect.
        const PROMPT: Duration = Duration::from_millis(250);
        // A fresh relink has been observed to have several connections held
        // before the verdict is cached, not just the first, so keep going until
        // one is prompt — bounded, so a host that never relents still runs the
        // suite (and its tests then fail loudly rather than hang).
        const DEADLINE: Duration = Duration::from_secs(90);
        static WARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if WARMED.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind warm-up listener");
        let address = listener.local_addr().expect("warm-up listener address");
        let accepting = tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        let started = Instant::now();
        while started.elapsed() < DEADLINE {
            let attempt = Instant::now();
            let connected = TcpStream::connect(address).await.is_ok();
            if connected && attempt.elapsed() < PROMPT {
                break;
            }
        }
        accepting.abort();
        WARMED.store(true, std::sync::atomic::Ordering::Release);
    }

    async fn spawn_server(application: Router, settings: HttpServerSettings) -> TestServer {
        warm_up_loopback().await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        spawn_on(listener, application, settings, HashSet::new())
    }

    fn spawn_on(
        listener: TcpListener,
        application: Router,
        settings: HttpServerSettings,
        per_ip_exempt: HashSet<IpAddr>,
    ) -> TestServer {
        let address = listener.local_addr().expect("listener local address");
        let (shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();
        let handle = tokio::spawn(serve_hardened(
            listener,
            application,
            settings,
            per_ip_exempt,
            async move {
                let _ = shutdown_receiver.await;
            },
        ));
        TestServer {
            address,
            shutdown: Some(shutdown_sender),
            handle,
        }
    }

    /// Read until the peer closes (or errors). Callers wrap this in a timeout:
    /// returning at all is the assertion.
    async fn read_until_eof(stream: &mut TcpStream) -> Vec<u8> {
        let mut collected = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return collected,
                Ok(read) => collected.extend_from_slice(&chunk[..read]),
            }
        }
    }

    /// Read exactly one response (head plus `Content-Length` body), leaving the
    /// connection open for keep-alive assertions.
    async fn read_one_response(stream: &mut TcpStream) -> String {
        let mut collected = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            if let Some(position) = collected
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            {
                break position + 4;
            }
            let read = stream.read(&mut chunk).await.expect("read response head");
            assert!(read > 0, "connection closed before a response head arrived");
            collected.extend_from_slice(&chunk[..read]);
        };

        let head = String::from_utf8_lossy(&collected[..header_end]).to_ascii_lowercase();
        let content_length: usize = head
            .split("\r\n")
            .find_map(|line| line.strip_prefix("content-length:"))
            .map_or(0, |value| value.trim().parse().unwrap_or(0));

        while collected.len() < header_end + content_length {
            let read = stream.read(&mut chunk).await.expect("read response body");
            assert!(read > 0, "connection closed mid-body");
            collected.extend_from_slice(&chunk[..read]);
        }
        String::from_utf8_lossy(&collected).into_owned()
    }

    fn request_bytes(path: &str, address: SocketAddr, close: bool) -> Vec<u8> {
        let connection = if close { "close" } else { "keep-alive" };
        format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: {connection}\r\n\r\n")
            .into_bytes()
    }

    // — 1. Slowloris: a head that never finishes —

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_request_head_is_closed_by_header_read_timeout() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let server = spawn_server(test_router(), short_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        stream
            .write_all(b"POST /graphql HTTP/1.1\r\nHos")
            .await
            .expect("write partial head");

        let outcome =
            tokio::time::timeout(tolerant(HEADER_TIMEOUT), read_until_eof(&mut stream)).await;
        assert!(
            outcome.is_ok(),
            "server held a stalled request head open past 4x the header read timeout (M-13)"
        );
    }

    /// A connection that never sends a single byte is closed too (M-22 side
    /// effect, and an M-13/M-33 gap it closes).
    ///
    /// Pre-T55 the sniffing `serve_connection_with_upgrades` path parked every
    /// new connection in hyper-util's `ReadVersion` future — which has no timer
    /// — until enough bytes arrived to tell h1 from h2. The h1 header-read
    /// timeout only started after that, so a client that connected and sent
    /// nothing held its slot (and its task) forever: 1024 silent sockets, no
    /// refresh needed, and the node accepted nothing ever again. Served as
    /// HTTP/1.1 directly, the head timer is armed at accept.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn silent_connection_is_closed_by_header_read_timeout() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let server = spawn_server(test_router(), short_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        // Not one byte.
        let outcome =
            tokio::time::timeout(tolerant(HEADER_TIMEOUT), read_until_eof(&mut stream)).await;
        assert!(
            outcome.is_ok(),
            "server held a connection that never sent a byte past 4x the header read timeout — \
             silent sockets can hoard every slot (M-13/M-22)"
        );
    }

    // — 1b. M-41: a request head hyper will not buffer —

    /// T66 / M-41: a 200 KiB `Host` value never reaches the request guard —
    /// hyper refuses the head at `HTTP1_MAX_BUF_SIZE` with a 431 (or closes
    /// the connection), so there is nothing for the guard to echo. Before
    /// `max_buf_size` was set, hyper buffered up to 417,792 bytes and the
    /// guard logged the whole value, once per request, outside every limiter.
    /// 200 KiB, not 100: hyper's read over-shoots the cap by up to ~1.75× in a
    /// burst (see the constant's doc), and the value must also stay under the
    /// old default so that reverting the cap makes this test fail.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_oversized_request_head_is_refused_before_the_guard_sees_it() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let server = spawn_server(test_router(), short_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        let host = format!("evil.example.{}", "a".repeat(200 * 1024));
        assert!(host.len() > 2 * HTTP1_MAX_BUF_SIZE && host.len() < 417_792);
        let head = format!("GET /health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        // The server may close mid-write once it has seen enough; that is the
        // refusal, not a test failure.
        let _ = stream.write_all(head.as_bytes()).await;

        let outcome =
            tokio::time::timeout(tolerant(HEADER_TIMEOUT), read_until_eof(&mut stream)).await;
        let response = outcome.expect("server held an oversized head open past the header timeout");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.is_empty() || response.starts_with("HTTP/1.1 431"),
            "expected a 431 or a close, got: {}",
            &response[..response.len().min(200)]
        );
        assert!(
            !response.contains("403"),
            "the guard answered, so the head was buffered whole: {}",
            &response[..response.len().min(200)]
        );
    }

    // — 2. Slow body: complete head, then silence —

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_request_body_is_closed_by_request_timeout() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let server = spawn_server(test_router(), short_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        let head = format!(
            "POST /graphql HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n",
            server.address
        );
        stream
            .write_all(head.as_bytes())
            .await
            .expect("write complete head");
        // Not one byte of the promised 1000-byte body follows.

        let outcome =
            tokio::time::timeout(tolerant(REQUEST_TIMEOUT), read_until_eof(&mut stream)).await;
        let response = outcome
            .expect("server held a stalled request body open past 4x the request timeout (M-13)");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.is_empty() || response.starts_with("HTTP/1.1 408"),
            "expected a 408 or a close, got: {response}"
        );
    }

    // — 3. Idle keep-alive hoarding —

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_keep_alive_connection_is_closed_by_header_read_timeout() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let server = spawn_server(test_router(), short_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        stream
            .write_all(&request_bytes("/", server.address, false))
            .await
            .expect("write request");
        let response = read_one_response(&mut stream).await;
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        assert!(response.ends_with("ok"), "got: {response}");

        // Now hold the connection and send nothing: hyper re-arms the header
        // read timeout before the next head, so this must not survive.
        let outcome =
            tokio::time::timeout(tolerant(HEADER_TIMEOUT), read_until_eof(&mut stream)).await;
        assert!(
            outcome.is_ok(),
            "server held an idle keep-alive connection open past 4x the header read timeout (M-13)"
        );
    }

    // — 4. Connection ceiling —

    /// Determinism note: permit-then-accept means a connection over the cap is
    /// never accepted at all, so "no bytes while the cap is held" is a property
    /// of the kernel backlog rather than a race — the server cannot answer a
    /// socket it has not accepted. This test uses a deliberately long header
    /// timeout (600ms) so the probe window (~150ms to ~350ms after the two
    /// holders are accepted) sits far from the moment the holders time out and
    /// release their permits. Both halves are then asserted: silence while the
    /// cap is held, service once it frees, plus a control run with a cap of 64
    /// that is served immediately.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connection_cap_defers_accepting_until_a_slot_frees() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let capped_header_timeout = Duration::from_millis(600);
        let settings = HttpServerSettings {
            header_read_timeout: capped_header_timeout,
            request_timeout: REQUEST_TIMEOUT,
            max_connections: 2,
            max_connections_per_ip: 2,
        };
        let server = spawn_server(test_router(), settings).await;

        // Two slowloris connections consume both permits.
        let mut holders = Vec::new();
        for _ in 0..2 {
            let mut holder = TcpStream::connect(server.address).await.expect("connect");
            holder
                .write_all(b"GET / HTTP/1.1\r\nHos")
                .await
                .expect("write partial head");
            holders.push(holder);
        }
        // Let the accept loop take both, then block on the third permit.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut third = TcpStream::connect(server.address).await.expect("connect");
        third
            .write_all(&request_bytes("/", server.address, true))
            .await
            .expect("write request");

        // Well inside the holders' 600ms head timeout: nothing may come back.
        let mut probe = [0_u8; 64];
        let early = tokio::time::timeout(Duration::from_millis(200), third.read(&mut probe)).await;
        assert!(
            early.is_err(),
            "server answered a connection beyond max_connections while the cap was held (M-13)"
        );

        // Once the holders time out their permits free and the third is served.
        let served =
            tokio::time::timeout(tolerant(capped_header_timeout), read_until_eof(&mut third))
                .await
                .expect("third connection was never served after slots freed");
        assert!(
            String::from_utf8_lossy(&served).contains("200 OK"),
            "third connection got: {}",
            String::from_utf8_lossy(&served)
        );
        drop(holders);

        // Control: the same traffic against a roomy cap is served at once.
        let roomy = spawn_server(
            test_router(),
            HttpServerSettings {
                header_read_timeout: capped_header_timeout,
                request_timeout: REQUEST_TIMEOUT,
                max_connections: 64,
                max_connections_per_ip: 64,
            },
        )
        .await;
        let mut control_holders = Vec::new();
        for _ in 0..2 {
            let mut holder = TcpStream::connect(roomy.address).await.expect("connect");
            holder
                .write_all(b"GET / HTTP/1.1\r\nHos")
                .await
                .expect("write partial head");
            control_holders.push(holder);
        }
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut control = TcpStream::connect(roomy.address).await.expect("connect");
        control
            .write_all(&request_bytes("/", roomy.address, true))
            .await
            .expect("write request");
        let control_response =
            tokio::time::timeout(Duration::from_millis(200), read_until_eof(&mut control))
                .await
                .expect("uncapped server should answer immediately");
        assert!(
            String::from_utf8_lossy(&control_response).contains("200 OK"),
            "control connection got: {}",
            String::from_utf8_lossy(&control_response)
        );
        drop(control_holders);
    }

    // — 5. Well-behaved traffic is untouched —

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn normal_request_completes_promptly() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let server = spawn_server(test_router(), short_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        stream
            .write_all(&request_bytes("/", server.address, true))
            .await
            .expect("write request");

        let response =
            tokio::time::timeout(Duration::from_millis(500), read_until_eof(&mut stream))
                .await
                .expect("a valid request must not be delayed by the limits");
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        assert!(response.ends_with("ok"), "got: {response}");
    }

    // — 6. Graceful shutdown —

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_stops_accepting_and_drains_in_flight_requests() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let mut server = spawn_server(test_router(), short_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        stream
            .write_all(&request_bytes("/slow", server.address, true))
            .await
            .expect("write request");
        // The handler sleeps 150ms; signal shutdown while it is in flight.
        tokio::time::sleep(Duration::from_millis(50)).await;
        server
            .shutdown
            .take()
            .expect("shutdown sender")
            .send(())
            .expect("serve loop should still be listening");

        let response = tokio::time::timeout(Duration::from_secs(2), read_until_eof(&mut stream))
            .await
            .expect("in-flight request must survive graceful shutdown");
        assert!(
            String::from_utf8_lossy(&response).contains("slow-ok"),
            "got: {}",
            String::from_utf8_lossy(&response)
        );

        let outcome = tokio::time::timeout(Duration::from_secs(5), server.handle)
            .await
            .expect("accept loop must exit after the shutdown signal")
            .expect("serve task must not panic");
        assert!(outcome.is_ok(), "serve_hardened returned {outcome:?}");
    }

    // — ConnectInfo is still wired: the rate limiter keys on it (H-2) —

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_info_carries_the_real_peer_address() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let server = spawn_server(test_router(), short_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        let client_address = stream.local_addr().expect("client local address");
        stream
            .write_all(&request_bytes("/peer", server.address, true))
            .await
            .expect("write request");

        let response =
            tokio::time::timeout(Duration::from_millis(500), read_until_eof(&mut stream))
                .await
                .expect("request should complete");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.ends_with(&client_address.to_string()),
            "ConnectInfo did not carry the peer address {client_address}; got: {response}"
        );
    }

    /// The full assembled application over the hardened loop. If `ConnectInfo`
    /// went missing the limiter would silently fall back to a hard-coded
    /// loopback IP and every client would share one bucket, so the point here
    /// is that repeated real requests keep succeeding rather than degrading.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_application_serves_graphql_over_the_hardened_loop() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let (_ledger_directory, application) = build_real_application();
        let server = spawn_server(application, short_settings()).await;

        for attempt in 0..3 {
            let mut stream = TcpStream::connect(server.address).await.expect("connect");
            let body = r#"{"query":"{ __typename }"}"#;
            let request = format!(
                "POST /graphql HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                server.address,
                body.len(),
                body
            );
            stream
                .write_all(request.as_bytes())
                .await
                .expect("write request");

            let response =
                tokio::time::timeout(Duration::from_millis(2000), read_until_eof(&mut stream))
                    .await
                    .expect("GraphQL request should complete");
            let response = String::from_utf8_lossy(&response);
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "attempt {attempt} got: {response}"
            );
            assert!(
                response.contains("QueryRoot"),
                "attempt {attempt} got: {response}"
            );
        }
    }

    // — M-22: no cleartext HTTP/2 —

    /// The HTTP/2 client connection preface (RFC 9113 §3.4) followed by an
    /// empty SETTINGS frame — exactly what `curl --http2-prior-knowledge`
    /// opens with.
    const H2_PRIOR_KNOWLEDGE: &[u8] =
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

    /// M-22 bug-catch: the server must answer the h2 preface as HTTP/1.1 (a
    /// 505 or a close), never with an HTTP/2 SETTINGS frame. An h2 server's
    /// first bytes are a frame header whose fourth byte is type 0x04; an
    /// HTTP/1.1 server's are `HTTP/1.1`.
    ///
    /// This is the test that catches the silent no-op: with `http1_only()` set
    /// but `serve_connection_with_upgrades` restored, hyper-util still sniffs
    /// the preface and serves h2c, and the assertion below fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h2_prior_knowledge_preface_is_refused() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let server = spawn_server(test_router(), serving_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        stream
            .write_all(H2_PRIOR_KNOWLEDGE)
            .await
            .expect("write h2 preface");

        // One read is enough: an h2 server sends SETTINGS immediately and then
        // waits, so reading to EOF would hang on exactly the failure case.
        let mut first = vec![0_u8; 256];
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut first))
            .await
            .expect("the server must answer or close within 2s, not sit on an h2 preface")
            .unwrap_or(0);
        first.truncate(read);

        let is_h2_settings = first.len() >= 9 && first[3] == 0x04;
        assert!(
            !is_h2_settings,
            "the server answered the prior-knowledge preface with an HTTP/2 SETTINGS frame — \
             cleartext h2c is being served (M-22): {first:02x?}"
        );
        assert!(
            first.is_empty() || first.starts_with(b"HTTP/1.1 "),
            "expected an HTTP/1.1 refusal or a close, got: {:?}",
            String::from_utf8_lossy(&first)
        );
        assert!(
            !first.starts_with(b"HTTP/1.1 2"),
            "the preface must be refused, not served: {:?}",
            String::from_utf8_lossy(&first)
        );
    }

    /// HTTP/1.1 upgrade requests are simply served as HTTP/1.1 — with the
    /// upgrade machinery gone there is nothing to switch to (M-22).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h2c_upgrade_header_is_ignored() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let server = spawn_server(test_router(), serving_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade, HTTP2-Settings, close\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n",
            server.address
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write upgrade request");
        let response = tokio::time::timeout(Duration::from_secs(2), read_until_eof(&mut stream))
            .await
            .expect("request should complete");
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        assert!(!response.contains("101"), "no protocol switch: {response}");
    }

    // — M-33: per-IP connection cap —

    #[test]
    fn per_ip_table_admits_refuses_frees_and_prunes() {
        let table = PerIpConnections::new(2, HashSet::new());
        let peer: IpAddr = "203.0.113.7".parse().unwrap();
        let first = table.try_admit(peer).expect("1st admitted");
        let second = table.try_admit(peer).expect("2nd admitted");
        assert!(table.try_admit(peer).is_none(), "3rd refused");
        // Another address has its own share.
        let other = table
            .try_admit("198.51.100.1".parse().unwrap())
            .expect("a second client is unaffected");
        drop(first);
        let third = table.try_admit(peer).expect("a freed share is reusable");
        drop((second, third, other));
        assert!(
            table.counts.lock().unwrap().is_empty(),
            "entries at 0 must be removed, so the map never outgrows live connections"
        );
    }

    #[test]
    fn per_ip_table_keys_like_the_rate_limiter() {
        // v4-mapped and plain IPv4 are one client (M-30), and so are two
        // addresses in one IPv6 /64 (M-04b).
        let table = PerIpConnections::new(1, HashSet::new());
        let _held = table
            .try_admit("::ffff:203.0.113.7".parse().unwrap())
            .unwrap();
        assert!(table.try_admit("203.0.113.7".parse().unwrap()).is_none());

        let _v6 = table.try_admit("2001:db8:1:2::1".parse().unwrap()).unwrap();
        assert!(table
            .try_admit("2001:db8:1:2:ffff::9".parse().unwrap())
            .is_none());
        assert!(table
            .try_admit("2001:db8:1:3::1".parse().unwrap())
            .is_some());
    }

    #[test]
    fn per_ip_table_exempts_trusted_proxies_in_either_spelling() {
        let exempt: HashSet<IpAddr> = ["172.18.0.9".parse().unwrap()].into_iter().collect();
        let table = PerIpConnections::new(1, exempt);
        let mapped: IpAddr = "::ffff:172.18.0.9".parse().unwrap();
        let slots: Vec<_> = (0..10)
            .map(|_| {
                table
                    .try_admit(mapped)
                    .expect("a trusted proxy is not per-IP capped")
            })
            .collect();
        assert!(
            table.counts.lock().unwrap().is_empty(),
            "exempt peers are not counted"
        );
        drop(slots);
    }

    /// Two loopback source addresses the test can connect *from*, and a
    /// listener that accepts both. Prefers a dual-stack `[::]` listener
    /// (`127.0.0.1` arrives v4-mapped, `::1` as itself — which also exercises
    /// the M-30 folding); falls back to `127.0.0.2` where IPv6 is disabled
    /// (Linux routes all of 127/8 to loopback). `None` if neither works.
    async fn two_source_listener() -> Option<(TcpListener, SocketAddr, SocketAddr)> {
        if let Ok(listener) = TcpListener::bind("[::]:0").await {
            let port = listener.local_addr().ok()?.port();
            let v6: SocketAddr = format!("[::1]:{port}").parse().ok()?;
            if TcpStream::connect(v6).await.is_ok() {
                return Some((listener, format!("127.0.0.1:{port}").parse().ok()?, v6));
            }
        }
        let listener = TcpListener::bind("0.0.0.0:0").await.ok()?;
        let port = listener.local_addr().ok()?.port();
        let probe = tokio::net::TcpSocket::new_v4().ok()?;
        probe.bind("127.0.0.2:0".parse().ok()?).ok()?;
        probe
            .connect(format!("127.0.0.1:{port}").parse().ok()?)
            .await
            .ok()?;
        Some((
            listener,
            format!("127.0.0.1:{port}").parse().ok()?,
            format!("127.0.0.2:{port}").parse().ok()?,
        ))
    }

    /// Connect to `target`, from 127.0.0.2 when that is the second source.
    async fn connect_from(target: SocketAddr, second_source: bool) -> TcpStream {
        if second_source && target.is_ipv4() {
            let socket = tokio::net::TcpSocket::new_v4().expect("socket");
            socket
                .bind("127.0.0.2:0".parse().unwrap())
                .expect("bind 127.0.0.2");
            let port = target.port();
            socket
                .connect(format!("127.0.0.1:{port}").parse().unwrap())
                .await
                .expect("connect from 127.0.0.2")
        } else {
            TcpStream::connect(target).await.expect("connect")
        }
    }

    /// M-33 bug-catch: one address opening more connections than its share
    /// cannot take the slots another address needs. Global cap 4, per-IP 2;
    /// the attacker opens 4 slowloris connections. Pre-T55 all 4 were accepted
    /// and held until the header timeout (8s here), so the second client got
    /// nothing inside the 4s probe window. Now the attacker's 3rd and 4th are
    /// closed on the spot and the second client is served at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_ip_cannot_take_every_slot() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let Some((listener, attacker_target, victim_target)) = two_source_listener().await else {
            eprintln!(
                "SKIPPED: no second loopback source address (IPv6 and 127.0.0.2 both unavailable)"
            );
            return;
        };
        let second_source_is_v4 = victim_target.is_ipv4();
        let long_head_timeout = Duration::from_secs(8);
        warm_up_loopback().await;
        let server = spawn_on(
            listener,
            test_router(),
            HttpServerSettings {
                header_read_timeout: long_head_timeout,
                request_timeout: long_head_timeout,
                max_connections: 4,
                max_connections_per_ip: 2,
            },
            HashSet::new(),
        );
        let _ = server.address;

        let mut holders = Vec::new();
        for _ in 0..4 {
            let mut holder = TcpStream::connect(attacker_target).await.expect("connect");
            let _ = holder.write_all(b"GET / HTTP/1.1\r\nHos").await;
            holders.push(holder);
        }
        tokio::time::sleep(Duration::from_millis(150)).await;

        // The victim first: a second address is served at once, while the
        // attacker is still holding everything it was allowed to keep. Pre-T55
        // it would wait in the backlog until the attacker's 8s head timeout.
        let mut victim = connect_from(victim_target, second_source_is_v4).await;
        victim
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let response = tokio::time::timeout(Duration::from_secs(4), read_until_eof(&mut victim))
            .await
            .expect(
                "a second client address was not served while one address held connections — \
                 one IP consumed every slot (M-33)",
            );
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
            "got: {}",
            String::from_utf8_lossy(&response)
        );

        // And the over-cap holders were closed on the spot — long before the
        // 8s head timeout could have done it — while the two within the share
        // are still open.
        let mut closed = 0;
        for holder in &mut holders {
            let mut probe = [0_u8; 16];
            if let Ok(Ok(0) | Err(_)) =
                tokio::time::timeout(Duration::from_millis(300), holder.read(&mut probe)).await
            {
                closed += 1;
            }
        }
        assert_eq!(
            closed, 2,
            "exactly the connections beyond the per-IP share must be closed at once (M-33)"
        );
        drop(holders);
    }

    // — H-01 residual: the Docker HEALTHCHECK still passes through the guard —

    /// `gl-node --health-check` runs `probe_local_health` against the real
    /// router, which now Host-guards and rate-limits `/health`. For a
    /// `0.0.0.0` bind it probes `127.0.0.1` with `Host: 127.0.0.1`; for `::`
    /// it probes `::1` with a bare `Host: ::1`. Both must still get a 200.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn docker_healthcheck_probe_passes_through_the_host_guard() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let (_ledger_directory, application) = build_real_application();

        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .expect("bind v4 wildcard");
        warm_up_loopback().await;
        let server = spawn_on(
            listener,
            application.clone(),
            serving_settings(),
            HashSet::new(),
        );
        let port = server.address.port();
        tokio::task::spawn_blocking(move || crate::health::probe_local_health("0.0.0.0", port))
            .await
            .expect("probe task")
            .expect("the Docker HEALTHCHECK against a 0.0.0.0 bind must pass (H-01 residual)");

        if let Ok(listener) = TcpListener::bind("[::]:0").await {
            warm_up_loopback().await;
            let server = spawn_on(listener, application, serving_settings(), HashSet::new());
            let port = server.address.port();
            match tokio::task::spawn_blocking(move || crate::health::probe_local_health("::", port))
                .await
                .expect("probe task")
            {
                Ok(()) => {}
                // No ::1 on this host: nothing to assert about the guard.
                Err(error) if error.contains("connect") => {
                    eprintln!("SKIPPED the :: half: {error}");
                }
                Err(error) => panic!("the HEALTHCHECK against a :: bind must pass: {error}"),
            }
        }
    }

    /// And over a real socket a foreign `Host` is refused on `/health`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_over_the_wire_refuses_a_foreign_host() {
        let _serialized = NET_TEST_LOCK.lock().await;
        let (_ledger_directory, application) = build_real_application();
        let server = spawn_server(application, serving_settings()).await;

        let mut stream = TcpStream::connect(server.address).await.expect("connect");
        stream
            .write_all(
                b"GET /health HTTP/1.1\r\nHost: rebound.example.com\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write request");
        let response = tokio::time::timeout(Duration::from_secs(2), read_until_eof(&mut stream))
            .await
            .expect("request should complete");
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 403"), "got: {response}");
        assert!(
            !response.contains("version"),
            "no health detail may leak: {response}"
        );
    }

    /// Assemble the real router the same way `main` does (mirrors the helper in
    /// `request_guard.rs` tests).
    fn build_real_application() -> (tempfile::TempDir, Router) {
        let mut config_file = NamedTempFile::new().expect("temp config");
        config_file
            .write_all(br#"{ "ledgerPath": "./data/ledger.bean" }"#)
            .expect("write temp config");
        let config = NodeConfig::load_from_path(&config_file.path().to_path_buf())
            .expect("config should load");

        let directory = tempfile::tempdir().expect("temp dir");
        let bean_path = directory.path().join("http_server.bean");
        std::fs::write(&bean_path, "").expect("create ledger file");
        let service = ledger::service::LedgerService::boot(&bean_path, "test-node".to_owned())
            .expect("ledger should boot");
        let shared: SharedLedger = Arc::new(RwLock::new(service));
        let peer_registry = p2p::node::PeerRegistry::new();
        let schema = build_schema_with_service(
            shared.clone(),
            TransactionBroadcast::new(),
            peer_registry.clone(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );
        let application = crate::build_application(
            schema,
            AuthState {
                enabled: false,
                api_key: String::new(),
                access: None,
            },
            HealthState {
                ledger: shared,
                peer_registry,
                public_bind: false,
                auth: AuthState {
                    enabled: false,
                    api_key: String::new(),
                    access: None,
                },
            },
            RequestGuardState {
                allowed_hosts: Arc::new(config.allowed_host_set()),
                allowed_origins: Arc::new(config.cors.allowed_origins.iter().cloned().collect()),
                tls_terminated: false,
            },
            CorsLayer::new(),
            true,
        );
        (directory, application)
    }
}
