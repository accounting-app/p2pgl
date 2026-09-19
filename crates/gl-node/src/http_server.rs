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
//! and adds the four missing bounds: a header-read timeout (which hyper re-arms
//! before every request head, so it also bounds idle keep-alive), a whole-request
//! timeout, HTTP/2 keep-alive probes, and a semaphore-backed connection ceiling.
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
use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;
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

/// How long an unanswered HTTP/2 keep-alive PING may go unacknowledged.
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);

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
}

impl Default for HttpServerSettings {
    fn default() -> Self {
        Self {
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
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
pub async fn serve_hardened<S>(
    listener: TcpListener,
    application: Router,
    settings: HttpServerSettings,
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
    let graceful = GracefulShutdown::new();

    let mut builder = auto::Builder::new(TokioExecutor::new());
    // The timer is not optional: without one hyper logs
    // "timeout `header_read_timeout` has default, but no timer set" and drops
    // the timeout entirely, which is exactly how `axum::serve` ships. hyper
    // re-arms this timer in `poll_read_head` for every head it is about to
    // read (`proto/h1/conn.rs`: the running flag is cleared once a head parses),
    // so it bounds the gap between keep-alive requests as well as the first one.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(settings.header_read_timeout);
    // HTTP/2 multiplexes, so a head timeout does not apply; probe instead so an
    // idle or black-holed h2 connection cannot be parked indefinitely.
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(settings.header_read_timeout)
        .keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT);

    info!(
        header_read_timeout_ms = settings.header_read_timeout.as_millis(),
        request_timeout_ms = settings.request_timeout.as_millis(),
        max_connections,
        "serving with connection limits (M-13)"
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

        // `IntoMakeServiceWithConnectInfo` is what inserts the
        // `ConnectInfo<SocketAddr>` extension the rate limiter reads. Its
        // `poll_ready` is unconditionally ready and its error is `Infallible`,
        // so there is nothing to await or handle before calling it.
        let connection_service = Service::<SocketAddr>::call(&mut make_service, remote_address)
            .await
            .expect("connect-info make service is infallible");

        let connection = builder
            .serve_connection_with_upgrades(
                TokioIo::new(stream),
                TowerToHyperService::new(connection_service),
            )
            .into_owned();
        let watched = graceful.watch(connection);

        tokio::spawn(async move {
            if let Err(error) = watched.await {
                debug!(%error, peer = %remote_address, "connection closed with error");
            }
            // Frees the slot for the next accept.
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

    const HEADER_TIMEOUT: Duration = Duration::from_millis(300);
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

    async fn spawn_server(application: Router, settings: HttpServerSettings) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let address = listener.local_addr().expect("listener local address");
        let (shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();
        let handle = tokio::spawn(serve_hardened(
            listener,
            application,
            settings,
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
            },
            HealthState {
                ledger: shared,
                peer_registry,
                public_bind: false,
                auth: AuthState {
                    enabled: false,
                    api_key: String::new(),
                },
            },
            RequestGuardState {
                allowed_hosts: Arc::new(config.allowed_host_set()),
                allowed_origins: Arc::new(config.cors.allowed_origins.iter().cloned().collect()),
            },
            CorsLayer::new(),
            true,
        );
        (directory, application)
    }
}
