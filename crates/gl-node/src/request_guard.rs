//! Host / Content-Type / Origin guard for the GraphQL surface (H-01).
//!
//! Without this layer any web page the operator visits can drive the node:
//! a CORS *simple request* (`text/plain` POST, no preflight) reaches
//! `POST /graphql` and executes mutations on the default loopback bind, and a
//! DNS-rebinding attacker (`evil.com` re-resolved to `127.0.0.1`) is treated by
//! the browser as same-origin with the node, so even a strict CORS allowlist
//! never gets consulted. The guard runs as the outermost layer of the GraphQL
//! routes — before rate limiting and auth — and rejects those shapes.
//!
//! `/health` is behind it too (H-01 residual, T55): on a loopback bind the
//! health body carries the version, head count and peer count, and without the
//! Host check a rebound `evil.com` page could read them exactly as it once
//! could `/graphql`. The Docker `HEALTHCHECK` is unaffected — it addresses
//! the node as `127.0.0.1` or `::1`, which are always in the allowed set.

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tracing::warn;

use crate::connection_limiter::{KeyedRefusalLog, MAX_REFUSAL_LOG_SOURCES};

/// Shared guard state for the middleware layer.
#[derive(Clone)]
pub struct RequestGuardState {
    /// Accepted `Host` values, lowercased and without a port.
    pub allowed_hosts: Arc<HashSet<String>>,
    /// Exact origin strings from `cors.allowedOrigins`.
    pub allowed_origins: Arc<HashSet<String>>,
    /// `tls.mode == "terminated"`: the public origin of this node is `https`,
    /// whatever scheme the hop from the terminator used (L-51). See
    /// [`origin_allowed`].
    pub tls_terminated: bool,
}

const HOST_REJECTION: &str = "request Host is not an allowed host for this node";
const CONTENT_TYPE_REJECTION: &str = "Content-Type must be application/json";
const ORIGIN_REJECTION: &str = "cross-origin requests to this node are not allowed";

/// Minimum gap between two guard-refusal `warn!` lines (M-41).
///
/// The same interval `PerIpConnections::should_log_refusal` uses. The guard is
/// the outermost layer of both routes — deliberately outside the rate limiter,
/// so a bad `Host` never reaches the schema — which also put its `warn!`s
/// outside every budget: one client was measured producing 100–190 MB/s of
/// log, ~13k lines/s, each echoing a header of its choosing. One line per
/// interval, carrying how many were suppressed since the last, says the same
/// thing to an operator at a rate the node chooses.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Longest prefix of an attacker-chosen header value a refusal line quotes (M-41).
///
/// Enough to recognise a misconfigured proxy or a rebinding domain; far short
/// of hyper's 64 KiB head buffer (`http_server::HTTP1_MAX_BUF_SIZE`), which is
/// the most a value could be.
const MAX_ECHOED_HEADER_CHARS: usize = 128;

/// The guard's refusal-log throttle: one line per client per
/// [`REFUSAL_LOG_INTERVAL`] (M-41, T77).
///
/// Keyed by the client's rate-limit bucket (`rate_limit::bucket_key`: the
/// address, or its `/64` for IPv6, so one host cannot mint sources by walking
/// its prefix), with `None` for a request that carries no peer address (only
/// in-process tests build those). Before T77 this was one window for the whole
/// process: one client's flood hid every other client's refusals, and what the
/// window swallowed was reported only by the next refusal — a burst of 999
/// that then stopped was never reported at all. See
/// [`crate::connection_limiter::KeyedRefusalLog`] for the table's bound and
/// the report at expiry.
///
/// A `static` rather than a field of [`RequestGuardState`] because the state is
/// built by struct literal at three sites and the log is per process anyway.
static REFUSAL_LOG: LazyLock<KeyedRefusalLog<Option<IpAddr>>> = LazyLock::new(guard_refusal_log);

/// A fresh guard throttle (the static's constructor; tests build their own).
fn guard_refusal_log() -> KeyedRefusalLog<Option<IpAddr>> {
    KeyedRefusalLog::new(
        REFUSAL_LOG_INTERVAL,
        MAX_REFUSAL_LOG_SOURCES,
        report_guard_refusals,
    )
}

/// The guard's expiry summary (T77): what one client's window swallowed.
fn report_guard_refusals(source: Option<&Option<IpAddr>>, suppressed: u64) {
    match source {
        Some(Some(client)) => warn!(
            client = %client,
            suppressed,
            "requests refused by the Host/Content-Type/Origin guard and not logged in the last \
             window"
        ),
        Some(None) => warn!(
            suppressed,
            "requests without a peer address refused by the Host/Content-Type/Origin guard and \
             not logged in the last window"
        ),
        None => warn!(
            suppressed,
            "requests refused by the Host/Content-Type/Origin guard and not logged in the last \
             window (clients past the per-client log table)"
        ),
    }
}

/// At most [`MAX_ECHOED_HEADER_CHARS`] of a header value, cut on a character
/// boundary and marked when cut (M-41).
fn excerpt(value: &str) -> String {
    let mut chars = value.char_indices();
    match chars.nth(MAX_ECHOED_HEADER_CHARS) {
        Some((cut, _)) => format!("{}…({} bytes)", &value[..cut], value.len()),
        None => value.to_owned(),
    }
}

/// Which header a refusal line quotes, if any (M-41).
enum Echo<'a> {
    Nothing,
    Host(&'a str),
    ContentType(&'a str),
    Origin(&'a str),
}

/// Emit one throttled refusal line, or nothing (M-41, T77).
///
/// Throttled per client, and as one class per client: an attacker can pick
/// whichever of the three checks fails, so a per-check interval would be three
/// lines per interval, not one. The excerpt is taken only when a line is
/// actually emitted, so a suppressed refusal allocates nothing for its log.
fn warn_refusal(client: Option<IpAddr>, reason: &'static str, echo: Echo<'_>) {
    warn_refusal_on(&REFUSAL_LOG, client, reason, echo);
}

/// [`warn_refusal`] against an explicit throttle (tests build their own).
fn warn_refusal_on(
    log: &KeyedRefusalLog<Option<IpAddr>>,
    client: Option<IpAddr>,
    reason: &'static str,
    echo: Echo<'_>,
) {
    let Some(suppressed) = log.note(client, Instant::now()) else {
        return;
    };
    let client = client.map_or_else(|| "-".to_owned(), |client| client.to_string());
    match echo {
        Echo::Nothing => warn!(%client, suppressed, "{reason}"),
        Echo::Host(value) => warn!(%client, host = %excerpt(value), suppressed, "{reason}"),
        Echo::ContentType(value) => {
            warn!(%client, content_type = %excerpt(value), suppressed, "{reason}")
        }
        Echo::Origin(value) => warn!(%client, origin = %excerpt(value), suppressed, "{reason}"),
    }
}

/// The key a request's refusals are throttled under (T77): the peer's
/// rate-limit bucket, from the `ConnectInfo` the hardened accept loop inserts.
fn refusal_source(request: &Request<Body>) -> Option<IpAddr> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| crate::rate_limit::bucket_key(peer.ip()))
}

/// Axum middleware enforcing Host, Content-Type and Origin on GraphQL routes (H-01).
///
/// Checks run in order:
///
/// 1. **Host — every method.** The `Host` header (or HTTP/2 `:authority`) must
///    name a host this node answers to. This is the DNS-rebinding defense: a
///    rebound `evil.com` still carries `Host: evil.com`, which is not on the
///    allowlist.
/// 2. **Content-Type — POST only.** The media type must be exactly
///    `application/json`, which no CORS simple request can send without a
///    preflight. It also forecloses the `multipart/form-data` upload path that
///    async-graphql would otherwise accept, another preflight-free shape.
/// 3. **Origin — POST only.** A present `Origin` must be on the CORS allowlist
///    or be same-origin with this node. A missing `Origin` passes so that curl
///    and native clients keep working.
pub async fn request_guard(
    State(guard_state): State<RequestGuardState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let client = refusal_source(&request);
    // (a) Host — applies to every method, GraphiQL GETs included.
    let authority = match request.headers().get(header::HOST) {
        Some(value) => match value.to_str() {
            Ok(text) => Some(text.to_owned()),
            Err(_) => {
                warn_refusal(
                    client,
                    "rejected request with a non-ASCII Host header",
                    Echo::Nothing,
                );
                return reject(StatusCode::FORBIDDEN, HOST_REJECTION);
            }
        },
        // HTTP/2 carries the authority in the pseudo-header, not in `Host`.
        None => request
            .uri()
            .authority()
            .map(|authority| authority.as_str().to_owned()),
    };
    let Some(authority) = authority else {
        warn_refusal(
            client,
            "rejected request with neither a Host header nor a URI authority",
            Echo::Nothing,
        );
        return reject(StatusCode::FORBIDDEN, HOST_REJECTION);
    };
    let host = normalize_host(&authority);
    if !guard_state.allowed_hosts.contains(&host) {
        // M-41: throttled, and the value is an excerpt — `%host` echoed up to
        // hyper's whole head buffer, once per request, outside every limiter.
        warn_refusal(
            client,
            "rejected request whose Host is not allowed (DNS rebinding)",
            Echo::Host(&host),
        );
        return reject(StatusCode::FORBIDDEN, HOST_REJECTION);
    }

    if request.method() == Method::POST {
        // (b) Content-Type — a browser can only send application/json after a
        // successful preflight, so this alone kills the simple-request CSRF.
        let media_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
            });
        match media_type.as_deref() {
            Some("application/json") => {}
            other => {
                warn_refusal(
                    client,
                    "rejected POST with a non-JSON Content-Type",
                    Echo::ContentType(other.unwrap_or("<missing>")),
                );
                return reject(StatusCode::UNSUPPORTED_MEDIA_TYPE, CONTENT_TYPE_REJECTION);
            }
        }

        // (c) Origin — only checked when the client sent one.
        if let Some(origin_value) = request.headers().get(header::ORIGIN) {
            let origin = match origin_value.to_str() {
                Ok(text) => text,
                Err(_) => {
                    warn_refusal(
                        client,
                        "rejected POST with a non-ASCII Origin header",
                        Echo::Nothing,
                    );
                    return reject(StatusCode::FORBIDDEN, ORIGIN_REJECTION);
                }
            };
            if !origin_allowed(
                origin,
                &authority,
                &guard_state.allowed_origins,
                &guard_state.allowed_hosts,
                guard_state.tls_terminated,
            ) {
                warn_refusal(client, "rejected cross-origin POST", Echo::Origin(origin));
                return reject(StatusCode::FORBIDDEN, ORIGIN_REJECTION);
            }
        }
    }

    next.run(request).await
}

fn reject(status: StatusCode, message: &'static str) -> Response {
    (status, message).into_response()
}

/// True when `origin` is explicitly allowlisted or is same-origin with this node.
///
/// The same-origin arm requires the origin's host to be one this node answers
/// to *and* its port to match the port the client addressed. Ports matter: a
/// page on `http://localhost:3000` is a different origin from a node on
/// `http://localhost:4000`, and admitting it would hand every other service
/// bound to loopback a writable ledger. Such a dev origin is admitted only by
/// listing it in `cors.allowedOrigins`.
///
/// **The scheme matters too (L-51).** An origin is scheme + host + port, and
/// before T55 this arm stripped the scheme and compared the rest — so behind
/// the TLS terminator a public bind is required to have, a page served over
/// plaintext `http://<node-host>` read as same-origin with the node. That page
/// is exactly the one an on-path attacker can inject script into, and the
/// node's real origin never serves it. What "same origin" means here:
///
/// * **`tls.mode: "terminated"`** — the browser reached this node through the
///   terminator, so its origin is `https://<host>[:port]`. The hop from the
///   terminator to us is plaintext, but that hop is not what the browser sees,
///   and the `Host` the terminator forwards names the public authority. So
///   only `https` is same-origin — with one exception: a loopback host
///   (`localhost`, `127.0.0.1`, `::1`) is also accepted over `http`, because
///   such a page never crossed a network an attacker could sit on, and it is
///   what an operator gets pointing a browser at the node's own port while a
///   terminator fronts everyone else.
/// * **`tls.mode: "disabled"`** — the node serves plaintext itself, so its own
///   origin is `http`; `https` is also accepted, because a TLS origin is never
///   the weaker of the two and a terminator the config was not told about may
///   be in front. The node cannot be stricter here without knowing more, and
///   the remedy for a node that *is* behind a terminator is to say so with
///   `tls.mode: "terminated"`.
///
/// `Origin: null` — sandboxed iframes, `data:` and `file:` documents — is
/// refused before either arm is consulted (L-52): those contexts are opaque,
/// every one of them serializes to the same string, and they are not trusted
/// callers. Config validation refuses `"null"` in `cors.allowedOrigins` as
/// well, so this is the backstop, not the only line.
fn origin_allowed(
    origin: &str,
    request_authority: &str,
    allowed_origins: &HashSet<String>,
    allowed_hosts: &HashSet<String>,
    tls_terminated: bool,
) -> bool {
    if origin.eq_ignore_ascii_case("null") {
        return false;
    }
    if allowed_origins.contains(origin) {
        return true;
    }
    let (secure, authority) = match origin.strip_prefix("https://") {
        Some(authority) => (true, authority),
        None => match origin.strip_prefix("http://") {
            Some(authority) => (false, authority),
            None => return false,
        },
    };
    // A serialized origin is scheme + authority and nothing else.
    if authority.is_empty() || authority.contains('/') {
        return false;
    }
    let (origin_host, origin_port) = split_authority(authority);
    let origin_host = origin_host.to_ascii_lowercase();
    let (_, request_port) = split_authority(request_authority);
    if !allowed_hosts.contains(&origin_host) || origin_port != request_port {
        return false;
    }
    secure || !tls_terminated || is_loopback_host(&origin_host)
}

/// The built-in loopback names (L-51). Deliberately the literal set config
/// always admits, not a resolver call: an origin host is attacker-chosen text.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Reduce an authority (`Host` header or origin authority) to a comparable host.
///
/// Strips an optional `:port` suffix and the brackets around an IPv6 literal,
/// then lowercases. A suffix that is not all ASCII digits is not a port, so the
/// whole value stays the host (and will simply fail the allowlist lookup).
fn normalize_host(authority: &str) -> String {
    split_authority(authority).0.to_ascii_lowercase()
}

/// Split an authority into its host and its explicit port, if any.
///
/// `pub(crate)` so config validation can run every `allowedHosts` entry through
/// the same split the guard applies to the `Host` header (§5 of the 0922-v2
/// audit): an entry this function would change can never be matched.
pub(crate) fn split_authority(authority: &str) -> (&str, Option<&str>) {
    if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: `[::1]:4000` → (`::1`, `4000`).
        match rest.split_once(']') {
            Some((inner, tail)) => (inner, port_suffix(tail.strip_prefix(':'))),
            None => (rest, None),
        }
    } else if authority.bytes().filter(|byte| *byte == b':').count() > 1 {
        // Bare IPv6 literal (`::1`): every colon belongs to the address.
        (authority, None)
    } else if let Some((name, suffix)) = authority.rsplit_once(':') {
        match port_suffix(Some(suffix)) {
            Some(port) => (name, Some(port)),
            // Not a port (`host:abc`), so the whole value is the host.
            None => (authority, None),
        }
    } else {
        (authority, None)
    }
}

fn port_suffix(suffix: Option<&str>) -> Option<&str> {
    suffix.filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthState;
    use crate::config::NodeConfig;
    use crate::graphql::broadcast::TransactionBroadcast;
    use crate::graphql::{build_schema_with_service, SharedLedger};
    use crate::health::HealthState;
    use axum::http::request::Builder;
    use axum::Router;
    use http_body_util::BodyExt;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;
    use tower::ServiceExt;
    use tower_http::cors::CorsLayer;

    const VALID_BODY: &str = r#"{"query":"{ __typename }"}"#;

    // — Host normalization units —

    #[test]
    fn test_normalize_host_strips_port() {
        assert_eq!(normalize_host("127.0.0.1:4000"), "127.0.0.1");
        assert_eq!(normalize_host("LocalHost:4000"), "localhost");
        assert_eq!(normalize_host("localhost"), "localhost");
    }

    #[test]
    fn test_normalize_host_ipv6_brackets() {
        assert_eq!(normalize_host("[::1]:4000"), "::1");
        assert_eq!(normalize_host("[::1]"), "::1");
        // Bare IPv6 literals have no port to strip.
        assert_eq!(normalize_host("::1"), "::1");
    }

    #[test]
    fn test_split_authority_extracts_port() {
        assert_eq!(
            split_authority("127.0.0.1:4000"),
            ("127.0.0.1", Some("4000"))
        );
        assert_eq!(split_authority("[::1]:4000"), ("::1", Some("4000")));
        assert_eq!(split_authority("[::1]"), ("::1", None));
        // An implicit port (443/80 behind a terminator) is absent on both sides.
        assert_eq!(
            split_authority("ledger.example.com"),
            ("ledger.example.com", None)
        );
        assert_eq!(split_authority("host:abc"), ("host:abc", None));
    }

    #[test]
    fn test_normalize_host_non_digit_suffix_is_not_a_port() {
        // "host:abc" has no port, so the whole value is the host — and will
        // therefore fail the allowlist lookup rather than degrading to "host".
        assert_eq!(normalize_host("host:abc"), "host:abc");
        assert_eq!(normalize_host("host:"), "host:");
        assert_eq!(normalize_host("host:40a0"), "host:40a0");
    }

    // — Router-level tests: every request goes through the real assembled
    //   application, so a wiring regression (guard dropped, wrong layer order,
    //   body limit that does not bind) fails here.

    fn load_config(json: &str) -> NodeConfig {
        let mut file = NamedTempFile::new().expect("failed to create temp config");
        file.write_all(json.as_bytes())
            .expect("failed to write temp config");
        NodeConfig::load_from_path(&file.path().to_path_buf()).expect("config should load")
    }

    fn guard_state(config: &NodeConfig) -> RequestGuardState {
        RequestGuardState {
            allowed_hosts: Arc::new(config.allowed_host_set()),
            allowed_origins: Arc::new(config.cors.allowed_origins.iter().cloned().collect()),
            tls_terminated: config.tls.mode == "terminated",
        }
    }

    fn default_config() -> NodeConfig {
        load_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#)
    }

    /// Assemble the real application router over a booted ledger service.
    fn build_test_app(state: RequestGuardState) -> (tempfile::TempDir, Router) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let bean_path = dir.path().join("guard.bean");
        std::fs::write(&bean_path, "").expect("failed to create ledger file");
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
            state,
            CorsLayer::new(),
            true,
        );
        (dir, application)
    }

    fn default_app() -> (tempfile::TempDir, Router) {
        build_test_app(guard_state(&default_config()))
    }

    /// `POST /graphql` with a good Host and a JSON content type.
    fn graphql_post() -> Builder {
        Request::post("/graphql")
            .header(header::HOST, "127.0.0.1:4000")
            .header(header::CONTENT_TYPE, "application/json")
    }

    async fn json_body(response: Response) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body should collect")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("body should be JSON")
    }

    #[tokio::test]
    async fn test_valid_json_post_without_origin_is_allowed() {
        let (_dir, application) = default_app();
        let request = graphql_post().body(Body::from(VALID_BODY)).unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["data"]["__typename"], "QueryRoot");
    }

    #[tokio::test]
    async fn test_text_plain_post_is_rejected() {
        // The CSRF reproduction: a CORS simple request needs no preflight.
        let (_dir, application) = default_app();
        let request = Request::post("/graphql")
            .header(header::HOST, "127.0.0.1:4000")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_post_without_content_type_is_rejected() {
        let (_dir, application) = default_app();
        let request = Request::post("/graphql")
            .header(header::HOST, "127.0.0.1:4000")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_json_content_type_with_charset_is_allowed() {
        let (_dir, application) = default_app();
        let request = Request::post("/graphql")
            .header(header::HOST, "127.0.0.1:4000")
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rebinding_host_is_rejected() {
        let (_dir, application) = default_app();
        let request = Request::post("/graphql")
            .header(header::HOST, "evil.example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_missing_host_is_rejected() {
        let (_dir, application) = default_app();
        let request = Request::post("/graphql")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_cross_origin_post_is_rejected() {
        let (_dir, application) = default_app();
        let request = graphql_post()
            .header(header::ORIGIN, "https://evil.example.com")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_same_origin_post_is_allowed() {
        // The shape the loopback GraphiQL playground sends.
        let (_dir, application) = default_app();
        let request = graphql_post()
            .header(header::ORIGIN, "http://127.0.0.1:4000")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_null_origin_is_rejected() {
        let (_dir, application) = default_app();
        let request = graphql_post()
            .header(header::ORIGIN, "null")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_allowlisted_origin_is_allowed() {
        let config = load_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "cors": { "allowedOrigins": ["http://localhost:3000"] } }"#,
        );
        let (_dir, application) = build_test_app(guard_state(&config));
        let request = graphql_post()
            .header(header::ORIGIN, "http://localhost:3000")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_dev_origin_is_rejected_when_not_allowlisted() {
        // Identical request, empty CORS allowlist: port 3000 is a different
        // origin from the node on port 4000, so only the allowlist admits it.
        let (_dir, application) = default_app();
        let request = graphql_post()
            .header(header::ORIGIN, "http://localhost:3000")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_loopback_host_forms_are_allowed() {
        for host in ["[::1]:4000", "localhost:4000"] {
            let (_dir, application) = default_app();
            let request = Request::post("/graphql")
                .header(header::HOST, host)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(VALID_BODY))
                .unwrap();
            let response = application.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "host {host} should pass");
        }
    }

    #[tokio::test]
    async fn test_graphiql_get_is_host_checked() {
        let (_dir, application) = default_app();
        let request = Request::get("/graphql")
            .header(header::HOST, "127.0.0.1:4000")
            .body(Body::empty())
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let (_dir, application) = default_app();
        let request = Request::get("/graphql")
            .header(header::HOST, "evil.example.com")
            .body(Body::empty())
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Build a JSON body of exactly `total` bytes.
    fn padded_body(total: usize) -> String {
        let prefix = r#"{"query":"{ __typename }","padding":""#;
        let suffix = r#""}"#;
        let padding = "a".repeat(total - prefix.len() - suffix.len());
        let body = format!("{prefix}{padding}{suffix}");
        assert_eq!(body.len(), total);
        body
    }

    #[tokio::test]
    async fn test_oversized_body_is_rejected() {
        // H-05 regression: `DefaultBodyLimit` never bound async-graphql's
        // extractor, so this used to be answered with 200 after buffering the
        // whole payload into RAM.
        let (_dir, application) = default_app();
        let body = padded_body(crate::GRAPHQL_MAX_BODY_BYTES + 1);
        let request = graphql_post()
            .header(header::CONTENT_LENGTH, body.len())
            .body(Body::from(body))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_body_at_the_limit_is_not_rejected() {
        // The largest body the cap permits must still reach the schema; it may
        // answer 200 or with a GraphQL error, but never 413.
        let (_dir, application) = default_app();
        let body = padded_body(crate::GRAPHQL_MAX_BODY_BYTES);
        let request = graphql_post()
            .header(header::CONTENT_LENGTH, body.len())
            .body(Body::from(body))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // — H-01 residual / L-42: /health is Host-guarded and rate-limited —

    #[tokio::test]
    async fn test_health_rejects_a_rebinding_host() {
        // A loopback node's /health carries version, head count and peer
        // count; a DNS-rebound `evil.example.com` page must not read them. The
        // pre-T55 router answered this with 200 and the full body.
        let (_dir, application) = default_app();
        let request = Request::get("/health")
            .header(header::HOST, "evil.example.com")
            .body(Body::empty())
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_health_answers_every_host_the_docker_probe_can_send() {
        // `probe_local_health` sends `Host: 127.0.0.1` for a 0.0.0.0 bind and
        // `Host: ::1` (bare, unbracketed) for a `::` bind; an operator's curl
        // sends `localhost:<port>`. All three must keep passing.
        for host in ["127.0.0.1", "::1", "localhost:3000", "[::1]:3000"] {
            let (_dir, application) = default_app();
            let request = Request::get("/health")
                .header(header::HOST, host)
                .body(Body::empty())
                .unwrap();
            let response = application.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "Host {host} must pass");
        }
    }

    #[tokio::test]
    async fn test_health_is_rate_limited_on_its_own_budget() {
        // L-42: unmetered, every /health call took the ledger read lock. It
        // now has a limiter — a sibling of GraphQL's, so exhausting one does
        // not spend the other (the Docker probe shares loopback with local
        // GraphQL clients).
        let (_dir, application) = default_app();
        let health = || {
            Request::get("/health")
                .header(header::HOST, "127.0.0.1:4000")
                .body(Body::empty())
                .unwrap()
        };

        // Spend the whole GraphQL budget first.
        for _ in 0..crate::rate_limit::GRAPHQL_RATE_LIMIT {
            let response = application
                .clone()
                .oneshot(graphql_post().body(Body::from(VALID_BODY)).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = application
            .clone()
            .oneshot(graphql_post().body(Body::from(VALID_BODY)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // /health still has all of its own.
        for attempt in 0..crate::rate_limit::HEALTH_RATE_LIMIT {
            let response = application.clone().oneshot(health()).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "health request {attempt} must not be charged to GraphQL's budget"
            );
        }
        let response = application.clone().oneshot(health()).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "past its own budget /health is limited too (L-42)"
        );
    }

    // — L-51: scheme-aware same-origin —

    fn terminated_state() -> RequestGuardState {
        let config = load_config(
            // A node behind a terminator is public (005): its key is given.
            r#"{ "ledgerPath": "./data/ledger.bean", "tls": { "mode": "terminated" }, "allowedHosts": ["ledger.example.com"], "auth": { "apiKey": "unit-test-api-key-0123456789abcd" } }"#,
        );
        let state = guard_state(&config);
        assert!(state.tls_terminated);
        state
    }

    #[test]
    fn test_plaintext_origin_is_not_same_origin_behind_a_terminator() {
        // The L-51 shape: Host is the public name the terminator forwarded, and
        // a plaintext page on that name must not pass as same-origin.
        let state = terminated_state();
        let allowed = |origin: &str| {
            origin_allowed(
                origin,
                "ledger.example.com",
                &state.allowed_origins,
                &state.allowed_hosts,
                state.tls_terminated,
            )
        };
        assert!(
            !allowed("http://ledger.example.com"),
            "a plaintext page is a different origin from the TLS-terminated node (L-51)"
        );
        assert!(allowed("https://ledger.example.com"));
    }

    #[test]
    fn test_loopback_http_origin_still_passes_behind_a_terminator() {
        // A loopback page never crossed a network, so it keeps working even
        // when tls.mode says a terminator fronts everyone else.
        let state = terminated_state();
        for (origin, authority) in [
            ("http://127.0.0.1:4000", "127.0.0.1:4000"),
            ("http://localhost:4000", "localhost:4000"),
            ("http://[::1]:4000", "[::1]:4000"),
        ] {
            assert!(
                origin_allowed(
                    origin,
                    authority,
                    &state.allowed_origins,
                    &state.allowed_hosts,
                    state.tls_terminated,
                ),
                "{origin} must stay same-origin on loopback"
            );
        }
    }

    #[tokio::test]
    async fn test_plaintext_origin_post_is_rejected_behind_a_terminator() {
        // The same rule through the real router.
        let (_dir, application) = build_test_app(terminated_state());
        let request = Request::post("/graphql")
            .header(header::HOST, "ledger.example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "http://ledger.example.com")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let (_dir, application) = build_test_app(terminated_state());
        let request = Request::post("/graphql")
            .header(header::HOST, "ledger.example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "https://ledger.example.com")
            .body(Body::from(VALID_BODY))
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_loopback_dev_keeps_plaintext_same_origin() {
        // tls.mode "disabled": the node serves http itself, so its own http
        // origin is same-origin (GraphiQL on loopback depends on this).
        let state = guard_state(&default_config());
        assert!(!state.tls_terminated);
        assert!(origin_allowed(
            "http://127.0.0.1:4000",
            "127.0.0.1:4000",
            &state.allowed_origins,
            &state.allowed_hosts,
            state.tls_terminated,
        ));
    }

    // — L-52: `Origin: null` is refused even when configured —

    #[test]
    fn test_null_origin_is_refused_even_if_allowlisted() {
        // Config validation refuses "null" in cors.allowedOrigins; this is the
        // guard's own backstop for a state built some other way.
        let allowed_origins: HashSet<String> = ["null".to_owned()].into_iter().collect();
        let allowed_hosts: HashSet<String> = ["127.0.0.1".to_owned()].into_iter().collect();
        for spelling in ["null", "NULL", "Null"] {
            assert!(
                !origin_allowed(
                    spelling,
                    "127.0.0.1:4000",
                    &allowed_origins,
                    &allowed_hosts,
                    false
                ),
                "Origin: {spelling} must be refused (L-52)"
            );
        }
    }

    // ── T66 / M-41: throttled, excerpted refusal logging ────────────────

    /// The throttle logs a client's first refusal, swallows everything inside
    /// the interval while counting it, and — outside a runtime, where no
    /// expiry report can be scheduled — hands the count to the next line out.
    #[test]
    fn refusal_log_throttle_emits_one_line_per_interval_with_a_count() {
        let throttle = guard_refusal_log();
        let client = Some(IpAddr::from([192, 0, 2, 1]));
        let start = Instant::now();
        assert_eq!(
            throttle.note(client, start),
            Some(0),
            "the first refusal is logged"
        );
        for _ in 0..999 {
            assert_eq!(
                throttle.note(client, start + Duration::from_millis(5)),
                None
            );
        }
        assert_eq!(
            throttle.note(
                client,
                start + REFUSAL_LOG_INTERVAL - Duration::from_millis(1)
            ),
            None,
            "still inside the interval"
        );
        assert_eq!(
            throttle.note(client, start + REFUSAL_LOG_INTERVAL),
            Some(1000),
            "the next line carries how many were swallowed"
        );
        assert_eq!(
            throttle.note(client, start + 2 * REFUSAL_LOG_INTERVAL),
            Some(0),
            "a quiet interval resets the count"
        );
    }

    /// T77 (Info): the guard's throttle is per client, and what a client's
    /// window swallowed is reported when the window closes. Two clients
    /// refused 100 times each inside one window get one first line EACH, and
    /// one expiry line each carrying `suppressed=99`; before T77 the second
    /// client got no line at all and the 198 swallowed refusals were reported
    /// by nobody (nothing came after them).
    ///
    /// Bug-catch: key the throttle by nothing and the second client's first
    /// line is missing; drop the scheduled report and there are no expiry
    /// lines.
    #[test]
    fn guard_refusals_are_throttled_per_client_and_reported_at_expiry() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let interval = Duration::from_millis(200);
        let log = KeyedRefusalLog::new(interval, MAX_REFUSAL_LOG_SOURCES, report_guard_refusals);
        let (one, two) = (
            IpAddr::from([192, 0, 2, 10]),
            IpAddr::from([198, 51, 100, 20]),
        );
        let ((), logged) = capture_warnings(|| {
            runtime.block_on(async {
                for _ in 0..100 {
                    for client in [one, two] {
                        warn_refusal_on(
                            &log,
                            Some(client),
                            "rejected request whose Host is not allowed (DNS rebinding)",
                            Echo::Host("evil.example"),
                        );
                    }
                }
                tokio::time::sleep(interval * 3).await;
            })
        });
        for client in [one, two] {
            let first: Vec<&str> = logged
                .lines()
                .filter(|line| line.contains("rejected") && line.contains(&client.to_string()))
                .collect();
            assert_eq!(first.len(), 1, "one first line for {client}:\n{logged}");
            assert!(first[0].contains("suppressed=0"), "{}", first[0]);
            let expiry: Vec<&str> = logged
                .lines()
                .filter(|line| {
                    line.contains("not logged in the last window")
                        && line.contains(&client.to_string())
                })
                .collect();
            assert_eq!(expiry.len(), 1, "one expiry line for {client}:\n{logged}");
            assert!(expiry[0].contains("suppressed=99"), "{}", expiry[0]);
        }
    }

    /// T77 (Info), through the real middleware: two clients' foreign-Host
    /// refusals, interleaved, each produce their own first line — the key is
    /// the `ConnectInfo` peer the accept loop inserts.
    ///
    /// Bug-catch: derive no source from the request (one shared key) and only
    /// one of the two clients is ever named.
    #[test]
    fn foreign_host_refusals_from_two_clients_each_get_a_line() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (_dir, application) = default_app();
        // TEST-NET addresses no other test in this binary uses, so the
        // process-wide throttle's windows for them are this test's alone.
        let clients: [SocketAddr; 2] = [
            "192.0.2.77:50000".parse().unwrap(),
            "203.0.113.77:50001".parse().unwrap(),
        ];
        let ((), logged) = capture_warnings(|| {
            runtime.block_on(async {
                for _ in 0..50 {
                    for client in clients {
                        let mut request = Request::post("/graphql")
                            .header(header::CONTENT_TYPE, "application/json")
                            .header(header::HOST, "evil.example")
                            .body(Body::from(VALID_BODY))
                            .expect("request");
                        request.extensions_mut().insert(ConnectInfo(client));
                        let response = application
                            .clone()
                            .oneshot(request)
                            .await
                            .expect("router never fails");
                        assert_eq!(response.status(), StatusCode::FORBIDDEN);
                    }
                }
            })
        });
        for client in clients {
            let lines = logged
                .lines()
                .filter(|line| line.contains("rejected") && line.contains(&client.ip().to_string()))
                .count();
            assert_eq!(lines, 1, "{client}:\n{logged}");
        }
    }

    /// `excerpt` keeps a short value whole, cuts a long one at the budget on a
    /// character boundary, and states the full length it stood in for.
    #[test]
    fn excerpt_is_bounded_and_char_safe() {
        assert_eq!(excerpt("evil.example"), "evil.example");
        let long = "é".repeat(100 * 1024);
        let cut = excerpt(&long);
        assert!(cut.starts_with(&"é".repeat(MAX_ECHOED_HEADER_CHARS)));
        assert!(cut.ends_with(&format!("…({} bytes)", long.len())), "{cut}");
        assert!(cut.len() < 512, "{}", cut.len());
    }

    /// Capture every `warn!` emitted while `body` runs on this thread.
    fn capture_warnings<T>(body: impl FnOnce() -> T) -> (T, String) {
        #[derive(Clone, Default)]
        struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for SharedBuffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
            type Writer = SharedBuffer;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        let value = tracing::subscriber::with_default(subscriber, body);
        let logged = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
        (value, logged)
    }

    /// M-41: N = 200 foreign-Host requests, each carrying a 100 KiB `Host`,
    /// are all refused (403) and produce at most K = 2 guard log lines (the
    /// throttle is process-wide, so another test may have spent this
    /// interval's line — the bound holds either way), none longer than
    /// T = 1,024 bytes, and none containing the header's payload. The same
    /// request shape against the Origin and Content-Type checks is bounded
    /// the same way, since all three share one throttle and one excerpt.
    #[test]
    fn foreign_host_refusals_are_throttled_and_never_echo_the_header() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (_dir, application) = default_app();
        let payload = format!("evil.example.{}", "a".repeat(100 * 1024));
        let marker = &payload[..2048];

        let (statuses, logged) = capture_warnings(|| {
            runtime.block_on(async {
                let mut statuses = Vec::new();
                for i in 0..200 {
                    // Built from scratch: adding a second `Host` on top of
                    // `graphql_post()`'s would leave the allowed one first.
                    let request = match i % 3 {
                        0 => Request::post("/graphql")
                            .header(header::CONTENT_TYPE, "application/json")
                            .header(header::HOST, payload.as_str())
                            .body(Body::from(VALID_BODY)),
                        1 => graphql_post()
                            .header(header::ORIGIN, format!("http://{payload}"))
                            .body(Body::from(VALID_BODY)),
                        _ => Request::post("/graphql")
                            .header(header::HOST, "127.0.0.1:4000")
                            .header(header::CONTENT_TYPE, format!("text/{payload}"))
                            .body(Body::from(VALID_BODY)),
                    }
                    .expect("request");
                    let response = application
                        .clone()
                        .oneshot(request)
                        .await
                        .expect("router never fails");
                    statuses.push(response.status());
                }
                statuses
            })
        });

        assert_eq!(statuses.len(), 200);
        assert!(
            statuses
                .iter()
                .all(|s| *s == StatusCode::FORBIDDEN || *s == StatusCode::UNSUPPORTED_MEDIA_TYPE),
            "{statuses:?}"
        );
        let guard_lines: Vec<&str> = logged.lines().filter(|l| l.contains("rejected")).collect();
        assert!(
            guard_lines.len() <= 2,
            "{} guard lines for 200 refusals:\n{}",
            guard_lines.len(),
            guard_lines.join("\n")
        );
        for line in &guard_lines {
            assert!(line.len() < 1024, "a {}-byte log line: {line}", line.len());
            assert!(!line.contains(marker), "the header payload reached the log");
            assert!(line.contains("suppressed="), "{line}");
        }
        assert!(!logged.contains(marker));
    }
}
