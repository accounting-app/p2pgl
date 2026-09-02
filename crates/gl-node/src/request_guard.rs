//! Host / Content-Type / Origin guard for the GraphQL surface (H-01).
//!
//! Without this layer any web page the operator visits can drive the node:
//! a CORS *simple request* (`text/plain` POST, no preflight) reaches
//! `POST /graphql` and executes mutations on the default loopback bind, and a
//! DNS-rebinding attacker (`evil.com` re-resolved to `127.0.0.1`) is treated by
//! the browser as same-origin with the node, so even a strict CORS allowlist
//! never gets consulted. The guard runs as the outermost layer of the GraphQL
//! routes — before rate limiting and auth — and rejects those shapes.

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::warn;

/// Shared guard state for the middleware layer.
#[derive(Clone)]
pub struct RequestGuardState {
    /// Accepted `Host` values, lowercased and without a port.
    pub allowed_hosts: Arc<HashSet<String>>,
    /// Exact origin strings from `cors.allowedOrigins`.
    pub allowed_origins: Arc<HashSet<String>>,
}

const HOST_REJECTION: &str = "request Host is not an allowed host for this node";
const CONTENT_TYPE_REJECTION: &str = "Content-Type must be application/json";
const ORIGIN_REJECTION: &str = "cross-origin requests to this node are not allowed";

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
    // (a) Host — applies to every method, GraphiQL GETs included.
    let authority = match request.headers().get(header::HOST) {
        Some(value) => match value.to_str() {
            Ok(text) => Some(text.to_owned()),
            Err(_) => {
                warn!("rejected request with a non-ASCII Host header");
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
        warn!("rejected request with neither a Host header nor a URI authority");
        return reject(StatusCode::FORBIDDEN, HOST_REJECTION);
    };
    let host = normalize_host(&authority);
    if !guard_state.allowed_hosts.contains(&host) {
        warn!(%host, "rejected request whose Host is not allowed (DNS rebinding)");
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
                warn!(
                    content_type = other.unwrap_or("<missing>"),
                    "rejected POST with a non-JSON Content-Type"
                );
                return reject(StatusCode::UNSUPPORTED_MEDIA_TYPE, CONTENT_TYPE_REJECTION);
            }
        }

        // (c) Origin — only checked when the client sent one.
        if let Some(origin_value) = request.headers().get(header::ORIGIN) {
            let origin = match origin_value.to_str() {
                Ok(text) => text,
                Err(_) => {
                    warn!("rejected POST with a non-ASCII Origin header");
                    return reject(StatusCode::FORBIDDEN, ORIGIN_REJECTION);
                }
            };
            if !origin_allowed(
                origin,
                &authority,
                &guard_state.allowed_origins,
                &guard_state.allowed_hosts,
            ) {
                warn!(%origin, "rejected cross-origin POST");
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
/// `Origin: null` — sandboxed iframes, `data:` and `file:` documents — matches
/// neither arm and is deliberately rejected: those contexts are opaque and are
/// not trusted callers.
fn origin_allowed(
    origin: &str,
    request_authority: &str,
    allowed_origins: &HashSet<String>,
    allowed_hosts: &HashSet<String>,
) -> bool {
    if allowed_origins.contains(origin) {
        return true;
    }
    let authority = match origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    {
        Some(authority) => authority,
        None => return false,
    };
    // A serialized origin is scheme + authority and nothing else.
    if authority.is_empty() || authority.contains('/') {
        return false;
    }
    let (origin_host, origin_port) = split_authority(authority);
    let (_, request_port) = split_authority(request_authority);
    allowed_hosts.contains(&origin_host.to_ascii_lowercase()) && origin_port == request_port
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
fn split_authority(authority: &str) -> (&str, Option<&str>) {
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
            },
            HealthState {
                ledger: shared,
                peer_registry,
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

    #[tokio::test]
    async fn test_health_is_not_host_guarded() {
        // /health stays outside the guard on purpose: Docker probes it over
        // loopback with whatever Host it likes, and it discloses nothing
        // writable. Gating it further is L-09 (T40).
        let (_dir, application) = default_app();
        let request = Request::get("/health")
            .header(header::HOST, "evil.example.com")
            .body(Body::empty())
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
