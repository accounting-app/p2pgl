use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Response body for `GET /health` (§2.9).
///
/// The three detail fields are optional so the same type can serialize both
/// shapes L-09 needs: the full body, and a bare `{"status":"ok"}` with the
/// detail keys **absent** rather than null/zero — an absent key cannot be
/// mistaken for "this node has no peers".
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heads: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Shared state for the health endpoint.
#[derive(Clone)]
pub struct HealthState {
    pub ledger: Arc<RwLock<ledger::service::LedgerService>>,
    pub peer_registry: p2p::node::PeerRegistry,
    /// True when strangers can reach the node (L-09): a non-loopback bind, or a
    /// proxy in front (`tls.mode: "terminated"`, `trustedProxies`) —
    /// `NodeConfig::is_public`.
    ///
    /// Keyed on the **config**, not on the client address, deliberately: behind
    /// the TLS terminator `tls.mode: "terminated"` assumes, the peer address is
    /// the proxy's and a client-address rule would hand every remote caller the
    /// loopback treatment — and so, until 005, did the bind: a loopback bind
    /// behind a proxy on the same host served the full body to the internet.
    /// `is_public()` is the same predicate config validation uses for the
    /// graphiql/auth/allowedHosts rules, so one deployment cannot be "public"
    /// for one check and private for another.
    pub public_bind: bool,
    /// The API-key state, so a public bind can still serve full detail to an
    /// authenticated operator (L-09).
    pub auth: crate::auth::AuthState,
}

/// Handler for `GET /health`.
///
/// Exempt from auth even when `auth.enabled` (§2.9) — it must answer `200` to an
/// unauthenticated prober, which is all the Docker `HEALTHCHECK` and
/// [`probe_local_health`] read. What it answers *with* depends on whether
/// the node is public (L-09, `NodeConfig::is_public`):
///
/// * **not public** (a loopback bind with no proxy in front) — full detail,
///   unauthenticated. This matches the loopback-trust precedent already in the
///   config rules (GraphiQL is allowed only there, and auth may be off only
///   there), and it keeps the endpoint useful for the operator running
///   `curl localhost:3000/health`.
/// * **public** (a non-loopback bind, or a proxy in front, even on the same
///   host) — `{"status":"ok"}` and nothing else, unless the
///   request carries a valid `X-Api-Key`. Version, head count and peer count are
///   reconnaissance: the version names the exact build to look up advisories
///   for, and heads/peers report mesh size and write activity to anyone who can
///   reach the port.
///
/// The unauthenticated-public branch is the only one reachable with auth off on
/// a public node, because config validation (M-2) refuses that combination at
/// boot — so there is no "public, auth disabled, full detail" case to handle.
pub async fn health_handler(
    State(state): State<HealthState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Any valid key — the operator's or a person's, any role — sees the detail
    // (002-users-and-roles): a read key already sees more through the reports.
    let detailed = !state.public_bind || state.auth.authenticate(&headers).await.is_some();
    if !detailed {
        return (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok".to_owned(),
                heads: None,
                peers: None,
                version: None,
            }),
        );
    }

    let svc = state.ledger.read().await;
    let response = HealthResponse {
        status: "ok".to_owned(),
        heads: Some(svc.head_count() as u64),
        peers: Some(state.peer_registry.count() as u64),
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
    };
    (StatusCode::OK, Json(response))
}

/// Probe `GET /health` on a running node (Docker HEALTHCHECK / `--health-check`).
///
/// `0.0.0.0` / `::` bind addresses are probed on loopback.
pub fn probe_local_health(bind_address: &str, port: u16) -> Result<(), String> {
    let host = match bind_address {
        "0.0.0.0" | "*" => "127.0.0.1",
        "::" => "::1",
        other => other,
    };
    let address = format!("{host}:{port}");
    let socket_addr = address
        .to_socket_addrs()
        .map_err(|error| format!("invalid health probe address {address}: {error}"))?
        .next()
        .ok_or_else(|| format!("health probe address {address} did not resolve"))?;
    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3))
        .map_err(|error| format!("health probe connect {address}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let request = format!("GET /health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("health probe write: {error}"))?;
    // T83 (0924 §5): bounded. Only the status line matters, and whatever
    // answers on the port could otherwise stream without end (the socket
    // timeout bounds the wait between reads, not the total).
    let mut body = String::new();
    (&mut stream)
        .take(64 * 1024)
        .read_to_string(&mut body)
        .map_err(|error| format!("health probe read: {error}"))?;
    let status_line = body.lines().next().unwrap_or("");
    if status_line.contains(" 200 ") || status_line.ends_with(" 200") {
        Ok(())
    } else {
        Err(format!("health probe unexpected response: {status_line}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_returns_ok() {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, "").unwrap();

        let service =
            ledger::service::LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let state = HealthState {
            ledger: Arc::new(RwLock::new(service)),
            peer_registry: p2p::node::PeerRegistry::new(),
            public_bind: false,
            auth: crate::auth::AuthState {
                enabled: false,
                api_key: String::new(),
                access: None,
            },
        };

        let application = Router::new()
            .route("/health", get(health_handler))
            .with_state(state);
        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = application.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let health: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("should be valid JSON");

        assert_eq!(health["status"], "ok");
        assert_eq!(health["heads"], 0);
        assert_eq!(health["peers"], 0);
        assert!(health["version"].is_string());
        assert!(!health["version"].as_str().unwrap().is_empty());
    }

    // ── L-09: detail is disclosed by bind, and by key on a public bind ───

    /// A `/health` router over a one-directive ledger, with the L-09 knobs.
    fn health_app(public_bind: bool, api_key: &str) -> (tempfile::TempDir, Router) {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, "2024-01-01 open Assets:Cash USD\n").unwrap();
        let service =
            ledger::service::LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let state = HealthState {
            ledger: Arc::new(RwLock::new(service)),
            peer_registry: p2p::node::PeerRegistry::new(),
            public_bind,
            auth: crate::auth::AuthState {
                enabled: !api_key.is_empty(),
                api_key: api_key.to_owned(),
                access: None,
            },
        };
        let router = Router::new()
            .route("/health", get(health_handler))
            .with_state(state);
        (dir, router)
    }

    async fn health_body(router: Router, api_key: Option<&str>) -> serde_json::Value {
        let mut builder = Request::builder().uri("/health");
        if let Some(key) = api_key {
            builder = builder.header("x-api-key", key);
        }
        let response = router
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        // Every branch is a 200 — the Docker HEALTHCHECK reads nothing else.
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).expect("valid JSON")
    }

    #[tokio::test]
    async fn test_public_bind_unauthenticated_health_is_minimal() {
        // L-09: version/heads/peers are reconnaissance for anyone who can reach
        // the port — the build to look up advisories for, plus mesh size and
        // write activity. On a public bind an unauthenticated caller gets the
        // liveness answer and nothing else.
        let (_dir, router) = health_app(true, "a-real-api-key-at-least-16-bytes");
        let body = health_body(router, None).await;

        assert_eq!(body["status"], "ok");
        let object = body.as_object().expect("a JSON object");
        assert_eq!(
            object.keys().collect::<Vec<_>>(),
            vec!["status"],
            "no detail key may be present, not even as null: {body}"
        );
        for key in ["version", "heads", "peers"] {
            assert!(!object.contains_key(key), "{key} must be absent: {body}");
        }
    }

    #[tokio::test]
    async fn test_public_bind_with_valid_key_gets_full_health() {
        // The operator is not locked out of their own node: the same key that
        // opens `/graphql` opens the detail here, through the same check.
        let key = "a-real-api-key-at-least-16-bytes";
        let (_dir, router) = health_app(true, key);
        let body = health_body(router, Some(key)).await;

        assert_eq!(body["status"], "ok");
        assert_eq!(body["heads"], 0); // one `open`, no transactions
        assert_eq!(body["peers"], 0);
        assert!(body["version"].as_str().is_some_and(|v| !v.is_empty()));
    }

    #[tokio::test]
    async fn test_public_bind_with_wrong_key_is_minimal() {
        let (_dir, router) = health_app(true, "a-real-api-key-at-least-16-bytes");
        let body = health_body(router, Some("not-the-key")).await;
        assert_eq!(
            body.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["status"]
        );
    }

    #[tokio::test]
    async fn test_loopback_bind_serves_full_health_unauthenticated() {
        // The loopback-trust precedent this codebase already follows for
        // GraphiQL and for `auth.enabled`: a node reachable only from the host
        // stays fully informative to `curl localhost:3000/health`.
        let (_dir, router) = health_app(false, "");
        let body = health_body(router, None).await;

        assert_eq!(body["status"], "ok");
        assert_eq!(body["heads"], 0);
        assert_eq!(body["peers"], 0);
        assert!(body["version"].as_str().is_some_and(|v| !v.is_empty()));
    }

    #[test]
    fn test_probe_local_health_connection_refused() {
        let error = probe_local_health("127.0.0.1", 1).expect_err("nothing listens on port 1");
        assert!(error.contains("health probe"));
    }
}
