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
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub heads: u64,
    pub peers: u64,
    pub version: String,
}

/// Shared state for the health endpoint.
#[derive(Clone)]
pub struct HealthState {
    pub ledger: Arc<RwLock<ledger::service::LedgerService>>,
    pub peer_registry: p2p::node::PeerRegistry,
}

/// Handler for `GET /health`.
///
/// Exempt from auth even when `auth.enabled` (§2.9).
/// Returns live head and peer counts from the ledger and peer registry.
pub async fn health_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let svc = state.ledger.read().await;
    let response = HealthResponse {
        status: "ok".to_owned(),
        heads: svc.head_count() as u64,
        peers: state.peer_registry.count() as u64,
        version: env!("CARGO_PKG_VERSION").to_owned(),
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
    let mut body = String::new();
    stream
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

    #[test]
    fn test_probe_local_health_connection_refused() {
        let error = probe_local_health("127.0.0.1", 1).expect_err("nothing listens on port 1");
        assert!(error.contains("health probe"));
    }
}
