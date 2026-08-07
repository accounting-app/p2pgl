use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use std::sync::Arc;
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
}
