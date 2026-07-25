use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

/// Response body for `GET /health` (§2.9).
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub heads: u64,
    pub peers: u64,
    pub version: String,
}

/// Handler for `GET /health`.
///
/// Exempt from auth even when `auth.enabled` (§2.9).
/// Returns head/peer counts matching GraphQL `Health` (stubbed to 0 until M2+).
pub async fn health_handler() -> impl IntoResponse {
    let response = HealthResponse {
        status: "ok".to_owned(),
        heads: 0,
        peers: 0,
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    (StatusCode::OK, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_returns_ok() {
        let application = Router::new().route("/health", get(health_handler));
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
