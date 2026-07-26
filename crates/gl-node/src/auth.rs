use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Shared auth state for the middleware layer.
#[derive(Clone, Debug)]
pub struct AuthState {
    pub enabled: bool,
    pub api_key: String,
}

/// Axum middleware that enforces `X-Api-Key` on protected routes (§3.8).
///
/// When `auth.enabled` is false, all requests pass through.
/// When enabled, missing or mismatched `X-Api-Key` header returns HTTP 401
/// with a GraphQL-shaped error body (§2.8 `UNAUTHORIZED`).
pub async fn auth_middleware(
    axum::extract::State(auth_state): axum::extract::State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Always allow CORS preflight requests through (OPTIONS).
    if request.method() == axum::http::Method::OPTIONS {
        return next.run(request).await;
    }

    if !auth_state.enabled {
        return next.run(request).await;
    }

    let api_key_header = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok());

    match api_key_header {
        Some(key) if key == auth_state.api_key => next.run(request).await,
        _ => {
            let error_body = json!({
                "errors": [{
                    "message": "Missing or invalid API key",
                    "extensions": { "code": "UNAUTHORIZED" }
                }]
            });
            (StatusCode::UNAUTHORIZED, Json(error_body)).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn build_app(auth_state: AuthState) -> Router {
        Router::new()
            .route("/protected", get(ok_handler))
            .layer(middleware::from_fn_with_state(auth_state, auth_middleware))
    }

    #[tokio::test]
    async fn test_auth_disabled_passes_through() {
        let application = build_app(AuthState {
            enabled: false,
            api_key: String::new(),
        });
        let request = Request::get("/protected").body(Body::empty()).unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_enabled_valid_key() {
        let application = build_app(AuthState {
            enabled: true,
            api_key: "test-secret".to_owned(),
        });
        let request = Request::get("/protected")
            .header("x-api-key", "test-secret")
            .body(Body::empty())
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_enabled_missing_key() {
        let application = build_app(AuthState {
            enabled: true,
            api_key: "test-secret".to_owned(),
        });
        let request = Request::get("/protected").body(Body::empty()).unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["errors"][0]["extensions"]["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn test_auth_enabled_wrong_key() {
        let application = build_app(AuthState {
            enabled: true,
            api_key: "test-secret".to_owned(),
        });
        let request = Request::get("/protected")
            .header("x-api-key", "wrong-key")
            .body(Body::empty())
            .unwrap();
        let response = application.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
