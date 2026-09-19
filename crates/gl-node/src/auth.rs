use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Shared auth state for the middleware layer.
#[derive(Clone)]
pub struct AuthState {
    pub enabled: bool,
    pub api_key: String,
}

/// Hand-written so the API key is never printed (T41).
///
/// The derived `Debug` printed `api_key` in the clear, and this type is reachable
/// from axum's `State` extractor — so the key landed in any `{:?}` of the router
/// state, in a panic message, and in the failure output of every test that
/// asserted on auth. That last one is how it was noticed: a proof run in T36
/// printed a live-shaped key to the terminal. A `Debug` impl is the one place a
/// secret leaks without anyone choosing to log it.
///
/// `enabled` stays visible — it is policy, not a credential, and it is the field
/// anyone actually debugs.
impl std::fmt::Debug for AuthState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthState")
            .field("enabled", &self.enabled)
            .field("api_key", &redact(&self.api_key))
            .finish()
    }
}

/// Render a secret as a non-reversible summary for `Debug` output (T41).
///
/// Length plus a 4-character prefix, matching the shape T39 chose for the mesh-id
/// boot log: enough to tell "unset" from "set" and to match two values against
/// each other while triaging, never enough to replay. Short values get no prefix
/// at all — four characters of a six-character key is most of the key.
pub(crate) fn redact(secret: &str) -> String {
    if secret.is_empty() {
        return "<unset>".to_owned();
    }
    let length = secret.len();
    if length < 12 {
        return format!("<redacted, {length} bytes>");
    }
    let prefix: String = secret.chars().take(4).collect();
    format!("<redacted, {length} bytes, starts {prefix}…>")
}

impl AuthState {
    /// Does this request carry a valid `X-Api-Key`? (§3.8)
    ///
    /// This is the single decision [`auth_middleware`] makes, factored out so
    /// `/health` can ask the same question (L-09). Health is deliberately *not*
    /// behind the middleware — it must answer `200` to an unauthenticated
    /// prober — so it needs the check without the 401, and it must not grow a
    /// second, subtly different key comparison to get it.
    ///
    /// Note this answers "carries a valid key", not "is allowed through":
    /// `enabled` is the middleware's policy, not part of the credential check.
    /// With auth disabled there is no key to match, so this is `false`, and the
    /// health handler's loopback branch is what keeps a local node informative.
    pub fn request_is_authenticated(&self, headers: &axum::http::HeaderMap) -> bool {
        self.enabled
            && headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|key| api_key_matches(key, &self.api_key))
    }
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

    match auth_state.request_is_authenticated(request.headers()) {
        true => next.run(request).await,
        false => {
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

/// Constant-time API key comparison (C-1).
///
/// Both keys are reduced to fixed-length SHA-256 digests before the constant-time
/// compare, so there is no length-mismatch branch: the comparison time is
/// independent of key length and the secret's length does not leak through timing.
/// (Hashing the provided key takes time proportional to *its* length, which the
/// attacker already controls and knows; the secret's length stays hidden.)
fn api_key_matches(provided: &str, expected: &str) -> bool {
    let provided_digest = Sha256::digest(provided.as_bytes());
    let expected_digest = Sha256::digest(expected.as_bytes());
    provided_digest
        .as_slice()
        .ct_eq(expected_digest.as_slice())
        .into()
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

    /// T41: the derived `Debug` printed `api_key` verbatim. `AuthState` is axum
    /// router state, so that value reached any `{:?}` of the state, every panic
    /// message carrying it, and the failure output of every auth test — which is
    /// where it was actually spotted.
    #[test]
    fn debug_output_never_contains_the_api_key() {
        let secret = "s3cr3t-key-value-0123456789abcdef";
        let rendered = format!(
            "{:?}",
            AuthState {
                enabled: true,
                api_key: secret.to_owned(),
            }
        );
        assert!(
            !rendered.contains(secret),
            "the key must not appear in Debug output: {rendered}"
        );
        // Still useful for triage: policy, length, and a short prefix.
        assert!(rendered.contains("enabled: true"), "{rendered}");
        assert!(rendered.contains("33 bytes"), "{rendered}");

        // A short key gets no prefix at all — four characters of a six-character
        // key is most of the key.
        let short = format!(
            "{:?}",
            AuthState {
                enabled: true,
                api_key: "abcdef".to_owned(),
            }
        );
        assert!(!short.contains("abcd"), "{short}");

        // And an unset key says so rather than showing an empty string, which
        // reads as "redacted" and is the opposite of the truth.
        let unset = format!(
            "{:?}",
            AuthState {
                enabled: false,
                api_key: String::new(),
            }
        );
        assert!(unset.contains("<unset>"), "{unset}");
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

    #[test]
    fn test_api_key_matches_equal() {
        assert!(api_key_matches("test-secret", "test-secret"));
    }

    #[test]
    fn test_api_key_matches_rejects_wrong_value() {
        assert!(!api_key_matches("wrong-key", "test-secret"));
    }

    #[test]
    fn test_api_key_matches_rejects_length_mismatch() {
        assert!(!api_key_matches("short", "test-secret"));
        assert!(!api_key_matches("test-secret-extra", "test-secret"));
    }

    #[test]
    fn test_api_key_matches_rejects_same_length_wrong_key() {
        // Same length as the secret but wrong value — exercises the digest
        // compare path (both are 11 bytes).
        assert!(!api_key_matches("test-secreX", "test-secret"));
    }
}
