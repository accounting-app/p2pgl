use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Requests admitted per client IP per window (H-2).
pub const GRAPHQL_RATE_LIMIT: u32 = 60;

/// Sliding window used by the GraphQL limiter.
pub const GRAPHQL_RATE_WINDOW: Duration = Duration::from_secs(60);

/// In-memory per-IP counter. Shared across GraphQL requests.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, Window>>>,
    limit: u32,
    window: Duration,
}

#[derive(Debug)]
struct Window {
    started: Instant,
    count: u32,
}

impl RateLimiter {
    pub fn graphql() -> Self {
        Self::new(GRAPHQL_RATE_LIMIT, GRAPHQL_RATE_WINDOW)
    }

    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            limit,
            window,
        }
    }

    /// Returns true if this IP may proceed.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut buckets = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        buckets.retain(|_, window| now.duration_since(window.started) < self.window);
        let window = buckets.entry(ip).or_insert(Window {
            started: now,
            count: 0,
        });
        if now.duration_since(window.started) >= self.window {
            window.started = now;
            window.count = 0;
        }
        if window.count >= self.limit {
            return false;
        }
        window.count = window.count.saturating_add(1);
        true
    }
}

/// Rate-limit `/graphql` by client IP. Health is not wrapped by this middleware.
pub async fn graphql_rate_limit(request: Request<Body>, next: Next) -> Response {
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let allowed = request
        .extensions()
        .get::<RateLimiter>()
        .map(|limiter| limiter.allow(ip))
        .unwrap_or(true);
    if !allowed {
        let error_body = json!({
            "errors": [{
                "message": "Rate limit exceeded",
                "extensions": { "code": "RATE_LIMITED" }
            }]
        });
        return (StatusCode::TOO_MANY_REQUESTS, axum::Json(error_body)).into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_allows_under_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }

    #[test]
    fn test_limits_are_per_ip() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(limiter.allow(a));
        assert!(!limiter.allow(a));
        assert!(limiter.allow(b));
    }
}
