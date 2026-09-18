//! Per-client fixed-window rate limiting for the GraphQL surface (H-2).
//!
//! Two things decide whether the limiter actually limits anything:
//!
//! * **Who the client is (M-04a).** A public bind must sit behind a
//!   TLS-terminating reverse proxy, and every request then arrives from the
//!   proxy's single socket address — so keying on the peer address puts the
//!   whole internet in one bucket, and one client starves every other. The
//!   limiter therefore honours `X-Forwarded-For`, but *only* when the peer is a
//!   configured trusted proxy, and only by the rightmost-untrusted rule (see
//!   [`RateLimiter::client_ip`]). A direct client's header is ignored outright,
//!   because it is attacker-controlled and would otherwise hand out one fresh
//!   bucket per request.
//! * **How wide a bucket is (M-04b).** IPv6 is handed out by prefix, not by
//!   address: one attacker with a /64 has 2^64 addresses. Buckets are keyed on
//!   the /64, so rotation inside an allocation shares one counter.
//!
//! Book-keeping is the third concern (L-24): the table is swept on an amortized
//! schedule rather than scanned in full on every request.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::debug;

/// Requests admitted per client IP per window (H-2).
pub const GRAPHQL_RATE_LIMIT: u32 = 60;

/// Sliding window used by the GraphQL limiter.
pub const GRAPHQL_RATE_WINDOW: Duration = Duration::from_secs(60);

/// The forwarding header each proxy in the chain appends its client to.
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Smallest table size that can trigger a sweep (L-24).
const PRUNE_AT: usize = 1024;

/// A sweep also runs when the table has gone this long unswept, so an idle node
/// releases the memory a burst allocated.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Hard ceiling on tracked buckets, so the table cannot be grown without bound
/// by a flood of distinct keys.
const MAX_BUCKETS: usize = 65_536;

/// Minimum gap between forced sweeps once the table sits at [`MAX_BUCKETS`]. At
/// the cap the size trigger is exhausted, and sweeping on every request would
/// re-create exactly the per-request O(n) scan L-24 is about.
const CAP_PRUNE_COOLDOWN: Duration = Duration::from_secs(1);

/// In-memory per-client counter. Shared across GraphQL requests.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    inner: Arc<Mutex<Buckets>>,
    limit: u32,
    window: Duration,
    /// Reverse proxies whose `X-Forwarded-For` is believed (M-04a). Empty means
    /// no header is trusted and every client is its TCP peer address.
    trusted_proxies: Arc<HashSet<IpAddr>>,
}

/// The bucket table plus the book-keeping that keeps sweeps amortized (L-24).
#[derive(Debug)]
struct Buckets {
    windows: HashMap<IpAddr, Window>,
    /// When the table was last swept.
    last_prune: Instant,
    /// Size that trips the next sweep. Recomputed after every sweep as
    /// `max(PRUNE_AT, 2 * survivors)`, so consecutive sweeps are separated by at
    /// least as many inserts as the last one had entries to scan — the scan cost
    /// is amortized O(1) per request instead of L-24's O(n).
    prune_at: usize,
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
            inner: Arc::new(Mutex::new(Buckets {
                windows: HashMap::new(),
                last_prune: Instant::now(),
                prune_at: PRUNE_AT,
            })),
            limit,
            window,
            trusted_proxies: Arc::new(HashSet::new()),
        }
    }

    /// Trust `X-Forwarded-For` from these reverse proxy addresses (M-04a).
    pub fn with_trusted_proxies(mut self, trusted_proxies: HashSet<IpAddr>) -> Self {
        self.trusted_proxies = Arc::new(trusted_proxies);
        self
    }

    /// Whether this request may proceed, keyed by the derived client address.
    pub fn allow_request(&self, peer: IpAddr, headers: &HeaderMap) -> bool {
        self.allow(self.client_ip(peer, headers))
    }

    /// Identify the client behind `peer` (M-04a).
    ///
    /// * **Peer not trusted** → the peer address, and `X-Forwarded-For` is
    ///   ignored entirely. A client talking to us directly writes its own
    ///   headers, so honouring the header there would let anyone mint a fresh
    ///   bucket per request — the limiter would stop limiting.
    /// * **Peer trusted** → the rightmost `X-Forwarded-For` entry that is not
    ///   itself a trusted proxy. Each proxy *appends* the address it saw, so the
    ///   list reads client-first and the rightmost entries are the ones our own
    ///   infrastructure wrote. Everything left of the first untrusted entry was
    ///   supplied by the client and is ignored: a request arriving with a forged
    ///   `X-Forwarded-For: 1.2.3.4` simply gets `1.2.3.4` appended-to by the
    ///   proxy, and the proxy's view of the real peer wins. Entries that do not
    ///   parse are skipped rather than trusted.
    /// * **Nothing usable** → the peer address, i.e. the proxy itself. That is
    ///   the pre-M-04 behavior (one shared bucket) and signals a misconfigured
    ///   proxy, so it is logged at debug rather than per-request warn.
    fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.trusted_proxies.contains(&peer) {
            return peer;
        }
        // A chain may arrive as one header with commas, as several headers, or
        // as both; `get_all` plus a comma split handles every shape in order.
        let forwarded: Vec<&str> = headers
            .get_all(X_FORWARDED_FOR)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .collect();
        for candidate in forwarded
            .iter()
            .rev()
            .copied()
            .filter_map(parse_forwarded_entry)
        {
            if !self.trusted_proxies.contains(&candidate) {
                return candidate;
            }
        }
        debug!(
            %peer,
            "trusted proxy sent no usable X-Forwarded-For — keying on the peer address"
        );
        peer
    }

    /// Returns true if this client may proceed.
    ///
    /// `ip` is collapsed to its bucket key first, so callers may pass a raw
    /// address (M-04b).
    pub fn allow(&self, ip: IpAddr) -> bool {
        let key = bucket_key(ip);
        let now = Instant::now();
        let mut buckets = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // L-24: sweep on a schedule, never on every request.
        if should_prune(
            buckets.windows.len(),
            buckets.prune_at,
            now.duration_since(buckets.last_prune),
        ) {
            self.prune(&mut buckets, now);
        }

        if let Some(window) = buckets.windows.get_mut(&key) {
            if now.duration_since(window.started) >= self.window {
                // The sweep is opportunistic, so an expired window can still be
                // here; rolling it over is what keeps the semantics identical.
                window.started = now;
                window.count = 1;
                return true;
            }
            if window.count >= self.limit {
                return false;
            }
            window.count = window.count.saturating_add(1);
            return true;
        }

        // A key we have never seen costs a slot.
        if buckets.windows.len() >= MAX_BUCKETS {
            if now.duration_since(buckets.last_prune) >= CAP_PRUNE_COOLDOWN {
                self.prune(&mut buckets, now);
            }
            if buckets.windows.len() >= MAX_BUCKETS {
                // Documented tradeoff: at the cap, a brand-new key is admitted
                // without being tracked. The alternatives are worse — evicting a
                // live bucket hands an attacker a way to clear any victim's
                // counter, and refusing the request fails closed on legitimate
                // users during someone else's flood. Already-tracked clients
                // stay limited throughout; only untracked newcomers slip, and
                // the table drains within one window.
                return true;
            }
        }

        buckets.windows.insert(
            key,
            Window {
                started: now,
                count: 1,
            },
        );
        true
    }

    /// Drop every expired window and re-arm the size trigger (L-24).
    fn prune(&self, buckets: &mut Buckets, now: Instant) {
        let window = self.window;
        buckets
            .windows
            .retain(|_, bucket| now.duration_since(bucket.started) < window);
        buckets.last_prune = now;
        buckets.prune_at = buckets.windows.len().saturating_mul(2).max(PRUNE_AT);
    }

    /// Tracked bucket count, for the pruning tests.
    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .windows
            .len()
    }
}

/// Whether the bucket table is due for a sweep (L-24).
///
/// The size trigger doubles after each sweep (see [`Buckets::prune_at`]), so it
/// cannot fire on consecutive requests; the time trigger bounds how long expired
/// entries linger when the table never grows.
fn should_prune(len: usize, prune_at: usize, since_last_prune: Duration) -> bool {
    len >= prune_at || since_last_prune >= PRUNE_INTERVAL
}

/// Collapse an address to its bucket key (M-04b).
///
/// IPv4 keys on the address itself. IPv6 keys on the /64 prefix: the smallest
/// allocation a provider hands an end site is a /64, so a per-/128 bucket lets a
/// single attacker rotate through 2^64 addresses for an unlimited supply of
/// fresh counters. Rotation inside a /64 must share one bucket. IPv4-mapped v6
/// addresses (`::ffff:a.b.c.d`) key as the IPv4 address they carry, so a
/// dual-stack socket cannot yield a second bucket for the same client.
fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => IpAddr::V4(mapped),
            None => {
                let mut octets = address.octets();
                octets[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        },
    }
}

/// Parse one `X-Forwarded-For` entry defensively (M-04a).
///
/// Accepts a bare literal, a literal with a port, and the bracketed IPv6 forms;
/// anything else (an obfuscated identifier, `unknown`, a hostname, a zone id)
/// yields `None` and is skipped by the caller.
fn parse_forwarded_entry(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    // "203.0.113.7" / "2001:db8::1"
    if let Ok(address) = entry.parse::<IpAddr>() {
        return Some(address);
    }
    // "203.0.113.7:443" / "[2001:db8::1]:443"
    if let Ok(socket) = entry.parse::<SocketAddr>() {
        return Some(socket.ip());
    }
    // "[2001:db8::1]" — bracketed without a port.
    entry
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<IpAddr>().ok())
}

/// Rate-limit `/graphql` by client IP. Health is not wrapped by this middleware.
pub async fn graphql_rate_limit(request: Request<Body>, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let allowed = request
        .extensions()
        .get::<RateLimiter>()
        .map(|limiter| limiter.allow_request(peer, request.headers()))
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
    use axum::http::{header, HeaderValue};
    use std::net::Ipv4Addr;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address should parse")
    }

    fn trusted(entries: &[&str]) -> HashSet<IpAddr> {
        entries.iter().map(|entry| ip(entry)).collect()
    }

    /// One `X-Forwarded-For` header per element, in order.
    fn forwarded(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                X_FORWARDED_FOR,
                HeaderValue::from_str(value).expect("test header should be valid"),
            );
        }
        headers
    }

    // — Window semantics (unchanged by T34) —

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

    // — M-04a: key derivation from X-Forwarded-For —

    #[test]
    fn test_untrusted_peer_ignores_forwarded_for() {
        // The spoof case: a direct client sets the header itself, so it must
        // count for nothing — otherwise every request buys a fresh bucket.
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1"]));
        let peer = ip("198.51.100.9");
        let headers = forwarded(&["203.0.113.7"]);
        assert_eq!(limiter.client_ip(peer, &headers), peer);

        assert!(limiter.allow_request(peer, &forwarded(&["203.0.113.1"])));
        assert!(
            !limiter.allow_request(peer, &forwarded(&["203.0.113.2"])),
            "rotating the forged header must not reset an untrusted peer's bucket"
        );
    }

    #[test]
    fn test_trusted_peer_uses_rightmost_untrusted_entry() {
        // "client, proxy2" with proxy2 trusted: proxy2 appended what it saw, so
        // the client is the entry to its left.
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1", "10.0.0.2"]));
        let headers = forwarded(&["203.0.113.7, 10.0.0.2"]);
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &headers),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn test_spoofed_left_entries_are_ignored() {
        // M-04a anti-spoof: the client prepended two forged entries before the
        // real chain. Only the rightmost untrusted entry — the one our own
        // edge proxy wrote — may win.
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1", "10.0.0.2"]));
        let headers = forwarded(&["1.1.1.1, 2.2.2.2, 203.0.113.7, 10.0.0.2"]);
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &headers),
            ip("203.0.113.7"),
            "a naive leftmost parse would hand the attacker a new bucket per forged entry"
        );

        // And the spoof cannot buy extra budget: both requests share one bucket.
        assert!(limiter.allow_request(ip("10.0.0.1"), &headers));
        let rotated = forwarded(&["9.9.9.9, 203.0.113.7, 10.0.0.2"]);
        assert!(!limiter.allow_request(ip("10.0.0.1"), &rotated));
    }

    #[test]
    fn test_trusted_peer_with_all_trusted_chain_falls_back_to_peer() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1", "10.0.0.2"]));
        let headers = forwarded(&["10.0.0.2, 10.0.0.1"]);
        assert_eq!(limiter.client_ip(ip("10.0.0.1"), &headers), ip("10.0.0.1"));
    }

    #[test]
    fn test_trusted_peer_without_forwarded_header_falls_back_to_peer() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1"]));
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &HeaderMap::new()),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn test_garbage_forwarded_entries_are_skipped() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1"]));
        let headers = forwarded(&["203.0.113.7, unknown, _hidden, , not-an-ip"]);
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &headers),
            ip("203.0.113.7"),
            "unparseable entries are skipped, not trusted"
        );
    }

    #[test]
    fn test_forwarded_entries_with_ports_and_brackets() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1"]));
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &forwarded(&["203.0.113.7:51234"])),
            ip("203.0.113.7")
        );
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &forwarded(&["[2001:db8::7]:51234"])),
            ip("2001:db8::7")
        );
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &forwarded(&["[2001:db8::7]"])),
            ip("2001:db8::7")
        );
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &forwarded(&["  203.0.113.7  "])),
            ip("203.0.113.7"),
            "surrounding whitespace is trimmed"
        );
    }

    #[test]
    fn test_multiple_forwarded_headers_are_concatenated_in_order() {
        // Two separate headers are equivalent to one comma-joined header, and
        // "rightmost" spans the whole concatenation.
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1", "10.0.0.2"]));
        let split = forwarded(&["1.1.1.1, 203.0.113.7", "10.0.0.2"]);
        assert_eq!(limiter.client_ip(ip("10.0.0.1"), &split), ip("203.0.113.7"));

        let joined = forwarded(&["1.1.1.1, 203.0.113.7, 10.0.0.2"]);
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &joined),
            limiter.client_ip(ip("10.0.0.1"), &split)
        );
    }

    #[test]
    fn test_empty_trusted_set_never_reads_the_header() {
        // The default is fail-closed: no proxy is trusted, so no header is read.
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let peer = ip("10.0.0.1");
        assert_eq!(
            limiter.client_ip(peer, &forwarded(&["203.0.113.7"])),
            peer,
            "empty trustedProxies must behave exactly like the pre-M-04 limiter"
        );
    }

    #[test]
    fn test_trusted_proxies_separate_distinct_clients() {
        // The point of the whole exercise: two clients behind one proxy get two
        // buckets instead of sharing the proxy's single one.
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1"]));
        let proxy = ip("10.0.0.1");
        assert!(limiter.allow_request(proxy, &forwarded(&["203.0.113.7"])));
        assert!(!limiter.allow_request(proxy, &forwarded(&["203.0.113.7"])));
        assert!(
            limiter.allow_request(proxy, &forwarded(&["203.0.113.8"])),
            "a second client behind the same proxy must not inherit the first's window"
        );
    }

    // — M-04b: IPv6 /64 bucketing —

    #[test]
    fn test_ipv6_addresses_in_one_slash64_share_a_bucket() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        let first = ip("2001:db8:1:2::1");
        let second = ip("2001:db8:1:2:ffff:ffff:ffff:ffff");
        assert!(limiter.allow(first));
        assert!(
            !limiter.allow(second),
            "rotating inside a /64 must count against the same window"
        );
    }

    #[test]
    fn test_ipv6_different_slash64_get_separate_buckets() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.allow(ip("2001:db8:1:2::1")));
        assert!(limiter.allow(ip("2001:db8:1:3::1")));
    }

    #[test]
    fn test_bucket_key_masks_only_the_interface_identifier() {
        assert_eq!(
            bucket_key(ip("2001:db8:1:2:3:4:5:6")),
            ip("2001:db8:1:2::"),
            "the low 64 bits are zeroed and the /64 prefix is kept"
        );
    }

    #[test]
    fn test_ipv4_is_not_masked() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert_eq!(bucket_key(ip("203.0.113.7")), ip("203.0.113.7"));
        assert!(limiter.allow(ip("203.0.113.7")));
        assert!(
            limiter.allow(ip("203.0.113.8")),
            "neighbouring IPv4 addresses stay independent"
        );
    }

    #[test]
    fn test_ipv4_mapped_ipv6_keys_as_the_ipv4_address() {
        assert_eq!(bucket_key(ip("::ffff:203.0.113.7")), ip("203.0.113.7"));
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.allow(ip("::ffff:203.0.113.7")));
        assert!(
            !limiter.allow(ip("203.0.113.7")),
            "the same client over a dual-stack socket must not get a second bucket"
        );
    }

    // — L-24: bounded, amortized pruning —

    #[test]
    fn test_should_prune_triggers() {
        // Size trigger.
        assert!(should_prune(PRUNE_AT, PRUNE_AT, Duration::ZERO));
        assert!(!should_prune(PRUNE_AT - 1, PRUNE_AT, Duration::ZERO));
        // Time trigger, regardless of size.
        assert!(should_prune(0, PRUNE_AT, PRUNE_INTERVAL));
        assert!(!should_prune(
            0,
            PRUNE_AT,
            PRUNE_INTERVAL - Duration::from_millis(1)
        ));
    }

    #[test]
    fn test_bucket_table_stays_under_the_cap_under_a_flood() {
        // L-24 / memory bound: a flood of distinct keys must neither grow the
        // table without limit nor (the original bug) scan it on every request.
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        for index in 0..(MAX_BUCKETS as u32 + 4096) {
            assert!(
                limiter.allow(IpAddr::V4(Ipv4Addr::from(index))),
                "a first request from a new key is always admitted"
            );
        }
        assert!(
            limiter.bucket_count() <= MAX_BUCKETS,
            "tracked buckets ({}) exceeded the cap",
            limiter.bucket_count()
        );
    }

    #[test]
    fn test_expired_entries_are_pruned_when_the_size_trigger_trips() {
        let limiter = RateLimiter::new(1, Duration::from_millis(10));
        for index in 0..600u32 {
            assert!(limiter.allow(IpAddr::V4(Ipv4Addr::from(index))));
        }
        assert_eq!(limiter.bucket_count(), 600);
        std::thread::sleep(Duration::from_millis(25));
        for index in 600..1600u32 {
            assert!(limiter.allow(IpAddr::V4(Ipv4Addr::from(index))));
        }
        let tracked = limiter.bucket_count();
        assert!(
            tracked < 1600,
            "the first 600 windows had expired and should have been swept, still tracking {tracked}"
        );
    }

    #[test]
    fn test_limit_is_still_enforced_after_a_sweep() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let victim = ip("203.0.113.7");
        assert!(limiter.allow(victim));
        assert!(limiter.allow(victim));
        // Push the table past the size trigger so at least one sweep runs.
        for index in 0..(PRUNE_AT as u32 * 3) {
            limiter.allow(IpAddr::V4(Ipv4Addr::from(index)));
        }
        assert!(
            !limiter.allow(victim),
            "a live window must survive the sweep and keep denying over-limit requests"
        );
    }

    // — Router-level smoke test: the real assembled application —

    /// `oneshot` inserts no `ConnectInfo`, so the middleware takes its recorded
    /// fail-open path and keys on 127.0.0.1. That behavior is informational and
    /// must not change here.
    #[tokio::test]
    async fn test_graphql_request_still_passes_through_the_limiter() {
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let directory = tempfile::tempdir().expect("temp dir");
        let bean_path = directory.path().join("rate_limit.bean");
        std::fs::write(&bean_path, "").expect("create ledger file");
        let service = ledger::service::LedgerService::boot(&bean_path, "test-node".to_owned())
            .expect("ledger should boot");
        let shared: crate::graphql::SharedLedger = Arc::new(tokio::sync::RwLock::new(service));
        let peer_registry = p2p::node::PeerRegistry::new();
        let schema = crate::graphql::build_schema_with_service(
            shared.clone(),
            crate::graphql::broadcast::TransactionBroadcast::new(),
            peer_registry.clone(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );
        let application = crate::build_application(
            schema,
            crate::auth::AuthState {
                enabled: false,
                api_key: String::new(),
            },
            crate::health::HealthState {
                ledger: shared,
                peer_registry,
            },
            crate::request_guard::RequestGuardState {
                allowed_hosts: Arc::new(
                    ["127.0.0.1".to_owned(), "localhost".to_owned()]
                        .into_iter()
                        .collect(),
                ),
                allowed_origins: Arc::new(HashSet::new()),
            },
            tower_http::cors::CorsLayer::new(),
            true,
        );

        // A forged X-Forwarded-For must not change the outcome: the default
        // trusted-proxy set is empty, so the header is never read.
        let request = Request::post("/graphql")
            .header(header::HOST, "127.0.0.1:4000")
            .header(header::CONTENT_TYPE, "application/json")
            .header(X_FORWARDED_FOR, "203.0.113.7")
            .body(Body::from(r#"{"query":"{ __typename }"}"#))
            .expect("request should build");
        let response = application.oneshot(request).await.expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body should collect")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("body should be JSON");
        assert_eq!(body["data"]["__typename"], "QueryRoot");
    }
}
