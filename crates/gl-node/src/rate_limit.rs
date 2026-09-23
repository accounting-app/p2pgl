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
//! schedule rather than scanned in full on every request — and it is bounded,
//! with a full table failing closed onto a shared overflow budget rather than
//! admitting untracked clients for free (M-21).

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Requests admitted per client IP per window (H-2).
pub const GRAPHQL_RATE_LIMIT: u32 = 60;

/// Sliding window used by the GraphQL limiter.
pub const GRAPHQL_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Requests admitted per client IP per window on `/health` (L-42).
///
/// A separate table from GraphQL's, and twice its budget, for two reasons. The
/// Docker `HEALTHCHECK` shares the loopback address with every other local
/// caller, so a local GraphQL client exhausting its 60/min must not be able to
/// fail the container's healthcheck; and an orchestrator running liveness and
/// readiness probes once a second each from one address sends 120/min, which
/// must pass. It still bounds what L-42 is about: an unauthenticated caller
/// taking the ledger read lock at whatever rate it likes.
pub const HEALTH_RATE_LIMIT: u32 = 120;

/// Window used by the `/health` limiter.
pub const HEALTH_RATE_WINDOW: Duration = Duration::from_secs(60);

/// The forwarding header each proxy in the chain appends its client to.
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Smallest table size that can trigger a sweep (L-24).
const PRUNE_AT: usize = 1024;

/// A sweep also runs when the table has gone this long unswept, so an idle node
/// releases the memory a burst allocated.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Hard ceiling on tracked buckets, so the table cannot be grown without bound
/// by a flood of distinct keys. What happens to a new key once it is reached is
/// the M-21 decision; see [`Buckets::overflow`].
const MAX_BUCKETS: usize = 65_536;

/// Most `X-Forwarded-For` entries examined per request, counted from the right
/// (L-36).
///
/// The walk only ever needs to step over our *own* proxies — each one appends
/// exactly one entry — so a real chain is a handful of hops. Without a cap a
/// client behind a trusted proxy could send a header of tens of thousands of
/// comma-separated entries and have every one of them split, collected and
/// parsed on every request, before the limiter has decided anything. Entries
/// beyond this are never looked at; if none of the examined ones is usable the
/// request keys on the proxy, the same fallback a missing header gets.
const MAX_FORWARDED_ENTRIES: usize = 16;

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
    ///
    /// Stored in canonical form (see [`canonical_ip`]), and every address is
    /// canonicalized before it is looked up here (M-30).
    trusted_proxies: Arc<HashSet<IpAddr>>,
    /// Set once the "an untrusted peer is forwarding for someone" warning has
    /// been logged (L-37), so it is one line per process, not one per request.
    /// Shared with [`Self::sibling`]s: it is a statement about the deployment,
    /// not about one table.
    untrusted_forwarder_warned: Arc<AtomicBool>,
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
    /// The one budget every untracked newcomer shares while the table is full
    /// (M-21).
    ///
    /// The pre-T55 rule admitted a new key at the cap **without tracking it**,
    /// reasoning that the table drains within one window. That only holds for
    /// an incidental overflow. An attacker can hold the table at the cap on
    /// purpose — touch 65,536 keys once per window, ~1,100 cheap requests a
    /// second each well under its own limit (one routed IPv6 /48 is exactly
    /// 65,536 /64 keys) — and every request from any *further* key was then
    /// admitted and never counted: a sustained, total bypass.
    ///
    /// The two alternatives, and why this one:
    ///
    /// * **Evict a bucket to make room.** Evicting a *live* bucket resets its
    ///   counter, so churning fresh keys becomes a way to wipe any chosen
    ///   client's window — the attacker's own exhausted key first of all. The
    ///   expired-soonest variant does not escape this: under a deliberate fill
    ///   every bucket is live, so it still evicts a live one, and finding the
    ///   oldest is the per-request O(n) scan L-24 removed (or a second index to
    ///   maintain). Expired buckets *are* already evicted, by the cap-time
    ///   sweep below; that is the only eviction that is free and safe.
    /// * **Refuse newcomers outright.** Fails closed, but gives one client's
    ///   flood the power to lock every new client out entirely.
    ///
    /// A shared overflow bucket is the middle: at the cap, all untracked keys
    /// together are treated as **one client**, with one client's budget. The
    /// flood from a fresh key is limited to `limit` per window no matter how
    /// many keys it rotates through; no live bucket is ever evicted, so no
    /// counter can be reset; and already-tracked clients are untouched. The
    /// cost is paid by legitimate newcomers during a full-table event, who
    /// share that one budget with the attacker — degraded, never free. A full
    /// table means 65,536 distinct clients inside one window, which on this
    /// node is an attack, not load.
    overflow: Window,
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
        let now = Instant::now();
        Self {
            inner: Arc::new(Mutex::new(Buckets {
                windows: HashMap::new(),
                last_prune: now,
                prune_at: PRUNE_AT,
                overflow: Window {
                    started: now,
                    count: 0,
                },
            })),
            limit,
            window,
            trusted_proxies: Arc::new(HashSet::new()),
            untrusted_forwarder_warned: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A limiter with its own table and budget that identifies clients exactly
    /// as this one does (L-42).
    ///
    /// `/health` gets one of these: the same trusted-proxy set — so a client
    /// behind the terminator is the same client on both routes — but counters
    /// of its own, so neither route's traffic can spend the other's budget.
    pub fn sibling(&self, limit: u32, window: Duration) -> Self {
        Self {
            trusted_proxies: Arc::clone(&self.trusted_proxies),
            untrusted_forwarder_warned: Arc::clone(&self.untrusted_forwarder_warned),
            ..Self::new(limit, window)
        }
    }

    /// Trust `X-Forwarded-For` from these reverse proxy addresses (M-04a).
    ///
    /// Entries are canonicalized (M-30), so `::ffff:10.0.0.1` in the config and
    /// a plain-IPv4 peer `10.0.0.1` — or the reverse — are the same proxy.
    pub fn with_trusted_proxies(mut self, trusted_proxies: HashSet<IpAddr>) -> Self {
        self.trusted_proxies = Arc::new(trusted_proxies.into_iter().map(canonical_ip).collect());
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
    ///
    /// Every address is canonicalized first (M-30): with `bindAddress: "::"` an
    /// IPv4 proxy arrives on the dual-stack socket as `::ffff:172.18.0.9`, which
    /// never equals the configured `172.18.0.9`. Before T55 that mismatch
    /// discarded the header silently — the operator saw the reassuring "X-Forwarded-For
    /// trusted" boot line while every client behind the terminator shared one
    /// bucket, which is M-04 re-created by a type mismatch.
    ///
    /// At most [`MAX_FORWARDED_ENTRIES`] entries are examined, from the right
    /// (L-36).
    fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = canonical_ip(peer);
        if !self.trusted_proxies.contains(&peer) {
            self.note_untrusted_forwarder(peer, headers);
            return peer;
        }
        // A chain may arrive as one header with commas, as several headers, or
        // as both. Walking the headers last-first and each one right-to-left
        // visits the entries in exactly reverse order without collecting (or
        // even splitting) anything left of the cap (L-36).
        let candidates = headers
            .get_all(X_FORWARDED_FOR)
            .iter()
            .rev()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.rsplit(','))
            .take(MAX_FORWARDED_ENTRIES)
            .filter_map(parse_forwarded_entry)
            .map(canonical_ip);
        for candidate in candidates {
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

    /// Say once, loudly, that an untrusted peer is forwarding for someone (L-37).
    ///
    /// The boot-time warning can only look at the config, and the config cannot
    /// tell a loopback dev node from a loopback node behind a same-host reverse
    /// proxy — the second is the M-04 trap (every client shares the proxy's
    /// bucket) and the first must not be nagged. The traffic can tell: curl and
    /// GraphiQL never send `X-Forwarded-For`, proxies always do. So the first
    /// such request from a peer that is not in `trustedProxies` logs one warning
    /// for the life of the process. A direct client can forge the header to
    /// trigger it, which costs nothing: it is one line, once.
    fn note_untrusted_forwarder(&self, peer: IpAddr, headers: &HeaderMap) {
        if !headers.contains_key(X_FORWARDED_FOR)
            || self
                .untrusted_forwarder_warned
                .swap(true, Ordering::Relaxed)
        {
            return;
        }
        warn!(
            %peer,
            trusted_proxies = self.trusted_proxies.len(),
            "a request from a peer that is not in trustedProxies carried X-Forwarded-For; the \
             header is ignored and the peer address is the rate-limit key. If this node sits \
             behind a reverse proxy, every client behind it now shares that proxy's single \
             bucket (M-04) — add the proxy's address to trustedProxies. Logged once"
        );
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
                // M-21: never admit free. Every untracked key shares one
                // budget while the table is full; see `Buckets::overflow` for
                // why this and not eviction or refusal.
                return self.charge_overflow(&mut buckets.overflow, now);
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

    /// Charge one request to the shared overflow budget (M-21).
    ///
    /// The same fixed-window rule as a tracked bucket. The warning fires when a
    /// fresh overflow window opens, so a sustained full-table event logs at
    /// most once per window rather than once per request.
    fn charge_overflow(&self, overflow: &mut Window, now: Instant) -> bool {
        if now.duration_since(overflow.started) >= self.window || overflow.count == 0 {
            warn!(
                max_buckets = MAX_BUCKETS,
                limit = self.limit,
                "rate-limit table is full — every client not already tracked now shares one \
                 overflow budget of `limit` requests per window (M-21); a full table means \
                 this many distinct clients inside one window, which is almost certainly a \
                 deliberate fill"
            );
            overflow.started = now;
            overflow.count = 1;
            return true;
        }
        if overflow.count >= self.limit {
            return false;
        }
        overflow.count = overflow.count.saturating_add(1);
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
///
/// Also the key the HTTP server's per-IP connection cap counts on (M-33), so
/// the two controls agree on who "one client" is.
pub(crate) fn bucket_key(ip: IpAddr) -> IpAddr {
    match canonical_ip(ip) {
        IpAddr::V4(address) => IpAddr::V4(address),
        IpAddr::V6(address) => {
            let mut octets = address.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

/// The one spelling of an address used for every comparison (M-30).
///
/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is the IPv4 address a
/// dual-stack socket reports an IPv4 peer as; it is converted back. Everything
/// else is returned unchanged — in particular this does *not* mask to a prefix,
/// because a trusted proxy is one exact host, not its /64.
pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => IpAddr::V4(mapped),
            None => ip,
        },
        IpAddr::V4(_) => ip,
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

/// Rate-limit a route by client IP, against the limiter it is layered with.
///
/// Used with `middleware::from_fn_with_state` on `/graphql` and — with its own
/// [`RateLimiter::sibling`] — on `/health` (L-42). The limiter is router state
/// rather than a request extension, so a route that is wired to this
/// middleware cannot silently run without a limiter: the pre-T55
/// extension-based version admitted everything when the extension was absent.
///
/// A request with no `ConnectInfo` (only `oneshot` in tests produces one) keys
/// on 127.0.0.1.
pub async fn rate_limit(
    State(limiter): State<RateLimiter>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    if !limiter.allow_request(peer, request.headers()) {
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

    // — M-30: a dual-stack socket reports an IPv4 proxy as v4-mapped v6 —

    #[test]
    fn test_v4_mapped_peer_matches_a_v4_trusted_proxy() {
        // `bindAddress: "::"` + an IPv4 terminator: the peer arrives as
        // `::ffff:172.18.0.9` while the config says `172.18.0.9`. Before T55
        // the two never compared equal and the header was dropped silently.
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["172.18.0.9"]));
        let mapped_proxy = ip("::ffff:172.18.0.9");
        assert_eq!(
            limiter.client_ip(mapped_proxy, &forwarded(&["203.0.113.7"])),
            ip("203.0.113.7"),
            "a v4-mapped peer must be recognized as the configured IPv4 proxy (M-30)"
        );
        // And the point of it: two clients behind that proxy, two buckets.
        assert!(limiter.allow_request(mapped_proxy, &forwarded(&["203.0.113.7"])));
        assert!(
            limiter.allow_request(mapped_proxy, &forwarded(&["203.0.113.8"])),
            "clients behind a dual-stack-reported proxy must not share one bucket"
        );
    }

    #[test]
    fn test_v4_mapped_trusted_entry_matches_a_v4_peer_and_chain() {
        // The reverse spelling, in the config and inside the chain.
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["::ffff:10.0.0.1", "::ffff:10.0.0.2"]));
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &forwarded(&["203.0.113.7, 10.0.0.2"])),
            ip("203.0.113.7"),
            "a v4-mapped config entry must trust the IPv4 peer, and skip the IPv4 hop"
        );
        assert_eq!(
            limiter.client_ip(
                ip("10.0.0.1"),
                &forwarded(&["203.0.113.7, ::ffff:10.0.0.2"])
            ),
            ip("203.0.113.7"),
            "a v4-mapped hop in the chain is still our own proxy"
        );
    }

    // — L-36: bounded X-Forwarded-For walk —

    #[test]
    fn test_forwarded_walk_is_capped() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1"]));
        // The real client sits one hop past the cap, behind a wall of junk: it
        // must not be reached — and the walk must not parse the whole header.
        let mut chain = vec!["203.0.113.7"];
        chain.extend(std::iter::repeat_n("junk", MAX_FORWARDED_ENTRIES));
        let header = chain.join(",");
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &forwarded(&[&header])),
            ip("10.0.0.1"),
            "entries beyond MAX_FORWARDED_ENTRIES from the right are never examined (L-36)"
        );

        // Just inside the cap it is still found.
        let mut chain = vec!["203.0.113.7"];
        chain.extend(std::iter::repeat_n("junk", MAX_FORWARDED_ENTRIES - 1));
        let header = chain.join(",");
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &forwarded(&[&header])),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn test_huge_forwarded_header_is_answered_from_the_right() {
        // 50,000 forged entries on the left cost nothing: the rightmost
        // untrusted entry wins after a handful of steps.
        let limiter = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1"]));
        let mut header = "1.1.1.1,".repeat(50_000);
        header.push_str("203.0.113.7");
        assert_eq!(
            limiter.client_ip(ip("10.0.0.1"), &forwarded(&[&header])),
            ip("203.0.113.7")
        );
    }

    // — L-37: runtime signal for an unlisted proxy —

    #[test]
    fn test_untrusted_forwarder_warning_is_armed_once_and_only_by_the_header() {
        let limiter = RateLimiter::new(10, Duration::from_secs(60));
        let peer = ip("127.0.0.1");
        // Loopback dev traffic (no header) must not trip it.
        limiter.client_ip(peer, &HeaderMap::new());
        assert!(!limiter.untrusted_forwarder_warned.load(Ordering::Relaxed));
        // A proxy that is not in trustedProxies does.
        limiter.client_ip(peer, &forwarded(&["203.0.113.7"]));
        assert!(limiter.untrusted_forwarder_warned.load(Ordering::Relaxed));
        // And a sibling shares the latch, so /health cannot log it a second time.
        let sibling = limiter.sibling(10, Duration::from_secs(60));
        assert!(sibling.untrusted_forwarder_warned.load(Ordering::Relaxed));
    }

    // — L-42: /health's limiter is a sibling, not a shared table —

    #[test]
    fn test_sibling_shares_identity_but_not_budget() {
        let graphql = RateLimiter::new(1, Duration::from_secs(60))
            .with_trusted_proxies(trusted(&["10.0.0.1"]));
        let health = graphql.sibling(2, Duration::from_secs(60));
        let proxy = ip("10.0.0.1");
        let client = forwarded(&["203.0.113.7"]);

        assert!(graphql.allow_request(proxy, &client));
        assert!(!graphql.allow_request(proxy, &client));
        assert!(
            health.allow_request(proxy, &client),
            "an exhausted GraphQL budget must not spend the health budget"
        );
        assert!(health.allow_request(proxy, &client));
        assert!(
            !health.allow_request(proxy, &client),
            "health has its own limit"
        );
        assert_eq!(
            health.client_ip(proxy, &client),
            ip("203.0.113.7"),
            "the sibling trusts the same proxies"
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
            limiter.allow(IpAddr::V4(Ipv4Addr::from(index)));
        }
        assert!(
            limiter.bucket_count() <= MAX_BUCKETS,
            "tracked buckets ({}) exceeded the cap",
            limiter.bucket_count()
        );
    }

    /// Fill the table to exactly [`MAX_BUCKETS`] live buckets, one request each
    /// — the M-21 attacker's once-per-window refresh.
    fn fill_to_cap(limiter: &RateLimiter) {
        for index in 0..MAX_BUCKETS as u32 {
            // 10.0.0.0/8 and up: never collides with the probe keys below.
            assert!(limiter.allow(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + index))));
        }
        assert_eq!(limiter.bucket_count(), MAX_BUCKETS);
    }

    #[test]
    fn test_full_table_does_not_admit_a_fresh_key_unlimited() {
        // M-21: with the table held at the cap, the pre-T55 limiter returned
        // `true` for any further key without inserting it — so a flood from
        // one fresh key was never counted and never limited.
        let limit = 5;
        let limiter = RateLimiter::new(limit, Duration::from_secs(60));
        fill_to_cap(&limiter);

        let flooder = ip("203.0.113.66");
        let admitted = (0..1_000).filter(|_| limiter.allow(flooder)).count();
        assert_eq!(
            admitted, limit as usize,
            "a fresh key flooding a full table must be held to one client's budget, \
             not admitted untracked (M-21)"
        );
        assert!(
            limiter.bucket_count() <= MAX_BUCKETS,
            "and the table must still not grow past the cap"
        );
    }

    #[test]
    fn test_full_table_overflow_budget_is_shared_across_fresh_keys() {
        // Rotating through fresh keys must not buy fresh budgets: at the cap all
        // untracked keys are one client (M-21).
        let limit = 3;
        let limiter = RateLimiter::new(limit, Duration::from_secs(60));
        fill_to_cap(&limiter);

        let admitted = (0..500u32)
            .filter(|index| limiter.allow(IpAddr::V4(Ipv4Addr::new(198, 51, 100, *index as u8))))
            .count();
        assert_eq!(admitted, limit as usize);
        // IPv6 /64s from one /48 — the exact M-21 key supply — share it too.
        assert!(!limiter.allow(ip("2001:db8:ffff:1::1")));
        assert!(!limiter.allow(ip("2001:db8:ffff:2::1")));
    }

    #[test]
    fn test_full_table_never_resets_a_tracked_client() {
        // The concern the old comment had right: making room must not let an
        // attacker clear a live counter. Nothing tracked is evicted, so a client
        // at its limit before the table filled is still at its limit after.
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let tracked = ip("192.0.2.1");
        assert!(limiter.allow(tracked));
        assert!(limiter.allow(tracked));
        assert!(!limiter.allow(tracked));
        for index in 0..(MAX_BUCKETS as u32 + 1_000) {
            limiter.allow(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + index)));
        }
        assert!(
            !limiter.allow(tracked),
            "churning fresh keys through a full table must not reset a live window"
        );
    }

    #[test]
    fn test_overflow_budget_renews_with_its_window() {
        // Driven with synthetic instants: filling the table takes long enough
        // on a loaded machine that a wall-clock window would expire mid-fill.
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let start = Instant::now();
        let mut overflow = Window {
            started: start,
            count: 0,
        };
        assert!(limiter.charge_overflow(&mut overflow, start));
        assert!(limiter.charge_overflow(&mut overflow, start));
        assert!(!limiter.charge_overflow(&mut overflow, start));
        let later = start + Duration::from_secs(59);
        assert!(
            !limiter.charge_overflow(&mut overflow, later),
            "same window"
        );
        let next = start + Duration::from_secs(60);
        assert!(
            limiter.charge_overflow(&mut overflow, next),
            "a new window brings a new shared budget"
        );
        assert!(limiter.charge_overflow(&mut overflow, next));
        assert!(!limiter.charge_overflow(&mut overflow, next));
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

    /// `oneshot` inserts no `ConnectInfo`, so the middleware keys on 127.0.0.1.
    /// That behavior is informational and must not change here.
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
                public_bind: false,
                auth: crate::auth::AuthState {
                    enabled: false,
                    api_key: String::new(),
                },
            },
            crate::request_guard::RequestGuardState {
                allowed_hosts: Arc::new(
                    ["127.0.0.1".to_owned(), "localhost".to_owned()]
                        .into_iter()
                        .collect(),
                ),
                allowed_origins: Arc::new(HashSet::new()),
                tls_terminated: false,
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
