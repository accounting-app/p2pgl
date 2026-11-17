//! One log line per HTTP request, like a Heroku router line (build-logs 009,
//! 010).
//!
//! ```text
//! INFO http: ledger=acme method=POST path=/ledgers/acme/graphql operation=AddTransaction user=u_7f3a… status=200 errors=0 ms=12 client=203.0.113.9
//! ```
//!
//! [`request_log`] is the outermost layer of the node's router, outside CORS
//! and the body limit, so it sees every answer the router makes, and every
//! request gets its line: strangers' 401s, 429s, guard refusals, preflights,
//! 413s, 404s, `/health` and requests cut short included (010). A request a
//! key let through carries a [`RequestNote`] — only code behind a key attaches
//! one: the GraphQL handlers, after `auth_middleware` or `operator_only`, and
//! `take_a_slot`'s 503 — which fills in its `user` and `operation`; every other
//! line says `-` for both.
//! A line with a note has the target `http`; a stranger's, `http::stranger`, so
//! `RUST_LOG=…,http::stranger=off` leaves strangers out (010).
//!
//! **No budget bounds these lines** (010, the maintainer's decision): a caller
//! with no key writes one line per request it sends, as fast as it sends them.
//! That is M-41's shape, accepted for the request line
//! (`docs/audits/OUTSTANDING_TASKS_11_16.md`). What M-41 also asked for still
//! holds: every value is a constant or checked, and anything a caller chose
//! is escaped here (tracing-subscriber 0.3.23 does not escape CR or LF), so no
//! value can start a line, and the line stays under 512 bytes. Never the key,
//! a header, the body, the query text, its variables or the URL's query
//! string.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tracing::{info, warn};

use crate::access_control::{Caller, CallerId};
use crate::config::{is_valid_ledger_name, DEFAULT_LEDGER};
use crate::rate_limit::RateLimiter;

/// Most bytes of a path the line shows, after escaping (M-41's bar).
const MAX_PATH_BYTES: usize = 128;

/// Longest GraphQL operation name the line shows; a longer one is `?`.
const MAX_OPERATION_CHARS: usize = 64;

/// What a handler behind a key tells the request line (009): who asked, the
/// operation's name and the count of errors. Carried in the response's
/// extensions, so an answer nobody behind a key made carries none, and its
/// line says `user=- operation=-`.
#[derive(Clone, Debug)]
pub(crate) struct RequestNote {
    user: String,
    operation: String,
    errors: usize,
}

impl RequestNote {
    /// The note for a request `caller` made, named `operation_name` by its
    /// client, whose answer carried `errors` GraphQL errors.
    pub(crate) fn new(
        caller: Option<&Caller>,
        operation_name: Option<&str>,
        errors: usize,
    ) -> Self {
        RequestNote {
            user: user_field(caller).to_owned(),
            operation: operation_field(operation_name).to_owned(),
            errors,
        }
    }

    /// Attach this note to `response`.
    pub(crate) fn attach(self, mut response: Response) -> Response {
        response.extensions_mut().insert(self);
        response
    }
}

/// The request line's state: who a client is.
#[derive(Clone)]
pub(crate) struct RequestLogState {
    /// A twin of the node's limiter, for its idea of the client (the
    /// rightmost-untrusted `X-Forwarded-For` rule, L-36, L-37, M-04).
    clients: RateLimiter,
}

impl RequestLogState {
    /// The request line for a node whose limiter is `limiter`.
    pub(crate) fn new(limiter: &RateLimiter) -> Self {
        RequestLogState {
            clients: limiter.twin(),
        }
    }
}

/// What the line knows before the request runs.
struct Head {
    ledger: String,
    method: String,
    path: String,
    client: IpAddr,
    started: Instant,
}

/// Writes the line for a request that never finished (009): the router's
/// future is dropped by `serve_hardened`'s `TimeoutLayer` (408) and by a
/// client that hangs up, and the request still gets its line.
struct CutShort {
    head: Option<Head>,
}

impl Drop for CutShort {
    fn drop(&mut self) {
        if let Some(head) = self.head.take() {
            write_line(&head, None, None);
        }
    }
}

/// The request line's middleware (009): the outermost layer of the node's
/// router.
pub(crate) async fn request_log(
    State(state): State<RequestLogState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let head = Head {
        ledger: ledger_field(path),
        method: method_field(request.method()).to_owned(),
        path: escaped(path, MAX_PATH_BYTES),
        client: state.clients.client_of(&request),
        started: Instant::now(),
    };
    let mut cut_short = CutShort { head: Some(head) };
    let response = next.run(request).await;
    if let Some(head) = cut_short.head.take() {
        write_line(
            &head,
            Some(response.status()),
            response.extensions().get::<RequestNote>(),
        );
    }
    response
}

/// The level a line is written at (009 decision 3; 010: a passing `/health`
/// too is `INFO`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Info,
    Warn,
}

fn level_of(status: Option<StatusCode>) -> Level {
    match status {
        Some(status) if status.as_u16() < 400 => Level::Info,
        _ => Level::Warn,
    }
}

fn enabled(level: Level, stranger: bool) -> bool {
    match (level, stranger) {
        (Level::Info, false) => tracing::enabled!(target: "http", tracing::Level::INFO),
        (Level::Warn, false) => tracing::enabled!(target: "http", tracing::Level::WARN),
        (Level::Info, true) => tracing::enabled!(target: "http::stranger", tracing::Level::INFO),
        (Level::Warn, true) => tracing::enabled!(target: "http::stranger", tracing::Level::WARN),
    }
}

/// Write the line for one request. `status` is `None` for a request cut
/// short; `note` is there when a key let the request through.
///
/// A stranger's line — one without a note — has the target
/// `http::stranger` (010), so `RUST_LOG=…,http::stranger=off` leaves them out
/// and keeps the key holders'; `http=off` matches both targets (a filter's
/// target is a prefix) and leaves out every request line.
fn write_line(head: &Head, status: Option<StatusCode>, note: Option<&RequestNote>) {
    let level = level_of(status);
    let stranger = note.is_none();
    // A line the filter drops is not even formatted.
    if !enabled(level, stranger) {
        return;
    }
    let line = line(head, status, note);
    match (level, stranger) {
        (Level::Info, false) => info!(target: "http", "{line}"),
        (Level::Warn, false) => warn!(target: "http", "{line}"),
        (Level::Info, true) => info!(target: "http::stranger", "{line}"),
        (Level::Warn, true) => warn!(target: "http::stranger", "{line}"),
    }
}

/// The line's text: `ledger method path operation user status errors ms
/// client`, then `cut_short=true` for a request that never finished.
fn line(head: &Head, status: Option<StatusCode>, note: Option<&RequestNote>) -> String {
    let (operation, user, errors) = match note {
        Some(note) => (note.operation.as_str(), note.user.as_str(), note.errors),
        None => ("-", "-", 0),
    };
    let status = status.map_or_else(|| "-".to_owned(), |status| status.as_u16().to_string());
    let mut line = format!(
        "ledger={} method={} path={} operation={operation} user={user} status={status} \
         errors={errors} ms={} client={}",
        head.ledger,
        head.method,
        head.path,
        head.started.elapsed().as_millis(),
        head.client,
    );
    if status == "-" {
        line.push_str(" cut_short=true");
    }
    line
}

/// The ledger a path names (009): `default` for the config file's ledger's
/// routes, the name in `/ledgers/NAME/…` **percent-decoded as axum's `Path`
/// decodes it** when it is a valid ledger name — so `/ledgers/acm%65/graphql`,
/// which serves `acme`, logs `acme` — and `-` otherwise.
fn ledger_field(path: &str) -> String {
    if matches!(path, "/graphql" | "/health" | "/plaid/webhook") {
        return DEFAULT_LEDGER.to_owned();
    }
    let Some(rest) = path.strip_prefix("/ledgers/") else {
        return "-".to_owned();
    };
    let segment = rest.split('/').next().unwrap_or_default();
    match percent_encoding::percent_decode_str(segment).decode_utf8() {
        Ok(name) if is_valid_ledger_name(&name) => name.into_owned(),
        _ => "-".to_owned(),
    }
}

/// A standard method's name, and `?` for any other: http 1.x accepts an
/// extension method of any length up to hyper's 64 KiB head, chosen by the
/// caller.
fn method_field(method: &Method) -> &'static str {
    const STANDARD: [&str; 9] = [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH", "TRACE",
    ];
    STANDARD
        .into_iter()
        .find(|standard| *standard == method.as_str())
        .unwrap_or("?")
}

/// The operation name a client sent when it is a GraphQL `Name` of at most
/// [`MAX_OPERATION_CHARS`], `-` when it sent none, `?` otherwise.
fn operation_field(name: Option<&str>) -> &str {
    match name {
        None | Some("") => "-",
        Some(name) if is_graphql_name(name) => name,
        Some(_) => "?",
    }
}

fn is_graphql_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= MAX_OPERATION_CHARS
        && bytes
            .next()
            .is_some_and(|first| first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

/// `operator`, the person's user id, or `-` — from the caller's identity,
/// never from a key. A user id is `u_` and 16 hex digits (64 random bits,
/// `access_list::new_user_id`); one of any other shape is `?`.
fn user_field(caller: Option<&Caller>) -> &str {
    match caller.map(|caller| &caller.who) {
        None => "-",
        Some(CallerId::Operator) => "operator",
        Some(CallerId::User(id))
            if id.len() <= 32
                && id
                    .bytes()
                    .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) =>
        {
            id
        }
        Some(CallerId::User(_)) => "?",
    }
}

/// `value` with every control and whitespace character written as `\u{…}`,
/// cut to at most `max_bytes` on a character boundary and marked `…` when cut.
/// No escaped value can start a line, or end a field early (M-41).
pub(crate) fn escaped(value: &str, max_bytes: usize) -> String {
    let mut out = String::new();
    for character in value.chars() {
        if character.is_control() || character.is_whitespace() {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(character));
        } else {
            out.push(character);
        }
        if out.len() > max_bytes {
            let mut cut = max_bytes;
            while !out.is_char_boundary(cut) {
                cut -= 1;
            }
            out.truncate(cut);
            out.push('…');
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::time::Duration;

    use axum::extract::ConnectInfo;
    use axum::Router;
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::ledgers::test_node::{hold_every_slot, node, node_with, OPERATOR};
    use crate::test_support::capture_logs;

    const READ: &str = "{ verify { ok } }";
    const PEER: [u8; 4] = [198, 51, 100, 4];

    /// A request from `peer`, with `body` as JSON (none when null).
    fn request(
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Value,
        peer: [u8; 4],
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1")
            .header("content-type", "application/json");
        if let Some(key) = key {
            builder = builder.header("x-api-key", key);
        }
        let body = if body.is_null() {
            Body::empty()
        } else {
            Body::from(body.to_string())
        };
        let mut request = builder.body(body).expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((peer, 40_000))));
        request
    }

    /// `request` with `X-Forwarded-For: forwarded`.
    fn forwarded(mut request: Request<Body>, forwarded: &str) -> Request<Body> {
        request
            .headers_mut()
            .insert("x-forwarded-for", forwarded.parse().expect("header value"));
        request
    }

    async fn answer(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
        let response = app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn query(text: &str) -> Value {
        json!({ "query": text })
    }

    /// The request lines (targets `http` and `http::stranger`) in `logged`.
    fn http_lines(logged: &str) -> Vec<&str> {
        logged
            .lines()
            .filter(|line| line.contains(" http: ") || line.contains(" http::stranger: "))
            .collect()
    }

    /// A read key on `acme`, granted by the operator.
    async fn read_key(app: &Router) -> String {
        let (status, body) = answer(
            app,
            request(
                "POST",
                "/ledgers/acme/graphql",
                Some(OPERATOR),
                query(r#"mutation { grantAccess(name: "Ana Ruiz", role: READ) { key } }"#),
                [127, 0, 0, 1],
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["data"]["grantAccess"]["key"]
            .as_str()
            .unwrap_or_else(|| panic!("a key in {body}"))
            .to_owned()
    }

    fn trusting_loopback() -> RateLimiter {
        RateLimiter::graphql().with_trusted_proxies(HashSet::from([IpAddr::from([127, 0, 0, 1])]))
    }

    /// 009: a read key's query on `acme` writes one `INFO` line naming the
    /// ledger, the method, the path, the operation, the person's user id, the
    /// status, the error count, the time taken and the client — and nothing
    /// after the client.
    ///
    /// Bug-catch: remove the layer from the node's router (NL-R1) and there is
    /// no line; stop `graphql_handler` attaching its note (NL-R2) and the line
    /// says `user=- operation=-`.
    #[tokio::test]
    async fn a_keyed_request_logs_one_line_with_ledger_user_operation_and_status() {
        let (_dir, app, _, _, _) = node();
        let key = read_key(&app).await;
        let ((status, body), logged) = capture_logs(
            "info",
            answer(
                &app,
                request(
                    "POST",
                    "/ledgers/acme/graphql",
                    Some(&key),
                    json!({ "query": "query Books { verify { ok } }", "operationName": "Books" }),
                    PEER,
                ),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 1, "{logged}");
        let line = lines[0];
        let start = " INFO http: ledger=acme method=POST path=/ledgers/acme/graphql \
                     operation=Books user=u_";
        let user = line.split_once(start).unwrap_or_else(|| panic!("{line}")).1;
        let (id, rest) = user.split_once(' ').expect("fields after the user");
        assert_eq!(id.len(), 16, "{line}");
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()), "{line}");
        assert!(rest.starts_with("status=200 errors=0 ms="), "{line}");
        assert!(rest.ends_with(" client=198.51.100.4"), "{line}");
    }

    /// 010: every request writes its own line, a stranger's too — wrong
    /// keys until the budget answers 429, a guard refusal, a preflight, a 413,
    /// a 404 and a 405 — in order, each with its status and its level, and
    /// none of them summarized (`suppressed=`).
    ///
    /// Bug-catch: leave out a request without a note (NL-R17) and only the
    /// requests a key let through are in the log.
    #[tokio::test]
    async fn every_request_logs_a_line_of_its_own_strangers_included() {
        let (_dir, app, _, _, _) = node();
        let (expected, logged) = capture_logs("info", async {
            let mut expected = Vec::new();
            let mut ask = |request: Request<Body>, status: StatusCode| {
                expected.push(status);
                let app = app.clone();
                async move {
                    let (answered, body) = answer(&app, request).await;
                    assert_eq!(answered, status, "{body}");
                }
            };
            for _ in 0..crate::rate_limit::GRAPHQL_RATE_LIMIT {
                let wrong = request(
                    "POST",
                    "/ledgers/acme/graphql",
                    Some("wrong"),
                    query(READ),
                    PEER,
                );
                ask(wrong, StatusCode::UNAUTHORIZED).await;
            }
            let spent = request("POST", "/ledgers/acme/graphql", None, query(READ), PEER);
            ask(spent, StatusCode::TOO_MANY_REQUESTS).await;
            let mut foreign = request("POST", "/graphql", None, query(READ), PEER);
            foreign
                .headers_mut()
                .insert("host", "evil.example".parse().expect("host"));
            ask(foreign, StatusCode::FORBIDDEN).await;
            let mut preflight = request("OPTIONS", "/graphql", None, Value::Null, PEER);
            preflight
                .headers_mut()
                .insert("origin", "https://app.example".parse().expect("origin"));
            preflight.headers_mut().insert(
                "access-control-request-method",
                "POST".parse().expect("method"),
            );
            ask(preflight, StatusCode::OK).await;
            let mut large = request("POST", "/graphql", Some(OPERATOR), Value::Null, PEER);
            *large.body_mut() = Body::from(vec![b' '; 2 * 1024 * 1024 + 1]);
            large.headers_mut().insert(
                "content-length",
                (2 * 1024 * 1024 + 1).to_string().parse().expect("length"),
            );
            ask(large, StatusCode::PAYLOAD_TOO_LARGE).await;
            ask(
                request("GET", "/nowhere", None, Value::Null, PEER),
                StatusCode::NOT_FOUND,
            )
            .await;
            ask(
                request("GET", "/ledgers/acme/graphql", None, Value::Null, PEER),
                StatusCode::METHOD_NOT_ALLOWED,
            )
            .await;
            expected
        })
        .await;
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), expected.len(), "{logged}");
        for (line, status) in lines.iter().zip(&expected) {
            let level = if status.as_u16() < 400 {
                " INFO"
            } else {
                " WARN"
            };
            assert!(
                line.contains(&format!("{level} http::stranger: ")),
                "{line}"
            );
            assert!(
                line.contains(&format!(" user=- status={} ", status.as_u16())),
                "{line}"
            );
            assert!(line.ends_with(" client=198.51.100.4"), "{line}");
        }
        assert!(
            lines.iter().all(|line| !line.contains("suppressed=")),
            "{logged}"
        );
    }

    /// 009, H-01, L-23: the log never carries the key, a variable's value, the
    /// query text or a URL's query string — at the default filter with the
    /// request line fully on, for a keyed request and a stranger's alike.
    ///
    /// Bug-catch: log `uri` instead of `uri.path()` (NL-R8) and the query
    /// string, `?api_key=…` included, is in the line.
    #[tokio::test]
    async fn the_log_never_carries_the_key_the_variables_the_query_or_a_query_string() {
        let (_dir, app, _, _, _) = node();
        let key = read_key(&app).await;
        let ((), logged) = capture_logs("info,http=trace", async {
            let keyed = request(
                "POST",
                "/ledgers/acme/graphql?api_key=QUERY-STRING-SECRET",
                Some(&key),
                json!({
                    "query": "query Books($name: String) { QUERYTEXTMARKER: verify { ok } }",
                    "operationName": "Books",
                    "variables": { "name": "VARIABLE-VALUE-SECRET" },
                }),
                PEER,
            );
            assert_eq!(answer(&app, keyed).await.0, StatusCode::OK);
            let stranger = request(
                "GET",
                "/graphql?query=STRANGER-QUERY-SECRET",
                Some(OPERATOR),
                Value::Null,
                [203, 0, 113, 9],
            );
            assert_eq!(
                answer(&app, stranger).await.0,
                StatusCode::METHOD_NOT_ALLOWED
            );
        })
        .await;
        assert_eq!(http_lines(&logged).len(), 2, "{logged}");
        for secret in [
            key.as_str(),
            OPERATOR,
            "QUERY-STRING-SECRET",
            "VARIABLE-VALUE-SECRET",
            "QUERYTEXTMARKER",
            "STRANGER-QUERY-SECRET",
            "api_key",
        ] {
            assert!(!logged.contains(secret), "{secret} in {logged}");
        }
    }

    /// 009, M-04, L-36, L-37: behind a trusted proxy the line's `client` is
    /// the address the proxy forwarded (the rightmost one it did not write
    /// itself); from a peer not in `trustedProxies` it is the peer, whatever
    /// `X-Forwarded-For` it sends.
    ///
    /// Bug-catch: take `client` from the TCP peer (NL-R3) and every client
    /// behind the installer's Caddy is `127.0.0.1`.
    #[tokio::test]
    async fn the_client_is_the_forwarded_address_only_behind_a_trusted_proxy() {
        let (_dir, app, _, _, _) = node_with(trusting_loopback());
        let ((), logged) = capture_logs("info", async {
            let behind = forwarded(
                request(
                    "POST",
                    "/graphql",
                    Some(OPERATOR),
                    query(READ),
                    [127, 0, 0, 1],
                ),
                "198.51.100.77, 203.0.113.9",
            );
            assert_eq!(answer(&app, behind).await.0, StatusCode::OK);
            let direct = forwarded(
                request("POST", "/graphql", Some(OPERATOR), query(READ), PEER),
                "203.0.113.50",
            );
            assert_eq!(answer(&app, direct).await.0, StatusCode::OK);
        })
        .await;
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 2, "{logged}");
        assert!(lines[0].ends_with(" client=203.0.113.9"), "{logged}");
        assert!(lines[1].ends_with(" client=198.51.100.4"), "{logged}");
    }

    /// 009, 010, M-04: behind one proxy, each stranger's request is logged
    /// with the address the proxy forwarded, not the proxy's own, which is
    /// every client's TCP peer — one line per request.
    ///
    /// Bug-catch: take `client` from the TCP peer (NL-R3) and every stranger
    /// behind the installer's Caddy is `127.0.0.1`.
    #[tokio::test]
    async fn strangers_behind_one_proxy_are_logged_with_their_forwarded_address() {
        let (_dir, app, _, _, _) = node_with(trusting_loopback());
        let ((), logged) = capture_logs("info", async {
            for client in ["203.0.113.1", "203.0.113.2", "203.0.113.1", "203.0.113.2"] {
                let wrong = forwarded(
                    request(
                        "POST",
                        "/graphql",
                        Some("wrong"),
                        query(READ),
                        [127, 0, 0, 1],
                    ),
                    client,
                );
                assert_eq!(answer(&app, wrong).await.0, StatusCode::UNAUTHORIZED);
            }
        })
        .await;
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 4, "{logged}");
        for (line, client) in
            lines
                .iter()
                .zip(["203.0.113.1", "203.0.113.2", "203.0.113.1", "203.0.113.2"])
        {
            assert!(line.ends_with(&format!(" client={client}")), "{logged}");
        }
    }

    /// 009, M-41: a control character a caller chose never reaches a line —
    /// an operation name carrying a newline is written `?`, and a path's
    /// control and whitespace characters (which `http` would not parse, but
    /// the escaping does not rely on that) are written `\u{…}`.
    ///
    /// Bug-catch: log the operation name unchecked (NL-R4) and the newline
    /// starts a forged line; leave the escaping to tracing (NL-R9), which
    /// does not escape CR or LF, and the path's newline does.
    #[tokio::test]
    async fn a_control_character_in_a_path_or_operation_name_cannot_start_a_line() {
        let (_dir, app, _, _, _) = node();
        let forged = "INFO http: ledger=acme forged";
        let ((), logged) = capture_logs("info", async {
            let named = request(
                "POST",
                "/graphql",
                Some(OPERATOR),
                json!({ "query": READ, "operationName": format!("Books\n{forged}") }),
                PEER,
            );
            answer(&app, named).await;
        })
        .await;
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 1, "{logged}");
        assert!(lines[0].contains(" operation=? "), "{logged}");
        assert!(!logged.contains(forged), "{logged}");

        let raw = "/x\ny\r\tz\u{2028}\u{85}\u{1b}[31m";
        let shown = escaped(raw, MAX_PATH_BYTES);
        assert_eq!(shown, "/x\\u{a}y\\u{d}\\u{9}z\\u{2028}\\u{85}\\u{1b}[31m");
        let head = Head {
            ledger: "-".to_owned(),
            method: "GET".to_owned(),
            path: shown,
            client: IpAddr::from(PEER),
            started: Instant::now(),
        };
        let text = line(&head, Some(StatusCode::NOT_FOUND), None);
        assert!(
            !text
                .chars()
                .any(|character| character.is_control()
                    || character.is_whitespace() && character != ' '),
            "{text:?}"
        );
    }

    /// 009, M-41: every line stays under 512 bytes, with the longest path,
    /// operation name, ledger name and method a caller can send.
    ///
    /// Bug-catch: log the method as sent (NL-R11) and a 10,000-byte
    /// extension method is a 10,000-byte line.
    #[tokio::test]
    async fn every_line_is_under_512_bytes() {
        let (_dir, app, _, _, _) = node();
        let ((), logged) = capture_logs("info", async {
            let long_path = format!("/{}", "a".repeat(10_000));
            answer(
                &app,
                request("GET", &long_path, None, Value::Null, [203, 0, 113, 1]),
            )
            .await;
            let long_name = format!("/ledgers/{}/graphql", "z".repeat(40));
            answer(
                &app,
                request("POST", &long_name, None, query(READ), [203, 0, 113, 2]),
            )
            .await;
            for name in ["B".repeat(64), "B".repeat(10_000)] {
                let named = request(
                    "POST",
                    "/graphql",
                    Some(OPERATOR),
                    json!({ "query": READ, "operationName": name }),
                    [203, 0, 113, 3],
                );
                answer(&app, named).await;
            }
            let method = "X".repeat(10_000);
            answer(
                &app,
                request(&method, "/graphql", None, Value::Null, [203, 0, 113, 4]),
            )
            .await;
        })
        .await;
        assert_eq!(http_lines(&logged).len(), 5, "{logged}");
        for line in logged.lines() {
            assert!(line.len() < 512, "{} bytes: {line}", line.len());
        }
        assert!(
            logged.contains(&format!(" operation={} ", "B".repeat(64))),
            "{logged}"
        );
        assert!(logged.contains(" method=? "), "{logged}");
    }

    /// 009: `/ledgers/acm%65/graphql` is served by `acme` (axum's `Path`
    /// decodes it), so its line says `ledger=acme`: a percent-encoded name
    /// cannot hide from `openledger logs acme`.
    ///
    /// Bug-catch: take the name from the raw path (NL-R13) and the line says
    /// `ledger=-`.
    #[tokio::test]
    async fn a_percent_encoded_ledger_name_logs_as_the_ledger_it_serves() {
        let (_dir, app, _, _, _) = node();
        let ((status, body), logged) = capture_logs(
            "info",
            answer(
                &app,
                request(
                    "POST",
                    "/ledgers/acm%65/graphql",
                    Some(OPERATOR),
                    query(READ),
                    PEER,
                ),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 1, "{logged}");
        assert!(
            lines[0].contains(" http: ledger=acme method=POST path=/ledgers/acm%65/graphql "),
            "{logged}"
        );
    }

    /// 009: a key holder's 503 `LEDGER_BUSY` is logged naming them — "the
    /// app is slow".
    ///
    /// Bug-catch: drop `take_a_slot`'s note (NL-R16) and the 503's line says
    /// `user=-`.
    #[tokio::test]
    async fn a_busy_ledger_logs_the_key_holders_503_in_full() {
        let (_dir, app, _, _, ledgers) = node();
        let _held = hold_every_slot(&ledgers, "acme").await;
        let ((status, _), logged) = capture_logs(
            "info",
            answer(
                &app,
                request(
                    "POST",
                    "/ledgers/acme/graphql",
                    Some(OPERATOR),
                    query(READ),
                    PEER,
                ),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 1, "{logged}");
        assert!(
            lines[0].contains(" WARN http: ledger=acme method=POST path=/ledgers/acme/graphql operation=- user=operator status=503 "),
            "{logged}"
        );
        assert!(!lines[0].contains("suppressed="), "{logged}");
    }

    /// 009, M-13: a request the server gives up on — `serve_hardened`'s
    /// timeout, or a client hanging up, drops the router's future — still
    /// writes its line, `status=- cut_short=true`.
    ///
    /// Bug-catch: remove the drop guard (NL-R10) and a request cut short
    /// leaves no trace.
    #[tokio::test]
    async fn a_request_cut_short_still_logs_a_line() {
        let (_dir, app, _, acme, _) = node();
        let held = acme.write().await;
        let ((), logged) = capture_logs("info", async {
            let waiting = answer(
                &app,
                request(
                    "POST",
                    "/ledgers/acme/graphql",
                    Some(OPERATOR),
                    query(READ),
                    PEER,
                ),
            );
            let gave_up = tokio::time::timeout(Duration::from_millis(300), waiting).await;
            assert!(gave_up.is_err(), "the query waits on the ledger's lock");
        })
        .await;
        drop(held);
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 1, "{logged}");
        assert!(
            lines[0].contains(" WARN http::stranger: ledger=acme method=POST path=/ledgers/acme/graphql operation=- user=- status=- "),
            "{logged}"
        );
        assert!(lines[0].ends_with(" cut_short=true"), "{logged}");
    }

    /// 010 (reverses 009's decision 1): a `/health` that answers 200 is
    /// written at `INFO`, like every answer below 400 — so it shows at the
    /// default filter — once per request, a ledger's `/health` too.
    ///
    /// Bug-catch: leave a passing `/health` out (NL-R18) and the probes,
    /// Docker's among them, never show.
    #[tokio::test]
    async fn a_passing_health_check_logs_at_info() {
        let (_dir, app, _, _, _) = node();
        let ((), logged) = capture_logs(crate::DEFAULT_LOG_FILTER, async {
            for _ in 0..2 {
                let health = request("GET", "/health", None, Value::Null, PEER);
                assert_eq!(answer(&app, health).await.0, StatusCode::OK);
            }
            let named = request(
                "GET",
                "/ledgers/acme/health",
                Some(OPERATOR),
                Value::Null,
                PEER,
            );
            assert_eq!(answer(&app, named).await.0, StatusCode::OK);
        })
        .await;
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 3, "{logged}");
        for line in &lines[..2] {
            assert!(
                line.contains(" INFO http::stranger: ledger=default method=GET path=/health operation=- user=- status=200 "),
                "{logged}"
            );
        }
        assert!(
            lines[2].contains(
                " INFO http::stranger: ledger=acme method=GET path=/ledgers/acme/health "
            ),
            "{logged}"
        );
    }

    /// 009, decision 3: `INFO` for an answer below 400, `WARN` for 4xx and
    /// 5xx — so a warning with target `http` or `http::stranger` is a refused
    /// or failed request.
    ///
    /// Bug-catch: write a key holder's warnings at `INFO` (NL-R15), or a
    /// stranger's (NL-R19), and a refusal reads as a success.
    #[tokio::test]
    async fn the_level_follows_the_status() {
        let (_dir, app, _, _, ledgers) = node();
        let ((), logged) = capture_logs("info", async {
            let read = request("POST", "/graphql", Some(OPERATOR), query(READ), PEER);
            assert_eq!(answer(&app, read).await.0, StatusCode::OK);
            let wrong = request(
                "POST",
                "/graphql",
                Some("wrong"),
                query(READ),
                [203, 0, 113, 9],
            );
            assert_eq!(answer(&app, wrong).await.0, StatusCode::UNAUTHORIZED);
            let _held = hold_every_slot(&ledgers, "acme").await;
            let busy = request(
                "POST",
                "/ledgers/acme/graphql",
                Some(OPERATOR),
                query(READ),
                PEER,
            );
            assert_eq!(answer(&app, busy).await.0, StatusCode::SERVICE_UNAVAILABLE);
        })
        .await;
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 3, "{logged}");
        assert!(
            lines[0].contains(" INFO http: ") && lines[0].contains(" status=200 "),
            "{logged}"
        );
        assert!(
            lines[1].contains(" WARN http::stranger: ") && lines[1].contains(" status=401 "),
            "{logged}"
        );
        assert!(
            lines[2].contains(" WARN http: ") && lines[2].contains(" status=503 "),
            "{logged}"
        );
    }

    /// 010: a stranger's line has the target `http::stranger`, a key
    /// holder's `http` — so `http::stranger=off` leaves out only strangers',
    /// and `http=off` (a filter's target is a prefix) leaves out both.
    ///
    /// Bug-catch: write a stranger's line under `http` (NL-R20) and
    /// `http::stranger=off` cannot leave it out.
    #[tokio::test]
    async fn stranger_lines_can_be_turned_off_alone() {
        let (_dir, app, _, _, _) = node();
        let both = || async {
            let keyed = request("POST", "/graphql", Some(OPERATOR), query(READ), PEER);
            assert_eq!(answer(&app, keyed).await.0, StatusCode::OK);
            let wrong = request("POST", "/graphql", Some("wrong"), query(READ), PEER);
            assert_eq!(answer(&app, wrong).await.0, StatusCode::UNAUTHORIZED);
        };
        let ((), logged) = capture_logs(crate::DEFAULT_LOG_FILTER, both()).await;
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 2, "{logged}");
        assert!(
            lines[0].contains(" INFO http: ") && lines[0].contains(" user=operator "),
            "{logged}"
        );
        assert!(
            lines[1].contains(" WARN http::stranger: ") && lines[1].contains(" status=401 "),
            "{logged}"
        );

        let ((), logged) = capture_logs("info,http::stranger=off", both()).await;
        let lines = http_lines(&logged);
        assert_eq!(lines.len(), 1, "{logged}");
        assert!(
            lines[0].contains(" INFO http: ") && lines[0].contains(" user=operator "),
            "{logged}"
        );

        let ((), logged) = capture_logs("info,http=off", both()).await;
        assert!(http_lines(&logged).is_empty(), "{logged}");
    }
}
