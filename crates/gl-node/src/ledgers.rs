//! The ledgers a node serves, and each request's way to its own
//! (`docs/build-log/003-multi-ledger-node`).
//!
//! Every ledger is served by a router of its own — `/graphql` behind that
//! ledger's auth (the operator key, or a person's key from *its* access list)
//! and `/health` — built from its [`RunningLedger`]. The node's routes name the
//! ledger: `/graphql` and `/health` are the `default` ledger's, as before 003;
//! `/ledgers/<name>/graphql` and `/ledgers/<name>/health` are the others'. The
//! request is handed to that ledger's router with the ledger's name stripped,
//! so each ledger sees exactly the requests it saw as a node of its own.
//!
//! A name this node does not serve — unknown, refused at boot, or not a ledger
//! name at all — answers exactly as a wrong key does (401), unless the caller
//! holds the operator key (404 unknown, 503 failed): a stranger learns nothing
//! about which companies a node serves. A named ledger's `/health` needs a key
//! that ledger accepts, for the same reason.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use serde_json::json;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt;
use tracing::{warn, Instrument};

use crate::auth::{self, AuthState};
use crate::config::{is_valid_ledger_name, LedgerConfig, DEFAULT_LEDGER};
use crate::graphql::{graphiql_handler, graphql_handler, AppSchema};
use crate::health::{health_handler, HealthState};
use crate::ledger_runtime::RunningLedger;
use crate::rate_limit::{peer_of, too_many_requests, RateLimiter, LEDGER_MAX_BUCKETS};

/// A ledger's request slots (003, step 3): GraphQL requests it serves at once.
type Slots = Arc<tokio::sync::Semaphore>;

/// One ledger as the node holds it.
enum Served {
    Running {
        router: Router,
        auth: AuthState,
        /// The same slots the router's `/graphql` takes from; all of them
        /// taken back is every request it was serving finished (step 4).
        slots: Slots,
        /// The settings it was started with and its node id (`None` for a
        /// ledger built from parts): the node endpoint's checks and list.
        config: Option<Box<LedgerConfig>>,
        node_id: Option<String>,
        /// This ledger's own GraphQL rate limit: a client's budget is per
        /// ledger (003 step 3, the maintainer's choice).
        limiter: RateLimiter,
        /// Taken by [`Ledgers::stop_all`]; `None` for a ledger built from
        /// parts (tests).
        running: Mutex<Option<Box<RunningLedger>>>,
    },
    /// Refused at boot; the reason is the boot log's.
    Failed(String),
}

/// A ledger taken out of the registry ([`Ledgers::take`]).
pub(crate) enum Taken {
    /// It was served; here to stop (`None`: built from parts, or stopping).
    Running(Option<Box<RunningLedger>>),
    /// It was refused at boot: nothing runs.
    Failed,
}

/// One ledger as the node endpoint lists it.
pub(crate) struct LedgerState {
    pub name: String,
    /// Why it is not served; `None` when it is.
    pub reason: Option<String>,
    pub node_id: Option<String>,
    /// Its P2P endpoint's UDP port, when fixed.
    pub listen_port: Option<u16>,
}

/// `config`'s fixed P2P port: none with P2P off, or a random port (`0`).
pub(crate) fn fixed_listen_port(config: &LedgerConfig) -> Option<u16> {
    (config.p2p.enabled && config.p2p.listen_port != 0).then_some(config.p2p.listen_port)
}

/// The node's ledgers, by name.
#[derive(Clone)]
pub(crate) struct Ledgers {
    by_name: Arc<RwLock<BTreeMap<String, Arc<Served>>>>,
    /// The operator key's check: the node's own key, admin of every ledger.
    operator: AuthState,
    /// `http.maxRequestsPerLedger`.
    max_requests: usize,
    /// The GraphQL limiter every ledger's own is a twin of.
    template: RateLimiter,
    /// The budget every caller no ledger accepts shares, per client — no key,
    /// a wrong key, a name not served: making names up buys no budget, and a
    /// stranger's 429 comes at the same count whatever name it tries.
    strangers: RateLimiter,
}

/// A ledger's own router: `/graphql` behind its auth and its request slots
/// (auth first, so only a caller the ledger accepts takes a slot — a stranger
/// can neither fill a ledger's slots nor tell a busy ledger from no ledger),
/// and `/health`.
pub(crate) fn ledger_router(
    schema: AppSchema,
    auth: AuthState,
    health: HealthState,
    graphiql: bool,
    slots: Slots,
) -> Router {
    let graphql = if graphiql {
        Router::new().route("/graphql", get(graphiql_handler).post(graphql_handler))
    } else {
        Router::new().route("/graphql", post(graphql_handler))
    };
    graphql
        .with_state(schema)
        .layer(middleware::from_fn_with_state(slots, take_a_slot))
        .layer(middleware::from_fn_with_state(auth, auth::auth_middleware))
        .merge(
            Router::new()
                .route("/health", get(health_handler))
                .with_state(health),
        )
}

/// Serve the request in one of the ledger's slots, or answer 503
/// `LEDGER_BUSY` when all are in use (003, step 3): a ledger flooded by its
/// own callers slows only itself.
async fn take_a_slot(
    State(slots): State<Slots>,
    request: Request,
    next: middleware::Next,
) -> Response {
    let Ok(_slot) = slots.try_acquire_owned() else {
        let mut response = refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "LEDGER_BUSY",
            "this ledger is serving as many requests as it takes at once; try again shortly"
                .to_owned(),
        );
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("1"),
        );
        return response;
    };
    next.run(request).await
}

impl Ledgers {
    /// No ledgers yet; `operator_enabled` and `operator_key` are `auth.enabled`
    /// and the node's key; `max_requests` is `http.maxRequestsPerLedger`.
    pub(crate) fn new(
        operator_enabled: bool,
        operator_key: String,
        max_requests: usize,
        limiter: RateLimiter,
    ) -> Self {
        Ledgers {
            strangers: limiter.twin(),
            template: limiter,
            by_name: Arc::default(),
            operator: AuthState {
                enabled: operator_enabled,
                api_key: operator_key,
                access: None,
            },
            max_requests,
        }
    }

    /// A ledger's own GraphQL limiter: the config file's ledger keeps the full
    /// table it always had; a folder ledger's holds fewer clients
    /// ([`LEDGER_MAX_BUCKETS`]), so a node of many is bounded as one was.
    fn limiter_for(&self, name: &str) -> RateLimiter {
        let limiter = self.template.twin();
        if name == DEFAULT_LEDGER {
            limiter
        } else {
            limiter.with_max_buckets(LEDGER_MAX_BUCKETS)
        }
    }

    fn slots(&self) -> Slots {
        Arc::new(tokio::sync::Semaphore::new(self.max_requests))
    }

    /// Serve `running` as `name`. GraphiQL is the `default` ledger's only (its
    /// page posts to `/graphql`). A name already held is never replaced
    /// (review I-1): `running` comes back, for the caller to stop.
    pub(crate) async fn insert_running(
        &self,
        name: &str,
        running: RunningLedger,
        graphiql: bool,
    ) -> Result<(), Box<RunningLedger>> {
        let mut by_name = self.by_name.write().await;
        if by_name.contains_key(name) {
            return Err(Box::new(running));
        }
        let slots = self.slots();
        let router = ledger_router(
            running.schema.clone(),
            running.auth.clone(),
            running.health.clone(),
            graphiql && name == DEFAULT_LEDGER,
            slots.clone(),
        );
        let served = Served::Running {
            router,
            auth: running.auth.clone(),
            slots,
            config: Some(Box::new(running.config.clone())),
            node_id: running.node_id.clone(),
            limiter: self.limiter_for(name),
            running: Mutex::new(Some(Box::new(running))),
        };
        by_name.insert(name.to_owned(), Arc::new(served));
        Ok(())
    }

    /// Serve a ledger built from its parts, with nothing to stop (tests; a
    /// fresh registry, so the lock is free).
    #[cfg(test)]
    pub(crate) fn insert_parts(
        &self,
        name: &str,
        schema: AppSchema,
        auth: AuthState,
        health: HealthState,
        graphiql: bool,
    ) {
        let slots = self.slots();
        let served = Served::Running {
            router: ledger_router(schema, auth.clone(), health, graphiql, slots.clone()),
            auth,
            slots,
            config: None,
            node_id: None,
            limiter: self.limiter_for(name),
            running: Mutex::new(None),
        };
        self.by_name
            .try_write()
            .expect("a fresh registry")
            .insert(name.to_owned(), Arc::new(served));
    }

    /// Record `name` as refused at boot, for `reason` — unless a ledger of
    /// that name is already held, which a refusal never replaces (review I-1:
    /// it would orphan a running ledger, its lock released and its tasks
    /// still writing).
    pub(crate) async fn insert_failed(&self, name: &str, reason: String) {
        self.by_name
            .write()
            .await
            .entry(name.to_owned())
            .or_insert_with(|| Arc::new(Served::Failed(reason)));
    }

    /// How many ledgers are served (not counting the refused).
    pub(crate) async fn running_count(&self) -> usize {
        self.by_name
            .read()
            .await
            .values()
            .filter(|served| matches!(***served, Served::Running { .. }))
            .count()
    }

    /// Stop every running ledger — the shutdown half of each, all at once
    /// (003, step 3): a node with many ledgers compacts them in parallel, so
    /// it fits in the time a container stop allows.
    pub(crate) async fn stop_all(&self) {
        let all: Vec<(String, Arc<Served>)> = self
            .by_name
            .read()
            .await
            .iter()
            .map(|(name, served)| (name.clone(), served.clone()))
            .collect();
        let mut stopping = tokio::task::JoinSet::new();
        for (name, served) in all {
            if let Served::Running { running, .. } = &*served {
                if let Some(running) = running.lock().await.take() {
                    stopping.spawn(
                        running
                            .stop()
                            .instrument(tracing::info_span!("ledger", ledger = %name)),
                    );
                }
            }
        }
        while let Some(stopped) = stopping.join_next().await {
            if let Err(error) = stopped {
                warn!(%error, "a ledger's shutdown did not finish");
            }
        }
    }

    /// Stop serving `name` (003 step 4): no new request reaches it, and once
    /// every request it was serving has finished — all its slots taken back,
    /// so none is left to write after its stop, perhaps into a ledger added
    /// later under the same name — it comes back for the caller to stop. A
    /// request routed to it just before then answers 503 `LEDGER_BUSY`. The
    /// wait is bounded by `http.requestTimeoutSeconds`, which ends any request.
    /// `None` when `name` is not held.
    pub(crate) async fn take(&self, name: &str) -> Option<Taken> {
        let served = self.by_name.write().await.remove(name)?;
        match &*served {
            Served::Running { slots, running, .. } => {
                let all = u32::try_from(self.max_requests).unwrap_or(u32::MAX);
                // Never closed but here, after this ledger left the map.
                if let Ok(drained) = slots.acquire_many(all).await {
                    drained.forget();
                }
                slots.close();
                Some(Taken::Running(running.lock().await.take()))
            }
            Served::Failed(_) => Some(Taken::Failed),
        }
    }

    /// One of served ledger `name`'s request slots, as a request in flight
    /// holds it (tests).
    #[cfg(test)]
    pub(crate) async fn slot_for_test(&self, name: &str) -> tokio::sync::OwnedSemaphorePermit {
        match &*self.get(name).await.expect("served") {
            Served::Running { slots, .. } => {
                Arc::clone(slots).try_acquire_owned().expect("a free slot")
            }
            Served::Failed(_) => panic!("{name} is served"),
        }
    }

    /// Whether `name` is held, served or refused.
    pub(crate) async fn holds(&self, name: &str) -> bool {
        self.by_name.read().await.contains_key(name)
    }

    /// Every ledger held, by name: served or refused, and why.
    pub(crate) async fn states(&self) -> Vec<LedgerState> {
        self.by_name
            .read()
            .await
            .iter()
            .map(|(name, served)| match &**served {
                Served::Running {
                    node_id, config, ..
                } => LedgerState {
                    name: name.clone(),
                    reason: None,
                    node_id: node_id.clone(),
                    listen_port: config.as_deref().and_then(fixed_listen_port),
                },
                Served::Failed(reason) => LedgerState {
                    name: name.clone(),
                    reason: Some(reason.clone()),
                    node_id: None,
                    listen_port: None,
                },
            })
            .collect()
    }

    /// The settings of every served ledger but `except`, the config file's
    /// first: what a ledger added or restarted must not conflict with.
    pub(crate) async fn served_configs(&self, except: &str) -> Vec<(String, LedgerConfig)> {
        let by_name = self.by_name.read().await;
        let mut configs: Vec<(String, LedgerConfig)> = by_name
            .iter()
            .filter(|(name, _)| name.as_str() != except)
            .filter_map(|(name, served)| match &**served {
                Served::Running {
                    config: Some(config),
                    ..
                } => Some((name.clone(), (**config).clone())),
                _ => None,
            })
            .collect();
        configs.sort_by_key(|(name, _)| name != DEFAULT_LEDGER);
        configs
    }

    /// Whether `headers` carry the operator key (or auth is off).
    pub(crate) async fn is_operator(&self, headers: &axum::http::HeaderMap) -> bool {
        !self.operator.enabled || self.operator.authenticate(headers).await.is_some()
    }

    async fn get(&self, name: &str) -> Option<Arc<Served>> {
        self.by_name.read().await.get(name).cloned()
    }

    /// Hand `request` to ledger `name`'s router as `path`, or answer for a
    /// ledger that is not served. `health`: a named ledger's `/health` needs a
    /// key the ledger accepts.
    async fn dispatch(&self, name: &str, path: &str, request: Request, health: bool) -> Response {
        let served = if is_valid_ledger_name(name) {
            self.get(name).await
        } else {
            None
        };
        let operator = self.is_operator(request.headers()).await;
        // GraphQL's rate limit, per client and ledger — for callers the ledger
        // accepts (its people, the operator), whose requests are charged to
        // the ledger's own table. Everyone else — no key, a wrong key, a name
        // not served — shares one strangers' table per client, so a stranger
        // sees the same budget whatever name it tries: choosing the table by
        // the name alone told a spent budget (429) from a fresh one (401) and
        // so which names are served (review). Every request is charged once,
        // before anything but the key checks runs.
        if !health {
            let accepted = match served.as_deref() {
                Some(Served::Running { auth, limiter, .. }) => (operator
                    || auth.authenticate(request.headers()).await.is_some())
                .then_some(limiter),
                _ => None,
            };
            let limiter = accepted.unwrap_or(&self.strangers);
            let allowed = tracing::info_span!("ledger", ledger = %name)
                .in_scope(|| limiter.allow_request(peer_of(&request), request.headers()));
            if !allowed {
                return too_many_requests();
            }
        }
        let (router, auth) = match served.as_deref() {
            Some(Served::Running { router, auth, .. }) => (router.clone(), auth),
            Some(Served::Failed(reason)) if operator => {
                return refusal(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "LEDGER_NOT_SERVED",
                    format!("ledger \"{name}\" is not served: {reason}"),
                );
            }
            None if operator => {
                return refusal(
                    StatusCode::NOT_FOUND,
                    "NO_SUCH_LEDGER",
                    format!("this node serves no ledger named \"{name}\""),
                );
            }
            _ => return auth::unauthorized(),
        };
        if health
            && name != DEFAULT_LEDGER
            && !operator
            && auth.authenticate(request.headers()).await.is_none()
        {
            return auth::unauthorized();
        }
        let (mut parts, body) = request.into_parts();
        parts.uri = match rewrite(&parts.uri, path) {
            Some(uri) => uri,
            None => {
                warn!(uri = %parts.uri, "could not rewrite a ledger request's path");
                return StatusCode::BAD_REQUEST.into_response();
            }
        };
        let request = Request::from_parts(parts, body);
        match router
            .oneshot(request)
            .instrument(tracing::info_span!("ledger", ledger = %name))
            .await
        {
            Ok(response) => response,
            Err(infallible) => match infallible {},
        }
    }
}

/// `uri` with its path replaced by `path`, the query kept.
fn rewrite(uri: &Uri, path: &str) -> Option<Uri> {
    let path_and_query = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    Uri::builder().path_and_query(path_and_query).build().ok()
}

/// A GraphQL-shaped refusal (the operator's view of a ledger not served).
fn refusal(status: StatusCode, code: &str, message: String) -> Response {
    let body = json!({ "errors": [{ "message": message, "extensions": { "code": code } }] });
    (status, Json(body)).into_response()
}

/// `/graphql`: the `default` ledger's.
pub(crate) async fn default_graphql(State(ledgers): State<Ledgers>, request: Request) -> Response {
    ledgers
        .dispatch(DEFAULT_LEDGER, "/graphql", request, false)
        .await
}

/// `/health`: the `default` ledger's.
pub(crate) async fn default_health(State(ledgers): State<Ledgers>, request: Request) -> Response {
    ledgers
        .dispatch(DEFAULT_LEDGER, "/health", request, true)
        .await
}

/// `/ledgers/<name>/graphql`.
pub(crate) async fn named_graphql(
    State(ledgers): State<Ledgers>,
    Path(name): Path<String>,
    request: Request<Body>,
) -> Response {
    ledgers.dispatch(&name, "/graphql", request, false).await
}

/// `/ledgers/<name>/health`.
pub(crate) async fn named_health(
    State(ledgers): State<Ledgers>,
    Path(name): Path<String>,
    request: Request<Body>,
) -> Response {
    ledgers.dispatch(&name, "/health", request, true).await
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tower::ServiceExt;
    use tower_http::cors::CorsLayer;

    use super::Ledgers;
    use crate::auth::{AccessSource, AuthState};
    use crate::graphql::broadcast::TransactionBroadcast;
    use crate::graphql::{build_schema_with_access, SharedLedger};
    use crate::health::HealthState;
    use crate::rate_limit::RateLimiter;
    use crate::request_guard::RequestGuardState;

    const OPERATOR: &str = "operator-key-for-the-ledger-routing-tests-0123456789";

    /// A node serving `default` and `acme`, with `broken` refused at boot —
    /// each ledger with its own books and its own access list.
    fn node() -> (
        tempfile::TempDir,
        Router,
        SharedLedger,
        SharedLedger,
        Ledgers,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledgers = Ledgers::new(true, OPERATOR.to_owned(), 64, RateLimiter::graphql());
        let mut shared = Vec::new();
        for name in ["default", "acme"] {
            let service = ledger::service::LedgerService::boot(
                dir.path().join(format!("{name}.bean")),
                format!("{name}-node"),
            )
            .expect("boot");
            let ledger: SharedLedger = Arc::new(tokio::sync::RwLock::new(service));
            let access = AccessSource::new(ledger.clone(), None);
            let peer_registry = p2p::node::PeerRegistry::new();
            let schema = build_schema_with_access(
                ledger.clone(),
                TransactionBroadcast::new(),
                peer_registry.clone(),
                Arc::new(security::signing::NoopSignatureProvider),
                false,
                None,
                Some(access.clone()),
            );
            let auth = AuthState {
                enabled: true,
                api_key: OPERATOR.to_owned(),
                access: Some(access),
            };
            let health = HealthState {
                ledger: ledger.clone(),
                peer_registry,
                public_bind: false,
                auth: auth.clone(),
            };
            ledgers.insert_parts(name, schema, auth, health, false);
            shared.push(ledger);
        }
        ledgers.by_name.try_write().expect("free").insert(
            "broken".to_owned(),
            Arc::new(super::Served::Failed(
                "its ledger.json does not parse".to_owned(),
            )),
        );
        let app = crate::build_application_with_limiter(
            ledgers.clone(),
            RequestGuardState {
                allowed_hosts: Arc::new(["127.0.0.1".to_owned()].into()),
                allowed_origins: Arc::new(HashSet::new()),
                tls_terminated: false,
            },
            CorsLayer::new(),
            false,
            RateLimiter::graphql(),
            None,
        );
        let acme = shared.pop().expect("acme");
        let default = shared.pop().expect("default");
        (dir, app, default, acme, ledgers)
    }

    async fn send(
        app: &Router,
        method: &str,
        path: &str,
        key: Option<&str>,
        query: &str,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1")
            .header("content-type", "application/json");
        if let Some(key) = key {
            request = request.header("x-api-key", key);
        }
        let body = if method == "POST" {
            Body::from(json!({ "query": query }).to_string())
        } else {
            Body::empty()
        };
        let response = app
            .clone()
            .oneshot(request.body(body).expect("request"))
            .await
            .expect("response");
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

    async fn post(app: &Router, path: &str, key: Option<&str>, query: &str) -> (StatusCode, Value) {
        send(app, "POST", path, key, query).await
    }

    fn grant(name: &str) -> String {
        format!(r#"mutation {{ grantAccess(name: "{name}", role: WRITE) {{ key }} }}"#)
    }

    /// 003: each request reaches its own ledger — an account opened through
    /// `/ledgers/acme/graphql` is in acme's books and not in the default
    /// ledger's, and the other way round — and a key from one ledger's access
    /// list gets 401 from the other; `/graphql` is the default ledger, as
    /// before.
    ///
    /// Bug-catch: route every name to the same ledger and one company's
    /// entries land in another's books, and its keys open the other's.
    #[tokio::test]
    async fn each_ledger_answers_with_its_own_books_and_keys() {
        let (_dir, app, default, acme, _) = node();
        let open = |account: &str| {
            format!(r#"mutation {{ openAccount(name: "{account}", date: "2026-01-01") }}"#)
        };
        let (status, body) = post(
            &app,
            "/ledgers/acme/graphql",
            Some(OPERATOR),
            &open("Assets:Acme"),
        )
        .await;
        assert!(
            status == StatusCode::OK && body["errors"].is_null(),
            "{body}"
        );
        let (status, body) = post(&app, "/graphql", Some(OPERATOR), &open("Assets:Home")).await;
        assert!(
            status == StatusCode::OK && body["errors"].is_null(),
            "{body}"
        );
        assert!(acme.read().await.accounts().is_open("Assets:Acme"));
        assert!(!acme.read().await.accounts().is_open("Assets:Home"));
        assert!(default.read().await.accounts().is_open("Assets:Home"));
        assert!(!default.read().await.accounts().is_open("Assets:Acme"));

        let (_, body) = post(&app, "/ledgers/acme/graphql", Some(OPERATOR), &grant("Ana")).await;
        let acme_key = body["data"]["grantAccess"]["key"]
            .as_str()
            .expect("key")
            .to_owned();
        let (_, body) = post(&app, "/graphql", Some(OPERATOR), &grant("Bea")).await;
        let default_key = body["data"]["grantAccess"]["key"]
            .as_str()
            .expect("key")
            .to_owned();
        let read = "{ verify { ok } }";
        let (status, _) = post(&app, "/ledgers/acme/graphql", Some(&acme_key), read).await;
        assert_eq!(status, StatusCode::OK, "acme's key on acme");
        let (status, _) = post(&app, "/graphql", Some(&acme_key), read).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "acme's key on the default ledger"
        );
        let (status, _) = post(&app, "/ledgers/acme/graphql", Some(&default_key), read).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the default ledger's key on acme"
        );
        let (status, _) = post(&app, "/graphql", Some(&default_key), read).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// 003 step 3: a ledger serves at most `http.maxRequestsPerLedger`
    /// GraphQL requests at once — past it, 503 `LEDGER_BUSY` with
    /// `Retry-After` — while the node's other ledgers answer as usual; and the
    /// slots are counted after the key check, so a stranger still gets 401
    /// from a busy ledger, never a 503 that would say it exists.
    ///
    /// Bug-catch: share one set of slots across ledgers and one company's
    /// flood stops every company on the node.
    #[tokio::test]
    async fn a_busy_ledger_slows_only_itself() {
        let (_dir, app, _, _, ledgers) = node();
        let slots = match &*ledgers.get("acme").await.expect("acme") {
            super::Served::Running { slots, .. } => slots.clone(),
            super::Served::Failed(_) => panic!("acme is served"),
        };
        let held = slots
            .clone()
            .try_acquire_many_owned(64)
            .expect("every slot");
        let read = "{ verify { ok } }";
        let response = app
            .clone()
            .oneshot(
                Request::post("/ledgers/acme/graphql")
                    .header("host", "127.0.0.1")
                    .header("content-type", "application/json")
                    .header("x-api-key", OPERATOR)
                    .body(Body::from(json!({ "query": read }).to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["retry-after"], "1");
        let (status, _) = post(&app, "/graphql", Some(OPERATOR), read).await;
        assert_eq!(status, StatusCode::OK, "the other ledger is untouched");
        let (status, _) = post(&app, "/ledgers/acme/graphql", None, read).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a stranger still gets 401"
        );
        drop(held);
        let (status, _) = post(&app, "/ledgers/acme/graphql", Some(OPERATOR), read).await;
        assert_eq!(status, StatusCode::OK, "served again once a slot is free");
    }

    /// 003 step 3, the maintainer's choice: a client's GraphQL budget is per
    /// ledger it is accepted by — spending it on one company leaves it whole on
    /// another — while every caller no ledger accepts (no key, a wrong key, a
    /// name not served) shares one strangers' budget, so making names up buys
    /// nothing and a stranger's 429 is the same for a served name as for an
    /// unknown one.
    ///
    /// Bug-catch: one table for every ledger and an accountant's app working
    /// across forty companies shares one minute's budget among them all; choose
    /// the table by the name and a stranger can tell served names by which
    /// ones still answer 401 once the strangers' budget is spent.
    #[tokio::test]
    async fn the_rate_limit_is_per_client_and_ledger() {
        let (_dir, app, _, _, _) = node();
        let read = "{ verify { ok } }";
        let limit = crate::rate_limit::GRAPHQL_RATE_LIMIT;
        for _ in 0..limit {
            let (status, _) = post(&app, "/graphql", Some(OPERATOR), read).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, body) = post(&app, "/graphql", Some(OPERATOR), read).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        let (status, _) = post(&app, "/ledgers/acme/graphql", Some(OPERATOR), read).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the same client's budget on another ledger"
        );

        for index in 0..limit {
            let (status, _) = post(
                &app,
                &format!("/ledgers/made-up-{index}/graphql"),
                None,
                read,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, _) = post(&app, "/ledgers/another-made-up/graphql", None, read).await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "made-up names share one budget"
        );
        // Review: and a served name, asked without a key, is charged to the
        // same strangers' budget — 429 like the made-up ones, not a fresh
        // budget's 401 that would say the name is served.
        for path in ["/ledgers/acme/graphql", "/graphql"] {
            let (status, _) = post(&app, path, None, read).await;
            assert_eq!(
                status,
                StatusCode::TOO_MANY_REQUESTS,
                "{path} without a key"
            );
        }
        let (status, _) = post(&app, "/ledgers/acme/graphql", Some(OPERATOR), read).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the ledger's own callers keep theirs"
        );
    }

    /// 003: a folder ledger's limiter tracks fewer clients than the config
    /// file's ledger's, which keeps the full table it always had.
    ///
    /// Bug-catch: give every ledger a full table and a flood of addresses
    /// across 100 ledgers holds 100 of them.
    #[tokio::test]
    async fn a_folder_ledgers_limiter_is_smaller() {
        let (_dir, _app, _, _, ledgers) = node();
        let max_buckets = |served: &super::Served| match served {
            super::Served::Running { limiter, .. } => limiter.max_buckets(),
            super::Served::Failed(_) => 0,
        };
        let acme = ledgers.get("acme").await.expect("acme");
        let default = ledgers.get("default").await.expect("default");
        assert_eq!(max_buckets(&acme), crate::rate_limit::LEDGER_MAX_BUCKETS);
        assert!(max_buckets(&default) > crate::rate_limit::LEDGER_MAX_BUCKETS);
    }

    /// Review I-1: a refusal recorded under a name already served — a folder
    /// named `default` beside the config file's ledger — never replaces the
    /// served ledger, and a second ledger of a served name is handed back.
    ///
    /// Bug-catch: let the refusal overwrite the entry and the running ledger
    /// is orphaned — unreachable, its lock released, its tasks still writing.
    #[tokio::test]
    async fn a_refusal_never_replaces_a_served_ledger() {
        let ledgers = Ledgers::new(true, OPERATOR.to_owned(), 64, RateLimiter::graphql());
        let dir = tempfile::tempdir().expect("tempdir");
        let service =
            ledger::service::LedgerService::boot(dir.path().join("x.bean"), "x".to_owned())
                .expect("boot");
        let ledger: SharedLedger = Arc::new(tokio::sync::RwLock::new(service));
        let auth = AuthState {
            enabled: true,
            api_key: OPERATOR.to_owned(),
            access: None,
        };
        let schema = crate::graphql::build_schema_with_service(
            ledger.clone(),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            false,
            None,
        );
        let health = HealthState {
            ledger,
            peer_registry: p2p::node::PeerRegistry::new(),
            public_bind: false,
            auth: auth.clone(),
        };
        ledgers.insert_parts("default", schema, auth, health, false);
        ledgers
            .insert_failed("default", "a folder named default".to_owned())
            .await;
        assert!(matches!(
            *ledgers.get("default").await.expect("held"),
            super::Served::Running { .. }
        ));
        assert_eq!(ledgers.running_count().await, 1);
    }

    /// 003: a ledger this node does not serve — unknown, refused at boot, or
    /// no ledger name at all — answers exactly as a wrong key does (401) to
    /// anyone but the operator, who is told which (404, 503); and a named
    /// ledger's `/health` needs a key that ledger accepts, while `/health`
    /// stays open as before.
    ///
    /// Bug-catch: answer 404 to everyone and a stranger can list which
    /// companies a node serves, name by name.
    #[tokio::test]
    async fn a_ledger_not_served_is_told_only_to_the_operator() {
        let (_dir, app, _, _, _) = node();
        let (_, body) = post(&app, "/ledgers/acme/graphql", Some(OPERATOR), &grant("Ana")).await;
        let acme_key = body["data"]["grantAccess"]["key"]
            .as_str()
            .expect("key")
            .to_owned();
        let read = "{ verify { ok } }";
        for path in [
            "/ledgers/nope/graphql",
            "/ledgers/broken/graphql",
            "/ledgers/Bad.Name/graphql",
        ] {
            for key in [
                None,
                Some("wrong-key-0123456789abcdef"),
                Some(acme_key.as_str()),
            ] {
                let (status, body) = post(&app, path, key, read).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} {key:?}: {body}");
                assert_eq!(body["errors"][0]["extensions"]["code"], "UNAUTHORIZED");
            }
        }
        for (path, status, code) in [
            (
                "/ledgers/nope/graphql",
                StatusCode::NOT_FOUND,
                "NO_SUCH_LEDGER",
            ),
            (
                "/ledgers/Bad.Name/graphql",
                StatusCode::NOT_FOUND,
                "NO_SUCH_LEDGER",
            ),
            (
                "/ledgers/broken/graphql",
                StatusCode::SERVICE_UNAVAILABLE,
                "LEDGER_NOT_SERVED",
            ),
        ] {
            let (got, body) = post(&app, path, Some(OPERATOR), read).await;
            assert_eq!(got, status, "{path}: {body}");
            assert_eq!(body["errors"][0]["extensions"]["code"], code);
        }

        let health = |key: Option<&'static str>| {
            let app = app.clone();
            async move { send(&app, "GET", "/ledgers/acme/health", key, "").await.0 }
        };
        assert_eq!(health(None).await, StatusCode::UNAUTHORIZED, "a stranger");
        assert_eq!(health(Some(OPERATOR)).await, StatusCode::OK);
        let (status, _) = send(&app, "GET", "/ledgers/acme/health", Some(&acme_key), "").await;
        assert_eq!(status, StatusCode::OK, "acme's own key");
        let (status, _) = send(&app, "GET", "/ledgers/nope/health", Some(OPERATOR), "").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = send(&app, "GET", "/health", None, "").await;
        assert_eq!(status, StatusCode::OK, "/health stays open");
    }
}
