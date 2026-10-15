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
use crate::config::{is_valid_ledger_name, DEFAULT_LEDGER};
use crate::graphql::{graphiql_handler, graphql_handler, AppSchema};
use crate::health::{health_handler, HealthState};
use crate::ledger_runtime::RunningLedger;

/// One ledger as the node holds it.
enum Served {
    Running {
        router: Router,
        auth: AuthState,
        /// Taken by [`Ledgers::stop_all`]; `None` for a ledger built from
        /// parts (tests).
        running: Mutex<Option<Box<RunningLedger>>>,
    },
    /// Refused at boot; the reason is the boot log's.
    Failed(String),
}

/// The node's ledgers, by name.
#[derive(Clone)]
pub(crate) struct Ledgers {
    by_name: Arc<RwLock<BTreeMap<String, Arc<Served>>>>,
    /// The operator key's check: the node's own key, admin of every ledger.
    operator: AuthState,
}

/// A ledger's own router: `/graphql` behind its auth, and `/health`.
pub(crate) fn ledger_router(
    schema: AppSchema,
    auth: AuthState,
    health: HealthState,
    graphiql: bool,
) -> Router {
    let graphql = if graphiql {
        Router::new().route("/graphql", get(graphiql_handler).post(graphql_handler))
    } else {
        Router::new().route("/graphql", post(graphql_handler))
    };
    graphql
        .with_state(schema)
        .layer(middleware::from_fn_with_state(auth, auth::auth_middleware))
        .merge(
            Router::new()
                .route("/health", get(health_handler))
                .with_state(health),
        )
}

impl Ledgers {
    /// No ledgers yet; `operator_enabled` and `operator_key` are `auth.enabled`
    /// and the node's key.
    pub(crate) fn new(operator_enabled: bool, operator_key: String) -> Self {
        Ledgers {
            by_name: Arc::default(),
            operator: AuthState {
                enabled: operator_enabled,
                api_key: operator_key,
                access: None,
            },
        }
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
        let router = ledger_router(
            running.schema.clone(),
            running.auth.clone(),
            running.health.clone(),
            graphiql && name == DEFAULT_LEDGER,
        );
        let served = Served::Running {
            router,
            auth: running.auth.clone(),
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
        let served = Served::Running {
            router: ledger_router(schema, auth.clone(), health, graphiql),
            auth,
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

    /// Stop every running ledger (the shutdown half of each, in name order).
    pub(crate) async fn stop_all(&self) {
        let all: Vec<(String, Arc<Served>)> = self
            .by_name
            .read()
            .await
            .iter()
            .map(|(name, served)| (name.clone(), served.clone()))
            .collect();
        for (name, served) in all {
            if let Served::Running { running, .. } = &*served {
                if let Some(running) = running.lock().await.take() {
                    running
                        .stop()
                        .instrument(tracing::info_span!("ledger", ledger = %name))
                        .await;
                }
            }
        }
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
        let operator = !self.operator.enabled
            || self
                .operator
                .authenticate(request.headers())
                .await
                .is_some();
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
    fn node() -> (tempfile::TempDir, Router, SharedLedger, SharedLedger) {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledgers = Ledgers::new(true, OPERATOR.to_owned());
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
            ledgers,
            RequestGuardState {
                allowed_hosts: Arc::new(["127.0.0.1".to_owned()].into()),
                allowed_origins: Arc::new(HashSet::new()),
                tls_terminated: false,
            },
            CorsLayer::new(),
            false,
            RateLimiter::graphql(),
        );
        let acme = shared.pop().expect("acme");
        let default = shared.pop().expect("default");
        (dir, app, default, acme)
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
        let (_dir, app, default, acme) = node();
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

    /// Review I-1: a refusal recorded under a name already served — a folder
    /// named `default` beside the config file's ledger — never replaces the
    /// served ledger, and a second ledger of a served name is handed back.
    ///
    /// Bug-catch: let the refusal overwrite the entry and the running ledger
    /// is orphaned — unreachable, its lock released, its tasks still writing.
    #[tokio::test]
    async fn a_refusal_never_replaces_a_served_ledger() {
        let ledgers = Ledgers::new(true, OPERATOR.to_owned());
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
        let (_dir, app, _, _) = node();
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
