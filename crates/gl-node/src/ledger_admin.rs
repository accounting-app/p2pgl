//! Adding, removing and restarting ledgers while the node runs
//! (`docs/build-log/003-multi-ledger-node`, step 4): the node endpoint,
//! `/node/graphql`, for the operator key only.
//!
//! - `ledgers` lists every ledger the node holds: served, or refused and why,
//!   with its node id.
//! - `addLedger(name, settings)` writes the ledger's folder in `ledgersDir` —
//!   its `ledger.json` and, when it signs or replicates, its node key — under
//!   a temporary name, renames it into place, and starts it. A restart in
//!   between sees all of it or none of it.
//! - `removeLedger(name)` stops the ledger — no new request reaches it, the
//!   ones it was serving finish, its journal is folded in — and moves its
//!   folder to `ledgersDir/.removed/<name>-<UTC time>`. Nothing is deleted.
//! - `restartLedger(name)` stops a folder ledger and starts it again from its
//!   `ledger.json`, so an edited file is picked up without stopping the node.
//!
//! One change at a time, each on a task of its own: a request cut short (a
//! timeout, a closed connection) never leaves a ledger half added or half
//! stopped. The config file's own ledger (`default`) changes only with the
//! node.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_graphql::{Context, EmptySubscription, ErrorExtensions, Object, Schema, SimpleObject};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use tracing::{error, info, Instrument};

use crate::config::{
    is_valid_ledger_name, ledgers_in_conflict, LedgerConfig, DEFAULT_LEDGER, LEDGER_FILE,
};
use crate::ledger_runtime::{self, NodeSettings, RunningLedger};
use crate::ledgers::{LedgerState, Ledgers, Taken};

/// The longest `ledger.json` `addLedger` writes: settings are a few hundred
/// bytes; a long allowlist fits many times over.
const MAX_SETTINGS_BYTES: usize = 64 * 1024;

/// The node schema's complexity budget, and a change's cost within it: one
/// change per request, so one request never adds a hundred ledgers.
const NODE_MAX_COMPLEXITY: usize = 1000;
const CHANGE_COMPLEXITY: usize = 600;

/// The node endpoint's schema.
pub(crate) type NodeSchema = Schema<NodeQuery, NodeMutation, EmptySubscription>;

/// What the node endpoint works on: the node's ledgers and where their
/// folders are.
pub(crate) struct NodeAdmin {
    ledgers: Ledgers,
    ledgers_dir: PathBuf,
    node: NodeSettings,
    max_ledgers: usize,
    /// Held for each change, and by the node's shutdown: one at a time.
    busy: tokio::sync::Mutex<()>,
}

/// A change refused, with its code.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub code: &'static str,
    pub message: String,
}

fn refused(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

impl Refusal {
    fn into_error(self) -> async_graphql::Error {
        async_graphql::Error::new(self.message).extend_with(|_, ext| ext.set("code", self.code))
    }
}

/// One ledger, as the node endpoint shows it.
#[derive(SimpleObject, Debug, Clone, PartialEq, Eq)]
pub(crate) struct LedgerInfo {
    pub name: String,
    pub served: bool,
    /// Why it is not served.
    pub reason: Option<String>,
    /// Its node id, for the other nodes' `p2p.bootstrapEndpointIds`; none
    /// when it neither signs nor replicates.
    pub node_id: Option<String>,
}

impl From<LedgerState> for LedgerInfo {
    fn from(state: LedgerState) -> Self {
        LedgerInfo {
            name: state.name,
            served: state.reason.is_none(),
            reason: state.reason,
            node_id: state.node_id,
        }
    }
}

/// A ledger removed: where its folder went.
#[derive(SimpleObject, Debug, Clone)]
pub(crate) struct RemovedLedger {
    pub name: String,
    /// The folder's new place; none when it had no folder left to move.
    pub moved_to: Option<String>,
}

impl NodeAdmin {
    pub(crate) fn new(
        ledgers: Ledgers,
        ledgers_dir: PathBuf,
        node: NodeSettings,
        max_ledgers: usize,
    ) -> Self {
        NodeAdmin {
            ledgers,
            ledgers_dir,
            node,
            max_ledgers,
            busy: tokio::sync::Mutex::new(()),
        }
    }

    /// Stop every ledger, after any change under way has finished (a ledger
    /// being added is stopped with the rest, not left running). No change runs
    /// after: `busy` stays held (review), so one queued behind the shutdown
    /// never starts a ledger nothing will stop.
    pub(crate) async fn stop_all(&self) {
        let busy = self.busy.lock().await;
        self.ledgers.stop_all().await;
        std::mem::forget(busy);
    }

    fn folder(&self, name: &str) -> PathBuf {
        self.ledgers_dir.join(name)
    }

    /// `name` as a folder ledger's: a valid name, not the config file's.
    fn folder_name(name: &str) -> Result<(), Refusal> {
        if name == DEFAULT_LEDGER {
            return Err(refused(
                "INVALID_INPUT",
                "\"default\" is the config file's own ledger: it changes with the config file and a restart of the node",
            ));
        }
        if !is_valid_ledger_name(name) {
            return Err(refused(
                "INVALID_INPUT",
                format!(
                    "{name:?} is not a ledger name: 1 to 40 of a-z, 0-9 and -, not starting with -"
                ),
            ));
        }
        Ok(())
    }

    /// The ledgers in conflict with `config` as `name`, beside every other
    /// ledger served — the rules boot applies (`ledgers_in_conflict`).
    async fn conflict(&self, name: &str, config: &LedgerConfig) -> Option<String> {
        let others = self.ledgers.served_configs(name).await;
        let mut all: Vec<(&str, &LedgerConfig)> = others
            .iter()
            .map(|(name, config)| (name.as_str(), config))
            .collect();
        all.push((name, config));
        ledgers_in_conflict(&all, self.max_ledgers)
            .into_iter()
            .find(|(refused, _)| refused == name)
            .map(|(_, reason)| reason)
    }

    /// Add ledger `name` with `settings` (a `ledger.json`; `{}` when none).
    pub(crate) async fn add(
        &self,
        name: &str,
        settings: Option<&str>,
    ) -> Result<LedgerInfo, Refusal> {
        let _busy = self.busy.lock().await;
        Self::folder_name(name)?;
        let folder = self.folder(name);
        if self.ledgers.holds(name).await || folder.symlink_metadata().is_ok() {
            return Err(refused(
                "LEDGER_EXISTS",
                format!(
                    "ledger \"{name}\" already has a folder in ledgersDir ({}); remove it first, or restart it to pick up its ledger.json",
                    folder.display()
                ),
            ));
        }
        let settings = settings.unwrap_or("{}\n");
        if settings.len() > MAX_SETTINGS_BYTES {
            return Err(refused(
                "INVALID_INPUT",
                format!("the settings are longer than {MAX_SETTINGS_BYTES} bytes"),
            ));
        }
        if !serde_json::from_str::<serde_json::Value>(settings).is_ok_and(|value| value.is_object())
        {
            return Err(refused(
                "INVALID_INPUT",
                "the settings are not a JSON object (a ledger.json)",
            ));
        }

        // Written aside, under a name boot skips, and renamed into place.
        let staging = {
            let (dir, name, settings) = (
                self.ledgers_dir.clone(),
                name.to_owned(),
                settings.to_owned(),
            );
            tokio::task::spawn_blocking(move || write_staging(&dir, &name, &settings))
                .await
                .map_err(|error| refused("START_FAILED", error.to_string()))?
                .map_err(|error| {
                    refused(
                        "START_FAILED",
                        format!("could not write the ledger's folder: {error}"),
                    )
                })?
        };
        let discard = |reason: Refusal| {
            if let Err(error) = std::fs::remove_dir_all(&staging) {
                error!(%error, path = %staging.display(), "could not remove a ledger folder that was never served");
            }
            reason
        };
        let config = match LedgerConfig::load_folder(&staging) {
            Ok(config) => config,
            Err(error) => {
                let message = error.to_string().replace(
                    &staging.display().to_string(),
                    &folder.display().to_string(),
                );
                return Err(discard(refused("INVALID_INPUT", message)));
            }
        };
        if let Some(reason) = self.conflict(name, &config).await {
            return Err(discard(refused("LEDGER_CONFLICT", reason)));
        }
        // Its node key, made now so that a ledger that signs without
        // replicating has one too: a new ledger is a new identity.
        if config.p2p.enabled || config.signing.enabled {
            let key = Path::new(&config.p2p.secret_key_path);
            if let Err(error) = crate::p2p_service::load_or_create_secret_key(key) {
                return Err(discard(refused(
                    "START_FAILED",
                    format!("could not create the ledger's node key: {error}"),
                )));
            }
        }
        if let Err(error) = place(&staging, &folder) {
            return Err(discard(refused(
                "START_FAILED",
                format!("could not move the ledger's folder into place: {error}"),
            )));
        }
        info!(ledger = %name, folder = %folder.display(), "ledger added");

        let config = match LedgerConfig::load_folder(&folder) {
            Ok(config) => config,
            Err(error) => return Err(self.set_aside_failed(name, error.to_string())),
        };
        match ledger_runtime::start(name, &config, &self.node).await {
            Ok(running) => self.serve(name, running).await,
            Err(ledger_runtime::StartFailed) => Err(self.set_aside_failed(
                name,
                "it could not start; the node's log says why".to_owned(),
            )),
        }
    }

    /// A ledger added that did not start: its folder moved aside, so the
    /// next boot does not try it again, and the refusal.
    fn set_aside_failed(&self, name: &str, reason: String) -> Refusal {
        match move_aside(&self.ledgers_dir, name, "-failed") {
            Ok(moved) => refused(
                "START_FAILED",
                format!(
                    "ledger \"{name}\" was not served: {reason}. Its folder was moved to {}",
                    moved.display()
                ),
            ),
            Err(error) => refused(
                "START_FAILED",
                format!(
                    "ledger \"{name}\" was not served: {reason}. Its folder could not be moved aside ({error}), so the next boot will try it again"
                ),
            ),
        }
    }

    /// Serve `running`, started as `name`, and say so.
    async fn serve(&self, name: &str, running: RunningLedger) -> Result<LedgerInfo, Refusal> {
        let node_id = running.node_id.clone();
        if let Err(running) = self
            .ledgers
            .insert_running(name, running, self.node.graphiql)
            .await
        {
            stop(name, *running).await;
            return Err(refused(
                "LEDGER_EXISTS",
                format!("ledger \"{name}\" is already served"),
            ));
        }
        info!(ledger = %name, "ledger served");
        Ok(LedgerInfo {
            name: name.to_owned(),
            served: true,
            reason: None,
            node_id,
        })
    }

    /// Remove ledger `name`: stop it and move its folder aside.
    pub(crate) async fn remove(&self, name: &str) -> Result<RemovedLedger, Refusal> {
        let _busy = self.busy.lock().await;
        Self::folder_name(name)?;
        let folder = self.folder(name);
        let on_disk = folder.symlink_metadata().is_ok();
        match self.ledgers.take(name).await {
            Some(Taken::Running(Some(running))) => stop(name, *running).await,
            Some(_) => {}
            None if on_disk => {}
            None => {
                return Err(refused(
                    "NO_SUCH_LEDGER",
                    format!("this node has no ledger named \"{name}\""),
                ))
            }
        }
        if !on_disk {
            info!(ledger = %name, "ledger removed; it had no folder");
            return Ok(RemovedLedger {
                name: name.to_owned(),
                moved_to: None,
            });
        }
        match move_aside(&self.ledgers_dir, name, "") {
            Ok(moved) => {
                info!(ledger = %name, moved_to = %moved.display(), "ledger removed");
                Ok(RemovedLedger {
                    name: name.to_owned(),
                    moved_to: Some(moved.display().to_string()),
                })
            }
            Err(error) => {
                let reason = format!(
                    "stopped, but its folder could not be moved aside ({error}); the next boot serves it again"
                );
                error!(ledger = %name, %reason, "ledger not served");
                self.ledgers.insert_failed(name, reason.clone()).await;
                Err(refused(
                    "MOVE_FAILED",
                    format!("ledger \"{name}\" was {reason}"),
                ))
            }
        }
    }

    /// Restart folder ledger `name` from its `ledger.json`. Settings that do
    /// not load, or conflict with another ledger, are refused before anything
    /// stops: the ledger keeps serving as it was.
    pub(crate) async fn restart(&self, name: &str) -> Result<LedgerInfo, Refusal> {
        let _busy = self.busy.lock().await;
        Self::folder_name(name)?;
        let folder = self.folder(name);
        if !folder.join(LEDGER_FILE).is_file() {
            return Err(refused(
                "NO_SUCH_LEDGER",
                format!(
                    "ledger \"{name}\" has no {LEDGER_FILE} in ledgersDir ({})",
                    folder.display()
                ),
            ));
        }
        let config = LedgerConfig::load_folder(&folder)
            .map_err(|error| refused("INVALID_INPUT", error.to_string()))?;
        if let Some(reason) = self.conflict(name, &config).await {
            return Err(refused("LEDGER_CONFLICT", reason));
        }
        if let Some(Taken::Running(Some(running))) = self.ledgers.take(name).await {
            stop(name, *running).await;
        }
        match ledger_runtime::start(name, &config, &self.node).await {
            Ok(running) => self.serve(name, running).await,
            Err(ledger_runtime::StartFailed) => {
                let reason = "it could not start; the node's log says why".to_owned();
                self.ledgers.insert_failed(name, reason.clone()).await;
                Err(refused(
                    "START_FAILED",
                    format!("ledger \"{name}\" was stopped and not served again: {reason}"),
                ))
            }
        }
    }
}

/// Stop `running`, logging under its name.
async fn stop(name: &str, running: RunningLedger) {
    running
        .stop()
        .instrument(tracing::info_span!("ledger", ledger = %name))
        .await;
}

/// Write `<ledgers_dir>/.adding-<name>-…/ledger.json` (folder 0700, file
/// 0600), synced, and return the folder.
fn write_staging(ledgers_dir: &Path, name: &str, settings: &str) -> std::io::Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if !ledgers_dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(ledgers_dir)?;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let staging = ledgers_dir.join(format!(".adding-{name}-{}-{nanos}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(staging.join(LEDGER_FILE))?;
    file.write_all(settings.as_bytes())?;
    file.sync_all()?;
    Ok(staging)
}

/// Rename `from` to `to` — which must not exist — and sync the directory
/// that holds them, so the rename is on disk before the ledger starts.
fn place(from: &Path, to: &Path) -> std::io::Result<()> {
    if to.symlink_metadata().is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} exists", to.display()),
        ));
    }
    std::fs::File::open(from)?.sync_all()?;
    std::fs::rename(from, to)?;
    if let Some(parent) = to.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Move ledger `name`'s folder to `<ledgers_dir>/.removed/<name>-<UTC
/// time><tag>` (`-2`, `-3`… after it if that is taken) and return where.
fn move_aside(ledgers_dir: &Path, name: &str, tag: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let removed = ledgers_dir.join(".removed");
    if !removed.exists() {
        std::fs::DirBuilder::new().mode(0o700).create(&removed)?;
    }
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let base = format!("{name}-{stamp}{tag}");
    let mut target = removed.join(&base);
    let mut next = 2;
    while target.symlink_metadata().is_ok() {
        target = removed.join(format!("{base}-{next}"));
        next += 1;
    }
    std::fs::rename(ledgers_dir.join(name), &target)?;
    std::fs::File::open(&removed)?.sync_all()?;
    std::fs::File::open(ledgers_dir)?.sync_all()?;
    Ok(target)
}

fn admin<'a>(ctx: &Context<'a>) -> &'a Arc<NodeAdmin> {
    ctx.data_unchecked::<Arc<NodeAdmin>>()
}

pub(crate) struct NodeQuery;

#[Object]
impl NodeQuery {
    /// Every ledger the node holds, by name: served, or refused and why.
    async fn ledgers(&self, ctx: &Context<'_>) -> Vec<LedgerInfo> {
        admin(ctx)
            .ledgers
            .states()
            .await
            .into_iter()
            .map(LedgerInfo::from)
            .collect()
    }
}

pub(crate) struct NodeMutation;

#[Object]
impl NodeMutation {
    /// Add and start ledger `name`, its folder made in `ledgersDir` with
    /// `settings` as its `ledger.json` (none: `{}`, a ledger of its own with
    /// no mesh).
    #[graphql(complexity = "CHANGE_COMPLEXITY")]
    async fn add_ledger(
        &self,
        ctx: &Context<'_>,
        name: String,
        settings: Option<String>,
    ) -> async_graphql::Result<LedgerInfo> {
        admin(ctx)
            .add(&name, settings.as_deref())
            .await
            .map_err(Refusal::into_error)
    }

    /// Stop ledger `name` and move its folder to `ledgersDir/.removed/`.
    #[graphql(complexity = "CHANGE_COMPLEXITY")]
    async fn remove_ledger(
        &self,
        ctx: &Context<'_>,
        name: String,
    ) -> async_graphql::Result<RemovedLedger> {
        admin(ctx).remove(&name).await.map_err(Refusal::into_error)
    }

    /// Stop ledger `name` and start it again from its `ledger.json`.
    #[graphql(complexity = "CHANGE_COMPLEXITY")]
    async fn restart_ledger(
        &self,
        ctx: &Context<'_>,
        name: String,
    ) -> async_graphql::Result<LedgerInfo> {
        admin(ctx).restart(&name).await.map_err(Refusal::into_error)
    }
}

/// The node endpoint's schema, over `admin`.
pub(crate) fn node_schema(admin: Arc<NodeAdmin>, introspection: bool) -> NodeSchema {
    let mut builder = Schema::build(NodeQuery, NodeMutation, EmptySubscription)
        .limit_depth(crate::graphql::GRAPHQL_MAX_DEPTH)
        .limit_complexity(NODE_MAX_COMPLEXITY)
        .data(admin);
    if !introspection {
        builder = builder.disable_introspection();
    }
    builder.finish()
}

/// `/node/graphql`: run the request on a task of its own, which a request cut
/// short does not stop (a ledger is never left half added or half stopped).
pub(crate) async fn node_graphql(
    State(schema): State<NodeSchema>,
    request: GraphQLRequest,
) -> GraphQLResponse {
    let request = request.into_inner();
    match crate::spawn_detached_in_span(async move { schema.execute(request).await }).await {
        Ok(response) => response.into(),
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => async_graphql::Response::from_errors(vec![async_graphql::ServerError::new(
            format!("the request did not finish: {error}"),
            None,
        )])
        .into(),
    }
}

/// The operator key, or 401 — exactly a wrong key's answer anywhere else. A
/// person's key, from any ledger's access list, is refused.
pub(crate) async fn operator_only(
    State(ledgers): State<Ledgers>,
    request: Request,
    next: Next,
) -> Response {
    if ledgers.is_operator(request.headers()).await {
        next.run(request).await
    } else {
        crate::auth::unauthorized()
    }
}

/// A node with the node endpoint, for tests here and in `ledger_cli`.
#[cfg(test)]
pub(crate) mod test_node {
    use std::collections::HashSet;
    use std::path::Path;
    use std::sync::Arc;

    use axum::Router;
    use tower_http::cors::CorsLayer;

    use super::{node_schema, NodeAdmin};
    use crate::config::LedgerConfig;
    use crate::ledger_runtime::{self, NodeIds, NodeSettings};
    use crate::ledgers::Ledgers;
    use crate::rate_limit::RateLimiter;
    use crate::request_guard::RequestGuardState;

    pub(crate) const OPERATOR: &str = "operator-key-for-the-node-endpoint-tests-0123456789";

    pub(crate) struct Node {
        pub dir: tempfile::TempDir,
        pub app: Router,
        pub admin: Arc<NodeAdmin>,
        pub ledgers: Ledgers,
    }

    impl Node {
        pub(crate) fn ledgers_dir(&self) -> std::path::PathBuf {
            self.dir.path().join("ledgers")
        }
    }

    /// The config file's ledger at `path`, as a node with only `ledgerPath`
    /// set has it.
    fn ledger_at(path: &Path) -> LedgerConfig {
        let file = tempfile::NamedTempFile::new().expect("config file");
        std::fs::write(file.path(), r#"{ "ledgerPath": "./data/ledger.bean" }"#).expect("write");
        let mut config = crate::config::NodeConfig::load_from_path(&file.path().to_path_buf())
            .expect("config")
            .ledger_config();
        config.ledger_path = path.to_string_lossy().into_owned();
        config
    }

    /// A node serving its config file's ledger, with an empty `ledgersDir`
    /// and the node endpoint.
    pub(crate) async fn node() -> Node {
        // Under the working directory, where a ledger's paths must resolve.
        let dir = tempfile::Builder::new()
            .prefix(".test-ledgers-")
            .tempdir_in(".")
            .expect("temp dir");
        let settings = NodeSettings {
            auth_enabled: true,
            operator_key: OPERATOR.to_owned(),
            graphiql: false,
            public_bind: false,
            node_ids: NodeIds::default(),
        };
        let ledgers = Ledgers::new(true, OPERATOR.to_owned(), 64, RateLimiter::graphql());
        let default = ledger_runtime::start(
            "default",
            &ledger_at(&dir.path().join("default.bean")),
            &settings,
        )
        .await
        .expect("the default ledger starts");
        assert!(ledgers
            .insert_running("default", default, false)
            .await
            .is_ok());
        let admin = Arc::new(NodeAdmin::new(
            ledgers.clone(),
            dir.path().join("ledgers"),
            settings,
            crate::config::MAX_LEDGERS,
        ));
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
            Some(node_schema(Arc::clone(&admin), false)),
        );
        Node {
            dir,
            app,
            admin,
            ledgers,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::test_node::{node, OPERATOR};
    use crate::config::{ledger_folders, LedgerConfig};

    async fn post(app: &Router, path: &str, key: Option<&str>, body: Value) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "127.0.0.1")
            .header("content-type", "application/json");
        if let Some(key) = key {
            request = request.header("x-api-key", key);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).expect("request"))
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

    /// `query` on the node endpoint with the operator key.
    async fn node_query(app: &Router, query: &str, variables: Value) -> Value {
        let (status, body) = post(
            app,
            "/node/graphql",
            Some(OPERATOR),
            json!({ "query": query, "variables": variables }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    async fn add(app: &Router, name: &str, settings: Option<&str>) -> Value {
        node_query(
            app,
            "mutation($name: String!, $settings: String) { addLedger(name: $name, settings: $settings) { name served reason nodeId } }",
            json!({ "name": name, "settings": settings }),
        )
        .await
    }

    async fn remove(app: &Router, name: &str) -> Value {
        node_query(
            app,
            "mutation($name: String!) { removeLedger(name: $name) { name movedTo } }",
            json!({ "name": name }),
        )
        .await
    }

    async fn restart(app: &Router, name: &str) -> Value {
        node_query(
            app,
            "mutation($name: String!) { restartLedger(name: $name) { name served reason nodeId } }",
            json!({ "name": name }),
        )
        .await
    }

    fn code(body: &Value) -> Option<&str> {
        body["errors"][0]["extensions"]["code"].as_str()
    }

    async fn open_account(app: &Router, path: &str, account: &str) -> (StatusCode, Value) {
        post(
            app,
            path,
            Some(OPERATOR),
            json!({ "query": format!(r#"mutation {{ openAccount(name: "{account}", date: "2026-01-01") }}"#) }),
        )
        .await
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    /// 003 step 4: a ledger added while the node runs is served at once at
    /// `/ledgers/<name>/graphql`, its folder is in place for the next boot —
    /// folder 0700, `ledger.json` 0600, nothing left under a temporary name —
    /// and a ledger that signs gets its node key made with it.
    ///
    /// Bug-catch: start the ledger without serving it and its requests get
    /// 404; leave the folder under its temporary name and the next boot does
    /// not serve it; make no key and a ledger that signs cannot start.
    #[tokio::test]
    async fn an_added_ledger_is_served_at_once_and_kept_for_the_next_boot() {
        let node = node().await;
        let added = add(&node.app, "acme", None).await;
        assert_eq!(
            added["data"]["addLedger"],
            json!({ "name": "acme", "served": true, "reason": null, "nodeId": null }),
            "{added}"
        );
        let (status, body) = open_account(&node.app, "/ledgers/acme/graphql", "Assets:Bank").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["errors"].is_null(), "{body}");

        let folder = node.ledgers_dir().join("acme");
        assert_eq!(mode(&folder), 0o700);
        assert_eq!(mode(&folder.join("ledger.json")), 0o600);
        let names: Vec<String> = std::fs::read_dir(node.ledgers_dir())
            .expect("ledgersDir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["acme"], "nothing left under a temporary name");
        let folders = ledger_folders(&node.ledgers_dir()).expect("folders");
        assert_eq!(folders.len(), 1);
        assert!(LedgerConfig::load_folder(&folder).is_ok());

        let signing = r#"{ "signing": { "enabled": true }, "p2p": { "meshId": "beta-books" } }"#;
        let added = add(&node.app, "beta", Some(signing)).await;
        assert_eq!(added["data"]["addLedger"]["served"], true, "{added}");
        let node_id = added["data"]["addLedger"]["nodeId"]
            .as_str()
            .unwrap_or_else(|| panic!("a node id: {added}"))
            .to_owned();
        assert!(node.ledgers_dir().join("beta/iroh.secret").is_file());

        let listed = node_query(&node.app, "{ ledgers { name served nodeId } }", json!({})).await;
        assert_eq!(
            listed["data"]["ledgers"],
            json!([
                { "name": "acme", "served": true, "nodeId": null },
                { "name": "beta", "served": true, "nodeId": node_id },
                { "name": "default", "served": true, "nodeId": null },
            ]),
            "{listed}"
        );
        node.admin.stop_all().await;
    }

    /// 003 step 4: a removed ledger is stopped — its requests answer as a
    /// name not served, its books are whole in its `.bean` — and its folder
    /// is moved to `.removed/<name>-<UTC time>`; the next boot does not serve
    /// it, and a ledger added under its name is a new one. Its folder moved
    /// back by hand — here under another name — and restarted, it is served
    /// again with its books and its node id.
    ///
    /// Bug-catch: move the folder without stopping the ledger and its node id
    /// is never freed: moved back, the ledger is refused as a copy of itself.
    #[tokio::test]
    async fn a_removed_ledger_is_stopped_and_its_folder_moved_aside() {
        let node = node().await;
        let signing = r#"{ "signing": { "enabled": true }, "p2p": { "meshId": "acme-books" } }"#;
        let added = add(&node.app, "acme", Some(signing)).await;
        let node_id = added["data"]["addLedger"]["nodeId"].clone();
        assert!(node_id.is_string(), "{added}");
        for account in ["Assets:Bank", "Income:Sales"] {
            let (_, body) = open_account(&node.app, "/ledgers/acme/graphql", account).await;
            assert!(body["errors"].is_null(), "{body}");
        }
        let (_, body) = post(
            &node.app,
            "/ledgers/acme/graphql",
            Some(OPERATOR),
            json!({ "query": r#"mutation { appendTransaction(input: { date: "2026-01-02", narration: "acme sale", postings: [
                { account: "Assets:Bank", amount: { number: "5", currency: "USD" } },
                { account: "Income:Sales" }] }) { txid } }"# }),
        )
        .await;
        assert!(body["errors"].is_null(), "{body}");

        let removed = remove(&node.app, "acme").await;
        let moved = removed["data"]["removeLedger"]["movedTo"]
            .as_str()
            .unwrap_or_else(|| panic!("moved: {removed}"))
            .to_owned();
        let moved = Path::new(&moved);
        assert_eq!(
            moved.parent(),
            Some(node.ledgers_dir().join(".removed").as_path())
        );
        assert!(moved
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("acme-20") && name.ends_with('Z')));
        assert!(!node.ledgers_dir().join("acme").exists());
        let books = std::fs::read_to_string(moved.join("ledger.bean")).expect("the books moved");
        assert!(
            books.contains("acme sale"),
            "the journal was folded in: {books}"
        );
        assert!(
            !moved.join("ledger.bean.journal").exists(),
            "nothing left to fold in"
        );
        assert!(moved.join("ledger.json").is_file());

        let (status, body) = open_account(&node.app, "/ledgers/acme/graphql", "Assets:Cash").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(ledger_folders(&node.ledgers_dir())
            .expect("folders")
            .is_empty());

        let added = add(&node.app, "acme", None).await;
        assert_eq!(added["data"]["addLedger"]["served"], true, "{added}");
        let books = std::fs::read_to_string(node.ledgers_dir().join("acme/ledger.bean"))
            .unwrap_or_default();
        assert!(!books.contains("acme sale"), "a new ledger: {books}");

        std::fs::rename(moved, node.ledgers_dir().join("acme-restored")).expect("moved back");
        let restarted = restart(&node.app, "acme-restored").await;
        assert_eq!(
            restarted["data"]["restartLedger"]["served"], true,
            "{restarted}"
        );
        assert_eq!(restarted["data"]["restartLedger"]["nodeId"], node_id);
        let (_, body) = post(
            &node.app,
            "/ledgers/acme-restored/graphql",
            Some(OPERATOR),
            json!({ "query": "{ journal { narration } }" }),
        )
        .await;
        assert_eq!(
            body["data"]["journal"],
            json!([{ "narration": "acme sale" }]),
            "{body}"
        );
        node.admin.stop_all().await;
    }

    /// 003 step 4: a change the node refuses changes nothing — no folder, no
    /// temporary folder, nothing stopped: a bad name, `default`, settings
    /// that are not a `ledger.json`, a name already used, a mesh another
    /// ledger is in; removing or restarting a ledger that is not there.
    ///
    /// Bug-catch: skip the conflict check and two ledgers serve one mesh;
    /// leave the temporary folder of a refused add and `ledgersDir` fills
    /// with them.
    #[tokio::test]
    async fn a_change_the_node_refuses_changes_nothing() {
        let node = node().await;
        let mesh = r#"{ "signing": { "enabled": true }, "p2p": { "meshId": "acme-books" } }"#;
        assert_eq!(
            add(&node.app, "acme", Some(mesh)).await["data"]["addLedger"]["served"],
            true
        );
        for (name, settings, expected) in [
            ("default", None, "INVALID_INPUT"),
            ("Acme", None, "INVALID_INPUT"),
            ("beta", Some("[1, 2]"), "INVALID_INPUT"),
            (
                "beta",
                Some(r#"{ "ledgerPath": "/etc/passwd" }"#),
                "INVALID_INPUT",
            ),
            (
                "beta",
                Some(r#"{ "p2p": { "secretKeyPath": "/tmp/key" } }"#),
                "INVALID_INPUT",
            ),
            ("acme", None, "LEDGER_EXISTS"),
            ("beta", Some(mesh), "LEDGER_CONFLICT"),
        ] {
            let body = add(&node.app, name, settings).await;
            assert_eq!(code(&body), Some(expected), "{name} {settings:?}: {body}");
        }
        for (body, expected) in [
            (remove(&node.app, "default").await, "INVALID_INPUT"),
            (remove(&node.app, "beta").await, "NO_SUCH_LEDGER"),
            (restart(&node.app, "beta").await, "NO_SUCH_LEDGER"),
            (restart(&node.app, "default").await, "INVALID_INPUT"),
        ] {
            assert_eq!(code(&body), Some(expected), "{body}");
        }
        let names: Vec<String> = std::fs::read_dir(node.ledgers_dir())
            .expect("ledgersDir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["acme"]);
        let (_, body) = open_account(&node.app, "/ledgers/acme/graphql", "Assets:Bank").await;
        assert!(body["errors"].is_null(), "acme still served: {body}");
        node.admin.stop_all().await;
    }

    /// 003 step 4: a restart picks up an edited `ledger.json`; one that does
    /// not load, or conflicts with another ledger, is refused before
    /// anything stops — the ledger serves on as it was; and a ledger refused
    /// at boot (or a folder made by hand) is served once its folder is fixed.
    ///
    /// Bug-catch: stop the ledger before loading its new settings and a typo
    /// in `ledger.json` takes it offline.
    #[tokio::test]
    async fn a_restart_picks_up_the_folder_or_keeps_the_ledger_as_it_was() {
        let node = node().await;
        let settings = |mesh: &str| {
            format!(r#"{{ "signing": {{ "enabled": true }}, "p2p": {{ "meshId": "{mesh}" }} }}"#)
        };
        let acme = add(&node.app, "acme", Some(&settings("acme-books"))).await;
        let node_id = acme["data"]["addLedger"]["nodeId"].clone();
        add(&node.app, "beta", Some(&settings("beta-books"))).await;
        let file = node.ledgers_dir().join("acme/ledger.json");
        let mesh_of = |configs: Vec<(String, LedgerConfig)>| {
            configs
                .into_iter()
                .find(|(name, _)| name == "acme")
                .and_then(|(_, config)| config.p2p.mesh_id)
        };

        std::fs::write(&file, settings("acme-books-2")).expect("edit");
        let restarted = restart(&node.app, "acme").await;
        assert_eq!(
            restarted["data"]["restartLedger"]["served"], true,
            "{restarted}"
        );
        assert_eq!(
            restarted["data"]["restartLedger"]["nodeId"], node_id,
            "the same key"
        );
        assert_eq!(
            mesh_of(node.ledgers.served_configs("").await).as_deref(),
            Some("acme-books-2")
        );

        for (edit, expected) in [
            ("{ not json".to_owned(), "INVALID_INPUT"),
            (settings("beta-books"), "LEDGER_CONFLICT"),
        ] {
            std::fs::write(&file, &edit).expect("edit");
            let body = restart(&node.app, "acme").await;
            assert_eq!(code(&body), Some(expected), "{body}");
            let (_, body) = post(
                &node.app,
                "/ledgers/acme/graphql",
                Some(OPERATOR),
                json!({ "query": "{ verify { ok } }" }),
            )
            .await;
            assert_eq!(body["data"]["verify"]["ok"], true, "acme serves on: {body}");
            assert_eq!(
                mesh_of(node.ledgers.served_configs("").await).as_deref(),
                Some("acme-books-2")
            );
        }

        // Refused at boot, then fixed.
        let gamma = node.ledgers_dir().join("gamma");
        std::fs::create_dir(&gamma).expect("folder");
        std::fs::write(gamma.join("ledger.json"), "{ not json").expect("write");
        node.ledgers
            .insert_failed("gamma", "its ledger.json does not parse".to_owned())
            .await;
        std::fs::write(gamma.join("ledger.json"), "{}").expect("fix");
        let restarted = restart(&node.app, "gamma").await;
        assert_eq!(
            restarted["data"]["restartLedger"]["served"], true,
            "{restarted}"
        );
        // Made by hand while the node ran.
        let delta = node.ledgers_dir().join("delta");
        std::fs::create_dir(&delta).expect("folder");
        std::fs::write(delta.join("ledger.json"), "{}").expect("write");
        let restarted = restart(&node.app, "delta").await;
        assert_eq!(
            restarted["data"]["restartLedger"]["served"], true,
            "{restarted}"
        );
        let (_, body) = open_account(&node.app, "/ledgers/delta/graphql", "Assets:Bank").await;
        assert!(body["errors"].is_null(), "{body}");
        node.admin.stop_all().await;
    }

    /// 003 step 4: the node endpoint answers the operator key only — a
    /// person's key, even an admin's of one of its ledgers, and no key
    /// at all get 401, as a wrong key does anywhere.
    ///
    /// Bug-catch: route `/node/graphql` without the operator check and a
    /// company's admin can add and remove the other companies' ledgers.
    #[tokio::test]
    async fn the_node_endpoint_is_the_operators_only() {
        let node = node().await;
        // People need a ledger that signs (an access list).
        let signing = r#"{ "signing": { "enabled": true }, "p2p": { "meshId": "acme-books" } }"#;
        add(&node.app, "acme", Some(signing)).await;
        let (_, granted) = post(
            &node.app,
            "/ledgers/acme/graphql",
            Some(OPERATOR),
            json!({ "query": r#"mutation { grantAccess(name: "Ana", role: ADMIN) { key } }"# }),
        )
        .await;
        let person = granted["data"]["grantAccess"]["key"]
            .as_str()
            .unwrap_or_else(|| panic!("a key: {granted}"))
            .to_owned();
        let list = json!({ "query": "{ ledgers { name } }" });
        for key in [Some(person.as_str()), None, Some("not-a-key")] {
            let (status, _) = post(&node.app, "/node/graphql", key, list.clone()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{key:?}");
        }
        let (status, body) = post(&node.app, "/node/graphql", Some(OPERATOR), list).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        node.admin.stop_all().await;
    }

    /// 003 step 4: a change whose request is cut short — a timeout, a closed
    /// connection — still runs to its end: here an add, queued behind another
    /// change, is served once that one finishes though its caller is gone.
    ///
    /// Bug-catch: run the change in the request's own future and a cut-short
    /// request drops it wherever it was — a folder placed and never served,
    /// a ledger stopped and never started again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_change_cut_short_still_runs_to_its_end() {
        let node = node().await;
        let busy = node.admin.busy.lock().await;
        let cut_short = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            add(&node.app, "acme", None),
        )
        .await;
        assert!(cut_short.is_err(), "the add waits for the change before it");
        drop(busy);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !node.ledgers.holds("acme").await {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("acme is added though its caller left");
        let (_, body) = open_account(&node.app, "/ledgers/acme/graphql", "Assets:Bank").await;
        assert!(body["errors"].is_null(), "{body}");
        node.admin.stop_all().await;
    }

    /// 003 step 4: a removal waits for the requests the ledger is serving —
    /// none is left to write after its stop — while every other ledger
    /// answers as usual, and no new request reaches the one going.
    ///
    /// Bug-catch: hand the ledger back without waiting and a request in
    /// flight writes after the stop; hold the registry while waiting and
    /// every ledger stops answering during a removal.
    #[tokio::test]
    async fn a_removal_waits_for_requests_in_flight_and_no_one_else() {
        let node = node().await;
        add(&node.app, "acme", None).await;
        let in_flight = node.ledgers.slot_for_test("acme").await;
        let removing = {
            let app = node.app.clone();
            tokio::spawn(async move { remove(&app, "acme").await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !removing.is_finished(),
            "it waits for the request in flight"
        );
        let (_, body) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            open_account(&node.app, "/graphql", "Assets:Bank"),
        )
        .await
        .expect("the others answer while it waits");
        assert!(body["errors"].is_null(), "the others answer: {body}");
        let (status, _) = open_account(&node.app, "/ledgers/acme/graphql", "Assets:Bank").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no new request reaches it");
        drop(in_flight);
        let removed = tokio::time::timeout(std::time::Duration::from_secs(10), removing)
            .await
            .expect("the removal finishes once the request has")
            .expect("joined");
        assert!(
            removed["data"]["removeLedger"]["movedTo"].is_string(),
            "{removed}"
        );
        node.admin.stop_all().await;
    }
}
