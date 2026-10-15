mod access_control;
mod access_list;
mod anti_entropy_alpn;
mod auth;
mod config;
mod connection_limiter;
mod fetch_coordinator;
mod graphql;
mod health;
mod http_server;
mod ledger_commit;
mod ledger_lock;
mod ledger_runtime;
mod ledgers;
mod p2p_service;
mod peer_addresses;
mod peer_connections;
mod rate_limit;
mod request_guard;
#[cfg(test)]
mod test_support;
mod user_cli;

#[cfg(test)]
use auth::AuthState;
use config::NodeConfig;
#[cfg(test)]
use graphql::AppSchema;
use health::probe_local_health;
#[cfg(test)]
use health::HealthState;
use rate_limit::RateLimiter;
use request_guard::RequestGuardState;

use axum::routing::{get, post};
use axum::{middleware, Router};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{error, info, warn};

/// Explicit GraphQL HTTP body cap (M-7), enforced by `RequestBodyLimitLayer`,
/// which wraps the request body itself: an oversized payload is refused with
/// 413 instead of being buffered into RAM (H-05).
///
/// Never reintroduce `axum::extract::DefaultBodyLimit` as the sole limit. It is
/// opt-in — it only inserts an extension that cooperating extractors consult —
/// and async-graphql's `GraphQLRequest` extractor reads the raw body stream via
/// `into_data_stream()`, so the cap never binds and bodies buffer unbounded.
const GRAPHQL_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// The log filter a node runs under when `RUST_LOG` is unset (T77 / L-72).
///
/// `info` for this node's own lines, and `error` for iroh's protocol router:
/// that module logs one `WARN` per failed inbound handshake — an unknown ALPN
/// dies in the TLS handshake (`accepting failed`), and a handler returning
/// `Err` is logged again (`ended with error`) — so on a public QUIC bind any
/// dialer could drive ~290–730 B of log per handshake, unthrottled (the audit
/// measured ≈ 83 KB/s from eight loopback dialers at 0.8 % CPU). This node's
/// own handler never returns `Err` for a refusal and throttles its own refusal
/// lines per source; the router's lines carry nothing an operator can act on
/// that this node does not already log. An explicit `RUST_LOG` replaces this
/// whole string, so an operator who sets one on a public bind should keep
/// `iroh::protocol=error` in it (README, "Log volume on a public bind").
const DEFAULT_LOG_FILTER: &str = "info,iroh::protocol=error";

/// Resolve the configured ledger path (a symlinked `.bean` is worked at its
/// target, T82 / L-84), lock the result (M-17), and — under that lock, where
/// no sibling process can be mid-rewrite — sweep the stale temporaries an
/// older build left beside the link (T94 / L-118: `boot` is handed the target,
/// so its own sweep never saw the link's directory). The path returned is the
/// one the node locks, boots, watches and reloads.
fn claim_ledger_path(configured: &Path) -> Result<(PathBuf, ledger_lock::LedgerLock), String> {
    let resolved =
        ledger::journal::resolve_ledger_path(configured).map_err(|error| error.to_string())?;
    // T101 (A5-5): a link resolution gives up on — a target missing or not
    // openable — returns the link itself. Locked as it stood, `boot` resolved
    // it again, and a target that had appeared by then was worked at under the
    // link's lock, with every recovery reload refusing the link (L-117).
    if std::fs::symlink_metadata(&resolved).is_ok_and(|metadata| metadata.is_symlink()) {
        return Err(format!(
            "ledger path {} is a symbolic link this node could not follow — its target is \
             missing or cannot be opened; create the target, or point ledgerPath at the real \
             file (L-84)",
            configured.display()
        ));
    }
    let guard = ledger_lock::acquire(&resolved)
        .map_err(|error| format!("failed to lock ledger file: {error}"))?;
    ledger::service::sweep_temporaries_beside_the_link(configured, &resolved);
    Ok((resolved, guard))
}

/// H-01: auth is on by default. A loopback node with no key configured reads
/// its key file, generating it on the first boot, and serves with that key; one
/// with auth turned off WARNs, since it serves its mutations to anything that
/// can reach the port.
fn resolve_api_key(config: &mut NodeConfig) -> Result<(), String> {
    if config.uses_api_key_file() {
        config.auth.api_key = auth::load_or_create_api_key(Path::new(&config.auth.api_key_path))
            .map_err(|error| error.to_string())?;
    } else if !config.auth.enabled {
        warn!(
            "auth.enabled is false: every GraphQL request, mutations included, is served without \
             an API key to any program or account on this machine that can reach the port. \
             Remove \"enabled\": false from the auth section to require the key (H-01)"
        );
    }
    Ok(())
}

/// The boot banner for records quarantined out of the DAG (H-08, R-12).
///
/// C25 (`docs/audits/RESIDUALS.md`): it defers to each record's own boot
/// warning for the remedy. Since T103 the amount-cap warning tells the operator
/// to delete a held block once its restatement is served — and the banner said
/// "restate … as its warning says" over a warning that said delete. A constant
/// so a test pins it (T103 noted the banner was pinned by none).
const QUARANTINE_BANNER: &str =
    "this node booted with ledger records quarantined out of the DAG: they stay in the .bean \
     (every compaction rewrites them verbatim) but are NOT served, NOT in any balance and NOT \
     replicated. The per-record boot warnings above give each one's reason — its \
     openledger-parents metadata, a disallowed character, excess fan-in, a signature that does \
     not verify, a parent no peer could resolve, or a block that does not parse at all (named \
     by line number; it has no id). If the boot warnings above include \"EVERY signature this \
     node checked failed\", fix p2p.meshId or the node key first and repair nothing: the \
     records load again once both are right. Otherwise stop the node and follow each record's \
     own warning, then restart: it says whether to repair the record, to restore it from a \
     peer or a backup (H-23), to restate the chain on ONE node only — every other node adopts \
     the restatement and must not restate — or, once that restatement is served, to delete the \
     held block (H-08, L-45, M-73)";

/// The boot banner for records the signature check quarantined (H-20).
///
/// T92 / M-69, decision (40): it defers to the per-record WARNs above it and
/// names only remedies that work. Before T92 it ended "or delete the edited
/// block and append a reversing entry instead" — the remedy T84 withdrew from
/// the ledger's own WARN and the README: deleting the block leaves what
/// descends from it held (H-23), and the reversing entry then counts twice once
/// the record returns; after enabling signing over an unsigned history,
/// following it emptied the served ledger.
const SIGNATURE_QUARANTINE_BANNER: &str =
    "ledger records QUARANTINED at boot by the signature check: they stay in the .bean (every \
     compaction writes them back) but are NOT served and NOT in any balance. The per-record \
     warnings above give each one's reason. Restore an edited record from a peer's or a \
     backup's copy; if only a record's openledger-* lines were edited, or it was written before \
     signing was enabled, delete those lines so it is re-adopted under the same id. Do not \
     delete the block itself — what descends from it stays held (H-23) — and do not append a \
     reversing entry for a record that is only held: it would count twice once the record \
     returns (H-20)";

enum CliAction {
    Serve,
    Version,
    HealthCheck,
    /// `--node-id` and what follows it (`--ledger NAME`).
    NodeId(Vec<String>),
    /// `gl-node user …` and its arguments (`user_cli`).
    User(Vec<String>),
    Usage(String),
}

const USAGE: &str =
    "Usage: gl-node [--health-check | --node-id [--ledger NAME] | --version | user …]";

fn parse_cli() -> CliAction {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => CliAction::Serve,
        Some("--version") | Some("-V") => CliAction::Version,
        Some("--health-check") => CliAction::HealthCheck,
        Some("--node-id") => CliAction::NodeId(args.collect()),
        Some("user") => CliAction::User(args.collect()),
        Some("--help") | Some("-h") => CliAction::Usage(format!("{USAGE}\n{}", user_cli::USAGE)),
        Some(other) => CliAction::Usage(format!("unknown argument: {other}\n{USAGE}")),
    }
}

/// Create the ledger file's parent directory if it is missing (§3.3).
///
/// Directories only. The `.bean` file is created by `LedgerService::boot` on the
/// ledger crate's hardened path (temp file at 0600 → fsync → rename), which is
/// the whole point of L-31: whoever creates the file decides its permissions,
/// and that decision belongs to the crate that owns the format, not to the
/// process umask.
fn ensure_ledger_parent_directory(ledger_path: &std::path::Path) -> std::io::Result<()> {
    match ledger_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() && !parent.exists() => {
            std::fs::create_dir_all(parent)
        }
        _ => Ok(()),
    }
}

/// One watcher poll of the `.bean`, on the blocking pool (M-42, T67).
///
/// The poller is moved into `spawn_blocking` and handed back with the state,
/// so its memory of the last `stat` identity survives from poll to poll while
/// the `stat` and any read + hash stay off the runtime's worker threads. A
/// panic in the poll (or the blocking pool going away at shutdown) loses that
/// memory: a fresh poller is returned, whose first poll simply reads again,
/// and `None` tells the caller to skip this tick.
async fn poll_ledger_file(
    poller: ledger::file_watcher::FilePoller,
    path: &std::path::Path,
) -> (
    ledger::file_watcher::FilePoller,
    Option<ledger::file_watcher::FileState>,
) {
    let polled = tokio::task::spawn_blocking(move || {
        let mut poller = poller;
        let state = poller.poll();
        (poller, state)
    })
    .await;
    match polled {
        Ok((poller, state)) => (poller, Some(state)),
        Err(error) => {
            warn!(%error, "ledger file poll failed; retrying at the next tick");
            (ledger::file_watcher::FilePoller::new(path), None)
        }
    }
}

fn run_health_check() -> ! {
    let config_path =
        std::env::var("GL_NODE_CONFIG").unwrap_or_else(|_| "gl-node.config.json".to_owned());
    let config = match NodeConfig::load_from_path(&PathBuf::from(&config_path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("health-check: failed to load config: {error}");
            std::process::exit(1);
        }
    };
    match probe_local_health(&config.bind_address, config.port) {
        Ok(()) => std::process::exit(0),
        Err(error) => {
            eprintln!("health-check: {error}");
            std::process::exit(1);
        }
    }
}

/// `gl-node --node-id`: print this node's EndpointId — what its peers list in
/// `p2p.bootstrapEndpointIds` and `p2p.peerAddresses` — and exit, serving
/// nothing (`docs/build-log/001-peer-discovery`). The key is loaded by the same
/// rule boot applies (below): created on first use when P2P is on (CAP-4),
/// required to exist when only signing is on, none at all otherwise. So the
/// id printed is the id the node will have, before it ever starts.
fn run_node_id(args: &[String]) -> ! {
    // Warnings to stderr — stdout carries only the id — so a key the loader
    // had to regenerate (an empty key file, L-32: a new identity peers must
    // be told) is said, not silent.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
        .init();
    let config_path =
        std::env::var("GL_NODE_CONFIG").unwrap_or_else(|_| "gl-node.config.json".to_owned());
    let config = match NodeConfig::load_from_path(&PathBuf::from(&config_path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("node-id: failed to load config: {error}");
            std::process::exit(1);
        }
    };
    // 003: `--ledger NAME` for one of the node's other ledgers, whose key is
    // in its folder; none for the config file's own.
    let ledger = match user_cli::take_ledger(args) {
        Ok((ledger, rest)) if rest.is_empty() => ledger,
        Ok((_, rest)) => {
            eprintln!("node-id: unknown argument {}\n{USAGE}", rest[0]);
            std::process::exit(2);
        }
        Err(error) => {
            eprintln!("node-id: {error}");
            std::process::exit(2);
        }
    };
    let config = if ledger == config::DEFAULT_LEDGER {
        config.ledger_config()
    } else {
        match config::LedgerConfig::load_folder(&Path::new(&config.ledgers_dir).join(&ledger)) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("node-id: ledger {ledger:?}: {error}");
                std::process::exit(1);
            }
        }
    };
    let path = PathBuf::from(&config.p2p.secret_key_path);
    let key = if config.p2p.enabled {
        p2p_service::load_or_create_secret_key(&path)
    } else if config.signing.enabled {
        p2p_service::load_secret_key(&path)
    } else {
        eprintln!("node-id: this node has no key — p2p.enabled and signing.enabled are both off");
        std::process::exit(1);
    };
    match key {
        Ok(key) => {
            println!("{}", key.iroh_secret_key().public());
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!(
                "node-id: the node key at {} could not be loaded: {error}",
                path.display()
            );
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    match parse_cli() {
        CliAction::Version => {
            println!("gl-node {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        CliAction::HealthCheck => {
            run_health_check();
        }
        CliAction::NodeId(args) => {
            run_node_id(&args);
        }
        CliAction::User(args) => {
            user_cli::run(&args);
        }
        CliAction::Usage(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
        CliAction::Serve => {}
    }

    // Initialize structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER)),
        )
        .init();

    // Determine config path from env or default.
    let config_path =
        std::env::var("GL_NODE_CONFIG").unwrap_or_else(|_| "gl-node.config.json".to_owned());
    let config_path = PathBuf::from(&config_path);

    info!(path = %config_path.display(), "loading configuration");

    let mut config = match NodeConfig::load_from_path(&config_path) {
        Ok(config) => config,
        Err(error) => {
            error!(%error, "failed to load configuration — aborting");
            std::process::exit(1);
        }
    };

    if let Err(error) = resolve_api_key(&mut config) {
        error!(%error, path = %config.auth.api_key_path, "failed to load or create the API key — aborting");
        std::process::exit(1);
    }

    // 003-multi-ledger-node: each ledger is started by
    // `ledger_runtime::start`, which runs the boot sequence that lived here —
    // key, author, signer, verifier, operator input, compaction, then P2P and
    // the watcher (H-13, L-04, T80) — in the same order: the config file's own
    // ledger (`default`), then every folder in `ledgersDir`.
    let node_settings = ledger_runtime::NodeSettings {
        auth_enabled: config.auth.enabled,
        operator_key: config.auth.api_key.clone(),
        graphiql: config.graphiql_enabled(),
        public_bind: config.binds_non_loopback(),
        node_ids: ledger_runtime::NodeIds::default(),
    };
    // Rate limiter keyed on the real client (M-04). With no trusted proxy the
    // key is the TCP peer, which behind a terminator is the proxy itself — one
    // bucket for every client at once — so say so loudly rather than silently
    // rate-limiting the whole internet as a single caller.
    //
    // L-37: the boot-time half fires whenever the config says a proxy is (or
    // must be) in front — `tls.mode: "terminated"` *or* a non-loopback bind —
    // not on the terminated flag alone. (Validation makes the second imply the
    // first today; keying on both keeps the warning honest if that rule ever
    // moves.) A plain loopback dev node stays quiet. The case config cannot
    // see — a loopback bind behind a same-host proxy — is caught at runtime by
    // the limiter itself, the first time an untrusted peer sends
    // X-Forwarded-For (`RateLimiter::note_untrusted_forwarder`).
    let trusted_proxies = config.trusted_proxy_set();
    if trusted_proxies.is_empty() {
        if config.tls.mode == "terminated" || config.binds_non_loopback() {
            warn!(
                tls_mode = %config.tls.mode,
                public_bind = config.binds_non_loopback(),
                "trustedProxies is empty on a node that sits behind a reverse proxy — every client behind the proxy shares one rate-limit bucket (M-04), and the proxy is subject to the per-IP connection cap like any single client (M-33); list the proxy address(es) in trustedProxies"
            );
        }
    } else {
        info!(
            proxies = trusted_proxies.len(),
            "X-Forwarded-For trusted from configured reverse proxies (rightmost untrusted entry wins)"
        );
    }
    let rate_limiter = RateLimiter::graphql().with_trusted_proxies(trusted_proxies.clone());

    let served_ledgers = ledgers::Ledgers::new(
        config.auth.enabled,
        config.auth.api_key.clone(),
        config.http.max_requests_per_ledger,
        rate_limiter.clone(),
    );
    start_ledgers(&config, &node_settings, &served_ledgers).await;
    // A node with nothing to serve stops, as a one-ledger node whose ledger
    // could not start always has; one healthy ledger is enough to serve.
    if served_ledgers.running_count().await == 0 {
        error!("no ledger could be served — aborting");
        std::process::exit(1);
    }

    // Host / Content-Type / Origin guard state (H-01).
    let guard_state = RequestGuardState {
        allowed_hosts: Arc::new(config.allowed_host_set()),
        allowed_origins: Arc::new(config.cors.allowed_origins.iter().cloned().collect()),
        // L-51: behind a terminator the node's public origin is https.
        tls_terminated: config.tls.mode == "terminated",
    };

    // A non-loopback bind with auth disabled is rejected at config validation
    // (M-2), so by this point a public bind always has auth enabled.
    if config.tls.mode == "terminated" {
        info!("TLS assumed terminated at the host or reverse proxy (in-process TLS is not implemented)");
    }

    let application = build_application_with_limiter(
        served_ledgers.clone(),
        guard_state,
        config.cors_layer(),
        config.graphiql_enabled(),
        rate_limiter,
    );

    // Bind and serve.
    let bind_address = format!("{}:{}", config.bind_address, config.port);
    let listener = match TcpListener::bind(&bind_address).await {
        Ok(listener) => listener,
        Err(error) => {
            error!(%error, address = %bind_address, "failed to bind");
            std::process::exit(1);
        }
    };

    info!(
        address = %bind_address,
        version = env!("CARGO_PKG_VERSION"),
        ledger = %config.ledger_path,
        auth_enabled = config.auth.enabled,
        p2p_enabled = config.p2p.enabled,
        graphiql = config.graphiql_enabled(),
        "gl-node starting"
    );

    // Serve with graceful shutdown on SIGTERM / SIGINT (§3.9), under the
    // connection-level limits `axum::serve` never applied (M-13). The settings
    // come from the optional `http` config section; with the section absent
    // every field is `HttpServerSettings::default()`'s own value, which is what
    // this call site used to pass literally.
    //
    // The trusted proxies are exempt from the per-IP connection cap (M-33): a
    // terminator fans every client in through one address, so capping it as
    // one client would cap the whole node. The global cap still binds it, and
    // the terminator is required to enforce per-client limits of its own.
    let server = http_server::serve_hardened(
        listener,
        application,
        config.http_server_settings(),
        trusted_proxies,
        shutdown_signal(),
    );

    if let Err(error) = server.await {
        error!(%error, "server error");
        std::process::exit(1);
    }

    served_ledgers.stop_all().await;

    info!("gl-node shut down gracefully");
}

/// Start the config file's ledger and every ledger folder in `ledgersDir`
/// (003), each through [`ledger_runtime::start`]. A folder that does not load,
/// a ledger in conflict with one started before it (`ledgers_in_conflict`),
/// and a ledger that fails to start are each logged and recorded as refused;
/// the rest are served.
async fn start_ledgers(
    config: &NodeConfig,
    node: &ledger_runtime::NodeSettings,
    served: &ledgers::Ledgers,
) {
    let mut found: Vec<(String, Result<config::LedgerConfig, String>)> = vec![(
        config::DEFAULT_LEDGER.to_owned(),
        Ok(config.ledger_config()),
    )];
    match config::ledger_folders(Path::new(&config.ledgers_dir)) {
        Ok(folders) => {
            for (name, folder) in folders {
                // Review I-1: `default` is the config file's ledger, never a
                // folder's — it is already first in `found`.
                if name == config::DEFAULT_LEDGER {
                    error!(dir = %config.ledgers_dir, "a folder or file named \"default\" in ledgersDir is ignored: \"default\" is the config file's own ledger");
                    continue;
                }
                let loaded = folder.and_then(|path| {
                    config::LedgerConfig::load_folder(&path).map_err(|error| error.to_string())
                });
                found.push((name, loaded));
            }
        }
        Err(error) => {
            error!(%error, dir = %config.ledgers_dir, "could not read ledgersDir; its ledgers are not served");
        }
    }
    let candidates: Vec<(&str, &config::LedgerConfig)> = found
        .iter()
        .filter_map(|(name, loaded)| loaded.as_ref().ok().map(|config| (name.as_str(), config)))
        .collect();
    let conflicts: std::collections::HashMap<String, String> =
        config::ledgers_in_conflict(&candidates, config.max_ledgers)
            .into_iter()
            .collect();
    // 003 step 3: the config file's ledger first — it wins any conflict, a
    // shared node key included — then the folders in parallel, up to one per
    // core: each boot reads, hashes and verifies its whole file, and one after
    // another a node of many large ledgers kept every company waiting.
    let mut queue = Vec::new();
    for (name, loaded) in found {
        let refusal = match &loaded {
            Err(reason) => Some(reason.clone()),
            Ok(_) => conflicts.get(&name).cloned(),
        };
        match (refusal, loaded) {
            (Some(reason), _) => {
                error!(ledger = %name, %reason, "ledger not served");
                served.insert_failed(&name, reason).await;
            }
            (None, Ok(ledger_config)) => queue.push((name, ledger_config)),
            (None, Err(_)) => {}
        }
    }
    // Review: the node ids, settled in order before anything boots in parallel.
    let shared_keys: std::collections::HashMap<String, String> =
        ledger_runtime::settle_node_keys(&queue, &node.node_ids)
            .into_iter()
            .collect();
    let mut kept = Vec::new();
    for (name, ledger_config) in queue {
        match shared_keys.get(&name) {
            Some(reason) => {
                error!(ledger = %name, %reason, "ledger not served");
                served.insert_failed(&name, reason.clone()).await;
            }
            None => kept.push((name, ledger_config)),
        }
    }
    let mut queue = kept.into_iter();
    if let Some((name, ledger_config)) = queue.next() {
        let started = ledger_runtime::start(&name, &ledger_config, node).await;
        serve_started(served, &name, started, node.graphiql).await;
    }
    let parallel = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    let gate = Arc::new(tokio::sync::Semaphore::new(parallel));
    let mut starting = tokio::task::JoinSet::new();
    for (name, ledger_config) in queue {
        let (gate, node) = (Arc::clone(&gate), node.clone());
        starting.spawn(async move {
            let _turn = gate
                .acquire_owned()
                .await
                .expect("the boot gate is never closed");
            let started = ledger_runtime::start(&name, &ledger_config, &node).await;
            (name, started)
        });
    }
    while let Some(joined) = starting.join_next().await {
        match joined {
            Ok((name, started)) => serve_started(served, &name, started, node.graphiql).await,
            // Review: a panic in a ledger's boot stops the node, as it did
            // before boots ran in parallel — never a ledger silently gone,
            // perhaps still writing without its lock.
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => error!(%error, "a ledger's boot was cancelled"),
        }
    }
}

/// Record what one ledger's start gave: served, or refused with its reason.
async fn serve_started(
    served: &ledgers::Ledgers,
    name: &str,
    started: Result<ledger_runtime::RunningLedger, ledger_runtime::StartFailed>,
    graphiql: bool,
) {
    match started {
        Ok(running) => {
            info!(ledger = %name, "ledger served");
            if let Err(running) = served.insert_running(name, running, graphiql).await {
                error!(ledger = %name, "a ledger of this name is already served; stopping this one");
                running.stop().await;
            }
        }
        Err(ledger_runtime::StartFailed) => {
            served
                .insert_failed(
                    name,
                    "it could not start; this ledger's boot log says why".to_owned(),
                )
                .await;
        }
    }
}

/// Assemble the application with a default limiter (no trusted proxies).
///
/// Test-only entry point kept at the pre-M-04 arity so the router-level tests in
/// `request_guard` and `http_server` keep assembling the *real* router;
/// production goes through [`build_application_with_limiter`] with the limiter
/// built from `trustedProxies`.
#[cfg(test)]
pub(crate) fn build_application(
    schema: AppSchema,
    auth_state: AuthState,
    health_state: HealthState,
    guard_state: RequestGuardState,
    cors: CorsLayer,
    graphiql: bool,
) -> Router {
    // 003: the node serving this one ledger as its `default`.
    let ledgers = ledgers::Ledgers::new(
        auth_state.enabled,
        auth_state.api_key.clone(),
        config::default_max_requests_per_ledger(),
        RateLimiter::graphql(),
    );
    ledgers.insert_parts(
        config::DEFAULT_LEDGER,
        schema,
        auth_state,
        health_state,
        graphiql,
    );
    build_application_with_limiter(ledgers, guard_state, cors, graphiql, RateLimiter::graphql())
}

/// Assemble the full application router.
///
/// Layer order, outermost first: CORS, body limit (H-05), then per route the
/// request guard (H-01), the rate limiter and — on `/graphql` only — auth. The
/// guard is outermost among those so a rejected Host, Content-Type or Origin
/// never reaches the limiter or the schema.
///
/// 003: auth is each ledger's own, so it sits inside the ledger's router
/// (`ledgers::ledger_router`), reached through the node's routes — `/graphql`
/// and `/health` for the `default` ledger, `/ledgers/<name>/…` for the others
/// — after the guard and the limiter, as before. GraphQL's limiter is each
/// ledger's own too (a client's budget is per ledger), checked first when
/// `Ledgers::dispatch` routes the request; `/health` keeps one node-wide.
///
/// `/health` is behind the guard and a limiter too (H-01 residual, L-42), and
/// outside auth only (§2.9: it must answer an unauthenticated prober). Before
/// T55 it was outside all three, so on a loopback bind — where L-09 serves the
/// full body — a DNS-rebound page could read the version, head count and peer
/// count with any `Host`, and every call took the ledger read lock unmetered.
/// Its limiter is a [`RateLimiter::sibling`] of `limiter`: the same idea of
/// who a client is, a budget of its own.
///
/// `limiter` carries the trusted-proxy set, so how a client is identified is a
/// boot-time decision rather than a per-request one (M-04). Since 003 it
/// drives `/health` only; GraphQL's limiters are the ledgers' own, built from
/// the same limiter by `Ledgers::new` (`main` passes clones of one).
pub(crate) fn build_application_with_limiter(
    ledgers: ledgers::Ledgers,
    guard_state: RequestGuardState,
    cors: CorsLayer,
    graphiql: bool,
    limiter: RateLimiter,
) -> Router {
    // GraphQL routes — POST always; GraphiQL on GET only when enabled (the
    // `default` ledger's: its page posts to `/graphql`).
    let default_graphql = if graphiql {
        info!("GraphiQL enabled on GET /graphql");
        get(ledgers::default_graphql).post(ledgers::default_graphql)
    } else {
        info!("GraphiQL disabled — POST /graphql only");
        post(ledgers::default_graphql)
    };
    let health_limiter = limiter.sibling(
        rate_limit::HEALTH_RATE_LIMIT,
        rate_limit::HEALTH_RATE_WINDOW,
    );
    // 003 step 3: GraphQL's rate limit is each ledger's own, checked when the
    // request is routed to it (`Ledgers::dispatch`), so a client's budget is
    // per ledger.
    let graphql_routes = Router::new()
        .route("/graphql", default_graphql)
        .route("/ledgers/{name}/graphql", post(ledgers::named_graphql))
        .with_state(ledgers.clone())
        .layer(middleware::from_fn_with_state(
            guard_state.clone(),
            request_guard::request_guard,
        ));
    let health_routes = Router::new()
        .route("/health", get(ledgers::default_health))
        .route("/ledgers/{name}/health", get(ledgers::named_health))
        .with_state(ledgers)
        .layer(middleware::from_fn_with_state(
            health_limiter,
            rate_limit::rate_limit,
        ))
        .layer(middleware::from_fn_with_state(
            guard_state,
            request_guard::request_guard,
        ));

    Router::new()
        .merge(health_routes)
        .merge(graphql_routes)
        .layer(RequestBodyLimitLayer::new(GRAPHQL_MAX_BODY_BYTES))
        .layer(cors)
}

/// Build the signature provider from the key material `ledger_runtime::start`
/// already loaded.
///
/// Takes the loaded key rather than a path (L-04): the signer and the iroh
/// endpoint must be the *same* key, and the only way to guarantee that is for
/// neither of them to read the file.
///
/// Takes the already-resolved `mesh_id` rather than the config field it came
/// from (L-23), for the same reason: the signer and the ALPN verifier must bind
/// the *same* domain, so this function must not be able to derive its own.
fn build_signature_provider(
    config: &config::LedgerConfig,
    node_secret_key: Option<&p2p_service::NodeSecretKey>,
    mesh_id: &str,
) -> Option<Arc<dyn security::signing::SignatureProvider>> {
    if config.signing.enabled {
        let Some(secret_key) = node_secret_key else {
            // 003: an error for this ledger, not an exit of the node.
            error!("signing enabled but no secret key was loaded; this ledger is not served");
            return None;
        };
        // Bind signatures to this node's mesh identity so they cannot be
        // replayed into another mesh (L2 / L-23).
        // Format v2 (Facet B): the API's writes are this node's records, in its
        // own format, so the provider signs them in that format's message.
        let provider = security::signing::PeerKeySignatureProvider::from_bytes(
            secret_key.bytes(),
            mesh_id.to_owned(),
        )
        .with_version(p2p::union_merge::signature_version(
            config.format.record_format(),
        ));
        info!(public_key = %provider.public_key_hex(), "signing enabled");
        Some(Arc::new(provider))
    } else {
        info!("signing disabled");
        Some(Arc::new(security::signing::NoopSignatureProvider))
    }
}

/// `tokio::spawn`, in the span of the caller (003): a ledger's background
/// tasks log under its name.
pub(crate) fn spawn_in_span<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    use tracing::Instrument;
    tokio::spawn(future.in_current_span())
}

/// Wait for SIGTERM or SIGINT (§3.9 graceful shutdown).
///
/// On signal, returns to let the serve loop drain in-flight requests.
/// `http_server::serve_hardened` handles the (bounded) drain period.
async fn shutdown_signal() {
    let control_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = control_c => { info!("received SIGINT — shutting down"); }
        () = terminate => { info!("received SIGTERM — shutting down"); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Used by `main` before 003 moved the ledger's boot to `ledger_runtime`.
    use graphql::broadcast::TransactionBroadcast;
    use p2p::orphan_buffer::OrphanBuffer;
    use tokio::sync::RwLock;

    /// H-01: a node with the default auth section serves with the key its key
    /// file holds — generated on the first boot, the same on the next — and a
    /// node that turns auth off generates nothing.
    ///
    /// Bug-catch: skip `resolve_api_key` in boot, or leave the key empty, and
    /// the router's auth state has no key a client could send.
    #[test]
    fn h01_a_default_loopback_node_serves_with_its_key_file() {
        let directory = tempfile::tempdir().expect("temp dir");
        let key_path = directory.path().join("api.key");
        let load = |auth: &str| {
            let mut file = tempfile::NamedTempFile::new().expect("temp config file");
            std::io::Write::write_all(
                &mut file,
                format!(r#"{{ "ledgerPath": "./data/ledger.bean"{auth} }}"#).as_bytes(),
            )
            .expect("write config");
            NodeConfig::load_from_path(&file.path().to_path_buf()).expect("loads")
        };
        let key_setting = format!(
            r#", "auth": {{ "apiKeyPath": {} }}"#,
            serde_json::to_string(key_path.to_str().expect("utf-8 path")).expect("json")
        );
        let mut config = load(&key_setting);
        resolve_api_key(&mut config).expect("resolved");
        assert!(config.auth.enabled);
        assert_eq!(config.auth.api_key.len(), 64);
        assert_eq!(
            std::fs::read_to_string(&key_path).expect("the key file"),
            config.auth.api_key
        );
        let mut restarted = load(&key_setting);
        resolve_api_key(&mut restarted).expect("resolved");
        assert_eq!(restarted.auth.api_key, config.auth.api_key);

        std::fs::remove_file(&key_path).expect("remove");
        let disabled = format!(
            r#", "auth": {{ "enabled": false, "apiKeyPath": {} }}"#,
            serde_json::to_string(key_path.to_str().expect("utf-8 path")).expect("json")
        );
        let mut off = load(&disabled);
        resolve_api_key(&mut off).expect("resolved");
        assert!(off.auth.api_key.is_empty());
        assert!(!key_path.exists(), "auth off generates no key");
    }

    /// L-118 (T94): gl-node resolves a symlinked `.bean` before `boot`, so the
    /// boot is handed the target and T87's sweep beside the LINK never ran on
    /// the node — a stale `<link>.tmp.*` an older build left (a whole-ledger
    /// copy, possibly) stayed for good (A4 `case_sweep_and_remedy.py`).
    /// `claim_ledger_path` sweeps it once the lock is held, and the lock sits
    /// beside the target.
    ///
    /// Bug-catch: drop the `sweep_temporaries_beside_the_link` call and the
    /// stale temp beside the link survives.
    #[cfg(unix)]
    #[test]
    fn l118_claiming_a_linked_ledger_sweeps_the_temporaries_beside_the_link() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = directory.path().join("store");
        std::fs::create_dir(&store).unwrap();
        let target = store.join("target.bean");
        std::fs::write(&target, "").unwrap();
        let link = directory.path().join("ledger.bean");
        std::os::unix::fs::symlink("store/target.bean", &link).unwrap();
        let stale = directory
            .path()
            .join("ledger.bean.tmp.4242.0123456789abcdef");
        std::fs::write(&stale, "a crashed rewrite").unwrap();

        let (resolved, guard) = claim_ledger_path(&link).expect("claimed");
        assert_eq!(resolved, std::fs::canonicalize(&target).unwrap());
        assert!(!stale.exists(), "the stale temp beside the link is swept");
        assert!(
            guard
                .path()
                .starts_with(std::fs::canonicalize(&store).unwrap()),
            "the lock sits beside the target: {}",
            guard.path().display()
        );
    }

    /// L-139 (T101): the sweep beside the link never removes the link's own
    /// target. An operator may name the real file like a crashed rewrite's
    /// temporary (`ledger.bean.tmp`) beside `ledger.bean -> ledger.bean.tmp`;
    /// T94's sweep deleted it and boot started an empty ledger (A5-4).
    ///
    /// Bug-catch: drop the identity comparison from the sweep and the target
    /// is gone.
    #[cfg(unix)]
    #[test]
    fn l139_claiming_a_link_never_sweeps_its_own_target() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = directory.path().join("ledger.bean.tmp");
        std::fs::write(&target, "2024-01-01 open Assets:Kept\n").unwrap();
        let link = directory.path().join("ledger.bean");
        std::os::unix::fs::symlink("ledger.bean.tmp", &link).unwrap();
        let (resolved, _guard) = claim_ledger_path(&link).expect("claimed");
        assert_eq!(resolved, std::fs::canonicalize(&target).unwrap());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "2024-01-01 open Assets:Kept\n",
            "the ledger itself is not swept"
        );
    }

    /// T101 (audit 0927 A5-5): a link resolution cannot follow — its target
    /// missing — comes back as the link itself. Locked as it stood, `boot`
    /// resolved it again, so a target that appeared in between was worked at
    /// under the link's lock. `claim_ledger_path` refuses it, naming the link,
    /// before any lock.
    ///
    /// Bug-catch: drop the refusal and the dangling link is claimed.
    #[cfg(unix)]
    #[test]
    fn a_link_that_cannot_be_followed_is_refused_before_the_lock() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = directory.path().join("ledger.bean");
        std::os::unix::fs::symlink("missing/target.bean", &link).unwrap();
        let error = claim_ledger_path(&link).expect_err("refused");
        assert!(error.contains("could not follow"), "{error}");
        assert!(
            !directory.path().join("ledger.bean.lock").exists(),
            "no lock was taken"
        );
    }

    /// M-69 (T92, decision (40)): the H-20 boot banner names only remedies
    /// that work — the per-record reasons, a restored copy, deleting the
    /// `openledger-*` lines — and warns off the two that do not.
    ///
    /// Bug-catch: restore "or delete the edited block and append a reversing
    /// entry instead" and this fails.
    #[test]
    fn m69_the_signature_quarantine_banner_names_only_remedies_that_work() {
        let banner = SIGNATURE_QUARANTINE_BANNER;
        assert!(!banner.contains("delete the edited block"), "{banner}");
        assert!(
            !banner.contains("append a reversing entry instead"),
            "{banner}"
        );
        for needle in [
            "per-record",
            "openledger-* lines",
            "re-adopted under the same id",
            "Do not delete the block",
            "count twice",
        ] {
            assert!(banner.contains(needle), "missing {needle:?}: {banner}");
        }
    }

    /// L-31: booting on a path that does not exist yet must leave the ledger
    /// file at 0600.
    ///
    /// This is the exact boot sequence `ledger_runtime::start` runs — create the
    /// parent directory,
    /// then `LedgerService::boot` — and it is the sequence that used to have a
    /// `std::fs::write(&ledger_path, "")` wedged between the two steps. That
    /// pre-create made the file at the process umask (0644 under the default
    /// 022), and because the file then *existed*, the ledger crate's hardened
    /// creation path never ran and never corrected the mode: a world-readable
    /// ledger for the life of the deployment. The umask is forced to 0 here so
    /// the assertion tests the code's intent rather than the environment's
    /// leniency — with the pre-create restored, this fails at 0666.
    #[cfg(unix)]
    #[test]
    fn ledger_created_on_boot_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().expect("temp dir");
        // A nested directory, so the parent-directory step is exercised too.
        let ledger_path = temp_dir.path().join("nested").join("fresh.bean");

        // SAFETY: `umask` is process-global. Forced to 0 so a permissive
        // developer umask cannot mask the bug, and restored immediately.
        let previous_umask = unsafe { libc_umask(0) };
        let result = (|| {
            ensure_ledger_parent_directory(&ledger_path)?;
            assert!(
                !ledger_path.exists(),
                "preparing the directory must not create the .bean itself (L-31)"
            );
            ledger::service::LedgerService::boot(&ledger_path, "local".to_owned())
                .map_err(|error| std::io::Error::other(error.to_string()))
        })();
        unsafe { libc_umask(previous_umask) };
        result.expect("boot on an absent ledger path must succeed");

        assert!(ledger_path.exists(), "boot must create the ledger file");
        let mode = std::fs::metadata(&ledger_path)
            .expect("stat the created ledger")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "a ledger created at boot must be owner-only, got {mode:o}"
        );
    }

    /// `umask(2)`, declared directly rather than pulling in a `libc` dependency
    /// for one test-only call. Always succeeds and returns the previous mask.
    #[cfg(unix)]
    unsafe fn libc_umask(mask: u32) -> u32 {
        extern "C" {
            fn umask(mask: u32) -> u32;
        }
        unsafe { umask(mask) }
    }

    /// Preparing the ledger path is directory-only and idempotent.
    #[test]
    fn ensure_ledger_parent_directory_creates_only_directories() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = temp_dir.path().join("a").join("b").join("ledger.bean");

        ensure_ledger_parent_directory(&ledger_path).expect("first call");
        ensure_ledger_parent_directory(&ledger_path).expect("second call is a no-op");

        assert!(ledger_path.parent().expect("parent").is_dir());
        assert!(
            !ledger_path.exists(),
            "the .bean must be left for LedgerService::boot to create (L-31)"
        );
    }

    /// A bare file name has no parent to create, and must not be mistaken for one.
    #[test]
    fn ensure_ledger_parent_directory_tolerates_a_bare_file_name() {
        ensure_ledger_parent_directory(std::path::Path::new("ledger.bean"))
            .expect("a bare file name has an empty parent, not a missing one");
    }

    // ── L-23: mesh identity decoupled from the swarm topic ───────────────

    /// C25: the quarantine banner defers to each record's own warning, which
    /// may say to restate on one node or, once the restatement is served, to
    /// delete the held block — it no longer says "restate … as its warning
    /// says" over a warning that says delete.
    ///
    /// Bug-catch: put back "restate the chain on ONE node only, as its warning
    /// says" and this fails.
    #[test]
    fn c25_the_quarantine_banner_defers_to_each_records_warning() {
        assert!(QUARANTINE_BANNER.contains("follow each record's own warning"));
        assert!(QUARANTINE_BANNER.contains("restate the chain on ONE node only"));
        assert!(QUARANTINE_BANNER.contains("delete the held block"));
        assert!(!QUARANTINE_BANNER.contains("as its warning says"));
        assert!(QUARANTINE_BANNER.contains("fix p2p.meshId or the node key first"));
    }

    mod mesh_identity {
        use super::*;

        use security::signing::{SignableMessage, SignatureProvider};
        use std::collections::BTreeMap;

        /// Parse and validate a config exactly as boot does.
        fn load_config(json: &str) -> NodeConfig {
            use std::io::Write;
            let mut file = tempfile::NamedTempFile::new().expect("temp config file");
            file.write_all(json.as_bytes()).expect("write temp config");
            NodeConfig::load_from_path(&file.path().to_path_buf()).expect("config must load")
        }

        /// A signing-enabled config on `topic`, with `mesh_id` set or not.
        fn config_for(topic: &str, mesh_id: Option<&str>) -> NodeConfig {
            let mesh_field = match mesh_id {
                Some(value) => format!(r#", "meshId": "{value}""#),
                None => String::new(),
            };
            load_config(&format!(
                r#"{{ "ledgerPath": "./data/ledger.bean",
                      "signing": {{ "enabled": true }},
                      "p2p": {{ "swarmTopic": "{topic}"{mesh_field} }} }}"#
            ))
        }

        /// A node's key material, created once per test in a temp directory.
        fn node_key(dir: &std::path::Path) -> p2p_service::NodeSecretKey {
            p2p_service::load_or_create_secret_key(&dir.join("node.secret")).expect("create key")
        }

        fn author_hex(key: &p2p_service::NodeSecretKey) -> String {
            security::signing::PeerKeySignatureProvider::from_bytes(key.bytes(), String::new())
                .public_key_hex()
        }

        /// The exact resolve-then-pass `main` performs — no site may re-derive
        /// the domain from `swarm_topic` on its own.
        fn signer_for(
            config: &NodeConfig,
            key: &p2p_service::NodeSecretKey,
        ) -> Arc<dyn SignatureProvider> {
            let domain = config.p2p.signature_domain().to_owned();
            build_signature_provider(&config.ledger_config(), Some(key), &domain).expect("a signer")
        }

        /// A signed transaction as it arrives over ALPN: economic body plus the
        /// four envelope keys `verify_remote_signature` reads.
        fn signed_directive(
            signer: &dyn SignatureProvider,
            author: &str,
        ) -> ledger::model::Directive {
            use ledger::model::*;
            use rust_decimal_macros::dec;

            let transaction = Transaction {
                date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
                flag: Flag::Complete,
                payee: None,
                narration: Some("cross-mesh replay".to_owned()),
                tags: vec![],
                links: vec![],
                postings: vec![
                    Posting {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(100),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                    Posting {
                        account: "Equity:Opening".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-100),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                ],
                metadata: BTreeMap::new(),
            };
            let record = Directive::Transaction(transaction.clone());
            let content_id = ledger::hash::compute_content_id(&record);
            // Signed in the record's own format, as the node's signer callback
            // signs every record — not in the provider's default version,
            // which is v4 on a node writing Format v2 (the default) while this
            // hand-built record is v1.
            let signature = signer
                .sign_in(
                    p2p::union_merge::signature_version(ledger::hash::RecordFormat::of(&record)),
                    &SignableMessage {
                        content_id: &content_id,
                        is_transaction: true,
                        parents: "",
                        lamport: "1",
                    },
                )
                .expect("signing is enabled");

            let mut metadata = BTreeMap::new();
            metadata.insert("openledger-author".to_owned(), author.to_owned());
            metadata.insert("openledger-lamport".to_owned(), "1".to_owned());
            metadata.insert("openledger-parents".to_owned(), String::new());
            metadata.insert("openledger-signature".to_owned(), signature);
            Directive::Transaction(Transaction {
                metadata,
                ..transaction
            })
        }

        /// THE two-mesh replay test (L-23).
        ///
        /// Two meshes that chose the same custom swarm topic — which anyone who
        /// can reach the overlay already knows, because the topic is also the
        /// join string — must not accept each other's signed directives. The
        /// author key is deliberately the *same* on both sides: this is the
        /// "one operator runs nodes on two meshes, or a key is allowlisted on
        /// both" case, where nothing but the domain separates them.
        #[test]
        fn mesh_id_domains_refuse_cross_mesh_replay() {
            let dir = tempfile::tempdir().expect("temp dir");
            let key = node_key(dir.path());
            let author = author_hex(&key);

            let shared_topic = "my-org/ledger";
            let config_a = config_for(shared_topic, Some("11111111-1111-4111-8111-111111111111"));
            let config_b = config_for(shared_topic, Some("22222222-2222-4222-8222-222222222222"));
            assert_eq!(
                config_a.p2p.swarm_topic, config_b.p2p.swarm_topic,
                "the whole point is that the topic is shared"
            );

            let directive = signed_directive(signer_for(&config_a, &key).as_ref(), &author);

            // Mesh A — the mesh it was signed for — accepts it.
            p2p::union_merge::verify_remote_signature(
                &directive,
                true,
                config_a.p2p.signature_domain(),
            )
            .expect("a directive must verify on the mesh it was signed for");

            // Mesh B, same topic, same key, different mesh id — refuses it.
            let error = p2p::union_merge::verify_remote_signature(
                &directive,
                true,
                config_b.p2p.signature_domain(),
            )
            .expect_err(
                "REPLAY ACCEPTED: a directive signed for mesh A verified on mesh B — the two \
                 share only their swarm topic, so the signature domain is still coming from \
                 the topic instead of the mesh id",
            );
            assert!(
                matches!(error, p2p::union_merge::MergeError::InvalidSignature(_)),
                "expected a signature rejection, got: {error}"
            );

            // Stated last so the behavioural assertions above are what fails if
            // the domain ever collapses back onto the topic.
            assert_ne!(
                config_a.p2p.signature_domain(),
                config_b.p2p.signature_domain(),
                "distinct mesh ids must resolve to distinct signature domains"
            );
        }

        /// Compatibility pin (L-23): a history signed before `meshId` existed
        /// was signed under the swarm topic, and the remedy the boot refusal
        /// names — `meshId` set to that topic verbatim — keeps it verifying,
        /// byte for byte.
        ///
        /// A signature is checked by *reconstructing* the signed message, so
        /// any other value would invalidate every signature the mesh holds.
        #[test]
        fn a_mesh_id_set_to_the_old_topic_keeps_a_pre_l23_history_verifying() {
            let dir = tempfile::tempdir().expect("temp dir");
            let key = node_key(dir.path());
            let author = author_hex(&key);

            // Signed as a pre-L-23 node did: under the topic string itself.
            let pre_l23: Arc<dyn SignatureProvider> =
                Arc::new(security::signing::PeerKeySignatureProvider::from_bytes(
                    key.bytes(),
                    "my-org/ledger".to_owned(),
                ));
            let directive = signed_directive(pre_l23.as_ref(), &author);

            let remedied = config_for("my-org/ledger", Some("my-org/ledger"));
            assert_eq!(remedied.p2p.signature_domain_source(), "p2p.meshId");
            p2p::union_merge::verify_remote_signature(
                &directive,
                true,
                remedied.p2p.signature_domain(),
            )
            .expect("meshId = the old topic must keep the history verifying");
            let fresh = config_for(
                "my-org/ledger",
                Some("44444444-4444-4444-8444-444444444444"),
            );
            p2p::union_merge::verify_remote_signature(
                &directive,
                true,
                fresh.p2p.signature_domain(),
            )
            .expect_err("any other meshId is a new domain");
        }

        /// The decoupling actually decouples: a directive signed under mesh id
        /// X still verifies after the swarm topic is changed — and signed
        /// under the topic itself, the same change breaks verification, which
        /// is the coupling L-23 removes.
        #[test]
        fn mesh_id_survives_a_swarm_topic_change() {
            let dir = tempfile::tempdir().expect("temp dir");
            let key = node_key(dir.path());
            let author = author_hex(&key);
            let mesh = "33333333-3333-4333-8333-333333333333";

            let before = config_for("my-org/ledger", Some(mesh));
            let after = config_for("my-org/ledger-renamed", Some(mesh));
            assert_ne!(before.p2p.swarm_topic, after.p2p.swarm_topic);

            let directive = signed_directive(signer_for(&before, &key).as_ref(), &author);
            p2p::union_merge::verify_remote_signature(
                &directive,
                true,
                after.p2p.signature_domain(),
            )
            .expect("a mesh id must outlive the gossip topic it was once tied to");

            // Contrast: signed under the topic itself — the pre-L-23 domain —
            // the same rename invalidates the history, which is precisely why
            // the two were separated.
            let coupled: Arc<dyn SignatureProvider> =
                Arc::new(security::signing::PeerKeySignatureProvider::from_bytes(
                    key.bytes(),
                    "my-org/ledger".to_owned(),
                ));
            let coupled = signed_directive(coupled.as_ref(), &author);
            p2p::union_merge::verify_remote_signature(&coupled, true, "my-org/ledger-renamed")
                .expect_err("when the topic IS the domain, renaming it breaks history");
        }

        /// The resolved domain reaches the ALPN verifier and the signer as one
        /// value — neither reads `swarm_topic` for itself.
        #[test]
        fn resolved_domain_reaches_both_the_signer_and_the_alpn_verifier() {
            let dir = tempfile::tempdir().expect("temp dir");
            let key = node_key(dir.path());
            let author = author_hex(&key);
            let config = config_for(
                "my-org/ledger",
                Some("44444444-4444-4444-8444-444444444444"),
            );

            // What `main` computes once and hands to both consumers.
            let domain = config.p2p.signature_domain().to_owned();
            assert_eq!(domain, "44444444-4444-4444-8444-444444444444");
            assert_eq!(config.p2p.signature_domain_source(), "p2p.meshId");

            let handler_domain = anti_entropy_alpn::AntiEntropyHandler {
                ledger: Arc::new(RwLock::new(
                    ledger::service::LedgerService::boot(
                        dir.path().join("ledger.bean"),
                        "local".to_owned(),
                    )
                    .expect("boot ledger"),
                )),
                broadcast: TransactionBroadcast::new(),
                orphan_buffer: Arc::new(RwLock::new(OrphanBuffer::new())),
                allowlist: p2p::allowlist::PeerAllowlist::parse(&[]).expect("allowlist"),
                signing_enabled: true,
                mesh_id: domain.clone(),
                timeouts: anti_entropy_alpn::AntiEntropyTimeouts::default(),
                limits: connection_limiter::AntiEntropyLimits::default(),
                limiter: connection_limiter::ConnectionLimiter::new(
                    connection_limiter::AntiEntropyLimits::default(),
                ),
                connections: peer_connections::PeerConnectionCache::new(),
                supply_backoff: anti_entropy_alpn::SupplyBackoff::default(),
                join_peer: None,
                wire_codec: p2p::protocol::WireCodec::V1,
            }
            .mesh_id;
            assert_eq!(
                handler_domain, domain,
                "the ALPN handler must carry the resolved domain, not the topic"
            );
            assert_ne!(
                handler_domain, config.p2p.swarm_topic,
                "and it must not be the swarm topic when a mesh id is configured"
            );

            let directive = signed_directive(signer_for(&config, &key).as_ref(), &author);
            p2p::union_merge::verify_remote_signature(&directive, true, &handler_domain)
                .expect("the signer's domain and the handler's domain must be the same value");
        }
    }
}
