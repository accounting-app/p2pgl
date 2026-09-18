mod anti_entropy_alpn;
mod auth;
mod config;
mod connection_limiter;
mod fetch_coordinator;
mod graphql;
mod health;
mod http_server;
mod ledger_lock;
mod p2p_service;
mod rate_limit;
mod request_guard;

use auth::AuthState;
use config::NodeConfig;
use graphql::broadcast::TransactionBroadcast;
use graphql::{
    build_schema_with_service, graphiql_handler, graphql_handler, AppSchema, SharedLedger,
};
use health::{health_handler, probe_local_health, HealthState};
use http_server::HttpServerSettings;
use rate_limit::RateLimiter;
use request_guard::RequestGuardState;

use axum::routing::{get, post};
use axum::{middleware, Extension, Router};
use p2p::node::PeerRegistry;
use p2p::orphan_buffer::OrphanBuffer;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::RwLock;
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

enum CliAction {
    Serve,
    Version,
    HealthCheck,
    Usage(String),
}

fn parse_cli() -> CliAction {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => CliAction::Serve,
        Some("--version") | Some("-V") => CliAction::Version,
        Some("--health-check") => CliAction::HealthCheck,
        Some("--help") | Some("-h") => {
            CliAction::Usage("Usage: gl-node [--health-check | --version]".to_owned())
        }
        Some(other) => CliAction::Usage(format!(
            "unknown argument: {other}\nUsage: gl-node [--health-check | --version]"
        )),
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
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Determine config path from env or default.
    let config_path =
        std::env::var("GL_NODE_CONFIG").unwrap_or_else(|_| "gl-node.config.json".to_owned());
    let config_path = PathBuf::from(&config_path);

    info!(path = %config_path.display(), "loading configuration");

    let config = match NodeConfig::load_from_path(&config_path) {
        Ok(config) => config,
        Err(error) => {
            error!(%error, "failed to load configuration — aborting");
            std::process::exit(1);
        }
    };

    // Ensure ledger file parent directory exists; create empty .bean if missing (§3.3).
    let ledger_path = PathBuf::from(&config.ledger_path);
    if let Some(parent_directory) = ledger_path.parent() {
        if !parent_directory.as_os_str().is_empty() && !parent_directory.exists() {
            if let Err(error) = std::fs::create_dir_all(parent_directory) {
                error!(%error, path = %parent_directory.display(), "failed to create ledger directory");
                std::process::exit(1);
            }
        }
    }

    // Claim the ledger for this process before touching it (M-17). Two nodes on
    // one .bean hold independent DAGs and rewrite the whole file per persist, so
    // the later writer silently discards the other's directives — fail closed
    // instead. The guard is bound for the whole of `main`: dropping it, or the
    // process dying, releases the lock, so a crash never wedges the ledger.
    //
    // Deliberately here and not inside `LedgerService::boot`: `persist_or_reload`
    // recovers from a failed persist by re-booting the same path, and an
    // flock-style lock conflicts across descriptors even within one process, so
    // a boot-level lock would refuse its own reload. See `ledger_lock` for the
    // full rationale. Taken before the empty-.bean creation below so even that
    // first write is serialized.
    let _ledger_lock = match ledger_lock::acquire(&ledger_path) {
        Ok(guard) => {
            info!(lock = %guard.path().display(), "ledger lock acquired");
            guard
        }
        Err(error) => {
            error!(%error, "failed to lock ledger file — aborting");
            std::process::exit(1);
        }
    };

    if !ledger_path.exists() {
        info!(path = %ledger_path.display(), "ledger file not found — creating empty .bean");
        if let Err(error) = std::fs::write(&ledger_path, "") {
            error!(%error, path = %ledger_path.display(), "failed to create empty ledger file");
            std::process::exit(1);
        }
    }

    // Boot the ledger service (§3.3).
    let author_id = "local".to_owned(); // Replaced by Iroh EndpointId when P2P boots.
    let service = match ledger::service::LedgerService::boot(&ledger_path, author_id) {
        Ok(service) => service,
        Err(error) => {
            error!(%error, "failed to boot ledger service — aborting");
            std::process::exit(1);
        }
    };

    let directive_count = service.directive_count();
    let head_count = service.head_count();
    info!(
        directives = directive_count,
        heads = head_count,
        path = %ledger_path.display(),
        "ledger service booted"
    );

    // Wrap in Arc<RwLock> for concurrent access (§3.5).
    let shared_ledger: SharedLedger = Arc::new(RwLock::new(service));

    // Transaction broadcast for subscriptions.
    let broadcast = TransactionBroadcast::new();

    // Shared orphan buffer for P2P.
    let orphan_buffer = Arc::new(RwLock::new(OrphanBuffer::new()));

    // Peer registry — either from PeerNode (when P2P enabled) or empty default.
    let peer_registry: PeerRegistry;
    let mut p2p_router = None;

    // Boot P2P if enabled (§3.4). Keep identity even when the allowlist is empty.
    let gossip_sender = if config.p2p.enabled {
        match p2p_service::boot_p2p(&config.p2p, &ledger_path).await {
            Ok(peer_node) => {
                // Update ledger service author to Iroh EndpointId (§3.3.1).
                let iroh_author_id = peer_node.node_id();
                info!(author_id = %iroh_author_id, "P2P identity derived from Iroh EndpointId");
                shared_ledger.write().await.set_author_id(iroh_author_id);

                peer_registry = peer_node.registry.clone();

                if peer_node.allowlist().is_empty() {
                    warn!(
                        "p2p.bootstrapEndpointIds is empty — inbound ALPN Supply will be refused"
                    );
                }

                // Generous defaults; a config surface follows in T38 (M-06, M-16).
                let limits = connection_limiter::AntiEntropyLimits::default();
                let handler = anti_entropy_alpn::AntiEntropyHandler {
                    ledger: shared_ledger.clone(),
                    broadcast: broadcast.clone(),
                    orphan_buffer: orphan_buffer.clone(),
                    allowlist: peer_node.allowlist().clone(),
                    signing_enabled: config.signing.enabled,
                    swarm_topic: config.p2p.swarm_topic.clone(),
                    timeouts: anti_entropy_alpn::AntiEntropyTimeouts::default(),
                    limits,
                    limiter: connection_limiter::ConnectionLimiter::new(limits),
                };
                p2p_router = Some(p2p_service::spawn_router(&peer_node, handler.clone()));
                let sender = p2p_service::spawn_gossip_loop(&peer_node, handler.clone());
                p2p_service::spawn_anti_entropy_loop(&peer_node, handler);
                Some(sender)
            }
            Err(error) => {
                error!(%error, "failed to boot P2P — aborting (p2p.enabled is true)");
                std::process::exit(1);
            }
        }
    } else {
        info!("P2P disabled — running in single-node mode");
        peer_registry = PeerRegistry::new();
        None
    };

    // Start file watcher if external edits enabled (§3.3, CT-12).
    let file_watcher_handle = if config.external_file_edits == "enabled" {
        let watcher_ledger = shared_ledger.clone();
        let watcher_path = ledger_path.clone();
        let handle = tokio::spawn(async move {
            use ledger::file_watcher::{FileChangeKind, FileState};
            let mut last_state = FileState::from_path(&watcher_path);
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));

            loop {
                interval.tick().await;
                let current = FileState::from_path(&watcher_path);
                let change = current.detect_change(&last_state);
                if change == FileChangeKind::Modified {
                    info!("external edit detected — reconciling");
                    let mut svc = watcher_ledger.write().await;
                    match svc.reconcile_file() {
                        Ok(result) => {
                            if result.new_directives > 0 {
                                info!(
                                    new = result.new_directives,
                                    duplicates = result.duplicates,
                                    rejected = result.rejected,
                                    "reconciled external edit"
                                );
                            }
                        }
                        Err(error) => {
                            warn!(%error, "failed to reconcile external edit");
                        }
                    }
                }
                last_state = current;
            }
        });
        info!("file watcher started (250ms poll)");
        Some(handle)
    } else {
        info!("external file edits disabled — file watcher not started");
        None
    };

    // Build signature provider based on config (§3.8.1).
    // When signing is enabled the key is mandatory — never fall back to noop (H-4).
    let signer = build_signature_provider(&config);

    // Build the GraphQL schema with live service + peer registry + signer.
    let schema = build_schema_with_service(
        shared_ledger.clone(),
        broadcast,
        peer_registry.clone(),
        signer,
        config.graphiql_enabled(),
        gossip_sender,
    );

    // Auth state for middleware (§3.8).
    let auth_state = AuthState {
        enabled: config.auth.enabled,
        api_key: config.auth.api_key.clone(),
    };

    // Health state with live shared ledger + peer registry.
    let health_state = HealthState {
        ledger: shared_ledger,
        peer_registry,
    };

    // Host / Content-Type / Origin guard state (H-01).
    let guard_state = RequestGuardState {
        allowed_hosts: Arc::new(config.allowed_host_set()),
        allowed_origins: Arc::new(config.cors.allowed_origins.iter().cloned().collect()),
    };

    // A non-loopback bind with auth disabled is rejected at config validation
    // (M-2), so by this point a public bind always has auth enabled.
    if config.tls.mode == "terminated" {
        info!("TLS assumed terminated at the host or reverse proxy (in-process TLS is not implemented)");
    }

    // Rate limiter keyed on the real client (M-04). With no trusted proxy the
    // key is the TCP peer, which behind a terminator is the proxy itself — one
    // bucket for every client at once — so say so loudly rather than silently
    // rate-limiting the whole internet as a single caller.
    let trusted_proxies = config.trusted_proxy_set();
    if trusted_proxies.is_empty() {
        if config.tls.mode == "terminated" {
            warn!(
                "trustedProxies is empty while tls.mode is \"terminated\" — every client behind the proxy shares one rate-limit bucket (M-04); list the proxy address(es) in trustedProxies"
            );
        }
    } else {
        info!(
            proxies = trusted_proxies.len(),
            "X-Forwarded-For trusted from configured reverse proxies (rightmost untrusted entry wins)"
        );
    }
    let rate_limiter = RateLimiter::graphql().with_trusted_proxies(trusted_proxies);

    let application = build_application_with_limiter(
        schema,
        auth_state,
        health_state,
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
    // connection-level limits `axum::serve` never applied (M-13).
    let server = http_server::serve_hardened(
        listener,
        application,
        HttpServerSettings::default(),
        shutdown_signal(),
    );

    if let Err(error) = server.await {
        error!(%error, "server error");
        std::process::exit(1);
    }

    // Stop file watcher if running.
    if let Some(handle) = file_watcher_handle {
        handle.abort();
    }

    if let Some(router) = p2p_router {
        if let Err(error) = router.shutdown().await {
            warn!(%error, "P2P router shutdown error");
        }
    }

    info!("gl-node shut down gracefully");
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
    build_application_with_limiter(
        schema,
        auth_state,
        health_state,
        guard_state,
        cors,
        graphiql,
        RateLimiter::graphql(),
    )
}

/// Assemble the full application router.
///
/// Layer order, outermost first: CORS, body limit (H-05), rate-limiter
/// extension, then — on the GraphQL routes only — the request guard (H-01),
/// the rate limiter and auth. The guard is outermost among those so a rejected
/// Host, Content-Type or Origin never reaches the limiter or the schema.
/// `/health` stays outside the guard and outside auth (§2.9).
///
/// `limiter` carries the trusted-proxy set, so how a client is identified is a
/// boot-time decision rather than a per-request one (M-04).
pub(crate) fn build_application_with_limiter(
    schema: AppSchema,
    auth_state: AuthState,
    health_state: HealthState,
    guard_state: RequestGuardState,
    cors: CorsLayer,
    graphiql: bool,
    limiter: RateLimiter,
) -> Router {
    // GraphQL routes — POST always; GraphiQL on GET only when enabled.
    let graphql_router = if graphiql {
        info!("GraphiQL enabled on GET /graphql");
        Router::new().route("/graphql", get(graphiql_handler).post(graphql_handler))
    } else {
        info!("GraphiQL disabled — POST /graphql only");
        Router::new().route("/graphql", post(graphql_handler))
    };
    let graphql_routes = graphql_router
        .with_state(schema)
        .layer(middleware::from_fn_with_state(
            auth_state,
            auth::auth_middleware,
        ))
        .layer(middleware::from_fn(rate_limit::graphql_rate_limit))
        .layer(middleware::from_fn_with_state(
            guard_state,
            request_guard::request_guard,
        ));

    Router::new()
        .route("/health", get(health_handler))
        .with_state(health_state)
        .merge(graphql_routes)
        .layer(Extension(limiter))
        .layer(RequestBodyLimitLayer::new(GRAPHQL_MAX_BODY_BYTES))
        .layer(cors)
}

fn build_signature_provider(config: &NodeConfig) -> Arc<dyn security::signing::SignatureProvider> {
    if config.signing.enabled {
        let key_path = std::path::Path::new(&config.p2p.secret_key_path);
        match p2p_service::read_secret_key_bytes(key_path) {
            Ok(key_bytes) => {
                // Bind signatures to this node's mesh identity (swarm topic) so
                // they cannot be replayed into another mesh (L2).
                let provider = security::signing::PeerKeySignatureProvider::from_bytes(
                    &key_bytes,
                    config.p2p.swarm_topic.clone(),
                );
                info!(public_key = %provider.public_key_hex(), "signing enabled");
                Arc::new(provider)
            }
            Err(error) => {
                error!(%error, "signing enabled but secret key could not be loaded — aborting");
                std::process::exit(1);
            }
        }
    } else {
        info!("signing disabled");
        Arc::new(security::signing::NoopSignatureProvider)
    }
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
