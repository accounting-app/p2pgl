mod auth;
mod config;
mod graphql;
mod health;
mod p2p_service;

use auth::AuthState;
use config::NodeConfig;
use graphql::broadcast::TransactionBroadcast;
use graphql::{build_schema_with_service, graphiql_handler, graphql_handler, SharedLedger};
use health::{health_handler, HealthState};

use axum::routing::get;
use axum::{middleware, Router};
use p2p::node::PeerRegistry;
use p2p::orphan_buffer::OrphanBuffer;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
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

    // Boot P2P if enabled (§3.4).
    let _gossip_sender = if config.p2p.enabled {
        match p2p_service::boot_p2p(&config.p2p, &ledger_path).await {
            Ok(peer_node) => {
                // Update ledger service author to Iroh EndpointId (§3.3.1).
                let iroh_author_id = peer_node.node_id();
                info!(author_id = %iroh_author_id, "P2P identity derived from Iroh EndpointId");
                shared_ledger.write().await.set_author_id(iroh_author_id);

                peer_registry = peer_node.registry.clone();

                // Spawn gossip loop (§3.4, §3.4.3).
                let sender = p2p_service::spawn_gossip_loop(
                    &peer_node,
                    shared_ledger.clone(),
                    broadcast.clone(),
                    orphan_buffer.clone(),
                );

                // Spawn anti-entropy loop (§3.4.1).
                p2p_service::spawn_anti_entropy_loop(
                    &peer_node,
                    shared_ledger.clone(),
                    broadcast.clone(),
                    orphan_buffer.clone(),
                );

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
    let signer: Arc<dyn security::signing::SignatureProvider> = if config.signing.enabled {
        let key_path = std::path::Path::new(&config.p2p.secret_key_path);
        match p2p_service::read_secret_key_bytes(key_path) {
            Ok(key_bytes) => {
                let provider = security::signing::PeerKeySignatureProvider::from_bytes(&key_bytes);
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
    };

    // Build the GraphQL schema with live service + peer registry + signer.
    let schema = build_schema_with_service(shared_ledger.clone(), broadcast, peer_registry.clone(), signer);

    // Auth state for middleware (§3.8).
    let auth_state = AuthState {
        enabled: config.auth.enabled,
        api_key: config.auth.api_key.clone(),
    };

    // GraphQL routes — behind auth middleware.
    let graphql_routes = Router::new()
        .route("/graphql", get(graphiql_handler).post(graphql_handler))
        .with_state(schema)
        .layer(middleware::from_fn_with_state(
            auth_state,
            auth::auth_middleware,
        ));

    // Health state with live shared ledger + peer registry.
    let health_state = HealthState {
        ledger: shared_ledger,
        peer_registry,
    };

    // Build full application router.
    // /health is exempt from auth (§2.9).
    let application = Router::new()
        .route("/health", get(health_handler))
        .with_state(health_state)
        .merge(graphql_routes)
        .layer(CorsLayer::permissive());

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
        "gl-node starting"
    );

    // Serve with graceful shutdown on SIGTERM / SIGINT (§3.9).
    let server = axum::serve(listener, application)
        .with_graceful_shutdown(shutdown_signal());

    if let Err(error) = server.await {
        error!(%error, "server error");
        std::process::exit(1);
    }

    // Stop file watcher if running.
    if let Some(handle) = file_watcher_handle {
        handle.abort();
    }

    info!("gl-node shut down gracefully");
}

/// Wait for SIGTERM or SIGINT (§3.9 graceful shutdown).
///
/// On signal, returns to let axum drain in-flight requests.
/// Axum's `with_graceful_shutdown` handles the drain period.
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
