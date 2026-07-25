mod config;
mod health;

use config::NodeConfig;
use health::health_handler;

use axum::Router;
use axum::routing::get;
use std::path::PathBuf;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info};

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
    let config_path = std::env::var("GL_NODE_CONFIG")
        .unwrap_or_else(|_| "gl-node.config.json".to_owned());
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

    // Build Axum router.
    let application = Router::new().route("/health", get(health_handler));

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
        "gl-node starting"
    );

    // Serve with graceful shutdown on SIGTERM / SIGINT (§3.9).
    axum::serve(listener, application)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|error| {
            error!(%error, "server error");
            std::process::exit(1);
        });

    info!("gl-node shut down gracefully");
}

/// Wait for SIGTERM or SIGINT (§3.9 graceful shutdown).
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
