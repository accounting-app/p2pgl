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
mod p2p_service;
mod peer_connections;
mod rate_limit;
mod request_guard;
#[cfg(test)]
mod test_support;

use auth::AuthState;
use config::NodeConfig;
use graphql::broadcast::TransactionBroadcast;
use graphql::{
    build_schema_with_service, graphiql_handler, graphql_handler, AppSchema, SharedLedger,
};
use health::{health_handler, probe_local_health, HealthState};
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

    // Ensure the ledger file's parent directory exists (§3.3). The `.bean` file
    // itself is deliberately NOT created here — see below.
    let ledger_path = PathBuf::from(&config.ledger_path);
    if let Err(error) = ensure_ledger_parent_directory(&ledger_path) {
        error!(%error, path = %ledger_path.display(), "failed to create ledger directory");
        std::process::exit(1);
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
    // full rationale. Taken before `LedgerService::boot`, so the ledger's own
    // first write is serialized too.
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

    // L-31: there is deliberately no `std::fs::write(&ledger_path, "")` here.
    // That pre-create ran before the ledger crate ever saw the path and produced
    // the file at the process umask — world-readable on a default 022 umask —
    // and `LedgerService::boot` then found a file that already existed and left
    // those permissions in place for the whole life of the ledger. Booting on an
    // absent path takes the crate's own creation path (`persist_atomically`),
    // which creates 0600 and fsyncs. Let the owner of the format own the file's
    // birth.

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
    let quarantined_count = service.quarantined_count();
    info!(
        directives = directive_count,
        heads = head_count,
        quarantined = quarantined_count,
        path = %ledger_path.display(),
        "ledger service booted"
    );

    // H-08: the startup compaction below rewrites the whole `.bean` from
    // memory, so anything boot could not load has to be carried by the ledger's
    // quarantine or it is deleted here, seconds after the node comes up and
    // before any operator has read the warning telling them to repair the file.
    // The ledger crate owns that guarantee (`LedgerService::quarantined`); this
    // repeats the count at the node's own startup banner because this is the
    // process where an operator actually looks, and because a node running with
    // a non-empty quarantine is serving an incomplete ledger — correct, but not
    // whole — until the file is repaired and the node restarted.
    if quarantined_count > 0 {
        warn!(
            quarantined = quarantined_count,
            ids = %service.quarantined_ids().join(", "),
            path = %ledger_path.display(),
            "this node booted with ledger directives quarantined out of the DAG: they stay in \
             the .bean (every compaction rewrites them verbatim) but are NOT served, NOT in any \
             balance and NOT replicated. Stop the node and repair their openledger-parents \
             metadata (H-08)"
        );
    }

    // Wrap in Arc<RwLock> for concurrent access (§3.5).
    let shared_ledger: SharedLedger = Arc::new(RwLock::new(service));

    // T44: fold any commit journal back into the canonical `.bean` before
    // serving. A journal is only ever present here after an unclean stop (a
    // clean one compacts on the way out), so this is the crash-recovery point:
    // boot has already unioned canonical ∪ journal into memory, and this writes
    // that union out as one canonical file and deletes the sidecar.
    //
    // A failure is logged, not fatal. The journal is still on disk and still
    // correct — boot read it once and would read it again — so refusing to
    // start would turn a recoverable disk hiccup into an outage.
    if let Err(error) = ledger_commit::compact(&shared_ledger).await {
        warn!(%error, "could not compact the ledger commit journal at startup; \
                       the journal is intact and will be folded in by a later write");
    }

    // Transaction broadcast for subscriptions.
    let broadcast = TransactionBroadcast::new();

    // Shared orphan buffer for P2P.
    let orphan_buffer = Arc::new(RwLock::new(OrphanBuffer::new()));

    // Peer registry — either from PeerNode (when P2P enabled) or empty default.
    let peer_registry: PeerRegistry;
    let mut p2p_router = None;

    // Load the node's Ed25519 secret key ONCE, here, before anything consumes it
    // (L-04). The same 32 bytes are the iroh QUIC identity *and* the
    // directive-signing key — `EndpointId` is the Ed25519 verifying key — so two
    // independent reads could hand the endpoint one key and the signer another,
    // and each read re-resolved the path after the permission check had already
    // passed on it. One open, one `fstat` of that handle, one read, both
    // consumers.
    //
    // Which loader applies is deliberately not uniform. With p2p on, the key is
    // this node's bootstrappable mesh identity and is created on first boot
    // (CAP-4). With signing on and p2p off there is no identity to bootstrap, so
    // a missing key stays an operator error rather than becoming a silently
    // invented one — the pre-L-04 behaviour of `build_signature_provider`,
    // preserved. Config validation already forces `signing.enabled` whenever
    // `p2p.enabled`, so the p2p branch covers both consumers.
    let secret_key_path = PathBuf::from(&config.p2p.secret_key_path);
    let node_secret_key = if config.p2p.enabled {
        match p2p_service::load_or_create_secret_key(&secret_key_path) {
            Ok(key) => Some(key),
            Err(error) => {
                error!(%error, path = %secret_key_path.display(), "failed to load or create the node secret key — aborting");
                std::process::exit(1);
            }
        }
    } else if config.signing.enabled {
        match p2p_service::load_secret_key(&secret_key_path) {
            Ok(key) => Some(key),
            Err(error) => {
                error!(%error, path = %secret_key_path.display(), "signing enabled but secret key could not be loaded — aborting");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Resolve the mesh signature domain ONCE (L-23), here, and hand the result
    // to every consumer. `p2p.meshId` when set, `p2p.swarmTopic` otherwise —
    // the fallback is what keeps already-persisted signatures verifiable on a
    // deployment that has not adopted a mesh id (see `P2pConfig::mesh_id`).
    //
    // One resolution, one value: the signer and the ALPN verification path both
    // receive this string, so neither reads `swarm_topic` for signature
    // purposes and the two cannot drift apart.
    let signature_domain = config.p2p.signature_domain().to_owned();
    info!(
        source = config.p2p.signature_domain_source(),
        length = signature_domain.len(),
        // The domain doubles as a quasi-credential when it falls back to the
        // swarm topic (which is also the gossip join string), so the log names
        // its shape, never its value.
        prefix = %signature_domain.chars().take(4).collect::<String>(),
        "mesh signature domain resolved"
    );

    // Boot P2P if enabled (§3.4). Keep identity even when the allowlist is empty.
    let gossip_sender = if config.p2p.enabled {
        let Some(secret_key) = node_secret_key.as_ref() else {
            error!("p2p.enabled is true but no secret key was loaded — aborting");
            std::process::exit(1);
        };
        match p2p_service::boot_p2p(&config.p2p, secret_key).await {
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
                    mesh_id: signature_domain.clone(),
                    timeouts: anti_entropy_alpn::AntiEntropyTimeouts::default(),
                    limits,
                    limiter: connection_limiter::ConnectionLimiter::new(limits),
                    // T42: one cache for the whole node — the router's clone,
                    // the gossip loop's and the anti-entropy tick's all share it.
                    connections: peer_connections::PeerConnectionCache::new(),
                };
                p2p_router = Some(p2p_service::spawn_router(&peer_node, handler.clone()));
                let sender = p2p_service::spawn_gossip_loop(&peer_node, handler.clone());
                p2p_service::spawn_anti_entropy_loop(&peer_node, handler);
                // L-20: expire orphans on a timer, not only when an insert
                // happens to run the sweep.
                p2p_service::spawn_orphan_eviction_loop(orphan_buffer.clone());
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

    // Build signature provider based on config (§3.8.1).
    // When signing is enabled the key is mandatory — never fall back to noop (H-4).
    //
    // Built here, BEFORE the file watcher starts, because the watcher reconciles
    // hand edits and those now get signed at adoption (L-11): an adoption that
    // ran before the signer was installed would persist an entry no peer will
    // ever accept, which is the exact failure L-11 closes.
    let signer = build_signature_provider(&config, node_secret_key.as_ref(), &signature_domain);

    // L-11: hand the service a signing callback so reconcile can stamp entries
    // the operator added by hand, exactly as `appendTransaction` stamps its own.
    // `set_author_id` above has already run when P2P is on, so the author this
    // signs for is the same `EndpointId` the key belongs to.
    {
        let signer_for_reconcile = Arc::clone(&signer);
        shared_ledger.write().await.set_signer(Arc::new(
            move |content_id: &str, is_transaction: bool, parents: &str, lamport: &str| {
                signer_for_reconcile.sign(&security::signing::SignableMessage {
                    content_id,
                    is_transaction,
                    parents,
                    lamport,
                })
            },
        ));
    }

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
                    // T44: the same permit → lock → prepare → unlock → commit
                    // sequence the mutations use. A reconcile always compacts
                    // (it has to delete the entries it refused and re-spell the
                    // rest), and that rewrite is exactly the kind of write that
                    // must not run under the read-blocking write lock.
                    let permit = ledger_commit::acquire_write_permit(&watcher_ledger).await;
                    let prepared = {
                        let mut svc = watcher_ledger.write().await;
                        match svc.reconcile_file_staged() {
                            Ok(result) => {
                                if result.new_directives > 0 {
                                    info!(
                                        new = result.new_directives,
                                        duplicates = result.duplicates,
                                        rejected = result.rejected,
                                        "reconciled external edit"
                                    );
                                    ledger_commit::prepare_or_recover(&mut svc, true)
                                } else {
                                    Ok(None)
                                }
                            }
                            Err(error) => {
                                warn!(%error, "failed to reconcile external edit");
                                Ok(None)
                            }
                        }
                    };
                    let committed = match prepared {
                        // H-11: the permit goes WITH the commit. The `Err` arm
                        // drops it here instead, which is correct — a prepare
                        // that failed left no commit to serialize against.
                        Ok(pending) => {
                            ledger_commit::commit_pending(&watcher_ledger, pending, permit).await
                        }
                        Err(error) => Err(error),
                    };
                    if let Err(error) = committed {
                        warn!(%error, "failed to persist a reconciled external edit");
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
    //
    // L-09: the bind decides how much detail `/health` discloses to an
    // unauthenticated caller, and the auth state lets an authenticated operator
    // get the full picture on a public bind regardless.
    // T44: kept for the shutdown compaction below, since `HealthState` takes
    // ownership of the shared handle.
    let ledger_for_shutdown = shared_ledger.clone();
    let health_state = HealthState {
        ledger: shared_ledger,
        peer_registry,
        public_bind: config.binds_non_loopback(),
        auth: auth_state.clone(),
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
    // connection-level limits `axum::serve` never applied (M-13). The settings
    // come from the optional `http` config section; with the section absent
    // every field is `HttpServerSettings::default()`'s own value, which is what
    // this call site used to pass literally.
    let server = http_server::serve_hardened(
        listener,
        application,
        config.http_server_settings(),
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

    // T44: fold the commit journal back into the canonical `.bean` on the way
    // out, so a cleanly-stopped node leaves exactly one file behind and the
    // next boot has nothing to replay. Cheap — it is one rewrite of a file
    // every pre-T44 mutation rewrote anyway — and safe to skip: the journal is
    // durable, and boot unions it if this fails.
    if let Err(error) = ledger_commit::compact(&ledger_for_shutdown).await {
        warn!(%error, "could not compact the ledger commit journal at shutdown; \
                       the journal is intact and will be folded in on the next boot");
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

/// Build the signature provider from the key material already loaded in `main`.
///
/// Takes the loaded key rather than a path (L-04): the signer and the iroh
/// endpoint must be the *same* key, and the only way to guarantee that is for
/// neither of them to read the file.
///
/// Takes the already-resolved `mesh_id` rather than the config field it came
/// from (L-23), for the same reason: the signer and the ALPN verifier must bind
/// the *same* domain, so this function must not be able to derive its own.
fn build_signature_provider(
    config: &NodeConfig,
    node_secret_key: Option<&p2p_service::NodeSecretKey>,
    mesh_id: &str,
) -> Arc<dyn security::signing::SignatureProvider> {
    if config.signing.enabled {
        let Some(secret_key) = node_secret_key else {
            error!("signing enabled but no secret key was loaded — aborting");
            std::process::exit(1);
        };
        // Bind signatures to this node's mesh identity so they cannot be
        // replayed into another mesh (L2 / L-23).
        let provider = security::signing::PeerKeySignatureProvider::from_bytes(
            secret_key.bytes(),
            mesh_id.to_owned(),
        );
        info!(public_key = %provider.public_key_hex(), "signing enabled");
        Arc::new(provider)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// L-31: booting on a path that does not exist yet must leave the ledger
    /// file at 0600.
    ///
    /// This is the exact boot sequence `main` runs — create the parent directory,
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
            build_signature_provider(config, Some(key), &domain)
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
            let content_id =
                ledger::hash::compute_content_id(&Directive::Transaction(transaction.clone()));
            let signature = signer
                .sign(&SignableMessage {
                    content_id: &content_id,
                    is_transaction: true,
                    parents: "",
                    lamport: "1",
                })
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

        /// Compatibility pin: with `meshId` unset on both sides, two nodes on
        /// one topic verify each other exactly as they did before L-23.
        ///
        /// This is the constraint the fallback exists for. A signature is
        /// checked by *reconstructing* the signed message, so any change to the
        /// domain an existing deployment resolves to would invalidate every
        /// signature it has already persisted.
        #[test]
        fn unset_mesh_id_falls_back_to_the_swarm_topic() {
            let dir = tempfile::tempdir().expect("temp dir");
            let key = node_key(dir.path());
            let author = author_hex(&key);

            let config_a = config_for("my-org/ledger", None);
            let config_b = config_for("my-org/ledger", None);
            assert_eq!(config_a.p2p.signature_domain(), "my-org/ledger");
            assert_eq!(
                config_a.p2p.signature_domain_source(),
                "p2p.swarmTopic (meshId unset)"
            );

            let directive = signed_directive(signer_for(&config_a, &key).as_ref(), &author);
            p2p::union_merge::verify_remote_signature(
                &directive,
                true,
                config_b.p2p.signature_domain(),
            )
            .expect("an unset meshId must keep verifying under the swarm topic");

            // And the bytes are the pre-L-23 bytes: the signed message is the
            // one built from the topic string itself.
            let peer = security::signing::PeerKeySignatureProvider::from_bytes(
                key.bytes(),
                "my-org/ledger".to_owned(),
            );
            let content_id = match &directive {
                ledger::model::Directive::Transaction(txn) => ledger::hash::compute_content_id(
                    &ledger::model::Directive::Transaction(txn.clone()),
                ),
                other => ledger::hash::compute_content_id(other),
            };
            let message = SignableMessage {
                content_id: &content_id,
                is_transaction: true,
                parents: "",
                lamport: "1",
            };
            let signature = match &directive {
                ledger::model::Directive::Transaction(txn) => txn
                    .metadata
                    .get("openledger-signature")
                    .expect("signature")
                    .clone(),
                _ => unreachable!(),
            };
            peer.verify(&message, &signature, &author)
                .expect("the fallback domain must be the swarm topic verbatim");
        }

        /// The decoupling actually decouples: a directive signed under mesh id
        /// X still verifies after the swarm topic is changed — and with no mesh
        /// id, the same topic change breaks verification, which is the coupling
        /// L-23 removes.
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

            // Contrast: the same topic change under the fallback invalidates
            // the history, which is precisely why the two were separated.
            let coupled_before = config_for("my-org/ledger", None);
            let coupled_after = config_for("my-org/ledger-renamed", None);
            let coupled = signed_directive(signer_for(&coupled_before, &key).as_ref(), &author);
            p2p::union_merge::verify_remote_signature(
                &coupled,
                true,
                coupled_after.p2p.signature_domain(),
            )
            .expect_err("without a mesh id the topic IS the domain, so renaming it breaks history");
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
