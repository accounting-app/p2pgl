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
use axum::{middleware, Router};
use p2p::node::PeerRegistry;
use p2p::orphan_buffer::OrphanBuffer;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{debug, error, info, warn};

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
    // T82 / L-84: a symlinked `.bean` is worked at its target, so the lock
    // sits beside the target too — two nodes pointed at one ledger through
    // different links exclude each other.
    let (ledger_path, _ledger_lock) = match claim_ledger_path(&ledger_path) {
        Ok((resolved, guard)) => {
            info!(lock = %guard.path().display(), "ledger lock acquired");
            (resolved, guard)
        }
        Err(error) => {
            error!(%error, "cannot use the configured ledger path — aborting");
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
    // Replaced by the key's EndpointId once the key is loaded, whenever signing
    // is enabled (T80); a signing-off node keeps it.
    //
    // Format v2 (Facets A + B): the format this node writes through its API.
    // Those writes happen once the key's author id is set, so a v2 id is
    // computed over the final author.
    let author_id = ledger::service::PLACEHOLDER_AUTHOR.to_owned();
    let service = match ledger::service::LedgerService::boot_emitting(
        &ledger_path,
        author_id,
        config.format.record_format(),
    ) {
        Ok(service) => service,
        Err(error) => {
            error!(%error, "failed to boot ledger service — aborting");
            std::process::exit(1);
        }
    };

    let directive_count = service.directive_count();
    let head_count = service.head_count();
    let quarantined_count = service.quarantined_count();
    // H-13: directives boot adopted as operator input (no envelope in the
    // file) that still await this node's identity and signature — finalised
    // below, after the key is loaded and before anything is written or served.
    let operator_input_count = service.unsigned_operator_input_count();
    info!(
        directives = directive_count,
        heads = head_count,
        quarantined = quarantined_count,
        operator_input = operator_input_count,
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
    //
    // R-12: the remedy names every reason a record can be held back, not only
    // the one H-08 started with. T47 and T51 widened the quarantine to charset,
    // fan-in and unparsable-block cases, and a banner that says "repair their
    // openledger-parents" sends the operator of a charset or parse failure to
    // look at a field that is fine. T103 (0927 §5, M-73): the EVERY-signature
    // shape — a wrong meshId or key — is not repaired record by record, and a
    // restatement is made on one node, not on each that prints this.
    if quarantined_count > 0 {
        warn!(
            quarantined = quarantined_count,
            unparsable_blocks = service.unparsable_block_count(),
            ids = %service.quarantined_ids().join(", "),
            path = %ledger_path.display(),
            "this node booted with ledger records quarantined out of the DAG: they stay in \
             the .bean (every compaction rewrites them verbatim) but are NOT served, NOT in any \
             balance and NOT replicated. The per-record boot warnings above give each one's \
             reason — its openledger-parents metadata, a disallowed character, excess fan-in, \
             a signature that does not verify, a parent no peer could resolve, or a block that \
             does not parse at all (named by line number; it has no id). If the boot warnings \
             above include \"EVERY signature this node checked failed\", fix p2p.meshId or the \
             node key first and repair nothing: the records load again once both are right. \
             Otherwise stop the node, repair those records in the file, and restart. A repair \
             that changes a record's body gives it a new id, and what descends from it stays \
             held: restore the original from a peer or a backup where you can (H-23); where \
             you cannot, restate the chain on ONE node only, as its warning says — every other \
             node adopts the restatement and must not restate (H-08, L-45, M-73)"
        );
    }

    // Wrap in Arc<RwLock> for concurrent access (§3.5).
    let shared_ledger: SharedLedger = Arc::new(RwLock::new(service));

    // The startup compaction used to run HERE, before the node key was loaded,
    // before `set_author_id` and before `set_signer` (H-13): it rewrote the
    // `.bean` with whatever envelope boot had — for a hand-typed record, none
    // — and the P2P tasks below started serving that file's contents before
    // the signer existed either. It now runs after the signer is installed
    // and the operator input is finalised, and the P2P tasks are spawned after
    // it. See "H-13: identity before the first write" below.

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

    // T80 / M-53: the author id is the key. Set here — as soon as the key is
    // loaded, before the signer, the verifier and `finalize_operator_input` —
    // whenever signing is enabled, P2P on or off. Before T80 it was set only
    // when P2P booted, so a node that signed with P2P off wrote the boot
    // placeholder as the author of every record under a real signature: its
    // own hand edits failed the verifier at their first boot, and turning P2P
    // on later quarantined its entire history at every boot. The P2P branch
    // below derives the same value from the endpoint and checks it matches.
    if config.signing.enabled {
        if let Some(secret_key) = node_secret_key.as_ref() {
            let author_id = secret_key.author_id();
            info!(author_id = %author_id, "ledger author id derived from the node key");
            shared_ledger.write().await.set_author_id(author_id);
        }
    }

    // Resolve the mesh signature domain ONCE (L-23), here, and hand the result
    // to every consumer. `p2p.meshId` when set, `p2p.swarmTopic` otherwise —
    // the fallback is what keeps already-persisted signatures verifiable on a
    // deployment that has not adopted a mesh id (see `P2pConfig::mesh_id`).
    //
    // One resolution, one value: the signer and the ALPN verification path both
    // receive this string, so neither reads `swarm_topic` for signature
    // purposes and the two cannot drift apart.
    let signature_domain = config.p2p.signature_domain().to_owned();
    // The domain doubles as a quasi-credential when it falls back to the swarm
    // topic (which is also the gossip join string), so the log names its
    // shape, never its value. R-9: with `meshId` unset on a signing node this
    // is a WARN whose remedy leads with "set p2p.meshId to your current
    // swarmTopic verbatim" — see `NodeConfig::log_signature_domain`.
    config.log_signature_domain();

    // Boot P2P if enabled (§3.4). Keep identity even when the allowlist is empty.
    //
    // H-13: only the IDENTITY is established here — the endpoint, the author
    // id, the handler. The router, the gossip loop and the anti-entropy loop
    // are spawned further down, after the signer is installed and the first
    // compaction has run, so nothing this node serves or gossips can predate
    // its own identity.
    let p2p_identity = if config.p2p.enabled {
        let Some(secret_key) = node_secret_key.as_ref() else {
            error!("p2p.enabled is true but no secret key was loaded — aborting");
            std::process::exit(1);
        };
        match p2p_service::boot_p2p(&config.p2p, secret_key, config.format.wire_codec()).await {
            Ok(peer_node) => {
                // §3.3.1: the ledger author IS the endpoint id. T80 set it from
                // the key above (signing is forced on with P2P); the endpoint
                // must agree, or this node would sign under one identity and
                // announce another.
                let iroh_author_id = peer_node.node_id();
                info!(author_id = %iroh_author_id, "P2P identity derived from Iroh EndpointId");
                let ledger_author = shared_ledger.read().await.author_id().to_owned();
                if ledger_author != iroh_author_id {
                    error!(
                        ledger_author = %ledger_author,
                        endpoint_id = %iroh_author_id,
                        "the ledger author id derived from the node key differs from the P2P \
                         endpoint id — aborting (T80)"
                    );
                    std::process::exit(1);
                }

                peer_registry = peer_node.registry.clone();

                if peer_node.allowlist().is_empty() {
                    warn!(
                        "p2p.bootstrapEndpointIds is empty — inbound ALPN Supply will be refused"
                    );
                }

                // R-7 (T70): the anti-entropy bounds come from `p2p.antiEntropy*`,
                // validated at boot; an absent key keeps the built-in default.
                let limits = config.p2p.anti_entropy_limits();
                // H-19: the join peer (validated as allowlisted at config load).
                let join_peer = config.p2p.join_from.as_ref().and_then(|raw| {
                    p2p::allowlist::PeerAllowlist::parse(std::slice::from_ref(raw))
                        .ok()
                        .and_then(|peer| peer.bootstrap_peers().first().copied())
                });
                if let Some(peer) = join_peer {
                    if shared_ledger.write().await.open_join_trust() {
                        info!(
                            peer = %peer,
                            "joining from p2p.joinFrom: the history this peer serves is adopted \
                             past the adoption ratchet until this node holds all of it (H-19)"
                        );
                    } else {
                        warn!(
                            peer = %peer,
                            "p2p.joinFrom is set, but this ledger already holds records this node \
                             wrote, so it is not joining and the adoption ratchet applies to every \
                             peer; the setting only serves a node that has not written — remove it \
                             (H-19)"
                        );
                    }
                }
                let handler = anti_entropy_alpn::AntiEntropyHandler {
                    ledger: shared_ledger.clone(),
                    broadcast: broadcast.clone(),
                    orphan_buffer: orphan_buffer.clone(),
                    allowlist: peer_node.allowlist().clone(),
                    signing_enabled: config.signing.enabled,
                    mesh_id: signature_domain.clone(),
                    timeouts: config.p2p.anti_entropy_timeouts(),
                    limits,
                    limiter: connection_limiter::ConnectionLimiter::new(limits),
                    // T42: one cache for the whole node — the router's clone,
                    // the gossip loop's and the anti-entropy tick's all share it.
                    connections: peer_connections::PeerConnectionCache::new(),
                    // M-39 (T69): one map for the node, shared by every clone.
                    supply_backoff: anti_entropy_alpn::SupplyBackoff::default(),
                    join_peer,
                    // Format v2, Facet C: what this node dials and gossips in.
                    wire_codec: config.format.wire_codec(),
                };
                Some((peer_node, handler))
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
    // `set_author_id` above has already run whenever signing is on (T80), so
    // the author this signs for is the same `EndpointId` the key belongs to.
    // Installed only with signing enabled (T80, 0924 §5): a disabled provider
    // signs nothing, and installing it made the ledger report
    // `signer_installed=true` on a node that cannot sign.
    // L-114: before the passes the signer and verifier run, so the override
    // is in place whatever they conclude.
    shared_ledger
        .write()
        .await
        .set_write_despite_signature_verdict(
            config.signing.allow_writes_when_every_signature_fails,
        );
    if config.signing.enabled {
        let signer_for_reconcile = Arc::clone(&signer);
        shared_ledger.write().await.set_signer(Arc::new(
            move |content_id: &str,
                  is_transaction: bool,
                  parents: &str,
                  lamport: &str,
                  format: ledger::hash::RecordFormat| {
                // Format v2: the record says which message it is signed in.
                signer_for_reconcile.sign_in(
                    p2p::union_merge::signature_version(format),
                    &security::signing::SignableMessage {
                        content_id,
                        is_transaction,
                        parents,
                        lamport,
                    },
                )
            },
        ));
    }

    // H-20: boot verifies what it loads. The verifier is the SAME check the
    // wire applies to a peer's directive (`verify_remote_signature`, built
    // from `security::signing::verify_signature` over the same message and
    // the same mesh id), so a record this node serves and a record a peer
    // would accept are held to one rule. Installed right after the signer;
    // installing it runs the pass over every foreign-authored record the
    // signer's own pass could not decide. Only with signing enabled: a
    // signing-off node produces and expects no signatures, and its history
    // stays unverified, which `verify_own_history` below says out loud.
    if config.signing.enabled {
        let mesh_id = signature_domain.clone();
        shared_ledger.write().await.set_verifier(Arc::new(
            move |content_id: &str,
                  is_transaction: bool,
                  parents: &str,
                  lamport: &str,
                  author: &str,
                  signature: &str,
                  format: ledger::hash::RecordFormat| {
                security::signing::verify_signature_in(
                    p2p::union_merge::signature_version(format),
                    &security::signing::SignableMessage {
                        content_id,
                        is_transaction,
                        parents,
                        lamport,
                    },
                    signature,
                    author,
                    &mesh_id,
                )
                .is_ok()
            },
        ));
    }

    // ── H-13: identity before the first write ──────────────────────────────
    //
    // The README's supported edit workflow is stop → edit → start, and boot
    // has just adopted whatever the operator typed as OPERATOR INPUT: this
    // node's lamport and parents stamped, author still the boot placeholder,
    // no signature — because the key was not loaded yet. Now it is: write the
    // real author id over the placeholder and sign, so the compaction that
    // follows persists those records exactly as an `appendTransaction` would
    // have, and every peer accepts them. Before this ordering the compaction
    // ran first, the file was rewritten without an envelope, and everything
    // the node authored afterwards named an unverifiable parent.
    {
        let mut service = shared_ledger.write().await;
        if service.unsigned_operator_input_count() > 0 {
            let finalized = service.finalize_operator_input();
            info!(
                finalized,
                signing_enabled = config.signing.enabled,
                "operator input adopted at boot now carries this node's author id and \
                 signature; the startup compaction writes it to the .bean (H-13)"
            );
        }
        // H-20: the identity is complete — author, signer, verifier, operator
        // input finalised — so this is where the history's signatures are
        // settled, before the compaction below persists anything and before
        // any peer is served. The signer and verifier installs above already
        // ran the pass; this call is the one that reports what could NOT be
        // checked, and the banner for what was quarantined.
        service.verify_own_history();
        // T80 (0924 §5): every pass, not only this call's — the signer and
        // verifier installs above already quarantined, and this call's own
        // return counts only what was left for it.
        let quarantined_by_signature = service.signature_quarantined_total();
        if quarantined_by_signature > 0 {
            warn!(
                quarantined = quarantined_by_signature,
                quarantined_total = service.quarantined_count(),
                directives = service.directive_count(),
                "{SIGNATURE_QUARANTINE_BANNER}"
            );
        }
    }

    // T44: fold any commit journal back into the canonical `.bean` before
    // serving. A journal is only ever present here after an unclean stop (a
    // clean one compacts on the way out), so this is the crash-recovery point:
    // boot has already unioned canonical ∪ journal into memory, and this writes
    // that union out as one canonical file and deletes the sidecar. H-13: and
    // it is the write that gives boot-adopted operator input its envelope on
    // disk, which is why it runs here — after the signer — and not before.
    //
    // A failure is logged, not fatal. The journal is still on disk and still
    // correct — boot read it once and would read it again — so refusing to
    // start would turn a recoverable disk hiccup into an outage.
    if let Err(error) = ledger_commit::compact(&shared_ledger).await {
        warn!(%error, "could not compact the ledger commit journal at startup; \
                       the journal is intact and will be folded in by a later write");
    }

    // H-13 (d): the P2P tasks start only now — with the author id set, the
    // signer installed and the operator input finalised — so the first
    // directive this node ever serves or gossips already carries its identity.
    let gossip_sender = match p2p_identity {
        Some((peer_node, handler)) => {
            p2p_router = Some(p2p_service::spawn_router(&peer_node, handler.clone()));
            let sender = p2p_service::spawn_gossip_loop(&peer_node, handler.clone());
            p2p_service::spawn_anti_entropy_loop(&peer_node, handler);
            // L-20: expire orphans on a timer, not only when an insert
            // happens to run the sweep.
            p2p_service::spawn_orphan_eviction_loop(orphan_buffer.clone());
            Some(sender)
        }
        None => None,
    };

    // Start the file watcher if the operator asked for it (§3.3, CT-12).
    //
    // M-19: this switch is `watchLedgerFile`, and it gates the watcher and
    // nothing else — which is all its predecessor `externalFileEdits` ever
    // gated either, while being documented as the master switch for adopting
    // hand edits. Adoption itself is unconditional: see
    // `LedgerService::adopt_external_edits` for why "off" could only mean
    // "destroy the operator's edit during our own rewrite".
    let file_watcher_handle = if config.watch_ledger_file {
        let watcher_ledger = shared_ledger.clone();
        let watcher_path = ledger_path.clone();
        let handle = tokio::spawn(async move {
            use ledger::file_watcher::{FileChangeKind, FilePoller, FileState};
            // M-42: a stateful poller that reads + hashes the file only when
            // its stat identity changed (or every `FULL_READ_EVERY` polls,
            // ≈10 s), and every poll runs on the blocking pool rather than on
            // a runtime worker.
            let (mut poller, first) =
                poll_ledger_file(FilePoller::new(watcher_path.clone()), &watcher_path).await;
            let mut last_state = first.unwrap_or(FileState {
                size: None,
                modified: None,
                content_hash: None,
            });
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
            // M-42: a poll slower than the period (a large file being read, a
            // slow disk) must not be followed by a burst of catch-up polls
            // back to back — the default `Burst` did exactly that.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                interval.tick().await;
                let (next_poller, current) = poll_ledger_file(poller, &watcher_path).await;
                poller = next_poller;
                let Some(current) = current else {
                    continue;
                };
                let change = current.detect_change(&last_state);
                // H-15: a `Deleted` is handled like a `Modified`. The
                // reconcile finds nothing to read, arms a forced compaction,
                // and the commit below recreates the file from memory.
                if matches!(change, FileChangeKind::Modified | FileChangeKind::Deleted) {
                    // M-29: self-write suppression. Every commit this node makes
                    // to the canonical file is a `Modified` here, and without
                    // this check the watcher answered it by taking the write
                    // permit and the write lock and re-parsing the entire
                    // ledger to discover that all of it was already in the DAG
                    // — while `reconcile_content` cleared `canonical_is_current`
                    // on the way out, which forced the NEXT commit to be a full
                    // compaction, which the watcher then saw as another change.
                    // T44's append path was off for the life of the process
                    // after one tick.
                    //
                    // The hash is the one already computed by the poll above, so
                    // suppression costs a read lock and a string compare. The
                    // service-side short-circuit in `reconcile_file_staged`
                    // backs it up for anything this misses (a BOM'd file, an
                    // over-cap one).
                    let is_own_write = match current.content_hash_hex() {
                        Some(hash) => watcher_ledger.read().await.file_hash_is_current(&hash),
                        None => false,
                    };
                    if is_own_write {
                        debug!("ledger file change is this node's own write — not reconciling");
                        last_state = current;
                        continue;
                    }
                    info!("external edit detected — reconciling");
                    // T44: the same permit → lock → prepare → unlock → commit
                    // sequence the mutations use. A reconcile always compacts
                    // (it has to delete the entries it refused and re-spell the
                    // rest), and that rewrite is exactly the kind of write that
                    // must not run under the read-blocking write lock.
                    let permit = ledger_commit::acquire_write_permit(&watcher_ledger).await;
                    let mut svc = watcher_ledger.write().await;
                    let committed = match svc.reconcile_file_staged() {
                        Ok(result) => {
                            // M-37(b): a rejected-ONLY edit compacts too. The
                            // L-12 warning promises the canonical re-persist
                            // drops what was refused; without this arm the
                            // refused entry stayed on disk and the next boot
                            // loaded it. H-15: and so does a reconcile that
                            // found the file gone.
                            if result.new_directives > 0
                                || result.rejected > 0
                                || svc.compaction_pending()
                            {
                                info!(
                                    new = result.new_directives,
                                    duplicates = result.duplicates,
                                    rejected = result.rejected,
                                    "reconciled external edit"
                                );
                                // M-39: a failed prepare reloads with the
                                // lock released. H-11: on success the permit
                                // goes WITH the commit; on failure it went
                                // with the recovery.
                                match ledger_commit::prepare_or_recover(
                                    &watcher_ledger,
                                    svc,
                                    true,
                                    permit,
                                )
                                .await
                                {
                                    Ok((svc, pending, permit)) => {
                                        drop(svc);
                                        ledger_commit::commit_pending(
                                            &watcher_ledger,
                                            pending,
                                            permit,
                                        )
                                        .await
                                    }
                                    Err(error) => Err(error),
                                }
                            } else {
                                Ok(())
                            }
                        }
                        // H-14 / M-37(a): a file that does not parse left
                        // every fact the service holds about the `.bean`
                        // untouched, so the next commit re-detects it and
                        // refuses too; nothing to restore here.
                        Err(error) => {
                            warn!(%error, "failed to reconcile external edit");
                            Ok(())
                        }
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
        // L-51: behind a terminator the node's public origin is https.
        tls_terminated: config.tls.mode == "terminated",
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
/// Layer order, outermost first: CORS, body limit (H-05), then per route the
/// request guard (H-01), the rate limiter and — on `/graphql` only — auth. The
/// guard is outermost among those so a rejected Host, Content-Type or Origin
/// never reaches the limiter or the schema.
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
    let health_limiter = limiter.sibling(
        rate_limit::HEALTH_RATE_LIMIT,
        rate_limit::HEALTH_RATE_WINDOW,
    );
    let graphql_routes = graphql_router
        .with_state(schema)
        .layer(middleware::from_fn_with_state(
            auth_state,
            auth::auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            limiter,
            rate_limit::rate_limit,
        ))
        .layer(middleware::from_fn_with_state(
            guard_state.clone(),
            request_guard::request_guard,
        ));
    let health_routes = Router::new()
        .route("/health", get(health_handler))
        .with_state(health_state)
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
