//! One ledger's life on a node (`docs/build-log/003-multi-ledger-node`): the
//! boot sequence that `main` ran for its one ledger, moved here unchanged and
//! in the same order, and the shutdown half.
//!
//! The order is the point. Each step's comment below is the audit finding that
//! put it where it is: the ledger is locked before it is read (M-17), the node
//! key is read once for both the endpoint and the signer (L-04), the author is
//! the key before anything is signed (T80), the signer and verifier are
//! installed and operator input finalised before the first write (H-13, H-20),
//! the startup compaction runs before P2P serves anything (H-13 (d)), and the
//! file watcher starts last. A ledger that cannot start says why in the log,
//! where it found the problem, and returns [`StartFailed`].

use std::path::PathBuf;
use std::sync::Arc;

use p2p::node::PeerRegistry;
use p2p::orphan_buffer::OrphanBuffer;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::auth::AuthState;
use crate::config::LedgerConfig;
use crate::graphql::broadcast::TransactionBroadcast;
use crate::graphql::{build_schema_with_access, AppSchema, SharedLedger};
use crate::health::HealthState;

/// What a ledger needs from the node that hosts it.
#[derive(Clone)]
pub(crate) struct NodeSettings {
    /// `auth.enabled`.
    pub auth_enabled: bool,
    /// The node's operator key (empty with auth off).
    pub operator_key: String,
    /// Whether GraphiQL (and so introspection) is on.
    pub graphiql: bool,
    /// Whether the node binds a non-loopback address (L-09, `/health`).
    pub public_bind: bool,
    /// The node ids of the ledgers started so far, by id, with their ledger's
    /// name (003, decision 1): no two ledgers share a node key.
    pub node_ids: NodeIds,
}

/// See [`NodeSettings::node_ids`].
pub(crate) type NodeIds = Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>;

/// A ledger that could not start. The reason was logged where it was found.
#[derive(Debug)]
pub(crate) struct StartFailed;

/// Claim each ledger's node id in the order given — the config file's ledger
/// first, then the folders by name — and name the ledgers whose key another
/// ledger before them already has (003, decision 1). Done before the ledgers
/// boot in parallel, so which of two ledgers sharing a key is served is the
/// same at every restart, and the config file's ledger always keeps its key.
/// A key that cannot be read here is left for the ledger's own start to
/// report. A P2P ledger's key is created here on its first boot, as its start
/// would create it.
pub(crate) fn settle_node_keys(
    ledgers: &[(String, LedgerConfig)],
    node_ids: &NodeIds,
) -> Vec<(String, String)> {
    let mut refused = Vec::new();
    let mut ids = node_ids.lock().expect("node ids lock");
    for (name, config) in ledgers {
        let path = PathBuf::from(&config.p2p.secret_key_path);
        let key = if config.p2p.enabled {
            crate::p2p_service::load_or_create_secret_key(&path)
        } else if config.signing.enabled {
            crate::p2p_service::load_secret_key(&path)
        } else {
            continue;
        };
        let Ok(key) = key else {
            continue;
        };
        let id = key.author_id();
        match ids.get(&id) {
            Some(other) => refused.push((
                name.clone(),
                format!(
                    "its node key is also ledger \"{other}\"'s: one node id in two meshes would tie them together; give each ledger its own key"
                ),
            )),
            None => {
                ids.insert(id, name.clone());
            }
        }
    }
    refused
}

/// A started ledger: what the node serves it with, and what [`Self::stop`]
/// shuts down.
pub(crate) struct RunningLedger {
    pub schema: AppSchema,
    pub auth: AuthState,
    pub health: HealthState,
    ledger: SharedLedger,
    file_watcher: Option<tokio::task::JoinHandle<()>>,
    p2p_router: Option<iroh::protocol::Router>,
    /// M-17: held for the ledger's whole life; dropped by [`Self::stop`].
    _lock: crate::ledger_lock::LedgerLock,
}

/// Start the ledger `name` that `config` describes; see the module doc for
/// the order. Every line it logs, and every task it spawns, carries the
/// ledger's name (a `ledger` span).
pub(crate) async fn start(
    name: &str,
    config: &LedgerConfig,
    node: &NodeSettings,
) -> Result<RunningLedger, StartFailed> {
    use tracing::Instrument;
    start_ledger(name, config, node)
        .instrument(tracing::info_span!("ledger", ledger = %name))
        .await
}

async fn start_ledger(
    name: &str,
    config: &LedgerConfig,
    node: &NodeSettings,
) -> Result<RunningLedger, StartFailed> {
    // 003: everything that can refuse the ledger is judged before anything is
    // spawned, so a refused ledger leaves no task running without its lock.
    // `auth.adminNodes` was parsed here last; it is checked first now.
    let admin_nodes = match config.admin_node_ids() {
        Ok(nodes) => nodes.map(std::sync::Arc::new),
        Err(error) => {
            error!(%error, "auth.adminNodes; this ledger is not served");
            return Err(StartFailed);
        }
    };

    // Ensure the ledger file's parent directory exists (§3.3). The `.bean` file
    // itself is deliberately NOT created here — see below.
    let ledger_path = PathBuf::from(&config.ledger_path);
    if let Err(error) = crate::ensure_ledger_parent_directory(&ledger_path) {
        error!(%error, path = %ledger_path.display(), "failed to create ledger directory");
        return Err(StartFailed);
    }

    // Claim the ledger for this process before touching it (M-17). Two nodes on
    // one .bean hold independent DAGs and rewrite the whole file per persist, so
    // the later writer silently discards the other's directives — fail closed
    // instead. The guard lives as long as the ledger runs (`RunningLedger`):
    // dropping it, or the process dying, releases the lock, so a crash never
    // wedges the ledger.
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
    let (ledger_path, ledger_lock) = match crate::claim_ledger_path(&ledger_path) {
        Ok((resolved, guard)) => {
            info!(lock = %guard.path().display(), "ledger lock acquired");
            (resolved, guard)
        }
        Err(error) => {
            error!(%error, "cannot use the configured ledger path; this ledger is not served");
            return Err(StartFailed);
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
    // 003 step 3 (review): the boot reads, hashes and verifies the whole file
    // — seconds for a large ledger — so it runs on the blocking pool, not on a
    // runtime worker the ledgers already started need for their P2P.
    let boot_path = ledger_path.clone();
    let format = config.format.record_format();
    let booted = tokio::task::spawn_blocking(move || {
        ledger::service::LedgerService::boot_emitting(&boot_path, author_id, format)
    })
    .await
    .unwrap_or_else(|panic| std::panic::resume_unwind(panic.into_panic()));
    let service = match booted {
        Ok(service) => service,
        Err(error) => {
            error!(%error, "failed to boot ledger service; this ledger is not served");
            return Err(StartFailed);
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
            "{}", crate::QUARANTINE_BANNER
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
        match crate::p2p_service::load_or_create_secret_key(&secret_key_path) {
            Ok(key) => Some(key),
            Err(error) => {
                error!(%error, path = %secret_key_path.display(), "failed to load or create the node secret key; this ledger is not served");
                return Err(StartFailed);
            }
        }
    } else if config.signing.enabled {
        match crate::p2p_service::load_secret_key(&secret_key_path) {
            Ok(key) => Some(key),
            Err(error) => {
                error!(%error, path = %secret_key_path.display(), "signing enabled but secret key could not be loaded; this ledger is not served");
                return Err(StartFailed);
            }
        }
    } else {
        None
    };

    // 003, decision 1 (review M-2): a ledger's node key is its own. The same
    // key in two ledgers — a copied folder, or the config file pointed at a
    // folder's key — would be one node id in two meshes, tying them together;
    // refused here, before anything joins a mesh.
    // `settle_node_keys` has already claimed the ids in a fixed order (the
    // config file's ledger, then the folders by name); this is the backstop
    // for a ledger started any other way.
    if let Some(secret_key) = node_secret_key.as_ref() {
        let id = secret_key.author_id();
        let mut ids = node.node_ids.lock().expect("node ids lock");
        if let Some(other) = ids.get(&id).filter(|other| *other != name) {
            error!(
                other_ledger = %other,
                "this ledger's node key is also ledger \"{other}\"'s: one node id in two meshes would tie them together; give each ledger its own key; this ledger is not served"
            );
            return Err(StartFailed);
        }
        ids.insert(id, name.to_owned());
    }

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
    // swarmTopic verbatim" — see `P2pConfig::log_signature_domain`.
    config.p2p.log_signature_domain();

    // Boot P2P if enabled (§3.4). Keep identity even when the allowlist is empty.
    //
    // H-13: only the IDENTITY is established here — the endpoint, the author
    // id, the handler. The router, the gossip loop and the anti-entropy loop
    // are spawned further down, after the signer is installed and the first
    // compaction has run, so nothing this node serves or gossips can predate
    // its own identity.
    let p2p_identity = if config.p2p.enabled {
        let Some(secret_key) = node_secret_key.as_ref() else {
            error!("p2p.enabled is true but no secret key was loaded; this ledger is not served");
            return Err(StartFailed);
        };
        match crate::p2p_service::boot_p2p(&config.p2p, secret_key, config.format.wire_codec())
            .await
        {
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
                         endpoint id — this ledger is not served (T80)"
                    );
                    // 003: the endpoint is closed, not dropped, so the ledger
                    // leaves nothing listening behind it.
                    peer_node.endpoint().close().await;
                    return Err(StartFailed);
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
                let handler = crate::anti_entropy_alpn::AntiEntropyHandler {
                    ledger: shared_ledger.clone(),
                    broadcast: broadcast.clone(),
                    orphan_buffer: orphan_buffer.clone(),
                    allowlist: peer_node.allowlist().clone(),
                    signing_enabled: config.signing.enabled,
                    mesh_id: signature_domain.clone(),
                    timeouts: config.p2p.anti_entropy_timeouts(),
                    limits,
                    limiter: crate::connection_limiter::ConnectionLimiter::new(limits),
                    // T42: one cache for the whole node — the router's clone,
                    // the gossip loop's and the anti-entropy tick's all share it.
                    connections: crate::peer_connections::PeerConnectionCache::new(),
                    // M-39 (T69): one map for the node, shared by every clone.
                    supply_backoff: crate::anti_entropy_alpn::SupplyBackoff::default(),
                    join_peer,
                    // Format v2, Facet C: what this node dials and gossips in.
                    wire_codec: config.format.wire_codec(),
                };
                Some((peer_node, handler))
            }
            Err(error) => {
                error!(%error, "failed to boot P2P — this ledger is not served (p2p.enabled is true)");
                return Err(StartFailed);
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
    let Some(signer) =
        crate::build_signature_provider(config, node_secret_key.as_ref(), &signature_domain)
    else {
        return Err(StartFailed);
    };

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
                "{}",
                crate::SIGNATURE_QUARANTINE_BANNER
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
    if let Err(error) = crate::ledger_commit::compact(&shared_ledger).await {
        warn!(%error, "could not compact the ledger commit journal at startup; \
                       the journal is intact and will be folded in by a later write");
    }

    // H-13 (d): the P2P tasks start only now — with the author id set, the
    // signer installed and the operator input finalised — so the first
    // directive this node ever serves or gossips already carries its identity.
    let gossip_sender = match p2p_identity {
        Some((peer_node, handler)) => {
            p2p_router = Some(crate::p2p_service::spawn_router(
                &peer_node,
                handler.clone(),
            ));
            let sender = crate::p2p_service::spawn_gossip_loop(&peer_node, handler.clone());
            crate::p2p_service::spawn_anti_entropy_loop(&peer_node, handler);
            // L-20: expire orphans on a timer, not only when an insert
            // happens to run the sweep.
            crate::p2p_service::spawn_orphan_eviction_loop(orphan_buffer.clone());
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
        let handle = crate::spawn_in_span(async move {
            use ledger::file_watcher::{FileChangeKind, FilePoller, FileState};
            // M-42: a stateful poller that reads + hashes the file only when
            // its stat identity changed (or every `FULL_READ_EVERY` polls,
            // ≈10 s), and every poll runs on the blocking pool rather than on
            // a runtime worker.
            let (mut poller, first) =
                crate::poll_ledger_file(FilePoller::new(watcher_path.clone()), &watcher_path).await;
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
                let (next_poller, current) = crate::poll_ledger_file(poller, &watcher_path).await;
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
                    let permit = crate::ledger_commit::acquire_write_permit(&watcher_ledger).await;
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
                                match crate::ledger_commit::prepare_or_recover(
                                    &watcher_ledger,
                                    svc,
                                    true,
                                    permit,
                                )
                                .await
                                {
                                    Ok((svc, pending, permit)) => {
                                        drop(svc);
                                        crate::ledger_commit::commit_pending(
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

    // Auth state for middleware (§3.8).
    // 002-users-and-roles: people's keys come from the ledger's access
    // records, judged on each request; the operator key stays the node's own.
    let access = crate::auth::access_source_for(
        node.auth_enabled,
        config,
        shared_ledger.clone(),
        admin_nodes,
    );
    if !config.signing.enabled
        && shared_ledger
            .read()
            .await
            .dag()
            .access_records()
            .next()
            .is_some()
    {
        warn!(
            "the ledger holds access records (people's keys), but signing.enabled is off: without signatures nothing proves who wrote them, so only the operator key is accepted — turn signing on to honour people's keys"
        );
    }
    // Build the GraphQL schema with live service + peer registry + signer, and
    // the access list the admin API manages.
    let schema = build_schema_with_access(
        shared_ledger.clone(),
        broadcast,
        peer_registry.clone(),
        signer,
        node.graphiql,
        gossip_sender,
        access.clone(),
    );
    let auth_state = AuthState {
        enabled: node.auth_enabled,
        api_key: node.operator_key.clone(),
        access,
    };

    // Health state with live shared ledger + peer registry.
    //
    // L-09: the bind decides how much detail `/health` discloses to an
    // unauthenticated caller, and the auth state lets an authenticated operator
    // get the full picture on a public bind regardless.
    // T44: kept for the shutdown compaction (`RunningLedger::stop`), since `HealthState` takes
    // ownership of the shared handle.
    let ledger_for_shutdown = shared_ledger.clone();
    let health_state = HealthState {
        ledger: shared_ledger,
        peer_registry,
        public_bind: node.public_bind,
        auth: auth_state.clone(),
    };

    Ok(RunningLedger {
        schema,
        auth: auth_state,
        health: health_state,
        ledger: ledger_for_shutdown,
        file_watcher: file_watcher_handle,
        p2p_router,
        _lock: ledger_lock,
    })
}

impl RunningLedger {
    /// The shutdown half: stop the watcher, compact, stop P2P — in that order,
    /// as `main` did. The ledger's lock is released last, when `self` drops.
    pub(crate) async fn stop(self) {
        // Stop file watcher if running.
        if let Some(handle) = self.file_watcher {
            handle.abort();
        }

        // T44: fold the commit journal back into the canonical `.bean` on the way
        // out, so a cleanly-stopped node leaves exactly one file behind and the
        // next boot has nothing to replay. Cheap — it is one rewrite of a file
        // every pre-T44 mutation rewrote anyway — and safe to skip: the journal is
        // durable, and boot unions it if this fails.
        if let Err(error) = crate::ledger_commit::compact(&self.ledger).await {
            warn!(%error, "could not compact the ledger commit journal at shutdown; \
                           the journal is intact and will be folded in on the next boot");
        }

        if let Some(router) = self.p2p_router {
            if let Err(error) = router.shutdown().await {
                warn!(%error, "P2P router shutdown error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> NodeSettings {
        NodeSettings {
            auth_enabled: true,
            operator_key: "operator-key-for-the-runtime-tests-0123456789".to_owned(),
            graphiql: false,
            public_bind: false,
            node_ids: NodeIds::default(),
        }
    }

    fn ledger_at(path: &std::path::Path) -> LedgerConfig {
        let file = tempfile::NamedTempFile::new().expect("config file");
        std::fs::write(file.path(), r#"{ "ledgerPath": "./data/ledger.bean" }"#).expect("write");
        let mut config = crate::config::NodeConfig::load_from_path(&file.path().to_path_buf())
            .expect("config")
            .ledger_config();
        config.ledger_path = path.to_string_lossy().into_owned();
        config
    }

    /// 003: a ledger that cannot start leaves nothing behind — refused for its
    /// `adminNodes`, it touched nothing on disk (the check runs before
    /// anything else); refused later (signing on, no key), it released its
    /// lock, so the same ledger starts at once with a good config — and stops.
    ///
    /// Bug-catch: check `adminNodes` after P2P and the watcher are spawned
    /// and a refused ledger leaves them running with no lock held.
    #[tokio::test]
    async fn a_ledger_that_cannot_start_leaves_nothing_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("acme").join("ledger.bean");

        let mut bad_admins = ledger_at(&path);
        bad_admins.admin_nodes = Some(vec!["not-an-endpoint-id".to_owned()]);
        assert!(start("acme", &bad_admins, &settings()).await.is_err());
        assert!(!dir.path().join("acme").exists(), "nothing was touched");

        let mut no_key = ledger_at(&path);
        no_key.signing.enabled = true;
        no_key.p2p.mesh_id = Some("acme-mesh".to_owned());
        no_key.p2p.secret_key_path = dir
            .path()
            .join("missing.secret")
            .to_string_lossy()
            .into_owned();
        assert!(start("acme", &no_key, &settings()).await.is_err());

        let running = start("acme", &ledger_at(&path), &settings())
            .await
            .expect("the lock was released");
        running.stop().await;
    }

    /// 003, decision 1 (review M-2): two ledgers with the same node key — a
    /// copied folder — are refused: the second does not start, so one node
    /// id never sits in two meshes.
    ///
    /// Bug-catch: skip the check and a copied folder's mesh learns the
    /// identity the node has in the original's.
    #[tokio::test]
    async fn a_second_ledger_with_the_same_node_key_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let original = dir.path().join("acme.secret");
        crate::p2p_service::load_or_create_secret_key(&original).expect("a key");
        let copy = dir.path().join("beta.secret");
        std::fs::copy(&original, &copy).expect("a copied key");
        let signing = |path: &std::path::Path, key: &std::path::Path, mesh: &str| {
            let mut config = ledger_at(path);
            config.signing.enabled = true;
            config.p2p.mesh_id = Some(mesh.to_owned());
            config.p2p.secret_key_path = key.to_string_lossy().into_owned();
            config
        };
        let node = settings();
        let acme = start(
            "acme",
            &signing(&dir.path().join("acme.bean"), &original, "acme"),
            &node,
        )
        .await
        .expect("acme starts");
        assert!(
            start(
                "beta",
                &signing(&dir.path().join("beta.bean"), &copy, "beta"),
                &node
            )
            .await
            .is_err(),
            "beta has acme's key"
        );
        acme.stop().await;
    }

    /// Review: which of two ledgers sharing a node key is served is settled
    /// in the order given — the config file's ledger, then the folders by name
    /// — before anything boots in parallel, so it is the same at every
    /// restart: the earlier keeps its key, the later is refused.
    ///
    /// Bug-catch: leave it to the boots racing in parallel and a copied folder
    /// is served on one restart and its original on the next.
    #[test]
    fn shared_node_keys_are_settled_in_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = |name: &str, copy_of: Option<&str>| {
            let path = dir.path().join(format!("{name}.secret"));
            match copy_of {
                Some(original) => {
                    std::fs::copy(dir.path().join(format!("{original}.secret")), &path)
                        .expect("a copied key");
                }
                None => {
                    crate::p2p_service::load_or_create_secret_key(&path).expect("a key");
                }
            }
            let mut config = ledger_at(&dir.path().join(format!("{name}.bean")));
            config.signing.enabled = true;
            config.p2p.secret_key_path = path.to_string_lossy().into_owned();
            (name.to_owned(), config)
        };
        let ledgers = vec![
            key("default", None),
            key("acme", Some("default")),
            key("beta", None),
            key("zeta", Some("beta")),
        ];
        for _ in 0..2 {
            let refused: Vec<String> = settle_node_keys(&ledgers, &NodeIds::default())
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            assert_eq!(
                refused,
                ["acme", "zeta"],
                "the earlier keeps its key, every time"
            );
        }
    }
}
