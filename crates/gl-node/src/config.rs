use crate::anti_entropy_alpn::AntiEntropyTimeouts;
use crate::connection_limiter::AntiEntropyLimits;
use crate::http_server::HttpServerSettings;
use axum::http::{header, HeaderName, HeaderValue, Method};
use serde::Deserialize;
use std::fs::File;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{info, warn};

/// Environment variable that supplies `auth.apiKey`.
///
/// It takes precedence over a non-empty value in the config file: an operator
/// rotating a key reaches for the environment, and the file is the thing that
/// tends to be stale (baked into an image, checked into a repository, mounted
/// read-only). See [`NodeConfig::load_from_path`].
const API_KEY_ENV_VAR: &str = "GL_NODE_API_KEY";

/// Documented sample key. Boot fails if this value is used (H-5).
pub const FORBIDDEN_SAMPLE_API_KEY: &str = "change-me-docker-api-key";

/// Values `auth.apiKey` may never take (L-08), compared case-insensitively
/// against the trimmed configured value.
///
/// The first two are the samples this repository actually ships — H-5 denylisted
/// only the Docker one, so the README's `"my-secret-key-here"`, which is the
/// value in the "Full Config (All Options)" block that operators copy verbatim,
/// booted a public node with a published key. The rest are the placeholders
/// people reach for when they mean "fill this in later", which is precisely the
/// deployment that never gets revisited.
///
/// Matching is exact (not substring): `"secret"` is refused, while a real key
/// that happens to contain the word is not. A denylist is not a strength test —
/// [`MIN_API_KEY_BYTES`] is — it is a guard against *published* values, where
/// length is no defence at all because the attacker has the string.
const FORBIDDEN_API_KEYS: &[&str] = &[
    FORBIDDEN_SAMPLE_API_KEY,
    "my-secret-key-here",
    "changeme",
    "change-me",
    "password",
    "secret",
    "test",
    "api-key",
];

/// Minimum length of a configured `auth.apiKey`, in bytes (L-08).
///
/// The key is the only thing between the internet and the writable GraphQL
/// mutations on a public bind, and it is checked with a constant-time compare
/// that offers no rate limiting of its own beyond the shared request limiter.
/// 16 bytes is the low end of "not guessable", and it is deliberately below
/// anything a generator would emit — the point is to refuse hand-typed keys
/// like `"hunter2"`, not to dictate a format.
const MIN_API_KEY_BYTES: usize = 16;

/// Whether `api_key` can be sent, and matched, as an `X-Api-Key` value (L-50).
fn is_header_safe_api_key(api_key: &str) -> bool {
    HeaderValue::from_str(api_key).is_ok()
        && api_key
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        && api_key.trim() == api_key
}

/// The denylisted value `api_key` matches, if any (L-08).
///
/// Returns the canonical denylist entry rather than the operator's spelling, so
/// the boot error names a value they can grep the docs for.
fn forbidden_api_key_match(api_key: &str) -> Option<&'static str> {
    let candidate = api_key.trim();
    FORBIDDEN_API_KEYS
        .iter()
        .copied()
        .find(|forbidden| forbidden.eq_ignore_ascii_case(candidate))
}

/// The rules every API key must meet (L-08, L-50), whether it came from the
/// config file, `GL_NODE_API_KEY` or the key file (H-01). The messages never
/// echo the key.
pub(crate) fn check_api_key(api_key: &str) -> Result<(), String> {
    if let Some(sample) = forbidden_api_key_match(api_key) {
        return Err(format!(
            "auth.apiKey must not be the documented sample or placeholder \"{sample}\"; \
             set a unique key or GL_NODE_API_KEY"
        ));
    }

    if api_key.len() < MIN_API_KEY_BYTES {
        return Err(format!(
            "auth.apiKey must be at least {MIN_API_KEY_BYTES} bytes, got {}; \
             it is the only credential guarding the writable GraphQL mutations",
            api_key.len()
        ));
    }

    // L-50: the key is compared against an `X-Api-Key` header value, so it
    // must be something a client can actually send. A non-ASCII or
    // control-character key booted fine and then 401'd every request forever —
    // `HeaderValue::to_str` fails on the client's side of the comparison, so no
    // request can ever match — and surrounding whitespace is stripped from
    // header values in transit, so a padded key can never match either. The
    // same `HeaderValue::from_str` test `allowedHosts` and
    // `cors.allowedOrigins` already get.
    if !is_header_safe_api_key(api_key) {
        return Err(
            "auth.apiKey must be printable ASCII with no leading or trailing whitespace; \
                    it is sent as the X-Api-Key header, and any other value can never match, \
                    so the node would reject every request (401) forever"
                .to_owned(),
        );
    }
    Ok(())
}

/// Top-level node configuration.
///
/// Deserialized from `gl-node.config.json` (or the path in `GL_NODE_CONFIG`).
/// Unknown keys are rejected at boot per §3.11.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct NodeConfig {
    /// Path to the single `.bean` file. Created if missing (§3.3).
    pub ledger_path: String,

    /// HTTP listen address. Default: `"127.0.0.1"`.
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// HTTP listen port. Default: `4000`.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Poll the `.bean` for hand edits and reconcile them promptly (§3.3,
    /// CT-12). Default: `false`.
    ///
    /// This replaces `externalFileEdits`, which claimed to control something it
    /// did not (M-19). What it gated, and all it ever gated, is the 250 ms file
    /// watcher — the node's *proactive* half, which notices a hand edit and
    /// folds it in without waiting for the next write.
    ///
    /// # What no setting controls, and why (M-19)
    ///
    /// Whether a hand edit is **adopted**. `LedgerService` re-reads and
    /// reconciles the file immediately before the full-file rewrite that would
    /// otherwise erase it (L-30 adopt-before-persist), and that is not a
    /// feature to be switched off: it is only reachable on the path that is
    /// about to overwrite the operator's bytes, so "off" would mean "destroy
    /// the edit silently" rather than "ignore it". Refusing the write instead
    /// would wedge every write on a node whose file was merely touched, and
    /// both readings strand the T47/T51 quarantine, whose release runs through
    /// the same reconcile. The README says so in the same words.
    ///
    /// Leaving this `false` therefore does not mean hand edits are ignored. It
    /// means they are adopted at the next full rewrite rather than within
    /// 250 ms, and that the node does not spend a read of the ledger file four
    /// times a second to find out.
    #[serde(default)]
    pub watch_ledger_file: bool,

    /// Serve GraphiQL on `GET /graphql`. Default: `false`. Loopback only.
    #[serde(default = "default_graphiql")]
    pub graphiql: bool,

    /// CORS origin allowlist. Empty (default) denies browser cross-origin access.
    #[serde(default)]
    pub cors: CorsConfig,

    /// Extra `Host` header values the request guard accepts (H-01), beyond the
    /// built-in loopback set (`localhost`, `127.0.0.1`, `::1`) and the bind
    /// address. Hostnames or IP literals only — no scheme, no port.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// IP addresses of the reverse proxies whose `X-Forwarded-For` is trusted
    /// (M-04). IP literals only — no hostnames, ports or CIDR ranges.
    ///
    /// A public bind must terminate TLS at a proxy (`tls.mode = "terminated"`),
    /// and behind a proxy every request arrives from the same socket address:
    /// without this list the whole internet shares one rate-limit bucket and a
    /// single client starves everyone else. When the TCP peer is one of these
    /// addresses, the client is identified instead by the **rightmost
    /// `X-Forwarded-For` entry that is not itself a trusted proxy** — the
    /// standard anti-spoof parse. Each proxy appends what it saw, so entries to
    /// the left of that one were supplied by the client and are ignored.
    ///
    /// Empty (the default) means no `X-Forwarded-For` is trusted at all and
    /// every client is keyed by its TCP peer address: fail-closed, and
    /// identical to the pre-M-04 behavior.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// Authentication configuration.
    #[serde(default)]
    pub auth: AuthConfig,

    /// Transaction signing configuration.
    #[serde(default)]
    #[allow(dead_code)] // Read when signing is wired (Phase 2).
    pub signing: SigningConfig,

    /// TLS policy for the GraphQL HTTP bind (M-13).
    #[serde(default)]
    pub tls: TlsConfig,

    /// Format v2 (T45): what this node emits, flipped mesh-wide; every node
    /// accepts both formats whatever this says.
    #[serde(default)]
    pub format: FormatConfig,

    /// Where this node's other ledgers live (`docs/build-log/003-multi-ledger-node`):
    /// one folder per ledger, named for it, holding its `ledger.json` beside
    /// its files. Default `./data/ledgers`; a missing folder means none. The
    /// config file's own ledger is the one named `default`.
    #[serde(default = "default_ledgers_dir")]
    pub ledgers_dir: String,

    /// The most ledgers this node serves, its own included (003). Default and
    /// ceiling [`MAX_LEDGERS`].
    #[serde(default = "default_max_ledgers")]
    pub max_ledgers: usize,

    /// Connection-level HTTP hardening knobs (M-13).
    ///
    /// Optional in full: an absent `http` section reproduces the hardcoded
    /// defaults `serve_hardened` shipped with, byte for byte, because every
    /// field's serde default is read straight off
    /// [`HttpServerSettings::default`].
    #[serde(default)]
    pub http: HttpConfig,

    /// Peer-to-peer replication configuration.
    #[serde(default)]
    pub p2p: P2pConfig,
}

/// Connection-level HTTP limits (M-13), tunable per deployment.
///
/// These are the node's own backstops. A public bind sits behind a
/// TLS-terminating reverse proxy, and **that proxy must enforce equivalent
/// header, request and connection limits of its own** — a value relaxed here
/// does not relax anything the proxy applies first, and a proxy with no limits
/// is not rescued by the values here, because it has already accepted and is
/// holding the connection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct HttpConfig {
    /// Seconds a client gets to deliver a complete request head. Re-armed
    /// before every head, so it also bounds idle keep-alive.
    #[serde(default = "default_header_read_timeout_seconds")]
    pub header_read_timeout_seconds: u64,

    /// Seconds a single request gets end to end, body read and GraphQL
    /// execution included.
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,

    /// Ceiling on concurrently served connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Ceiling on concurrently served connections from one client address —
    /// an IPv4 address or an IPv6 /64 (M-33). Addresses in `trustedProxies`
    /// are exempt: a terminator carries every client through one address.
    /// Values above `maxConnections` behave as `maxConnections`.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,

    /// GraphQL requests one ledger serves at once (003): past it the ledger
    /// answers 503 `LEDGER_BUSY`, and the node's other ledgers are untouched.
    /// Counted after the key check, so only callers the ledger accepts use a
    /// slot.
    #[serde(default = "default_max_requests_per_ledger")]
    pub max_requests_per_ledger: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            header_read_timeout_seconds: default_header_read_timeout_seconds(),
            request_timeout_seconds: default_request_timeout_seconds(),
            max_connections: default_max_connections(),
            max_connections_per_ip: default_max_connections_per_ip(),
            max_requests_per_ledger: default_max_requests_per_ledger(),
        }
    }
}

/// Format v2 (T45, docs/FORMAT_V2_DESIGN.md): the coordinated encoding
/// transition. Each switch decides only what this node EMITS; a node accepts
/// both formats always, so a mesh flips one node at a time.
///
/// Both are on by default since 2026-10-06, before any release: a mesh is
/// born in v2, with M-10 and L-06 closed, instead of every deployed mesh
/// switching over later. Setting one to `false` is how a node keeps writing
/// for peers on a build from before Format v2, which read neither.
#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct FormatConfig {
    /// Dial anti-entropy and gossip in the wire-v2 encoding (Facet C): the
    /// `openledger/anti-entropy/2` ALPN and the `<swarmTopic>/2` gossip topic.
    /// Both ALPNs are served regardless.
    #[serde(default = "default_format_v2")]
    pub wire2: bool,

    /// Write records in Format v2 (Facets A + B): `openledger-format: "2"`,
    /// an id that covers the author (another author's copy of a body is
    /// another record — M-10), signed in signature v4 (L-06). Records of both
    /// formats are accepted regardless.
    #[serde(default = "default_format_v2")]
    pub idv2: bool,
}

impl Default for FormatConfig {
    fn default() -> Self {
        Self {
            wire2: default_format_v2(),
            idv2: default_format_v2(),
        }
    }
}

fn default_format_v2() -> bool {
    true
}

impl FormatConfig {
    /// The format of the records this node writes.
    pub fn record_format(&self) -> ledger::hash::RecordFormat {
        if self.idv2 {
            ledger::hash::RecordFormat::V2
        } else {
            ledger::hash::RecordFormat::V1
        }
    }

    /// The encoding this node dials and gossips in.
    pub fn wire_codec(&self) -> p2p::protocol::WireCodec {
        if self.wire2 {
            p2p::protocol::WireCodec::V2
        } else {
            p2p::protocol::WireCodec::V1
        }
    }
}

/// Authentication settings (§3.8).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfig {
    /// Whether `X-Api-Key` is required on GraphQL endpoints. On by default
    /// (H-01): before, a loopback node served its mutations to anything that
    /// could reach the port — another program, another account on the
    /// machine, or a browser page past a hole in the request guard. Turning it
    /// off is allowed only on a node that is not public (`is_public`), and
    /// WARNs at every boot.
    #[serde(default = "default_auth_enabled")]
    pub enabled: bool,

    /// The API key value. Required on a public node (`is_public`); on any
    /// other, left empty, the key is read from `api_key_path` (generated there
    /// on the first boot).
    #[serde(default)]
    pub api_key: String,

    /// Where a loopback node keeps the API key it generated (H-01): a 0600
    /// file owned by the node's user, read like the node's secret key. Used
    /// only while `enabled` and no key is configured.
    #[serde(default = "default_api_key_path")]
    pub api_key_path: String,

    /// The nodes whose access records count (`docs/build-log/002-users-and-roles`):
    /// EndpointIds. Unset, every node the mesh admits may change who has
    /// access — as every such node may already write any record. Set, a grant
    /// or revocation written by any other node is ignored.
    #[serde(default)]
    pub admin_nodes: Option<Vec<String>>,
}

/// `auth.adminNodes` as the node ids access records carry: each entry parsed
/// as an `EndpointId` and written back in its canonical form.
fn admin_node_ids(
    nodes: Option<&[String]>,
) -> Result<Option<std::collections::HashSet<String>>, ConfigError> {
    let Some(nodes) = nodes else {
        return Ok(None);
    };
    nodes
        .iter()
        .map(|raw| {
            raw.parse::<iroh::EndpointId>()
                .map(|id| id.to_string())
                .map_err(|error| {
                    ConfigError::Validation(format!(
                        "auth.adminNodes entry \"{raw}\" is not an EndpointId: {error}"
                    ))
                })
        })
        .collect::<Result<_, _>>()
        .map(Some)
}

/// The settings that belong to one ledger rather than to the node
/// (`docs/build-log/003-multi-ledger-node`): its file, the watcher, signing,
/// Format, its mesh, and whose access records count. Today every node has one,
/// read from the config file ([`NodeConfig::ledger_config`]).
#[derive(Debug, Clone)]
pub struct LedgerConfig {
    pub ledger_path: String,
    pub watch_ledger_file: bool,
    pub signing: SigningConfig,
    pub format: FormatConfig,
    pub p2p: P2pConfig,
    /// `auth.adminNodes`.
    pub admin_nodes: Option<Vec<String>>,
}

impl LedgerConfig {
    /// Load and validate the ledger folder `folder` (003): its `ledger.json`,
    /// read like the config file (L-73: bounded, a regular file), and its
    /// files — `ledger.bean`, `iroh.secret` — always inside it.
    pub fn load_folder(folder: &Path) -> Result<LedgerConfig, ConfigError> {
        let path = folder.join(LEDGER_FILE);
        let (_file, content) = read_config_file(&path)?;
        reject_removed_config_keys(&content)?;
        let value: serde_json::Value =
            serde_json::from_str(&content).map_err(ConfigError::Parse)?;
        if value.pointer("/p2p/secretKeyPath").is_some() {
            return Err(ConfigError::Validation(format!(
                "{}: p2p.secretKeyPath is not set in a ledger folder; the ledger's key is always {}",
                path.display(),
                folder.join("iroh.secret").display()
            )));
        }
        let file: LedgerFile = serde_json::from_value(value).map_err(ConfigError::Parse)?;
        let mut p2p = file.p2p;
        p2p.secret_key_path = folder.join("iroh.secret").to_string_lossy().into_owned();
        let config = LedgerConfig {
            ledger_path: folder.join("ledger.bean").to_string_lossy().into_owned(),
            watch_ledger_file: file.watch_ledger_file,
            signing: file.signing,
            format: file.format,
            p2p,
            admin_nodes: file.auth.admin_nodes,
        };
        config
            .validate()
            .map_err(|error| ConfigError::Validation(format!("{}: {error}", path.display())))?;
        Ok(config)
    }

    /// Validate the ledger's own boot-time invariants (§3.11): the rules a node
    /// applies to its config file's ledger, and to every ledger folder
    /// (`docs/build-log/003-multi-ledger-node`).
    pub fn validate(&self) -> Result<(), ConfigError> {
        NodeConfig::validate_ledger_path(&self.ledger_path)?;

        if self.p2p.enabled && self.p2p.secret_key_path.is_empty() {
            return Err(ConfigError::Validation(
                "p2p.secretKeyPath is required when p2p.enabled is true".to_owned(),
            ));
        }

        if self.p2p.enabled {
            let allowlist =
                match p2p::allowlist::PeerAllowlist::parse(&self.p2p.bootstrap_endpoint_ids) {
                    Ok(allowlist) => allowlist,
                    Err(error) => return Err(ConfigError::Validation(error)),
                };
            // H-19: the join peer is trusted with this node's first history,
            // so it must be a peer this node accepts at all.
            if let Some(join_from) = &self.p2p.join_from {
                let peer = p2p::allowlist::PeerAllowlist::parse(std::slice::from_ref(join_from))
                    .map_err(|error| ConfigError::Validation(format!("p2p.joinFrom: {error}")))?
                    .bootstrap_peers();
                if !peer.first().is_some_and(|peer| allowlist.admits(*peer)) {
                    return Err(ConfigError::Validation(
                        "p2p.joinFrom must be one of p2p.bootstrapEndpointIds".to_owned(),
                    ));
                }
            }
            self.validate_peer_addresses(&allowlist)?;
            if self.p2p.swarm_topic == default_swarm_topic() {
                return Err(ConfigError::Validation(
                    "p2p.swarmTopic must not be the public default \"openledger/transactions\" when p2p.enabled is true".to_owned(),
                ));
            }
            // H3: with signing off, verify_remote_signature is a no-op and the only
            // origin check is that openledger-author appears *somewhere* on the
            // allowlist — never bound to the authenticated connection. A single
            // compromised allowlisted peer could then forge directives attributed to
            // any other peer. Require signing so remote directives carry a verifiable
            // Ed25519 signature from the claimed author's key.
            if !self.signing.enabled {
                return Err(ConfigError::Validation(
                    "signing.enabled must be true when p2p.enabled is true; unsigned remote directives allow author spoofing across the peer allowlist".to_owned(),
                ));
            }
        }

        // L-23 / M-31: the rules below are applied to whatever actually
        // *resolves* as the signature domain, not merely to the field the rules
        // were written for.
        //
        // L-23 shipped the four checks on `p2p.meshId` alone. `meshId` is
        // opt-in and no shipped config sets one, so on every real deployment
        // `P2pConfig::signature_domain` falls back to `p2p.swarmTopic` — which
        // had exactly one check, and that one is about *uniqueness* (it forbids
        // the public default topic), not well-formedness. The validated field
        // was the one nobody sets; the field every node signs with was
        // unvalidated. So both are checked here, and
        // `signature_domain_is_validated` below pins that the resolved value
        // went through this regardless of which field it came from.
        //
        // Both fields, always, rather than only the resolved one: the other is
        // one config edit away from *becoming* the resolved one (delete
        // `meshId` and the topic is the domain again), and a rule that only
        // holds for the current shape of the file is a rule that fails on the
        // day someone changes the file.
        //
        // Unconditional, not gated on `p2p.enabled`, for L-22's reason plus one
        // of its own: the domain is consumed whenever `signing.enabled`, with
        // or without p2p. A malformed value here is not a boot failure at the
        // point of use — it is a silent mesh-wide verification failure that
        // presents as "the other node's key is wrong".
        NodeConfig::validate_signature_domain(
            "p2p.swarmTopic",
            &self.p2p.swarm_topic,
            if self.p2p.mesh_id.is_some() {
                "it is the gossip join credential, hashed byte-for-byte into the TopicId every \
                 peer must agree on, and it becomes this node's signature domain again the \
                 moment p2p.meshId is removed"
            } else {
                "with p2p.meshId unset it IS this node's signature domain, compared \
                 byte-for-byte on both sides of every signature"
            },
        )?;
        if let Some(mesh_id) = &self.p2p.mesh_id {
            NodeConfig::validate_signature_domain(
                "p2p.meshId",
                mesh_id,
                "the value is compared byte-for-byte on both sides of every signature",
            )?;
        } else if self.signing.enabled {
            // L-23 (R-9's announced step): a signing node names its mesh. The
            // swarm topic is the gossip join credential; signing under it made
            // "can reach this mesh" and "is this mesh" one claim, so two meshes
            // that picked the same topic accepted each other's records. The
            // refusal leads with the one value that keeps an existing mesh's
            // signatures verifying, and never prints the topic (M-32, L-56).
            return Err(ConfigError::Validation(
                "p2p.meshId is required when signing.enabled is true. For an existing mesh, \
                 set it to your current p2p.swarmTopic, copied byte for byte on every node — \
                 any other value invalidates every signature already in the mesh; after that \
                 the topic can change without touching signatures. For a new mesh, use a \
                 random value such as the output of uuidgen (L-23, R-9)"
                    .to_owned(),
            ));
        }
        debug_assert!(
            NodeConfig::validate_signature_domain(
                self.p2p.signature_domain_source(),
                self.p2p.signature_domain(),
                "resolved domain",
            )
            .is_ok(),
            "the resolved signature domain must have been validated above (M-31)"
        );

        // L-22: validated unconditionally, not only when `p2p.enabled` — the
        // value is a boot-time typo either way, and catching it before the
        // operator flips `enabled` is the whole point of boot validation.
        if self.p2p.anti_entropy_interval_milliseconds < MIN_ANTI_ENTROPY_INTERVAL_MILLISECONDS {
            return Err(ConfigError::Validation(format!(
                "p2p.antiEntropyIntervalMilliseconds must be at least {MIN_ANTI_ENTROPY_INTERVAL_MILLISECONDS} ms, got {}; \
                 0 panics the replication task at runtime and sub-{MIN_ANTI_ENTROPY_INTERVAL_MILLISECONDS}ms cadences flood every allowlisted peer",
                self.p2p.anti_entropy_interval_milliseconds
            )));
        }

        // R-7: the anti-entropy session bounds, unconditionally for L-22's
        // reason — a typo is a typo whether or not `p2p.enabled` is set yet.
        self.validate_anti_entropy_bounds()?;

        // 002-users-and-roles: an `adminNodes` entry that does not parse would
        // be no node at all — every access record would then be ignored.
        if let Some(nodes) = &self.admin_nodes {
            if !self.signing.enabled {
                return Err(ConfigError::Validation(
                    "auth.adminNodes needs signing.enabled: without signatures a record's author is only what it says, and people's keys are not honoured".to_owned(),
                ));
            }
            if nodes.is_empty() {
                return Err(ConfigError::Validation(
                    "auth.adminNodes is empty: leave it out to let every mesh node change access, or list the nodes that may".to_owned(),
                ));
            }
            self.admin_node_ids()?;
        }

        match self.p2p.relay_mode.as_str() {
            "n0" | "disabled" | "custom" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "p2p.relayMode must be \"n0\", \"disabled\" or \"custom\", got \"{other}\""
                )));
            }
        }
        // 001-peer-discovery: a relay URL means the mesh's own relay, which only
        // "custom" uses — refused elsewhere rather than silently ignored — and
        // "custom" with neither a relay nor an address reaches no peer.
        if let Some(relay_url) = &self.p2p.relay_url {
            if self.p2p.relay_mode != "custom" {
                return Err(ConfigError::Validation(format!(
                    "p2p.relayUrl is set but p2p.relayMode is \"{}\"; a relay URL is used only with relayMode \"custom\"",
                    self.p2p.relay_mode
                )));
            }
            crate::peer_addresses::parse_relay_url(relay_url).map_err(ConfigError::Validation)?;
        }
        if self.p2p.relay_mode == "custom"
            && self.p2p.relay_url.is_none()
            && self.p2p.peer_addresses.is_empty()
        {
            return Err(ConfigError::Validation(
                "p2p.relayMode \"custom\" needs the mesh's own relay (p2p.relayUrl) or peers' addresses (p2p.peerAddresses), or both; with neither this node reaches no peer, and nothing goes to n0".to_owned(),
            ));
        }
        Ok(())
    }

    /// `p2p.peerAddresses` (`docs/build-log/001-peer-discovery`): every key is a
    /// peer `bootstrapEndpointIds` admits — an address says where an admitted
    /// peer is, it never admits one — and every value is 1 to
    /// [`crate::peer_addresses::MAX_ADDRESSES_PER_PEER`] `host:port` addresses.
    fn validate_peer_addresses(
        &self,
        allowlist: &p2p::allowlist::PeerAllowlist,
    ) -> Result<(), ConfigError> {
        let peers = crate::peer_addresses::PeerAddresses::from_config(&self.p2p.peer_addresses)
            .map_err(ConfigError::Validation)?;
        if let Some(stranger) = peers.peer_ids().find(|peer| !allowlist.admits(**peer)) {
            return Err(ConfigError::Validation(format!(
                "p2p.peerAddresses names {stranger}, which is not one of p2p.bootstrapEndpointIds — an address only says where an admitted peer is; add the peer to bootstrapEndpointIds first"
            )));
        }
        Ok(())
    }

    /// Refuse any anti-entropy session bound outside its floor and ceiling
    /// (R-7); see the `MIN_`/`MAX_ANTI_ENTROPY_*` constants for each pair.
    fn validate_anti_entropy_bounds(&self) -> Result<(), ConfigError> {
        let p2p = &self.p2p;
        let bounds: [(&str, u64, u64, u64, &str); 8] = [
            (
                "p2p.antiEntropySessionSeconds",
                p2p.anti_entropy_session_seconds,
                MIN_ANTI_ENTROPY_SESSION_SECONDS,
                MAX_ANTI_ENTROPY_SESSION_SECONDS,
                "below the floor an honest catch-up is cut off every tick; above the \
                 ceiling one peer may pin an inbound connection slot for that long",
            ),
            (
                "p2p.antiEntropyMaxAdvertPages",
                p2p.anti_entropy_max_advert_pages as u64,
                MIN_ANTI_ENTROPY_MAX_ADVERT_PAGES as u64,
                MAX_ANTI_ENTROPY_MAX_ADVERT_PAGES as u64,
                "below the floor an honest advert at the id-count cap cannot finish; \
                 above the ceiling a peer may stream pages for free",
            ),
            (
                "p2p.antiEntropyMaxAdvertIdBytes",
                p2p.anti_entropy_max_advert_id_bytes as u64,
                MIN_ANTI_ENTROPY_MAX_ADVERT_ID_BYTES as u64,
                MAX_ANTI_ENTROPY_MAX_ADVERT_ID_BYTES as u64,
                "below the floor an honest advert of a full ledger is refused; above \
                 the ceiling the id-count cap binds first and only memory grows",
            ),
            (
                "p2p.antiEntropyMaxSessionFrames",
                p2p.anti_entropy_max_session_frames as u64,
                MIN_ANTI_ENTROPY_MAX_SESSION_FRAMES as u64,
                MAX_ANTI_ENTROPY_MAX_SESSION_FRAMES as u64,
                "below the floor an honest full catch-up runs out of frames; above the \
                 ceiling one connection may do unbounded work",
            ),
            (
                "p2p.antiEntropyAcceptBurst",
                u64::from(p2p.anti_entropy_accept_burst),
                u64::from(MIN_ANTI_ENTROPY_ACCEPT_BURST),
                u64::from(MAX_ANTI_ENTROPY_ACCEPT_BURST),
                "below the floor a pooled connection's re-dial is refused; above the \
                 ceiling the burst exceeds every inbound slot and bounds nothing",
            ),
            (
                "p2p.antiEntropyAcceptRefillMilliseconds",
                p2p.anti_entropy_accept_refill_milliseconds,
                MIN_ANTI_ENTROPY_ACCEPT_REFILL_MILLISECONDS,
                MAX_ANTI_ENTROPY_ACCEPT_REFILL_MILLISECONDS,
                "below the floor a reconnect loop is admitted at a rate no honest peer \
                 needs; above the ceiling an honest peer's re-dials are rationed",
            ),
            (
                "p2p.antiEntropyMaxConcurrentExchanges",
                p2p.anti_entropy_max_concurrent_exchanges as u64,
                MIN_ANTI_ENTROPY_MAX_CONCURRENT_EXCHANGES as u64,
                MAX_ANTI_ENTROPY_MAX_CONCURRENT_EXCHANGES as u64,
                "0 stops outbound replication; above the ceiling hostile peers may each \
                 hold an exchange's worst-case memory at once",
            ),
            (
                "p2p.antiEntropySupplyBackoffSeconds",
                p2p.anti_entropy_supply_backoff_seconds,
                MIN_ANTI_ENTROPY_SUPPLY_BACKOFF_SECONDS,
                MAX_ANTI_ENTROPY_SUPPLY_BACKOFF_SECONDS,
                "below the floor a node at its size cap re-pulls the same batch every \
                 tick; above the ceiling it sits out a peer long after room was made",
            ),
        ];
        for (field, value, min, max, why) in bounds {
            if !(min..=max).contains(&value) {
                return Err(ConfigError::Validation(format!(
                    "{field} must be between {min} and {max}, got {value}; {why}"
                )));
            }
        }
        Ok(())
    }

    /// `auth.adminNodes` as the node ids access records carry in
    /// `openledger-author` (one canonical spelling, whatever form the config
    /// used), or `None` when unset.
    pub fn admin_node_ids(&self) -> Result<Option<std::collections::HashSet<String>>, ConfigError> {
        admin_node_ids(self.admin_nodes.as_deref())
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: default_auth_enabled(),
            api_key: String::new(),
            api_key_path: default_api_key_path(),
            admin_nodes: None,
        }
    }
}

fn default_auth_enabled() -> bool {
    true
}

fn default_api_key_path() -> String {
    "./data/api.key".to_owned()
}

/// Hand-written so the API key is never printed (T41) — see
/// [`crate::auth::AuthState`]'s impl for why. `NodeConfig` derives `Debug` and
/// this type is a field of it, so the derived impl here put the key into any
/// `{:?}` of the whole config.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthConfig")
            .field("enabled", &self.enabled)
            .field("api_key", &crate::auth::redact(&self.api_key))
            .field("api_key_path", &self.api_key_path)
            .field("admin_nodes", &self.admin_nodes)
            .finish()
    }
}

/// Signing settings (§3.8.1).
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct SigningConfig {
    /// Whether Ed25519 signing is enabled.
    #[serde(default)]
    #[allow(dead_code)] // Read when signing is wired (Phase 2).
    pub enabled: bool,

    /// Write even while every signature this node checked failed (L-114).
    /// Off by default: that verdict means the signature domain (`p2p.meshId`)
    /// or the node key is wrong, and a record written then is signed under the
    /// wrong domain — and at the next boot it verifies and hides the verdict.
    #[serde(default)]
    pub allow_writes_when_every_signature_fails: bool,
}

/// Peer-to-peer replication settings (§3.4, §3.9).
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct P2pConfig {
    /// Whether the Iroh mesh is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Path to the persisted Iroh `SecretKey`.
    #[serde(default = "default_secret_key_path")]
    pub secret_key_path: String,

    /// Bootstrap peer `EndpointId`s.
    #[serde(default)]
    pub bootstrap_endpoint_ids: Vec<String>,

    /// The peer this node joins from (H-19): one of
    /// [`bootstrap_endpoint_ids`](Self::bootstrap_endpoint_ids). While the
    /// ledger holds none of this node's own records, the history this peer
    /// serves is adopted past the adoption ratchet until the node holds all of
    /// it — the trusted-bootstrap join taken over the wire instead of by
    /// copying the peer's `.bean`. Every other check still applies.
    #[serde(default)]
    pub join_from: Option<String>,

    /// iroh-gossip announce cadence in milliseconds.
    #[serde(default = "default_gossip_interval")]
    #[allow(dead_code)] // Available for gossip pacing.
    pub gossip_interval_milliseconds: u64,

    /// ALPN head-exchange cadence in milliseconds.
    #[serde(default = "default_anti_entropy_interval")]
    pub anti_entropy_interval_milliseconds: u64,

    /// TopicId preimage string (§3.4.3), and — while
    /// [`mesh_id`](Self::mesh_id) is unset — the signature domain too (M-31).
    ///
    /// Two jobs, both byte-exact. As a preimage it is SHA-256'd into the
    /// `TopicId` every peer must derive identically to meet on the overlay; as
    /// the fallback domain it is interpolated into every signed message. It is
    /// therefore held to the same rules as `mesh_id`
    /// ([`NodeConfig::validate_signature_domain`]) rather than the single
    /// uniqueness check it used to get: a trailing space here is not a cosmetic
    /// difference, it is a different mesh.
    #[serde(default = "default_swarm_topic")]
    pub swarm_topic: String,

    /// This mesh's identity, bound into every signature (L-23).
    ///
    /// Required when `signing.enabled` (L-23). A node with signing off may
    /// leave it out, and its domain then falls back to
    /// [`swarm_topic`](Self::swarm_topic), unused. The value is compared byte
    /// for byte: a signature is verified by *reconstructing* the signed message
    /// with the verifier's own domain, so changing the domain a deployment
    /// resolves to invalidates every signature it has already persisted and
    /// every signature its peers hold. A mesh that signed before `meshId`
    /// existed signed under its swarm topic, and keeps its history by setting
    /// `meshId` to that topic verbatim on every node — the remedy the boot
    /// refusal names.
    ///
    /// Why it exists: the swarm topic is also the gossip *join credential* —
    /// anyone holding the string plus one member id can join the overlay — and
    /// using one value for both meant "can reach this mesh" and "is this mesh"
    /// were the same claim. Two meshes that happened to pick the same custom
    /// topic string accepted each other's signed directives. A random UUID here
    /// separates identity from reachability.
    #[serde(default)]
    pub mesh_id: Option<String>,

    /// Iroh relay/discovery profile: `"n0"` (n0's public relays and
    /// discovery), `"disabled"` (direct addresses only) or `"custom"` (the
    /// mesh's own relay, [`relay_url`](Self::relay_url), plus direct
    /// addresses — nothing goes to n0; `docs/build-log/001-peer-discovery`).
    #[serde(default = "default_relay_mode")]
    pub relay_mode: String,

    /// The mesh's own relay, for `relayMode: "custom"`: an `https` URL of an
    /// `iroh-relay` server, the same on every node of the mesh. One relay per
    /// mesh: every node registers there, and that is where its peers look.
    #[serde(default)]
    pub relay_url: Option<String>,

    /// Where allowlisted peers can be reached directly:
    /// `{ "<EndpointId>": ["host:port", …] }` (`docs/build-log/001-peer-discovery`).
    /// Each key must be one of [`bootstrap_endpoint_ids`](Self::bootstrap_endpoint_ids):
    /// an address is a hint for reaching a peer this node admits, never a reason
    /// to admit one. Resolved at boot and every few minutes after
    /// ([`crate::peer_addresses`]).
    #[serde(default)]
    pub peer_addresses: std::collections::BTreeMap<String, Vec<String>>,

    /// The UDP port this node's P2P endpoint listens on, so peers can list it
    /// in their `peerAddresses` (`docs/build-log/001-peer-discovery`). `0`, the
    /// default, lets the system pick a free port at every boot — fine when
    /// peers find this node through n0 or reach it only by dialling out, wrong
    /// when they are told its address.
    #[serde(default)]
    pub listen_port: u16,

    // — Anti-entropy session bounds (R-7) —
    //
    // The T49/T58/T70 bounds had no config surface; these give them one. Every
    // default is read off `AntiEntropyTimeouts::default()` /
    // `AntiEntropyLimits::default()` rather than restated, so an absent key is
    // provably today's behaviour, and every key is bounded from BOTH sides at
    // boot (see the `MIN_`/`MAX_ANTI_ENTROPY_*` constants): too small cuts off
    // honest catch-up, too large is the protection switched off.
    /// Wall-clock cap on one anti-entropy session, inbound and outbound
    /// (H-10, M-28, M-40), in seconds.
    #[serde(default = "default_anti_entropy_session_seconds")]
    pub anti_entropy_session_seconds: u64,

    /// Pages one peer's `HaveHeads` advert may span (H-10, M-26).
    #[serde(default = "default_anti_entropy_max_advert_pages")]
    pub anti_entropy_max_advert_pages: usize,

    /// Distinct advertised id bytes one exchange may retain (M-26).
    #[serde(default = "default_anti_entropy_max_advert_id_bytes")]
    pub anti_entropy_max_advert_id_bytes: usize,

    /// Frames one anti-entropy session may cost, on either side (T24, L-01,
    /// M-28). One key for both, so the client's budget keeps mirroring the
    /// server's by construction.
    #[serde(default = "default_anti_entropy_max_session_frames")]
    pub anti_entropy_max_session_frames: usize,

    /// New inbound anti-entropy connections one peer may open back to back
    /// (M-40): its accept bucket's capacity.
    #[serde(default = "default_anti_entropy_accept_burst")]
    pub anti_entropy_accept_burst: u32,

    /// One accept token back per this many milliseconds (M-40).
    #[serde(default = "default_anti_entropy_accept_refill_milliseconds")]
    pub anti_entropy_accept_refill_milliseconds: u64,

    /// Outbound anti-entropy exchanges this node runs at once, across all
    /// peers (R-5, T69; config surface T71). Past it, peers queue FIFO for the
    /// next free slot.
    #[serde(default = "default_anti_entropy_max_concurrent_exchanges")]
    pub anti_entropy_max_concurrent_exchanges: usize,

    /// Seconds a peer's `Supply` stays deferred after one of its batches did
    /// not fit under the ledger's size cap (M-39, T69; config surface T71).
    #[serde(default = "default_anti_entropy_supply_backoff_seconds")]
    pub anti_entropy_supply_backoff_seconds: u64,
}

/// Hand-written so the two quasi-credentials this struct carries are not
/// printed in the clear (T41).
///
/// `swarmTopic` is the gossip **join credential**: anyone holding the string
/// plus one member id can join the overlay (L-23's premise). `meshId` is the
/// signature domain, and when it is unset the domain *is* the swarm topic — so
/// both are values a log reader should not be handed. T39 already made the boot
/// log print source + length + a 4-character prefix rather than the value; this
/// makes `{:?}` agree with that choice instead of quietly undoing it.
///
/// Everything else is ordinary operational config and stays visible.
impl std::fmt::Debug for P2pConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("P2pConfig")
            .field("enabled", &self.enabled)
            .field("secret_key_path", &self.secret_key_path)
            .field("bootstrap_endpoint_ids", &self.bootstrap_endpoint_ids)
            .field(
                "gossip_interval_milliseconds",
                &self.gossip_interval_milliseconds,
            )
            .field(
                "anti_entropy_interval_milliseconds",
                &self.anti_entropy_interval_milliseconds,
            )
            .field("swarm_topic", &crate::auth::redact(&self.swarm_topic))
            .field("mesh_id", &self.mesh_id.as_deref().map(crate::auth::redact))
            .field("relay_mode", &self.relay_mode)
            .field("relay_url", &self.relay_url)
            .field("peer_addresses", &self.peer_addresses)
            .field("listen_port", &self.listen_port)
            .field(
                "anti_entropy_session_seconds",
                &self.anti_entropy_session_seconds,
            )
            .field(
                "anti_entropy_max_advert_pages",
                &self.anti_entropy_max_advert_pages,
            )
            .field(
                "anti_entropy_max_advert_id_bytes",
                &self.anti_entropy_max_advert_id_bytes,
            )
            .field(
                "anti_entropy_max_session_frames",
                &self.anti_entropy_max_session_frames,
            )
            .field("anti_entropy_accept_burst", &self.anti_entropy_accept_burst)
            .field(
                "anti_entropy_accept_refill_milliseconds",
                &self.anti_entropy_accept_refill_milliseconds,
            )
            .field(
                "anti_entropy_max_concurrent_exchanges",
                &self.anti_entropy_max_concurrent_exchanges,
            )
            .field(
                "anti_entropy_supply_backoff_seconds",
                &self.anti_entropy_supply_backoff_seconds,
            )
            .finish()
    }
}

impl P2pConfig {
    /// Log which field the signature domain resolved from (L-23).
    ///
    /// Until `meshId` was required, a signing node without one WARNed here with
    /// the remedy R-9 chose; that remedy is now the boot refusal in
    /// [`Self::validate`], so a node that reaches this line and signs has a
    /// `meshId`. Only a node with signing off can still resolve to the swarm
    /// topic, and it has no signatures the domain could invalidate.
    ///
    /// Never prints the domain: on the fallback path it *is* the gossip join
    /// credential (M-32, L-56), so only its source, length and a four-character
    /// prefix appear — the shape `main` always logged.
    pub fn log_signature_domain(&self) {
        let domain = self.signature_domain();
        let source = self.signature_domain_source();
        let length = domain.len();
        let prefix: String = domain.chars().take(4).collect();
        info!(
            source,
            length,
            prefix = %prefix,
            "mesh signature domain resolved"
        );
    }

    /// The domain every signature on this node is bound to (L-23).
    ///
    /// The **single** resolution point: `ledger_runtime::start` calls this once
    /// at boot and
    /// hands the result to the signer and to the ALPN verification path, so no
    /// other site reads `swarm_topic` for signature purposes and the two cannot
    /// disagree.
    ///
    /// Whichever arm it takes, the value returned has passed
    /// [`NodeConfig::validate_signature_domain`] (M-31) — the fallback arm is
    /// the default path in every shipped config, so validating only `mesh_id`
    /// validated nothing that actually shipped.
    pub fn signature_domain(&self) -> &str {
        match self.mesh_id.as_deref() {
            Some(mesh_id) => mesh_id,
            // Pre-L-23 behaviour, preserved on purpose: see `mesh_id`.
            None => &self.swarm_topic,
        }
    }

    /// The outbound session bounds these keys configure (R-7), over
    /// [`AntiEntropyTimeouts::default`] for everything without a key.
    ///
    /// With none of the keys set this is exactly `AntiEntropyTimeouts::default()`.
    /// `main.rs` builds the handler from this (T70 wiring).
    pub fn anti_entropy_timeouts(&self) -> AntiEntropyTimeouts {
        AntiEntropyTimeouts {
            session: Duration::from_secs(self.anti_entropy_session_seconds),
            max_advert_pages: self.anti_entropy_max_advert_pages,
            max_advert_id_bytes: self.anti_entropy_max_advert_id_bytes,
            max_session_frames: self.anti_entropy_max_session_frames,
            supply_backoff: Duration::from_secs(self.anti_entropy_supply_backoff_seconds),
            ..AntiEntropyTimeouts::default()
        }
    }

    /// The inbound limits these keys configure (R-7), over
    /// [`AntiEntropyLimits::default`] for everything without a key.
    ///
    /// `antiEntropyMaxSessionFrames` lands in BOTH this and
    /// [`Self::anti_entropy_timeouts`] — the server's per-connection request
    /// budget and the client's per-session frame budget are one limit (M-28).
    pub fn anti_entropy_limits(&self) -> AntiEntropyLimits {
        AntiEntropyLimits {
            max_requests_per_connection: self.anti_entropy_max_session_frames,
            accept_burst: self.anti_entropy_accept_burst,
            accept_refill_interval: Duration::from_millis(
                self.anti_entropy_accept_refill_milliseconds,
            ),
            max_concurrent_outbound_exchanges: self.anti_entropy_max_concurrent_exchanges,
            ..AntiEntropyLimits::default()
        }
    }

    /// Which config field [`Self::signature_domain`] came from, for the boot log.
    pub fn signature_domain_source(&self) -> &'static str {
        match self.mesh_id {
            Some(_) => "p2p.meshId",
            None => "p2p.swarmTopic (meshId unset)",
        }
    }
}

/// TLS settings. In-process TLS is not implemented; production public bind
/// requires a host terminator (`mode = "terminated"`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct TlsConfig {
    /// `"disabled"` (loopback only) or `"terminated"` (TLS at the host/proxy,
    /// which makes the node public whatever its bind: `NodeConfig::is_public`).
    #[serde(default = "default_tls_mode")]
    pub mode: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: default_tls_mode(),
        }
    }
}

/// CORS settings. Empty allowlist means no `Access-Control-Allow-Origin` (same-origin only).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct CorsConfig {
    /// Explicit origins such as `"http://localhost:3000"`. `"*"` is rejected.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            secret_key_path: default_secret_key_path(),
            bootstrap_endpoint_ids: Vec::new(),
            join_from: None,
            gossip_interval_milliseconds: default_gossip_interval(),
            anti_entropy_interval_milliseconds: default_anti_entropy_interval(),
            swarm_topic: default_swarm_topic(),
            mesh_id: None,
            relay_mode: default_relay_mode(),
            relay_url: None,
            peer_addresses: std::collections::BTreeMap::new(),
            listen_port: 0,
            anti_entropy_session_seconds: default_anti_entropy_session_seconds(),
            anti_entropy_max_advert_pages: default_anti_entropy_max_advert_pages(),
            anti_entropy_max_advert_id_bytes: default_anti_entropy_max_advert_id_bytes(),
            anti_entropy_max_session_frames: default_anti_entropy_max_session_frames(),
            anti_entropy_accept_burst: default_anti_entropy_accept_burst(),
            anti_entropy_accept_refill_milliseconds:
                default_anti_entropy_accept_refill_milliseconds(),
            anti_entropy_max_concurrent_exchanges: default_anti_entropy_max_concurrent_exchanges(),
            anti_entropy_supply_backoff_seconds: default_anti_entropy_supply_backoff_seconds(),
        }
    }
}

// — Default value functions —

fn default_bind_address() -> String {
    "127.0.0.1".to_owned()
}

fn default_port() -> u16 {
    4000
}

fn default_ledgers_dir() -> String {
    "./data/ledgers".to_owned()
}

fn default_max_ledgers() -> usize {
    MAX_LEDGERS
}

/// The most ledgers one node serves (003, decision 4: up to about 100 — the
/// scale the design is measured at).
pub const MAX_LEDGERS: usize = 100;

/// The name of the config file's own ledger, served at `/graphql` as before.
pub const DEFAULT_LEDGER: &str = "default";

/// Where the public-node rules apply, as their refusals say it
/// ([`NodeConfig::is_public`]).
const ON_A_PUBLIC_NODE: &str =
    "on a public node (a non-loopback bind, or behind a proxy: tls.mode \"terminated\" or trustedProxies set)";

/// A ledger name (003): 1 to 40 of `a-z`, `0-9` and `-`, not starting with
/// `-`. It is a folder name and a URL segment, so nothing else is accepted.
pub fn is_valid_ledger_name(name: &str) -> bool {
    (1..=40).contains(&name.len())
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// A ledger folder's `ledger.json` (003): the [`LedgerConfig`] fields a folder
/// may set. Its file, key and lock are always in the folder, so `ledgerPath`
/// is unknown here and `p2p.secretKeyPath` is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct LedgerFile {
    #[serde(default)]
    watch_ledger_file: bool,
    #[serde(default)]
    signing: SigningConfig,
    #[serde(default)]
    format: FormatConfig,
    #[serde(default)]
    p2p: P2pConfig,
    #[serde(default)]
    auth: LedgerAuthFile,
}

/// The `auth` section of a `ledger.json`: whose access records count.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct LedgerAuthFile {
    #[serde(default)]
    admin_nodes: Option<Vec<String>>,
}

/// The file name of a ledger folder's settings.
pub const LEDGER_FILE: &str = "ledger.json";

/// A ledger folder: its name, and its path or why it is not a ledger.
pub type LedgerFolder = (String, Result<PathBuf, String>);

/// The ledger folders under `ledgers_dir`, by name, sorted: each a valid
/// name, or the reason it is not served. Entries starting with `.` (such as
/// `.removed`) and files (a stray note or backup) are not ledgers and are
/// skipped; a missing directory holds none.
pub fn ledger_folders(ledgers_dir: &Path) -> Result<Vec<LedgerFolder>, ConfigError> {
    let entries = match std::fs::read_dir(ledgers_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(ConfigError::FileRead(error)),
    };
    let mut folders = Vec::new();
    for entry in entries {
        let entry = entry.map_err(ConfigError::FileRead)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let verdict = if name == DEFAULT_LEDGER {
            Err(
                "\"default\" is the config file's own ledger; a folder may not take its name"
                    .to_owned(),
            )
        } else if !is_valid_ledger_name(&name) {
            Err("a ledger name is 1 to 40 of a-z, 0-9 and -, not starting with -".to_owned())
        } else {
            Ok(path)
        };
        folders.push((name, verdict));
    }
    folders.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(folders)
}

/// The ledgers in `ledgers` (in order, the config file's first) that cannot be
/// served beside the ones before them, each with its reason (003): two ledgers
/// in one mesh (the same signature domain), on one gossip topic, or on one
/// P2P port; and any past `max_ledgers`.
pub fn ledgers_in_conflict(
    ledgers: &[(&str, &LedgerConfig)],
    max_ledgers: usize,
) -> Vec<(String, String)> {
    let mut refused = Vec::new();
    let mut domains = std::collections::HashMap::new();
    let mut topics = std::collections::HashMap::new();
    let mut ports = std::collections::HashMap::new();
    let mut served = 0usize;
    for (name, config) in ledgers {
        let conflict = if config.signing.enabled
            && domains.contains_key(config.p2p.signature_domain())
        {
            Some(format!(
                "ledger \"{}\" is already in this mesh (the same p2p.meshId); one node serves a mesh once",
                domains[config.p2p.signature_domain()]
            ))
        } else if config.p2p.enabled && topics.contains_key(config.p2p.swarm_topic.as_str()) {
            Some(format!(
                "ledger \"{}\" already uses this p2p.swarmTopic",
                topics[config.p2p.swarm_topic.as_str()]
            ))
        } else if config.p2p.enabled
            && config.p2p.listen_port != 0
            && ports.contains_key(&config.p2p.listen_port)
        {
            Some(format!(
                "ledger \"{}\" already listens on p2p.listenPort {}",
                ports[&config.p2p.listen_port], config.p2p.listen_port
            ))
        } else if served >= max_ledgers {
            Some(format!(
                "this node serves at most maxLedgers ({max_ledgers}) ledgers"
            ))
        } else {
            None
        };
        match conflict {
            Some(reason) => refused.push(((*name).to_owned(), reason)),
            None => {
                served += 1;
                if config.signing.enabled {
                    domains.insert(config.p2p.signature_domain(), *name);
                }
                if config.p2p.enabled {
                    topics.insert(config.p2p.swarm_topic.as_str(), *name);
                    if config.p2p.listen_port != 0 {
                        ports.insert(config.p2p.listen_port, *name);
                    }
                }
            }
        }
    }
    refused
}

fn default_graphiql() -> bool {
    false
}

fn default_secret_key_path() -> String {
    "./data/iroh.secret".to_owned()
}

fn default_gossip_interval() -> u64 {
    5000
}

fn default_anti_entropy_interval() -> u64 {
    5000
}

/// Lower bound on `p2p.antiEntropyIntervalMilliseconds` (L-22).
///
/// `tokio::time::interval` panics outright on a zero period, and that panic
/// happens inside the spawned replication task — so a `0` in the config file
/// killed replication silently at runtime while the node otherwise looked
/// healthy. Anything in the low tens of milliseconds is a self-inflicted flood
/// of the whole peer allowlist besides, so the floor is set where a cadence
/// stops being plausible rather than at 1.
const MIN_ANTI_ENTROPY_INTERVAL_MILLISECONDS: u64 = 100;

// — Anti-entropy session bounds (R-7) —
//
// Defaults read off the serve/exchange layer's own `Default`s, for the reason
// the `http` defaults are: one set of numbers, so the config layer cannot drift
// from the code it configures by being edited on its own.

fn default_anti_entropy_session_seconds() -> u64 {
    AntiEntropyTimeouts::default().session.as_secs()
}

fn default_anti_entropy_max_advert_pages() -> usize {
    AntiEntropyTimeouts::default().max_advert_pages
}

fn default_anti_entropy_max_advert_id_bytes() -> usize {
    AntiEntropyTimeouts::default().max_advert_id_bytes
}

fn default_anti_entropy_max_session_frames() -> usize {
    AntiEntropyTimeouts::default().max_session_frames
}

fn default_anti_entropy_accept_burst() -> u32 {
    AntiEntropyLimits::default().accept_burst
}

fn default_anti_entropy_accept_refill_milliseconds() -> u64 {
    u64::try_from(
        AntiEntropyLimits::default()
            .accept_refill_interval
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn default_anti_entropy_max_concurrent_exchanges() -> usize {
    AntiEntropyLimits::default().max_concurrent_outbound_exchanges
}

fn default_anti_entropy_supply_backoff_seconds() -> u64 {
    AntiEntropyTimeouts::default().supply_backoff.as_secs()
}

/// Bounds on `p2p.antiEntropySessionSeconds` (M-40, R-7).
///
/// Floor: the per-frame `io` (30 s). A session shorter than one frame's own
/// timeout is not a session bound, it is a second, tighter frame timeout — and
/// it would cut an honest full catch-up (tens of seconds of transfer at the
/// file-size cap) on every tick. Ceiling: one hour. The deadline is what stops
/// one peer pinning an inbound slot indefinitely (M-40); at an hour, eight
/// colluding peers still pin every slot for an hour per connection, and past
/// that the bound stops meaning anything.
const MIN_ANTI_ENTROPY_SESSION_SECONDS: u64 = 30;
const MAX_ANTI_ENTROPY_SESSION_SECONDS: u64 = 3_600;

/// Bounds on `p2p.antiEntropyMaxAdvertPages` (M-26, R-7).
///
/// Floor: 256 — exactly the full pages (4,096 ids each) the advert count cap
/// (2^20 ids) takes, so no lower value lets an honest peer at that cap finish
/// its advert. The default (512) is twice that for a sender that pages less
/// tightly than ours. Ceiling: 1,024, four times the floor; every page is a
/// frame the peer sends for free, so past that the cap is a flood allowance.
const MIN_ANTI_ENTROPY_MAX_ADVERT_PAGES: usize = 256;
const MAX_ANTI_ENTROPY_MAX_ADVERT_PAGES: usize = 1_024;

/// Bounds on `p2p.antiEntropyMaxAdvertIdBytes` (M-26, R-7).
///
/// Floor: 16 MiB. A ledger at the file-size cap holds a few hundred thousand
/// directives, ~15 MiB of 64-hex id text; below this an honest full advert is
/// refused. Ceiling: the default, 64 MiB — the form rule admits only 64-byte
/// ids, so 2^20 of them (the count cap) is exactly 64 MiB and a larger value
/// buys nothing but a bigger R-5 worst case per exchange. Lowering it is the
/// supported direction: it trades catch-up headroom for resident memory.
const MIN_ANTI_ENTROPY_MAX_ADVERT_ID_BYTES: usize = 16 * 1024 * 1024;
const MAX_ANTI_ENTROPY_MAX_ADVERT_ID_BYTES: usize = 64 * 1024 * 1024;

/// Bounds on `p2p.antiEntropyMaxSessionFrames` (T24, L-01, M-28, R-7).
///
/// Floor: 10,000. An honest full catch-up at the accumulation cap spends
/// ~8,700 frames (256 advert pages each way, then one `Want` and one `Supply`
/// per 256-id chunk). Ceiling: 1,000,000 — ten times the default. The session
/// deadline is now the primary bound on a long session (M-40); this one stops a
/// fast peer from doing unbounded work inside it, and a million frames of
/// full-advert replies is already far past anything that bounds.
const MIN_ANTI_ENTROPY_MAX_SESSION_FRAMES: usize = 10_000;
const MAX_ANTI_ENTROPY_MAX_SESSION_FRAMES: usize = 1_000_000;

/// Bounds on `p2p.antiEntropyAcceptBurst` (M-40, R-7).
///
/// Floor: 2 — a stale pooled connection's one re-dial plus the dial behind it,
/// the smallest honest burst (T42). Ceiling: 256, the default global connection
/// cap; a burst larger than every slot on the node bounds nothing.
const MIN_ANTI_ENTROPY_ACCEPT_BURST: u32 = 2;
const MAX_ANTI_ENTROPY_ACCEPT_BURST: u32 = 256;

/// Bounds on `p2p.antiEntropyAcceptRefillMilliseconds` (M-40, R-7).
///
/// Floor: 100 ms, i.e. 10 new connections a second per peer, the same floor as
/// the anti-entropy interval — below it the bucket admits a reconnect loop at
/// a rate no honest peer approaches. Ceiling: 30 s, the per-frame `io`: an
/// honest peer's steady redial rate is at most one per server idle close, which
/// happens once per `io`, so a slower refill would ration honest traffic.
const MIN_ANTI_ENTROPY_ACCEPT_REFILL_MILLISECONDS: u64 = 100;
const MAX_ANTI_ENTROPY_ACCEPT_REFILL_MILLISECONDS: u64 = 30_000;

/// Bounds on `p2p.antiEntropyMaxConcurrentExchanges` (R-5, T69 → T71).
///
/// Floor: 1 — one exchange at a time still converges (anti-entropy needs only
/// one honest exchange to run; the rest queue FIFO), and `0` would stop
/// outbound replication altogether. Ceiling: 64. Each exchange against a
/// hostile peer can hold ≈ 130–150 MiB resident at worst, so 64 is ≈ 8–10 GiB —
/// already past what the bound exists to prevent; beyond it the allowlist size
/// is the only limit again, which is the pre-R-5 state.
const MIN_ANTI_ENTROPY_MAX_CONCURRENT_EXCHANGES: usize = 1;
const MAX_ANTI_ENTROPY_MAX_CONCURRENT_EXCHANGES: usize = 64;

/// Bounds on `p2p.antiEntropySupplyBackoffSeconds` (M-39, T69 → T71).
///
/// Floor: 5 s. The backoff exists so a node at its size cap stops re-pulling,
/// re-validating and re-deferring the same batch on every tick; at the
/// anti-entropy interval's default of 5 s, anything shorter lifts before the
/// next tick and is no backoff at all. Ceiling: one hour, the session ceiling's
/// reasoning in the other direction — a node an operator has already made room
/// on should not sit out replication from a peer for longer than that.
const MIN_ANTI_ENTROPY_SUPPLY_BACKOFF_SECONDS: u64 = 5;
const MAX_ANTI_ENTROPY_SUPPLY_BACKOFF_SECONDS: u64 = 3_600;

fn default_swarm_topic() -> String {
    "openledger/transactions".to_owned()
}

/// Upper bound in bytes on **either** field that can resolve as the signature
/// domain — `p2p.meshId` and `p2p.swarmTopic` (L-23, M-31).
///
/// The value is a domain separator hashed into every signature, not a payload,
/// so the only thing length buys past an identifier is room to hide things in.
/// A UUID is 36 characters; 128 leaves space for a prefixed or namespaced one.
///
/// Applied to the topic too as of M-31: `meshId` is opt-in, so on every shipped
/// config the *topic* is the domain, and a bound that only guards the field
/// nobody sets is not a bound.
const MAX_SIGNATURE_DOMAIN_BYTES: usize = 128;

/// Characters `p2p.meshId` and `p2p.swarmTopic` may contain (L-23, M-31).
///
/// ASCII alphanumerics plus the separators identifiers are actually spelled
/// with. Deliberately excludes whitespace and control characters: the value is
/// compared byte-for-byte on both sides of a signature, so a stray character
/// that survives a copy-paste is a mesh-wide verification failure that looks
/// like a key problem.
///
/// **This charset is what keeps the v3 signature message injective (L-06), and
/// it is a prerequisite for T45 Facet B.** The signed string is
/// `openledger-sig-v3|{kind}|{content_id}|parents|{parents}|lamport|{lamport}|mesh|{mesh_id}`
/// ([`security::signing::build_sign_message`]), and it is unambiguous *only*
/// because every interpolated field is independently constrained so that none
/// of them can spell the `|` separator: `parents` is 64-lowercase-hex CSV and
/// `lamport` is a decimal `u64` (both pinned by M-01), and `content_id` is
/// computed locally rather than carried. Until M-31 the domain was the one
/// field with no constraint at all whenever `meshId` was unset — which is every
/// real deployment — so a topic containing `|` could shift the field boundaries
/// and make two different logical messages share one signed string. Excluding
/// `|` here is what makes the injectivity premise in
/// `docs/FORMAT_V2_DESIGN.md` §0.2 true of the running code rather than only of
/// the opt-in path; T45 Facet B builds on that premise and must not be started
/// before this rule is in force.
fn is_signature_domain_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':' | '/')
}

// — HTTP hardening defaults and bounds (M-13 / T22) —
//
// The defaults are read off `HttpServerSettings::default()` rather than
// restated here. That is the whole reason an absent `http` section is
// *provably* today's behaviour: there is one set of numbers, and the config
// layer cannot drift from the serve layer by being edited on its own.

fn default_header_read_timeout_seconds() -> u64 {
    HttpServerSettings::default().header_read_timeout.as_secs()
}

fn default_request_timeout_seconds() -> u64 {
    HttpServerSettings::default().request_timeout.as_secs()
}

fn default_max_connections() -> usize {
    HttpServerSettings::default().max_connections
}

pub(crate) fn default_max_requests_per_ledger() -> usize {
    64
}

fn default_max_connections_per_ip() -> usize {
    HttpServerSettings::default().max_connections_per_ip
}

/// Floor on both `http` timeouts, in seconds (M-13, L-22 style).
///
/// `0` is the value that matters: a zero header-read timeout fires before any
/// client can finish a head (the node answers nothing at all), and a zero
/// request timeout turns every request into a `408`. Both read as "turn the
/// timeout off" to someone writing the config, and neither does that — they
/// disable the *server*. One second is the smallest value that is still a
/// timeout rather than a denial of service against yourself.
const MIN_HTTP_TIMEOUT_SECONDS: u64 = 1;

/// Ceiling on both `http` timeouts, in seconds (M-13).
///
/// A floor alone does not keep the protection: `"headerReadTimeoutSeconds":
/// 86400` re-opens slowloris exactly as effectively as `0` would have, and it
/// looks far more innocent in a diff. Five minutes is well past any legitimate
/// GraphQL request against this node (the body limit is 2 MiB and the query
/// complexity is capped), so a larger value is not a tuning choice — it is the
/// control being switched off.
const MAX_HTTP_TIMEOUT_SECONDS: u64 = 300;

/// Floor on `http.maxConnections` (M-13).
///
/// The cap is applied by a permit-then-accept semaphore, so it is also the
/// node's own concurrency: set it to `1` and a single held keep-alive
/// connection stalls every other client, which is a self-inflicted outage
/// wearing the costume of a hardening setting. Eight is enough for the health
/// probe, a proxy's connection pool and a human with a browser open.
const MIN_MAX_CONNECTIONS: usize = 8;

/// Ceiling on `http.maxConnections` (M-13).
///
/// Same reasoning as the timeout ceiling: `usize::MAX` is not a cap. 65,536
/// concurrent connections already exceeds the file-descriptor limit of any
/// default-configured host, so anything beyond it is a number chosen to mean
/// "unlimited".
const MAX_MAX_CONNECTIONS: usize = 65_536;

/// Floor on `http.maxConnectionsPerIp` (M-33).
///
/// A browser opens up to six connections per host, and GraphiQL on a loopback
/// node is a browser; below that the operator's own tab starts getting its
/// connections closed.
const MIN_MAX_CONNECTIONS_PER_IP: usize = 8;

fn default_relay_mode() -> String {
    "n0".to_owned()
}

fn default_tls_mode() -> String {
    "disabled".to_owned()
}

/// Config keys this node no longer accepts, each with the sentence an operator
/// needs in order to act on it (M-19).
///
/// `deny_unknown_fields` already refuses them — with serde's "unknown field"
/// message, which is accurate and tells an operator whose node stopped booting
/// after an upgrade nothing about what to do. A removed key is the one case
/// where the node knows exactly what the operator meant, so it says so. The
/// node still fails closed: a config carrying a key that no longer means what
/// it says is not silently ignored.
const REMOVED_CONFIG_KEYS: [(&str, &str); 1] = [(
    "externalFileEdits",
    "it never controlled whether hand edits to the .bean were adopted — adoption \
     is unconditional by design, because the only alternative is destroying the \
     edit during the node's own full-file rewrite (M-19). The one thing it gated \
     was the poll-and-reconcile file watcher: set \"watchLedgerFile\": true for \
     that, or drop the key",
)];

/// Refuse a config that still carries a removed key, by name (M-19).
///
/// Runs before the typed parse, so the removed key wins over serde's generic
/// unknown-field complaint. Anything that is not a JSON object is left to the
/// typed parse, whose error carries a line and column.
fn reject_removed_config_keys(content: &str) -> Result<(), ConfigError> {
    let Ok(serde_json::Value::Object(keys)) = serde_json::from_str::<serde_json::Value>(content)
    else {
        return Ok(());
    };
    for (key, guidance) in REMOVED_CONFIG_KEYS {
        if keys.contains_key(key) {
            return Err(ConfigError::Validation(format!(
                "{key} is no longer a configuration key: {guidance}"
            )));
        }
    }
    Ok(())
}

/// Errors that can occur during configuration loading or validation.
#[derive(Debug)]
pub enum ConfigError {
    /// The config file could not be read from disk.
    FileRead(std::io::Error),
    /// The config file contained invalid JSON or unknown keys.
    Parse(serde_json::Error),
    /// A validation rule was violated (message describes which).
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::FileRead(error) => {
                write!(formatter, "failed to read config file: {error}")
            }
            ConfigError::Parse(error) => {
                write!(formatter, "failed to parse config file: {error}")
            }
            ConfigError::Validation(message) => {
                write!(formatter, "config validation failed: {message}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Largest config file [`NodeConfig::load_from_path`] reads (T77 / L-73).
///
/// Every shipped config is a few KiB; the largest honest one — every key set,
/// a long allowlist and origin list — is well under 100 KiB. One MiB is an
/// order of magnitude past that and small enough that a wrong path (a log, a
/// ledger, a disk image) is refused in one bounded read instead of being
/// loaded, parsed and reported as JSON noise.
pub(crate) const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

/// Open and read the config file the way every other operator file is opened
/// (T77 / L-73): through [`ledger::journal::open_checked`] with
/// [`ledger::journal::FileTrust::OperatorConfig`] — a symlink followed to a
/// regular file, anything else (a FIFO, a device, a directory, a dangling
/// link) refused before a byte is read and without blocking — and read with
/// [`ledger::journal::read_to_end_capped`] at [`MAX_CONFIG_FILE_BYTES`].
///
/// Before this the config was the one operator file opened with a plain,
/// blocking `File::open` and read without a cap: a FIFO at `GL_NODE_CONFIG`
/// parked boot (and `--health-check`, which shares this loader) before the
/// ledger lock with one log line, and a 200 MB file was still loading at 30 s.
///
/// Returns the handle as well as the text, so the permission check describes
/// the inode whose bytes were read (the L-04 rule).
pub(crate) fn read_config_file(config_path: &Path) -> Result<(File, String), ConfigError> {
    let checked = ledger::journal::open_checked(
        config_path,
        std::fs::OpenOptions::new().read(true),
        ledger::journal::FileTrust::OperatorConfig,
        "config file",
    )
    .map_err(ConfigError::FileRead)?;
    let bytes = ledger::journal::read_to_end_capped(
        &checked.file,
        checked.metadata.len(),
        MAX_CONFIG_FILE_BYTES,
    )
    .map_err(|error| {
        if error.kind() == std::io::ErrorKind::FileTooLarge {
            ConfigError::FileRead(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!(
                    "{} is larger than {MAX_CONFIG_FILE_BYTES} bytes; refusing to load it as \
                     a config file (L-73)",
                    config_path.display()
                ),
            ))
        } else {
            ConfigError::FileRead(error)
        }
    })?;
    let content = String::from_utf8(bytes).map_err(|error| {
        ConfigError::FileRead(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not UTF-8: {error}", config_path.display()),
        ))
    })?;
    Ok((checked.file, content))
}

impl NodeConfig {
    /// Load configuration from the given path, applying defaults and validating.
    ///
    /// **`GL_NODE_API_KEY` beats a non-empty `auth.apiKey` in the file.** It used
    /// to be the other way round — the environment was consulted only when the
    /// file's value was empty — which made key rotation silently fail: an
    /// operator sets the new key in the environment, restarts, sees a healthy
    /// node, and the node is still accepting the old key baked into the config
    /// file. Nothing reported the conflict. The file is the value that goes
    /// stale (committed to a repository, baked into an image, mounted read-only
    /// from a ConfigMap); the environment is where a rotation is actually
    /// performed. When both are set the node says so and names the winner.
    // `&PathBuf` is the signature this function has always had, and roughly
    // fifty call sites across the crate's tests pass `&…to_path_buf()`.
    // Narrowing it to `&Path` is the idiomatic shape, but it would turn every
    // one of those into an `unnecessary_to_owned` lint — a large mechanical
    // rewrite of test code this change has no business touching. The parameter
    // is forwarded to a `&Path` seam immediately below, so the lint is correct
    // and simply not worth acting on here.
    #[allow(clippy::ptr_arg)]
    pub fn load_from_path(config_path: &PathBuf) -> Result<Self, ConfigError> {
        Self::load_from_path_with_env_api_key(config_path, std::env::var(API_KEY_ENV_VAR).ok())
    }

    /// [`Self::load_from_path`] with the environment supplied explicitly.
    ///
    /// The seam exists for the tests: `cargo test` runs a process-wide
    /// environment across parallel threads, so a test that really set
    /// `GL_NODE_API_KEY` would be changing the input of every other test in
    /// this module at the same time. Passing the value in keeps the precedence
    /// rule deterministic to test; `load_from_path` is the one place that reads
    /// the process environment, and [`API_KEY_ENV_VAR`] is the one place the
    /// name is spelled. `gl-node init` uses it too, to check the config it
    /// wrote with a key of its own choosing (`node_init`).
    pub(crate) fn load_from_path_with_env_api_key(
        config_path: &Path,
        env_api_key: Option<String>,
    ) -> Result<Self, ConfigError> {
        // Opened once and read from the handle, so the permission warning below
        // describes the inode whose bytes became the key rather than whatever
        // happens to sit at the path a moment later (the L-04 rule).
        let (file, content) = read_config_file(config_path)?;
        reject_removed_config_keys(&content)?;
        let mut config: NodeConfig = serde_json::from_str(&content).map_err(ConfigError::Parse)?;

        let file_api_key_set = !config.auth.api_key.is_empty();
        if file_api_key_set {
            warn_if_config_file_is_readable_by_others(&file, config_path);
        }

        if let Some(env_api_key) = env_api_key.filter(|key| !key.is_empty()) {
            if file_api_key_set {
                // Warned whenever both are set, not only when they differ: two
                // sources of truth for one credential is the condition worth
                // reporting, and they agree only until the next rotation —
                // which is precisely the moment the old precedence went wrong.
                warn!(
                    path = %config_path.display(),
                    env_var = API_KEY_ENV_VAR,
                    "auth.apiKey is set in both the config file and the environment; the \
                     ENVIRONMENT value wins. Remove one so there is a single source of truth — \
                     under the previous precedence the file value won silently, so a rotated \
                     environment key left the node still accepting the stale one"
                );
            }
            if !config.auth.enabled {
                // 0922-v2 §5: the environment key used to be discarded in
                // silence when auth is off, so an operator who exported it
                // believed the node was guarded. A public bind is refused
                // anyway (auth is forced on there); this is the loopback case,
                // where the mutations are then open to anything local. The
                // value is never echoed.
                warn!(
                    env_var = API_KEY_ENV_VAR,
                    "GL_NODE_API_KEY is set but auth.enabled is false, so the key is IGNORED and \
                     every GraphQL request, mutations included, is served without one; remove \
                     \"enabled\": false from the auth section (auth is on by default) to \
                     require it, or unset the variable"
                );
            }
            config.auth.api_key = env_api_key;
        }

        config.validate()?;
        Ok(config)
    }

    /// Validate boot-time invariants per §3.11.
    fn validate(&self) -> Result<(), ConfigError> {
        // 003: the ledger's own rules, shared with every ledger folder.
        self.ledger_config().validate()?;
        Self::validate_path_under_cwd("ledgersDir", &self.ledgers_dir)?;
        if !(1..=MAX_LEDGERS).contains(&self.max_ledgers) {
            return Err(ConfigError::Validation(format!(
                "maxLedgers must be between 1 and {MAX_LEDGERS}, got {}",
                self.max_ledgers
            )));
        }
        let cwd = std::env::current_dir().map_err(|error| {
            ConfigError::Validation(format!("failed to read working directory: {error}"))
        })?;
        if lexical_normalize(&cwd.join(&self.ledger_path))
            .starts_with(lexical_normalize(&cwd.join(&self.ledgers_dir)))
        {
            return Err(ConfigError::Validation(
                "ledgerPath must not be inside ledgersDir: that folder holds the node's other ledgers, one folder each".to_owned(),
            ));
        }

        if self.graphiql && self.is_public() {
            return Err(ConfigError::Validation(format!(
                "graphiql must be false {ON_A_PUBLIC_NODE}"
            )));
        }

        // H-01: a loopback node with no key configured uses the key file
        // (`main` loads or generates it). A public bind is checked below,
        // after M-2.
        if self.uses_api_key_file() && !self.is_public() && self.auth.api_key_path.is_empty() {
            return Err(ConfigError::Validation(
                "auth.apiKeyPath is required when auth is enabled and no auth.apiKey is set"
                    .to_owned(),
            ));
        }

        // L-08: gated on `auth.enabled` alone, with no bind condition — matching
        // the H-5 check this replaces. A non-loopback bind with auth disabled is
        // already refused above (M-2), so "auth is on" is strictly wider than
        // "the bind is public": every public node passes through here, and a
        // loopback node with a published sample key is refused too. That is the
        // fail-closed reading, and the right one — `bindAddress` is one edit away
        // from `0.0.0.0`, and a key that was never a secret does not become one
        // because today's listener is loopback.
        if self.auth.enabled && !self.uses_api_key_file() {
            check_api_key(&self.auth.api_key).map_err(ConfigError::Validation)?;
        }

        for origin in &self.cors.allowed_origins {
            if origin == "*" {
                return Err(ConfigError::Validation(
                    "cors.allowedOrigins must not include \"*\"; list explicit origins".to_owned(),
                ));
            }
            if origin.is_empty() || HeaderValue::from_str(origin).is_err() {
                return Err(ConfigError::Validation(format!(
                    "cors.allowedOrigins contains invalid origin: {origin}"
                )));
            }
            // L-52: `null` is the origin of every sandboxed iframe, `data:` and
            // `file:` document at once — listing it trusts all of them, and the
            // CORS layer would then echo `Access-Control-Allow-Origin: null`.
            // The request guard refuses it regardless; refusing it here too
            // means the config cannot claim a trust the node will not honour.
            if origin.eq_ignore_ascii_case("null") {
                return Err(ConfigError::Validation(
                    "cors.allowedOrigins must not include \"null\"; it is the shared origin of \
                     every sandboxed iframe, data: and file: document, and is never a trusted caller"
                        .to_owned(),
                ));
            }
        }

        for host in &self.allowed_hosts {
            if host.is_empty() {
                return Err(ConfigError::Validation(
                    "allowedHosts must not contain empty entries".to_owned(),
                ));
            }
            if host.contains("://") {
                return Err(ConfigError::Validation(format!(
                    "allowedHosts entries are hostnames or IP literals without a scheme or port, got \"{host}\""
                )));
            }
            if host.contains('/') || host.chars().any(char::is_whitespace) {
                return Err(ConfigError::Validation(format!(
                    "allowedHosts entries must not contain \"/\" or whitespace, got \"{host}\""
                )));
            }
            if HeaderValue::from_str(host).is_err() {
                return Err(ConfigError::Validation(format!(
                    "allowedHosts contains invalid host: {host}"
                )));
            }
            Self::validate_allowed_host_form(host)?;
        }

        // M-13: bound the HTTP hardening knobs from both sides. A floor alone
        // is not enough here — unlike an interval, where only small values are
        // dangerous, a timeout or a connection cap is disabled just as
        // effectively by being made enormous, and that spelling looks far more
        // reasonable in a config file than a `0` does.
        Self::validate_http_timeout(
            "http.headerReadTimeoutSeconds",
            self.http.header_read_timeout_seconds,
            "a client that never finishes a request head holds a connection and a task for this \
             long (slowloris)",
        )?;
        Self::validate_http_timeout(
            "http.requestTimeoutSeconds",
            self.http.request_timeout_seconds,
            "this is the only wall-clock bound on a stalled body and on GraphQL execution",
        )?;
        if !(MIN_MAX_CONNECTIONS..=MAX_MAX_CONNECTIONS).contains(&self.http.max_connections) {
            return Err(ConfigError::Validation(format!(
                "http.maxConnections must be between {MIN_MAX_CONNECTIONS} and \
                 {MAX_MAX_CONNECTIONS}, got {}; below the floor the node stalls itself, above \
                 the ceiling there is no cap left to exhaust before the file-descriptor limit \
                 does",
                self.http.max_connections
            )));
        }
        // M-33: the per-IP share. Only a floor and the same absolute ceiling —
        // a value above `maxConnections` is clamped to it at serve time rather
        // than refused, so lowering the global cap never bricks a config that
        // left this at its default.
        if !(MIN_MAX_CONNECTIONS_PER_IP..=MAX_MAX_CONNECTIONS)
            .contains(&self.http.max_connections_per_ip)
        {
            return Err(ConfigError::Validation(format!(
                "http.maxConnectionsPerIp must be between {MIN_MAX_CONNECTIONS_PER_IP} and \
                 {MAX_MAX_CONNECTIONS}, got {}; below the floor a browser's normal parallel \
                 connections are refused",
                self.http.max_connections_per_ip
            )));
        }

        // 003: one ledger's share of the node's request slots.
        if !(1..=MAX_MAX_CONNECTIONS).contains(&self.http.max_requests_per_ledger) {
            return Err(ConfigError::Validation(format!(
                "http.maxRequestsPerLedger must be between 1 and {MAX_MAX_CONNECTIONS}, got {}",
                self.http.max_requests_per_ledger
            )));
        }

        // M-04: a trusted proxy entry that does not parse would be silently
        // dropped from the trust set, leaving the operator believing
        // `X-Forwarded-For` is honoured while every client still shares the
        // proxy's single bucket. Refuse to boot instead.
        for proxy in &self.trusted_proxies {
            if proxy.parse::<IpAddr>().is_err() {
                return Err(ConfigError::Validation(format!(
                    "trustedProxies entries must be IP literals without a port or prefix length, got \"{proxy}\""
                )));
            }
        }

        match self.tls.mode.as_str() {
            "disabled" | "terminated" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "tls.mode must be \"disabled\" or \"terminated\", got \"{other}\""
                )));
            }
        }

        if self.binds_non_loopback() && self.tls.mode != "terminated" {
            return Err(ConfigError::Validation(
                "tls.mode must be \"terminated\" when binding a non-loopback address (TLS at the host or proxy; in-process TLS is not implemented)".to_owned(),
            ));
        }

        // M-2: fail closed. A non-loopback bind with auth disabled serves
        // unauthenticated GraphQL — including the appendTransaction/openAccount/
        // closeAccount mutations — to the whole network. Refuse to boot rather
        // than only warning.
        if self.is_public() && !self.auth.enabled {
            return Err(ConfigError::Validation(format!(
                "auth.enabled must be true {ON_A_PUBLIC_NODE}; an unauthenticated public node exposes writable GraphQL mutations"
            )));
        }

        // H-01: a public node needs a key its clients were given on purpose,
        // never one generated into a file on the server.
        if self.is_public() && self.uses_api_key_file() {
            return Err(ConfigError::Validation(format!(
                "auth.apiKey (or GL_NODE_API_KEY) is required {ON_A_PUBLIC_NODE}"
            )));
        }

        // H-01: fail closed. The request guard only admits the built-in loopback
        // hosts plus the bind address, so on a non-loopback bind the operator
        // must say which hostname(s)/IP(s) clients use — otherwise every request
        // through a proxy or DNS name is rejected with 403 at runtime.
        if self.is_public() && self.allowed_hosts.is_empty() {
            return Err(ConfigError::Validation(format!(
                "allowedHosts must list the hostname(s) or IP(s) clients use to reach this node {ON_A_PUBLIC_NODE}; otherwise the Host guard rejects every request"
            )));
        }

        Ok(())
    }

    /// The four well-formedness rules every candidate signature domain obeys
    /// (L-23, M-31), applied to `p2p.meshId` and `p2p.swarmTopic` alike.
    ///
    /// One function for both fields, for the same reason
    /// [`Self::validate_http_timeout`] is one function for both timeouts: two
    /// copies of a rule are two rules, and the pair that must agree here is the
    /// pair that decides whether a signature made on one node verifies on
    /// another.
    ///
    /// `why` names the role the value plays in *this* call, so the boot error
    /// tells an operator what they have actually broken — the topic's role
    /// differs depending on whether a `meshId` is displacing it as the domain.
    ///
    /// **Nothing here normalizes.** A padded value is *refused*, never trimmed:
    /// the domain is compared byte-for-byte on both sides of every signature,
    /// so quietly trimming it on the node that happens to run this code would
    /// let two nodes resolve different domains from the same intent — turning a
    /// loud boot failure into a silent mesh partition that surfaces much later
    /// as `InvalidSignature`, which reads as a key problem and sends the
    /// operator hunting in the wrong place entirely.
    fn validate_signature_domain(field: &str, value: &str, why: &str) -> Result<(), ConfigError> {
        if value.trim().is_empty() {
            return Err(ConfigError::Validation(format!(
                "{field} must not be empty or whitespace; {why}, so it must name something (a \
                 random UUID is the recommendation)"
            )));
        }
        if value.trim() != value {
            // L-56: never echo the value. The padded string differs from the
            // live join credential / signature domain by one byte, `main`
            // surfaces this error through `error!`, and every other site that
            // names this value redacts it (M-32). The redacted shape (length and
            // a four-character prefix) plus the byte offset of the offending
            // whitespace is enough to find the typo in the file.
            let offset = if value.starts_with(char::is_whitespace) {
                0
            } else {
                value.trim_end().len()
            };
            return Err(ConfigError::Validation(format!(
                "{field} must not have leading or trailing whitespace, got {} with whitespace at \
                 byte {offset}; {why} — refused rather than trimmed, because trimming it here \
                 would turn a loud boot failure into a silent partition",
                crate::auth::redact(value)
            )));
        }
        if value.len() > MAX_SIGNATURE_DOMAIN_BYTES {
            return Err(ConfigError::Validation(format!(
                "{field} must be at most {MAX_SIGNATURE_DOMAIN_BYTES} bytes, got {}; it is an \
                 identifier (a random UUID is the recommendation), not a payload",
                value.len()
            )));
        }
        if let Some(character) = value.chars().find(|c| !is_signature_domain_character(*c)) {
            return Err(ConfigError::Validation(format!(
                "{field} contains invalid character {character:?} (U+{:04X}); allowed are ASCII \
                 letters, digits and - _ . : / (a random UUID is the recommendation). \"|\" in \
                 particular is the field separator of the v3 signature message, which is \
                 injective only because no interpolated field can spell it (L-06)",
                character as u32
            )));
        }
        Ok(())
    }

    /// Refuse an `allowedHosts` entry the Host guard could never match (0922-v2
    /// §5).
    ///
    /// The guard reduces every `Host` header with
    /// [`crate::request_guard::split_authority`] — port and IPv6 brackets
    /// stripped — and looks the bare host up in this list. An entry spelled
    /// with a port (`ledger.example.com:443`) or brackets (`[::1]`) therefore
    /// matched nothing: it passed validation, and then every request through
    /// that name got `403`, with nothing at boot to say why. Running the entry
    /// through the same split and refusing it when the split changes it keeps
    /// the two in agreement by construction.
    ///
    /// A trailing dot (`ledger.example.com.`) is the fully-qualified spelling
    /// of the same name, but clients send the name without it and the guard
    /// compares bytes, so it too matches nothing in practice.
    ///
    /// Echoing the entry is fine here: a host name is not a credential, and
    /// the neighbouring `allowedHosts` errors already name it.
    fn validate_allowed_host_form(host: &str) -> Result<(), ConfigError> {
        let (bare, port) = crate::request_guard::split_authority(host);
        if let Some(port) = port {
            return Err(ConfigError::Validation(format!(
                "allowedHosts entries are hostnames or IP literals without a port, got \"{host}\"; \
                 the Host guard strips the port (:{port}) from every request before the lookup, \
                 so this entry could never match and every request through it would get 403 — \
                 list \"{bare}\" instead"
            )));
        }
        if bare != host {
            return Err(ConfigError::Validation(format!(
                "allowedHosts entries must not be bracketed, got \"{host}\"; the Host guard \
                 strips IPv6 brackets before the lookup, so this entry could never match — \
                 list \"{bare}\" instead"
            )));
        }
        if host.len() > 1 && host.ends_with('.') {
            return Err(ConfigError::Validation(format!(
                "allowedHosts entries must not end with a dot, got \"{host}\"; clients send the \
                 name without the trailing dot and the Host guard compares it byte for byte, so \
                 this entry would match nothing and every request would get 403 — list \"{}\" \
                 instead",
                host.trim_end_matches('.')
            )));
        }
        Ok(())
    }

    /// One bounds check for both `http` timeouts, so they cannot drift apart.
    fn validate_http_timeout(field: &str, seconds: u64, why: &str) -> Result<(), ConfigError> {
        if !(MIN_HTTP_TIMEOUT_SECONDS..=MAX_HTTP_TIMEOUT_SECONDS).contains(&seconds) {
            return Err(ConfigError::Validation(format!(
                "{field} must be between {MIN_HTTP_TIMEOUT_SECONDS} and \
                 {MAX_HTTP_TIMEOUT_SECONDS} seconds, got {seconds}; {why}, so 0 disables the \
                 server and a very large value disables the protection"
            )));
        }
        Ok(())
    }

    /// The connection-level limits `serve_hardened` runs under (M-13).
    ///
    /// With no `http` section in the file every field here is
    /// [`HttpServerSettings::default`]'s own value, so this returns exactly the
    /// settings the call site used to hardcode.
    pub fn http_server_settings(&self) -> HttpServerSettings {
        HttpServerSettings {
            header_read_timeout: Duration::from_secs(self.http.header_read_timeout_seconds),
            request_timeout: Duration::from_secs(self.http.request_timeout_seconds),
            max_connections: self.http.max_connections,
            max_connections_per_ip: self.http.max_connections_per_ip,
        }
    }

    /// Whether the API key comes from `auth.apiKeyPath` (H-01): auth is on and
    /// neither the config file nor `GL_NODE_API_KEY` supplied one. Validation
    /// admits that only on a node that is not public (`is_public`).
    pub fn uses_api_key_file(&self) -> bool {
        self.auth.enabled && self.auth.api_key.is_empty()
    }

    /// True when the HTTP bind address is not loopback (I-1 / H-5 warning).
    pub fn binds_non_loopback(&self) -> bool {
        !matches!(
            self.bind_address.as_str(),
            "127.0.0.1" | "::1" | "localhost"
        )
    }

    /// Whether strangers can reach this node's API (005): a non-loopback
    /// bind, `tls.mode: "terminated"` — a TLS terminator in front, which on
    /// the same host hands a loopback bind the whole internet — or a
    /// `trustedProxies` entry, the operator's word that a proxy forwards to it
    /// (review: with `tls.mode` left `"disabled"` it is a proxy all the same).
    /// Every rule that
    /// protects a node others reach keys on this (L-09's minimal `/health`, M-2
    /// auth on, no GraphiQL, H-01's key given on purpose and `allowedHosts`),
    /// so a loopback node behind a proxy is held to them as the public node it
    /// is. Only the rule that a non-loopback bind must be terminated keys on
    /// the bind itself.
    pub fn is_public(&self) -> bool {
        self.binds_non_loopback()
            || self.tls.mode == "terminated"
            || !self.trusted_proxies.is_empty()
    }

    /// This node's one ledger's settings, as the config file gives them.
    pub fn ledger_config(&self) -> LedgerConfig {
        LedgerConfig {
            ledger_path: self.ledger_path.clone(),
            watch_ledger_file: self.watch_ledger_file,
            signing: self.signing.clone(),
            format: self.format,
            p2p: self.p2p.clone(),
            admin_nodes: self.auth.admin_nodes.clone(),
        }
    }

    /// Whether to serve GraphiQL on `GET /graphql`.
    pub fn graphiql_enabled(&self) -> bool {
        self.graphiql
    }

    /// Host values the request guard accepts, lowercased and portless (H-01).
    ///
    /// Loopback names are always accepted, the configured bind address is added
    /// unless it is a wildcard, and `allowedHosts` supplies the rest.
    pub fn allowed_host_set(&self) -> std::collections::HashSet<String> {
        let mut hosts: std::collections::HashSet<String> = ["localhost", "127.0.0.1", "::1"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        match self.bind_address.as_str() {
            // Wildcard binds name no host a client could send.
            "0.0.0.0" | "::" | "" => {}
            bind_address => {
                hosts.insert(bind_address.to_ascii_lowercase());
            }
        }
        for host in &self.allowed_hosts {
            hosts.insert(host.to_ascii_lowercase());
        }
        hosts
    }

    /// Reverse-proxy addresses whose `X-Forwarded-For` the rate limiter trusts (M-04).
    ///
    /// Every entry is checked at boot, so nothing is dropped here in practice.
    pub fn trusted_proxy_set(&self) -> std::collections::HashSet<IpAddr> {
        self.trusted_proxies
            .iter()
            .filter_map(|proxy| proxy.parse::<IpAddr>().ok())
            .collect()
    }

    /// Restrictive CORS: empty allowlist denies cross-origin browser access (H-1).
    pub fn cors_layer(&self) -> CorsLayer {
        if self.cors.allowed_origins.is_empty() {
            return CorsLayer::new();
        }
        let origins: Vec<HeaderValue> = self
            .cors
            .allowed_origins
            .iter()
            .map(|origin| HeaderValue::from_str(origin).expect("cors origins validated at boot"))
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([
                header::CONTENT_TYPE,
                header::ACCEPT,
                HeaderName::from_static("x-api-key"),
            ])
    }

    fn validate_ledger_path(ledger_path: &str) -> Result<(), ConfigError> {
        Self::validate_path_under_cwd("ledgerPath", ledger_path)
    }

    /// A path the node writes under (`ledgerPath`, `ledgersDir`): not empty, no
    /// NUL, no `..`, and resolving under the process working directory.
    fn validate_path_under_cwd(field: &str, ledger_path: &str) -> Result<(), ConfigError> {
        if ledger_path.is_empty() {
            return Err(ConfigError::Validation(format!(
                "{field} is required and must not be empty"
            )));
        }
        if ledger_path.contains('\0') {
            return Err(ConfigError::Validation(format!(
                "{field} must not contain NUL"
            )));
        }
        let configured = Path::new(ledger_path);
        if configured
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(ConfigError::Validation(format!(
                "{field} must not contain \"..\""
            )));
        }
        let cwd = std::env::current_dir().map_err(|error| {
            ConfigError::Validation(format!("failed to read working directory: {error}"))
        })?;
        let resolved = if configured.is_absolute() {
            configured.to_path_buf()
        } else {
            cwd.join(configured)
        };
        let cwd_normalized = lexical_normalize(&cwd);
        let resolved_normalized = lexical_normalize(&resolved);
        if !resolved_normalized.starts_with(&cwd_normalized) {
            return Err(ConfigError::Validation(format!(
                "{field} must resolve under the process working directory"
            )));
        }
        Ok(())
    }
}

/// Warn when a config file carrying an `auth.apiKey` is readable beyond its owner.
///
/// A **warning**, deliberately, where the node's secret key is a hard failure
/// (C-2/L-04): the API key's config file is a general-purpose operator artefact
/// that legitimately lives in places with a shared mode — a mounted ConfigMap,
/// a deployment directory, a checkout — and refusing to boot on its mode would
/// strand nodes that are otherwise correctly configured, for a file the
/// operator may not even own. What was missing was any signal at all: a
/// world-readable file holding the only credential in front of the writable
/// GraphQL mutations looked exactly like a private one.
///
/// The mode is read through the **open handle** the key was parsed from, not by
/// re-`stat`ing the path, for the same reason the L-04 key check does: a
/// path-based check reports on whatever is at the path at check time, which
/// need not be the file that was read.
#[cfg(unix)]
fn warn_if_config_file_is_readable_by_others(file: &File, config_path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    // A mode we cannot read is not worth failing a boot over; the key itself
    // was already read successfully.
    let Ok(metadata) = file.metadata() else {
        return;
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        warn!(
            path = %config_path.display(),
            mode = format_args!("{mode:04o}"),
            env_var = API_KEY_ENV_VAR,
            "config file carries auth.apiKey and is readable by group or other; that key is the \
             only credential guarding the writable GraphQL mutations — restrict the file \
             (`chmod 600`), or move the key out of it into the environment variable"
        );
    }
}

/// Non-Unix: say that the check did not happen rather than staying silent (L-05).
///
/// Silence here is indistinguishable from "the mode is fine", which is the
/// exact trap L-05 closed on the secret-key path. Gated on the file actually
/// carrying a key, so it is not a warning every node prints at every boot.
#[cfg(not(unix))]
fn warn_if_config_file_is_readable_by_others(_file: &File, config_path: &Path) {
    warn!(
        path = %config_path.display(),
        "config file carries auth.apiKey, but file permissions are NOT verified on this platform \
         (non-Unix) — restrict access to it with the platform's own ACLs, as the key is the only \
         credential guarding the writable GraphQL mutations"
    );
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        file.write_all(content.as_bytes())
            .expect("failed to write temp config");
        file
    }

    #[test]
    fn test_minimal_config_loads() {
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert_eq!(config.ledger_path, "./data/ledger.bean");
        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.port, 4000);
        assert!(
            !config.watch_ledger_file,
            "the file watcher is off by default (M-19)"
        );
        assert!(!config.graphiql, "GraphiQL off by default");
        assert!(config.cors.allowed_origins.is_empty());
        assert!(config.auth.enabled, "auth is on by default (H-01)");
        assert!(config.uses_api_key_file());
        assert_eq!(config.auth.api_key_path, "./data/api.key");
        assert!(!config.signing.enabled);
        assert!(!config.p2p.enabled);
        assert_eq!(config.tls.mode, "disabled");
        assert_eq!(config.p2p.relay_mode, "n0");
    }

    #[test]
    fn test_full_config_loads() {
        let peer_a = iroh::SecretKey::generate().public().to_string();
        let peer_b = iroh::SecretKey::generate().public().to_string();
        let content = format!(
            r#"{{
            "ledgerPath": "./data/ledger.bean",
            "bindAddress": "0.0.0.0",
            "port": 8080,
            "watchLedgerFile": true,
            "cors": {{ "allowedOrigins": ["http://localhost:8080"] }},
            "allowedHosts": ["ledger.example.com"],
            "trustedProxies": ["10.0.0.1"],
            "auth": {{ "enabled": true, "apiKey": "unit-test-api-key-0123456789abcd" }},
            "signing": {{ "enabled": true }},
            "tls": {{ "mode": "terminated" }},
            "p2p": {{
                "enabled": true,
                "secretKeyPath": "./keys/iroh.secret",
                "bootstrapEndpointIds": ["{peer_a}", "{peer_b}"],
                "gossipIntervalMilliseconds": 3000,
                "antiEntropyIntervalMilliseconds": 10000,
                "swarmTopic": "my-org/ledger",
                "meshId": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
                "relayMode": "disabled"
            }}
        }}"#
        );
        let file = write_temp_config(&content);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert!(config.watch_ledger_file);
        assert_eq!(config.cors.allowed_origins, vec!["http://localhost:8080"]);
        assert_eq!(config.allowed_hosts, vec!["ledger.example.com"]);
        assert_eq!(config.trusted_proxies, vec!["10.0.0.1"]);
        assert!(config.auth.enabled);
        assert_eq!(config.auth.api_key, "unit-test-api-key-0123456789abcd");
        assert!(config.signing.enabled);
        assert!(config.p2p.enabled);
        assert_eq!(config.p2p.bootstrap_endpoint_ids.len(), 2);
        assert_eq!(config.p2p.gossip_interval_milliseconds, 3000);
        assert_eq!(config.tls.mode, "terminated");
        assert_eq!(config.p2p.relay_mode, "disabled");
        assert!(
            !config.graphiql_enabled(),
            "GraphiQL stays off on public bind unless explicitly enabled (which is rejected)"
        );
    }

    #[test]
    fn test_unknown_key_rejected() {
        let file =
            write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean", "unknownKey": true }"#);
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("parse"));
    }

    #[test]
    fn test_empty_ledger_path_rejected() {
        let file = write_temp_config(r#"{ "ledgerPath": "" }"#);
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("ledgerPath"));
    }

    /// H-01: auth with no key configured takes the key file on a loopback
    /// bind and is refused on a public one.
    #[test]
    fn test_auth_enabled_without_key_uses_the_key_file_on_loopback_only() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "auth": { "enabled": true, "apiKey": "" } }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("loopback");
        assert!(config.uses_api_key_file());

        let public = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "tls": { "mode": "terminated" }, "allowedHosts": ["ledger.example.com"] }"#,
        );
        let result = NodeConfig::load_from_path(&public.path().to_path_buf());
        let error_message = format!("{}", result.expect_err("a public bind needs a key"));
        assert!(error_message.contains("auth.apiKey"), "{error_message}");

        let no_path = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "auth": { "apiKeyPath": "" } }"#,
        );
        let result = NodeConfig::load_from_path(&no_path.path().to_path_buf());
        let error_message = format!("{}", result.expect_err("no key and nowhere to keep one"));
        assert!(error_message.contains("auth.apiKeyPath"), "{error_message}");
    }

    /// M-19: the removed key is refused by name, with the replacement spelled
    /// out — not with serde's generic "unknown field".
    #[test]
    fn m19_removed_external_file_edits_key_is_refused_with_guidance() {
        for value in ["\"disabled\"", "\"enabled\"", "\"maybe\"", "true"] {
            let file = write_temp_config(&format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", "externalFileEdits": {value} }}"#
            ));
            let result = NodeConfig::load_from_path(&file.path().to_path_buf());
            let error_message = format!(
                "{}",
                result.expect_err("a config carrying the removed key must not boot")
            );
            assert!(
                error_message.contains("externalFileEdits"),
                "the refusal must name the key: {error_message}"
            );
            assert!(
                error_message.contains("watchLedgerFile"),
                "the refusal must name the replacement: {error_message}"
            );
            assert!(
                error_message.contains("M-19"),
                "the refusal must cite the finding: {error_message}"
            );
        }
    }

    /// M-19: and the setting really is gone — it is not merely undocumented.
    #[test]
    fn m19_the_watcher_switch_is_the_only_file_edit_setting() {
        let file =
            write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean", "watchLedgerFile": true }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert!(config.watch_ledger_file);
    }

    #[test]
    fn test_wildcard_cors_origin_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "cors": { "allowedOrigins": ["*"] } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("allowedOrigins"));
    }

    #[test]
    fn test_graphiql_explicit_false_disables_playground() {
        // A public bind now requires auth (M-2), so include it here.
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "graphiql": false, "tls": { "mode": "terminated" }, "auth": { "enabled": true, "apiKey": "unit-test-api-key-0123456789abcd" }, "allowedHosts": ["ledger.example.com"] }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert!(!config.graphiql_enabled());
    }

    #[test]
    fn test_public_bind_without_auth_rejected() {
        // M-2: a non-loopback bind with auth off must fail closed, even when TLS
        // is terminated (otherwise an unauthenticated writable ledger is served).
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "tls": { "mode": "terminated" }, "auth": { "enabled": false } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("auth.enabled must be true"));
    }

    #[test]
    fn test_public_bind_with_auth_accepted() {
        // The same public bind loads once auth is enabled (and the Host
        // allowlist is populated, per H-01).
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "tls": { "mode": "terminated" }, "auth": { "enabled": true, "apiKey": "unit-test-api-key-0123456789abcd" }, "allowedHosts": ["ledger.example.com"] }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert!(config.binds_non_loopback());
        assert!(config.auth.enabled);
    }

    #[test]
    fn test_loopback_bind_without_auth_still_allowed() {
        // H-01: a loopback bind may still turn auth off, but only by saying so
        // (boot WARNs); with the auth section absent, auth is on.
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "auth": { "enabled": false } }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert!(!config.binds_non_loopback());
        assert!(!config.auth.enabled);
        assert!(!config.uses_api_key_file());
    }

    /// 005 step 2: a loopback node behind a TLS proxy (`tls.mode:
    /// "terminated"`, or a `trustedProxies` entry) is public — the proxy hands it the internet — so it is
    /// held to every public-node rule: no GraphiQL, auth on, a key given on
    /// purpose rather than a generated key file, and `allowedHosts`; with all
    /// of them it loads. A loopback node without a proxy keeps its leeway.
    ///
    /// Bug-catch: key the rules on the bind alone and a node behind a proxy on
    /// its own host serves GraphiQL, or no auth at all, to the internet.
    #[test]
    fn a_loopback_node_behind_a_proxy_is_held_to_the_public_rules() {
        let load = |body: &str, key: Option<&str>| {
            let file = write_temp_config(&format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", "tls": {{ "mode": "terminated" }}{body} }}"#
            ));
            NodeConfig::load_from_path_with_env_api_key(file.path(), key.map(str::to_owned))
        };
        let key = Some("unit-test-api-key-0123456789abcd");
        let hosts = r#", "allowedHosts": ["ledger.example.com"]"#;
        for (body, key, refused_for) in [
            (format!(r#"{hosts}, "graphiql": true"#), key, "graphiql"),
            (
                format!(r#"{hosts}, "auth": {{ "enabled": false }}"#),
                None,
                "auth.enabled",
            ),
            (hosts.to_owned(), None, "auth.apiKey"),
            (String::new(), key, "allowedHosts"),
        ] {
            let Err(error) = load(&body, key) else {
                panic!("{refused_for}: a node behind a proxy loaded with {body}");
            };
            let message = error.to_string();
            assert!(
                message.contains(refused_for) && message.contains("public node"),
                "{refused_for}: {message}"
            );
        }
        let config = load(hosts, key).expect("with every rule kept it loads");
        assert!(config.is_public() && !config.binds_non_loopback());

        // A proxy named in trustedProxies is a proxy, `tls.mode` or not.
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "trustedProxies": ["127.0.0.1"], "graphiql": true }"#,
        );
        let Err(error) =
            NodeConfig::load_from_path_with_env_api_key(file.path(), key.map(str::to_owned))
        else {
            panic!("a node with a trusted proxy served GraphiQL");
        };
        assert!(error.to_string().contains("graphiql"), "{error}");

        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean", "graphiql": true }"#);
        let local = NodeConfig::load_from_path_with_env_api_key(file.path(), None)
            .expect("a loopback node without a proxy keeps GraphiQL and its key file");
        assert!(!local.is_public());
    }

    #[test]
    fn test_graphiql_true_rejected_on_public_bind() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "graphiql": true }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("graphiql"));
    }

    #[test]
    fn test_graphiql_true_allowed_on_loopback() {
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean", "graphiql": true }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert!(config.graphiql_enabled());
    }

    /// Format v2: the `format` section defaults to v1 everywhere and refuses
    /// a key it does not know.
    #[test]
    fn test_format_section_defaults_to_v2_and_is_strict() {
        // On by default (2026-10-06): with the section absent, and with it
        // present but empty.
        for content in [
            r#"{ "ledgerPath": "./data/ledger.bean" }"#,
            r#"{ "ledgerPath": "./data/ledger.bean", "format": {} }"#,
        ] {
            let file = write_temp_config(content);
            let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("load");
            assert_eq!(config.format.wire_codec(), p2p::protocol::WireCodec::V2);
            assert_eq!(
                config.format.record_format(),
                ledger::hash::RecordFormat::V2
            );
        }
        // Each switch turns off on its own.
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "format": { "wire2": false } }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("load");
        assert_eq!(config.format.wire_codec(), p2p::protocol::WireCodec::V1);
        assert_eq!(
            config.format.record_format(),
            ledger::hash::RecordFormat::V2
        );
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "format": { "idv2": false } }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("load");
        assert_eq!(
            config.format.record_format(),
            ledger::hash::RecordFormat::V1
        );
        assert_eq!(config.format.wire_codec(), p2p::protocol::WireCodec::V2);
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "format": { "wire3": true } }"#,
        );
        assert!(NodeConfig::load_from_path(&file.path().to_path_buf()).is_err());
    }

    /// L-114: the write override is off unless set.
    #[test]
    fn test_allow_writes_when_every_signature_fails_defaults_off() {
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert!(!config.signing.allow_writes_when_every_signature_fails);
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "signing": { "enabled": true, "allowWritesWhenEverySignatureFails": true }, "p2p": { "meshId": "3f2504e0-4f89-41d3-9a0c-0305e82c3301" } }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert!(config.signing.allow_writes_when_every_signature_fails);
    }

    /// H-19: `p2p.joinFrom` must name a peer this node accepts at all — it is
    /// trusted with the node's first history.
    #[test]
    fn test_join_from_must_be_an_allowlisted_peer() {
        let peer_a = iroh::SecretKey::generate().public().to_string();
        let stranger = iroh::SecretKey::generate().public().to_string();
        let config_with = |join_from: &str| {
            format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", "signing": {{ "enabled": true }},
                "p2p": {{ "enabled": true, "bootstrapEndpointIds": ["{peer_a}"],
                "swarmTopic": "my-org/ledger", "meshId": "my-org/ledger",
                "joinFrom": "{join_from}" }} }}"#
            )
        };
        let file = write_temp_config(&config_with(&peer_a));
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert_eq!(config.p2p.join_from.as_deref(), Some(peer_a.as_str()));
        for bad in [stranger.as_str(), "not-an-id"] {
            let file = write_temp_config(&config_with(bad));
            let Err(error) = NodeConfig::load_from_path(&file.path().to_path_buf()) else {
                panic!("{bad}: refused");
            };
            assert!(format!("{error}").contains("p2p.joinFrom"), "{error}");
        }
    }

    /// `p2p.peerAddresses` (`docs/build-log/001-peer-discovery`): addresses
    /// for an allowlisted peer load; an address for a peer the allowlist does
    /// not admit is refused — an address says where an admitted peer is, it
    /// never admits one — and so are a malformed address, an empty list and a
    /// key that is not an EndpointId, each naming the key.
    ///
    /// Bug-catch: drop the allowlist check in `validate_peer_addresses` and an
    /// address for a stranger loads.
    #[test]
    fn test_peer_addresses_only_for_allowlisted_peers_and_well_formed() {
        let peer_a = iroh::SecretKey::generate().public().to_string();
        let stranger = iroh::SecretKey::generate().public().to_string();
        let config_with = |addresses: &str| {
            format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", "signing": {{ "enabled": true }},
                "p2p": {{ "enabled": true, "bootstrapEndpointIds": ["{peer_a}"],
                "swarmTopic": "my-org/ledger", "meshId": "my-org/ledger",
                "relayMode": "disabled", "peerAddresses": {addresses} }} }}"#
            )
        };
        let good = format!(r#"{{ "{peer_a}": ["ledger.example.com:4433", "203.0.113.7:4433"] }}"#);
        let file = write_temp_config(&config_with(&good));
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert_eq!(config.p2p.peer_addresses[&peer_a].len(), 2);

        for (bad, expected) in [
            (
                format!(r#"{{ "{stranger}": ["ledger.example.com:4433"] }}"#),
                "not one of p2p.bootstrapEndpointIds",
            ),
            (
                format!(r#"{{ "{peer_a}": ["https://ledger.example.com"] }}"#),
                "is not a peer address",
            ),
            (format!(r#"{{ "{peer_a}": [] }}"#), "lists 0 addresses"),
            (
                r#"{ "not-an-id": ["ledger.example.com:4433"] }"#.to_owned(),
                "is not an EndpointId",
            ),
        ] {
            let file = write_temp_config(&config_with(&bad));
            let Err(error) = NodeConfig::load_from_path(&file.path().to_path_buf()) else {
                panic!("{bad}: refused");
            };
            let message = format!("{error}");
            assert!(
                message.contains("p2p.peerAddresses") && message.contains(expected),
                "{bad}: {message}"
            );
        }
    }

    /// `relayMode: "custom"` and `p2p.relayUrl` (`docs/build-log/001-peer-discovery`):
    /// an `https` relay URL with `"custom"` loads; a relay URL with another mode
    /// is refused rather than ignored; `"custom"` with neither a relay nor an
    /// address is refused; and a URL that is not plain `https://host[:port]`
    /// — `http`, user info, a query (a token), a path — is refused, naming
    /// `p2p.relayUrl`.
    ///
    /// No refusal repeats the URL's password or token.
    ///
    /// Bug-catch: drop the `https` check and an unauthenticated relay loads;
    /// drop the mode check and a relay URL beside `"n0"` is silently ignored;
    /// echo the refused text and a password or relay token lands in the log.
    #[test]
    fn test_relay_url_only_with_custom_and_only_plain_https() {
        let peer = iroh::SecretKey::generate().public().to_string();
        let config_with = |p2p_extra: &str| {
            format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", "signing": {{ "enabled": true }},
                "p2p": {{ "enabled": true, "bootstrapEndpointIds": ["{peer}"],
                "swarmTopic": "my-org/ledger", "meshId": "my-org/ledger", {p2p_extra} }} }}"#
            )
        };
        for good in [
            r#""relayMode": "custom", "relayUrl": "https://relay.example.com""#,
            r#""relayMode": "custom", "relayUrl": "https://relay.example.com:8443/""#,
        ] {
            let file = write_temp_config(&config_with(good));
            NodeConfig::load_from_path(&file.path().to_path_buf())
                .unwrap_or_else(|error| panic!("{good}: {error}"));
        }
        for (bad, expected) in [
            (
                r#""relayMode": "n0", "relayUrl": "https://relay.example.com""#,
                "used only with relayMode \"custom\"",
            ),
            (r#""relayMode": "custom""#, "needs the mesh's own relay"),
            (
                r#""relayMode": "custom", "relayUrl": "http://relay.example.com""#,
                "must use https",
            ),
            (
                r#""relayMode": "custom", "relayUrl": "https://user:pw@relay.example.com""#,
                "must not carry user info",
            ),
            (
                r#""relayMode": "custom", "relayUrl": "https://relay.example.com/?token=secret""#,
                "must not carry a query",
            ),
            (
                r#""relayMode": "custom", "relayUrl": "https://relay.example.com/relay""#,
                "must not carry a path",
            ),
            (
                r#""relayMode": "custom", "relayUrl": "relay.example.com""#,
                "is not a URL",
            ),
            (r#""relayMode": "mine""#, "\"custom\", got \"mine\""),
        ] {
            let file = write_temp_config(&config_with(bad));
            let Err(error) = NodeConfig::load_from_path(&file.path().to_path_buf()) else {
                panic!("{bad}: refused");
            };
            let message = format!("{error}");
            assert!(message.contains(expected), "{bad}: {message}");
            // A refusal never repeats a credential it refuses (M-32 / L-56).
            for secret in ["pw", "secret", "token="] {
                assert!(!message.contains(secret), "{bad} leaks {secret}: {message}");
            }
        }
    }

    /// 003: a ledger name is a folder and a URL segment, so only `a-z`, `0-9`
    /// and `-`, 1 to 40 of them, not starting with `-`.
    ///
    /// Bug-catch: accept a `.` or a `/` and a name walks out of `ledgersDir`
    /// or into another ledger's URL.
    #[test]
    fn ledger_names_are_folder_and_url_safe() {
        for good in ["acme", "a-1", "0", &"x".repeat(40)] {
            assert!(is_valid_ledger_name(good), "{good}");
        }
        for bad in [
            "",
            "-acme",
            "Acme",
            "a_b",
            "a.b",
            "a/b",
            "..",
            ".removed",
            "a b",
            &"x".repeat(41),
        ] {
            assert!(!is_valid_ledger_name(bad), "{bad:?}");
        }
    }

    /// A temporary folder under the working directory, where a ledger's paths
    /// must resolve (`ledgerPath` rule).
    fn temp_dir_here() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(".test-ledgers-")
            .tempdir_in(".")
            .expect("temp dir")
    }

    /// 003: a ledger folder's `ledger.json` sets the ledger's own settings;
    /// its file and key are always in the folder (`p2p.secretKeyPath` is
    /// refused, `ledgerPath` is unknown), Format v2 is the default as for the
    /// config file, and a ledger rule it breaks is refused naming the file.
    ///
    /// Bug-catch: honour a `secretKeyPath` and two folders can share one node
    /// key — one identity in two meshes, which decision 1 rules out.
    #[test]
    fn a_ledger_folder_holds_its_own_files_and_settings() {
        let dir = temp_dir_here();
        let folder = dir.path().join("acme");
        std::fs::create_dir(&folder).expect("folder");
        let write = |json: &str| std::fs::write(folder.join(LEDGER_FILE), json).expect("write");

        write(r#"{ "signing": { "enabled": true }, "p2p": { "meshId": "acme-mesh" } }"#);
        let config = LedgerConfig::load_folder(&folder).expect("loads");
        assert_eq!(Path::new(&config.ledger_path), folder.join("ledger.bean"));
        assert_eq!(
            Path::new(&config.p2p.secret_key_path),
            folder.join("iroh.secret")
        );
        assert_eq!(
            config.format.record_format(),
            ledger::hash::RecordFormat::V2
        );
        assert!(config.signing.enabled && config.admin_nodes.is_none());

        write(r#"{ "p2p": { "secretKeyPath": "./data/iroh.secret" } }"#);
        let error = LedgerConfig::load_folder(&folder).expect_err("refused");
        assert!(format!("{error}").contains("iroh.secret"), "{error}");
        write(r#"{ "ledgerPath": "elsewhere.bean" }"#);
        assert!(LedgerConfig::load_folder(&folder).is_err(), "unknown key");
        write(r#"{ "signing": { "enabled": true } }"#);
        let error = LedgerConfig::load_folder(&folder).expect_err("no meshId");
        let text = format!("{error}");
        assert!(
            text.contains("ledger.json") && text.contains("meshId"),
            "{text}"
        );
    }

    /// 003: the folders in `ledgersDir` are ledgers by name, sorted; one named
    /// `default`, or one whose name breaks the rule, is listed as not a
    /// ledger; a dot entry (`.removed`) and a file are not listed; no
    /// directory, none.
    ///
    /// Bug-catch: let a folder take the name `default` and it shadows the
    /// config file's ledger at `/graphql`.
    #[test]
    fn ledger_folders_lists_ledgers_and_refuses_what_is_not_one() {
        let dir = temp_dir_here();
        for folder in ["acme", "default", "Bad_Name", ".removed"] {
            std::fs::create_dir(dir.path().join(folder)).expect("folder");
        }
        std::fs::write(dir.path().join("notes.txt"), "").expect("file");
        let listed = ledger_folders(dir.path()).expect("listed");
        let verdicts: Vec<(&str, bool)> = listed
            .iter()
            .map(|(name, verdict)| (name.as_str(), verdict.is_ok()))
            .collect();
        assert_eq!(
            verdicts,
            vec![("Bad_Name", false), ("acme", true), ("default", false)]
        );
        assert!(ledger_folders(&dir.path().join("missing"))
            .expect("none")
            .is_empty());
    }

    fn ledger_with(mesh: &str, topic: &str, port: u16) -> LedgerConfig {
        let mut config = NodeConfig::load_from_path(
            &write_temp_config(&format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", "signing": {{ "enabled": true }},
                "p2p": {{ "enabled": true, "meshId": "{mesh}", "swarmTopic": "{topic}",
                "relayMode": "disabled" }} }}"#
            ))
            .path()
            .to_path_buf(),
        )
        .expect("config")
        .ledger_config();
        config.p2p.listen_port = port;
        config
    }

    /// 003: one node serves a mesh once — a second ledger with the same
    /// `meshId`, the same gossip topic or the same fixed P2P port is refused,
    /// the first kept — and at most `maxLedgers`; a refused ledger takes no
    /// place in that count, and port 0 (a random port) is never a conflict.
    ///
    /// Bug-catch: let two ledgers share a `meshId` and the node is one member
    /// of a mesh twice, under two keys.
    #[test]
    fn ledgers_in_conflict_refuses_a_second_copy_of_a_mesh_topic_or_port() {
        let ledgers = [
            ("a", ledger_with("mesh-a", "topic/a", 0)),
            ("b", ledger_with("mesh-a", "topic/b", 0)),
            ("c", ledger_with("mesh-c", "topic/a", 0)),
            ("d", ledger_with("mesh-d", "topic/d", 7000)),
            ("e", ledger_with("mesh-e", "topic/e", 7000)),
            ("f", ledger_with("mesh-f", "topic/f", 0)),
            ("g", ledger_with("mesh-g", "topic/g", 0)),
        ];
        let named: Vec<(&str, &LedgerConfig)> = ledgers
            .iter()
            .map(|(name, config)| (*name, config))
            .collect();
        let refused: Vec<String> = ledgers_in_conflict(&named, 3)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            refused,
            ["b", "c", "e", "g"],
            "a, d and f are served; g is the fourth"
        );
        assert!(ledgers_in_conflict(&named[..1], MAX_LEDGERS).is_empty());
    }

    /// 003: `ledgersDir` is held to the `ledgerPath` rule (no `..`, under the
    /// working directory), the config file's ledger may not sit inside it,
    /// `maxLedgers` is 1 to [`MAX_LEDGERS`], and `http.maxRequestsPerLedger`
    /// (default 64) is at least 1.
    ///
    /// Bug-catch: let `ledgerPath` sit in `ledgersDir` and a folder named for
    /// its directory is the same ledger twice.
    #[test]
    fn ledgers_dir_and_max_ledgers_are_checked() {
        for (fields, expected) in [
            (
                r#""ledgersDir": "../elsewhere""#,
                "ledgersDir must not contain",
            ),
            (
                r#""ledgersDir": "./data""#,
                "ledgerPath must not be inside ledgersDir",
            ),
            (r#""maxLedgers": 0"#, "maxLedgers must be between"),
            (r#""maxLedgers": 101"#, "maxLedgers must be between"),
            (
                r#""http": { "maxRequestsPerLedger": 0 }"#,
                "http.maxRequestsPerLedger must be between",
            ),
            (
                r#""http": { "maxRequestsPerLedger": 65537 }"#,
                "http.maxRequestsPerLedger must be between",
            ),
        ] {
            let file = write_temp_config(&format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", {fields} }}"#
            ));
            let Err(error) = NodeConfig::load_from_path(&file.path().to_path_buf()) else {
                panic!("{fields}: refused");
            };
            assert!(format!("{error}").contains(expected), "{fields}: {error}");
        }
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("defaults");
        assert_eq!(
            (config.ledgers_dir.as_str(), config.max_ledgers),
            ("./data/ledgers", 100)
        );
        assert_eq!(config.http.max_requests_per_ledger, 64);
    }

    /// `auth.adminNodes` (002-users-and-roles): EndpointIds, loaded in the
    /// spelling access records carry; an entry that is not one, or an empty
    /// list (which would silently ignore every access record), is refused, and
    /// so is the setting on a node that does not sign.
    ///
    /// Bug-catch: accept an unparsable entry and it matches no node, so every
    /// grant is silently ignored.
    #[test]
    fn test_admin_nodes_are_endpoint_ids() {
        let node = iroh::SecretKey::generate().public().to_string();
        let config_with = |nodes: &str| {
            format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", "signing": {{ "enabled": true }},
                "p2p": {{ "meshId": "my-org/ledger" }}, "auth": {{ "adminNodes": {nodes} }} }}"#
            )
        };
        let file = write_temp_config(&config_with(&format!(r#"["{node}"]"#)));
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("loads");
        assert_eq!(
            config.ledger_config().admin_node_ids().expect("ids"),
            Some([node.clone()].into())
        );
        for (bad, expected) in [
            (r#"["not-a-node"]"#, "is not an EndpointId"),
            ("[]", "auth.adminNodes is empty"),
        ] {
            let file = write_temp_config(&config_with(bad));
            let Err(error) = NodeConfig::load_from_path(&file.path().to_path_buf()) else {
                panic!("{bad}: refused");
            };
            assert!(format!("{error}").contains(expected), "{bad}: {error}");
        }
        // Without signing nothing proves a record's author (review I-2).
        let file = write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean", "auth": {{ "adminNodes": ["{node}"] }} }}"#
        ));
        let Err(error) = NodeConfig::load_from_path(&file.path().to_path_buf()) else {
            panic!("adminNodes without signing: refused");
        };
        assert!(
            format!("{error}").contains("needs signing.enabled"),
            "{error}"
        );
    }

    #[test]
    fn test_invalid_bootstrap_endpoint_id_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "p2p": { "enabled": true, "bootstrapEndpointIds": ["not-an-id"], "swarmTopic": "my-org/ledger" } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("bootstrapEndpointIds"));
    }

    #[test]
    fn test_default_swarm_topic_rejected_on_public_bind() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "p2p": { "enabled": true } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("swarmTopic"));
    }

    #[test]
    fn test_default_swarm_topic_rejected_on_loopback() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "p2p": { "enabled": true } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("swarmTopic"));
    }

    #[test]
    fn test_p2p_without_signing_rejected() {
        // H3: a valid P2P config (non-default swarm topic, valid bootstrap) must
        // still be refused when signing is off, closing the author-spoofing hole.
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "p2p": { "enabled": true, "swarmTopic": "my-org/ledger" }, "signing": { "enabled": false } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("signing.enabled must be true"));
    }

    #[test]
    fn test_p2p_with_signing_accepted() {
        // The same config with signing on must load.
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "p2p": { "enabled": true, "swarmTopic": "my-org/ledger", "meshId": "my-org/ledger" }, "signing": { "enabled": true } }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).unwrap();
        assert!(config.p2p.enabled);
        assert!(config.signing.enabled);
    }

    #[test]
    fn test_sample_api_key_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "auth": { "enabled": true, "apiKey": "change-me-docker-api-key" } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("change-me-docker-api-key"));
    }

    // ── L-08: API-key denylist + minimum length ──────────────────────────

    /// Load a config whose only interesting field is `auth.apiKey`.
    ///
    /// `public_bind` picks between the two shapes that reach the key checks: a
    /// non-loopback bind (which also needs `tls.mode` and `allowedHosts` to get
    /// past the M-2 / H-01 rules) and the default loopback bind.
    fn load_with_api_key(api_key: &str, public_bind: bool) -> Result<NodeConfig, ConfigError> {
        let body = if public_bind {
            format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "tls": {{ "mode": "terminated" }}, "allowedHosts": ["ledger.example.com"], "auth": {{ "enabled": true, "apiKey": "{api_key}" }} }}"#
            )
        } else {
            format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", "auth": {{ "enabled": true, "apiKey": "{api_key}" }} }}"#
            )
        };
        let file = write_temp_config(&body);
        NodeConfig::load_from_path(&file.path().to_path_buf())
    }

    /// Every sample or placeholder on the denylist is refused on a public bind,
    /// and the error names the value so the operator knows what to change.
    #[test]
    fn test_denylisted_api_keys_refused_on_public_bind() {
        for sample in FORBIDDEN_API_KEYS {
            let error = load_with_api_key(sample, true)
                .err()
                .unwrap_or_else(|| panic!("{sample:?} must not boot a public node"));
            let message = format!("{error}");
            assert!(
                message.contains("auth.apiKey"),
                "the error must name the field for {sample:?}: {message}"
            );
            assert!(
                message.contains(sample),
                "the error must name the offending value for {sample:?}: {message}"
            );
        }
    }

    /// The README's "Full Config (All Options)" key is the one H-5 missed: it is
    /// the value operators copy, and it booted a public node until L-08.
    #[test]
    fn test_readme_sample_api_key_refused() {
        let error =
            load_with_api_key("my-secret-key-here", true).expect_err("README sample must not boot");
        assert!(format!("{error}").contains("my-secret-key-here"));
    }

    /// The denylist is a set of *published strings*, so their casing is not a
    /// defence — `ChangeMe` is exactly as public as `changeme`.
    #[test]
    fn test_api_key_denylist_is_case_insensitive() {
        for spelling in ["CHANGEME", "ChangeMe", "My-Secret-Key-Here", "  changeme  "] {
            assert!(
                load_with_api_key(spelling, true).is_err(),
                "{spelling:?} must be refused"
            );
        }
    }

    /// A key shorter than the floor is refused, and the error states both the
    /// rule and the offending length.
    #[test]
    fn test_short_api_key_refused() {
        let fifteen = "abcdefghijklmno";
        assert_eq!(fifteen.len(), 15, "fixture must be one byte short");

        let error = load_with_api_key(fifteen, true).expect_err("15 bytes must be refused");
        let message = format!("{error}");
        assert!(message.contains("auth.apiKey"), "{message}");
        assert!(
            message.contains("16"),
            "the error must name the floor: {message}"
        );
        assert!(
            message.contains("got 15"),
            "the error must name the length: {message}"
        );
    }

    /// Exactly at the floor is accepted — the rule is "at least", not "more than".
    #[test]
    fn test_api_key_at_minimum_length_accepted() {
        let sixteen = "abcdefghijklmnop";
        assert_eq!(sixteen.len(), MIN_API_KEY_BYTES);

        let config = load_with_api_key(sixteen, true).expect("16 bytes is exactly the floor");
        assert_eq!(config.auth.api_key, sixteen);
    }

    /// A realistic generated key boots a public node unchanged.
    #[test]
    fn test_strong_api_key_accepted_on_public_bind() {
        let strong = "7f3a9c1e5b08d24617ae9f0c3b5d8e21";
        assert_eq!(strong.len(), 32);

        let config = load_with_api_key(strong, true).expect("a 32-byte key must boot");
        assert_eq!(config.auth.api_key, strong);
    }

    /// House-rule gating: both checks hang off `auth.enabled`, with no bind
    /// condition — exactly like the H-5 check they extend. A loopback node with
    /// a published sample key, or a five-byte one, is refused too.
    #[test]
    fn test_weak_api_keys_refused_on_loopback_as_well() {
        assert!(
            load_with_api_key("changeme", false).is_err(),
            "a denylisted key must be refused on loopback too"
        );
        assert!(
            load_with_api_key("short", false).is_err(),
            "a short key must be refused on loopback too"
        );
        assert!(
            load_with_api_key("7f3a9c1e5b08d24617ae9f0c3b5d8e21", false).is_ok(),
            "a strong key must still boot on loopback"
        );
    }

    /// With auth off there is no key to judge, so neither rule fires — otherwise
    /// a `"test"` left in a disabled `auth` block would block boot for nothing.
    #[test]
    fn test_api_key_rules_do_not_fire_when_auth_is_disabled() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "auth": { "enabled": false, "apiKey": "test" } }"#,
        );
        NodeConfig::load_from_path(&file.path().to_path_buf())
            .expect("auth disabled means the key is inert");
    }

    /// Keep the denylist honest as the docs change: every `apiKey` value the
    /// README publishes must be on it. A new sample added to the README without
    /// a matching denylist entry re-creates L-08 exactly.
    #[test]
    fn test_every_api_key_published_in_the_readme_is_denylisted() {
        let readme = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../README.md"),
        )
        .expect("README.md must be readable");

        let mut found = 0;
        for fragment in readme.split("\"apiKey\":").skip(1) {
            let Some(rest) = fragment.trim_start().strip_prefix('"') else {
                continue;
            };
            let Some(value) = rest.split('"').next() else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            found += 1;
            assert!(
                forbidden_api_key_match(value).is_some(),
                "README publishes apiKey {value:?}, which is not on the L-08 denylist"
            );
        }
        assert!(found >= 1, "expected to find a sample apiKey in the README");
    }

    // ── L-50: auth.apiKey must be sendable as a header ──────────────────────

    #[test]
    fn test_non_header_safe_api_keys_refused_at_boot() {
        // Each of these booted pre-T55 and then 401'd every request forever:
        // no client can send (or have delivered intact) a matching header.
        for (label, key) in [
            ("non-ASCII", "clé-secrète-0123456789abcdef"),
            ("control character", "abcdefghij\u{0007}klmnopqrstuv"),
            ("tab", "abcdefghij\tklmnopqrstuvwxyz"),
            ("leading space", " abcdefghijklmnopqrstuvwxyz"),
            ("trailing space", "abcdefghijklmnopqrstuvwxyz "),
        ] {
            let json = serde_json::json!({
                "ledgerPath": "./data/ledger.bean",
                "auth": { "enabled": true, "apiKey": key }
            });
            let file = write_temp_config(&json.to_string());
            let error = NodeConfig::load_from_path(&file.path().to_path_buf())
                .expect_err(&format!("a {label} key must be refused at boot (L-50)"));
            let message = format!("{error}");
            assert!(message.contains("auth.apiKey"), "{label}: {message}");
            assert!(
                !message.contains(key.trim()),
                "{label}: the error must not echo the key: {message}"
            );
        }
    }

    #[test]
    fn test_header_safe_api_key_with_inner_space_accepted() {
        // Printable ASCII including an inner space is a sendable header value.
        load_with_api_key("correct horse battery staple", false)
            .expect("an inner space is header-safe");
    }

    // ── L-52: "null" is never an allowed origin ─────────────────────────────

    #[test]
    fn test_null_cors_origin_rejected() {
        for spelling in ["null", "NULL"] {
            let file = write_temp_config(&format!(
                r#"{{ "ledgerPath": "./data/ledger.bean", "cors": {{ "allowedOrigins": ["{spelling}"] }} }}"#
            ));
            let error = NodeConfig::load_from_path(&file.path().to_path_buf())
                .expect_err("Origin null must not be configurable (L-52)");
            assert!(format!("{error}").contains("\"null\""), "{error}");
        }
    }

    #[test]
    fn test_parent_dir_ledger_path_rejected() {
        let file = write_temp_config(r#"{ "ledgerPath": "../outside.bean" }"#);
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("ledgerPath"));
    }

    #[test]
    fn test_absolute_ledger_path_outside_cwd_rejected() {
        let file = write_temp_config(r#"{ "ledgerPath": "/etc/passwd" }"#);
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        if std::env::current_dir()
            .map(|cwd| cwd == std::path::Path::new("/"))
            .unwrap_or(false)
        {
            return;
        }
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("ledgerPath"));
    }

    #[test]
    fn test_public_bind_without_tls_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0" }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("tls.mode"));
    }

    #[test]
    fn test_allowed_hosts_defaults_to_empty() {
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert!(config.allowed_hosts.is_empty());
    }

    #[test]
    fn test_allowed_hosts_accepted() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "allowedHosts": ["ledger.example.com", "10.0.0.7"] }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert_eq!(config.allowed_hosts, vec!["ledger.example.com", "10.0.0.7"]);
    }

    #[test]
    fn test_allowed_hosts_with_scheme_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "allowedHosts": ["https://x"] }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("without a scheme or port"));
    }

    #[test]
    fn test_allowed_hosts_with_slash_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "allowedHosts": ["example.com/graphql"] }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("allowedHosts"));
    }

    /// A config listing `hosts` in `allowedHosts`.
    fn load_with_allowed_hosts(hosts: &[&str]) -> Result<NodeConfig, ConfigError> {
        let file = write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean", "allowedHosts": {} }}"#,
            serde_json::json!(hosts)
        ));
        NodeConfig::load_from_path(&file.path().to_path_buf())
    }

    /// 0922-v2 §5: an entry with a port, IPv6 brackets or a trailing dot used
    /// to boot and then 403 every request through that name. Each is now a
    /// `ConfigError::Validation` that says why and names the spelling to use.
    #[test]
    fn test_allowed_hosts_entries_the_guard_cannot_match_are_refused() {
        for (entry, says, instead) in [
            (
                "ledger.example.com:443",
                "without a port",
                "ledger.example.com",
            ),
            ("10.0.0.7:4000", "without a port", "10.0.0.7"),
            ("[::1]:4000", "without a port", "::1"),
            ("[2001:db8::7]", "must not be bracketed", "2001:db8::7"),
            (
                "ledger.example.com.",
                "must not end with a dot",
                "ledger.example.com",
            ),
        ] {
            let error = load_with_allowed_hosts(&[entry])
                .map(|_| ())
                .expect_err(&format!("{entry} must be refused at boot"));
            assert!(
                matches!(error, ConfigError::Validation(_)),
                "{entry}: {error}"
            );
            let message = error.to_string();
            assert!(message.contains("allowedHosts"), "{entry}: {message}");
            assert!(message.contains(says), "{entry}: {message}");
            assert!(
                message.contains(&format!("list \"{instead}\" instead")),
                "{entry}: the error names the spelling that works: {message}"
            );
        }
    }

    /// The bare spellings the guard compares against still load, IPv6
    /// literals included (every colon of a bare literal belongs to it).
    #[test]
    fn test_allowed_hosts_bare_names_and_literals_still_load() {
        let config = load_with_allowed_hosts(&["ledger.example.com", "10.0.0.7", "2001:db8::7"])
            .expect("bare hosts are the documented form");
        assert_eq!(config.allowed_hosts.len(), 3);
    }

    #[test]
    fn test_allowed_hosts_empty_entry_rejected() {
        let file =
            write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean", "allowedHosts": [""] }"#);
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("empty entries"));
    }

    #[test]
    fn test_public_bind_without_allowed_hosts_rejected() {
        // H-01: a non-loopback bind with no Host allowlist would 403 every
        // request, so it must fail closed at boot instead.
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "tls": { "mode": "terminated" }, "auth": { "enabled": true, "apiKey": "unit-test-api-key-0123456789abcd" } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("allowedHosts must list the hostname(s)"));
    }

    #[test]
    fn test_public_bind_with_allowed_hosts_accepted() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "tls": { "mode": "terminated" }, "auth": { "enabled": true, "apiKey": "unit-test-api-key-0123456789abcd" }, "allowedHosts": ["ledger.example.com"] }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert_eq!(config.allowed_hosts, vec!["ledger.example.com"]);
    }

    #[test]
    fn test_allowed_host_set_default_loopback() {
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        let hosts = config.allowed_host_set();
        assert!(hosts.contains("localhost"));
        assert!(hosts.contains("127.0.0.1"));
        assert!(hosts.contains("::1"));
    }

    #[test]
    fn test_allowed_host_set_includes_bind_address_and_entries() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "127.0.0.1", "allowedHosts": ["Ledger.Example.COM"] }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        let hosts = config.allowed_host_set();
        assert!(hosts.contains("127.0.0.1"));
        assert!(
            hosts.contains("ledger.example.com"),
            "allowedHosts entries are lowercased: {hosts:?}"
        );
    }

    #[test]
    fn test_allowed_host_set_omits_wildcard_bind() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "tls": { "mode": "terminated" }, "auth": { "enabled": true, "apiKey": "unit-test-api-key-0123456789abcd" }, "allowedHosts": ["ledger.example.com"] }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        let hosts = config.allowed_host_set();
        assert!(
            !hosts.contains("0.0.0.0"),
            "a wildcard bind names no host a client could send: {hosts:?}"
        );
        assert!(hosts.contains("ledger.example.com"));
    }

    // — trustedProxies (M-04) —

    #[test]
    fn test_trusted_proxies_defaults_to_empty() {
        // Fail closed: with no entry, X-Forwarded-For is trusted from nobody.
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert!(config.trusted_proxies.is_empty());
        assert!(config.trusted_proxy_set().is_empty());
    }

    #[test]
    fn test_trusted_proxies_accepted() {
        let file = write_temp_config(
            // A node with a proxy in front is public (005): its key and host.
            r#"{ "ledgerPath": "./data/ledger.bean", "trustedProxies": ["10.0.0.1", "2001:db8::1"], "allowedHosts": ["ledger.example.com"] }"#,
        );
        let config = NodeConfig::load_from_path_with_env_api_key(
            file.path(),
            Some("unit-test-api-key-0123456789abcd".to_owned()),
        )
        .expect("should load");
        assert_eq!(config.trusted_proxies, vec!["10.0.0.1", "2001:db8::1"]);
        let trusted = config.trusted_proxy_set();
        assert_eq!(trusted.len(), 2);
        assert!(trusted.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(trusted.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_invalid_trusted_proxy_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "trustedProxies": ["not-an-ip"] }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(
            error_message.contains("trustedProxies") && error_message.contains("not-an-ip"),
            "error should name the key and the offending entry: {error_message}"
        );
    }

    #[test]
    fn test_trusted_proxy_with_port_rejected() {
        // A "host:port" entry never matches a peer address, so it would trust
        // nothing while looking configured.
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "trustedProxies": ["10.0.0.1:8080"] }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("trustedProxies"));
    }

    #[test]
    fn test_trusted_proxy_cidr_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "trustedProxies": ["10.0.0.0/8"] }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("trustedProxies"));
    }

    #[test]
    fn test_invalid_relay_mode_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "p2p": { "relayMode": "mdns" } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("relayMode"));
    }

    // ── L-22: anti-entropy interval floor ────────────────────────────────

    fn load_with_anti_entropy_interval(interval: u64) -> Result<NodeConfig, ConfigError> {
        let file = write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean", "p2p": {{ "antiEntropyIntervalMilliseconds": {interval} }} }}"#
        ));
        NodeConfig::load_from_path(&file.path().to_path_buf())
    }

    #[test]
    fn test_anti_entropy_interval_zero_rejected() {
        // `tokio::time::interval(Duration::ZERO)` panics, and it panics inside
        // the spawned replication task — so a `0` here used to kill replication
        // silently while the node kept serving GraphQL.
        let error_message = format!(
            "{}",
            load_with_anti_entropy_interval(0).expect_err("0 ms must be refused at boot")
        );
        assert!(
            error_message.contains("antiEntropyIntervalMilliseconds"),
            "the error must name the field: {error_message}"
        );
        assert!(
            error_message.contains("100"),
            "the error must name the floor: {error_message}"
        );
        assert!(
            error_message.contains("got 0"),
            "the error must name the offending value: {error_message}"
        );
    }

    #[test]
    fn test_anti_entropy_interval_below_floor_rejected() {
        let error_message = format!(
            "{}",
            load_with_anti_entropy_interval(99).expect_err("99 ms is below the floor")
        );
        assert!(error_message.contains("antiEntropyIntervalMilliseconds"));
        assert!(error_message.contains("got 99"));
    }

    #[test]
    fn test_anti_entropy_interval_at_floor_accepted() {
        let config = load_with_anti_entropy_interval(100).expect("100 ms is exactly the floor");
        assert_eq!(config.p2p.anti_entropy_interval_milliseconds, 100);
    }

    #[test]
    fn test_anti_entropy_interval_default_is_above_the_floor() {
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert_eq!(config.p2p.anti_entropy_interval_milliseconds, 5000);
    }

    #[test]
    fn test_shipped_sample_configs_still_validate() {
        // The floor must not brick the configs in `config/` or `deploy/`, which
        // are the copy-paste starting points every operator uses.
        let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut checked = 0;
        for directory in ["config", "deploy"] {
            let Ok(entries) = std::fs::read_dir(repository_root.join(directory)) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let config: NodeConfig = serde_json::from_str(
                    &std::fs::read_to_string(&path).expect("sample config must be readable"),
                )
                .unwrap_or_else(|error| panic!("{} does not parse: {error}", path.display()));
                assert!(
                    config.p2p.anti_entropy_interval_milliseconds
                        >= MIN_ANTI_ENTROPY_INTERVAL_MILLISECONDS,
                    "{} sets antiEntropyIntervalMilliseconds below the floor",
                    path.display()
                );
                // The `http` bounds are the other validation surface a shipped
                // config can fall foul of. Every sample currently omits the
                // section entirely, so this asserts the *defaults* are inside
                // their own bounds — which is exactly the regression to catch
                // if someone later tightens a bound past the shipped default.
                for (field, seconds) in [
                    (
                        "http.headerReadTimeoutSeconds",
                        config.http.header_read_timeout_seconds,
                    ),
                    (
                        "http.requestTimeoutSeconds",
                        config.http.request_timeout_seconds,
                    ),
                ] {
                    assert!(
                        (MIN_HTTP_TIMEOUT_SECONDS..=MAX_HTTP_TIMEOUT_SECONDS).contains(&seconds),
                        "{} sets {field} to {seconds}, outside \
                         {MIN_HTTP_TIMEOUT_SECONDS}..={MAX_HTTP_TIMEOUT_SECONDS}",
                        path.display()
                    );
                }
                assert!(
                    (MIN_MAX_CONNECTIONS..=MAX_MAX_CONNECTIONS)
                        .contains(&config.http.max_connections),
                    "{} sets http.maxConnections to {}, outside \
                     {MIN_MAX_CONNECTIONS}..={MAX_MAX_CONNECTIONS}",
                    path.display(),
                    config.http.max_connections
                );
                // R-7: the anti-entropy bounds, the newest validation surface.
                config
                    .ledger_config()
                    .validate_anti_entropy_bounds()
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                checked += 1;
            }
        }
        assert!(checked >= 4, "expected to find the shipped sample configs");
    }

    /// The production template (`deploy/gl-node.production.json`, decision 1 of
    /// `docs/build-log/001-peer-discovery`) runs `relayMode: "custom"` with
    /// neither a relay nor an address, so — even with the mesh's topic and id
    /// chosen — it refuses to boot, naming both ways out, until the operator
    /// picks the mesh's own relay or its peers' addresses; it never falls back
    /// to n0. With a `relayUrl` it loads.
    ///
    /// Bug-catch: ship the template with `"n0"` (or drop the "custom needs a
    /// relay or addresses" rule) and a production node quietly uses n0.
    #[test]
    fn test_production_template_refuses_to_boot_until_a_relay_or_addresses_are_chosen() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/gl-node.production.json");
        let mut template: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("production template"))
                .expect("the template is JSON");
        // What the operator must choose anyway, plus a ledger path this test's
        // working directory holds (the template's are the Docker image's).
        template["ledgerPath"] = "./data/ledger.bean".into();
        template["ledgersDir"] = "./data/ledgers".into();
        template["p2p"]["swarmTopic"] = "openledger/production-test".into();
        template["p2p"]["meshId"] = "8a4f2c1e-0d3b-4c5a-9e7f-1b2d3c4e5f60".into();
        let load = |template: &serde_json::Value| {
            let file = write_temp_config(&template.to_string());
            NodeConfig::load_from_path_with_env_api_key(
                file.path(),
                Some("unit-test-api-key-0123456789abcd".to_owned()),
            )
        };

        let Err(error) = load(&template) else {
            panic!("the template must not boot before a relay or addresses are chosen");
        };
        let message = format!("{error}");
        assert!(
            message.contains("p2p.relayUrl") && message.contains("p2p.peerAddresses"),
            "{message}"
        );

        template["p2p"]["relayUrl"] = "https://relay.example.com".into();
        load(&template).expect("with the mesh's relay the template boots");
    }

    /// 003 step 5: the image's configs keep the node's other ledgers in its
    /// volume, beside the config file's ledger and not around it:
    /// `ledgersDir` under `/data` (the image's working directory, which a
    /// node's paths must stay under, and the volume), `ledgerPath` outside it.
    ///
    /// Bug-catch: point a template's `ledgersDir` outside `/data` and the
    /// image refuses to boot — or, mounted elsewhere, a container rebuilt
    /// loses every company but the first.
    #[test]
    fn the_image_configs_keep_their_ledgers_in_the_volume() {
        for file in ["gl-node.production.json", "gl-node.docker.json"] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../deploy")
                .join(file);
            let config: NodeConfig =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("shipped config"))
                    .expect("shipped config parses");
            let ledgers_dir = Path::new(&config.ledgers_dir);
            assert_eq!(ledgers_dir, Path::new("/data/ledgers"), "{file}");
            assert!(
                !Path::new(&config.ledger_path).starts_with(ledgers_dir),
                "{file}: ledgerPath inside ledgersDir"
            );
        }
    }

    /// R-9: the shipped docker config sets `meshId` to its own `swarmTopic`
    /// byte for byte — the only value that keeps the stack's already-signed
    /// history verifying — and both pass the signature-domain rules.
    #[test]
    fn test_docker_config_pins_mesh_id_to_its_swarm_topic() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/gl-node.docker.json");
        let config: NodeConfig =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("docker config"))
                .expect("docker config parses");
        assert_eq!(
            config.p2p.mesh_id.as_deref(),
            Some(config.p2p.swarm_topic.as_str()),
            "meshId must equal swarmTopic verbatim, or the stack's signatures stop verifying"
        );
        assert_eq!(config.p2p.signature_domain(), "openledger/docker-dev");
        NodeConfig::validate_signature_domain("p2p.meshId", config.p2p.signature_domain(), "")
            .expect("the shipped meshId is a well-formed domain");
    }

    // ── L-23 / R-9: meshId on a signing node ──────────────────────────

    /// A signing node on a fixed topic, with or without a `meshId`.
    fn signing_config(topic: &str, mesh_id: Option<&str>, signing: bool) -> NodeConfig {
        let mesh_field = match mesh_id {
            Some(value) => format!(r#", "meshId": {}"#, serde_json::json!(value)),
            None => String::new(),
        };
        let file = write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean", "signing": {{ "enabled": {signing} }},
                  "p2p": {{ "swarmTopic": {}{mesh_field} }} }}"#,
            serde_json::json!(topic)
        ));
        NodeConfig::load_from_path(&file.path().to_path_buf()).expect("valid config")
    }

    /// L-23: `meshId` unset on a signing node is refused at boot, and the
    /// refusal leads with the remedy that keeps an existing mesh's history (the
    /// current `swarmTopic`, verbatim) — without printing the topic, which on
    /// that path was the join credential and the domain.
    ///
    /// Bug-catch: drop the refusal and the signing node boots on the topic
    /// fallback.
    #[test]
    fn test_mesh_id_unset_on_a_signing_node_is_refused_with_the_verbatim_remedy() {
        let topic = "acme/secret-join-topic-77";
        let file = write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean", "signing": {{ "enabled": true }},
                  "p2p": {{ "swarmTopic": {} }} }}"#,
            serde_json::json!(topic)
        ));
        let error = NodeConfig::load_from_path(&file.path().to_path_buf())
            .expect_err("a signing node must name its mesh");
        let message = error.to_string();
        assert!(message.contains("p2p.meshId is required"), "{message}");
        assert!(
            message.contains(
                "set it to your current p2p.swarmTopic, copied byte for byte on every node — \
                 any other value invalidates every signature already in the mesh"
            ),
            "the refusal leads with the history-preserving value: {message}"
        );
        assert!(!message.contains(topic), "the topic was printed: {message}");
        // A node that does not sign has no domain to name.
        signing_config(topic, None, false);
    }

    /// No warning once `meshId` is set (any value — the verbatim one included),
    /// and none on a node that does not sign (it has no signatures to lose).
    #[test]
    fn test_mesh_id_set_or_signing_off_does_not_warn() {
        let topic = "acme/secret-join-topic-77";
        for config in [
            signing_config(topic, Some(topic), true),
            signing_config(topic, Some("3f2504e0-4f89-41d3-9a0c-0305e82c3301"), true),
            signing_config(topic, None, false),
        ] {
            let ((), logged) = capture_warnings(|| config.p2p.log_signature_domain());
            assert!(logged.is_empty(), "unexpected warning: {logged}");
        }
    }

    // ── R-7: anti-entropy session bounds ───────────────────────────────

    /// A config setting one `p2p` anti-entropy key to `value`.
    fn load_with_p2p_key(key: &str, value: u64) -> Result<NodeConfig, ConfigError> {
        let file = write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean", "p2p": {{ "{key}": {value} }} }}"#
        ));
        NodeConfig::load_from_path(&file.path().to_path_buf())
    }

    /// Every R-7 key with its floor and ceiling.
    fn anti_entropy_keys() -> [(&'static str, u64, u64); 8] {
        [
            (
                "antiEntropySessionSeconds",
                MIN_ANTI_ENTROPY_SESSION_SECONDS,
                MAX_ANTI_ENTROPY_SESSION_SECONDS,
            ),
            (
                "antiEntropyMaxAdvertPages",
                MIN_ANTI_ENTROPY_MAX_ADVERT_PAGES as u64,
                MAX_ANTI_ENTROPY_MAX_ADVERT_PAGES as u64,
            ),
            (
                "antiEntropyMaxAdvertIdBytes",
                MIN_ANTI_ENTROPY_MAX_ADVERT_ID_BYTES as u64,
                MAX_ANTI_ENTROPY_MAX_ADVERT_ID_BYTES as u64,
            ),
            (
                "antiEntropyMaxSessionFrames",
                MIN_ANTI_ENTROPY_MAX_SESSION_FRAMES as u64,
                MAX_ANTI_ENTROPY_MAX_SESSION_FRAMES as u64,
            ),
            (
                "antiEntropyAcceptBurst",
                u64::from(MIN_ANTI_ENTROPY_ACCEPT_BURST),
                u64::from(MAX_ANTI_ENTROPY_ACCEPT_BURST),
            ),
            (
                "antiEntropyAcceptRefillMilliseconds",
                MIN_ANTI_ENTROPY_ACCEPT_REFILL_MILLISECONDS,
                MAX_ANTI_ENTROPY_ACCEPT_REFILL_MILLISECONDS,
            ),
            (
                "antiEntropyMaxConcurrentExchanges",
                MIN_ANTI_ENTROPY_MAX_CONCURRENT_EXCHANGES as u64,
                MAX_ANTI_ENTROPY_MAX_CONCURRENT_EXCHANGES as u64,
            ),
            (
                "antiEntropySupplyBackoffSeconds",
                MIN_ANTI_ENTROPY_SUPPLY_BACKOFF_SECONDS,
                MAX_ANTI_ENTROPY_SUPPLY_BACKOFF_SECONDS,
            ),
        ]
    }

    /// R-7: each key is refused at boot one below its floor, at 0 and one
    /// above its ceiling — with an error naming the key — and accepted at both
    /// bounds.
    #[test]
    fn test_anti_entropy_bounds_refused_outside_floor_and_ceiling() {
        for (key, min, max) in anti_entropy_keys() {
            for bad in [0, min - 1, max + 1] {
                let error = load_with_p2p_key(key, bad)
                    .map(|_| ())
                    .expect_err(&format!("{key} = {bad} must be refused at boot"));
                let message = error.to_string();
                assert!(
                    message.contains(&format!("p2p.{key}")),
                    "the refusal must name the key: {message}"
                );
            }
            for good in [min, max] {
                load_with_p2p_key(key, good)
                    .unwrap_or_else(|error| panic!("{key} = {good} must be accepted: {error}"));
            }
        }
    }

    /// R-7: an absent key is exactly today's behaviour — the built settings
    /// equal the serve layer's own defaults, which lie inside their bounds.
    #[test]
    fn test_anti_entropy_defaults_are_todays_constants() {
        let config = NodeConfig::load_from_path(
            &write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#)
                .path()
                .to_path_buf(),
        )
        .expect("defaults validate");
        let timeouts = config.p2p.anti_entropy_timeouts();
        let expected = AntiEntropyTimeouts::default();
        assert_eq!(timeouts.session, expected.session);
        assert_eq!(timeouts.session, Duration::from_secs(300));
        assert_eq!(timeouts.io, expected.io);
        assert_eq!(timeouts.connect, expected.connect);
        assert_eq!(timeouts.open_stream, expected.open_stream);
        assert_eq!(timeouts.max_advert_pages, expected.max_advert_pages);
        assert_eq!(timeouts.max_advert_id_bytes, expected.max_advert_id_bytes);
        assert_eq!(timeouts.max_session_frames, expected.max_session_frames);
        // T71: the two keys routed here by T69 default to its constants.
        assert_eq!(timeouts.supply_backoff, expected.supply_backoff);
        assert_eq!(
            timeouts.supply_backoff,
            crate::anti_entropy_alpn::SUPPLY_HEADROOM_BACKOFF
        );
        assert_eq!(timeouts.supply_backoff, Duration::from_secs(60));

        let limits = config.p2p.anti_entropy_limits();
        let expected = AntiEntropyLimits::default();
        assert_eq!(
            limits.max_requests_per_connection,
            expected.max_requests_per_connection
        );
        assert_eq!(limits.max_total_connections, expected.max_total_connections);
        assert_eq!(
            limits.max_connections_per_peer,
            expected.max_connections_per_peer
        );
        assert_eq!(limits.accept_burst, expected.accept_burst);
        assert_eq!(
            limits.accept_refill_interval,
            expected.accept_refill_interval
        );
        assert_eq!(
            limits.max_concurrent_outbound_exchanges,
            crate::connection_limiter::DEFAULT_MAX_CONCURRENT_OUTBOUND_EXCHANGES
        );
        assert_eq!(limits.max_concurrent_outbound_exchanges, 8);
    }

    /// R-7: a set key reaches the settings the handler is built from, and the
    /// frame key reaches BOTH sides' budgets (M-28's mirror).
    #[test]
    fn test_anti_entropy_keys_reach_the_built_settings() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "p2p": {
                "antiEntropySessionSeconds": 120,
                "antiEntropyMaxAdvertPages": 300,
                "antiEntropyMaxAdvertIdBytes": 33554432,
                "antiEntropyMaxSessionFrames": 20000,
                "antiEntropyAcceptBurst": 4,
                "antiEntropyAcceptRefillMilliseconds": 5000,
                "antiEntropyMaxConcurrentExchanges": 3,
                "antiEntropySupplyBackoffSeconds": 90 } }"#,
        );
        let config =
            NodeConfig::load_from_path(&file.path().to_path_buf()).expect("in-bounds values");
        let timeouts = config.p2p.anti_entropy_timeouts();
        assert_eq!(timeouts.session, Duration::from_secs(120));
        assert_eq!(timeouts.max_advert_pages, 300);
        assert_eq!(timeouts.max_advert_id_bytes, 32 * 1024 * 1024);
        assert_eq!(timeouts.max_session_frames, 20_000);
        let limits = config.p2p.anti_entropy_limits();
        assert_eq!(limits.max_requests_per_connection, 20_000);
        assert_eq!(limits.accept_burst, 4);
        assert_eq!(limits.accept_refill_interval, Duration::from_secs(5));
        assert_eq!(limits.max_concurrent_outbound_exchanges, 3);
        assert_eq!(timeouts.supply_backoff, Duration::from_secs(90));
    }

    // ── L-23: p2p.meshId ─────────────────────────────────────────────────

    /// A config carrying `meshId` (or not, when `None`) on a fixed topic.
    fn load_with_mesh_id(mesh_id: Option<&str>) -> Result<NodeConfig, ConfigError> {
        let mesh_field = match mesh_id {
            Some(value) => format!(r#", "meshId": {}"#, serde_json::json!(value)),
            None => String::new(),
        };
        let file = write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean", "p2p": {{ "swarmTopic": "my-org/ledger"{mesh_field} }} }}"#
        ));
        NodeConfig::load_from_path(&file.path().to_path_buf())
    }

    #[test]
    fn test_mesh_id_accepted_and_becomes_the_signature_domain() {
        let config = load_with_mesh_id(Some("3f2504e0-4f89-41d3-9a0c-0305e82c3301"))
            .expect("a UUID meshId must load");
        assert_eq!(
            config.p2p.signature_domain(),
            "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
        );
        assert_eq!(config.p2p.signature_domain_source(), "p2p.meshId");
        assert_ne!(
            config.p2p.signature_domain(),
            config.p2p.swarm_topic,
            "a configured meshId must displace the topic as the domain"
        );
    }

    #[test]
    fn test_absent_mesh_id_falls_back_to_the_swarm_topic() {
        // The compatibility constraint: unset must behave exactly as it did
        // before the field existed, or every already-persisted signature on
        // the deployment stops verifying.
        let config = load_with_mesh_id(None).expect("an absent meshId is the default");
        assert!(config.p2p.mesh_id.is_none());
        assert_eq!(config.p2p.signature_domain(), "my-org/ledger");
        assert_eq!(
            config.p2p.signature_domain_source(),
            "p2p.swarmTopic (meshId unset)"
        );
    }

    #[test]
    fn test_empty_mesh_id_rejected() {
        let error_message = format!(
            "{}",
            load_with_mesh_id(Some("")).expect_err("an empty meshId must be refused")
        );
        assert!(error_message.contains("p2p.meshId"), "{error_message}");
        assert!(
            error_message.contains("UUID"),
            "the error should recommend a UUID: {error_message}"
        );
    }

    #[test]
    fn test_whitespace_only_mesh_id_rejected() {
        let error_message = format!(
            "{}",
            load_with_mesh_id(Some("   ")).expect_err("a blank meshId must be refused")
        );
        assert!(error_message.contains("p2p.meshId"), "{error_message}");
    }

    #[test]
    fn test_mesh_id_with_surrounding_whitespace_rejected() {
        // Refused rather than trimmed: the value is compared byte-for-byte on
        // both sides of a signature, so silently trimming here would make two
        // nodes disagree about the domain depending on how each was edited.
        let error_message = format!(
            "{}",
            load_with_mesh_id(Some(" mesh-a ")).expect_err("padded meshId must be refused")
        );
        assert!(error_message.contains("whitespace"), "{error_message}");
    }

    #[test]
    fn test_mesh_id_with_invalid_characters_rejected() {
        let error_message = format!(
            "{}",
            load_with_mesh_id(Some("mesh a")).expect_err("a space inside meshId must be refused")
        );
        assert!(error_message.contains("p2p.meshId"), "{error_message}");
        assert!(
            error_message.contains("invalid character"),
            "{error_message}"
        );

        for rejected in ["mesh\u{0}a", "mesh\na", "mesh\u{00e9}", "mesh#a"] {
            assert!(
                load_with_mesh_id(Some(rejected)).is_err(),
                "meshId {rejected:?} must be refused"
            );
        }
    }

    #[test]
    fn test_mesh_id_length_bound() {
        let at_bound = "a".repeat(MAX_SIGNATURE_DOMAIN_BYTES);
        assert!(
            load_with_mesh_id(Some(&at_bound)).is_ok(),
            "exactly the bound must be accepted"
        );

        let over_bound = "a".repeat(MAX_SIGNATURE_DOMAIN_BYTES + 1);
        let error_message = format!(
            "{}",
            load_with_mesh_id(Some(&over_bound)).expect_err("over the bound must be refused")
        );
        assert!(error_message.contains("p2p.meshId"), "{error_message}");
        assert!(
            error_message.contains(&MAX_SIGNATURE_DOMAIN_BYTES.to_string()),
            "the error must name the bound: {error_message}"
        );
    }

    #[test]
    fn test_mesh_id_accepts_non_uuid_identifiers() {
        // A UUID is the recommendation, not a requirement — an operator with an
        // existing naming scheme must not be forced to abandon it.
        for accepted in [
            "acme-prod-ledger",
            "acme:prod:ledger",
            "acme.prod/ledger-01",
            "MESH_A",
        ] {
            assert!(
                load_with_mesh_id(Some(accepted)).is_ok(),
                "meshId {accepted:?} must be accepted"
            );
        }
    }

    #[test]
    fn test_mesh_id_validated_even_with_p2p_disabled() {
        // Same reasoning as the L-22 interval floor: it is a boot-time typo
        // either way, and the domain is consumed whenever signing is enabled —
        // with or without p2p.
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "p2p": { "enabled": false, "meshId": "bad mesh" } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(
            result.is_err(),
            "a malformed meshId must be refused even with p2p disabled"
        );
    }

    // ── M-31: the *resolved* signature domain, not just the meshId field ─────

    /// A config with an explicit `swarmTopic`, optionally carrying a `meshId`.
    ///
    /// `p2p.enabled` is left false so these exercise the validation itself
    /// rather than the p2p-only uniqueness and signing gates; the enabled path
    /// gets its own test below.
    fn load_with_swarm_topic(
        swarm_topic: &str,
        mesh_id: Option<&str>,
    ) -> Result<NodeConfig, ConfigError> {
        let mesh_field = match mesh_id {
            Some(value) => format!(r#", "meshId": {}"#, serde_json::json!(value)),
            None => String::new(),
        };
        let file = write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean", "p2p": {{ "swarmTopic": {}{mesh_field} }} }}"#,
            serde_json::json!(swarm_topic)
        ));
        NodeConfig::load_from_path(&file.path().to_path_buf())
    }

    /// Values no signature domain may take, with the reason each is refused.
    ///
    /// Shared by the two tests below so the `meshId` path and the `swarmTopic`
    /// path are provably held to the *same* list rather than to two lists that
    /// drift.
    fn malformed_domain_values() -> Vec<(String, &'static str)> {
        vec![
            (String::new(), "empty"),
            ("   ".to_owned(), "whitespace only"),
            (
                "my-org/ledger ".to_owned(),
                "trailing space — the M-31 headline case",
            ),
            (" my-org/ledger".to_owned(), "leading space"),
            ("my-org/ledger\t".to_owned(), "trailing tab"),
            ("my-org/ledger\n".to_owned(), "trailing newline"),
            ("my org/ledger".to_owned(), "interior space"),
            (
                "my-org|ledger".to_owned(),
                "the v3 signature field separator (L-06)",
            ),
            ("my-org/ledger\u{0}".to_owned(), "NUL"),
            ("my-org/l\u{00e9}dger".to_owned(), "non-ASCII"),
            (
                "a".repeat(MAX_SIGNATURE_DOMAIN_BYTES + 1),
                "over the length cap",
            ),
        ]
    }

    #[test]
    fn test_malformed_swarm_topic_refused_at_boot_when_it_is_the_domain() {
        // M-31, the default path in every shipped config: `meshId` is unset, so
        // `swarmTopic` IS the signature domain. Before this it got exactly one
        // check — "must not be the public default" — which is about uniqueness,
        // not well-formedness. A trailing space therefore booted happily and
        // partitioned the mesh, surfacing much later as InvalidSignature.
        for (value, reason) in malformed_domain_values() {
            let error = load_with_swarm_topic(&value, None)
                .err()
                .unwrap_or_else(|| panic!("swarmTopic {value:?} ({reason}) must be refused"));
            let message = format!("{error}");
            assert!(
                message.contains("p2p.swarmTopic"),
                "the error must name the field the operator has to fix ({reason}): {message}"
            );
            // L-56: the topic is the gossip join credential and, here, the
            // signature domain; the boot error is logged, so it must never
            // carry the value. (An empty or all-whitespace value has nothing
            // to leak, and `contains("")` is vacuously true.)
            if !value.trim().is_empty() {
                assert!(
                    !message.contains(value.trim()),
                    "the error must not echo the topic ({reason}): {message}"
                );
            }
        }
    }

    /// L-56: the whitespace refusal locates the typo without printing the
    /// value — the redacted shape and the byte offset of the whitespace.
    #[test]
    fn test_padded_signature_domain_error_names_the_offset_not_the_value() {
        let topic = "acme/secret-join-topic-77";
        for (padded, offset) in [(format!("{topic} "), topic.len()), (format!(" {topic}"), 0)] {
            let message = load_with_swarm_topic(&padded, None)
                .expect_err("a padded topic must be refused")
                .to_string();
            assert!(!message.contains(topic), "value echoed: {message}");
            assert!(
                message.contains(&format!("whitespace at byte {offset}")),
                "the offset locates the typo: {message}"
            );
            assert!(
                message.contains(&format!("{} bytes", padded.len())),
                "the redacted shape names the length: {message}"
            );
            let mesh_message = load_with_mesh_id(Some(&padded))
                .expect_err("a padded meshId must be refused")
                .to_string();
            assert!(
                !mesh_message.contains(topic),
                "meshId echoed: {mesh_message}"
            );
        }
    }

    #[test]
    fn test_swarm_topic_error_says_it_is_the_signature_domain() {
        // The whole failure mode M-31 describes is that the operator is told
        // nothing until a peer reports InvalidSignature. The boot error has to
        // say, at the point of refusal, that this string is signed with.
        let message = format!(
            "{}",
            load_with_swarm_topic("my-org/ledger ", None)
                .expect_err("padded topic must be refused")
        );
        assert!(message.contains("whitespace"), "{message}");
        assert!(
            message.contains("signature domain"),
            "the error must explain the value's role: {message}"
        );
        assert!(
            message.contains("refused rather than trimmed"),
            "and that it is deliberately not normalized: {message}"
        );
    }

    #[test]
    fn test_resolved_signature_domain_is_validated_whichever_field_it_came_from() {
        // The rule must not be bypassable by leaving `meshId` unset (M-31), and
        // it must not be bypassable by setting one either: whichever field
        // `signature_domain()` resolves to, the same list applies.
        for (value, reason) in malformed_domain_values() {
            assert!(
                load_with_mesh_id(Some(&value)).is_err(),
                "meshId {value:?} ({reason}) must be refused — it is the resolved domain"
            );
            assert!(
                load_with_swarm_topic(&value, None).is_err(),
                "swarmTopic {value:?} ({reason}) must be refused — with meshId unset it is the \
                 resolved domain"
            );
            // And the topic is still checked when a meshId displaces it: it
            // remains the gossip join credential, and deleting one line of
            // config makes it the domain again.
            assert!(
                load_with_swarm_topic(&value, Some("3f2504e0-4f89-41d3-9a0c-0305e82c3301"))
                    .is_err(),
                "swarmTopic {value:?} ({reason}) must be refused even behind a valid meshId"
            );
        }
    }

    #[test]
    fn test_well_formed_swarm_topics_still_load() {
        // The complement of the above: M-31 must refuse the malformed, not
        // narrow what a legitimate deployment may call itself. The shipped
        // Docker topic and the default are both in here on purpose — a rule
        // that rejects what this repository ships is a rule that gets reverted.
        for accepted in [
            "openledger/transactions", // the default (p2p disabled, so allowed)
            "openledger/docker-dev",   // deploy/gl-node.docker.json
            "my-org/ledger",
            "acme:prod:ledger",
            "acme.prod/ledger-01",
            "MESH_A",
            "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            &"a".repeat(MAX_SIGNATURE_DOMAIN_BYTES), // exactly at the bound
        ] {
            assert!(
                load_with_swarm_topic(accepted, None).is_ok(),
                "swarmTopic {accepted:?} must be accepted"
            );
        }
    }

    #[test]
    fn test_malformed_swarm_topic_refused_on_a_live_p2p_node() {
        // The shape an actual mesh runs in: p2p on, signing on, a unique topic
        // — and a trailing space. This is the config that used to boot.
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean",
                  "signing": { "enabled": true },
                  "p2p": { "enabled": true, "swarmTopic": "my-org/ledger " } }"#,
        );
        let message = format!(
            "{}",
            NodeConfig::load_from_path(&file.path().to_path_buf())
                .expect_err("a padded topic must not boot a p2p node")
        );
        assert!(message.contains("p2p.swarmTopic"), "{message}");
        assert!(message.contains("whitespace"), "{message}");
    }

    #[test]
    fn test_signature_domain_charset_excludes_the_v3_field_separator() {
        // L-06 / T45 Facet B: `openledger-sig-v3|…|mesh|{mesh_id}` is injective
        // only because no interpolated field can spell `|`. `parents` is
        // hex-CSV and `lamport` is decimal by M-01; the domain was the last
        // unconstrained field on the default path, so this is the check that
        // makes the premise in docs/FORMAT_V2_DESIGN.md §0.2 true of the
        // running code and not only of the opt-in path.
        assert!(!is_signature_domain_character('|'));
        for field in ["p2p.swarmTopic", "p2p.meshId"] {
            let error = NodeConfig::validate_signature_domain(field, "mesh|a", "under test")
                .expect_err("a pipe must be refused");
            let message = format!("{error}");
            assert!(message.contains("L-06"), "{message}");
        }
    }

    // ── GL_NODE_API_KEY precedence over the file value ───────────────────────

    /// A 32-byte key that passes the L-08 denylist and length floor.
    const TEST_FILE_API_KEY: &str = "file-key-0123456789abcdef0123456";
    /// A different one, so "which value won" is observable.
    const TEST_ENV_API_KEY: &str = "env-key-0123456789abcdef01234567";

    /// A loopback config whose `auth.apiKey` is `file_api_key` (empty = unset).
    /// T41: `NodeConfig` derives `Debug`, so one `{:?}` of the whole config used
    /// to print the API key in the clear — and, through `P2pConfig`, the swarm
    /// topic that doubles as the gossip join credential and the mesh id that is
    /// the signature domain (L-23).
    #[test]
    fn node_config_debug_redacts_every_credential() {
        let api_key = "s3cr3t-key-value-0123456789abcdef";
        let swarm_topic = "acme/private/ledger-topic-2026";
        let mesh_id = "9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f";
        let file = write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean",
                  "auth": {{ "enabled": true, "apiKey": {} }},
                  "signing": {{ "enabled": true }},
                  "p2p": {{ "enabled": true, "swarmTopic": {}, "meshId": {} }} }}"#,
            serde_json::json!(api_key),
            serde_json::json!(swarm_topic),
            serde_json::json!(mesh_id),
        ));
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("valid config");

        let rendered = format!("{config:?}");
        for secret in [api_key, swarm_topic, mesh_id] {
            assert!(
                !rendered.contains(secret),
                "Debug output must not carry {secret}: {rendered}"
            );
        }
        // The values are still *there* — only the rendering is redacted.
        assert_eq!(config.auth.api_key, api_key);
        assert_eq!(config.p2p.signature_domain(), mesh_id);
        // And enough survives to triage with.
        assert!(rendered.contains("<redacted"), "{rendered}");
        assert!(
            rendered.contains("ledgerPath") || rendered.contains("ledger_path"),
            "{rendered}"
        );
    }

    fn write_config_with_api_key(file_api_key: &str) -> NamedTempFile {
        write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean",
                  "auth": {{ "enabled": true, "apiKey": {} }} }}"#,
            serde_json::json!(file_api_key)
        ))
    }

    /// Run `body` with every `WARN`/`ERROR` it logs captured as text.
    ///
    /// `tracing::subscriber::with_default` installs a *thread-local*
    /// subscriber, so this stays correct under `cargo test`'s
    /// thread-per-test parallelism — a concurrent test's logs never land in
    /// this buffer. (Same helper shape as `ledger::service`'s.)
    fn capture_warnings<T>(body: impl FnOnce() -> T) -> (T, String) {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for SharedBuffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
            type Writer = SharedBuffer;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        let value = tracing::subscriber::with_default(subscriber, body);
        let logged = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
        (value, logged)
    }

    /// 0922-v2 §5: an environment key with auth disabled is not silently
    /// discarded — boot warns, names the variable, and never prints the key.
    #[test]
    fn test_environment_api_key_with_auth_disabled_warns_without_echoing_it() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "auth": { "enabled": false } }"#,
        );
        let (config, logged) = capture_warnings(|| {
            NodeConfig::load_from_path_with_env_api_key(
                file.path(),
                Some(TEST_ENV_API_KEY.to_owned()),
            )
            .expect("auth disabled on loopback still boots")
        });
        assert!(!config.auth.enabled);
        assert!(
            logged.contains("GL_NODE_API_KEY is set but auth.enabled is false"),
            "the ignored key must be reported: {logged}"
        );
        assert!(
            !logged.contains(TEST_ENV_API_KEY),
            "the warning must not print the key: {logged}"
        );

        // Auth on, or no environment key: no such warning.
        let (_, quiet) = capture_warnings(|| {
            NodeConfig::load_from_path_with_env_api_key(file.path(), None).expect("loads")
        });
        assert!(!quiet.contains("GL_NODE_API_KEY is set"), "{quiet}");
        let enabled = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "auth": { "enabled": true } }"#,
        );
        let (_, quiet) = capture_warnings(|| {
            NodeConfig::load_from_path_with_env_api_key(
                enabled.path(),
                Some(TEST_ENV_API_KEY.to_owned()),
            )
            .expect("the environment supplies the required key")
        });
        assert!(!quiet.contains("GL_NODE_API_KEY is set"), "{quiet}");
    }

    /// The name is published in the README, in the compose file and in a boot
    /// error message; pin it so a rename has to be deliberate.
    #[test]
    fn test_api_key_environment_variable_name_is_the_documented_one() {
        assert_eq!(API_KEY_ENV_VAR, "GL_NODE_API_KEY");
    }

    /// The finding itself: a rotated environment key must not lose to a stale
    /// file key.
    #[test]
    fn test_environment_api_key_wins_over_a_non_empty_file_key() {
        let file = write_config_with_api_key(TEST_FILE_API_KEY);
        let config = NodeConfig::load_from_path_with_env_api_key(
            file.path(),
            Some(TEST_ENV_API_KEY.to_owned()),
        )
        .expect("both keys are valid, so this must load");
        assert_eq!(
            config.auth.api_key, TEST_ENV_API_KEY,
            "the environment must take precedence over the config file"
        );
    }

    /// ...and it must say so, naming the winner, rather than resolving the
    /// conflict in silence.
    #[test]
    fn test_both_api_key_sources_set_warns_and_names_the_winner() {
        let file = write_config_with_api_key(TEST_FILE_API_KEY);
        let (config, logged) = capture_warnings(|| {
            NodeConfig::load_from_path_with_env_api_key(
                file.path(),
                Some(TEST_ENV_API_KEY.to_owned()),
            )
            .expect("must load")
        });

        assert_eq!(config.auth.api_key, TEST_ENV_API_KEY);
        assert!(
            logged.contains("auth.apiKey is set in both"),
            "a config with two key sources must warn: {logged}"
        );
        assert!(
            logged.contains("ENVIRONMENT value wins"),
            "the warning must name which source won: {logged}"
        );
        assert!(
            !logged.contains(TEST_ENV_API_KEY) && !logged.contains(TEST_FILE_API_KEY),
            "the warning must not print either key value: {logged}"
        );
    }

    /// File-only: unchanged behaviour, and no conflict to report.
    #[test]
    fn test_file_api_key_is_used_when_the_environment_is_unset() {
        let file = write_config_with_api_key(TEST_FILE_API_KEY);
        let (config, logged) = capture_warnings(|| {
            NodeConfig::load_from_path_with_env_api_key(file.path(), None).expect("must load")
        });
        assert_eq!(config.auth.api_key, TEST_FILE_API_KEY);
        assert!(
            !logged.contains("auth.apiKey is set in both"),
            "one source is not a conflict: {logged}"
        );
    }

    /// Environment-only: unchanged behaviour (this is the case that always
    /// worked), and still no conflict to report.
    #[test]
    fn test_environment_api_key_is_used_when_the_file_value_is_empty() {
        let file = write_config_with_api_key("");
        let (config, logged) = capture_warnings(|| {
            NodeConfig::load_from_path_with_env_api_key(
                file.path(),
                Some(TEST_ENV_API_KEY.to_owned()),
            )
            .expect("must load")
        });
        assert_eq!(config.auth.api_key, TEST_ENV_API_KEY);
        assert!(
            !logged.contains("auth.apiKey is set in both"),
            "one source is not a conflict: {logged}"
        );
    }

    /// An exported-but-empty `GL_NODE_API_KEY` is "unset", not "clear the key".
    /// Treating it as a value would turn a stray `export GL_NODE_API_KEY=` into
    /// a boot failure on a node that is perfectly well configured by file.
    #[test]
    fn test_empty_environment_api_key_does_not_displace_the_file_key() {
        let file = write_config_with_api_key(TEST_FILE_API_KEY);
        let config = NodeConfig::load_from_path_with_env_api_key(file.path(), Some(String::new()))
            .expect("must load");
        assert_eq!(config.auth.api_key, TEST_FILE_API_KEY);
    }

    /// The environment key is subject to every rule the file value is: it is
    /// the same credential whichever door it came through.
    #[test]
    fn test_environment_api_key_is_held_to_the_denylist_and_length_floor() {
        let file = write_config_with_api_key(TEST_FILE_API_KEY);
        assert!(
            NodeConfig::load_from_path_with_env_api_key(file.path(), Some("changeme".to_owned()))
                .is_err(),
            "a denylisted environment key must be refused, not smuggled past the file value"
        );
        assert!(
            NodeConfig::load_from_path_with_env_api_key(file.path(), Some("short".to_owned()))
                .is_err(),
            "an environment key below the length floor must be refused"
        );
    }

    // ── Config-file permissions (config hygiene) ─────────────────────────────

    #[cfg(unix)]
    fn set_mode(file: &NamedTempFile, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(file.path()).unwrap().permissions();
        permissions.set_mode(mode);
        std::fs::set_permissions(file.path(), permissions).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_group_readable_config_carrying_an_api_key_warns() {
        let file = write_config_with_api_key(TEST_FILE_API_KEY);
        set_mode(&file, 0o644);

        let (config, logged) = capture_warnings(|| {
            NodeConfig::load_from_path_with_env_api_key(file.path(), None).expect("must load")
        });

        assert_eq!(
            config.auth.api_key, TEST_FILE_API_KEY,
            "boot is not blocked"
        );
        assert!(
            logged.contains("readable by group or other"),
            "a 0644 config holding the API key must warn: {logged}"
        );
        assert!(
            logged.contains("0644"),
            "the warning must name the mode it found: {logged}"
        );
        assert!(
            !logged.contains(TEST_FILE_API_KEY),
            "the warning must not print the key: {logged}"
        );
    }

    /// Control: the mode the check wants produces no noise.
    #[cfg(unix)]
    #[test]
    fn test_owner_only_config_carrying_an_api_key_does_not_warn() {
        let file = write_config_with_api_key(TEST_FILE_API_KEY);
        set_mode(&file, 0o600);

        let (_config, logged) = capture_warnings(|| {
            NodeConfig::load_from_path_with_env_api_key(file.path(), None).expect("must load")
        });

        assert!(
            !logged.contains("readable by group or other"),
            "0600 is the expected mode and must be silent: {logged}"
        );
    }

    /// Control for the gate: the warning is about a key being exposed, so a
    /// config that carries no key has nothing to expose however it is chmod'ed.
    /// Without this gate every default `gl-node.config.json` in a checkout
    /// would warn at every boot and the signal would be worthless.
    #[cfg(unix)]
    #[test]
    fn test_group_readable_config_without_an_api_key_does_not_warn() {
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#);
        set_mode(&file, 0o644);

        let (_config, logged) = capture_warnings(|| {
            NodeConfig::load_from_path_with_env_api_key(file.path(), None).expect("must load")
        });

        assert!(
            !logged.contains("readable by group or other"),
            "no key in the file means nothing to warn about: {logged}"
        );
    }

    /// The mode check must not fire on a key supplied by the environment: the
    /// file does not hold it, so the file's mode says nothing about it.
    #[cfg(unix)]
    #[test]
    fn test_group_readable_config_with_only_an_environment_key_does_not_warn() {
        let file = write_config_with_api_key("");
        set_mode(&file, 0o644);

        let (config, logged) = capture_warnings(|| {
            NodeConfig::load_from_path_with_env_api_key(
                file.path(),
                Some(TEST_ENV_API_KEY.to_owned()),
            )
            .expect("must load")
        });

        assert_eq!(config.auth.api_key, TEST_ENV_API_KEY);
        assert!(
            !logged.contains("readable by group or other"),
            "the key came from the environment, not this file: {logged}"
        );
    }

    // ── The optional `http` section (M-13 / T22) ─────────────────────────────

    /// A loopback config carrying the given raw `http` object.
    fn load_with_http_section(http_json: &str) -> Result<NodeConfig, ConfigError> {
        let file = write_temp_config(&format!(
            r#"{{ "ledgerPath": "./data/ledger.bean", "http": {http_json} }}"#
        ));
        NodeConfig::load_from_path(&file.path().to_path_buf())
    }

    /// The compatibility guarantee: no `http` section means exactly the numbers
    /// `serve_hardened`'s call site used to hardcode. The literals are spelled
    /// out on purpose — comparing only against `HttpServerSettings::default()`
    /// would pass even if someone changed both sides at once.
    #[test]
    fn test_absent_http_section_yields_the_shipped_serve_defaults() {
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");

        let settings = config.http_server_settings();
        assert_eq!(settings.header_read_timeout, Duration::from_secs(30));
        assert_eq!(settings.request_timeout, Duration::from_secs(30));
        assert_eq!(settings.max_connections, 1024);
        assert_eq!(
            settings,
            HttpServerSettings::default(),
            "an absent section must be byte-for-byte the previous behaviour"
        );
    }

    /// The wiring: a configured value has to arrive in the struct
    /// `serve_hardened` actually reads.
    #[test]
    fn test_http_section_values_reach_the_server_settings() {
        let config = load_with_http_section(
            r#"{ "headerReadTimeoutSeconds": 5, "requestTimeoutSeconds": 12, "maxConnections": 64 }"#,
        )
        .expect("in-bounds values must load");

        assert_eq!(config.http.header_read_timeout_seconds, 5);
        assert_eq!(config.http.request_timeout_seconds, 12);
        assert_eq!(config.http.max_connections, 64);

        let settings = config.http_server_settings();
        assert_eq!(settings.header_read_timeout, Duration::from_secs(5));
        assert_eq!(settings.request_timeout, Duration::from_secs(12));
        assert_eq!(settings.max_connections, 64);
    }

    /// Each field defaults independently, so tuning one knob does not silently
    /// reset the other two.
    #[test]
    fn test_partial_http_section_keeps_the_remaining_defaults() {
        let config =
            load_with_http_section(r#"{ "maxConnections": 32 }"#).expect("partial must load");
        assert_eq!(config.http.max_connections, 32);
        assert_eq!(
            config.http.header_read_timeout_seconds,
            HttpServerSettings::default().header_read_timeout.as_secs()
        );
        assert_eq!(
            config.http.request_timeout_seconds,
            HttpServerSettings::default().request_timeout.as_secs()
        );
    }

    #[test]
    fn test_http_section_rejects_unknown_keys() {
        let error_message = format!(
            "{}",
            load_with_http_section(r#"{ "requestTimeoutSecond": 10 }"#)
                .expect_err("a typo'd key must not be silently ignored")
        );
        assert!(error_message.contains("parse"), "{error_message}");
    }

    /// A zero timeout does not "turn the timeout off", it turns the server off
    /// — and is exactly what someone reaching for "no limit" would write.
    #[test]
    fn test_zero_http_timeouts_rejected() {
        for (field, http_json) in [
            (
                "http.headerReadTimeoutSeconds",
                r#"{ "headerReadTimeoutSeconds": 0 }"#,
            ),
            (
                "http.requestTimeoutSeconds",
                r#"{ "requestTimeoutSeconds": 0 }"#,
            ),
        ] {
            let error_message = format!(
                "{}",
                load_with_http_section(http_json).expect_err("0 must be refused")
            );
            assert!(
                error_message.contains(field),
                "the error must name the field: {error_message}"
            );
            assert!(
                error_message.contains("got 0"),
                "the error must name the offending value: {error_message}"
            );
        }
    }

    /// The other half of the same rule: an enormous timeout re-opens the very
    /// attack the timeout exists to stop.
    #[test]
    fn test_absurdly_large_http_timeouts_rejected() {
        for http_json in [
            r#"{ "headerReadTimeoutSeconds": 86400 }"#,
            r#"{ "requestTimeoutSeconds": 86400 }"#,
        ] {
            let error_message = format!(
                "{}",
                load_with_http_section(http_json).expect_err("a day-long timeout must be refused")
            );
            assert!(
                error_message.contains(&MAX_HTTP_TIMEOUT_SECONDS.to_string()),
                "the error must name the ceiling: {error_message}"
            );
        }
    }

    #[test]
    fn test_http_timeout_bounds_are_inclusive() {
        let at_floor = load_with_http_section(&format!(
            r#"{{ "headerReadTimeoutSeconds": {MIN_HTTP_TIMEOUT_SECONDS},
                   "requestTimeoutSeconds": {MIN_HTTP_TIMEOUT_SECONDS} }}"#
        ))
        .expect("exactly the floor must be accepted");
        assert_eq!(
            at_floor.http_server_settings().header_read_timeout,
            Duration::from_secs(MIN_HTTP_TIMEOUT_SECONDS)
        );

        load_with_http_section(&format!(
            r#"{{ "headerReadTimeoutSeconds": {MAX_HTTP_TIMEOUT_SECONDS},
                   "requestTimeoutSeconds": {MAX_HTTP_TIMEOUT_SECONDS} }}"#
        ))
        .expect("exactly the ceiling must be accepted");
    }

    /// Both ends. `0` means "accept nothing", `1` means "serve one client at a
    /// time" (one held keep-alive connection is then a full outage), and
    /// `usize::MAX` means the cap is not a cap.
    #[test]
    fn test_max_connections_outside_its_bounds_rejected() {
        for value in ["0", "1", "7", "65537", "18446744073709551615"] {
            let Err(error) = load_with_http_section(&format!(r#"{{ "maxConnections": {value} }}"#))
            else {
                panic!("maxConnections {value} must be refused");
            };
            let error_message = format!("{error}");
            assert!(
                error_message.contains("http.maxConnections"),
                "the error must name the field: {error_message}"
            );
            assert!(
                error_message.contains(&format!("got {value}")),
                "the error must name the offending value: {error_message}"
            );
        }
    }

    // ── M-33: http.maxConnectionsPerIp ───────────────────────────────────────

    #[test]
    fn test_max_connections_per_ip_defaults_and_wires_through() {
        let file = write_temp_config(r#"{ "ledgerPath": "./data/ledger.bean" }"#);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert_eq!(config.http.max_connections_per_ip, 64);
        assert_eq!(config.http_server_settings().max_connections_per_ip, 64);

        let config = load_with_http_section(r#"{ "maxConnectionsPerIp": 16 }"#)
            .expect("an in-bounds per-IP cap must load");
        assert_eq!(config.http_server_settings().max_connections_per_ip, 16);
    }

    #[test]
    fn test_max_connections_per_ip_floor_is_enforced() {
        for value in ["0", "1", "7"] {
            let Err(error) =
                load_with_http_section(&format!(r#"{{ "maxConnectionsPerIp": {value} }}"#))
            else {
                panic!("maxConnectionsPerIp {value} must be refused");
            };
            let message = format!("{error}");
            assert!(message.contains("http.maxConnectionsPerIp"), "{message}");
            assert!(message.contains(&format!("got {value}")), "{message}");
        }
        load_with_http_section(&format!(
            r#"{{ "maxConnectionsPerIp": {MIN_MAX_CONNECTIONS_PER_IP} }}"#
        ))
        .expect("exactly the floor must be accepted");
    }

    #[test]
    fn test_lowering_max_connections_alone_does_not_brick_the_per_ip_default() {
        // The default per-IP share (64) is above a lowered global cap; that is
        // clamped at serve time, never refused at boot.
        load_with_http_section(r#"{ "maxConnections": 32 }"#)
            .expect("a global cap below the per-IP default must still boot");
    }

    #[test]
    fn test_max_connections_bounds_are_inclusive() {
        let at_floor =
            load_with_http_section(&format!(r#"{{ "maxConnections": {MIN_MAX_CONNECTIONS} }}"#))
                .expect("exactly the floor must be accepted");
        assert_eq!(at_floor.http.max_connections, MIN_MAX_CONNECTIONS);

        let at_ceiling =
            load_with_http_section(&format!(r#"{{ "maxConnections": {MAX_MAX_CONNECTIONS} }}"#))
                .expect("exactly the ceiling must be accepted");
        assert_eq!(at_ceiling.http.max_connections, MAX_MAX_CONNECTIONS);
    }

    // ── T77 / L-73: the config file is opened like every other operator file ─

    /// A config body padded with trailing JSON whitespace to exactly `total`
    /// bytes — still valid JSON, so only the size decides.
    fn padded_config(total: usize) -> String {
        let mut body = r#"{ "ledgerPath": "./data/ledger.bean" }"#.to_owned();
        assert!(body.len() <= total);
        body.push_str(&" ".repeat(total - body.len()));
        body
    }

    /// L-73: a FIFO at `GL_NODE_CONFIG` used to park boot (and
    /// `--health-check`, which calls the same loader) inside a blocking
    /// `File::open` forever. It must now be refused, promptly, as not a
    /// regular file.
    ///
    /// Bug-catch: restore `File::open` + `read_to_string` and the load never
    /// returns — the 10 s receive times out.
    #[cfg(unix)]
    #[test]
    fn l73_a_fifo_config_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("gl-node.config.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "mkfifo failed");

        let (sender, receiver) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = sender.send(NodeConfig::load_from_path(&path).map(|_| ()));
        });
        let outcome = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("L-73: loading a FIFO config must not block");
        let message = format!("{}", outcome.expect_err("a FIFO is not a config file"));
        assert!(message.contains("FIFO"), "{message}");
        assert!(message.contains("config file"), "{message}");
    }

    /// L-73: the read is capped at `MAX_CONFIG_FILE_BYTES`; a 2 MiB config —
    /// valid JSON, padded — is refused rather than loaded, and one exactly at
    /// the cap still loads.
    ///
    /// Bug-catch: restore the uncapped `read_to_string` and the 2 MiB file
    /// loads.
    #[test]
    fn l73_a_config_over_the_cap_is_refused() {
        let oversized = write_temp_config(&padded_config(2 * 1024 * 1024));
        let message = format!(
            "{}",
            NodeConfig::load_from_path(&oversized.path().to_path_buf())
                .expect_err("a 2 MiB config must be refused")
        );
        assert!(
            message.contains(&format!("larger than {MAX_CONFIG_FILE_BYTES} bytes")),
            "{message}"
        );

        let at_cap = write_temp_config(&padded_config(
            usize::try_from(MAX_CONFIG_FILE_BYTES).unwrap(),
        ));
        NodeConfig::load_from_path(&at_cap.path().to_path_buf())
            .expect("a config exactly at the cap loads");
    }

    /// L-73: a symlinked config (a ConfigMap mount) is still followed, but a
    /// dangling link or a directory is refused as not a regular file.
    #[cfg(unix)]
    #[test]
    fn l73_a_symlinked_config_is_followed_and_non_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.json");
        std::fs::write(&target, r#"{ "ledgerPath": "./data/ledger.bean" }"#).unwrap();
        let link = dir.path().join("gl-node.config.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        NodeConfig::load_from_path(&link).expect("a symlinked config is followed");

        let dangling = dir.path().join("dangling.json");
        std::os::unix::fs::symlink(dir.path().join("absent.json"), &dangling).unwrap();
        let message = format!(
            "{}",
            NodeConfig::load_from_path(&dangling).expect_err("a dangling link is refused")
        );
        assert!(message.contains("symbolic link"), "{message}");

        let message = format!(
            "{}",
            NodeConfig::load_from_path(&dir.path().to_path_buf())
                .expect_err("a directory is refused")
        );
        assert!(message.contains("directory"), "{message}");
    }
}
