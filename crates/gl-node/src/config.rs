use axum::http::{header, HeaderName, HeaderValue, Method};
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Documented sample key. Boot fails if this value is used (H-5).
pub const FORBIDDEN_SAMPLE_API_KEY: &str = "change-me-docker-api-key";

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

    /// Whether external (non-API) edits to `.bean` are accepted.
    /// `"enabled"` or `"disabled"`. Default: `"disabled"`.
    #[serde(default = "default_external_file_edits")]
    pub external_file_edits: String,

    /// Serve GraphiQL on `GET /graphql`. Default: `false`. Loopback only.
    #[serde(default = "default_graphiql")]
    pub graphiql: bool,

    /// CORS origin allowlist. Empty (default) denies browser cross-origin access.
    #[serde(default)]
    pub cors: CorsConfig,

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

    /// Peer-to-peer replication configuration.
    #[serde(default)]
    pub p2p: P2pConfig,
}

/// Authentication settings (§3.8).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfig {
    /// Whether `X-Api-Key` is required on GraphQL endpoints.
    #[serde(default)]
    pub enabled: bool,

    /// The API key value. Required when `enabled` is true.
    #[serde(default)]
    pub api_key: String,
}

/// Signing settings (§3.8.1).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct SigningConfig {
    /// Whether Ed25519 signing is enabled.
    #[serde(default)]
    #[allow(dead_code)] // Read when signing is wired (Phase 2).
    pub enabled: bool,
}

/// Peer-to-peer replication settings (§3.4, §3.9).
#[derive(Debug, Deserialize)]
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

    /// iroh-gossip announce cadence in milliseconds.
    #[serde(default = "default_gossip_interval")]
    #[allow(dead_code)] // Available for gossip pacing.
    pub gossip_interval_milliseconds: u64,

    /// ALPN head-exchange cadence in milliseconds.
    #[serde(default = "default_anti_entropy_interval")]
    pub anti_entropy_interval_milliseconds: u64,

    /// TopicId preimage string (§3.4.3).
    #[serde(default = "default_swarm_topic")]
    pub swarm_topic: String,

    /// Iroh relay/discovery profile: `"n0"` (public relays) or `"disabled"` (direct-only).
    #[serde(default = "default_relay_mode")]
    pub relay_mode: String,
}

/// TLS settings. In-process TLS is not implemented; production public bind
/// requires a host terminator (`mode = "terminated"`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct TlsConfig {
    /// `"disabled"` (loopback only) or `"terminated"` (TLS at the host/proxy).
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
            gossip_interval_milliseconds: default_gossip_interval(),
            anti_entropy_interval_milliseconds: default_anti_entropy_interval(),
            swarm_topic: default_swarm_topic(),
            relay_mode: default_relay_mode(),
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

fn default_external_file_edits() -> String {
    "disabled".to_owned()
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

fn default_swarm_topic() -> String {
    "openledger/transactions".to_owned()
}

fn default_relay_mode() -> String {
    "n0".to_owned()
}

fn default_tls_mode() -> String {
    "disabled".to_owned()
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

impl NodeConfig {
    /// Load configuration from the given path, applying defaults and validating.
    pub fn load_from_path(config_path: &PathBuf) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(config_path).map_err(ConfigError::FileRead)?;
        let mut config: NodeConfig = serde_json::from_str(&content).map_err(ConfigError::Parse)?;
        if config.auth.api_key.is_empty() {
            if let Ok(api_key) = std::env::var("GL_NODE_API_KEY") {
                if !api_key.is_empty() {
                    config.auth.api_key = api_key;
                }
            }
        }
        config.validate()?;
        Ok(config)
    }

    /// Validate boot-time invariants per §3.11.
    fn validate(&self) -> Result<(), ConfigError> {
        Self::validate_ledger_path(&self.ledger_path)?;

        match self.external_file_edits.as_str() {
            "enabled" | "disabled" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "externalFileEdits must be \"enabled\" or \"disabled\", got \"{other}\""
                )));
            }
        }

        if self.graphiql && self.binds_non_loopback() {
            return Err(ConfigError::Validation(
                "graphiql must be false when binding a non-loopback address".to_owned(),
            ));
        }

        if self.auth.enabled && self.auth.api_key.is_empty() {
            return Err(ConfigError::Validation(
                "auth.apiKey is required when auth.enabled is true".to_owned(),
            ));
        }

        if self.auth.enabled && self.auth.api_key == FORBIDDEN_SAMPLE_API_KEY {
            return Err(ConfigError::Validation(
                "auth.apiKey must not be the documented sample \"change-me-docker-api-key\"; set a unique key or GL_NODE_API_KEY".to_owned(),
            ));
        }

        if self.p2p.enabled && self.p2p.secret_key_path.is_empty() {
            return Err(ConfigError::Validation(
                "p2p.secretKeyPath is required when p2p.enabled is true".to_owned(),
            ));
        }

        if self.p2p.enabled {
            if let Err(error) =
                p2p::allowlist::PeerAllowlist::parse(&self.p2p.bootstrap_endpoint_ids)
            {
                return Err(ConfigError::Validation(error));
            }
            if self.p2p.swarm_topic == default_swarm_topic() {
                return Err(ConfigError::Validation(
                    "p2p.swarmTopic must not be the public default \"openledger/transactions\" when p2p.enabled is true".to_owned(),
                ));
            }
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
        }

        match self.p2p.relay_mode.as_str() {
            "n0" | "disabled" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "p2p.relayMode must be \"n0\" or \"disabled\", got \"{other}\""
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

        Ok(())
    }

    /// True when the HTTP bind address is not loopback (I-1 / H-5 warning).
    pub fn binds_non_loopback(&self) -> bool {
        !matches!(
            self.bind_address.as_str(),
            "127.0.0.1" | "::1" | "localhost"
        )
    }

    /// Whether to serve GraphiQL on `GET /graphql`.
    pub fn graphiql_enabled(&self) -> bool {
        self.graphiql
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
        if ledger_path.is_empty() {
            return Err(ConfigError::Validation(
                "ledgerPath is required and must not be empty".to_owned(),
            ));
        }
        if ledger_path.contains('\0') {
            return Err(ConfigError::Validation(
                "ledgerPath must not contain NUL".to_owned(),
            ));
        }
        let configured = Path::new(ledger_path);
        if configured
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(ConfigError::Validation(
                "ledgerPath must not contain \"..\"".to_owned(),
            ));
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
            return Err(ConfigError::Validation(
                "ledgerPath must resolve under the process working directory".to_owned(),
            ));
        }
        Ok(())
    }
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
        assert_eq!(config.external_file_edits, "disabled");
        assert!(!config.graphiql, "GraphiQL off by default");
        assert!(config.cors.allowed_origins.is_empty());
        assert!(!config.auth.enabled);
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
            "externalFileEdits": "disabled",
            "cors": {{ "allowedOrigins": ["http://localhost:8080"] }},
            "auth": {{ "enabled": true, "apiKey": "secret-key-123" }},
            "signing": {{ "enabled": true }},
            "tls": {{ "mode": "terminated" }},
            "p2p": {{
                "enabled": true,
                "secretKeyPath": "./keys/iroh.secret",
                "bootstrapEndpointIds": ["{peer_a}", "{peer_b}"],
                "gossipIntervalMilliseconds": 3000,
                "antiEntropyIntervalMilliseconds": 10000,
                "swarmTopic": "my-org/ledger",
                "relayMode": "disabled"
            }}
        }}"#
        );
        let file = write_temp_config(&content);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert_eq!(config.external_file_edits, "disabled");
        assert_eq!(config.cors.allowed_origins, vec!["http://localhost:8080"]);
        assert!(config.auth.enabled);
        assert_eq!(config.auth.api_key, "secret-key-123");
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

    #[test]
    fn test_auth_enabled_without_key_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "auth": { "enabled": true, "apiKey": "" } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("apiKey"));
    }

    #[test]
    fn test_invalid_external_file_edits_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "externalFileEdits": "maybe" }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("externalFileEdits"));
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
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "bindAddress": "0.0.0.0", "graphiql": false, "tls": { "mode": "terminated" } }"#,
        );
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert!(!config.graphiql_enabled());
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
    fn test_sample_api_key_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "auth": { "enabled": true, "apiKey": "change-me-docker-api-key" } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("change-me-docker-api-key"));
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
    fn test_invalid_relay_mode_rejected() {
        let file = write_temp_config(
            r#"{ "ledgerPath": "./data/ledger.bean", "p2p": { "relayMode": "mdns" } }"#,
        );
        let result = NodeConfig::load_from_path(&file.path().to_path_buf());
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("relayMode"));
    }
}
