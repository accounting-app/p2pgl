use serde::Deserialize;
use std::path::PathBuf;

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
    /// `"enabled"` or `"disabled"`. Default: `"enabled"`.
    #[serde(default = "default_external_file_edits")]
    pub external_file_edits: String,

    /// Authentication configuration.
    #[serde(default)]
    pub auth: AuthConfig,

    /// Transaction signing configuration.
    #[serde(default)]
    pub signing: SigningConfig,

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
    pub gossip_interval_milliseconds: u64,

    /// ALPN head-exchange cadence in milliseconds.
    #[serde(default = "default_anti_entropy_interval")]
    pub anti_entropy_interval_milliseconds: u64,

    /// TopicId preimage string (§3.4.3).
    #[serde(default = "default_swarm_topic")]
    pub swarm_topic: String,
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
    "enabled".to_owned()
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
        let config: NodeConfig = serde_json::from_str(&content).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate boot-time invariants per §3.11.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.ledger_path.is_empty() {
            return Err(ConfigError::Validation(
                "ledgerPath is required and must not be empty".to_owned(),
            ));
        }

        match self.external_file_edits.as_str() {
            "enabled" | "disabled" => {}
            other => {
                return Err(ConfigError::Validation(format!(
                    "externalFileEdits must be \"enabled\" or \"disabled\", got \"{other}\""
                )));
            }
        }

        if self.auth.enabled && self.auth.api_key.is_empty() {
            return Err(ConfigError::Validation(
                "auth.apiKey is required when auth.enabled is true".to_owned(),
            ));
        }

        if self.p2p.enabled && self.p2p.secret_key_path.is_empty() {
            return Err(ConfigError::Validation(
                "p2p.secretKeyPath is required when p2p.enabled is true".to_owned(),
            ));
        }

        Ok(())
    }
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
        assert_eq!(config.external_file_edits, "enabled");
        assert!(!config.auth.enabled);
        assert!(!config.signing.enabled);
        assert!(!config.p2p.enabled);
    }

    #[test]
    fn test_full_config_loads() {
        let content = r#"{
            "ledgerPath": "./data/ledger.bean",
            "bindAddress": "0.0.0.0",
            "port": 8080,
            "externalFileEdits": "disabled",
            "auth": { "enabled": true, "apiKey": "secret-key-123" },
            "signing": { "enabled": true },
            "p2p": {
                "enabled": true,
                "secretKeyPath": "./keys/iroh.secret",
                "bootstrapEndpointIds": ["peer1", "peer2"],
                "gossipIntervalMilliseconds": 3000,
                "antiEntropyIntervalMilliseconds": 10000,
                "swarmTopic": "my-org/ledger"
            }
        }"#;
        let file = write_temp_config(content);
        let config = NodeConfig::load_from_path(&file.path().to_path_buf()).expect("should load");
        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert_eq!(config.external_file_edits, "disabled");
        assert!(config.auth.enabled);
        assert_eq!(config.auth.api_key, "secret-key-123");
        assert!(config.signing.enabled);
        assert!(config.p2p.enabled);
        assert_eq!(config.p2p.bootstrap_endpoint_ids.len(), 2);
        assert_eq!(config.p2p.gossip_interval_milliseconds, 3000);
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
}
