//! `gl-node init --domain DOMAIN` (`docs/build-log/005-installer`, step 2):
//! write the config of a node that serves `https://DOMAIN` through a TLS
//! proxy on the same host — the installer's node.
//!
//! The node binds loopback and is public all the same (`tls.mode:
//! "terminated"`, `NodeConfig::is_public`): the proxy, on the same host, is
//! its one client (`trustedProxies: ["127.0.0.1"]`), `allowedHosts` is the
//! domain, auth is on with the key from `GL_NODE_API_KEY` (never in the file),
//! and GraphiQL is off. The config file's own ledger (`default`) is the
//! operator's and needs no mesh: signing and P2P are off. Companies are ledger
//! folders in `ledgersDir`, each with its mesh (`gl-node ledger add`).
//!
//! It writes a new file only — an existing config is never replaced — and
//! checks that what it wrote loads as the node will load it.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::config::NodeConfig;

/// The usage line for `gl-node init`.
pub const USAGE: &str = "Usage:
  gl-node init --domain DOMAIN [--data-dir DIR] [--output FILE]
      (the config of a node behind an HTTPS proxy on the same host, for
      https://DOMAIN; DIR defaults to /data, the image's, and FILE to
      GL_NODE_CONFIG or gl-node.config.json; an existing FILE is never replaced)";

/// `gl-node init`'s arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitArgs {
    pub domain: String,
    pub data_dir: String,
    pub output: Option<String>,
}

/// Parse the arguments after `gl-node init`.
pub fn parse(args: &[String]) -> Result<InitArgs, String> {
    let mut options = std::collections::BTreeMap::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--domain" | "--data-dir" | "--output" => {
                let value = rest.next().ok_or_else(|| format!("{arg} needs a value"))?;
                if options.insert(arg.as_str(), value.clone()).is_some() {
                    return Err(format!("{arg} given twice"));
                }
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(InitArgs {
        domain: options.remove("--domain").ok_or("--domain is required")?,
        data_dir: options
            .remove("--data-dir")
            .unwrap_or_else(|| "/data".to_owned()),
        output: options.remove("--output"),
    })
}

/// `domain` as the node will list it: a DNS name of at least two labels, each
/// 1–63 of `a-z`, `0-9` and `-` (not first or last), lower-cased; no scheme,
/// port, path or trailing dot. An IP address is refused: the proxy gets its
/// certificate for a name.
pub fn check_domain(domain: &str) -> Result<String, String> {
    let domain = domain.to_ascii_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();
    let label_ok = |label: &&str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    let all_digits = labels
        .last()
        .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()));
    if domain.len() > 253 || labels.len() < 2 || !labels.iter().all(label_ok) || all_digits {
        return Err(format!(
            "{domain:?} is not a domain name: give the name clients use, such as ledger.example.com (no https://, port or path; not an IP address; an international name in its xn-- form)"
        ));
    }
    Ok(domain)
}

/// The config for `domain`, its files under `data_dir`.
pub fn node_config(domain: &str, data_dir: &str) -> Result<Value, String> {
    let domain = check_domain(domain)?;
    let data = data_dir.trim_end_matches('/');
    Ok(json!({
        "ledgerPath": format!("{data}/ledger.bean"),
        "ledgersDir": format!("{data}/ledgers"),
        "bindAddress": "127.0.0.1",
        "port": 4000,
        "graphiql": false,
        "allowedHosts": [domain],
        "trustedProxies": ["127.0.0.1"],
        "tls": { "mode": "terminated" },
        "auth": { "enabled": true, "apiKey": "" },
        "signing": { "enabled": false },
        "p2p": { "enabled": false },
    }))
}

/// Write `config` to a new file at `path` (0600; an existing file is never
/// replaced), then check it loads as the node will load it, with a key from
/// the environment; a config that does not is removed again.
pub fn write_config(path: &Path, config: &Value) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    // Serialized first: once the file exists, every early return leaves it.
    let text = serde_json::to_string_pretty(config).map_err(|error| error.to_string())? + "\n";
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => format!(
                "{} exists: init writes a new config and never replaces one",
                path.display()
            ),
            _ => format!("cannot create {}: {error}", path.display()),
        })?;
    // The file's bytes, then its directory entry, on disk.
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::File::open(parent)?.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", path.display()));
    let checked = written.and_then(|()| {
        // Any well-formed key will do: the node gets its own from
        // GL_NODE_API_KEY.
        let key =
            hex::encode(zeroize::Zeroizing::new(iroh::SecretKey::generate().to_bytes()).as_slice());
        NodeConfig::load_from_path_with_env_api_key(path, Some(key))
            .map(|_| ())
            .map_err(|error| format!("the config does not load: {error}"))
    });
    if checked.is_err() {
        let _ = std::fs::remove_file(path);
    }
    checked
}

/// `gl-node init …`: write the config, say where, exit.
pub fn run(args: &[String]) -> ! {
    let init = match parse(args) {
        Ok(init) => init,
        Err(error) => {
            eprintln!("init: {error}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let output = PathBuf::from(init.output.clone().unwrap_or_else(|| {
        std::env::var("GL_NODE_CONFIG").unwrap_or_else(|_| "gl-node.config.json".to_owned())
    }));
    let written =
        node_config(&init.domain, &init.data_dir).and_then(|config| write_config(&output, &config));
    match written {
        Ok(()) => {
            println!(
                "Wrote {}: the node for https://{} behind a proxy on this host.\n\
                 Start it with GL_NODE_API_KEY set to its operator key (not in the file).",
                output.display(),
                init.domain.to_ascii_lowercase()
            );
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("init: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    /// Under the working directory, where a node's paths must resolve.
    fn temp_dir_here() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(".test-init-")
            .tempdir_in(".")
            .expect("temp dir")
    }

    /// 005 step 2: `init` writes the config of a public node behind a proxy
    /// on the same host — loopback bind, `tls.mode: "terminated"`, the proxy
    /// its only trusted one, the domain its only host, auth on with no key in
    /// the file, no GraphiQL — that loads as the node loads it, 0600.
    ///
    /// Bug-catch: trust every proxy (or none) and the rate limit keys on the
    /// wrong client; bind `0.0.0.0` and the API answers past the proxy.
    #[test]
    fn init_writes_a_public_node_behind_its_proxy() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir_here();
        let data = dir.path().to_string_lossy().into_owned();
        let path = dir.path().join("gl-node.config.json");
        let config = node_config("Ledger.Example.com", &data).expect("a config");
        write_config(&path, &config).expect("written");
        assert_eq!(
            std::fs::metadata(&path).expect("file").permissions().mode() & 0o777,
            0o600
        );
        let loaded = NodeConfig::load_from_path_with_env_api_key(
            &path,
            Some("unit-test-api-key-0123456789abcd".to_owned()),
        )
        .expect("loads");
        assert!(loaded.is_public());
        assert!(!loaded.binds_non_loopback(), "the proxy is its only client");
        assert_eq!(loaded.allowed_hosts, ["ledger.example.com"]);
        assert_eq!(loaded.trusted_proxy_set().len(), 1);
        assert!(loaded
            .trusted_proxy_set()
            .contains(&"127.0.0.1".parse::<std::net::IpAddr>().expect("ip")));
        assert!(loaded.auth.enabled && !loaded.graphiql_enabled());
        let text = std::fs::read_to_string(&path).expect("text");
        assert!(
            text.contains(r#""apiKey": """#),
            "no key in the file: {text}"
        );
        assert_eq!(loaded.ledgers_dir, format!("{data}/ledgers"));
    }

    /// 005 step 2: `init` never replaces a config — a second run, or a file
    /// already there, is refused and the file is unchanged.
    ///
    /// Bug-catch: open the file for writing without `create_new` and a re-run
    /// of the installer overwrites the operator's edits.
    #[test]
    fn init_never_replaces_a_config() {
        let dir = temp_dir_here();
        let path = dir.path().join("gl-node.config.json");
        std::fs::write(&path, "{ \"the operator's\": true }\n").expect("existing");
        let config = node_config("ledger.example.com", "/data").expect("a config");
        let refused = write_config(&path, &config).expect_err("refused");
        assert!(refused.contains("never replaces"), "{refused}");
        assert_eq!(
            std::fs::read_to_string(&path).expect("text"),
            "{ \"the operator's\": true }\n"
        );
    }

    /// 005 step 2: a config that would not load — here its data outside the
    /// working directory, which the node refuses — is refused and not left
    /// behind, so a re-run starts clean.
    ///
    /// Bug-catch: keep the file when the check fails and every re-run is
    /// refused for a config the node never boots with.
    #[test]
    fn init_leaves_no_config_that_does_not_load() {
        let dir = temp_dir_here();
        let path = dir.path().join("gl-node.config.json");
        let config = node_config("ledger.example.com", "/not-under-the-working-directory")
            .expect("a config");
        let refused = write_config(&path, &config).expect_err("refused");
        assert!(refused.contains("does not load"), "{refused}");
        assert!(!path.exists(), "nothing left behind");
    }

    /// `--domain` is a DNS name the proxy can get a certificate for, lower
    /// cased; anything else is refused before a file is written.
    ///
    /// Bug-catch: take `https://ledger.example.com` as given and every request
    /// is refused by the Host guard.
    #[test]
    fn init_takes_a_domain_name_only() {
        assert_eq!(
            check_domain("Books.Example.COM").as_deref(),
            Ok("books.example.com")
        );
        assert_eq!(check_domain("a-b.c1.io").as_deref(), Ok("a-b.c1.io"));
        for refused in [
            "",
            "localhost",
            "https://ledger.example.com",
            "ledger.example.com:443",
            "ledger.example.com/",
            "ledger.example.com.",
            "-ledger.example.com",
            "ledger_1.example.com",
            "203.0.113.7",
            "ledger example.com",
        ] {
            assert!(check_domain(refused).is_err(), "{refused:?}");
        }
        assert_eq!(
            parse(&args("--domain ledger.example.com")),
            Ok(InitArgs {
                domain: "ledger.example.com".into(),
                data_dir: "/data".into(),
                output: None,
            })
        );
        for refused in [
            "",
            "--domain",
            "--domain a.b --domain c.d",
            "--domain a.b --force",
        ] {
            assert!(parse(&args(refused)).is_err(), "{refused:?}");
        }
    }
}
