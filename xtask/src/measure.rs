//! Measure a gl-node serving many ledgers (`docs/build-log/003-multi-ledger-node`).
//!
//! The Rust form of what was `scripts/measure_ledgers.py` (004-no-python): the
//! same modes, the same JSON line, the same care with the nodes it starts.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const USAGE: &str = "Measure a gl-node serving many ledgers.

Starts the built binary in a fresh directory with the config file's ledger and
N-1 ledger folders, waits until every ledger answers, and reports:

  boot     seconds from start until the last ledger answers its /health
  rss      resident memory once booted, and after one write per ledger
  files    open file descriptors once booted (lsof)
  write    seconds to write one entry into every ledger, one after another
  stop     seconds from SIGTERM to exit (every ledger compacts on the way out)

Usage:
  scripts/measure_ledgers.sh [--ledgers N] [--p2p] [--entries N] [--binary PATH]
  scripts/measure_ledgers.sh --mesh [--ledgers N]   two nodes, each ledger meshed with its pair

--p2p gives every ledger its own mesh and P2P endpoint (signing on, relays
off, a random UDP port each), as production ledgers have; without it every
ledger runs with P2P and signing off. --entries N types N transactions into
every ledger's .bean before boot (P2P off only). HTTP and every mesh stay on
loopback, but each P2P endpoint is the production one: it binds all interfaces
and asks the network's gateway for a port mapping (UPnP / NAT-PMP / PCP), so
--p2p and --mesh send those probes to the LAN (an outbound firewall such as
LuLu will ask). The default binary is target/release/gl-node (build it with
`cargo build --release -p gl-node`). On a failure the work directory and its
node.log are kept, and their path printed.";

struct Options {
    ledgers: usize,
    p2p: bool,
    entries: usize,
    mesh: bool,
    binary: PathBuf,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        ledgers: 100,
        p2p: false,
        entries: 0,
        mesh: false,
        binary: crate::repo_root().join("target/release/gl-node"),
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| -> Result<String, String> {
            args.next().cloned().ok_or(format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--ledgers" => {
                options.ledgers = value("--ledgers")?
                    .parse()
                    .map_err(|_| "--ledgers takes a number")?
            }
            "--entries" => {
                options.entries = value("--entries")?
                    .parse()
                    .map_err(|_| "--entries takes a number")?
            }
            // Made absolute here: the node runs in its own work directory.
            "--binary" => {
                let raw = PathBuf::from(value("--binary")?);
                options.binary = if raw.is_absolute() {
                    raw
                } else {
                    std::env::current_dir()
                        .map_err(|error| error.to_string())?
                        .join(raw)
                };
            }
            "--p2p" => options.p2p = true,
            "--mesh" => options.mesh = true,
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
        }
    }
    if options.ledgers == 0 {
        return Err("--ledgers must be at least 1".to_owned());
    }
    Ok(options)
}

pub fn main(args: &[String]) -> ExitCode {
    let options = match parse(args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    if !options.binary.exists() {
        eprintln!(
            "{} not found; build it with: cargo build --release -p gl-node",
            options.binary.display()
        );
        return ExitCode::FAILURE;
    }
    let result = if options.mesh {
        run_mesh(&options)
    } else {
        run_one(&options)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

// ── Small helpers ───────────────────────────────────────────────────────────

/// `bytes` random bytes from the OS, hex.
fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buffer))
        .expect("/dev/urandom");
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random_below(bound: u32) -> u32 {
    let hex = random_hex(4);
    u32::from_str_radix(&hex, 16).expect("hex") % bound
}

/// A fresh work directory under the system's temp dir.
fn work_dir(prefix: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("{prefix}{}", random_hex(6)));
    fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    Ok(dir)
}

fn free_tcp_port() -> Result<u16, String> {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|error| error.to_string())
}

/// `count` distinct UDP ports below the ephemeral range (49152+ on macOS,
/// 32768+ on Linux), so no socket the running nodes open on their own lands on
/// one before its ledger binds it, and free on IPv4 and IPv6 alike, as the
/// endpoint binds both families. Each stays bound until all are chosen.
fn free_udp_ports(count: usize) -> Vec<u16> {
    let mut held = Vec::new();
    choose_ports(count, |port| {
        match (
            UdpSocket::bind(("0.0.0.0", port)),
            UdpSocket::bind(("::", port)),
        ) {
            (Ok(v4), Ok(v6)) => {
                held.push((v4, v6));
                true
            }
            _ => false,
        }
    })
}

/// `count` distinct ports in 20000–29999 that `claim` accepts.
fn choose_ports(count: usize, claim: impl FnMut(u16) -> bool) -> Vec<u16> {
    let candidates = std::iter::repeat_with(|| 20_000 + random_below(10_000) as u16);
    choose_ports_from(count, candidates, claim)
}

/// The first `count` distinct `candidates` that `claim` accepts.
fn choose_ports_from(
    count: usize,
    candidates: impl IntoIterator<Item = u16>,
    mut claim: impl FnMut(u16) -> bool,
) -> Vec<u16> {
    let mut ports = Vec::new();
    for port in candidates {
        if ports.len() == count {
            break;
        }
        if !ports.contains(&port) && claim(port) {
            ports.push(port);
        }
    }
    ports
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    fs::write(path, value.to_string()).map_err(|error| format!("{}: {error}", path.display()))
}

/// One HTTP/1.1 exchange on loopback: `(status, body)`.
fn http(
    port: u16,
    method: &str,
    path: &str,
    key: &str,
    client: Option<&str>,
    body: Option<&str>,
    timeout: Duration,
) -> Result<(u16, String), String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Api-Key: {key}\r\nConnection: close\r\n"
    );
    if let Some(client) = client {
        request.push_str(&format!("X-Forwarded-For: {client}\r\n"));
    }
    let payload = body.unwrap_or("");
    if body.is_some() {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        ));
    }
    request.push_str("\r\n");
    request.push_str(payload);
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut raw = Vec::new();
    stream
        .take(16 * 1024 * 1024)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())?;
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("no end of response head")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or("no status code")?;
    let content = &raw[split + 4..];
    let chunked = head.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim() == "transfer-encoding" && value.contains("chunked")
        })
    });
    let content = if chunked {
        dechunk(content)
    } else {
        content.to_vec()
    };
    Ok((status, String::from_utf8_lossy(&content).into_owned()))
}

fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(line_end) = rest.windows(2).position(|window| window == b"\r\n") {
        let size_text = String::from_utf8_lossy(&rest[..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .unwrap_or(0);
        rest = &rest[line_end + 2..];
        if size == 0 || rest.len() < size {
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
    out
}

/// A GraphQL request that must succeed: its `data`.
fn graphql(port: u16, path: &str, key: &str, query: &str, client: &str) -> Result<Value, String> {
    let body = json!({ "query": query }).to_string();
    let (status, text) = http(
        port,
        "POST",
        path,
        key,
        Some(client),
        Some(&body),
        Duration::from_secs(30),
    )?;
    let answer: Value =
        serde_json::from_str(&text).map_err(|_| format!("{path}: HTTP {status}: {text}"))?;
    if status != 200 || answer.get("errors").is_some_and(|errors| !errors.is_null()) {
        return Err(format!("{path}: HTTP {status}: {text}"));
    }
    Ok(answer["data"].clone())
}

fn answers(port: u16, path: &str, key: &str) -> bool {
    matches!(
        http(port, "GET", path, key, None, None, Duration::from_secs(5)),
        Ok((200, _))
    )
}

fn rss_kib(pid: u32) -> u64 {
    Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|output| String::from_utf8_lossy(&output.stdout).trim().parse().ok())
        .unwrap_or(0)
}

fn open_files(pid: u32) -> usize {
    Command::new("lsof")
        .args(["-p", &pid.to_string()])
        .output()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .count()
                .saturating_sub(1)
        })
        .unwrap_or(0)
}

/// A started gl-node: killed when dropped unless it already exited.
struct Node {
    child: Child,
}

impl Node {
    fn start(binary: &Path, home: &Path, key: &str) -> Result<Node, String> {
        let log = fs::File::create(home.join("node.log")).map_err(|error| error.to_string())?;
        let child = Command::new(binary)
            .current_dir(home)
            .env("GL_NODE_CONFIG", home.join("gl-node.config.json"))
            .env("GL_NODE_API_KEY", key)
            .env_remove("RUST_LOG")
            .stdout(log.try_clone().map_err(|error| error.to_string())?)
            .stderr(log)
            .spawn()
            .map_err(|error| format!("start {}: {error}", binary.display()))?;
        Ok(Node { child })
    }

    fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// SIGTERM, then wait up to `limit`: the exit code.
    fn stop(&mut self, limit: Duration) -> Result<i32, String> {
        Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .map_err(|error| error.to_string())?;
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait().map_err(|error| error.to_string())? {
                return Ok(exit_code(status));
            }
            if Instant::now() > deadline {
                return Err(format!("gl-node did not exit within {limit:?} of SIGTERM"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.running() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// The exit code, or minus the signal that ended the process (as Python's
/// `returncode` reports it).
fn exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return -signal;
        }
    }
    status.code().unwrap_or(-1)
}

/// Wait until every path answers 200 (with `key`), the node still running.
fn wait_for(
    node: &mut Node,
    port: u16,
    paths: &[String],
    key: &str,
    home: &Path,
    limit: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + limit;
    let mut pending: Vec<&String> = paths.iter().collect();
    while !pending.is_empty() {
        if !node.running() {
            return Err(format!(
                "gl-node exited during boot; see {}/node.log",
                home.display()
            ));
        }
        if Instant::now() > deadline {
            return Err(format!(
                "not every ledger answered within {} s; see {}/node.log",
                limit.as_secs(),
                home.display()
            ));
        }
        pending.retain(|path| !answers(port, path, key));
        if !pending.is_empty() {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    Ok(())
}

/// Run `body` in a fresh work directory: removed on success, kept (and named)
/// on failure.
fn in_work_dir(prefix: &str, body: impl FnOnce(&Path) -> Result<(), String>) -> Result<(), String> {
    let work = work_dir(prefix)?;
    let result = body(&work);
    match &result {
        Ok(()) => {
            let _ = fs::remove_dir_all(&work);
        }
        Err(_) => eprintln!("kept {} for its node.log", work.display()),
    }
    result
}

/// One simulated client per request (`X-Forwarded-For`, trusted from
/// loopback): the GraphQL rate limit is per client, so one client writing to
/// 100 ledgers would measure the limit, not the node.
fn client(index: usize) -> String {
    format!(
        "10.{}.{}.{}",
        index / 62_500,
        index / 250 % 250,
        index % 250 + 1
    )
}

fn ledger_settings(p2p: bool, name: &str) -> Value {
    if !p2p {
        return json!({});
    }
    json!({
        "signing": { "enabled": true },
        "p2p": {
            "enabled": true,
            "relayMode": "disabled",
            "bootstrapEndpointIds": [],
            "meshId": format!("measure-{name}-{}", random_hex(8)),
            "swarmTopic": format!("measure/{name}-{}", random_hex(8)),
        },
    })
}

fn path_of(name: &str, what: &str) -> String {
    if name == "default" {
        format!("/{what}")
    } else {
        format!("/ledgers/{name}/{what}")
    }
}

fn book(entries: usize) -> String {
    let mut lines = vec![
        "2025-01-01 open Assets:Bank USD".to_owned(),
        "2025-01-01 open Expenses:Supplies USD".to_owned(),
        String::new(),
    ];
    for index in 0..entries {
        lines.push(format!(
            "2025-{:02}-{:02} * \"Supplier {}\" \"Invoice {index}\"",
            index % 12 + 1,
            index % 28 + 1,
            index % 97
        ));
        lines.push(format!(
            "  Expenses:Supplies  {}.{:02} USD",
            index % 500 + 1,
            index % 100
        ));
        lines.push("  Assets:Bank".to_owned());
        lines.push(String::new());
    }
    lines.join("\n")
}

// ── One node ────────────────────────────────────────────────────────────────

fn run_one(options: &Options) -> Result<(), String> {
    if options.entries > 0 && options.p2p {
        return Err(
            "--entries is for P2P off: typed entries are signed at boot, which needs each ledger's key first"
                .to_owned(),
        );
    }
    in_work_dir("gl-node-measure-", |work| {
        let port = free_tcp_port()?;
        let key = random_hex(32);
        let names: Vec<String> = (1..options.ledgers)
            .map(|index| format!("l{index:03}"))
            .collect();
        let mut config = json!({
            "ledgerPath": "ledger.bean",
            "port": port,
            "auth": { "enabled": true, "apiKey": "" },
            "trustedProxies": ["127.0.0.1"],
        });
        if let (Some(config), Some(extra)) = (
            config.as_object_mut(),
            ledger_settings(options.p2p, "default").as_object(),
        ) {
            config.extend(extra.clone());
        }
        write_json(&work.join("gl-node.config.json"), &config)?;
        let mut books = vec![work.join("ledger.bean")];
        for name in &names {
            let folder = work.join("data/ledgers").join(name);
            fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
            write_json(
                &folder.join("ledger.json"),
                &ledger_settings(options.p2p, name),
            )?;
            books.push(folder.join("ledger.bean"));
        }
        if options.entries > 0 {
            let text = book(options.entries);
            for path in &books {
                fs::write(path, &text).map_err(|error| error.to_string())?;
                set_private(path)?;
            }
        }

        let started = Instant::now();
        let mut node = Node::start(&options.binary, work, &key)?;
        let paths: Vec<String> = std::iter::once("default".to_owned())
            .chain(names.iter().cloned())
            .map(|name| path_of(&name, "health"))
            .collect();
        wait_for(
            &mut node,
            port,
            &paths,
            &key,
            work,
            Duration::from_secs(600),
        )?;
        let boot = started.elapsed();
        let pid = node.child.id();
        let rss_booted = rss_kib(pid);
        let files = open_files(pid);

        let write_started = Instant::now();
        for (index, name) in std::iter::once("default".to_owned())
            .chain(names.iter().cloned())
            .enumerate()
        {
            graphql(
                port,
                &path_of(&name, "graphql"),
                &key,
                r#"mutation { openAccount(name: "Assets:Cash", date: "2026-01-01") }"#,
                &client(index + 1),
            )?;
        }
        let write = write_started.elapsed();
        let rss_written = rss_kib(pid);

        let stop_started = Instant::now();
        let code = node.stop(Duration::from_secs(300))?;
        let stop = stop_started.elapsed();
        println!(
            "{}",
            python_json(&[
                ("ledgers", json!(options.ledgers)),
                ("entries_per_ledger", json!(options.entries)),
                ("p2p", json!(options.p2p)),
                ("boot_seconds", json!(round(boot))),
                ("rss_mib_booted", json!(mib(rss_booted))),
                ("rss_mib_after_writes", json!(mib(rss_written))),
                ("open_files", json!(files)),
                ("write_seconds", json!(round(write))),
                ("stop_seconds", json!(round(stop))),
                ("exit_code", json!(code)),
            ])
        );
        if code == 0 {
            Ok(())
        } else {
            Err(format!(
                "gl-node exited {code}; see {}/node.log",
                work.display()
            ))
        }
    })
}

#[cfg(unix)]
fn set_private(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn set_private(_: &Path) -> Result<(), String> {
    Ok(())
}

/// A JSON object the way Python's `json.dumps` writes one — fields in the
/// order given, `", "` and `": "` between them — so a result line reads as it
/// did before 004.
fn python_json(fields: &[(&str, Value)]) -> String {
    let parts: Vec<(String, Value)> = fields
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect();
    python_object(&parts)
}

/// `pairs` as a Python-style JSON object, in their order.
fn python_object(pairs: &[(String, Value)]) -> String {
    let parts: Vec<String> = pairs
        .iter()
        .map(|(key, value)| format!("{}: {}", json!(key), python_value(value)))
        .collect();
    format!("{{{}}}", parts.join(", "))
}

/// The crossed ledgers as a JSON value whose text keeps their order.
fn crossed_json(crossed: &[(String, Value)]) -> Value {
    Value::String(python_object(crossed))
}

fn python_value(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(key, value)| format!("{}: {}", json!(key), python_value(value)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(python_value).collect();
            format!("[{}]", parts.join(", "))
        }
        // A pre-written object (`crossed_json`): its text as it stands.
        Value::String(text) if text.starts_with('{') => text.clone(),
        other => other.to_string(),
    }
}

fn round(duration: Duration) -> f64 {
    (duration.as_secs_f64() * 100.0).round() / 100.0
}

fn mib(kib: u64) -> f64 {
    (kib as f64 / 1024.0 * 10.0).round() / 10.0
}

// ── Two nodes, every ledger meshed with its pair ────────────────────────────

struct Side {
    home: PathBuf,
    port: u16,
    key: String,
    udp: Vec<u16>,
    ids: Vec<String>,
}

/// Two nodes, `--ledgers` ledgers each, every ledger paired with its namesake
/// on the other node in a mesh of its own (direct loopback addresses, no
/// relay). One entry per ledger is written on node A; reports how long until
/// node B holds every one, and checks no entry crossed into another ledger.
fn run_mesh(options: &Options) -> Result<(), String> {
    in_work_dir("gl-node-mesh-", |work| {
        let names: Vec<String> = std::iter::once("default".to_owned())
            .chain((1..options.ledgers).map(|index| format!("l{index:03}")))
            .collect();
        let pairs: Vec<(String, String)> = names
            .iter()
            .map(|name| {
                (
                    format!("mesh-{name}-{}", random_hex(8)),
                    format!("measure/{name}-{}", random_hex(8)),
                )
            })
            .collect();
        let mut ports = free_udp_ports(2 * names.len()).into_iter();
        let mut sides = Vec::new();
        for side in ["a", "b"] {
            let home = work.join(side);
            fs::create_dir_all(&home).map_err(|error| error.to_string())?;
            sides.push(Side {
                home,
                port: free_tcp_port()?,
                key: random_hex(32),
                udp: names
                    .iter()
                    .map(|_| ports.next().expect("enough ports"))
                    .collect(),
                ids: Vec::new(),
            });
        }

        let p2p = |side: &Side, index: usize, peer: Option<&Side>| -> Value {
            let mut section = json!({
                "enabled": true,
                "relayMode": "disabled",
                "meshId": pairs[index].0,
                "swarmTopic": pairs[index].1,
                "listenPort": side.udp[index],
                "bootstrapEndpointIds": [],
            });
            if let Some(peer) = peer {
                let id = &peer.ids[index];
                section["bootstrapEndpointIds"] = json!([id]);
                section["peerAddresses"] =
                    json!({ id.as_str(): [format!("127.0.0.1:{}", peer.udp[index])] });
            }
            section
        };
        let write_configs = |side: &Side, peer: Option<&Side>| -> Result<(), String> {
            write_json(
                &side.home.join("gl-node.config.json"),
                &json!({
                    "ledgerPath": "ledger.bean",
                    "port": side.port,
                    "auth": { "enabled": true, "apiKey": "" },
                    "trustedProxies": ["127.0.0.1"],
                    "signing": { "enabled": true },
                    "p2p": p2p(side, 0, peer),
                }),
            )?;
            for (index, name) in names.iter().enumerate().skip(1) {
                let folder = side.home.join("data/ledgers").join(name);
                fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
                write_json(
                    &folder.join("ledger.json"),
                    &json!({ "signing": { "enabled": true }, "p2p": p2p(side, index, peer) }),
                )?;
            }
            Ok(())
        };

        for side in &mut sides {
            write_configs(side, None)?;
            for name in &names {
                let mut command = Command::new(&options.binary);
                command
                    .arg("--node-id")
                    .current_dir(&side.home)
                    .env("GL_NODE_CONFIG", side.home.join("gl-node.config.json"))
                    .env("GL_NODE_API_KEY", &side.key)
                    .env_remove("RUST_LOG")
                    .stdin(Stdio::null());
                if name != "default" {
                    command.args(["--ledger", name]);
                }
                let output = command.output().map_err(|error| error.to_string())?;
                if !output.status.success() {
                    return Err(format!(
                        "--node-id {name}: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
                side.ids
                    .push(String::from_utf8_lossy(&output.stdout).trim().to_owned());
            }
        }
        write_configs(&sides[0], Some(&sides[1]))?;
        write_configs(&sides[1], Some(&sides[0]))?;

        let mut nodes = Vec::new();
        for side in &sides {
            nodes.push(Node::start(&options.binary, &side.home, &side.key)?);
        }
        for (side, node) in sides.iter().zip(nodes.iter_mut()) {
            let paths: Vec<String> = names.iter().map(|name| path_of(name, "health")).collect();
            wait_for(
                node,
                side.port,
                &paths,
                &side.key,
                &side.home,
                Duration::from_secs(120),
            )?;
        }

        let (a, b) = (&sides[0], &sides[1]);
        let mut clients = 0usize;
        let mut next_client = || {
            clients += 1;
            client(clients)
        };
        for name in &names {
            for account in ["Assets:Cash", "Income:Sales"] {
                graphql(
                    a.port,
                    &path_of(name, "graphql"),
                    &a.key,
                    &format!(
                        r#"mutation {{ openAccount(name: "{account}", date: "2026-01-01") }}"#
                    ),
                    &next_client(),
                )?;
            }
            graphql(
                a.port,
                &path_of(name, "graphql"),
                &a.key,
                &format!(
                    r#"mutation {{ appendTransaction(input: {{ date: "2026-01-02", narration: "entry in {name}", postings: [{{ account: "Assets:Cash", amount: {{ number: "1", currency: "USD" }} }}, {{ account: "Income:Sales" }}] }}) {{ txid }} }}"#
                ),
                &next_client(),
            )?;
        }
        let written = Instant::now();
        let mut seen: Vec<(String, Duration, Vec<String>)> = Vec::new();
        while seen.len() < names.len() && written.elapsed() < Duration::from_secs(120) {
            for name in &names {
                if seen.iter().any(|(done, _, _)| done == name) {
                    continue;
                }
                // A poll that fails is a poll that saw nothing yet.
                let Ok(data) = graphql(
                    b.port,
                    &path_of(name, "graphql"),
                    &b.key,
                    "{ journal { narration } }",
                    &next_client(),
                ) else {
                    continue;
                };
                let narrations: Vec<String> = data["journal"]
                    .as_array()
                    .map(|rows| {
                        rows.iter()
                            .map(|row| row["narration"].as_str().unwrap_or("").to_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                if !narrations.is_empty() {
                    seen.push((name.clone(), written.elapsed(), narrations));
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        // In the order they were seen, as the Python tool reported them.
        let crossed: Vec<(String, Value)> = seen
            .iter()
            .filter(|(name, _, rows)| rows != &[format!("entry in {name}")])
            .map(|(name, _, rows)| (name.clone(), json!(rows)))
            .collect();
        for node in &mut nodes {
            node.stop(Duration::from_secs(120))?;
        }
        let slowest = seen
            .iter()
            .map(|(_, delay, _)| *delay)
            .max()
            .unwrap_or_default();
        println!(
            "{}",
            python_json(&[
                ("mesh", json!("two nodes")),
                ("ledgers_per_node", json!(options.ledgers)),
                ("replicated", json!(seen.len())),
                ("slowest_seconds", json!(round(slowest))),
                ("crossed_into_another_ledger", crossed_json(&crossed)),
            ])
        );
        if seen.len() < names.len() || !crossed.is_empty() {
            return Err("not every ledger replicated, or an entry crossed".to_owned());
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The options parse as the usage says, and a typo is refused.
    ///
    /// Bug-catch: accept an unknown flag silently and `--p2pp` measures a
    /// node without P2P while the operator reads the numbers as with it.
    #[test]
    fn options_parse_as_the_usage_says() {
        let args =
            |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_owned).collect() };
        let options = parse(&args("--ledgers 10 --p2p --binary /x/gl-node")).expect("parses");
        assert_eq!(
            (options.ledgers, options.p2p, options.mesh),
            (10, true, false)
        );
        assert_eq!(options.binary, PathBuf::from("/x/gl-node"));
        assert_eq!(parse(&args("")).expect("defaults").ledgers, 100);
        for bad in ["--p2pp", "--ledgers", "--ledgers ten", "--ledgers 0"] {
            assert!(parse(&args(bad)).is_err(), "{bad}");
        }
    }

    /// Each simulated client is a distinct address, and the UDP ports chosen
    /// are distinct and below the ephemeral range.
    ///
    /// Bug-catch: hand two ledgers the same port and the node refuses one
    /// (as it should), so the measurement waits for a ledger that never comes.
    #[test]
    fn clients_and_ports_are_distinct() {
        let addresses: std::collections::HashSet<String> = (1..2_000).map(client).collect();
        assert_eq!(addresses.len(), 1_999);
        // No socket is bound here (tests stay off the network). A candidate
        // seen twice is taken once; one `claim` refuses is skipped.
        let ports = choose_ports_from(3, [20_000, 20_000, 20_001, 20_002, 20_003], |port| {
            port != 20_001
        });
        assert_eq!(ports, [20_000, 20_002, 20_003]);
        assert!(choose_ports(3, |_| true)
            .iter()
            .all(|port| (20_000..30_000).contains(port)));
    }

    /// The typed book has its two opens and one balanced entry per
    /// transaction asked for, and a result line is written as Python wrote
    /// it.
    ///
    /// Bug-catch: drop the opens and every typed entry is refused at boot
    /// (its accounts are not open), so `--entries` measures empty ledgers.
    #[test]
    fn the_typed_book_has_the_entries_asked_for() {
        let text = book(3);
        assert_eq!(text.matches(" open ").count(), 2);
        assert_eq!(text.matches("\"Invoice ").count(), 3);
        assert!(text.ends_with("  Assets:Bank\n"));
        assert_eq!(
            python_json(&[("a", json!(1)), ("b", json!({ "c": ["d"] }))]),
            r#"{"a": 1, "b": {"c": ["d"]}}"#
        );
    }
}
