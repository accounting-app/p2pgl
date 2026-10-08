//! The `gl-node` binary itself, run the way an operator runs it.
//!
//! Every other test calls the code in-process. These start the built binary as
//! a child process, from a fresh directory, with its config in `GL_NODE_CONFIG`
//! and its API key in `GL_NODE_API_KEY`, and talk to it over HTTP — so they
//! cover what only the binary does: `main`'s wiring, the `--version` and
//! `--health-check` flags (the Docker `HEALTHCHECK`), key creation, the
//! `SIGTERM` shutdown and a restart from the files it left (docs/RELEASE.md).
//!
//! The node runs as the production template has it — auth, signing and P2P on —
//! but binds its API to 127.0.0.1 and runs P2P with relays off and no peers, so
//! it dials nothing and nothing leaves the machine.
//!
//! `cargo test --release` runs them against the release build; `release.sh`
//! does, and also sets `GL_NODE_PREVIOUS_BINARY` for the upgrade rehearsal.

use serde_json::{json, Value};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PREVIOUS_BINARY_VAR: &str = "GL_NODE_PREVIOUS_BINARY";

fn this_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gl-node"))
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut buffer))
        .expect("read /dev/urandom");
    hex::encode(buffer)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free loopback port")
        .port()
}

/// Connect to the node on loopback, retrying a refused or stalled connect for
/// up to 90 s. Nothing is sent before the connection exists, so a retry never
/// repeats a request. The bound matters on a dev Mac whose security software
/// holds new connections from freshly built binaries for up to a minute; a
/// plain `connect` waits that out in one call, a 3 s attempt retries past it.
fn connect(port: u16) -> Result<TcpStream, String> {
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_secs(3)) {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() > deadline => return Err(error.to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Err(error.to_string())
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// One HTTP/1.1 exchange on loopback: `(status, body)`, or why there was none.
fn http(
    port: u16,
    path: &str,
    api_key: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String), String> {
    let mut stream = connect(port)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|error| error.to_string())?;
    let method = if body.is_some() { "POST" } else { "GET" };
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    if let Some(key) = api_key {
        request.push_str(&format!("X-Api-Key: {key}\r\n"));
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
    let content = if head.contains("transfer-encoding: chunked") {
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

/// A gl-node child process in its own directory, killed on drop whatever the
/// test does.
struct Node {
    binary: PathBuf,
    dir: PathBuf,
    port: u16,
    api_key: String,
    child: Option<Child>,
}

impl Node {
    fn new(binary: PathBuf, dir: &Path) -> Self {
        let port = free_port();
        let config = json!({
            // Relative: a node refuses a ledgerPath outside its working directory.
            "ledgerPath": "ledger.bean",
            "bindAddress": "127.0.0.1",
            "port": port,
            "graphiql": false,
            "auth": { "enabled": true, "apiKey": "" },
            "signing": { "enabled": true },
            // P2P on, as in production: only then does a node create its key on
            // first boot (a signing-only node must be given one).
            "p2p": {
                "enabled": true,
                "relayMode": "disabled",
                "bootstrapEndpointIds": [],
                "swarmTopic": format!("shipped-binary/{}", random_hex(8)),
                "meshId": format!("shipped-binary-{}", random_hex(16)),
            },
        });
        std::fs::write(dir.join("gl-node.config.json"), config.to_string()).expect("write config");
        Node {
            binary,
            dir: dir.to_owned(),
            port,
            api_key: random_hex(32),
            child: None,
        }
    }

    fn command(&self, binary: &Path) -> Command {
        let mut command = Command::new(binary);
        command
            .current_dir(&self.dir)
            .env("GL_NODE_CONFIG", self.dir.join("gl-node.config.json"))
            .env("GL_NODE_API_KEY", &self.api_key)
            .env_remove("RUST_LOG");
        command
    }

    fn log(&self, label: &str) -> String {
        std::fs::read_to_string(self.dir.join(format!("{label}.log"))).unwrap_or_default()
    }

    /// Start and wait for `/health` to answer ok; on failure, the boot log.
    fn start(&mut self, label: &str) -> Result<(), String> {
        let log = File::create(self.dir.join(format!("{label}.log"))).expect("create log");
        let child = self
            .command(&self.binary)
            .stdout(log.try_clone().expect("clone log"))
            .stderr(log)
            .spawn()
            .expect("spawn gl-node");
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if let Some(status) = self
                .child
                .as_mut()
                .and_then(|child| child.try_wait().ok().flatten())
            {
                self.child = None;
                return Err(format!(
                    "exited during boot ({status}):\n{}",
                    self.log(label)
                ));
            }
            if let Ok((200, body)) = http(self.port, "/health", None, None) {
                if body.contains("\"status\":\"ok\"") {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        self.kill();
        Err(format!(
            "/health never answered within 120 s:\n{}",
            self.log(label)
        ))
    }

    /// `SIGTERM`, as `docker stop` and systemd send it, and wait for the exit.
    fn stop(&mut self) -> ExitStatus {
        let mut child = self.child.take().expect("a running node");
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("run kill");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().expect("wait for gl-node") {
                return status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("gl-node did not exit within 30 s of SIGTERM");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn graphql_with(&self, query: &str, api_key: Option<&str>) -> (u16, Value) {
        let body = json!({ "query": query }).to_string();
        match http(self.port, "/graphql", api_key, Some(&body)) {
            Ok((status, text)) => (
                status,
                serde_json::from_str(&text).unwrap_or(Value::String(text)),
            ),
            Err(error) => (0, Value::String(error)),
        }
    }

    fn graphql(&self, query: &str) -> Value {
        let (status, body) = self.graphql_with(query, Some(&self.api_key));
        assert_eq!(status, 200, "{query}: {body}");
        body
    }

    /// A mutation that must succeed: no `errors`, and data present.
    fn mutate(&self, mutation: &str) -> Value {
        let body = self.graphql(mutation);
        assert!(
            body.get("errors").is_none() && !body["data"].is_null(),
            "{mutation}: {body}"
        );
        body
    }

    fn cash(&self) -> Value {
        self.graphql(r#"{ account(name: "Assets:Cash") { balances { number currency } } }"#)["data"]
            ["account"]["balances"]
            .clone()
    }

    /// `verify` is ok AND nothing is quarantined: `ok` judges only what the node
    /// serves, so a record held back (a bad signature, say) leaves it true.
    fn assert_verified(&self, when: &str) {
        let body = self.graphql("{ verify { ok quarantined } }");
        assert_eq!(
            body["data"]["verify"],
            json!({ "ok": true, "quarantined": [] }),
            "verify {when}: {body}"
        );
    }

    fn health_check(&self) -> ExitStatus {
        self.command(&self.binary)
            .arg("--health-check")
            .output()
            .expect("run --health-check")
            .status
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.kill();
    }
}

fn post(node: &Node, date: &str, narration: &str, amount: &str) -> Value {
    node.mutate(&format!(
        r#"mutation {{ appendTransaction(input: {{ date: "{date}", narration: "{narration}", postings: [
            {{ account: "Assets:Cash", amount: {{ number: "{amount}", currency: "USD" }} }},
            {{ account: "Income:Salary" }}] }}) {{ txid signature }} }}"#
    ))
}

fn usd(amount: &str) -> Value {
    json!([{ "number": amount, "currency": "USD" }])
}

/// The binary a release ships, end to end: it reports its version, boots from
/// an empty directory with auth and signing on, answers `/health` and the
/// Docker `HEALTHCHECK`, refuses requests without the right key, writes signed
/// transactions and refuses an unbalanced one, reports a balanced trial
/// balance, stops cleanly on `SIGTERM`, and restarts from its files with the
/// same balance and every signature verifying.
///
/// Bug-catch: map `--health-check` to anything that exits 0 without probing
/// and the stopped node passes its health check; ignore `GL_NODE_API_KEY` and
/// every request with it gets 401; drop the `SIGTERM` handler and the node dies
/// by the signal instead of exiting 0.
#[test]
fn the_shipped_binary_serves_signs_stops_and_restarts() {
    let version = Command::new(this_binary())
        .arg("--version")
        .output()
        .expect("run --version");
    let printed = String::from_utf8_lossy(&version.stdout);
    assert!(
        version.status.success() && printed.contains(VERSION),
        "--version: {printed}"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path().canonicalize().expect("canonical tempdir");
    let mut node = Node::new(this_binary(), &dir);

    node.start("first-boot")
        .unwrap_or_else(|log| panic!("boot: {log}"));
    let (_, health) = http(node.port, "/health", None, None).expect("/health");
    assert!(
        health.contains(&format!("\"version\":\"{VERSION}\"")),
        "/health: {health}"
    );
    assert!(
        node.health_check().success(),
        "--health-check against the running node"
    );

    let (status, body) = node.graphql_with("{ verify { ok } }", None);
    assert!(
        status == 401 && body.to_string().contains("UNAUTHORIZED"),
        "no key: {status} {body}"
    );
    let (status, body) = node.graphql_with("{ verify { ok } }", Some(&random_hex(32)));
    assert!(
        status == 401 && body.to_string().contains("UNAUTHORIZED"),
        "wrong key: {status} {body}"
    );

    node.mutate(
        r#"mutation { a1: openAccount(name: "Assets:Cash", date: "2024-01-01", currencies: ["USD"])
            a2: openAccount(name: "Income:Salary", date: "2024-01-01")
            a3: openAccount(name: "Expenses:Rent", date: "2024-01-01") }"#,
    );
    let salary = post(&node, "2024-02-01", "Salary", "5000");
    assert!(
        salary["data"]["appendTransaction"]["signature"]
            .as_str()
            .is_some_and(|signature| !signature.is_empty()),
        "the transaction is signed: {salary}"
    );
    node.mutate(
        r#"mutation { appendTransaction(input: { date: "2024-02-15", narration: "Rent", postings: [
            { account: "Expenses:Rent", amount: { number: "1500", currency: "USD" } },
            { account: "Assets:Cash" }] }) { txid } }"#,
    );
    let unbalanced = node.graphql(
        r#"mutation { appendTransaction(input: { date: "2024-03-01", narration: "Unbalanced", postings: [
            { account: "Assets:Cash", amount: { number: "1", currency: "USD" } },
            { account: "Income:Salary", amount: { number: "-2", currency: "USD" } }] }) { txid } }"#,
    );
    assert!(
        unbalanced.get("errors").is_some() && unbalanced["data"]["appendTransaction"].is_null(),
        "an unbalanced transaction is refused: {unbalanced}"
    );

    assert_eq!(node.cash(), usd("3500"));
    let trial = node.graphql(r#"{ trialBalance(at: "2024-12-31") { totalDebit totalCredit } }"#);
    assert_eq!(
        trial["data"]["trialBalance"],
        json!({ "totalDebit": "5000", "totalCredit": "5000" }),
        "{trial}"
    );
    node.assert_verified("before the restart");

    let exit = node.stop();
    assert_eq!(
        exit.code(),
        Some(0),
        "SIGTERM ends the node with exit 0, not by the signal: {exit}"
    );
    assert!(
        !node.health_check().success(),
        "--health-check fails once the node is stopped"
    );
    let ledger = std::fs::read_to_string(dir.join("ledger.bean")).expect("read ledger");
    assert!(
        ledger.contains("Salary")
            && ledger.contains("Rent")
            && ledger.contains("openledger-signature"),
        "the file holds both transactions, signed:\n{ledger}"
    );

    node.start("restart")
        .unwrap_or_else(|log| panic!("restart: {log}"));
    node.assert_verified("after the restart");
    assert_eq!(node.cash(), usd("3500"), "the balance survives the restart");
    assert_eq!(node.stop().code(), Some(0));
}

/// The upgrade and rollback procedure of docs/OPERATIONS.md, from the previous
/// release's binary (`GL_NODE_PREVIOUS_BINARY`) to this one: the previous
/// version writes a ledger and a backup is taken; this version starts on those
/// files with the balance unchanged and writes; the previous version starts on
/// the restored backup with the pre-upgrade balance; and this version upgrades
/// from there again. Skipped when the variable is unset — `release.sh
/// --previous` sets it.
///
/// Bug-catch: a release that cannot read the previous release's files, or
/// writes files a restored backup does not undo, fails here before it ships.
#[test]
fn an_upgrade_from_the_previous_release_and_a_rollback_keep_the_books() {
    // Unset or empty (`release.sh` without `--previous`) means skip.
    let Some(previous) = std::env::var_os(PREVIOUS_BINARY_VAR)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    else {
        eprintln!("skipped: set {PREVIOUS_BINARY_VAR} to the previous release's gl-node binary");
        return;
    };
    assert!(
        previous.is_file(),
        "{PREVIOUS_BINARY_VAR}: no binary at {}",
        previous.display()
    );
    let current = this_binary();
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path().canonicalize().expect("canonical tempdir");
    let backup = dir.join("backup");
    let ledger_files = ["ledger.bean", "ledger.bean.journal"];
    let mut node = Node::new(previous.clone(), &dir);

    // 1. The previous release writes a ledger; a backup is taken while stopped.
    node.start("previous")
        .unwrap_or_else(|log| panic!("previous release boot: {log}"));
    node.mutate(
        r#"mutation { a1: openAccount(name: "Assets:Cash", date: "2024-01-01", currencies: ["USD"])
            a2: openAccount(name: "Income:Salary", date: "2024-01-01") }"#,
    );
    post(&node, "2024-02-01", "Before the upgrade", "1000");
    assert_eq!(node.cash(), usd("1000"));
    assert_eq!(node.stop().code(), Some(0));
    std::fs::create_dir(&backup).expect("backup dir");
    for name in ledger_files {
        if dir.join(name).exists() {
            std::fs::copy(dir.join(name), backup.join(name)).expect("back up");
        }
    }

    // 2. Upgrade: this release starts on those files, keeps them, and writes.
    node.binary = current.clone();
    node.start("upgraded")
        .unwrap_or_else(|log| panic!("upgraded boot: {log}"));
    assert_eq!(node.cash(), usd("1000"), "the upgrade keeps the balance");
    node.assert_verified("after the upgrade");
    post(&node, "2024-03-01", "After the upgrade", "500");
    assert_eq!(node.cash(), usd("1500"));
    assert_eq!(node.stop().code(), Some(0));

    // 3. Rollback: the previous release on the restored backup — the ledger
    //    files deleted first, as the procedure says.
    for name in ledger_files {
        let _ = std::fs::remove_file(dir.join(name));
        if backup.join(name).exists() {
            std::fs::copy(backup.join(name), dir.join(name)).expect("restore");
        }
    }
    node.binary = previous;
    node.start("rolled-back")
        .unwrap_or_else(|log| panic!("rollback boot: {log}"));
    assert_eq!(
        node.cash(),
        usd("1000"),
        "the rollback restores the pre-upgrade balance"
    );
    node.assert_verified("after the rollback");
    assert_eq!(node.stop().code(), Some(0));

    // 4. Upgrade again from the restored state.
    node.binary = current;
    node.start("upgraded-again")
        .unwrap_or_else(|log| panic!("second upgrade boot: {log}"));
    assert_eq!(node.cash(), usd("1000"));
    assert_eq!(node.stop().code(), Some(0));
}
