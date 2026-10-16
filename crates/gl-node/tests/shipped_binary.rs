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

/// `gl-node --node-id` (`docs/build-log/001-peer-discovery`): before the node
/// has ever started, it creates the node key and prints the EndpointId; again,
/// it prints the same id; the key file is the node's alone (0600); and the
/// node, once started, binds with exactly that id — so an operator can hand
/// peers the id before the first boot.
///
/// Bug-catch: route `--node-id` anywhere else and no id is printed; print an
/// id from anything but the node key and the running node disagrees with it.
#[test]
fn node_id_prints_the_id_the_node_will_have_before_it_starts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path().canonicalize().expect("canonical tempdir");
    let mut node = Node::new(this_binary(), &dir);
    let node_id = |node: &Node| {
        let output = node
            .command(&node.binary)
            .arg("--node-id")
            .output()
            .expect("run --node-id");
        assert!(
            output.status.success(),
            "--node-id: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("utf-8")
            .trim()
            .to_owned()
    };

    let first = node_id(&node);
    assert_eq!(first.len(), 64, "an EndpointId in hex: {first:?}");
    assert!(
        first.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{first:?}"
    );
    assert_eq!(node_id(&node), first, "the same id every time");
    let key_file = dir.join("data/iroh.secret");
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&key_file)
                .expect("the key file exists")
                .permissions()
        ) & 0o777,
        0o600,
        "the node key is readable by its owner alone"
    );

    node.start("after-node-id")
        .unwrap_or_else(|log| panic!("boot: {log}"));
    // The log is colored: drop the ANSI escapes before matching `node_id=<id>`.
    let mut log = String::new();
    let raw = node.log("after-node-id");
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            log.push(c);
        }
    }
    assert!(
        log.contains(&format!("node_id={first}")),
        "the running node has the id --node-id printed ({first}):\n{log}"
    );
    assert_eq!(node.stop().code(), Some(0));
}

/// `--node-id` on a node that signs with P2P off loads the key and never
/// creates one, as boot does: a missing key is an operator error there, not an
/// identity to invent (`main.rs`, the key-loading comment).
///
/// Bug-catch: let `--node-id` create the key whenever signing is on and a
/// signing-only node gets an identity its boot would have refused to invent.
#[test]
fn node_id_never_creates_a_key_for_a_signing_only_node() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path().canonicalize().expect("canonical tempdir");
    let config = dir.join("gl-node.config.json");
    std::fs::write(
        &config,
        json!({
            "ledgerPath": "ledger.bean",
            "signing": { "enabled": true },
            "p2p": { "enabled": false, "meshId": "signing-only-test" },
        })
        .to_string(),
    )
    .expect("write config");
    let output = Command::new(this_binary())
        .arg("--node-id")
        .current_dir(&dir)
        .env("GL_NODE_CONFIG", &config)
        .env_remove("RUST_LOG")
        .output()
        .expect("run --node-id");
    assert!(
        !output.status.success(),
        "a missing key is refused, not created"
    );
    assert!(output.stdout.is_empty(), "no id is printed");
    assert!(
        !dir.join("data/iroh.secret").exists(),
        "no key file was created"
    );
}

/// On a loopback node with auth turned off, every request runs as the
/// operator (002-users-and-roles): the role check sees an admin caller, so
/// writes still work, as they did before roles existed.
///
/// It issues no one a key, though: with auth off, `gl-node user add` (as any
/// local process) is refused (`NO_ACCESS_LIST`).
///
/// Bug-catch: attach no caller on the auth-off path and every request on
/// such a node is refused; keep an access list with auth off and any local
/// process mints admin keys the whole mesh honours.
#[test]
fn with_auth_off_a_loopback_node_still_serves_its_operator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path().canonicalize().expect("canonical tempdir");
    let mut node = Node::new(this_binary(), &dir);
    let mut config: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("gl-node.config.json")).expect("config"),
    )
    .expect("json");
    config["auth"] = json!({ "enabled": false });
    std::fs::write(dir.join("gl-node.config.json"), config.to_string()).expect("write config");

    node.start("auth-off")
        .unwrap_or_else(|log| panic!("boot: {log}"));
    let (status, body) = node.graphql_with(
        r#"mutation { openAccount(name: "Assets:Cash", date: "2024-01-01") }"#,
        None,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.get("errors").is_none(), "the operator writes: {body}");
    // 002 step 3 review I-1: anything on this machine is the operator here,
    // so it must not issue keys the whole mesh would honour.
    let output = node
        .command(&node.binary)
        .args(["user", "add", "--name", "Mallory", "--role", "admin"])
        .output()
        .expect("run gl-node user");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "refused");
    assert!(stderr.contains("NO_ACCESS_LIST"), "{stderr}");
    assert_eq!(node.stop().code(), Some(0));
}

/// `gl-node user` against the shipped binary (002-users-and-roles step 3):
/// with the operator key from the node's own environment, `user add` prints a
/// key that works at once with the role given — reads, but not writes, for
/// read — and `user list` shows the person by name; a writer's entries carry
/// their id (`entered-by`); after a restart the signed access records and
/// entries verify, the key still works and the journal names the writer;
/// `user revoke` ends it (401).
///
/// Bug-catch: drop the `user` subcommand and every `gl-node user` exits with
/// the usage; sign access records over the wrong message and the restart
/// quarantines them, so the key stops working.
#[test]
fn people_are_managed_with_gl_node_user() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path().canonicalize().expect("canonical tempdir");
    let mut node = Node::new(this_binary(), &dir);
    node.start("users")
        .unwrap_or_else(|log| panic!("boot: {log}"));
    // A fn, not a closure: the node is stopped and restarted in between.
    fn user(node: &Node, args: &[&str]) -> String {
        let output = node
            .command(&node.binary)
            .arg("user")
            .args(args)
            .output()
            .expect("run gl-node user");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "user {args:?}: {stderr}");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
    let field = |output: &str, label: &str| {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix(label))
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|| panic!("{label} in {output}"))
    };

    let added = user(&node, &["add", "--name", "Ana Ruiz", "--role", "read"]);
    let (id, key) = (field(&added, "user id:"), field(&added, "key:"));
    let (status, body) = node.graphql_with("{ verify { ok } }", Some(&key));
    assert_eq!(
        (status, &body["data"]["verify"]["ok"]),
        (200, &json!(true)),
        "{body}"
    );
    let (status, body) = node.graphql_with(
        r#"mutation { openAccount(name: "Assets:Cash", date: "2024-01-01") }"#,
        Some(&key),
    );
    assert_eq!(status, 200);
    assert_eq!(
        body["errors"][0]["extensions"]["code"], "FORBIDDEN",
        "{body}"
    );
    let listed = user(&node, &["list"]);
    assert!(
        listed.contains(&id) && listed.contains("Ana Ruiz"),
        "{listed}"
    );

    // Step 4: a writer's entries carry their id, signed with the record.
    let writer = user(&node, &["add", "--name", "Bea Soto", "--role", "write"]);
    let (bea, bea_key) = (field(&writer, "user id:"), field(&writer, "key:"));
    for account in ["Assets:Cash", "Income:Salary"] {
        let (status, body) = node.graphql_with(
            &format!(r#"mutation {{ openAccount(name: "{account}", date: "2024-01-01") }}"#),
            Some(&bea_key),
        );
        assert!(status == 200 && body.get("errors").is_none(), "{body}");
    }
    let (status, body) = node.graphql_with(
        r#"mutation { appendTransaction(input: { date: "2024-01-02", narration: "by Bea", postings: [
            { account: "Assets:Cash", amount: { number: "5", currency: "USD" } },
            { account: "Income:Salary" }] }) { txid signature } }"#,
        Some(&bea_key),
    );
    assert!(status == 200 && body.get("errors").is_none(), "{body}");

    assert_eq!(node.stop().code(), Some(0));
    node.start("users-restarted")
        .unwrap_or_else(|log| panic!("restart: {log}"));
    node.assert_verified("after the restart");
    let (status, body) = node.graphql_with("{ verify { ok } }", Some(&key));
    assert_eq!(status, 200, "the key survives a restart: {body}");
    let journal = node.graphql("{ journal { narration enteredBy enteredByName signature } }");
    let entry = journal["data"]["journal"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["narration"] == "by Bea"))
        .cloned()
        .unwrap_or_else(|| panic!("{journal}"));
    assert_eq!(entry["enteredBy"], json!(bea), "{entry}");
    assert_eq!(entry["enteredByName"], "Bea Soto");
    assert!(entry["signature"].is_string(), "signed: {entry}");

    user(&node, &["revoke", &bea]);
    user(&node, &["revoke", &id]);
    let (status, _) = node.graphql_with("{ verify { ok } }", Some(&key));
    assert_eq!(status, 401, "revoked");
    assert!(user(&node, &["list"]).starts_with("No one is on the access list"));
    assert_eq!(node.stop().code(), Some(0));
}

/// Several ledgers on the shipped binary (003 step 2): beside the config
/// file's ledger, a folder `ledgers/acme` with its own mesh and a folder
/// whose `ledger.json` does not parse. The node serves both good ledgers and
/// refuses the broken one without stopping; acme has its own node id; a key
/// issued in acme (`gl-node user --ledger acme`) works there and gets 401 on
/// the default ledger; an account opened in acme is in acme's books only; the
/// broken ledger is a 503 to the operator and a 401 to anyone else; and after
/// a restart acme's key still works.
///
/// A folder named `default` in `ledgersDir` is ignored: the config file's
/// ledger stays served (review I-1); and a folder holding a copy of the config
/// file's node key is refused while the config file's ledger keeps it.
///
/// Bug-catch: stop the node when one ledger folder does not load and every
/// company on it goes down with the one; let `--node-id` ignore `--ledger`
/// and acme's peers are given the default ledger's id.
#[test]
fn several_ledgers_are_served_side_by_side() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path().canonicalize().expect("canonical tempdir");
    let mut node = Node::new(this_binary(), &dir);
    let acme = dir.join("data/ledgers/acme");
    std::fs::create_dir_all(&acme).expect("acme folder");
    std::fs::write(
        acme.join("ledger.json"),
        json!({
            "signing": { "enabled": true },
            "p2p": {
                "enabled": true,
                "relayMode": "disabled",
                "bootstrapEndpointIds": [],
                "swarmTopic": format!("shipped-binary/acme-{}", random_hex(8)),
                "meshId": format!("acme-{}", random_hex(16)),
            },
        })
        .to_string(),
    )
    .expect("acme ledger.json");
    let broken = dir.join("data/ledgers/broken");
    std::fs::create_dir_all(&broken).expect("broken folder");
    std::fs::write(broken.join("ledger.json"), "{").expect("broken ledger.json");
    std::fs::create_dir_all(dir.join("data/ledgers/default")).expect("a stray default folder");
    // A folder holding a copy of the config file's own node key (review):
    // the config file's ledger keeps its key, the copy is refused.
    let copied = dir.join("data/ledgers/copied");
    std::fs::create_dir_all(&copied).expect("copied folder");
    let own_id = node
        .command(&node.binary)
        .arg("--node-id")
        .output()
        .expect("create the node's key");
    assert!(
        own_id.status.success(),
        "{}",
        String::from_utf8_lossy(&own_id.stderr)
    );
    std::fs::copy(dir.join("data/iroh.secret"), copied.join("iroh.secret")).expect("copy the key");
    std::fs::write(
        copied.join("ledger.json"),
        json!({
            "signing": { "enabled": true },
            "p2p": {
                "enabled": true,
                "relayMode": "disabled",
                "bootstrapEndpointIds": [],
                "swarmTopic": format!("shipped-binary/copied-{}", random_hex(8)),
                "meshId": format!("copied-{}", random_hex(16)),
            },
        })
        .to_string(),
    )
    .expect("copied ledger.json");
    node.start("ledgers")
        .unwrap_or_else(|log| panic!("boot: {log}"));

    let node_id = |ledger: Option<&str>| {
        let mut command = node.command(&node.binary);
        command.arg("--node-id");
        if let Some(ledger) = ledger {
            command.args(["--ledger", ledger]);
        }
        let output = command.output().expect("run --node-id");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    };
    assert_ne!(node_id(None), node_id(Some("acme")), "a key per ledger");

    let added = node
        .command(&node.binary)
        .args([
            "user", "--ledger", "acme", "add", "--name", "Ana", "--role", "write",
        ])
        .output()
        .expect("run gl-node user");
    let stdout = String::from_utf8_lossy(&added.stdout).into_owned();
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let key = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("key:"))
        .map(|key| key.trim().to_owned())
        .unwrap_or_else(|| panic!("a key in {stdout}"));

    let port = node.port;
    let at = |path: &str, key: Option<&str>, query: &str| {
        let body = json!({ "query": query }).to_string();
        let (status, text) = http(port, path, key, Some(&body)).expect("http");
        (
            status,
            serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text)),
        )
    };
    for account in ["Assets:Acme", "Income:Acme"] {
        let (status, body) = at(
            "/ledgers/acme/graphql",
            Some(&key),
            &format!(r#"mutation {{ openAccount(name: "{account}", date: "2024-01-01") }}"#),
        );
        assert!(status == 200 && body.get("errors").is_none(), "{body}");
    }
    let (status, body) = at(
        "/ledgers/acme/graphql",
        Some(&key),
        r#"mutation { appendTransaction(input: { date: "2024-01-02", narration: "acme only", postings: [
            { account: "Assets:Acme", amount: { number: "5", currency: "USD" } },
            { account: "Income:Acme" }] }) { txid } }"#,
    );
    assert!(status == 200 && body.get("errors").is_none(), "{body}");
    let (status, _) = at("/graphql", Some(&key), "{ verify { ok } }");
    assert_eq!(status, 401, "acme's key on the default ledger");
    let operator = node.api_key.clone();
    let narrations = |path: &str| {
        let (status, body) = at(path, Some(&operator), "{ journal { narration } }");
        assert!(
            status == 200 && body.get("errors").is_none(),
            "{path}: {body}"
        );
        body["data"]["journal"]
            .as_array()
            .expect("rows")
            .iter()
            .map(|row| row["narration"].as_str().unwrap_or("").to_owned())
            .collect::<Vec<_>>()
    };
    assert!(
        !narrations("/graphql").contains(&"acme only".to_owned()),
        "not in the default ledger"
    );
    assert_eq!(narrations("/ledgers/acme/graphql"), ["acme only"]);

    let (status, body) = at(
        "/ledgers/broken/graphql",
        Some(&operator),
        "{ verify { ok } }",
    );
    assert_eq!(status, 503, "{body}");
    let (status, _) = at("/ledgers/broken/graphql", None, "{ verify { ok } }");
    assert_eq!(status, 401);
    let (status, body) = at(
        "/ledgers/copied/graphql",
        Some(&operator),
        "{ verify { ok } }",
    );
    assert_eq!(status, 503, "the copy of the node's key is refused: {body}");

    assert_eq!(node.stop().code(), Some(0));
    node.start("ledgers-restarted")
        .unwrap_or_else(|log| panic!("restart: {log}"));
    node.assert_verified("the default ledger after the restart");
    let (status, body) = at("/ledgers/acme/graphql", Some(&key), "{ verify { ok } }");
    assert_eq!(status, 200, "acme's key after the restart: {body}");
    assert_eq!(narrations("/ledgers/acme/graphql"), ["acme only"]);
    assert_eq!(node.stop().code(), Some(0));
}

/// Ledgers added and removed while the shipped binary runs (003 step 4):
/// `gl-node ledger add` serves a new company at once, its own mesh and node
/// key made with it — the id it prints is the one `--node-id --ledger` gives
/// — and people are added to it with `gl-node user --ledger`; `gl-node
/// ledger remove` stops it and moves its folder, books included, to
/// `ledgersDir/.removed/`; a ledger added again under the name is a new one;
/// and after a restart the node serves what was added, not what was removed.
///
/// Bug-catch: route `gl-node ledger` anywhere but the node endpoint and
/// every command fails; leave a removed folder in `ledgersDir` and the
/// restart serves the company that was removed.
#[test]
fn ledgers_are_added_and_removed_while_the_node_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir = dir.path().canonicalize().expect("canonical tempdir");
    let mut node = Node::new(this_binary(), &dir);
    node.start("runtime")
        .unwrap_or_else(|log| panic!("boot: {log}"));
    let run = |node: &Node, args: &[&str]| {
        let output = node
            .command(&node.binary)
            .args(args)
            .output()
            .expect("run gl-node");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "{args:?}: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        stdout
    };
    let settings = dir.join("acme.json");
    std::fs::write(
        &settings,
        json!({
            "signing": { "enabled": true },
            "p2p": {
                "enabled": true,
                "relayMode": "disabled",
                "bootstrapEndpointIds": [],
                "swarmTopic": format!("shipped-binary/acme-{}", random_hex(8)),
                "meshId": format!("acme-{}", random_hex(16)),
            },
        })
        .to_string(),
    )
    .expect("acme settings");
    let added = run(
        &node,
        &[
            "ledger",
            "add",
            "acme",
            "--settings",
            settings.to_str().expect("utf-8"),
        ],
    );
    let printed = added
        .lines()
        .find_map(|line| line.trim().strip_prefix("node id:"))
        .map(|id| id.trim().to_owned())
        .unwrap_or_else(|| panic!("a node id in {added}"));
    let node_id = run(&node, &["--node-id", "--ledger", "acme"]);
    assert_eq!(printed, node_id.trim(), "the id peers are given is acme's");

    let granted = run(
        &node,
        &[
            "user", "--ledger", "acme", "add", "--name", "Ana", "--role", "write",
        ],
    );
    let key = granted
        .lines()
        .find_map(|line| line.trim().strip_prefix("key:"))
        .map(|key| key.trim().to_owned())
        .unwrap_or_else(|| panic!("a key in {granted}"));
    let port = node.port;
    let at = |key: &str, query: &str| {
        let body = json!({ "query": query }).to_string();
        let (status, text) =
            http(port, "/ledgers/acme/graphql", Some(key), Some(&body)).expect("http");
        (
            status,
            serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text)),
        )
    };
    let (status, body) = at(
        &key,
        r#"mutation { openAccount(name: "Assets:Acme", date: "2024-01-01") }"#,
    );
    assert!(status == 200 && body.get("errors").is_none(), "{body}");
    let listed = run(&node, &["ledger", "list"]);
    assert!(
        listed
            .lines()
            .any(|line| line.starts_with("acme ") && line.contains(&printed)),
        "{listed}"
    );

    let removed = run(&node, &["ledger", "remove", "acme"]);
    assert!(removed.contains(".removed/acme-"), "{removed}");
    let ledgers_dir = dir.join("data/ledgers");
    let moved: Vec<PathBuf> = std::fs::read_dir(ledgers_dir.join(".removed"))
        .expect("the removed folders")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert_eq!(moved.len(), 1, "{moved:?}");
    let books = std::fs::read_to_string(moved[0].join("ledger.bean")).expect("acme's books");
    assert!(
        books.contains("Assets:Acme"),
        "folded in and moved: {books}"
    );
    let operator = node.api_key.clone();
    let (status, _) = at(&operator, "{ verify { ok } }");
    assert_eq!(status, 404, "acme is no longer served");

    run(&node, &["ledger", "add", "acme"]);
    let (status, body) = at(
        &operator,
        r#"{ account(name: "Assets:Acme") { balances { number } } }"#,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body["data"]["account"].is_null(), "a new ledger: {body}");
    let (status, _) = at(&key, "{ verify { ok } }");
    assert_eq!(status, 401, "the old acme's people are not the new one's");

    assert_eq!(node.stop().code(), Some(0));
    node.start("runtime-restarted")
        .unwrap_or_else(|log| panic!("restart: {log}"));
    let listed = run(&node, &["ledger", "list"]);
    let names: Vec<&str> = listed
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(names, ["acme", "default"], "{listed}");
    assert!(
        !listed.contains(&printed),
        "the removed acme is not back: {listed}"
    );
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
