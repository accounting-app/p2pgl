//! `gl-node user add | list | revoke | rename` (`docs/build-log/002-users-and-roles`,
//! step 3): a thin client of the admin API (`crate::graphql::access`) for the
//! operator at the node's own machine.
//!
//! It reads the node's config (`GL_NODE_CONFIG`) for the port and the operator
//! key — `auth.apiKey`, `GL_NODE_API_KEY` or the key file, which it reads and
//! never creates — and sends one GraphQL request to the node's own port. It
//! holds no rules of its own: the node judges every change, so the CLI and the
//! API cannot disagree. Run it as the node's user (the key file is 0600).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{json, Value};

use crate::config::NodeConfig;

/// The usage line for `gl-node user`.
pub const USAGE: &str = "Usage:
  gl-node user add --name NAME --role read|write|admin [--expires YYYY-MM-DD]
  gl-node user add --user USER_ID --role read|write|admin [--expires YYYY-MM-DD] [--name NAME]
      (someone already on the list: new role, expiry and key; their old key stops working)
  gl-node user list
  gl-node user rename USER_ID --name NAME
  gl-node user revoke USER_ID
Each takes --ledger NAME for a ledger other than the config file's own.";

/// One `gl-node user` command, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserCommand {
    Add {
        name: Option<String>,
        role: String,
        expires: Option<String>,
        user: Option<String>,
    },
    List,
    Rename {
        user: String,
        name: String,
    },
    Revoke {
        user: String,
    },
}

/// Parse the arguments after `gl-node user`.
pub fn parse(args: &[String]) -> Result<UserCommand, String> {
    let (command, rest) = args.split_first().ok_or("no user command given")?;
    let mut positional = Vec::new();
    let mut options = std::collections::BTreeMap::new();
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--name" | "--role" | "--expires" | "--user" => {
                let value = rest.next().ok_or_else(|| format!("{arg} needs a value"))?;
                if options.insert(arg.as_str(), value.clone()).is_some() {
                    return Err(format!("{arg} given twice"));
                }
            }
            other if other.starts_with("--") => return Err(format!("unknown option {other}")),
            other => positional.push(other.to_owned()),
        }
    }
    let allow = |allowed: &[&str]| -> Result<(), String> {
        match options.keys().find(|option| !allowed.contains(option)) {
            Some(option) => Err(format!("{option} does not apply to `user {command}`")),
            None => Ok(()),
        }
    };
    let one_user = |positional: Vec<String>| -> Result<String, String> {
        match <[String; 1]>::try_from(positional) {
            Ok([user]) => Ok(user),
            Err(_) => Err(format!("`user {command}` takes one USER_ID")),
        }
    };
    match command.as_str() {
        "add" => {
            allow(&["--name", "--role", "--expires", "--user"])?;
            if !positional.is_empty() {
                return Err("`user add` takes no USER_ID; use --user to change someone".to_owned());
            }
            let role = options.remove("--role").ok_or("`user add` needs --role")?;
            let user = options.remove("--user");
            let name = options.remove("--name");
            if user.is_none() && name.is_none() {
                return Err("`user add` needs --name for a new person".to_owned());
            }
            Ok(UserCommand::Add {
                name,
                role,
                expires: options.remove("--expires"),
                user,
            })
        }
        "list" => {
            allow(&[])?;
            if !positional.is_empty() {
                return Err("`user list` takes no arguments".to_owned());
            }
            Ok(UserCommand::List)
        }
        "rename" => {
            allow(&["--name"])?;
            let name = options
                .remove("--name")
                .ok_or("`user rename` needs --name")?;
            Ok(UserCommand::Rename {
                user: one_user(positional)?,
                name,
            })
        }
        "revoke" => {
            allow(&[])?;
            Ok(UserCommand::Revoke {
                user: one_user(positional)?,
            })
        }
        other => Err(format!("unknown user command {other:?}")),
    }
}

/// The GraphQL request body for `command`.
fn request_body(command: &UserCommand) -> Result<Value, String> {
    Ok(match command {
        UserCommand::Add {
            name,
            role,
            expires,
            user,
        } => {
            let role = match role.as_str() {
                "read" | "write" | "admin" => role.to_ascii_uppercase(),
                other => {
                    return Err(format!(
                        "--role must be read, write or admin, not {other:?}"
                    ))
                }
            };
            json!({
                "query": "mutation($name: String, $role: AccessRole!, $expires: Date, $user: String) \
                          { grantAccess(name: $name, role: $role, expires: $expires, userId: $user) \
                          { userId name role expires key } }",
                "variables": { "name": name, "role": role, "expires": expires, "user": user },
            })
        }
        UserCommand::List => json!({
            "query": "{ accessList { userId name role expires expired } }",
        }),
        UserCommand::Rename { user, name } => json!({
            "query": "mutation($user: String!, $name: String!) { renameUser(userId: $user, name: $name) }",
            "variables": { "user": user, "name": name },
        }),
        UserCommand::Revoke { user } => json!({
            "query": "mutation($user: String!) { revokeAccess(userId: $user) }",
            "variables": { "user": user },
        }),
    })
}

/// What to print for `command`'s answer `data`.
fn render(command: &UserCommand, data: &Value) -> String {
    let text = |value: &Value| value.as_str().unwrap_or("").to_owned();
    let role = |value: &Value| text(value).to_ascii_lowercase();
    match command {
        UserCommand::Add { .. } => {
            let granted = &data["grantAccess"];
            let expires = match granted["expires"].as_str() {
                Some(last) => format!("{last} (the last day the key works)"),
                None => "never".to_owned(),
            };
            format!(
                "Granted {name} {role} access.\n  user id:  {user}\n  expires:  {expires}\n  \
                 key:      {key}\n\nThe key is shown this once: the node keeps only its hash. Give \
                 it to {name} over a channel you trust; they send it as the X-Api-Key header.\n",
                name = text(&granted["name"]),
                role = role(&granted["role"]),
                user = text(&granted["userId"]),
                key = text(&granted["key"]),
            )
        }
        UserCommand::List => {
            let people = data["accessList"].as_array().cloned().unwrap_or_default();
            if people.is_empty() {
                return "No one is on the access list; only the operator key works. Add someone \
                        with `gl-node user add`.\n"
                    .to_owned();
            }
            let mut out = format!(
                "{:<20}  {:<6}  {:<21}  NAME\n",
                "USER ID", "ROLE", "EXPIRES"
            );
            for person in &people {
                let expires = match (person["expires"].as_str(), person["expired"].as_bool()) {
                    (Some(last), Some(true)) => format!("{last} (expired)"),
                    (Some(last), _) => last.to_owned(),
                    (None, _) => "never".to_owned(),
                };
                out.push_str(&format!(
                    "{:<20}  {:<6}  {:<21}  {}\n",
                    text(&person["userId"]),
                    role(&person["role"]),
                    expires,
                    text(&person["name"]),
                ));
            }
            out
        }
        UserCommand::Rename { user, name } => format!("Renamed {user} to {name}.\n"),
        UserCommand::Revoke { user } => {
            format!("Revoked {user}: their key is refused on each node as the record reaches it.\n")
        }
    }
}

/// The bound on a response the CLI reads: an access list of thousands of
/// people fits many times over.
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// `--ledger NAME` taken out of `args` (003), anywhere in them, with the rest:
/// the ledger the command is for — `default`, the config file's own, unless
/// named.
pub fn take_ledger(args: &[String]) -> Result<(String, Vec<String>), String> {
    let mut ledger = None;
    let mut rest = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--ledger" {
            let name = args.next().ok_or("--ledger needs a value")?;
            if ledger.replace(name.clone()).is_some() {
                return Err("--ledger given twice".to_owned());
            }
        } else {
            rest.push(arg.clone());
        }
    }
    let ledger = ledger.unwrap_or_else(|| crate::config::DEFAULT_LEDGER.to_owned());
    if ledger != crate::config::DEFAULT_LEDGER && !crate::config::is_valid_ledger_name(&ledger) {
        return Err(format!(
            "{ledger:?} is not a ledger name: 1 to 40 of a-z, 0-9 and -, not starting with -"
        ));
    }
    Ok((ledger, rest))
}

/// The GraphQL path of `ledger` on its node (003): `/graphql` for the config
/// file's own, `/ledgers/<name>/graphql` for the others.
pub fn graphql_path(ledger: &str) -> String {
    if ledger == crate::config::DEFAULT_LEDGER {
        "/graphql".to_owned()
    } else {
        format!("/ledgers/{ledger}/graphql")
    }
}

/// Send `body` to the node's `path` on `host:port` with `api_key`, and return
/// the GraphQL response.
fn exchange(
    host: &str,
    port: u16,
    path: &str,
    api_key: Option<&str>,
    body: &Value,
) -> Result<Value, String> {
    let address = format!("{host}:{port}");
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        address.clone()
    };
    let socket_address = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("node address {address}: {error}"))?
        .next()
        .ok_or_else(|| format!("node address {address} did not resolve"))?;
    let mut stream = TcpStream::connect_timeout(&socket_address, Duration::from_secs(5))
        .map_err(|error| format!("could not reach the node at {address}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|error| error.to_string())?;
    let payload = body.to_string();
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n",
        payload.len()
    );
    if let Some(key) = api_key {
        request.push_str(&format!("X-Api-Key: {key}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&payload);
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("sending to the node: {error}"))?;
    let mut raw = Vec::new();
    (&mut stream)
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut raw)
        .map_err(|error| format!("reading the node's answer: {error}"))?;
    let (status, content) = split_response(&raw)?;
    if status == 401 {
        return Err(
            "the node refused the operator key (HTTP 401): is GL_NODE_CONFIG this node's config, \
             and the key the one it serves with?"
                .to_owned(),
        );
    }
    serde_json::from_slice(&content).map_err(|_| {
        format!(
            "the node answered HTTP {status} with something other than GraphQL: {}",
            String::from_utf8_lossy(&content)
                .chars()
                .take(200)
                .collect::<String>()
        )
    })
}

/// An HTTP/1.1 response's status and body (de-chunked).
fn split_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("the node's answer has no end of headers")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or("the node's answer has no status code")?;
    let content = &raw[split + 4..];
    let chunked = head.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim() == "transfer-encoding"
                && value.split(',').any(|coding| coding.trim() == "chunked")
        })
    });
    if !chunked {
        return Ok((status, content.to_vec()));
    }
    let mut rest = content;
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or("a chunk of the node's answer is cut short")?;
        let size_text = String::from_utf8_lossy(&rest[..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "a chunk of the node's answer has no size")?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok((status, out));
        }
        let chunk = rest
            .get(..size)
            .ok_or("a chunk of the node's answer is cut short")?;
        out.extend_from_slice(chunk);
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
}

/// The GraphQL errors in `answer`, as one message, if any.
fn graphql_errors(answer: &Value) -> Option<String> {
    let errors = answer["errors"]
        .as_array()
        .filter(|errors| !errors.is_empty())?;
    Some(
        errors
            .iter()
            .map(|error| match error["extensions"]["code"].as_str() {
                Some(code) => format!("{} ({code})", error["message"].as_str().unwrap_or("")),
                None => error["message"].as_str().unwrap_or("").to_owned(),
            })
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// Run `command` against the node at `host:port`: what to print, or why not.
#[cfg(test)]
pub fn execute(
    host: &str,
    port: u16,
    api_key: Option<&str>,
    command: &UserCommand,
) -> Result<String, String> {
    execute_on(host, port, "/graphql", api_key, command)
}

/// [`execute`] against the ledger at `path` ([`graphql_path`]).
pub fn execute_on(
    host: &str,
    port: u16,
    path: &str,
    api_key: Option<&str>,
    command: &UserCommand,
) -> Result<String, String> {
    let answer = exchange(host, port, path, api_key, &request_body(command)?)?;
    if let Some(errors) = graphql_errors(&answer) {
        return Err(errors);
    }
    Ok(render(command, &answer["data"]))
}

/// `gl-node user …`: parse, find the node and its operator key, run, exit.
pub fn run(args: &[String]) -> ! {
    let (ledger, args) = match take_ledger(args) {
        Ok(taken) => taken,
        Err(error) => {
            eprintln!("user: {error}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let command = match parse(&args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("user: {error}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let config_path =
        std::env::var("GL_NODE_CONFIG").unwrap_or_else(|_| "gl-node.config.json".to_owned());
    let config = match NodeConfig::load_from_path(&std::path::PathBuf::from(&config_path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("user: failed to load config {config_path}: {error}");
            std::process::exit(1);
        }
    };
    let api_key = if !config.auth.enabled {
        None
    } else if config.uses_api_key_file() {
        match crate::auth::read_existing_api_key(std::path::Path::new(&config.auth.api_key_path)) {
            Ok(key) => Some(key),
            Err(error) => {
                eprintln!("user: {error}");
                std::process::exit(1);
            }
        }
    } else {
        Some(zeroize::Zeroizing::new(config.auth.api_key.clone()))
    };
    // A wildcard bind is reached on loopback, as `--health-check` does.
    let host = match config.bind_address.as_str() {
        "0.0.0.0" | "*" | "" => "127.0.0.1",
        "::" => "::1",
        other => other,
    };
    match execute_on(
        host,
        config.port,
        &graphql_path(&ledger),
        api_key.as_ref().map(|key| key.as_str()),
        &command,
    ) {
        Ok(output) => {
            print!("{output}");
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("user: {error}");
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

    /// The commands parse as the usage says, and a mistyped one is refused
    /// with a reason rather than guessed at: a missing value, an option given
    /// twice, an option another command owns, a stray USER_ID.
    ///
    /// Bug-catch: let `add` through without `--name` or `--user` and a typo
    /// reaches the node as a request for a nameless person, refused there
    /// with a message about the API rather than the command.
    #[test]
    fn user_commands_parse_as_the_usage_says() {
        assert_eq!(
            parse(&args("add --name Ana --role write --expires 2026-12-31")),
            Ok(UserCommand::Add {
                name: Some("Ana".to_owned()),
                role: "write".to_owned(),
                expires: Some("2026-12-31".to_owned()),
                user: None,
            })
        );
        assert_eq!(
            parse(&args("add --user u_0123456789abcdef --role read")),
            Ok(UserCommand::Add {
                name: None,
                role: "read".to_owned(),
                expires: None,
                user: Some("u_0123456789abcdef".to_owned()),
            })
        );
        assert_eq!(parse(&args("list")), Ok(UserCommand::List));
        assert_eq!(
            parse(&args("rename u_1 --name Bea")),
            Ok(UserCommand::Rename {
                user: "u_1".to_owned(),
                name: "Bea".to_owned()
            })
        );
        assert_eq!(
            parse(&args("revoke u_1")),
            Ok(UserCommand::Revoke {
                user: "u_1".to_owned()
            })
        );
        // A name with spaces is one argument (the shell quotes it).
        let spaced = vec![
            "add".to_owned(),
            "--name".to_owned(),
            "Ana Ruiz".to_owned(),
            "--role".to_owned(),
            "read".to_owned(),
        ];
        assert!(matches!(
            parse(&spaced),
            Ok(UserCommand::Add { name: Some(name), .. }) if name == "Ana Ruiz"
        ));

        for bad in [
            "",
            "add --role write",
            "add --name Ana",
            "add --name Ana --role write u_1",
            "add --name Ana --name Bea --role read",
            "add --name",
            "list --name Ana",
            "list extra",
            "rename --name Bea",
            "rename u_1",
            "revoke",
            "revoke u_1 u_2",
            "revoke u_1 --role read",
            "promote u_1",
            "add --name Ana --role read --colour blue",
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?} should be refused");
        }
    }

    /// The role the CLI sends is the API's enum, and a role the API does not
    /// have is refused before anything is sent.
    ///
    /// Bug-catch: send the role as typed and every `--role write` is refused
    /// by the node as an unknown enum value.
    #[test]
    fn the_role_is_sent_as_the_apis_enum() {
        let add = |role: &str| UserCommand::Add {
            name: Some("Ana".to_owned()),
            role: role.to_owned(),
            expires: None,
            user: None,
        };
        let body = request_body(&add("write")).expect("a role");
        assert_eq!(body["variables"]["role"], "WRITE");
        assert!(request_body(&add("owner")).is_err());
        assert!(
            request_body(&add("WRITE")).is_err(),
            "as the usage spells it"
        );
    }

    /// The CLI against the real router on a loopback port (002 step 3):
    /// `add` prints the person's id and key, and the key works; `list` shows
    /// them by name; `rename` and `revoke` change the list; a change the node
    /// refuses comes back as its message and code; a wrong operator key is
    /// told as a 401, not as a parse failure.
    ///
    /// Bug-catch: send no `X-Api-Key` and every command gets 401; send no
    /// `Host` and the request guard refuses every command.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_cli_manages_people_through_the_node() {
        use crate::graphql::access::test_node::{node, OPERATOR};
        let node = node(true, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("address").port();
        let app = node.app.clone();
        tokio::spawn(async move { axum::serve(listener, app).await });
        // The client is blocking, so each command runs off the runtime.
        let run = |key: &str, line: String| {
            let key = key.to_owned();
            tokio::task::spawn_blocking(move || {
                let command = parse(&args(&line)).expect("parses");
                execute("127.0.0.1", port, Some(&key), &command)
            })
        };
        let run = |key: &str, line: String| {
            let joined = run(key, line);
            async move { joined.await.expect("joined") }
        };

        let added = run(
            OPERATOR,
            "add --name Ana --role write --expires 2999-12-31".into(),
        )
        .await
        .expect("added");
        let field = |label: &str| {
            added
                .lines()
                .find_map(|line| line.trim().strip_prefix(label))
                .map(|value| value.trim().to_owned())
                .unwrap_or_else(|| panic!("{label} in {added}"))
        };
        let (user, key) = (field("user id:"), field("key:"));
        assert!(added.contains("Granted Ana write access"), "{added}");
        assert!(field("expires:").starts_with("2999-12-31"), "{added}");
        let person = key.clone();
        let read = tokio::task::spawn_blocking(move || {
            exchange(
                "127.0.0.1",
                port,
                "/graphql",
                Some(&person),
                &json!({ "query": "{ verify { ok } }" }),
            )
        })
        .await
        .expect("joined")
        .expect("the person's key works");
        assert_eq!(read["data"]["verify"]["ok"], true, "{read}");

        let listed = run(OPERATOR, "list".into()).await.expect("listed");
        assert!(listed.contains(&user) && listed.contains("Ana"), "{listed}");
        assert!(!listed.contains(&key), "no key in the list");

        run(OPERATOR, format!("rename {user} --name Bea"))
            .await
            .expect("renamed");
        let listed = run(OPERATOR, "list".into()).await.expect("listed");
        assert!(
            listed.contains("Bea") && !listed.contains("Ana"),
            "{listed}"
        );

        run(OPERATOR, format!("revoke {user}"))
            .await
            .expect("revoked");
        let listed = run(OPERATOR, "list".into()).await.expect("listed");
        assert!(
            listed.starts_with("No one is on the access list"),
            "{listed}"
        );

        let refused = run(OPERATOR, format!("revoke {user}"))
            .await
            .expect_err("refused");
        assert!(refused.contains("INVALID_INPUT"), "{refused}");
        let wrong = run("not-the-operator-key", "list".into())
            .await
            .expect_err("401");
        assert!(wrong.contains("HTTP 401"), "{wrong}");
    }

    /// A chunked answer is put back together; one cut short is an error, not
    /// a truncated answer read as whole.
    ///
    /// Bug-catch: read a chunked body as it arrived and the JSON carries the
    /// chunk sizes, so every answer fails to parse.
    #[test]
    fn a_chunked_answer_is_put_back_together() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"a\":\r\n2\r\n1}\r\n0\r\n\r\n";
        assert_eq!(split_response(raw), Ok((200, b"{\"a\":1}".to_vec())),);
        let spelled_otherwise =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding:gzip, chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(split_response(spelled_otherwise), Ok((200, b"{}".to_vec())));
        let plain = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(split_response(plain), Ok((401, b"{}".to_vec())));
        let cut = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n{\"a\"";
        assert!(split_response(cut).is_err());
    }
}
