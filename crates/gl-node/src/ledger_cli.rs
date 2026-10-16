//! `gl-node ledger add | list | remove | restart`
//! (`docs/build-log/003-multi-ledger-node`, step 4): a thin client of the node
//! endpoint (`crate::ledger_admin`) for the operator at the node's own
//! machine, as `gl-node user` is of the admin API — the node judges every
//! change, the CLI holds no rules of its own.

use serde_json::{json, Value};

use crate::user_cli::{exchange, graphql_errors, OperatorTarget};

/// The usage line for `gl-node ledger`.
pub const USAGE: &str = "Usage:
  gl-node ledger add NAME [--settings FILE]
      (FILE is the ledger's ledger.json; none: a ledger of its own, with no mesh)
  gl-node ledger list
  gl-node ledger restart NAME
      (picks up an edited ledger.json)
  gl-node ledger remove NAME
      (stops it and moves its folder to ledgersDir/.removed/; nothing is deleted)";

/// The node endpoint's path.
pub const NODE_PATH: &str = "/node/graphql";

/// One `gl-node ledger` command, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerCommand {
    Add {
        name: String,
        settings: Option<String>,
    },
    List,
    Remove {
        name: String,
    },
    Restart {
        name: String,
    },
}

/// Parse the arguments after `gl-node ledger`; `read` reads a `--settings`
/// file.
pub fn parse(
    args: &[String],
    read: impl Fn(&str) -> Result<String, String>,
) -> Result<LedgerCommand, String> {
    let (command, rest) = args.split_first().ok_or("no ledger command given")?;
    let mut positional = Vec::new();
    let mut settings = None;
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--settings" => {
                let file = rest.next().ok_or("--settings needs a file")?;
                if settings.replace(file.clone()).is_some() {
                    return Err("--settings given twice".to_owned());
                }
            }
            other if other.starts_with("--") => return Err(format!("unknown option {other}")),
            other => positional.push(other.to_owned()),
        }
    }
    if settings.is_some() && command != "add" {
        return Err(format!("--settings does not apply to `ledger {command}`"));
    }
    let one_name = |positional: Vec<String>| -> Result<String, String> {
        match <[String; 1]>::try_from(positional) {
            Ok([name]) => Ok(name),
            Err(_) => Err(format!("`ledger {command}` takes one NAME")),
        }
    };
    match command.as_str() {
        "add" => Ok(LedgerCommand::Add {
            name: one_name(positional)?,
            settings: settings.map(|file| read(&file)).transpose()?,
        }),
        "list" if positional.is_empty() => Ok(LedgerCommand::List),
        "list" => Err("`ledger list` takes no arguments".to_owned()),
        "remove" => Ok(LedgerCommand::Remove {
            name: one_name(positional)?,
        }),
        "restart" => Ok(LedgerCommand::Restart {
            name: one_name(positional)?,
        }),
        other => Err(format!("unknown ledger command {other:?}")),
    }
}

/// The GraphQL request body for `command`.
fn request_body(command: &LedgerCommand) -> Value {
    const LEDGER: &str = "name served reason nodeId";
    match command {
        LedgerCommand::Add { name, settings } => json!({
            "query": format!("mutation($name: String!, $settings: String) {{ addLedger(name: $name, settings: $settings) {{ {LEDGER} }} }}"),
            "variables": { "name": name, "settings": settings },
        }),
        LedgerCommand::List => json!({ "query": format!("{{ ledgers {{ {LEDGER} }} }}") }),
        LedgerCommand::Remove { name } => json!({
            "query": "mutation($name: String!) { removeLedger(name: $name) { name movedTo } }",
            "variables": { "name": name },
        }),
        LedgerCommand::Restart { name } => json!({
            "query": format!("mutation($name: String!) {{ restartLedger(name: $name) {{ {LEDGER} }} }}"),
            "variables": { "name": name },
        }),
    }
}

/// The paths `name` is served at.
fn served_at(name: &str) -> String {
    format!("/ledgers/{name}/graphql")
}

/// What to print for `command`'s answer `data`.
fn render(command: &LedgerCommand, data: &Value) -> String {
    let text = |value: &Value| value.as_str().unwrap_or("").to_owned();
    let node_id = |ledger: &Value| match ledger["nodeId"].as_str() {
        Some(id) => id.to_owned(),
        None => "none (it neither signs nor replicates)".to_owned(),
    };
    match command {
        LedgerCommand::Add { name, .. } => {
            let added = &data["addLedger"];
            let mut out = format!(
                "Added ledger {name}, served at {}.\n  node id:  {}\n",
                served_at(name),
                node_id(added)
            );
            if added["nodeId"].is_string() {
                out.push_str(
                    "\nGive the node id to the other nodes of this ledger's mesh, for their \
                     p2p.bootstrapEndpointIds. Add people with `gl-node user add --ledger ",
                );
                out.push_str(&format!("{name} …`.\n"));
            } else {
                out.push_str(&format!(
                    "\nAdd people with `gl-node user add --ledger {name} …`.\n"
                ));
            }
            out
        }
        LedgerCommand::List => {
            let ledgers = data["ledgers"].as_array().cloned().unwrap_or_default();
            if ledgers.is_empty() {
                return "This node holds no ledgers.\n".to_owned();
            }
            let mut out = format!("{:<40}  {:<10}  NODE ID\n", "NAME", "STATE");
            for ledger in &ledgers {
                let served = ledger["served"].as_bool() == Some(true);
                out.push_str(&format!(
                    "{:<40}  {:<10}  {}\n",
                    text(&ledger["name"]),
                    if served { "served" } else { "not served" },
                    ledger["nodeId"].as_str().unwrap_or("-"),
                ));
                if !served {
                    out.push_str(&format!("    why: {}\n", text(&ledger["reason"])));
                }
            }
            out
        }
        LedgerCommand::Remove { name } => match data["removeLedger"]["movedTo"].as_str() {
            Some(moved) => format!(
                "Removed ledger {name}: stopped, its journal folded in, and its folder moved to \
                 {moved}. Nothing was deleted; to serve it again, move the folder back and \
                 restart it.\n"
            ),
            None => format!("Removed ledger {name}: stopped; it had no folder to move.\n"),
        },
        LedgerCommand::Restart { name } => {
            format!("Restarted ledger {name}, served at {}.\n", served_at(name))
        }
    }
}

/// Run `command` against the node at `host:port`: what to print, or why not.
pub fn execute(
    host: &str,
    port: u16,
    api_key: Option<&str>,
    command: &LedgerCommand,
) -> Result<String, String> {
    let answer = exchange(host, port, NODE_PATH, api_key, &request_body(command))?;
    if let Some(errors) = graphql_errors(&answer) {
        return Err(errors);
    }
    Ok(render(command, &answer["data"]))
}

/// `gl-node ledger …`: parse, find the node and its operator key, run, exit.
pub fn run(args: &[String]) -> ! {
    let read = |file: &str| {
        std::fs::read_to_string(file).map_err(|error| format!("--settings {file}: {error}"))
    };
    let command = match parse(args, read) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("ledger: {error}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let node = match OperatorTarget::from_config() {
        Ok(node) => node,
        Err(error) => {
            eprintln!("ledger: {error}");
            std::process::exit(1);
        }
    };
    match execute(&node.host, node.port, node.api_key(), &command) {
        Ok(output) => {
            print!("{output}");
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("ledger: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, LedgerCommand};

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn no_file(file: &str) -> Result<String, String> {
        Err(format!("no file {file}"))
    }

    /// `gl-node ledger` parses as its usage says, and refuses the rest.
    ///
    /// Bug-catch: take `--settings` on `remove` and an operator believes the
    /// settings did something.
    #[test]
    fn ledger_commands_parse_as_the_usage_says() {
        let read = |file: &str| Ok(format!("contents of {file}"));
        assert_eq!(
            parse(&args("add acme --settings acme.json"), read),
            Ok(LedgerCommand::Add {
                name: "acme".into(),
                settings: Some("contents of acme.json".into()),
            })
        );
        assert_eq!(
            parse(&args("add acme"), no_file),
            Ok(LedgerCommand::Add {
                name: "acme".into(),
                settings: None,
            })
        );
        assert_eq!(parse(&args("list"), no_file), Ok(LedgerCommand::List));
        assert_eq!(
            parse(&args("remove acme"), no_file),
            Ok(LedgerCommand::Remove {
                name: "acme".into()
            })
        );
        assert_eq!(
            parse(&args("restart acme"), no_file),
            Ok(LedgerCommand::Restart {
                name: "acme".into()
            })
        );
        for refused in [
            "",
            "add",
            "add acme beta",
            "add acme --settings",
            "add acme --settings missing.json",
            "add acme --settings a --settings b",
            "list acme",
            "remove",
            "remove acme --settings acme.json",
            "restart acme --force",
            "rename acme",
        ] {
            assert!(parse(&args(refused), no_file).is_err(), "{refused:?}");
        }
    }

    /// The CLI adds, lists, restarts and removes ledgers through the node
    /// endpoint, and a refusal comes back as the node's message and code.
    ///
    /// Bug-catch: send the CLI's requests to `/graphql` and every command is
    /// answered by the config file's ledger, which has no `addLedger`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_cli_adds_lists_and_removes_ledgers_through_the_node() {
        let node = crate::ledger_admin::test_node::node().await;
        let (app, admin) = (node.app.clone(), node.admin.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("address").port();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let run = |line: &str| {
            let line = line.to_owned();
            async move {
                tokio::task::spawn_blocking(move || {
                    let command = parse(&args(&line), no_file).expect("parses");
                    super::execute(
                        "127.0.0.1",
                        port,
                        Some(crate::ledger_admin::test_node::OPERATOR),
                        &command,
                    )
                })
                .await
                .expect("joined")
            }
        };
        let added = run("add acme").await.expect("added");
        assert!(
            added.starts_with("Added ledger acme, served at /ledgers/acme/graphql."),
            "{added}"
        );
        let listed = run("list").await.expect("listed");
        assert!(
            listed
                .lines()
                .any(|line| line.starts_with("acme ") && line.contains("served")),
            "{listed}"
        );
        let restarted = run("restart acme").await.expect("restarted");
        assert!(
            restarted.starts_with("Restarted ledger acme"),
            "{restarted}"
        );
        let removed = run("remove acme").await.expect("removed");
        assert!(
            removed.starts_with("Removed ledger acme") && removed.contains(".removed"),
            "{removed}"
        );
        let refused = run("remove acme").await.expect_err("refused");
        assert!(refused.contains("NO_SUCH_LEDGER"), "{refused}");
        admin.stop_all().await;
    }
}
