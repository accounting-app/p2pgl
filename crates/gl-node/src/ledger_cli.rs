//! `gl-node ledger add | list | remove | restart`
//! (`docs/build-log/003-multi-ledger-node`, step 4): a thin client of the node
//! endpoint (`crate::ledger_admin`) for the operator at the node's own
//! machine, as `gl-node user` is of the admin API — the node judges every
//! change, the CLI holds no rules of its own.

use serde_json::{json, Value};

use crate::user_cli::{exchange, graphql_errors, OperatorTarget};

/// The usage line for `gl-node ledger`.
pub const USAGE: &str = "Usage:
  gl-node ledger add NAME [--settings FILE | --new-mesh FROM-TO]
      (FILE is the ledger's ledger.json; --new-mesh: a mesh of its own, signing
      and P2P on, on a free UDP port in FROM-TO; neither: a ledger of its own,
      with no mesh)
  gl-node ledger list
  gl-node ledger restart NAME
      (picks up an edited ledger.json)
  gl-node ledger remove NAME
      (stops it and moves its folder to ledgersDir/.removed/; nothing is deleted)
  gl-node ledger invite NAME --address HOST
      (an invitation to NAME's mesh for a second server; HOST is how other
      servers reach this one: its domain or IP address)
  gl-node ledger join INVITATION --address HOST --new-mesh FROM-TO
      (on the new server: joins the company, prints the reply to accept)
  gl-node ledger accept REPLY
      (on every server already in the company's mesh: the new one joins its peers)
  INVITATION or REPLY as - is read from stdin, so it is on no command line";

/// The node endpoint's path.
pub const NODE_PATH: &str = "/node/graphql";

/// One `gl-node ledger` command, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerCommand {
    Add {
        name: String,
        settings: Option<String>,
        /// `--new-mesh FROM-TO`: the node composes the settings.
        new_mesh: Option<String>,
    },
    List,
    Remove {
        name: String,
    },
    Restart {
        name: String,
    },
    Invite {
        name: String,
        address: String,
    },
    Join {
        invitation: String,
        address: String,
        new_mesh: String,
    },
    Accept {
        reply: String,
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
    let mut new_mesh = None;
    let mut address = None;
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--settings" => {
                let file = rest.next().ok_or("--settings needs a file")?;
                if settings.replace(file.clone()).is_some() {
                    return Err("--settings given twice".to_owned());
                }
            }
            "--new-mesh" => {
                let ports = rest.next().ok_or("--new-mesh needs FROM-TO")?;
                if new_mesh.replace(ports.clone()).is_some() {
                    return Err("--new-mesh given twice".to_owned());
                }
            }
            "--address" => {
                let host = rest.next().ok_or("--address needs a HOST")?;
                if address.replace(host.clone()).is_some() {
                    return Err("--address given twice".to_owned());
                }
            }
            other if other.starts_with("--") => return Err(format!("unknown option {other}")),
            other => positional.push(other.to_owned()),
        }
    }
    if settings.is_some() && command != "add" {
        return Err(format!("--settings does not apply to `ledger {command}`"));
    }
    if new_mesh.is_some() && command != "add" && command != "join" {
        return Err(format!("--new-mesh does not apply to `ledger {command}`"));
    }
    if address.is_some() && command != "invite" && command != "join" {
        return Err(format!("--address does not apply to `ledger {command}`"));
    }
    if settings.is_some() && new_mesh.is_some() {
        return Err("give --settings or --new-mesh, not both".to_owned());
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
            new_mesh,
        }),
        "list" if positional.is_empty() => Ok(LedgerCommand::List),
        "list" => Err("`ledger list` takes no arguments".to_owned()),
        "remove" => Ok(LedgerCommand::Remove {
            name: one_name(positional)?,
        }),
        "restart" => Ok(LedgerCommand::Restart {
            name: one_name(positional)?,
        }),
        "invite" => Ok(LedgerCommand::Invite {
            name: one_name(positional)?,
            address: address.ok_or("`ledger invite` needs --address HOST")?,
        }),
        "join" => Ok(LedgerCommand::Join {
            invitation: one_name(positional)
                .map_err(|_| "`ledger join` takes one INVITATION".to_owned())?,
            address: address.ok_or("`ledger join` needs --address HOST")?,
            new_mesh: new_mesh.ok_or("`ledger join` needs --new-mesh FROM-TO")?,
        }),
        "accept" => Ok(LedgerCommand::Accept {
            reply: one_name(positional)
                .map_err(|_| "`ledger accept` takes one REPLY".to_owned())?,
        }),
        other => Err(format!("unknown ledger command {other:?}")),
    }
}

/// The GraphQL request body for `command`.
fn request_body(command: &LedgerCommand) -> Value {
    const LEDGER: &str = "name served reason nodeId listenPort";
    match command {
        LedgerCommand::Add {
            name,
            settings,
            new_mesh,
        } => match new_mesh {
            // `newMeshPorts` only when asked for, so a plain add still works
            // against a node from before it.
            Some(ports) => json!({
                "query": format!("mutation($name: String!, $newMesh: String) {{ addLedger(name: $name, newMeshPorts: $newMesh) {{ {LEDGER} }} }}"),
                "variables": { "name": name, "newMesh": ports },
            }),
            None => json!({
                "query": format!("mutation($name: String!, $settings: String) {{ addLedger(name: $name, settings: $settings) {{ {LEDGER} }} }}"),
                "variables": { "name": name, "settings": settings },
            }),
        },
        LedgerCommand::List => json!({ "query": format!("{{ ledgers {{ {LEDGER} }} }}") }),
        LedgerCommand::Remove { name } => json!({
            "query": "mutation($name: String!) { removeLedger(name: $name) { name movedTo } }",
            "variables": { "name": name },
        }),
        LedgerCommand::Restart { name } => json!({
            "query": format!("mutation($name: String!) {{ restartLedger(name: $name) {{ {LEDGER} }} }}"),
            "variables": { "name": name },
        }),
        LedgerCommand::Invite { name, address } => json!({
            "query": "mutation($name: String!, $address: String!) { inviteLedger(name: $name, address: $address) }",
            "variables": { "name": name, "address": address },
        }),
        LedgerCommand::Join {
            invitation,
            address,
            new_mesh,
        } => json!({
            "query": format!("mutation($invitation: String!, $address: String!, $ports: String!) {{ joinLedger(invitation: $invitation, address: $address, newMeshPorts: $ports) {{ reply trusts ledger {{ {LEDGER} }} }} }}"),
            "variables": { "invitation": invitation, "address": address, "ports": new_mesh },
        }),
        LedgerCommand::Accept { reply } => json!({
            "query": format!("mutation($reply: String!) {{ acceptLedger(reply: $reply) {{ nodeId address ledger {{ {LEDGER} }} }} }}"),
            "variables": { "reply": reply },
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
            if let Some(port) = added["listenPort"].as_u64() {
                out.push_str(&format!("  UDP port: {port}\n"));
            }
            if added["nodeId"].is_string() {
                out.push_str(
                    "\nGive the node id to the other nodes of this ledger's mesh, for their \
                     p2p.bootstrapEndpointIds.",
                );
            }
            out.push_str(&format!(
                "\nAdd people with `gl-node user --ledger {name} add …` (on a server set up \
                 by the installer: `openledger person add {name} …`).\n"
            ));
            out
        }
        LedgerCommand::List => {
            let ledgers = data["ledgers"].as_array().cloned().unwrap_or_default();
            if ledgers.is_empty() {
                return "This node holds no ledgers.\n".to_owned();
            }
            let mut out = format!("{:<40}  {:<10}  {:<5}  NODE ID\n", "NAME", "STATE", "PORT");
            for ledger in &ledgers {
                let served = ledger["served"].as_bool() == Some(true);
                let port = ledger["listenPort"]
                    .as_u64()
                    .map_or("-".to_owned(), |port| port.to_string());
                out.push_str(&format!(
                    "{:<40}  {:<10}  {:<5}  {}\n",
                    text(&ledger["name"]),
                    if served { "served" } else { "not served" },
                    port,
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
        LedgerCommand::Invite { name, .. } => format!(
            "The invitation to {name}'s mesh (one line). It holds the mesh's join credential: \
             keep it like a password, and hand it over on a channel you trust.\n\n{}\n\n\
             On the new server: join with it (`gl-node ledger join - --address <that server> \
             --new-mesh FROM-TO`, the line on stdin, or `openledger join`), then accept its reply \
             here and on every other server already serving {name}.\n",
            text(&data["inviteLedger"])
        ),
        LedgerCommand::Join { .. } => {
            let joined = &data["joinLedger"];
            let ledger = &joined["ledger"];
            let name = text(&ledger["name"]);
            let trusts: Vec<String> = joined["trusts"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|id| id.as_str().map(|id| format!("  {id}\n")))
                .collect();
            format!(
                "Joined {name}, served at {}.\n  node id:  {}\n  UDP port: {}\n\n\
                 It trusts, for {name}, these servers' node ids (the inviter first) — compare \
                 them with theirs (`gl-node ledger list` there):\n{}\n\
                 The reply (one line), for EVERY one of those servers to accept:\n\n{}\n\n\
                 On each: `gl-node ledger accept <reply>` (or `openledger accept`). A server that \
                 has not accepted it takes no records from this one.\n",
                served_at(&name),
                node_id(ledger),
                ledger["listenPort"]
                    .as_u64()
                    .map_or("-".to_owned(), |port| port.to_string()),
                trusts.concat(),
                text(&joined["reply"]),
            )
        }
        LedgerCommand::Accept { .. } => {
            let accepted = &data["acceptLedger"];
            format!(
                "Accepted: {} now replicates with node {} at {}, and restarted with it.\n\
                 Compare that node id with the one the joining server printed.\n",
                text(&accepted["ledger"]["name"]),
                text(&accepted["nodeId"]),
                text(&accepted["address"]),
            )
        }
    }
}

/// An invitation or a reply given as `-` read from stdin, one line: so it
/// is on no command line (`ps`) and in no shell history.
fn lines_from_stdin(command: LedgerCommand) -> Result<LedgerCommand, String> {
    let line = || -> Result<String, String> {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|error| format!("reading the line from stdin: {error}"))?;
        Ok(line.trim().to_owned())
    };
    Ok(match command {
        LedgerCommand::Join {
            invitation,
            address,
            new_mesh,
        } if invitation == "-" => LedgerCommand::Join {
            invitation: line()?,
            address,
            new_mesh,
        },
        LedgerCommand::Accept { reply } if reply == "-" => LedgerCommand::Accept { reply: line()? },
        other => other,
    })
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
    let command = match parse(args, read).and_then(lines_from_stdin) {
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
                new_mesh: None,
            })
        );
        assert_eq!(
            parse(&args("add acme"), no_file),
            Ok(LedgerCommand::Add {
                name: "acme".into(),
                settings: None,
                new_mesh: None,
            })
        );
        assert_eq!(
            parse(&args("invite acme --address a.example"), no_file),
            Ok(LedgerCommand::Invite {
                name: "acme".into(),
                address: "a.example".into(),
            })
        );
        assert_eq!(
            parse(
                &args("join LINE --address b.example --new-mesh 4433-4532"),
                no_file
            ),
            Ok(LedgerCommand::Join {
                invitation: "LINE".into(),
                address: "b.example".into(),
                new_mesh: "4433-4532".into(),
            })
        );
        assert_eq!(
            parse(&args("accept REPLY"), no_file),
            Ok(LedgerCommand::Accept {
                reply: "REPLY".into()
            })
        );
        assert_eq!(
            parse(&args("add acme --new-mesh 4433-4532"), no_file),
            Ok(LedgerCommand::Add {
                name: "acme".into(),
                settings: None,
                new_mesh: Some("4433-4532".into()),
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
            "add acme --new-mesh",
            "add acme --new-mesh 1-2 --settings acme.json",
            "remove acme --new-mesh 1-2",
            "invite acme",
            "invite acme --address",
            "invite acme --address a.example --new-mesh 1-2",
            "join LINE --address b.example",
            "join LINE --new-mesh 1-2",
            "join --address b.example --new-mesh 1-2",
            "accept",
            "accept REPLY --address b.example",
            "list --address b.example",
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
