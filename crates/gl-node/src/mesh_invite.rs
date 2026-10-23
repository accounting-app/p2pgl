//! Joining another server to a company's mesh (`docs/build-log/005-installer`,
//! step 5): the one-line invitation and reply servers trade, and the
//! `ledger.json` changes they make.
//!
//! - A server of company `acme` writes an **invitation**: acme's `meshId` and
//!   `swarmTopic`, its own node id for acme and the address its endpoint
//!   listens on, **every server already in the mesh** (each node id, and the
//!   addresses it is listed at), and the mesh's relay, `auth.adminNodes` and
//!   `format` — what a server of the mesh must share with the others.
//! - The new server **joins** with it: acme in the same mesh on a port of its
//!   own, every server of the invitation among its peers, `joinFrom` the
//!   inviter (so it adopts acme's history); it writes a **reply**: its own node
//!   id and address.
//! - **Every server already in the mesh accepts** the reply: the new one joins
//!   acme's peers there. A node takes records only from the peers it lists
//!   (H-14), so a server that never accepts the reply refuses everything the
//!   new one writes, and the books drift apart.
//!
//! An invitation carries the mesh's join credential — its gossip topic, with
//! a member's id and address — and is to be kept like a password until it has
//! been used; a reply decides whom a server trusts. Neither grants anything
//! alone: a server joins only when the others' operators accept its reply.
//! Each is a prefix naming what it is and a version, then its JSON in URL-safe
//! base64, so it pastes as one line; a reply given to `join`, or an invitation
//! to `accept`, is refused by its prefix.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::ledger_admin::{refused, Refusal};

pub(crate) const INVITE_PREFIX: &str = "openledger-invite-v1.";
pub(crate) const REPLY_PREFIX: &str = "openledger-reply-v1.";

/// The longest line accepted: an invitation for a mesh of a dozen servers is
/// a few kilobytes.
const MAX_LINE_BYTES: usize = 16 * 1024;
/// The most servers an invitation names besides its sender.
const MAX_PEERS: usize = 64;

/// A server of the mesh, as an invitation names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct MeshPeer {
    pub node_id: String,
    /// Where it is listed as listening (none: found through the relay).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

/// The format flags every node of a mesh shares (`format`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MeshFormat {
    pub wire2: bool,
    pub idv2: bool,
}

/// What an invitation or a reply says. A reply carries only its sender —
/// the mesh's settings are the accepting server's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct MeshLine {
    /// The company's ledger name, the same on every node of its mesh.
    pub ledger: String,
    pub mesh_id: String,
    /// The sender's node id for that ledger.
    pub node_id: String,
    /// Where the sender's endpoint listens: `host:port`.
    pub address: String,
    /// An invitation's: the mesh's gossip topic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swarm_topic: Option<String>,
    /// An invitation's: every other server of the mesh.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<MeshPeer>,
    /// An invitation's: the mesh's own relay, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// An invitation's: `auth.adminNodes`, when the mesh sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_nodes: Option<Vec<String>>,
    /// An invitation's: the mesh's format flags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<MeshFormat>,
}

impl MeshLine {
    /// A reply's: its sender, and nothing of the mesh but its id.
    pub(crate) fn reply(ledger: &str, mesh_id: &str, node_id: String, address: String) -> Self {
        MeshLine {
            ledger: ledger.to_owned(),
            mesh_id: mesh_id.to_owned(),
            node_id,
            address,
            swarm_topic: None,
            peers: Vec::new(),
            relay_url: None,
            admin_nodes: None,
            format: None,
        }
    }

    /// Every server an invitation names: its sender, then the others.
    pub(crate) fn servers(&self) -> Vec<MeshPeer> {
        let mut servers = vec![MeshPeer {
            node_id: self.node_id.clone(),
            addresses: vec![self.address.clone()],
        }];
        servers.extend(self.peers.iter().cloned());
        servers
    }
}

/// `line` with `prefix`, as one line.
pub(crate) fn encode(prefix: &str, line: &MeshLine) -> String {
    let json = serde_json::to_vec(line).expect("JSON");
    format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    )
}

/// The line `text` holds, if it is a `prefix` line and well formed: its
/// ledger name valid, every node id an `EndpointId`, every address one a node
/// accepts in `p2p.peerAddresses`, its relay one a node accepts in
/// `p2p.relayUrl` — and a reply nothing but its sender.
pub(crate) fn decode(prefix: &str, text: &str) -> Result<MeshLine, Refusal> {
    let text = text.trim();
    let what = if prefix == INVITE_PREFIX {
        "an invitation"
    } else {
        "a reply"
    };
    if text.len() > MAX_LINE_BYTES {
        return Err(refused(
            "INVALID_INPUT",
            format!("that is not {what}: too long"),
        ));
    }
    let Some(body) = text.strip_prefix(prefix) else {
        let hint = if text.starts_with(REPLY_PREFIX) {
            " (it is a reply: give it to `accept` on the servers already in the mesh)"
        } else if text.starts_with(INVITE_PREFIX) {
            " (it is an invitation: give it to `join` on the server that is to join)"
        } else {
            ""
        };
        return Err(refused(
            "INVALID_INPUT",
            format!("that is not {what}: it does not start with {prefix}{hint}"),
        ));
    };
    let bad = |why: String| refused("INVALID_INPUT", format!("that is not {what}: {why}"));
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| bad("it is cut short or changed (not base64)".to_owned()))?;
    let line: MeshLine = serde_json::from_slice(&json)
        .map_err(|error| bad(format!("it is cut short or changed ({error})")))?;
    if !crate::config::is_valid_ledger_name(&line.ledger)
        || line.ledger == crate::config::DEFAULT_LEDGER
    {
        return Err(bad(format!(
            "{:?} is not a company's ledger name",
            line.ledger
        )));
    }
    let mesh_fields = line.swarm_topic.is_some()
        || !line.peers.is_empty()
        || line.relay_url.is_some()
        || line.admin_nodes.is_some()
        || line.format.is_some();
    let invitation = prefix == INVITE_PREFIX;
    if invitation != (line.swarm_topic.is_some() && line.format.is_some())
        || (!invitation && mesh_fields)
    {
        return Err(bad(
            "its fields are not an invitation's or a reply's".to_owned()
        ));
    }
    check_peer(&line.node_id, std::slice::from_ref(&line.address)).map_err(bad)?;
    if line.peers.len() > MAX_PEERS {
        return Err(bad(format!("it names more than {MAX_PEERS} servers")));
    }
    for peer in &line.peers {
        check_peer(&peer.node_id, &peer.addresses).map_err(bad)?;
    }
    for node in line.admin_nodes.iter().flatten() {
        node.parse::<iroh::EndpointId>()
            .map_err(|_| bad(format!("its admin node {node:?} is not a node id")))?;
    }
    if let Some(relay) = &line.relay_url {
        crate::peer_addresses::parse_relay_url(relay).map_err(bad)?;
    }
    Ok(line)
}

/// `node_id` an `EndpointId` and `addresses` addresses a node may list for
/// it, by the rules `p2p.peerAddresses` is held to.
fn check_peer(node_id: &str, addresses: &[String]) -> Result<(), String> {
    node_id
        .parse::<iroh::EndpointId>()
        .map_err(|_| format!("{node_id:?} is not a node id"))?;
    if addresses.is_empty() {
        return Ok(());
    }
    let peers = std::collections::BTreeMap::from([(node_id.to_owned(), addresses.to_vec())]);
    crate::peer_addresses::PeerAddresses::from_config(&peers).map(|_| ())
}

/// `host:port` for this node's endpoint, `host` the name or address other
/// servers reach it by (the installer passes the server's domain). An IPv6
/// address goes in brackets.
pub(crate) fn address(host: &str, port: u16) -> Result<String, Refusal> {
    let host = host.trim();
    let address = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    // Any node id will do to check the address alone.
    let probe = iroh::SecretKey::generate().public().to_string();
    check_peer(&probe, std::slice::from_ref(&address)).map_err(|why| {
        refused(
            "INVALID_INPUT",
            format!("{host:?} is not an address other servers can reach this one by: {why}"),
        )
    })?;
    Ok(address)
}

/// The `ledger.json` of a company joined by `invitation`, on `port`: its
/// mesh — topic, relay, admin nodes and format as every server of it has
/// them — every server the invitation names among its peers (with their
/// addresses), and `joinFrom` the inviter, so this node, which has written
/// nothing, adopts the company's history. Without a relay, `relayMode:
/// "disabled"`: the servers are reached at their addresses, never through n0.
pub(crate) fn joined_settings(invitation: &MeshLine, port: u16) -> String {
    let servers = invitation.servers();
    let ids: Vec<&str> = servers.iter().map(|peer| peer.node_id.as_str()).collect();
    let addresses: serde_json::Map<String, Value> = servers
        .iter()
        .filter(|peer| !peer.addresses.is_empty())
        .map(|peer| (peer.node_id.clone(), json!(peer.addresses)))
        .collect();
    let mut p2p = json!({
        "enabled": true,
        "meshId": invitation.mesh_id,
        "swarmTopic": invitation.swarm_topic,
        "relayMode": "disabled",
        "listenPort": port,
        "bootstrapEndpointIds": ids,
        "peerAddresses": addresses,
        "joinFrom": invitation.node_id,
    });
    if let Some(relay) = &invitation.relay_url {
        p2p["relayMode"] = json!("custom");
        p2p["relayUrl"] = json!(relay);
    }
    let mut settings = json!({ "signing": { "enabled": true }, "p2p": p2p });
    if let Some(format) = invitation.format {
        settings["format"] = json!({ "wire2": format.wire2, "idv2": format.idv2 });
    }
    if let Some(admins) = &invitation.admin_nodes {
        settings["auth"] = json!({ "adminNodes": admins });
    }
    serde_json::to_string_pretty(&settings).expect("JSON") + "\n"
}

/// `settings` (a ledger's `ledger.json`) with the node of `reply` among its
/// peers: its id in `bootstrapEndpointIds` (once) and its address in
/// `peerAddresses` (replacing an older one). Everything else is kept as it
/// was, in its order. A reply from another mesh, or to a ledger without P2P,
/// is refused.
pub(crate) fn with_peer(settings: &str, reply: &MeshLine) -> Result<String, Refusal> {
    let mut value: Value = serde_json::from_str(settings).map_err(|error| {
        refused(
            "INVALID_INPUT",
            format!("the ledger's ledger.json does not parse: {error}"),
        )
    })?;
    let p2p = value
        .get_mut("p2p")
        .and_then(Value::as_object_mut)
        .filter(|p2p| p2p.get("enabled") == Some(&Value::Bool(true)))
        .ok_or_else(|| {
            refused(
                "INVALID_INPUT",
                format!(
                    "ledger \"{}\" has no P2P: it has no mesh to join",
                    reply.ledger
                ),
            )
        })?;
    if p2p.get("meshId").and_then(Value::as_str) != Some(reply.mesh_id.as_str()) {
        return Err(refused(
            "LEDGER_CONFLICT",
            format!(
                "that reply is for another mesh of \"{}\" (meshId {}): it answers another invitation",
                reply.ledger, reply.mesh_id
            ),
        ));
    }
    let peers = p2p
        .entry("bootstrapEndpointIds")
        .or_insert_with(|| json!([]));
    let Some(peers) = peers.as_array_mut() else {
        return Err(refused(
            "INVALID_INPUT",
            "p2p.bootstrapEndpointIds is not a list",
        ));
    };
    if !peers
        .iter()
        .any(|peer| peer.as_str() == Some(reply.node_id.as_str()))
    {
        peers.push(json!(reply.node_id));
    }
    let addresses = p2p.entry("peerAddresses").or_insert_with(|| json!({}));
    let Some(addresses) = addresses.as_object_mut() else {
        return Err(refused(
            "INVALID_INPUT",
            "p2p.peerAddresses is not an object",
        ));
    };
    addresses.insert(reply.node_id.clone(), json!([reply.address]));
    Ok(serde_json::to_string_pretty(&value).expect("JSON") + "\n")
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LedgerConfig;

    fn node_id() -> String {
        iroh::SecretKey::generate().public().to_string()
    }

    fn invitation() -> MeshLine {
        MeshLine {
            swarm_topic: Some("openledger/0d1e7c2a-1f4b-4c8d-9e3f-5a6b7c8d9e0f".into()),
            format: Some(MeshFormat {
                wire2: true,
                idv2: true,
            }),
            ..MeshLine::reply(
                "acme",
                "6b18df34-6c47-4ad3-96b1-3ff9479f5e79",
                node_id(),
                "a.ledger.example:4433".into(),
            )
        }
    }

    fn reply() -> MeshLine {
        MeshLine::reply(
            "acme",
            "6b18df34-6c47-4ad3-96b1-3ff9479f5e79",
            node_id(),
            "b.ledger.example:4434".into(),
        )
    }

    fn joined(invitation: &MeshLine) -> LedgerConfig {
        let dir = tempfile::Builder::new()
            .prefix(".test-ledgers-")
            .tempdir_in(".")
            .expect("temp dir");
        std::fs::write(
            dir.path().join("ledger.json"),
            joined_settings(invitation, 4440),
        )
        .expect("write");
        LedgerConfig::load_folder(dir.path()).expect("loads as a folder's")
    }

    /// 005 step 5: an invitation and a reply round-trip as one line each,
    /// and each is refused where the other belongs, and when cut short,
    /// changed, or carrying a field it should not — a reply carries nothing
    /// of the mesh but its id.
    ///
    /// Bug-catch: decode without the prefix check and a reply given to
    /// `join` makes a ledger whose one peer is itself.
    #[test]
    fn an_invitation_and_a_reply_are_each_one_line_and_only_what_they_say() {
        let invite = MeshLine {
            peers: vec![MeshPeer {
                node_id: node_id(),
                addresses: vec!["c.ledger.example:4433".into()],
            }],
            admin_nodes: Some(vec![node_id()]),
            relay_url: Some("https://relay.ledger.example".into()),
            ..invitation()
        };
        let line = encode(INVITE_PREFIX, &invite);
        assert!(!line.contains(char::is_whitespace), "one line: {line}");
        assert_eq!(
            decode(INVITE_PREFIX, &format!("  {line}\n")),
            Ok(invite.clone())
        );
        let reply = reply();
        let reply_line = encode(REPLY_PREFIX, &reply);
        assert_eq!(decode(REPLY_PREFIX, &reply_line), Ok(reply.clone()));

        let crossed = decode(INVITE_PREFIX, &reply_line).expect_err("a reply is no invitation");
        assert!(
            crossed.message.contains("it is a reply"),
            "{}",
            crossed.message
        );
        assert!(
            decode(REPLY_PREFIX, &line).is_err(),
            "an invitation is no reply"
        );
        assert!(
            decode(INVITE_PREFIX, &line[..line.len() - 6]).is_err(),
            "cut short"
        );
        for bad_invite in [
            MeshLine {
                swarm_topic: None,
                ..invite.clone()
            },
            MeshLine {
                ledger: "default".into(),
                ..invite.clone()
            },
            MeshLine {
                ledger: "Acme Inc".into(),
                ..invite.clone()
            },
            MeshLine {
                node_id: "not-a-node".into(),
                ..invite.clone()
            },
            MeshLine {
                address: "a.ledger.example".into(),
                ..invite.clone()
            },
            MeshLine {
                admin_nodes: Some(vec!["not-a-node".into()]),
                ..invite.clone()
            },
            MeshLine {
                relay_url: Some("http://relay.example".into()),
                ..invite.clone()
            },
            MeshLine {
                peers: vec![MeshPeer {
                    node_id: node_id(),
                    addresses: vec!["c".into()],
                }],
                ..invite.clone()
            },
        ] {
            assert!(
                decode(INVITE_PREFIX, &encode(INVITE_PREFIX, &bad_invite)).is_err(),
                "{bad_invite:?}"
            );
        }
        let reply_with_mesh = MeshLine {
            peers: invite.peers.clone(),
            ..reply.clone()
        };
        assert!(
            decode(REPLY_PREFIX, &encode(REPLY_PREFIX, &reply_with_mesh)).is_err(),
            "a reply names no other server"
        );
        assert!(decode(
            INVITE_PREFIX,
            &format!("{INVITE_PREFIX}{}", "A".repeat(20_000))
        )
        .is_err());
    }

    /// 005 step 5: the joining node's `ledger.json` is the invitation's mesh
    /// on its own port, the inviting node its peer at its address, and
    /// `joinFrom` it — so a node that has written nothing adopts the history
    /// — with signing and P2P on and never n0; it loads as a folder's.
    ///
    /// Bug-catch: leave out `joinFrom` and the joining node refuses the
    /// company's history past the adoption ratchet.
    #[test]
    fn a_joining_node_is_in_the_mesh_with_the_inviter_as_its_peer() {
        let invite = invitation();
        let config = joined(&invite);
        assert!(config.signing.enabled && config.p2p.enabled);
        assert_eq!(config.p2p.mesh_id.as_deref(), Some(invite.mesh_id.as_str()));
        assert_eq!(Some(config.p2p.swarm_topic.clone()), invite.swarm_topic);
        assert_eq!(config.p2p.listen_port, 4440);
        assert_eq!(config.p2p.relay_mode, "disabled");
        assert_eq!(
            config.p2p.bootstrap_endpoint_ids,
            std::slice::from_ref(&invite.node_id)
        );
        assert_eq!(
            config.p2p.join_from.as_deref(),
            Some(invite.node_id.as_str())
        );
        assert_eq!(
            config.p2p.peer_addresses.get(&invite.node_id),
            Some(&vec![invite.address.clone()])
        );
    }

    /// Review (005 step 5): a server joining a mesh that already has others
    /// takes every one of them as a peer, with their addresses — a node takes
    /// records only from the peers it lists (H-14), so one listing only its
    /// inviter refuses every record another server wrote, and the books drift
    /// apart — and it shares the mesh's relay, `auth.adminNodes` and format:
    /// without them, its access list would take grants the others refuse.
    ///
    /// Bug-catch: build the joining node's peers from the inviter alone and a
    /// third server refuses everything the second one writes.
    #[test]
    fn a_third_server_takes_every_server_of_the_mesh_and_its_rules() {
        let (b, c) = (node_id(), node_id());
        let admins = vec![b.clone()];
        let invite = MeshLine {
            peers: vec![
                MeshPeer {
                    node_id: b.clone(),
                    addresses: vec!["b.ledger.example:4434".into()],
                },
                MeshPeer {
                    node_id: c.clone(),
                    addresses: Vec::new(),
                },
            ],
            relay_url: Some("https://relay.ledger.example".into()),
            admin_nodes: Some(admins.clone()),
            format: Some(MeshFormat {
                wire2: false,
                idv2: true,
            }),
            ..invitation()
        };
        let config = joined(&invite);
        assert_eq!(
            config.p2p.bootstrap_endpoint_ids,
            [invite.node_id.clone(), b.clone(), c.clone()]
        );
        assert_eq!(
            config.p2p.peer_addresses.get(&b),
            Some(&vec!["b.ledger.example:4434".to_owned()])
        );
        assert!(
            !config.p2p.peer_addresses.contains_key(&c),
            "found through the relay"
        );
        assert_eq!(config.p2p.relay_mode, "custom");
        assert_eq!(
            config.p2p.relay_url.as_deref(),
            Some("https://relay.ledger.example")
        );
        assert_eq!(config.admin_nodes, Some(admins));
        assert!(!config.format.wire2 && config.format.idv2);
        assert_eq!(
            config.p2p.join_from.as_deref(),
            Some(invite.node_id.as_str())
        );
    }

    /// 005 step 5: accepting a reply adds its node to the ledger's peers —
    /// once, its address replacing an older one — and keeps every other
    /// setting, in its order; a reply from another mesh, or to a ledger
    /// without P2P, is refused.
    ///
    /// Bug-catch: skip the mesh check and a reply to another company's
    /// invitation ties the two companies' meshes together.
    #[test]
    fn accepting_a_reply_adds_its_node_and_nothing_else() {
        let invite = invitation();
        let mine = joined_settings(
            &MeshLine {
                node_id: node_id(),
                ..invite.clone()
            },
            4433,
        );
        let reply = reply();
        let once: Value =
            serde_json::from_str(&with_peer(&mine, &reply).expect("accepted")).expect("JSON");
        let moved = MeshLine {
            address: "b2.ledger.example:4434".into(),
            ..reply.clone()
        };
        let again = with_peer(&once.to_string(), &moved).expect("accepted again");
        let twice: Value = serde_json::from_str(&again).expect("JSON");
        let peers = twice["p2p"]["bootstrapEndpointIds"]
            .as_array()
            .expect("peers");
        assert_eq!(
            peers.len(),
            2,
            "the inviter's peer and the new one, once: {peers:?}"
        );
        assert_eq!(
            twice["p2p"]["peerAddresses"][&reply.node_id],
            json!(["b2.ledger.example:4434"])
        );
        let before: Value = serde_json::from_str(&mine).expect("JSON");
        assert_eq!(twice["p2p"]["listenPort"], before["p2p"]["listenPort"]);
        assert_eq!(
            twice["p2p"]["joinFrom"], before["p2p"]["joinFrom"],
            "everything else kept"
        );
        assert!(
            again.find("\"signing\"") < again.find("\"p2p\""),
            "the keys keep their order: {again}"
        );

        let other_mesh = MeshLine {
            mesh_id: "another-mesh".into(),
            ..reply.clone()
        };
        assert_eq!(
            with_peer(&mine, &other_mesh)
                .expect_err("another mesh")
                .code,
            "LEDGER_CONFLICT"
        );
        assert_eq!(
            with_peer(r#"{ "signing": { "enabled": true } }"#, &reply)
                .expect_err("no P2P")
                .code,
            "INVALID_INPUT"
        );
    }

    /// An address is the host other servers reach this one by and the
    /// ledger's port; an IPv6 address goes in brackets, and a host with a
    /// port, a scheme or a space is refused.
    #[test]
    fn an_address_is_a_host_and_the_ledgers_port() {
        assert_eq!(
            address("a.ledger.example", 4433).expect("a name").as_str(),
            "a.ledger.example:4433"
        );
        assert_eq!(
            address("203.0.113.7", 4433).expect("IPv4").as_str(),
            "203.0.113.7:4433"
        );
        assert_eq!(
            address("2001:db8::7", 4433).expect("IPv6").as_str(),
            "[2001:db8::7]:4433"
        );
        for bad in ["", "https://a.example", "a.example:80", "a example"] {
            assert!(address(bad, 4433).is_err(), "{bad:?}");
        }
    }
}
