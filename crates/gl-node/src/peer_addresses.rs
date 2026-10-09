//! Where an allowlisted peer can be reached (`docs/build-log/001-peer-discovery`).
//!
//! `p2p.peerAddresses` maps a peer's EndpointId to `host:port` addresses. They
//! go into the endpoint's address lookup, so a dial by EndpointId — every dial
//! this node makes — finds the peer without n0's discovery service. A task
//! resolves them at boot and again every [`REFRESH_INTERVAL`], so a host name
//! whose address changes is followed; boot never waits on DNS.
//!
//! An address is only a hint for reaching a peer `p2p.bootstrapEndpointIds`
//! already admits, never a reason to admit one: config validation refuses an
//! address for a peer that is not on the list, and the connection is still
//! authenticated by the peer's key whatever address it came in on.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::{EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use tracing::{info, warn};

/// Addresses one peer may list: enough for a few interfaces and both IP
/// families, few enough that a typo'd paste cannot become a resolver storm.
pub const MAX_ADDRESSES_PER_PEER: usize = 16;

/// How often configured addresses are resolved again.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// How often while some configured address has never resolved — a node that
/// boots before its peers exist (a compose stack, a mesh starting together)
/// finds them within seconds, not at the next [`REFRESH_INTERVAL`].
pub const UNRESOLVED_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// How long one name may take to resolve before it counts as unresolved.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// One configured address: an IP literal or a DNS name, and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAddress {
    host: String,
    port: u16,
}

impl PeerAddress {
    /// `ip:port` (`[v6]:port` for IPv6) or `name:port`. No scheme, path, user
    /// info or trailing dot; port 1–65535.
    pub fn parse(text: &str) -> Result<Self, String> {
        let refuse = |why: &str| {
            Err(format!(
                "\"{text}\" is not a peer address: {why} (write host:port, e.g. ledger.example.com:4433 or 203.0.113.7:4433)"
            ))
        };
        if let Ok(socket) = text.parse::<SocketAddr>() {
            if socket.port() == 0 {
                return refuse("port 0");
            }
            if matches!(socket, SocketAddr::V6(v6) if v6.scope_id() != 0) {
                return refuse("an IPv6 zone id (%…) is not supported");
            }
            return Ok(Self {
                host: socket.ip().to_string(),
                port: socket.port(),
            });
        }
        let Some((host, port)) = text.rsplit_once(':') else {
            return refuse("no port");
        };
        let Some(port) = Some(port)
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u16>().ok())
            .filter(|port| *port != 0)
        else {
            return refuse("the port is not 1–65535");
        };
        if !is_dns_name(host) {
            return refuse("the host is neither an IP address nor a DNS name");
        }
        // No real top-level domain is numeric. A name ending in digits is an
        // IP address mistyped (`203.0.113` for `203.0.113.7`), which the system
        // resolver would read as the old short form — another host
        // (203.0.0.113) — instead of refusing it.
        if host
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return refuse("the host looks like an IP address but is not a complete one");
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

impl std::fmt::Display for PeerAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(formatter, "[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{}:{}", self.host, self.port)
        }
    }
}

/// Letters, digits and hyphens in dot-separated labels of 1–63 bytes, none
/// starting or ending with a hyphen, 253 bytes at most, no trailing dot.
fn is_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// `p2p.relayUrl`: the mesh's own relay (`relayMode: "custom"`). `https` with a
/// host and nothing else — no user info, query or fragment (no secrets in
/// config or logs), no path. Plain `http` is refused: a relay carries every
/// node's traffic, and its certificate is what proves it is the operator's.
///
/// A refusal never repeats the value it refuses: a URL refused for its user
/// info or query may carry a password or a relay token, and the message goes
/// to the boot log (the M-32 / L-56 rule). It names `scheme://host[:port]`
/// when the value parses, and only its length and first characters when not.
pub fn parse_relay_url(text: &str) -> Result<RelayUrl, String> {
    let refuse = |shown: &str, why: &str| {
        Err(format!(
            "p2p.relayUrl ({shown}) {why} (write https://relay.example.com, the address of the mesh's own iroh-relay)"
        ))
    };
    let Ok(url) = text.parse::<RelayUrl>() else {
        return refuse(&crate::auth::redact(text), "is not a URL");
    };
    let shown = match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{}://{host}:{port}", url.scheme()),
        (Some(host), None) => format!("{}://{host}", url.scheme()),
        (None, _) => format!("{}://", url.scheme()),
    };
    let refuse = |why: &str| refuse(&shown, why);
    if url.scheme() != "https" {
        return refuse("must use https");
    }
    if url.host_str().is_none_or(str::is_empty) {
        return refuse("has no host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return refuse("must not carry user info");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return refuse("must not carry a query or fragment");
    }
    if !matches!(url.path(), "" | "/") {
        return refuse("must not carry a path");
    }
    Ok(url)
}

/// Every peer's configured addresses, parsed, with what each last resolved to,
/// and the mesh's relay when there is one.
#[derive(Debug, Default)]
pub struct PeerAddresses {
    peers: BTreeMap<EndpointId, Vec<PeerAddress>>,
    /// `p2p.relayUrl` (`relayMode: "custom"`): every bootstrap peer is reached
    /// through it as well as at its own addresses.
    relay: Option<RelayUrl>,
    /// The sockets each `(peer, address index)` resolved to last time, so an
    /// address that fails one refresh keeps its last known sockets.
    last_known: std::sync::Mutex<BTreeMap<(EndpointId, usize), Vec<SocketAddr>>>,
    /// When each never-resolved address was last warned about: while the quick
    /// retry runs every [`UNRESOLVED_RETRY_INTERVAL`], its WARN repeats only
    /// every [`REFRESH_INTERVAL`] (`usize::MAX` stands for the per-peer line).
    last_warned: std::sync::Mutex<BTreeMap<(EndpointId, usize), std::time::Instant>>,
}

impl PeerAddresses {
    /// Parse `p2p.peerAddresses`. Config validation has already checked it;
    /// this returns the same messages if called on an unchecked map.
    pub fn from_config(map: &BTreeMap<String, Vec<String>>) -> Result<Self, String> {
        let mut peers = BTreeMap::new();
        for (peer, addresses) in map {
            let id = peer
                .parse::<EndpointId>()
                .map_err(|_| format!("p2p.peerAddresses: \"{peer}\" is not an EndpointId"))?;
            if addresses.is_empty() || addresses.len() > MAX_ADDRESSES_PER_PEER {
                return Err(format!(
                    "p2p.peerAddresses: peer {peer} lists {} addresses; list 1 to {MAX_ADDRESSES_PER_PEER}",
                    addresses.len()
                ));
            }
            let parsed = addresses
                .iter()
                .map(|address| PeerAddress::parse(address))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("p2p.peerAddresses: peer {peer}: {error}"))?;
            if peers.insert(id, parsed).is_some() {
                return Err(format!(
                    "p2p.peerAddresses: peer {id} is listed twice (two spellings of one EndpointId); list it once"
                ));
            }
        }
        Ok(Self {
            peers,
            relay: None,
            last_known: std::sync::Mutex::default(),
            last_warned: std::sync::Mutex::default(),
        })
    }

    /// Whether to WARN about `key` now: always for an address that resolved
    /// before (it fails only at the long interval), at most once per
    /// [`REFRESH_INTERVAL`] for one that never has (retried every
    /// [`UNRESOLVED_RETRY_INTERVAL`]).
    fn should_warn(&self, key: (EndpointId, usize), resolved_before: bool) -> bool {
        if resolved_before {
            return true;
        }
        let now = std::time::Instant::now();
        let mut last_warned = self.last_warned.lock().expect("last_warned lock");
        match last_warned.get(&key) {
            Some(at) if now.duration_since(*at) < REFRESH_INTERVAL => false,
            _ => {
                last_warned.insert(key, now);
                true
            }
        }
    }

    /// Reach every `bootstrap` peer through `relay` too — the mesh's own relay,
    /// where each node is registered — including peers with no address of
    /// their own (a node behind a router has none to give).
    pub fn with_relay(
        mut self,
        relay: RelayUrl,
        bootstrap: impl IntoIterator<Item = EndpointId>,
    ) -> Self {
        for peer in bootstrap {
            self.peers.entry(peer).or_default();
        }
        self.relay = Some(relay);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn peer_ids(&self) -> impl Iterator<Item = &EndpointId> {
        self.peers.keys()
    }

    /// Resolve every peer's addresses and **replace** its lookup entry with the
    /// result. An address that fails this time contributes what it last
    /// resolved to (stale beats nothing), with a WARN naming the peer and the
    /// address; a peer none of whose addresses has ever resolved keeps no
    /// entry. Returns whether every configured address has resolved at least
    /// once (so the next refresh may wait the long interval).
    pub async fn refresh<R, F>(&self, lookup: &MemoryLookup, resolve: R) -> bool
    where
        R: Fn(String, u16) -> F,
        F: Future<Output = std::io::Result<Vec<SocketAddr>>>,
    {
        let mut all_known = true;
        for (peer, addresses) in &self.peers {
            let mut resolved = BTreeSet::new();
            for (index, address) in addresses.iter().enumerate() {
                let outcome = match resolve(address.host.clone(), address.port).await {
                    Ok(sockets) if !sockets.is_empty() => Ok(sockets),
                    Ok(_) => Err("it resolves to nothing".to_owned()),
                    Err(error) => Err(error.to_string()),
                };
                let mut last_known = self.last_known.lock().expect("last_known lock");
                let sockets = match outcome {
                    Ok(sockets) => {
                        last_known.insert((*peer, index), sockets.clone());
                        sockets
                    }
                    Err(error) => {
                        all_known &= last_known.contains_key(&(*peer, index));
                        let kept = last_known.get(&(*peer, index)).cloned().unwrap_or_default();
                        if self.should_warn((*peer, index), !kept.is_empty()) {
                            warn!(
                                peer = %peer, address = %address, %error, kept = kept.len(),
                                "a configured peer address does not resolve; its last known sockets (if any) are kept, and it is tried again — every 10 s until it first resolves, then every 5 min"
                            );
                        }
                        kept
                    }
                };
                resolved.extend(sockets.into_iter().map(TransportAddr::Ip));
            }
            if let Some(relay) = &self.relay {
                resolved.insert(TransportAddr::Relay(relay.clone()));
            }
            if resolved.is_empty() {
                if self.should_warn((*peer, usize::MAX), false) {
                    warn!(
                        peer = %peer,
                    "no configured address of this peer has resolved yet; it is not reachable by address until one does"
                    );
                }
                continue;
            }
            lookup.set_endpoint_info(EndpointAddr {
                id: *peer,
                addrs: resolved,
            });
        }
        all_known
    }

    /// Resolve now, then every [`UNRESOLVED_RETRY_INTERVAL`] while some address
    /// has never resolved (a peer not up yet) and every [`REFRESH_INTERVAL`]
    /// once all have, for as long as the runtime lives. Nothing to do when no
    /// peer has an address and there is no relay.
    pub fn spawn_refresh(self, lookup: MemoryLookup) {
        if self.is_empty() {
            return;
        }
        info!(
            peers = self.peers.len(),
            with_addresses = self.peers.values().filter(|addresses| !addresses.is_empty()).count(),
            relay = self.relay.is_some(),
            "keeping peers in the address lookup: their p2p.peerAddresses (resolved now, every 10 s until each has resolved, then every 5 min) and the mesh's relay if one is set"
        );
        tokio::spawn(async move {
            loop {
                let all_known = self.refresh(&lookup, resolve_with_system_dns).await;
                tokio::time::sleep(if all_known {
                    REFRESH_INTERVAL
                } else {
                    UNRESOLVED_RETRY_INTERVAL
                })
                .await;
            }
        });
    }
}

/// The system resolver, bounded by [`RESOLVE_TIMEOUT`]. An IP literal resolves
/// to itself without a lookup.
pub async fn resolve_with_system_dns(host: String, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    match tokio::time::timeout(
        RESOLVE_TIMEOUT,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    {
        Ok(result) => result.map(Iterator::collect),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("no answer within {} s", RESOLVE_TIMEOUT.as_secs()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The form check behind `p2p.peerAddresses`: IP literals (IPv6 in
    /// brackets) and DNS names with a port 1–65535 pass; anything with a
    /// scheme, path, missing or zero port, bad label or trailing dot is
    /// refused with the text it was given.
    ///
    /// Bug-catch: accept a host the label rules refuse and a URL-shaped value
    /// is resolved as a name; drop the numeric-last-label rule and
    /// `203.0.113:4433` dials 203.0.0.113.
    #[test]
    fn a_peer_address_is_host_and_port_and_nothing_else() {
        for good in [
            "203.0.113.7:4433",
            "[2001:db8::1]:4433",
            "ledger.example.com:4433",
            "node-1.acme.internal:1",
            "localhost:65535",
        ] {
            let parsed = PeerAddress::parse(good).unwrap_or_else(|error| panic!("{good}: {error}"));
            assert_eq!(parsed.to_string(), good, "round-trips");
        }
        for bad in [
            "",
            "ledger.example.com",
            "ledger.example.com:0",
            "ledger.example.com:70000",
            "https://ledger.example.com:4433",
            "ledger.example.com:4433/path",
            "user@ledger.example.com:4433",
            "ledger.example.com.:4433",
            "-ledger.example.com:4433",
            "ledger..example.com:4433",
            "led ger.example.com:4433",
            "2001:db8::1:4433",
            "[2001:db8::1]:0",
            "[fe80::1%4]:4433",
            "ledger.example.com:+4433",
            // Mistyped IPv4: the system resolver would read these as other
            // hosts (203.0.0.113, 127.0.0.1) instead of refusing them.
            "203.0.113:4433",
            "127.1:4433",
            "2130706433:4433",
            "999.0.0.1:4433",
        ] {
            let error = PeerAddress::parse(bad).expect_err(bad);
            assert!(error.contains(&format!("\"{bad}\"")), "{error}");
        }
    }

    /// A refresh replaces a peer's addresses — it does not pile up every
    /// address a name ever had — and an address that fails a refresh keeps
    /// what it last resolved to, beside the addresses that did resolve.
    ///
    /// It reports whether every address has resolved once, which picks the
    /// quick retry (a peer not up yet) or the long interval.
    ///
    /// Bug-catch: `add_endpoint_info` instead of `set_endpoint_info` keeps the
    /// old address beside the new one; dropping the per-address memory loses
    /// the failed address's last socket while the other one still resolves;
    /// report "all resolved" regardless and a node booted before its peers
    /// waits the long interval to find them.
    #[tokio::test]
    async fn a_refresh_replaces_a_peers_addresses_and_survives_an_outage() {
        let peer = iroh::SecretKey::generate().public();
        let map = BTreeMap::from([(peer.to_string(), vec!["ledger.example.com:4433".to_owned()])]);
        let peers = PeerAddresses::from_config(&map).expect("parses");
        let lookup = MemoryLookup::new();
        let first: SocketAddr = "198.51.100.1:4433".parse().unwrap();
        let moved: SocketAddr = "198.51.100.2:4433".parse().unwrap();
        let addresses = |lookup: &MemoryLookup| -> BTreeSet<TransportAddr> {
            lookup
                .get_endpoint_info(peer)
                .map(|info| info.data.addrs().cloned().collect())
                .unwrap_or_default()
        };

        assert!(
            !peers
                .refresh(&lookup, |_, _| async move {
                    Err(std::io::Error::other("not up yet"))
                })
                .await,
            "an address that has never resolved asks for the quick retry"
        );
        assert!(
            peers
                .refresh(&lookup, |_, _| async move { Ok(vec![first]) })
                .await,
            "once resolved, the long interval"
        );
        assert_eq!(
            addresses(&lookup),
            BTreeSet::from([TransportAddr::Ip(first)])
        );

        peers
            .refresh(&lookup, |_, _| async move { Ok(vec![moved]) })
            .await;
        assert_eq!(
            addresses(&lookup),
            BTreeSet::from([TransportAddr::Ip(moved)]),
            "the old address is gone"
        );

        peers
            .refresh(&lookup, |_, _| async move {
                Err(std::io::Error::other("resolver down"))
            })
            .await;
        assert_eq!(
            addresses(&lookup),
            BTreeSet::from([TransportAddr::Ip(moved)]),
            "an outage keeps the last known address"
        );
        assert!(
            peers
                .refresh(&lookup, |_, _| async move {
                    Err(std::io::Error::other("resolver down"))
                })
                .await,
            "an outage of an address that resolved before keeps the long interval"
        );

        // Two addresses: `a` fails this round while `b` moves. The entry holds
        // b's new socket AND a's last one.
        let two = BTreeMap::from([(
            peer.to_string(),
            vec![
                "a.example.com:4433".to_owned(),
                "b.example.com:4433".to_owned(),
            ],
        )]);
        let peers = PeerAddresses::from_config(&two).expect("parses");
        let lookup = MemoryLookup::new();
        let a_socket: SocketAddr = "198.51.100.10:4433".parse().unwrap();
        let b_before: SocketAddr = "198.51.100.20:4433".parse().unwrap();
        let b_after: SocketAddr = "198.51.100.21:4433".parse().unwrap();
        peers
            .refresh(&lookup, |host, _| async move {
                Ok(vec![if host.starts_with('a') {
                    a_socket
                } else {
                    b_before
                }])
            })
            .await;
        peers
            .refresh(&lookup, |host, _| async move {
                if host.starts_with('a') {
                    Err(std::io::Error::other("timed out"))
                } else {
                    Ok(vec![b_after])
                }
            })
            .await;
        assert_eq!(
            addresses(&lookup),
            BTreeSet::from([TransportAddr::Ip(a_socket), TransportAddr::Ip(b_after)]),
            "a keeps its last socket while b moves"
        );
    }
}
