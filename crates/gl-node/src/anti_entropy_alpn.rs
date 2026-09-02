//! ALPN anti-entropy — authenticated Want/Supply over Iroh QUIC (§3.4.1, R3).
//!
//! Gossip carries Announce only. Ledger bodies are fetched from an allowlisted
//! peer whose QUIC `EndpointId` is the connection remote. `openledger-author`
//! must also be on the same allowlist (H-14).

use std::collections::HashSet;
use std::sync::Arc;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::EndpointId;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::graphql::broadcast::TransactionBroadcast;
use crate::graphql::query::domain_txn_to_graphql;
use crate::graphql::SharedLedger;

use p2p::allowlist::PeerAllowlist;
use p2p::gossip::make_supply_entry;
use p2p::orphan_buffer::OrphanBuffer;
use p2p::protocol::{WireMessage, MAX_MESSAGE_SIZE, MAX_SUPPLY_ENTRIES};
use p2p::union_merge::{validate_supply_entry, verify_author_allowlisted, verify_remote_signature};

/// Cap on ids accumulated across one peer's paginated `HaveHeads` advert (H-02).
///
/// Pagination lets an honest peer advertise a ledger of any size, but it also
/// lets a malicious one stream pages forever. A million ids is far past any
/// ledger the 64 MiB file cap permits, so honest peers never approach it.
const MAX_ACCUMULATED_HAVE_HEADS: usize = 1_048_576;

/// Shared handler registered on `openledger/anti-entropy/1`.
#[derive(Clone)]
pub struct AntiEntropyHandler {
    pub ledger: SharedLedger,
    pub broadcast: TransactionBroadcast,
    pub orphan_buffer: Arc<RwLock<OrphanBuffer>>,
    pub allowlist: PeerAllowlist,
    pub signing_enabled: bool,
    /// This node's mesh identity (swarm topic), bound into signature checks (L2).
    pub swarm_topic: String,
}

impl std::fmt::Debug for AntiEntropyHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AntiEntropyHandler")
            .field("signing_enabled", &self.signing_enabled)
            .finish_non_exhaustive()
    }
}

impl ProtocolHandler for AntiEntropyHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        if !self.allowlist.admits(remote) {
            warn!(peer = %remote, "rejecting anti-entropy connection not on bootstrap allowlist");
            connection.close(1u32.into(), b"not-allowlisted");
            return Err(AcceptError::from_err(std::io::Error::other(
                "anti-entropy peer not allowlisted",
            )));
        }
        if let Err(error) = serve_anti_entropy(self, connection, remote).await {
            warn!(peer = %remote, %error, "anti-entropy inbound session failed");
            return Err(AcceptError::from_err(std::io::Error::other(error)));
        }
        Ok(())
    }
}

async fn serve_anti_entropy(
    handler: &AntiEntropyHandler,
    connection: Connection,
    remote: EndpointId,
) -> Result<(), String> {
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|error| error.to_string())?;
    loop {
        let message = match read_message(&mut recv).await {
            Ok(message) => message,
            Err(error) if error.contains("early eof") || error.contains("closed") => break,
            Err(error) => return Err(error),
        };
        match message {
            // A non-final page of the peer's advert (H-02): its content is not
            // used — we always answer with our own full state — so wait for the
            // final page and reply exactly once per advert, keeping the session
            // lockstep.
            WireMessage::HaveHeads { more: true, .. } => {}
            WireMessage::HaveHeads { .. } => {
                for page in local_have_heads_pages(&handler.ledger).await {
                    write_message(&mut send, &page).await?;
                }
            }
            WireMessage::Want { ids, .. } => {
                // One Supply per Want, trimmed to what the requester can decode
                // (H-02); it re-Wants any tail we could not fit.
                let entries = collect_supply(&handler.ledger, &ids).await;
                let reply = p2p::anti_entropy::truncate_supply(entries);
                write_message(&mut send, &reply).await?;
            }
            WireMessage::Supply { entries, .. } => {
                apply_supply_entries(handler, entries, remote).await;
            }
            WireMessage::Announce { .. } => {
                debug!(peer = %remote, "ignoring announce on anti-entropy ALPN");
            }
        }
    }
    let _ = send.finish();
    Ok(())
}

/// Fetch missing ids from an allowlisted peer (gossip Announce catch-up).
pub async fn fetch_want(
    endpoint: &iroh::Endpoint,
    peer: impl Into<iroh::EndpointAddr>,
    ids: Vec<String>,
    handler: &AntiEntropyHandler,
) {
    let peer_addr = peer.into();
    let peer = peer_addr.id;
    if ids.is_empty() || !handler.allowlist.admits(peer) {
        return;
    }
    let connection = match endpoint
        .connect(peer_addr, p2p::protocol::ANTI_ENTROPY_ALPN)
        .await
    {
        Ok(connection) => connection,
        Err(error) => {
            warn!(peer = %peer, %error, "anti-entropy connect failed");
            return;
        }
    };
    if let Err(error) = run_want_session(&connection, ids, handler, peer).await {
        warn!(peer = %peer, %error, "anti-entropy want session failed");
    }
}

/// Periodic head exchange with one allowlisted peer.
pub async fn exchange_with_peer(
    endpoint: &iroh::Endpoint,
    peer: impl Into<iroh::EndpointAddr>,
    handler: &AntiEntropyHandler,
) {
    let peer_addr = peer.into();
    let peer = peer_addr.id;
    if !handler.allowlist.admits(peer) {
        return;
    }
    let connection = match endpoint
        .connect(peer_addr, p2p::protocol::ANTI_ENTROPY_ALPN)
        .await
    {
        Ok(connection) => connection,
        Err(error) => {
            debug!(peer = %peer, %error, "anti-entropy exchange connect failed");
            return;
        }
    };
    if let Err(error) = run_head_exchange(&connection, handler, peer).await {
        warn!(peer = %peer, %error, "anti-entropy head exchange failed");
    }
}

async fn run_want_session(
    connection: &Connection,
    ids: Vec<String>,
    handler: &AntiEntropyHandler,
    remote: EndpointId,
) -> Result<(), String> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    for chunk in ids.chunks(MAX_SUPPLY_ENTRIES) {
        fetch_want_chunk(&mut send, &mut recv, chunk, handler, remote).await?;
    }
    let _ = send.finish();
    Ok(())
}

async fn run_head_exchange(
    connection: &Connection,
    handler: &AntiEntropyHandler,
    remote: EndpointId,
) -> Result<(), String> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    for page in local_have_heads_pages(&handler.ledger).await {
        write_message(&mut send, &page).await?;
    }
    let (head_txids, directive_ids) = read_have_heads_advert(&mut recv, remote).await?;
    let want = {
        let svc = handler.ledger.read().await;
        p2p::anti_entropy::compute_want(
            &svc.head_txids(),
            &svc.all_directive_ids(),
            &head_txids,
            &directive_ids,
        )
    };
    for chunk in want.chunks(MAX_SUPPLY_ENTRIES) {
        fetch_want_chunk(&mut send, &mut recv, chunk, handler, remote).await?;
    }
    let _ = send.finish();
    Ok(())
}

/// Read one peer's `HaveHeads` advert, following `more` pages (H-02).
///
/// Returns the accumulated head txids and directive ids.
async fn read_have_heads_advert(
    recv: &mut RecvStream,
    remote: EndpointId,
) -> Result<(Vec<String>, Vec<String>), String> {
    let mut head_txids: Vec<String> = Vec::new();
    let mut directive_ids: Vec<String> = Vec::new();
    loop {
        let WireMessage::HaveHeads {
            head_txids: page_heads,
            directive_ids: page_directives,
            more,
            ..
        } = read_message(recv).await?
        else {
            return Err("expected HaveHeads from peer".to_owned());
        };
        head_txids.extend(page_heads);
        directive_ids.extend(page_directives);
        if head_txids.len() > MAX_ACCUMULATED_HAVE_HEADS
            || directive_ids.len() > MAX_ACCUMULATED_HAVE_HEADS
        {
            return Err(format!(
                "peer {remote} advertised more than {MAX_ACCUMULATED_HAVE_HEADS} ids"
            ));
        }
        if !more {
            return Ok((head_txids, directive_ids));
        }
    }
}

/// Request one chunk of ids and drain the peer's replies (H-02).
///
/// A `Supply` may be a strict prefix of what was asked — the peer trims to its
/// frame budget — so re-`Want` whatever did not arrive until a round makes no
/// progress. Progress is measured against the ids the peer *served*, not the
/// ones we accepted: an entry we reject as invalid must end the loop, not spin
/// it forever.
async fn fetch_want_chunk(
    send: &mut SendStream,
    recv: &mut RecvStream,
    chunk: &[String],
    handler: &AntiEntropyHandler,
    remote: EndpointId,
) -> Result<(), String> {
    let mut remaining: Vec<String> = chunk.to_vec();
    while !remaining.is_empty() {
        write_message(send, &WireMessage::want(remaining.clone())).await?;
        let entries = match read_message(recv).await? {
            WireMessage::Supply { entries, .. } => entries,
            other => {
                warn!(peer = %remote, ?other, "expected Supply after Want");
                return Ok(());
            }
        };
        let served: HashSet<&str> = entries.iter().map(|entry| entry.id.as_str()).collect();
        let next: Vec<String> = remaining
            .iter()
            .filter(|id| !served.contains(id.as_str()))
            .cloned()
            .collect();
        let stalled = next.len() == remaining.len();
        apply_supply_entries(handler, entries, remote).await;
        if stalled {
            // The peer served none of what we asked for: it does not have them,
            // or the reply was empty. Another round would ask the same thing.
            return Ok(());
        }
        remaining = next;
    }
    Ok(())
}

async fn local_have_heads_pages(ledger: &SharedLedger) -> Vec<WireMessage> {
    let svc = ledger.read().await;
    p2p::anti_entropy::paginate_have_heads(&svc.head_txids(), &svc.all_directive_ids())
}

async fn collect_supply(ledger: &SharedLedger, ids: &[String]) -> Vec<p2p::protocol::SupplyEntry> {
    let svc = ledger.read().await;
    ids.iter()
        .filter_map(|id| svc.get_directive(id).map(make_supply_entry))
        .collect()
}

async fn apply_supply_entries(
    handler: &AntiEntropyHandler,
    entries: Vec<p2p::protocol::SupplyEntry>,
    remote: EndpointId,
) {
    let from_peer = remote.to_string();
    for entry in entries {
        match validate_supply_entry(&entry) {
            Ok(directive) => {
                if let Err(error) = verify_author_allowlisted(&directive, &handler.allowlist) {
                    warn!(%error, peer = %remote, "rejected ALPN supply: author not allowlisted");
                    continue;
                }
                if let Err(error) = verify_remote_signature(
                    &directive,
                    handler.signing_enabled,
                    &handler.swarm_topic,
                ) {
                    warn!(%error, peer = %remote, "rejected ALPN supply: signature");
                    continue;
                }
                let mut svc = handler.ledger.write().await;
                let missing_parents = svc.missing_parent_ids(&directive);
                if !missing_parents.is_empty() {
                    let content_id = ledger::service::LedgerService::content_id(&directive);
                    let mut buffer = handler.orphan_buffer.write().await;
                    if buffer.insert(
                        content_id.clone(),
                        directive,
                        missing_parents,
                        Some(from_peer.clone()),
                    ) {
                        debug!(content_id = %content_id, "buffered ALPN directive with missing parents");
                    } else {
                        warn!(content_id = %content_id, "orphan buffer full or per-peer quota exceeded");
                    }
                    continue;
                }
                match svc.insert_remote_directive(directive.clone()) {
                    Ok(Some(content_id)) => {
                        info!(content_id = %content_id, peer = %remote, "merged remote directive from ALPN");
                        if let ledger::model::Directive::Transaction(ref txn) = directive {
                            let graphql_txn = domain_txn_to_graphql(txn, &svc);
                            handler.broadcast.publish(graphql_txn);
                        }
                        drain_orphans(
                            &handler.orphan_buffer,
                            &mut svc,
                            &handler.broadcast,
                            handler.signing_enabled,
                            &handler.allowlist,
                            &handler.swarm_topic,
                        )
                        .await;
                    }
                    Ok(None) => debug!("ALPN supply entry was duplicate"),
                    Err(error) => warn!(%error, "rejected remote directive from ALPN"),
                }
            }
            Err(error) => warn!(%error, "invalid ALPN supply entry"),
        }
    }
}

/// Drain orphans whose parents have arrived. Re-checks signature and author.
pub async fn drain_orphans(
    orphan_buffer: &Arc<RwLock<OrphanBuffer>>,
    service: &mut ledger::service::LedgerService,
    broadcast: &TransactionBroadcast,
    signing_enabled: bool,
    allowlist: &PeerAllowlist,
    mesh_id: &str,
) {
    let mut dag_ids = service.all_directive_ids();
    let mut buffer = orphan_buffer.write().await;
    let mut resolved_any = true;
    while resolved_any {
        resolved_any = false;
        let wanted = buffer.wanted_parent_ids();
        for parent_id in wanted {
            if dag_ids.contains(&parent_id) {
                let freed = buffer.parent_arrived(&parent_id);
                for entry in freed {
                    if let Err(error) = verify_author_allowlisted(&entry.directive, allowlist) {
                        warn!(%error, "rejected resolved orphan: author");
                        continue;
                    }
                    if let Err(error) =
                        verify_remote_signature(&entry.directive, signing_enabled, mesh_id)
                    {
                        warn!(%error, "rejected resolved orphan: signature");
                        continue;
                    }
                    match service.insert_remote_directive(entry.directive.clone()) {
                        Ok(Some(content_id)) => {
                            info!(content_id = %content_id, "resolved orphan directive");
                            dag_ids.insert(content_id);
                            if let ledger::model::Directive::Transaction(ref txn) = entry.directive
                            {
                                let graphql_txn = domain_txn_to_graphql(txn, service);
                                broadcast.publish(graphql_txn);
                            }
                            resolved_any = true;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            warn!(%error, "rejected resolved orphan directive");
                        }
                    }
                }
            }
        }
    }
}

async fn write_message(send: &mut SendStream, message: &WireMessage) -> Result<(), String> {
    let bytes = message.to_wire()?;
    send.write_all(&bytes)
        .await
        .map_err(|error| error.to_string())
}

async fn read_message(recv: &mut RecvStream) -> Result<WireMessage, String> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|error| format!("early eof: {error}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE as usize {
        return Err(format!("anti-entropy frame too large: {len}"));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|error| error.to_string())?;
    WireMessage::decode_checked(&body).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;
    use std::time::Duration;

    use chrono::NaiveDate;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{Endpoint, TransportAddr};
    use ledger::model::{Amount, Flag};
    use ledger::service::{LedgerService, PostingInput, TransactionInput};
    use rust_decimal_macros::dec;

    /// Serializes the network tests in this module.
    ///
    /// They each bind several real QUIC endpoints and converge on wall-clock
    /// deadlines; run concurrently under `cargo test` they starve one another's
    /// runtimes and the deadlines flake. Every network test below holds this
    /// for its whole body.
    static NET_TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> =
        LazyLock::new(|| tokio::sync::Mutex::new(()));

    async fn bind_direct_endpoint() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .alpns(vec![p2p::protocol::ANTI_ENTROPY_ALPN.to_vec()])
            .bind()
            .await
            .expect("bind direct-only Iroh endpoint")
    }

    async fn wait_until_dialable(endpoint: &Endpoint) {
        for _ in 0..50 {
            if endpoint.addr().addrs.iter().any(TransportAddr::is_ip) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "endpoint {} never advertised an IP address: {:?}",
            endpoint.id(),
            endpoint.addr()
        );
    }

    fn balanced_funding_input() -> TransactionInput {
        TransactionInput {
            date: NaiveDate::from_ymd_opt(2024, 1, 15).expect("valid date"),
            flag: Flag::Complete,
            payee: Some("Acme".to_owned()),
            narration: Some("Funding".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        }
    }

    fn make_handler(ledger: SharedLedger, allowlist: PeerAllowlist) -> AntiEntropyHandler {
        AntiEntropyHandler {
            ledger,
            broadcast: TransactionBroadcast::new(),
            orphan_buffer: Arc::new(RwLock::new(OrphanBuffer::new())),
            allowlist,
            signing_enabled: false,
            swarm_topic: String::new(),
        }
    }

    /// R6 / SPEC M6: three direct-only endpoints converge over ALPN (no N0 relay).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn three_node_alpn_convergence() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_zero = bind_direct_endpoint().await;
        let endpoint_one = bind_direct_endpoint().await;
        let endpoint_two = bind_direct_endpoint().await;

        let id_zero = endpoint_zero.id();
        let id_one = endpoint_one.id();
        let id_two = endpoint_two.id();

        let allow_zero = PeerAllowlist::parse(&[id_one.to_string(), id_two.to_string()])
            .expect("allowlist zero");
        let allow_one = PeerAllowlist::parse(&[id_zero.to_string(), id_two.to_string()])
            .expect("allowlist one");
        let allow_two = PeerAllowlist::parse(&[id_zero.to_string(), id_one.to_string()])
            .expect("allowlist two");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_zero: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("zero.bean"), id_zero.to_string())
                .expect("boot ledger zero"),
        ));
        let ledger_one: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("one.bean"), id_one.to_string())
                .expect("boot ledger one"),
        ));
        let ledger_two: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("two.bean"), id_two.to_string())
                .expect("boot ledger two"),
        ));

        {
            let mut service = ledger_zero.write().await;
            service
                .open_account(
                    "Assets:Cash".to_owned(),
                    NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                    vec!["USD".to_owned()],
                )
                .expect("open cash");
            service
                .open_account(
                    "Equity:Opening".to_owned(),
                    NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                    Vec::new(),
                )
                .expect("open equity");
            service
                .append_transaction(balanced_funding_input())
                .expect("append funding");
        }
        let source_count = ledger_zero.read().await.directive_count();
        assert_eq!(
            source_count, 3,
            "source node should have two opens and one txn"
        );

        let handler_zero = make_handler(ledger_zero.clone(), allow_zero);
        let handler_one = make_handler(ledger_one.clone(), allow_one);
        let handler_two = make_handler(ledger_two.clone(), allow_two);

        let router_zero = Router::builder(endpoint_zero.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_zero.clone())
            .spawn();
        let router_one = Router::builder(endpoint_one.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_one.clone())
            .spawn();
        let router_two = Router::builder(endpoint_two.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_two.clone())
            .spawn();

        // Wait for real addresses instead of a fixed sleep: on a loaded machine
        // 200 ms is not always enough for the endpoints to advertise an IP, and
        // the first dial then fails for a reason the retry loop cannot see.
        wait_until_dialable(&endpoint_zero).await;
        wait_until_dialable(&endpoint_one).await;
        wait_until_dialable(&endpoint_two).await;

        let addr_zero = endpoint_zero.addr();
        let addr_one = endpoint_one.addr();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            exchange_with_peer(&endpoint_one, addr_zero.clone(), &handler_one).await;
            exchange_with_peer(&endpoint_two, addr_one.clone(), &handler_two).await;
            let count_one = ledger_one.read().await.directive_count();
            let count_two = ledger_two.read().await.directive_count();
            if count_one == source_count && count_two == source_count {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let probe = endpoint_one
                    .connect(addr_zero.clone(), p2p::protocol::ANTI_ENTROPY_ALPN)
                    .await;
                let _ = router_zero.shutdown().await;
                let _ = router_one.shutdown().await;
                let _ = router_two.shutdown().await;
                panic!(
                    "R6: three-node ALPN cluster did not converge: zero={source_count} one={count_one} two={count_two}; probe={probe:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let _ = router_zero.shutdown().await;
        let _ = router_one.shutdown().await;
        let _ = router_two.shutdown().await;
    }

    /// Write a `.bean` file holding `count` distinct `open` directives.
    ///
    /// Built as text so the source node can boot a large ledger in one shot;
    /// `openledger-author` is required on the receive path (H-14), and is not
    /// part of the economic body, so every directive still hashes distinctly by
    /// its account name alone.
    fn write_open_directive_ledger(path: &std::path::Path, count: usize, author: &str) {
        use std::fmt::Write as _;

        let mut content = String::new();
        for index in 0..count {
            writeln!(content, "2024-01-01 open Assets:Acct{index:05}").expect("write to String");
            writeln!(content, "  openledger-author: \"{author}\"").expect("write to String");
            content.push('\n');
        }
        std::fs::write(path, content).expect("write source ledger");
    }

    /// One-way catch-up of a ledger too big for a single frame of any kind.
    ///
    /// The source serves; the sink starts empty and pulls until it matches.
    async fn run_catchup_beyond_caps(directive_count: usize, timeout: Duration) {
        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_sink = bind_direct_endpoint().await;

        let id_source = endpoint_source.id();
        let id_sink = endpoint_sink.id();

        let allow_source = PeerAllowlist::parse(&[id_sink.to_string()]).expect("allowlist source");
        let allow_sink = PeerAllowlist::parse(&[id_source.to_string()]).expect("allowlist sink");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let source_path = temp_dir.path().join("source.bean");
        write_open_directive_ledger(&source_path, directive_count, &id_source.to_string());

        let ledger_source: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(source_path, id_source.to_string()).expect("boot source ledger"),
        ));
        let ledger_sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), id_sink.to_string())
                .expect("boot sink ledger"),
        ));

        let source_count = ledger_source.read().await.directive_count();
        assert_eq!(source_count, directive_count, "source ledger boot count");
        assert_eq!(
            ledger_sink.read().await.directive_count(),
            0,
            "sink starts empty"
        );

        let handler_source = make_handler(ledger_source.clone(), allow_source);
        let handler_sink = make_handler(ledger_sink.clone(), allow_sink);

        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_source.clone())
            .spawn();

        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_sink).await;
        let addr_source = endpoint_source.addr();

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            exchange_with_peer(&endpoint_sink, addr_source.clone(), &handler_sink).await;
            let count = ledger_sink.read().await.directive_count();
            if count == source_count {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let _ = router_source.shutdown().await;
                panic!("H-02: sink never caught up: source={source_count} sink={count}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = router_source.shutdown().await;
    }

    /// H-02: 1_500 directives is past both the 256-entry `Supply` cap and the
    /// 1_024-id `Want` cap, so the pre-fix senders wedge here — the server
    /// answered a 1_024-id `Want` with one oversized `Supply` that the client's
    /// own `decode_checked` then rejected, forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_node_catchup_beyond_caps() {
        let _serialized = NET_TEST_LOCK.lock().await;
        run_catchup_beyond_caps(1_500, Duration::from_secs(180)).await;
    }

    /// H-02: 4_300 directives additionally crosses `MAX_HAVE_HEADS` (4_096), so
    /// the head advert itself has to paginate.
    ///
    /// Ignored by default because the receiving side re-serializes and fsyncs
    /// the whole `.bean` file on every single insert, making catch-up O(N²) IO.
    /// That cost is T27's to fix, not this test's; run it manually or nightly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "slow: run manually / nightly"]
    async fn two_node_catchup_beyond_have_heads_cap() {
        let _serialized = NET_TEST_LOCK.lock().await;
        run_catchup_beyond_caps(4_300, Duration::from_secs(900)).await;
    }
}
