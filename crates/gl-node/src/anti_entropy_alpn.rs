//! ALPN anti-entropy — authenticated Want/Supply over Iroh QUIC (§3.4.1, R3).
//!
//! Gossip carries Announce only. Ledger bodies are fetched from an allowlisted
//! peer whose QUIC `EndpointId` is the connection remote. `openledger-author`
//! must also be on the same allowlist (H-14).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

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

/// Per-operation timeouts for ALPN anti-entropy sessions (M-06).
///
/// Without these a peer that accepts a connection and then never sends stalls
/// the session — and, before the loop was made concurrent, all replication.
///
/// The defaults are deliberately generous: a full 16 MiB Supply frame transfers
/// well within 30s on any real link, and a read timeout only fires when a peer
/// genuinely stalls. These will get a config surface later (T38).
#[derive(Clone, Copy, Debug)]
pub struct AntiEntropyTimeouts {
    /// Cap on establishing a QUIC connection to a peer.
    pub connect: Duration,
    /// Cap on a single frame read or write.
    pub io: Duration,
}

impl Default for AntiEntropyTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            io: Duration::from_secs(30),
        }
    }
}

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
    /// Per-operation connect and I/O timeouts (M-06).
    pub timeouts: AntiEntropyTimeouts,
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
    let io_timeout = handler.timeouts.io;
    loop {
        let message = match read_message(&mut recv, io_timeout).await {
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
                    write_message(&mut send, &page, io_timeout).await?;
                }
            }
            WireMessage::Want { ids, .. } => {
                // One Supply per Want, trimmed to what the requester can decode
                // (H-02); it re-Wants any tail we could not fit.
                let entries = collect_supply(&handler.ledger, &ids).await;
                let reply = p2p::anti_entropy::truncate_supply(entries);
                write_message(&mut send, &reply, io_timeout).await?;
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
    let connection = match tokio::time::timeout(
        handler.timeouts.connect,
        endpoint.connect(peer_addr, p2p::protocol::ANTI_ENTROPY_ALPN),
    )
    .await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            warn!(peer = %peer, %error, "anti-entropy connect failed");
            return;
        }
        Err(_elapsed) => {
            warn!(peer = %peer, "anti-entropy connect timed out");
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
    let connection = match tokio::time::timeout(
        handler.timeouts.connect,
        endpoint.connect(peer_addr, p2p::protocol::ANTI_ENTROPY_ALPN),
    )
    .await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            debug!(peer = %peer, %error, "anti-entropy exchange connect failed");
            return;
        }
        Err(_elapsed) => {
            debug!(peer = %peer, "anti-entropy exchange connect timed out");
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
        write_message(&mut send, &page, handler.timeouts.io).await?;
    }
    let (head_txids, directive_ids) =
        read_have_heads_advert(&mut recv, remote, handler.timeouts.io).await?;
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
    io_timeout: Duration,
) -> Result<(Vec<String>, Vec<String>), String> {
    let mut head_txids: Vec<String> = Vec::new();
    let mut directive_ids: Vec<String> = Vec::new();
    loop {
        let WireMessage::HaveHeads {
            head_txids: page_heads,
            directive_ids: page_directives,
            more,
            ..
        } = read_message(recv, io_timeout).await?
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
        write_message(
            send,
            &WireMessage::want(remaining.clone()),
            handler.timeouts.io,
        )
        .await?;
        let entries = match read_message(recv, handler.timeouts.io).await? {
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
    // L-21: a Want may list the same id more than once (every missing head is
    // also a directive id upstream, so `compute_want` used to want it twice).
    // Serve each distinct id at most once — preserving first-occurrence order —
    // so the requester does not re-validate the same body per copy. Composes
    // with `truncate_supply` (T18), which trims the deduped batch to the frame.
    let mut seen: HashSet<&str> = HashSet::new();
    ids.iter()
        .filter(|id| seen.insert(id.as_str()))
        .filter_map(|id| svc.get_directive(id).map(make_supply_entry))
        .collect()
}

/// Tally of what `apply_supply_entries` did with one `Supply` batch (M-14).
///
/// Every entry lands in exactly one bucket, so the fields partition the batch.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SupplyOutcome {
    /// M-14 fast path: `entry.id` was already in the DAG, so validation was skipped.
    pub skipped_present: usize,
    /// Validated and newly merged into the DAG.
    pub merged: usize,
    /// Parents missing; took the orphan-buffer path.
    pub buffered: usize,
    /// `insert_remote_directive` returned `Ok(None)` (present at insert time).
    pub duplicate: usize,
    /// Invalid body / author / signature / insert error.
    pub rejected: usize,
}

async fn apply_supply_entries(
    handler: &AntiEntropyHandler,
    entries: Vec<p2p::protocol::SupplyEntry>,
    remote: EndpointId,
) -> SupplyOutcome {
    let from_peer = remote.to_string();
    let mut outcome = SupplyOutcome::default();
    for entry in entries {
        // M-14: dedup BEFORE validate. `validate_supply_entry` parses up to 1 MiB
        // of beancount, re-serializes, hashes, and Ed25519-verifies every entry
        // before anything checks whether `entry.id` is already in the DAG — the
        // G-Set dedup only happens later inside `insert_remote_directive`. So an
        // allowlisted peer can replay the same Supply in a loop, paying full
        // parse+verify per entry to change nothing.
        //
        // Skipping validation for an id we already hold is state-preserving:
        // `entry.id` is content-addressed and is re-checked authoritatively under
        // the write lock by `insert_remote_directive`, which returns `Ok(None)`
        // for a present id without overwriting. A forged entry claiming a present
        // id either (a) hashes to that id — it IS that content, a genuine
        // duplicate — or (b) does not, in which case `validate_supply_entry` would
        // reject it. In case (b) the entry is discarded whether we skip it here or
        // reject it below, so it is never stored either way. Thus this fast path
        // changes no state; it only avoids wasted CPU and a log line. The read
        // guard is a temporary dropped at the end of this statement, so no lock is
        // held into validation.
        if handler
            .ledger
            .read()
            .await
            .get_directive(&entry.id)
            .is_some()
        {
            outcome.skipped_present += 1;
            continue;
        }
        match validate_supply_entry(&entry) {
            Ok(directive) => {
                if let Err(error) = verify_author_allowlisted(&directive, &handler.allowlist) {
                    warn!(%error, peer = %remote, "rejected ALPN supply: author not allowlisted");
                    outcome.rejected += 1;
                    continue;
                }
                if let Err(error) = verify_remote_signature(
                    &directive,
                    handler.signing_enabled,
                    &handler.swarm_topic,
                ) {
                    warn!(%error, peer = %remote, "rejected ALPN supply: signature");
                    outcome.rejected += 1;
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
                    outcome.buffered += 1;
                    continue;
                }
                match svc.insert_remote_directive(directive.clone()) {
                    Ok(Some(content_id)) => {
                        info!(content_id = %content_id, peer = %remote, "merged remote directive from ALPN");
                        outcome.merged += 1;
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
                    Ok(None) => {
                        debug!("ALPN supply entry was duplicate");
                        outcome.duplicate += 1;
                    }
                    Err(error) => {
                        warn!(%error, "rejected remote directive from ALPN");
                        outcome.rejected += 1;
                    }
                }
            }
            Err(error) => {
                warn!(%error, "invalid ALPN supply entry");
                outcome.rejected += 1;
            }
        }
    }
    debug!(
        peer = %remote,
        skipped_present = outcome.skipped_present,
        merged = outcome.merged,
        buffered = outcome.buffered,
        duplicate = outcome.duplicate,
        rejected = outcome.rejected,
        "applied ALPN supply batch"
    );
    outcome
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

async fn write_message(
    send: &mut SendStream,
    message: &WireMessage,
    io_timeout: Duration,
) -> Result<(), String> {
    let bytes = message.to_wire()?;
    match tokio::time::timeout(io_timeout, send.write_all(&bytes)).await {
        Ok(result) => result.map_err(|error| error.to_string()),
        // A stalled write is a torn-down session, not a clean shutdown, so this
        // error string deliberately avoids "early eof"/"closed" (M-06).
        Err(_elapsed) => Err("anti-entropy write timed out".to_owned()),
    }
}

async fn read_message(recv: &mut RecvStream, io_timeout: Duration) -> Result<WireMessage, String> {
    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(io_timeout, recv.read_exact(&mut len_buf)).await {
        Ok(result) => result.map_err(|error| format!("early eof: {error}"))?,
        // A stalled read is a torn-down session, not a clean shutdown. The error
        // string must NOT contain "early eof"/"closed": `serve_anti_entropy`
        // matches those to break cleanly, and a timeout is a real error (M-06).
        Err(_elapsed) => return Err("anti-entropy read timed out".to_owned()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE as usize {
        return Err(format!("anti-entropy frame too large: {len}"));
    }
    let mut body = vec![0u8; len];
    match tokio::time::timeout(io_timeout, recv.read_exact(&mut body)).await {
        Ok(result) => result.map_err(|error| error.to_string())?,
        Err(_elapsed) => return Err("anti-entropy read timed out".to_owned()),
    }
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
        make_handler_with_timeouts(ledger, allowlist, AntiEntropyTimeouts::default())
    }

    fn make_handler_with_timeouts(
        ledger: SharedLedger,
        allowlist: PeerAllowlist,
        timeouts: AntiEntropyTimeouts,
    ) -> AntiEntropyHandler {
        AntiEntropyHandler {
            ledger,
            broadcast: TransactionBroadcast::new(),
            orphan_buffer: Arc::new(RwLock::new(OrphanBuffer::new())),
            allowlist,
            signing_enabled: false,
            swarm_topic: String::new(),
            timeouts,
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

    /// Short timeouts so the M-06 tests trip their read caps in milliseconds.
    fn short_timeouts() -> AntiEntropyTimeouts {
        AntiEntropyTimeouts {
            connect: Duration::from_millis(500),
            io: Duration::from_millis(500),
        }
    }

    /// Seed `ledger` with two `open`s and one balanced transaction (3 directives).
    async fn seed_funding_ledger(ledger: &SharedLedger) -> usize {
        let mut service = ledger.write().await;
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
        service.directive_count()
    }

    /// An ALPN server that accepts a connection and then never replies — the
    /// M-06 stall vector. Used to prove the client's per-frame read timeout
    /// fires instead of the session hanging forever.
    #[derive(Debug, Clone)]
    struct TarpitHandler;

    impl ProtocolHandler for TarpitHandler {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            // Accept the client's bi-stream, then hang forever without ever
            // replying: the client must tear the session down on its own timer.
            let _streams = connection.accept_bi().await;
            std::future::pending::<Result<(), AcceptError>>().await
        }
    }

    /// M-06 core vector: a peer that accepts a connection and then never replies
    /// (a "tarpit") must not hang the client. The per-frame read timeout tears
    /// the session down; `exchange_with_peer` RETURNS well within a generous
    /// bound. The assertion is that the OUTER guard timeout does NOT fire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tarpit_peer_read_times_out() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_tarpit = bind_direct_endpoint().await;

        let id_client = endpoint_client.id();
        let id_tarpit = endpoint_tarpit.id();

        let router_tarpit = Router::builder(endpoint_tarpit.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, TarpitHandler)
            .spawn();

        let allow_client =
            PeerAllowlist::parse(&[id_tarpit.to_string()]).expect("allowlist client");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));

        let handler_client =
            make_handler_with_timeouts(ledger_client, allow_client, short_timeouts());

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_tarpit).await;
        let addr_tarpit = endpoint_tarpit.addr();

        // 4×io is a generous bound: the exchange should return at ~io (500 ms)
        // once the read against the silent peer times out.
        let outcome = tokio::time::timeout(
            Duration::from_millis(2_000),
            exchange_with_peer(&endpoint_client, addr_tarpit, &handler_client),
        )
        .await;

        let _ = router_tarpit.shutdown().await;
        assert!(
            outcome.is_ok(),
            "M-06: exchange_with_peer hung against a tarpit peer instead of timing out"
        );
    }

    /// M-06 money test: one healthy peer + one tarpit, exchanged CONCURRENTLY
    /// (the pattern `spawn_anti_entropy_loop` now uses). The healthy peer's
    /// directives must still be pulled despite the tarpit, and the whole tick
    /// must finish within a bounded time — proving a hung peer no longer blocks
    /// a healthy one, which it did when the loop awaited each exchange inline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hung_peer_does_not_block_healthy_peer() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_source = bind_direct_endpoint().await;
        let endpoint_tarpit = bind_direct_endpoint().await;

        let id_client = endpoint_client.id();
        let id_source = endpoint_source.id();
        let id_tarpit = endpoint_tarpit.id();

        // Seed the healthy source with independent `open`s (no parent chain), so
        // one exchange round transfers and applies the whole set with no orphan
        // buffering — the single-tick convergence here is deterministic, unlike a
        // transaction that depends on its parents arriving first.
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let source_path = temp_dir.path().join("source.bean");
        write_open_directive_ledger(&source_path, 5, &id_source.to_string());
        let ledger_source: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(source_path, id_source.to_string()).expect("boot source ledger"),
        ));
        let source_count = ledger_source.read().await.directive_count();
        assert_eq!(source_count, 5, "seed: five independent opens");

        let allow_source =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist source");
        let handler_source = make_handler(ledger_source.clone(), allow_source);
        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_source.clone())
            .spawn();

        let router_tarpit = Router::builder(endpoint_tarpit.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, TarpitHandler)
            .spawn();

        let allow_client = PeerAllowlist::parse(&[id_source.to_string(), id_tarpit.to_string()])
            .expect("allowlist client");
        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));
        let handler_client =
            make_handler_with_timeouts(ledger_client.clone(), allow_client, short_timeouts());

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_source).await;
        wait_until_dialable(&endpoint_tarpit).await;

        let addr_source = endpoint_source.addr();
        let addr_tarpit = endpoint_tarpit.addr();

        // Each tick runs BOTH peers' exchanges concurrently, exactly as
        // `spawn_anti_entropy_loop` now does: spawn into a JoinSet and drain
        // before the next tick (M-06). Driving the drain pattern directly avoids
        // standing up a PeerNode/registry while exercising the isolation
        // property. If a hung peer blocked a healthy one (the pre-fix serial
        // loop), a single drain would exceed its bound and the client would
        // never converge.
        let run_concurrent_tick = || {
            let addr_source = addr_source.clone();
            let addr_tarpit = addr_tarpit.clone();
            let endpoint_client = endpoint_client.clone();
            let handler_client = handler_client.clone();
            async move {
                let mut set = tokio::task::JoinSet::new();
                for addr in [addr_source, addr_tarpit] {
                    let endpoint = endpoint_client.clone();
                    let handler = handler_client.clone();
                    set.spawn(async move {
                        exchange_with_peer(&endpoint, addr, &handler).await;
                    });
                }
                while set.join_next().await.is_some() {}
            }
        };

        // Converge with the healthy peer despite the tarpit. Every tick is bounded
        // by the tarpit's ~io read timeout (500 ms), so both the per-tick guard
        // and the overall deadline are generous multiples of that (M-06).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let count_client = loop {
            let tick_started = tokio::time::Instant::now();
            let tick_outcome =
                tokio::time::timeout(Duration::from_millis(2_000), run_concurrent_tick()).await;
            assert!(
                tick_outcome.is_ok(),
                "M-06: a concurrent tick exceeded 4x io ({:?}) — the tarpit blocked the drain",
                tick_started.elapsed()
            );

            let count = ledger_client.read().await.directive_count();
            if count == source_count {
                break count;
            }
            if tokio::time::Instant::now() > deadline {
                break count;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        let _ = router_source.shutdown().await;
        let _ = router_tarpit.shutdown().await;

        assert_eq!(
            count_client, source_count,
            "M-06: healthy peer's directives were not pulled despite the tarpit"
        );
    }

    /// M-06 guard: the timeouts must not break a legitimate transfer. Two real
    /// handlers on SHORT timeouts still converge — proving the caps are not so
    /// tight that they trip on a normal exchange.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn happy_path_short_timeouts_converges() {
        let _serialized = NET_TEST_LOCK.lock().await;

        let endpoint_client = bind_direct_endpoint().await;
        let endpoint_source = bind_direct_endpoint().await;

        let id_client = endpoint_client.id();
        let id_source = endpoint_source.id();

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_source: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("source.bean"), id_source.to_string())
                .expect("boot source ledger"),
        ));
        let source_count = seed_funding_ledger(&ledger_source).await;

        let allow_source =
            PeerAllowlist::parse(&[id_client.to_string()]).expect("allowlist source");
        let allow_client =
            PeerAllowlist::parse(&[id_source.to_string()]).expect("allowlist client");

        let ledger_client: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("client.bean"), id_client.to_string())
                .expect("boot client ledger"),
        ));

        let handler_source =
            make_handler_with_timeouts(ledger_source.clone(), allow_source, short_timeouts());
        let handler_client =
            make_handler_with_timeouts(ledger_client.clone(), allow_client, short_timeouts());

        let router_source = Router::builder(endpoint_source.clone())
            .accept(p2p::protocol::ANTI_ENTROPY_ALPN, handler_source.clone())
            .spawn();

        wait_until_dialable(&endpoint_client).await;
        wait_until_dialable(&endpoint_source).await;
        let addr_source = endpoint_source.addr();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            exchange_with_peer(&endpoint_client, addr_source.clone(), &handler_client).await;
            if ledger_client.read().await.directive_count() == source_count {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let _ = router_source.shutdown().await;
                panic!("M-06 happy path: client did not converge under short timeouts");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = router_source.shutdown().await;
    }

    /// L-21: a `Want` listing the same id N times yields exactly ONE `SupplyEntry`.
    #[tokio::test]
    async fn collect_supply_dedups_repeated_ids() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("led.bean"), "author".to_owned())
                .expect("boot ledger"),
        ));
        let id = {
            let mut svc = ledger.write().await;
            svc.open_account(
                "Assets:Cash".to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                vec!["USD".to_owned()],
            )
            .expect("open account")
        };

        let entries = collect_supply(&ledger, &[id.clone(), id.clone(), id.clone()]).await;
        assert_eq!(
            entries.len(),
            1,
            "one directive → one entry, however many copies the Want listed"
        );
        assert_eq!(entries[0].id, id);
    }

    /// M-14: an entry whose id is already in the DAG is skipped BEFORE
    /// `validate_supply_entry`, even when its body would fail validation.
    #[tokio::test]
    async fn apply_supply_entries_skips_present_id_without_validating() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("led.bean"), "author".to_owned())
                .expect("boot ledger"),
        ));
        let present_id = {
            let mut svc = ledger.write().await;
            svc.open_account(
                "Assets:Cash".to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                vec!["USD".to_owned()],
            )
            .expect("open account")
        };
        assert_eq!(ledger.read().await.directive_count(), 1);

        // Same id (D's kind is Open), but a body that WOULD fail
        // `validate_supply_entry`. With the fast path this is never parsed
        // (skipped_present); without it, it reaches validate and is counted
        // rejected instead.
        let entry = p2p::protocol::SupplyEntry {
            id: present_id.clone(),
            kind: p2p::protocol::DirectiveKind::Open,
            economic_bean: "this is not valid beancount".to_owned(),
            envelope: std::collections::BTreeMap::new(),
        };

        let handler = make_handler(
            ledger.clone(),
            PeerAllowlist::parse(&[]).expect("allowlist"),
        );
        let remote = iroh::SecretKey::generate().public();
        let outcome = apply_supply_entries(&handler, vec![entry], remote).await;

        assert_eq!(
            outcome.skipped_present, 1,
            "a present id must take the M-14 fast path"
        );
        assert_eq!(outcome.merged, 0);
        assert_eq!(
            outcome.rejected, 0,
            "the garbage body must never reach validation"
        );

        // Ledger unchanged: still exactly D.
        let svc = ledger.read().await;
        assert_eq!(svc.directive_count(), 1);
        assert!(svc.get_directive(&present_id).is_some());
    }

    /// M-14 does not over-skip: a genuinely new, valid entry still merges.
    #[tokio::test]
    async fn apply_supply_entries_merges_genuinely_new_entry() {
        let author = iroh::SecretKey::generate().public();
        let allow = PeerAllowlist::parse(&[author.to_string()]).expect("allowlist");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        // A source ledger authored by `author`: its `open` is stamped with
        // `openledger-author` = an allowlisted id, so the served entry passes
        // `verify_author_allowlisted`.
        let mut source = LedgerService::boot(temp_dir.path().join("src.bean"), author.to_string())
            .expect("boot source");
        let open_id = source
            .open_account(
                "Assets:Cash".to_owned(),
                NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date"),
                vec!["USD".to_owned()],
            )
            .expect("open account");
        let entry = make_supply_entry(source.get_directive(&open_id).expect("directive present"));

        // A sink ledger that has never seen this id.
        let sink: SharedLedger = Arc::new(RwLock::new(
            LedgerService::boot(temp_dir.path().join("sink.bean"), "sink".to_owned())
                .expect("boot sink"),
        ));
        let handler = make_handler(sink.clone(), allow);
        let remote = iroh::SecretKey::generate().public();

        let outcome = apply_supply_entries(&handler, vec![entry], remote).await;
        assert_eq!(
            outcome.skipped_present, 0,
            "a genuinely new id must NOT be skipped by the fast path"
        );
        assert_eq!(outcome.merged, 1, "a new valid entry must merge");
        assert_eq!(outcome.rejected, 0);
        assert_eq!(sink.read().await.directive_count(), 1);
    }
}
