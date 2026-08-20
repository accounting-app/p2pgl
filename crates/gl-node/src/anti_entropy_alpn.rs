//! ALPN anti-entropy — authenticated Want/Supply over Iroh QUIC (§3.4.1, R3).
//!
//! Gossip carries Announce only. Ledger bodies are fetched from an allowlisted
//! peer whose QUIC `EndpointId` is the connection remote. `openledger-author`
//! must also be on the same allowlist (H-14).

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
use p2p::protocol::{WireMessage, MAX_MESSAGE_SIZE, MAX_WANT_IDS};
use p2p::union_merge::{validate_supply_entry, verify_author_allowlisted, verify_remote_signature};

/// Shared handler registered on `openledger/anti-entropy/1`.
#[derive(Clone)]
pub struct AntiEntropyHandler {
    pub ledger: SharedLedger,
    pub broadcast: TransactionBroadcast,
    pub orphan_buffer: Arc<RwLock<OrphanBuffer>>,
    pub allowlist: PeerAllowlist,
    pub signing_enabled: bool,
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
            WireMessage::HaveHeads { .. } => {
                let reply = local_have_heads(&handler.ledger).await;
                write_message(&mut send, &reply).await?;
            }
            WireMessage::Want { ids, .. } => {
                let entries = collect_supply(&handler.ledger, &ids).await;
                write_message(&mut send, &WireMessage::supply(entries)).await?;
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
    peer: EndpointId,
    ids: Vec<String>,
    handler: &AntiEntropyHandler,
) {
    if ids.is_empty() || !handler.allowlist.admits(peer) {
        return;
    }
    let connection = match endpoint
        .connect(peer, p2p::protocol::ANTI_ENTROPY_ALPN)
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
    peer: EndpointId,
    handler: &AntiEntropyHandler,
) {
    if !handler.allowlist.admits(peer) {
        return;
    }
    let connection = match endpoint
        .connect(peer, p2p::protocol::ANTI_ENTROPY_ALPN)
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
    for chunk in ids.chunks(MAX_WANT_IDS) {
        write_message(&mut send, &WireMessage::want(chunk.to_vec())).await?;
        match read_message(&mut recv).await? {
            WireMessage::Supply { entries, .. } => {
                apply_supply_entries(handler, entries, remote).await;
            }
            other => {
                warn!(peer = %remote, ?other, "expected Supply on want session");
            }
        }
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
    write_message(&mut send, &local_have_heads(&handler.ledger).await).await?;
    let WireMessage::HaveHeads {
        head_txids,
        directive_ids,
        ..
    } = read_message(&mut recv).await?
    else {
        return Err("expected HaveHeads from peer".to_owned());
    };
    let want = {
        let svc = handler.ledger.read().await;
        p2p::anti_entropy::compute_want(
            &svc.head_txids(),
            &svc.all_directive_ids(),
            &head_txids,
            &directive_ids,
        )
    };
    for chunk in want.chunks(MAX_WANT_IDS) {
        if chunk.is_empty() {
            continue;
        }
        write_message(&mut send, &WireMessage::want(chunk.to_vec())).await?;
        match read_message(&mut recv).await? {
            WireMessage::Supply { entries, .. } => {
                apply_supply_entries(handler, entries, remote).await;
            }
            other => {
                warn!(peer = %remote, ?other, "expected Supply after Want");
            }
        }
    }
    let _ = send.finish();
    Ok(())
}

async fn local_have_heads(ledger: &SharedLedger) -> WireMessage {
    let svc = ledger.read().await;
    p2p::anti_entropy::make_have_heads(&svc.head_txids(), &svc.all_directive_ids())
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
                if let Err(error) = verify_remote_signature(&directive, handler.signing_enabled) {
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
                    if let Err(error) = verify_remote_signature(&entry.directive, signing_enabled) {
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
