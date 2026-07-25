//! Anti-entropy protocol (§3.4).
//!
//! On connect and every `antiEntropyIntervalMilliseconds`, peers exchange
//! heads + non-transaction ID digests. The lagging peer pulls missing
//! directives until closed.

use std::collections::HashSet;

use crate::protocol::{SupplyEntry, WireMessage};

/// Compute which IDs the remote has that we don't (the `want` set).
///
/// Given our local heads and the remote's advertised heads + directive IDs,
/// returns the IDs we should request via a `want` message.
pub fn compute_want(
    local_txids: &HashSet<String>,
    local_directive_ids: &HashSet<String>,
    remote_head_txids: &[String],
    remote_directive_ids: &[String],
) -> Vec<String> {
    let mut want = Vec::new();

    for txid in remote_head_txids {
        if !local_txids.contains(txid) {
            want.push(txid.clone());
        }
    }

    for id in remote_directive_ids {
        if !local_directive_ids.contains(id) {
            want.push(id.clone());
        }
    }

    want
}

/// Compute the `have_heads` message for our local state.
///
/// This advertises our DAG frontier to the remote peer so they can
/// determine what they're missing.
pub fn make_have_heads(
    local_head_txids: &HashSet<String>,
    local_directive_ids: &HashSet<String>,
) -> WireMessage {
    let mut heads: Vec<String> = local_head_txids.iter().cloned().collect();
    heads.sort();
    let mut directives: Vec<String> = local_directive_ids.iter().cloned().collect();
    directives.sort();

    WireMessage::have_heads(heads, directives)
}

/// Filter a list of requested IDs to only those we have locally.
///
/// Returns the entries we can supply, plus the IDs we don't have.
pub fn filter_supply_requests<'a>(
    requested_ids: &[String],
    local_entries: &'a [SupplyEntry],
) -> (Vec<&'a SupplyEntry>, Vec<String>) {
    let local_map: HashSet<&str> = local_entries.iter().map(|e| e.id.as_str()).collect();

    let mut can_supply = Vec::new();
    let mut cannot_supply = Vec::new();

    for id in requested_ids {
        if local_map.contains(id.as_str()) {
            if let Some(entry) = local_entries.iter().find(|e| e.id == *id) {
                can_supply.push(entry);
            }
        } else {
            cannot_supply.push(id.clone());
        }
    }

    (can_supply, cannot_supply)
}

/// Result of an anti-entropy exchange round.
#[derive(Debug, Clone, Default)]
pub struct ExchangeResult {
    /// IDs we need from the remote.
    pub want_from_remote: Vec<String>,
    /// IDs the remote needs from us.
    pub want_from_local: Vec<String>,
    /// Whether the exchange determined we are fully synced.
    pub is_synced: bool,
}

/// Perform a head exchange: compare local and remote heads to determine
/// what each side needs.
pub fn head_exchange(
    local_head_txids: &HashSet<String>,
    local_directive_ids: &HashSet<String>,
    remote_head_txids: &[String],
    remote_directive_ids: &[String],
) -> ExchangeResult {
    let want_from_remote = compute_want(
        local_head_txids,
        local_directive_ids,
        remote_head_txids,
        remote_directive_ids,
    );

    // The remote will compute their own wants — we just tell them our heads.
    // But for testing, we can compute what they'd want from us.
    let remote_txid_set: HashSet<&str> = remote_head_txids.iter().map(|s| s.as_str()).collect();
    let remote_dir_set: HashSet<&str> = remote_directive_ids.iter().map(|s| s.as_str()).collect();

    let mut want_from_local = Vec::new();
    for txid in local_head_txids {
        if !remote_txid_set.contains(txid.as_str()) {
            want_from_local.push(txid.clone());
        }
    }
    for id in local_directive_ids {
        if !remote_dir_set.contains(id.as_str()) {
            want_from_local.push(id.clone());
        }
    }

    let is_synced = want_from_remote.is_empty() && want_from_local.is_empty();

    ExchangeResult {
        want_from_remote,
        want_from_local,
        is_synced,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_compute_want_empty_local() {
        let local = HashSet::new();
        let want = compute_want(
            &local,
            &HashSet::new(),
            &["tx1".to_owned(), "tx2".to_owned()],
            &[],
        );
        assert_eq!(want.len(), 2);
    }

    #[test]
    fn test_compute_want_all_present() {
        let local = set(&["tx1", "tx2"]);
        let want = compute_want(
            &local,
            &HashSet::new(),
            &["tx1".to_owned(), "tx2".to_owned()],
            &[],
        );
        assert!(want.is_empty(), "All present → nothing to want");
    }

    #[test]
    fn test_compute_want_partial_overlap() {
        let local = set(&["tx1", "tx3"]);
        let want = compute_want(
            &local,
            &HashSet::new(),
            &["tx1".to_owned(), "tx2".to_owned(), "tx3".to_owned()],
            &[],
        );
        assert_eq!(want, vec!["tx2"]);
    }

    #[test]
    fn test_compute_want_includes_directive_ids() {
        let local_txids = set(&["tx1"]);
        let local_dir = set(&["dir1"]);
        let want = compute_want(
            &local_txids,
            &local_dir,
            &["tx1".to_owned()],
            &["dir1".to_owned(), "dir2".to_owned()],
        );
        assert_eq!(want, vec!["dir2"]);
    }

    #[test]
    fn test_make_have_heads_sorted() {
        let heads = set(&["zzz", "aaa", "mmm"]);
        let msg = make_have_heads(&heads, &HashSet::new());
        match msg {
            WireMessage::HaveHeads { head_txids, .. } => {
                assert_eq!(head_txids, vec!["aaa", "mmm", "zzz"]);
            }
            _ => panic!("Expected HaveHeads"),
        }
    }

    #[test]
    fn test_head_exchange_synced() {
        let local = set(&["tx1", "tx2"]);
        let result = head_exchange(
            &local,
            &HashSet::new(),
            &["tx1".to_owned(), "tx2".to_owned()],
            &[],
        );
        assert!(result.is_synced);
        assert!(result.want_from_remote.is_empty());
        assert!(result.want_from_local.is_empty());
    }

    #[test]
    fn test_head_exchange_local_behind() {
        let local = set(&["tx1"]);
        let result = head_exchange(
            &local,
            &HashSet::new(),
            &["tx1".to_owned(), "tx2".to_owned()],
            &[],
        );
        assert!(!result.is_synced);
        assert_eq!(result.want_from_remote, vec!["tx2"]);
        assert!(result.want_from_local.is_empty());
    }

    #[test]
    fn test_head_exchange_remote_behind() {
        let local = set(&["tx1", "tx2", "tx3"]);
        let result = head_exchange(&local, &HashSet::new(), &["tx1".to_owned()], &[]);
        assert!(!result.is_synced);
        assert!(result.want_from_remote.is_empty());
        assert_eq!(result.want_from_local.len(), 2); // tx2, tx3
    }

    #[test]
    fn test_head_exchange_both_have_unique() {
        let local = set(&["tx1", "tx2"]);
        let result = head_exchange(
            &local,
            &HashSet::new(),
            &["tx2".to_owned(), "tx3".to_owned()],
            &[],
        );
        assert!(!result.is_synced);
        assert_eq!(result.want_from_remote, vec!["tx3"]);
        assert_eq!(result.want_from_local, vec!["tx1"]);
    }
}
