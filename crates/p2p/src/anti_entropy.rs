//! Anti-entropy protocol (§3.4).
//!
//! On connect and every `antiEntropyIntervalMilliseconds`, peers exchange
//! heads + non-transaction ID digests. The lagging peer pulls missing
//! directives until closed.

use std::collections::HashSet;

use crate::protocol::{
    SupplyEntry, WireMessage, MAX_HAVE_HEADS, MAX_SUPPLY_ENTRIES, SUPPLY_FRAME_BUDGET_BYTES,
};

/// Per-entry framing allowance in the `Supply` size estimate (H-02).
///
/// Covers the CBOR map keys, the kind tag, and the length prefixes around each
/// string; generous so the estimate stays an over-approximation of the encoded
/// size, which is what keeps the frame under `MAX_MESSAGE_SIZE`.
const SUPPLY_ENTRY_OVERHEAD_BYTES: usize = 128;

/// Compute which IDs the remote has that we don't (the `want` set).
///
/// Given our local heads and the remote's advertised heads + directive IDs,
/// returns the IDs we should request via a `want` message.
///
/// The remote lists arrive already **form-checked**: T49 made the advert reader
/// (`gl-node`'s `read_have_heads_advert`) refuse a page carrying anything that
/// is not a `protocol::is_content_id` — the rule `openledger-parents` has had
/// since L-29 (M-26, L-53). The check is deliberately there and NOT repeated
/// here: this function would have to *filter*, and a filter would let a
/// malformed advert produce a successful-looking exchange in which the two
/// nodes silently disagree about what was offered. One refusal, at the point
/// where the bytes are first retained, is the stronger property.
pub fn compute_want(
    local_txids: &HashSet<String>,
    local_directive_ids: &HashSet<String>,
    remote_head_txids: &[String],
    remote_directive_ids: &[String],
) -> Vec<String> {
    // L-21: every head txid is also a directive id, so a missing head is
    // advertised in both `remote_head_txids` and `remote_directive_ids` and would
    // be wanted twice; a list that repeats an id doubles up the same way. Dedup
    // the output — preserving first-occurrence order — so each missing id is
    // requested (and later served + re-validated by the peer) exactly once.
    let mut want = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for txid in remote_head_txids {
        if !local_txids.contains(txid) && seen.insert(txid.clone()) {
            want.push(txid.clone());
        }
    }

    for id in remote_directive_ids {
        if !local_directive_ids.contains(id) && seen.insert(id.clone()) {
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

/// Split our local frontier into `have_heads` pages the receiver will accept (H-02).
///
/// `make_have_heads` advertises every id in one frame, which a conforming peer
/// rejects outright once the ledger passes `MAX_HAVE_HEADS` directives — every
/// head exchange then fails and the mesh stops syncing. Each returned page
/// carries at most `MAX_HAVE_HEADS` head txids and at most `MAX_HAVE_HEADS`
/// directive ids; every page but the last has `more: true`.
///
/// Always returns at least one page, so an empty ledger still advertises.
pub fn paginate_have_heads(
    local_head_txids: &HashSet<String>,
    local_directive_ids: &HashSet<String>,
) -> Vec<WireMessage> {
    let mut heads: Vec<String> = local_head_txids.iter().cloned().collect();
    heads.sort();
    let mut directives: Vec<String> = local_directive_ids.iter().cloned().collect();
    directives.sort();

    let page_count = heads
        .len()
        .div_ceil(MAX_HAVE_HEADS)
        .max(directives.len().div_ceil(MAX_HAVE_HEADS))
        .max(1);

    (0..page_count)
        .map(|index| {
            let start = index * MAX_HAVE_HEADS;
            WireMessage::have_heads_page(
                page_slice(&heads, start),
                page_slice(&directives, start),
                index + 1 < page_count,
            )
        })
        .collect()
}

/// One `MAX_HAVE_HEADS`-sized window of `ids` starting at `start` (empty past the end).
fn page_slice(ids: &[String], start: usize) -> Vec<String> {
    if start >= ids.len() {
        return Vec::new();
    }
    ids[start..(start + MAX_HAVE_HEADS).min(ids.len())].to_vec()
}

/// Estimated encoded size of one supply entry (H-02). An over-approximation.
fn estimated_entry_bytes(entry: &SupplyEntry) -> usize {
    let envelope: usize = entry
        .envelope
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum();
    entry
        .economic_bean
        .len()
        .saturating_add(envelope)
        .saturating_add(entry.id.len())
        .saturating_add(SUPPLY_ENTRY_OVERHEAD_BYTES)
}

/// Trim a supply batch to a prefix the receiver will accept (H-02).
///
/// Answering a `Want` with everything it asked for violates both receive-side
/// caps: `MAX_SUPPLY_ENTRIES` (a 1024-id `Want` cannot be answered in one
/// `Supply`) and `MAX_MESSAGE_SIZE` (~17 max-size entries overflow the frame).
/// Entries past either bound are dropped; the requester re-`Want`s whatever it
/// did not receive, so truncation costs a round trip rather than correctness.
pub fn truncate_supply(entries: Vec<SupplyEntry>) -> WireMessage {
    let mut used = 0usize;
    let mut kept: Vec<SupplyEntry> = Vec::new();
    for entry in entries {
        if kept.len() >= MAX_SUPPLY_ENTRIES {
            break;
        }
        let size = estimated_entry_bytes(&entry);
        if used.saturating_add(size) > SUPPLY_FRAME_BUDGET_BYTES {
            break;
        }
        used += size;
        kept.push(entry);
    }
    WireMessage::supply(kept)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DirectiveKind, MAX_MESSAGE_SIZE};
    use std::collections::BTreeMap;

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// `count` distinct 64-hex ids, the shape real content ids have.
    fn hex_ids(count: usize) -> HashSet<String> {
        (0..count).map(|index| format!("{index:064x}")).collect()
    }

    fn sorted(ids: &HashSet<String>) -> Vec<String> {
        let mut sorted: Vec<String> = ids.iter().cloned().collect();
        sorted.sort();
        sorted
    }

    fn as_page(message: &WireMessage) -> (&[String], &[String], bool) {
        match message {
            WireMessage::HaveHeads {
                head_txids,
                directive_ids,
                more,
                ..
            } => (head_txids, directive_ids, *more),
            other => panic!("expected HaveHeads, got {other:?}"),
        }
    }

    fn as_entries(message: &WireMessage) -> &[SupplyEntry] {
        match message {
            WireMessage::Supply { entries, .. } => entries,
            other => panic!("expected Supply, got {other:?}"),
        }
    }

    /// Assert a frame is one the receive path accepts (H-02).
    fn assert_frameable(message: &WireMessage) {
        let wire = message.to_wire().expect("frame must encode");
        assert!(wire.len() <= 4 + MAX_MESSAGE_SIZE as usize);
        WireMessage::decode_checked(&wire[4..]).expect("frame must decode");
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
    fn test_compute_want_dedups_head_also_in_directives() {
        // L-21: every head txid is also a directive id, so a missing head is
        // advertised in both lists. It must be wanted EXACTLY once.
        let want = compute_want(
            &HashSet::new(),
            &HashSet::new(),
            &["tx1".to_owned()],
            &["tx1".to_owned(), "dir2".to_owned()],
        );
        assert_eq!(want, vec!["tx1", "dir2"], "the shared id collapses to one");
    }

    #[test]
    fn test_compute_want_dedups_within_list() {
        // A single list that repeats an id collapses to one want too, in
        // first-occurrence order.
        let want = compute_want(
            &HashSet::new(),
            &HashSet::new(),
            &["tx1".to_owned(), "tx1".to_owned(), "tx2".to_owned()],
            &["dir1".to_owned(), "dir1".to_owned()],
        );
        assert_eq!(want, vec!["tx1", "tx2", "dir1"]);
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

    // ── H-02: have_heads pagination ──────────────────────────────────────

    #[test]
    fn test_paginate_have_heads_empty_still_advertises() {
        let pages = paginate_have_heads(&HashSet::new(), &HashSet::new());
        assert_eq!(pages.len(), 1);
        let (heads, directives, more) = as_page(&pages[0]);
        assert!(heads.is_empty());
        assert!(directives.is_empty());
        assert!(!more);
        assert_frameable(&pages[0]);
    }

    #[test]
    fn test_paginate_have_heads_single_id() {
        let ids = hex_ids(1);
        let pages = paginate_have_heads(&ids, &ids);
        assert_eq!(pages.len(), 1);
        let (heads, directives, more) = as_page(&pages[0]);
        assert_eq!(heads.len(), 1);
        assert_eq!(directives.len(), 1);
        assert!(!more);
    }

    #[test]
    fn test_paginate_have_heads_exactly_at_cap() {
        let ids = hex_ids(MAX_HAVE_HEADS);
        let pages = paginate_have_heads(&ids, &ids);
        assert_eq!(pages.len(), 1, "a full page must not spill into a second");
        let (heads, directives, more) = as_page(&pages[0]);
        assert_eq!(heads.len(), MAX_HAVE_HEADS);
        assert_eq!(directives.len(), MAX_HAVE_HEADS);
        assert!(!more);
        assert_frameable(&pages[0]);
    }

    #[test]
    fn test_paginate_have_heads_one_past_cap() {
        let ids = hex_ids(MAX_HAVE_HEADS + 1);
        let pages = paginate_have_heads(&ids, &ids);
        assert_eq!(pages.len(), 2);
        assert_eq!(as_page(&pages[0]).0.len(), MAX_HAVE_HEADS);
        assert!(as_page(&pages[0]).2, "non-final page sets more");
        assert_eq!(as_page(&pages[1]).0.len(), 1);
        assert!(!as_page(&pages[1]).2, "final page clears more");
    }

    #[test]
    fn test_paginate_have_heads_ten_thousand_ids() {
        let ids = hex_ids(10_000);
        let pages = paginate_have_heads(&ids, &ids);
        assert_eq!(pages.len(), 3);
        let sizes: Vec<usize> = pages.iter().map(|page| as_page(page).0.len()).collect();
        assert_eq!(sizes, vec![MAX_HAVE_HEADS, MAX_HAVE_HEADS, 1808]);
        let flags: Vec<bool> = pages.iter().map(|page| as_page(page).2).collect();
        assert_eq!(flags, vec![true, true, false]);
        for page in &pages {
            assert_frameable(page);
        }
    }

    #[test]
    fn test_paginate_have_heads_preserves_content_in_order() {
        let heads = hex_ids(5_000);
        let directives = hex_ids(9_000);
        let pages = paginate_have_heads(&heads, &directives);

        let mut head_union: Vec<String> = Vec::new();
        let mut directive_union: Vec<String> = Vec::new();
        for page in &pages {
            let (page_heads, page_directives, _) = as_page(page);
            head_union.extend_from_slice(page_heads);
            directive_union.extend_from_slice(page_directives);
        }
        assert_eq!(head_union, sorted(&heads));
        assert_eq!(directive_union, sorted(&directives));
    }

    #[test]
    fn test_paginate_have_heads_uneven_list_lengths() {
        // Directives outnumber heads by two pages; the short list simply runs dry.
        let heads = hex_ids(10);
        let directives = hex_ids(MAX_HAVE_HEADS * 2 + 5);
        let pages = paginate_have_heads(&heads, &directives);
        assert_eq!(pages.len(), 3);
        assert_eq!(as_page(&pages[0]).0.len(), 10);
        assert!(as_page(&pages[1]).0.is_empty());
        assert!(as_page(&pages[2]).0.is_empty());
        assert_eq!(as_page(&pages[2]).1.len(), 5);
    }

    // ── H-02: supply truncation ──────────────────────────────────────────

    fn supply_entry(index: usize, bean_bytes: usize) -> SupplyEntry {
        SupplyEntry {
            id: format!("{index:064x}"),
            kind: DirectiveKind::Open,
            economic_bean: "x".repeat(bean_bytes),
            envelope: BTreeMap::from([("openledger-author".to_owned(), "peer-1".to_owned())]),
        }
    }

    #[test]
    fn test_truncate_supply_under_both_caps_is_untouched() {
        let entries: Vec<SupplyEntry> = (0..10).map(|index| supply_entry(index, 64)).collect();
        let message = truncate_supply(entries.clone());
        assert_eq!(as_entries(&message), entries.as_slice());
        assert_frameable(&message);
    }

    #[test]
    fn test_truncate_supply_enforces_entry_cap() {
        let entries: Vec<SupplyEntry> = (0..MAX_SUPPLY_ENTRIES * 4)
            .map(|index| supply_entry(index, 32))
            .collect();
        let message = truncate_supply(entries.clone());
        let kept = as_entries(&message);
        assert_eq!(kept.len(), MAX_SUPPLY_ENTRIES);
        assert_eq!(kept, &entries[..MAX_SUPPLY_ENTRIES], "keeps a prefix");
        assert_frameable(&message);
    }

    /// The finding's worst case: ~17 max-size (1 MiB) entries overflow the frame.
    #[test]
    fn test_truncate_supply_enforces_byte_budget() {
        let entries: Vec<SupplyEntry> = (0..20)
            .map(|index| supply_entry(index, 1024 * 1024))
            .collect();
        let message = truncate_supply(entries);
        let kept = as_entries(&message);
        assert!(
            kept.len() < 20,
            "20 one-MiB entries must not all be framed, kept {}",
            kept.len()
        );
        assert!(!kept.is_empty(), "1 MiB entries fit individually");
        assert!(kept.len() <= MAX_SUPPLY_ENTRIES);
        let wire = message.to_wire().expect("truncated frame must encode");
        assert!(
            wire.len() <= 4 + MAX_MESSAGE_SIZE as usize,
            "frame is {} bytes",
            wire.len()
        );
        WireMessage::decode_checked(&wire[4..]).expect("truncated frame must decode");
    }

    #[test]
    fn test_truncate_supply_drops_entry_larger_than_the_whole_budget() {
        // Cannot ever be framed, so it is filtered rather than emitted.
        let message = truncate_supply(vec![supply_entry(0, SUPPLY_FRAME_BUDGET_BYTES + 1)]);
        assert!(as_entries(&message).is_empty());
    }
}
