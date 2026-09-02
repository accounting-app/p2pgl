//! Property / fuzz harness (T17): malformed peer input must never panic.
//!
//! `decode_checked` is the entry point for bytes off the wire (length framing +
//! CBOR); `validate_supply_entry` runs the economic body and envelope of a
//! supplied directive. Both face hostile input from allowlisted-but-malicious
//! peers and must return Ok/Err, never panic. A panic here fails the test.

use std::collections::{BTreeMap, HashSet};

use p2p::anti_entropy::{paginate_have_heads, truncate_supply};
use p2p::protocol::{
    DirectiveKind, SupplyEntry, WireMessage, MAX_HAVE_HEADS, MAX_MESSAGE_SIZE, MAX_SUPPLY_ENTRIES,
};
use p2p::union_merge::validate_supply_entry;
use proptest::prelude::*;

fn any_kind() -> impl Strategy<Value = DirectiveKind> {
    prop_oneof![
        Just(DirectiveKind::Transaction),
        Just(DirectiveKind::Open),
        Just(DirectiveKind::Close),
        Just(DirectiveKind::Price),
    ]
}

proptest! {
    // Arbitrary bytes (malformed framing / CBOR bombs / truncated payloads) must
    // decode to Ok/Err, never panic or over-allocate into a crash.
    #[test]
    fn wire_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = WireMessage::decode_checked(&bytes);
    }

    // Arbitrary supply entries (untrusted economic body + envelope) must validate
    // to Ok/Err, never panic — exercises parse, content-hash, and the envelope /
    // parent-count caps (T5).
    #[test]
    fn validate_supply_entry_never_panics(
        id in "[0-9a-f]{0,80}",
        kind in any_kind(),
        economic_bean in "(?s).{0,2048}",
        parents in "(?s).{0,4096}",
        lamport in "(?s).{0,32}",
        author in "(?s).{0,80}",
    ) {
        let mut envelope = BTreeMap::new();
        envelope.insert("openledger-author".to_owned(), author);
        envelope.insert("openledger-lamport".to_owned(), lamport);
        envelope.insert("openledger-parents".to_owned(), parents);
        let entry = SupplyEntry {
            id,
            kind,
            economic_bean,
            envelope,
        };
        let _ = validate_supply_entry(&entry);
    }
}

// ─── H-02: senders must never emit a frame their own receivers reject ────────

/// Round-trip one frame exactly as the wire path does: encode, strip the 4-byte
/// length prefix, and run the receive-side gate over the body.
fn assert_frame_is_acceptable(message: &WireMessage) {
    let wire = message
        .to_wire()
        .unwrap_or_else(|error| panic!("sender produced an unframeable message: {error}"));
    assert_eq!(
        u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize,
        wire.len() - 4
    );
    assert!(wire.len() - 4 <= MAX_MESSAGE_SIZE as usize);
    WireMessage::decode_checked(&wire[4..])
        .unwrap_or_else(|error| panic!("receiver rejected our own frame: {error}"));
}

/// Content ids are 64-hex; derive them from random u64s so generation stays cheap
/// at the ten-thousand-id sizes this property needs.
fn id_set() -> impl Strategy<Value = HashSet<String>> {
    prop::collection::vec(any::<u64>(), 0..=10_000).prop_map(|values| {
        values
            .into_iter()
            .map(|value| format!("{value:064x}"))
            .collect()
    })
}

/// Filler of roughly `target_bytes` bytes, built from a repeated unit so
/// multi-byte units keep byte length and char count distinct.
fn filler(unit: &str, target_bytes: usize) -> String {
    unit.repeat(target_bytes.div_ceil(unit.len()))
}

fn supply_entry_strategy(max_bean_bytes: usize) -> impl Strategy<Value = SupplyEntry> {
    (
        any::<u64>(),
        any_kind(),
        0..=max_bean_bytes,
        prop::sample::select(vec!["a", "xy", "é", "漢字", "\u{1f600}"]),
        0usize..=512,
    )
        .prop_map(
            |(seed, kind, bean_bytes, unit, envelope_bytes)| SupplyEntry {
                id: format!("{seed:064x}"),
                kind,
                economic_bean: filler(unit, bean_bytes),
                envelope: BTreeMap::from([
                    ("openledger-author".to_owned(), format!("{seed:x}")),
                    ("openledger-parents".to_owned(), filler("f", envelope_bytes)),
                ]),
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    // Every page of an advert of any size must survive the receive-side gate:
    // the id lists are capped per page, and the union is order-preserving.
    #[test]
    fn paginate_have_heads_pages_are_always_decodable(
        heads in id_set(),
        directives in id_set(),
    ) {
        let pages = paginate_have_heads(&heads, &directives);
        prop_assert!(!pages.is_empty(), "an advert is always sent, even when empty");

        let mut head_union: Vec<String> = Vec::new();
        let mut directive_union: Vec<String> = Vec::new();
        for (index, page) in pages.iter().enumerate() {
            assert_frame_is_acceptable(page);
            let WireMessage::HaveHeads { head_txids, directive_ids, more, .. } = page else {
                panic!("paginate_have_heads must produce HaveHeads");
            };
            prop_assert!(head_txids.len() <= MAX_HAVE_HEADS);
            prop_assert!(directive_ids.len() <= MAX_HAVE_HEADS);
            prop_assert_eq!(*more, index + 1 < pages.len());
            head_union.extend(head_txids.iter().cloned());
            directive_union.extend(directive_ids.iter().cloned());
        }

        let mut expected_heads: Vec<String> = heads.into_iter().collect();
        expected_heads.sort();
        let mut expected_directives: Vec<String> = directives.into_iter().collect();
        expected_directives.sort();
        prop_assert_eq!(head_union, expected_heads);
        prop_assert_eq!(directive_union, expected_directives);
    }

    // Whatever a peer asks for, the Supply we answer with must be one we would
    // ourselves accept — both the entry cap and the 16 MiB frame cap.
    #[test]
    fn truncate_supply_output_is_always_decodable(
        entries in prop::collection::vec(supply_entry_strategy(2_000), 0..=600),
    ) {
        let requested = entries.len();
        let message = truncate_supply(entries.clone());
        assert_frame_is_acceptable(&message);
        let WireMessage::Supply { entries: kept, .. } = &message else {
            panic!("truncate_supply must produce Supply");
        };
        prop_assert!(kept.len() <= MAX_SUPPLY_ENTRIES);
        prop_assert!(kept.len() <= requested);
        // Truncation keeps a prefix, so the client can tell what is still missing.
        prop_assert_eq!(kept.as_slice(), &entries[..kept.len()]);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    // The finding's byte case: a handful of near-maximum (1 MiB) economic bodies
    // blows the frame cap long before the 256-entry cap is reached.
    #[test]
    fn truncate_supply_handles_near_maximum_entries(
        entries in prop::collection::vec(supply_entry_strategy(1_048_576), 20..=20),
    ) {
        let message = truncate_supply(entries);
        assert_frame_is_acceptable(&message);
    }
}
