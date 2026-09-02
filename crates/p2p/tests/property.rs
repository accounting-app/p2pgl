//! Property / fuzz harness (T17): malformed peer input must never panic.
//!
//! `decode_checked` is the entry point for bytes off the wire (length framing +
//! CBOR); `validate_supply_entry` runs the economic body and envelope of a
//! supplied directive. Both face hostile input from allowlisted-but-malicious
//! peers and must return Ok/Err, never panic. A panic here fails the test.

use std::collections::BTreeMap;

use p2p::protocol::{DirectiveKind, SupplyEntry, WireMessage};
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
