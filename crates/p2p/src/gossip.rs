//! Gossip handler — broadcast and receive directives via iroh-gossip.
//!
//! Wraps iroh-gossip subscription with OpenLedger message types.
//! The handler converts between domain directives and wire protocol messages.

use bytes::Bytes;
use std::collections::BTreeMap;

use ledger::hash::compute_content_id;
use ledger::model::Directive;
use ledger::serialize::economic_canonical_serialize;

use crate::protocol::{DirectiveKind, SupplyEntry, WireCodec, WireMessage};

/// Create an announce message for a directive that was just inserted locally.
pub fn make_announce(directive: &Directive) -> WireMessage {
    let id = compute_content_id(directive);
    let kind = DirectiveKind::from_directive(directive);
    WireMessage::announce(id, kind)
}

/// Create a supply entry for a directive (for responding to `want` requests).
pub fn make_supply_entry(directive: &Directive) -> SupplyEntry {
    let id = compute_content_id(directive);
    let kind = DirectiveKind::from_directive(directive);
    let economic_bean = economic_canonical_serialize(directive);

    // Extract envelope metadata (the closed `ENVELOPE_KEYS` set, T21 follow-up).
    let envelope = extract_envelope(directive);

    SupplyEntry {
        id,
        kind,
        economic_bean,
        envelope,
    }
}

/// Encode a gossip broadcast message as bytes (for iroh-gossip sender).
pub fn encode_broadcast(msg: &WireMessage) -> Result<Bytes, String> {
    let cbor = msg.to_cbor()?;
    Ok(Bytes::from(cbor))
}

/// Decode a gossip message from bytes (from iroh-gossip receiver).
///
/// Enforces the 16 MiB cap and `v == 1` (H-7). Gossip is already framed by
/// iroh-gossip, so this is CBOR-only (no extra length prefix).
pub fn decode_broadcast(data: &[u8]) -> Result<WireMessage, String> {
    decode_broadcast_in(WireCodec::V1, data)
}

/// [`encode_broadcast`] in `codec` (Format v2, Facet C): a wire-v2 node
/// gossips on its own topic, in its own encoding.
pub fn encode_broadcast_in(codec: WireCodec, msg: &WireMessage) -> Result<Bytes, String> {
    Ok(Bytes::from(msg.to_cbor_in(codec)?))
}

/// [`decode_broadcast`] in `codec`: the same gates as the anti-entropy path.
pub fn decode_broadcast_in(codec: WireCodec, data: &[u8]) -> Result<WireMessage, String> {
    WireMessage::decode_checked_in(codec, data).map_err(|error| error.to_string())
}

/// Extract envelope metadata from a directive, for the wire.
///
/// Filtered to [`ledger::service::ENVELOPE_KEYS`] — the same closed set every
/// ingest path enforces — rather than to the `openledger-` prefix (T21
/// follow-up). Promotion of a stray key is already unreachable: H-06's
/// `validate_body_envelope_keys` runs on the local append path, on reconcile and
/// on both halves of the remote path, so no directive holding one can reach a
/// DAG in the first place, and `test_body_smuggled_key_poisons_the_next_hop_on_re_serve`
/// pins what would happen if one did.
///
/// This is belt-and-braces on principle: the serve side is where a directive
/// stops being our problem and becomes the next hop's, and "whatever happens to
/// carry the prefix" is the wrong rule to apply at that boundary. Reading the
/// closed set from `ledger` rather than restating it here also means the wire
/// set cannot drift from the stamped set — the same single-sourcing
/// `ALLOWED_ENVELOPE_KEYS` already uses on the receive side.
fn extract_envelope(directive: &Directive) -> BTreeMap<String, String> {
    let metadata = match directive {
        Directive::Transaction(txn) => &txn.metadata,
        Directive::Open(open) => &open.metadata,
        Directive::Close(close) => &close.metadata,
        Directive::Commodity(c) => &c.metadata,
        Directive::Pad(p) => &p.metadata,
        Directive::Balance(b) => &b.metadata,
        Directive::Note(n) => &n.metadata,
        Directive::Document(d) => &d.metadata,
        Directive::Event(e) => &e.metadata,
        Directive::Price(p) => &p.metadata,
    };

    metadata
        .iter()
        .filter(|(key, _)| ledger::service::ENVELOPE_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use ledger::model::*;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn sample_transaction() -> Directive {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-1".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "1".to_owned());
        metadata.insert("openledger-parents".to_owned(), "".to_owned());
        metadata.insert("custom-key".to_owned(), "should-not-appear".to_owned());

        Directive::Transaction(Transaction {
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            flag: Flag::Complete,
            payee: Some("Test".to_owned()),
            narration: Some("Gossip test".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata,
        })
    }

    #[test]
    fn test_make_announce() {
        let directive = sample_transaction();
        let msg = make_announce(&directive);
        match msg {
            WireMessage::Announce { id, kind, .. } => {
                assert_eq!(id.len(), 64, "Content ID should be 64-char hex");
                assert_eq!(kind, DirectiveKind::Transaction);
            }
            _ => panic!("Expected Announce"),
        }
    }

    #[test]
    fn test_make_supply_entry() {
        let directive = sample_transaction();
        let entry = make_supply_entry(&directive);

        assert_eq!(entry.id.len(), 64);
        assert_eq!(entry.kind, DirectiveKind::Transaction);
        assert!(!entry.economic_bean.is_empty());

        // Envelope should only contain openledger-* keys.
        assert!(entry.envelope.contains_key("openledger-author"));
        assert!(entry.envelope.contains_key("openledger-lamport"));
        assert!(entry.envelope.contains_key("openledger-parents"));
        assert!(
            !entry.envelope.contains_key("custom-key"),
            "Non-openledger keys should be excluded from envelope"
        );
    }

    #[test]
    fn test_broadcast_roundtrip() {
        let directive = sample_transaction();
        let msg = make_announce(&directive);
        let encoded = encode_broadcast(&msg).unwrap();
        let decoded = decode_broadcast(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_supply_content_id_matches_economic_body() {
        let directive = sample_transaction();
        let entry = make_supply_entry(&directive);

        // Verify: hash(economic_bean) == id (§3.4.1 verification rule).
        let computed_id = compute_content_id(&directive);
        assert_eq!(
            entry.id, computed_id,
            "Supply entry id must match hash of economic body"
        );
    }

    /// Format v2, Facet C: an announce round-trips in the wire-v2 encoding,
    /// and neither encoding reads the other's bytes.
    #[test]
    fn wire_v2_broadcast_roundtrips_and_is_not_v1() {
        let msg = WireMessage::announce("a".repeat(64), DirectiveKind::Transaction);
        let v2 = encode_broadcast_in(WireCodec::V2, &msg).unwrap();
        assert_eq!(decode_broadcast_in(WireCodec::V2, &v2).unwrap(), msg);
        assert!(decode_broadcast(&v2).is_err());
        let v1 = encode_broadcast(&msg).unwrap();
        assert!(decode_broadcast_in(WireCodec::V2, &v1).is_err());
    }

    #[test]
    fn test_decode_broadcast_rejects_unsupported_version() {
        let msg = WireMessage::Announce {
            v: 2,
            id: "abc".to_owned(),
            kind: DirectiveKind::Transaction,
        };
        let encoded = encode_broadcast(&msg).unwrap();
        let error = decode_broadcast(&encoded).unwrap_err();
        assert!(error.contains("Unsupported version") || error.contains("version"));
    }
}
