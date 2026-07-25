//! Wire protocol types for §3.4.1 (anti-entropy + gossip).
//!
//! All messages are CBOR-encoded with `uint32_be length || cbor_body`.
//! Every message includes `"v": 1`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Protocol version. Unknown versions → close the stream.
pub const WIRE_VERSION: u64 = 1;

/// ALPN for the anti-entropy protocol.
pub const ANTI_ENTROPY_ALPN: &[u8] = b"openledger/anti-entropy/1";

/// Maximum message size (16 MiB per §3.4.1).
pub const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

// ─── Message types ───────────────────────────────────────────────────────────

/// A wire protocol message (§3.4.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum WireMessage {
    /// Gossip/push hint for a new directive.
    #[serde(rename = "announce")]
    Announce {
        v: u64,
        id: String,
        kind: DirectiveKind,
    },

    /// Advertise the local DAG frontier.
    #[serde(rename = "have_heads")]
    HaveHeads {
        v: u64,
        head_txids: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        directive_ids: Vec<String>,
    },

    /// Request missing directives by ID.
    #[serde(rename = "want")]
    Want {
        v: u64,
        ids: Vec<String>,
    },

    /// Supply requested directives.
    #[serde(rename = "supply")]
    Supply {
        v: u64,
        entries: Vec<SupplyEntry>,
    },
}

/// The kind of directive being announced or supplied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DirectiveKind {
    Transaction,
    Open,
    Close,
    Commodity,
    Pad,
    Balance,
    Note,
    Document,
    Event,
    Price,
}

/// A single entry in a `supply` message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupplyEntry {
    pub id: String,
    pub kind: DirectiveKind,
    /// Economic canonical text (without envelope metadata).
    pub economic_bean: String,
    /// Envelope metadata (`openledger-*` key-value pairs).
    pub envelope: BTreeMap<String, String>,
}

impl WireMessage {
    /// Create an announce message.
    pub fn announce(id: String, kind: DirectiveKind) -> Self {
        WireMessage::Announce {
            v: WIRE_VERSION,
            id,
            kind,
        }
    }

    /// Create a have_heads message.
    pub fn have_heads(head_txids: Vec<String>, directive_ids: Vec<String>) -> Self {
        WireMessage::HaveHeads {
            v: WIRE_VERSION,
            head_txids,
            directive_ids,
        }
    }

    /// Create a want message.
    pub fn want(ids: Vec<String>) -> Self {
        WireMessage::Want {
            v: WIRE_VERSION,
            ids,
        }
    }

    /// Create a supply message.
    pub fn supply(entries: Vec<SupplyEntry>) -> Self {
        WireMessage::Supply {
            v: WIRE_VERSION,
            entries,
        }
    }

    /// Get the protocol version from any message.
    pub fn version(&self) -> u64 {
        match self {
            WireMessage::Announce { v, .. }
            | WireMessage::HaveHeads { v, .. }
            | WireMessage::Want { v, .. }
            | WireMessage::Supply { v, .. } => *v,
        }
    }

    /// Encode to CBOR bytes (without length prefix).
    pub fn to_cbor(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        serde_cbor::to_vec(self)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self, serde_cbor::Error> {
        serde_cbor::from_slice(data)
    }

    /// Encode with the length-prefixed wire format: `uint32_be || cbor_body`.
    pub fn to_wire(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        let cbor = self.to_cbor()?;
        let len = cbor.len() as u32;
        let mut buf = Vec::with_capacity(4 + cbor.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&cbor);
        Ok(buf)
    }

    /// Decode from the length-prefixed wire format.
    pub fn from_wire(data: &[u8]) -> Result<(Self, usize), WireError> {
        if data.len() < 4 {
            return Err(WireError::InsufficientData);
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if len > MAX_MESSAGE_SIZE as usize {
            return Err(WireError::MessageTooLarge(len));
        }
        if data.len() < 4 + len {
            return Err(WireError::InsufficientData);
        }
        let msg = Self::from_cbor(&data[4..4 + len])
            .map_err(|e| WireError::CborDecode(e.to_string()))?;
        if msg.version() != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion(msg.version()));
        }
        Ok((msg, 4 + len))
    }
}

/// Wire protocol errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    InsufficientData,
    MessageTooLarge(usize),
    CborDecode(String),
    UnsupportedVersion(u64),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::InsufficientData => write!(f, "Insufficient data for wire message"),
            WireError::MessageTooLarge(len) => {
                write!(f, "Message too large: {len} bytes (max {MAX_MESSAGE_SIZE})")
            }
            WireError::CborDecode(e) => write!(f, "CBOR decode error: {e}"),
            WireError::UnsupportedVersion(v) => {
                write!(f, "Unsupported wire version: {v} (expected {WIRE_VERSION})")
            }
        }
    }
}

impl std::error::Error for WireError {}

// ─── Directive kind conversion ───────────────────────────────────────────────

impl DirectiveKind {
    /// Map from a ledger Directive to its wire kind.
    pub fn from_directive(directive: &ledger::model::Directive) -> Self {
        match directive {
            ledger::model::Directive::Transaction(_) => DirectiveKind::Transaction,
            ledger::model::Directive::Open(_) => DirectiveKind::Open,
            ledger::model::Directive::Close(_) => DirectiveKind::Close,
            ledger::model::Directive::Commodity(_) => DirectiveKind::Commodity,
            ledger::model::Directive::Pad(_) => DirectiveKind::Pad,
            ledger::model::Directive::Balance(_) => DirectiveKind::Balance,
            ledger::model::Directive::Note(_) => DirectiveKind::Note,
            ledger::model::Directive::Document(_) => DirectiveKind::Document,
            ledger::model::Directive::Event(_) => DirectiveKind::Event,
            ledger::model::Directive::Price(_) => DirectiveKind::Price,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_announce_roundtrip() {
        let msg = WireMessage::announce("abc123".to_owned(), DirectiveKind::Transaction);
        let cbor = msg.to_cbor().unwrap();
        let decoded = WireMessage::from_cbor(&cbor).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_have_heads_roundtrip() {
        let msg = WireMessage::have_heads(
            vec!["tx1".to_owned(), "tx2".to_owned()],
            vec!["dir1".to_owned()],
        );
        let cbor = msg.to_cbor().unwrap();
        let decoded = WireMessage::from_cbor(&cbor).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_want_roundtrip() {
        let msg = WireMessage::want(vec!["id1".to_owned(), "id2".to_owned()]);
        let cbor = msg.to_cbor().unwrap();
        let decoded = WireMessage::from_cbor(&cbor).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_supply_roundtrip() {
        let entry = SupplyEntry {
            id: "txid123".to_owned(),
            kind: DirectiveKind::Transaction,
            economic_bean: "2024-01-15 * \"Test\"\n  Assets:Cash 100 USD\n  Equity:Opening -100 USD".to_owned(),
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "peer-1".to_owned()),
                ("openledger-lamport".to_owned(), "1".to_owned()),
            ]),
        };
        let msg = WireMessage::supply(vec![entry]);
        let cbor = msg.to_cbor().unwrap();
        let decoded = WireMessage::from_cbor(&cbor).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_wire_format_roundtrip() {
        let msg = WireMessage::announce("test".to_owned(), DirectiveKind::Open);
        let wire = msg.to_wire().unwrap();

        // First 4 bytes = length.
        let len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        assert_eq!(wire.len(), 4 + len);

        let (decoded, consumed) = WireMessage::from_wire(&wire).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn test_wire_insufficient_data() {
        let result = WireMessage::from_wire(&[0, 0, 0]);
        assert_eq!(result.unwrap_err(), WireError::InsufficientData);
    }

    #[test]
    fn test_wire_message_too_large() {
        // Claim a huge length.
        let data = [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0];
        let result = WireMessage::from_wire(&data);
        assert!(matches!(result, Err(WireError::MessageTooLarge(_))));
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let msg = WireMessage::Announce {
            v: 99,
            id: "test".to_owned(),
            kind: DirectiveKind::Transaction,
        };
        let wire = msg.to_wire().unwrap();
        let result = WireMessage::from_wire(&wire);
        assert_eq!(result.unwrap_err(), WireError::UnsupportedVersion(99));
    }

    #[test]
    fn test_version_accessor() {
        assert_eq!(
            WireMessage::announce("a".to_owned(), DirectiveKind::Open).version(),
            1
        );
        assert_eq!(WireMessage::want(vec![]).version(), 1);
        assert_eq!(WireMessage::supply(vec![]).version(), 1);
    }

    #[test]
    fn test_directive_kind_mapping() {
        use ledger::model::*;
        let open = Directive::Open(Open {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            account: "Assets:Cash".to_owned(),
            currencies: vec![],
            metadata: BTreeMap::new(),
        });
        assert_eq!(DirectiveKind::from_directive(&open), DirectiveKind::Open);
    }
}
