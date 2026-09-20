//! Wire protocol types for §3.4.1 (anti-entropy + gossip).
//!
//! All messages are CBOR-encoded with `uint32_be length || cbor_body`.
//! Every message includes `"v": 1`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::cbor_scan::{self, ArrayBound, CborScanError, ScanOutcome};

/// Protocol version. Unknown versions → close the stream.
pub const WIRE_VERSION: u64 = 1;

/// ALPN for the anti-entropy protocol.
pub const ANTI_ENTROPY_ALPN: &[u8] = b"openledger/anti-entropy/1";

/// Maximum message size (16 MiB per §3.4.1).
pub const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Maximum `Supply.entries` in one message (H-2).
pub const MAX_SUPPLY_ENTRIES: usize = 256;

/// Maximum `Want.ids` in one message (H-2).
pub const MAX_WANT_IDS: usize = 1024;

/// Maximum `HaveHeads` id lists in one message (H-2).
pub const MAX_HAVE_HEADS: usize = 4096;

/// Sender-side byte budget for one `Supply` frame (H-02).
///
/// `MAX_SUPPLY_ENTRIES` alone does not bound the frame: 256 entries with a
/// 1 MiB `economic_bean` each is far past `MAX_MESSAGE_SIZE`. Senders fill a
/// `Supply` up to this budget, leaving 1 MiB of headroom under the 16 MiB
/// receive cap for CBOR framing overhead.
pub const SUPPLY_FRAME_BUDGET_BYTES: usize = 15 * 1024 * 1024;

/// CBOR bytes of the `"type": "supply"` map entry that opens a serialized
/// `Supply` frame (M-16).
///
/// `WireMessage` is `#[serde(tag = "type")]` (internally tagged), so serde
/// emits the tag as the FIRST map entry and ciborium encodes each variant as a
/// definite-length map. A `Supply` therefore starts with a one-byte map header
/// (`0xA3` for its 3 fields) immediately followed by these 12 bytes:
/// `text(4) "type"` (`0x64 74 79 70 65`) then `text(6) "supply"`
/// (`0x66 73 75 70 70 6c 79`). The map header byte is intentionally excluded so
/// the discriminator does not depend on a variant's field count — the reader
/// skips byte 0 and compares from byte 1.
///
/// This lets `read_message` (see `anti_entropy_alpn`) recognise a genuine
/// `Supply` from a ~13-byte peek and reject an oversized non-`Supply` frame
/// before allocating or `Content`-buffering its body. The coupling to serde's
/// tag-first, definite-length-map encoding is pinned by
/// `supply_discriminator_pins_wire_format`: if the encoding ever drifts, that
/// test fails loudly.
pub const SUPPLY_TYPE_DISCRIMINATOR: &[u8] = b"\x64type\x66supply";

/// Whether `head` — a frame's leading bytes, or the whole frame — carries the
/// `Supply` discriminator at the one offset serde can put it (M-16).
///
/// The single statement of "the map header occupies byte 0, the tag entry
/// follows it", so the ~13-byte peek gate in `anti_entropy_alpn::read_frame` and
/// the T43 pre-scan gate in [`WireMessage::decode_checked`] cannot drift about
/// where the discriminator lives. A `head` too short to hold it is not a
/// `Supply`.
///
/// This answers "does this frame CLAIM to be a `Supply`", which is exactly the
/// question both gates need — a claim is enough to decide which bound applies,
/// and the ordinary decode still has to agree afterwards.
pub fn carries_supply_discriminator(head: &[u8]) -> bool {
    head.get(1..1 + SUPPLY_TYPE_DISCRIMINATOR.len()) == Some(SUPPLY_TYPE_DISCRIMINATOR)
}

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
        /// More pages of this advert follow (H-02). A ledger with more than
        /// `MAX_HAVE_HEADS` ids cannot be advertised in one frame, so the
        /// advert is paginated. Absent on the wire when `false`, and defaulted
        /// to `false` on decode, so both directions stay compatible with peers
        /// that predate the field.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        more: bool,
    },

    /// Request missing directives by ID.
    #[serde(rename = "want")]
    Want { v: u64, ids: Vec<String> },

    /// Supply requested directives.
    #[serde(rename = "supply")]
    Supply { v: u64, entries: Vec<SupplyEntry> },
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

    /// Create a have_heads message (single, final page).
    pub fn have_heads(head_txids: Vec<String>, directive_ids: Vec<String>) -> Self {
        Self::have_heads_page(head_txids, directive_ids, false)
    }

    /// Create one page of a paginated have_heads advert (H-02).
    ///
    /// `more` is `true` on every page but the last.
    pub fn have_heads_page(
        head_txids: Vec<String>,
        directive_ids: Vec<String>,
        more: bool,
    ) -> Self {
        WireMessage::HaveHeads {
            v: WIRE_VERSION,
            head_txids,
            directive_ids,
            more,
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

    /// The post-decode cardinality caps (H-2).
    ///
    /// Still the authority on a DECODED message — `to_wire` senders and any
    /// caller holding a `WireMessage` reach it — but on the inbound path
    /// [`prescan_frame`] has already enforced the same three caps against the
    /// wire bytes (T43, T43b), so by the time a frame gets here the check is a
    /// restatement rather than the first line of defence. The `kind` strings are
    /// shared with `NON_SUPPLY_ARRAY_BOUNDS` so both points refuse identically.
    fn check_cardinality(&self) -> Result<(), WireError> {
        match self {
            WireMessage::Supply { entries, .. } if entries.len() > MAX_SUPPLY_ENTRIES => {
                Err(WireError::BatchTooLarge {
                    kind: "supply",
                    count: entries.len(),
                    max: MAX_SUPPLY_ENTRIES,
                })
            }
            WireMessage::Want { ids, .. } if ids.len() > MAX_WANT_IDS => {
                Err(WireError::BatchTooLarge {
                    kind: "want",
                    count: ids.len(),
                    max: MAX_WANT_IDS,
                })
            }
            WireMessage::HaveHeads {
                head_txids,
                directive_ids,
                ..
            } if head_txids.len() > MAX_HAVE_HEADS || directive_ids.len() > MAX_HAVE_HEADS => {
                Err(WireError::BatchTooLarge {
                    kind: "have_heads",
                    count: head_txids.len().max(directive_ids.len()),
                    max: MAX_HAVE_HEADS,
                })
            }
            _ => Ok(()),
        }
    }

    /// Encode to CBOR bytes (without length prefix).
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).map_err(|error| error.to_string())?;
        Ok(buffer)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(data).map_err(|error| error.to_string())
    }

    /// Decode gossip/application CBOR with the same size and version gates as `from_wire` (H-7).
    ///
    /// THE inbound choke point: `from_wire`, `gossip::decode_broadcast` and
    /// `anti_entropy_alpn::read_frame` all arrive here, and nothing on a send
    /// path does. That is why T43's pre-scan is wired in here rather than beside
    /// T26's peek gate in `read_frame` — one placement covers every reader of a
    /// `Supply` frame, including the gossip-side decode that never sees a length
    /// prefix at all. T43b widened the same gate to `Want` and `HaveHeads`
    /// without moving it: see [`prescan_frame`].
    pub fn decode_checked(data: &[u8]) -> Result<Self, WireError> {
        if data.len() > MAX_MESSAGE_SIZE as usize {
            return Err(WireError::MessageTooLarge(data.len()));
        }
        prescan_frame(data)?;
        let message = Self::from_cbor(data).map_err(WireError::CborDecode)?;
        if message.version() != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion(message.version()));
        }
        message.check_cardinality()?;
        Ok(message)
    }

    /// Encode with the length-prefixed wire format: `uint32_be || cbor_body`.
    ///
    /// Fails rather than emitting a frame every conforming receiver must reject
    /// (H-02). Senders are expected to stay under budget by construction — see
    /// `SUPPLY_FRAME_BUDGET_BYTES` and `anti_entropy::paginate_have_heads` —
    /// so this is a backstop, not the primary bound.
    pub fn to_wire(&self) -> Result<Vec<u8>, String> {
        let cbor = self.to_cbor()?;
        if cbor.len() > MAX_MESSAGE_SIZE as usize {
            return Err(format!(
                "wire message is {} bytes (max {MAX_MESSAGE_SIZE})",
                cbor.len()
            ));
        }
        // T41: the cast is explicit about why it cannot lose bits, instead of
        // an `as u32` that silently would. `MAX_MESSAGE_SIZE` is 16 MiB and the
        // check immediately above has already refused anything larger, so the
        // conversion is unreachable-on-failure — but a truncating `as` here
        // would be the worst possible bug to reintroduce: the length prefix
        // would name a fraction of the body, and the receiver would decode a
        // short frame and then resynchronize on the remaining bytes as if they
        // were the next frame. Two things keep that unreachable today — the
        // byte check above, and `MAX_MESSAGE_SIZE` being typed `u32` — and
        // `try_into` states the dependency so that relaxing either one is a
        // loud local panic rather than a silent protocol desync.
        let len: u32 = cbor
            .len()
            .try_into()
            .expect("frame length fits u32: MAX_MESSAGE_SIZE (16 MiB) is checked above");
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
        let message = Self::decode_checked(&data[4..4 + len])?;
        Ok((message, 4 + len))
    }
}

/// Every unbounded-cardinality array a non-`Supply` frame can carry, with the
/// cap it is held to and the `BatchTooLarge` kind that names it (T43b).
///
/// `label` IS the kind string `check_cardinality` reports for the same array, so
/// the pre-decode and post-decode refusals are identical by construction rather
/// than by two string literals that happen to agree today:
/// `Want.ids` → `"want"`, and both of `HaveHeads`' lists → `"have_heads"`.
/// `Announce` carries no array and matches nothing here, which is exactly the
/// tolerance [`cbor_scan::scan_bounded_arrays`] is built for.
///
/// `Supply.entries` is deliberately absent: it has its own stricter path (see
/// [`prescan_supply_entries`]), which requires the key to be present rather than
/// tolerating its absence.
pub(crate) const NON_SUPPLY_ARRAY_BOUNDS: &[ArrayBound] = &[
    ArrayBound {
        key: b"ids",
        max: MAX_WANT_IDS,
        label: "want",
    },
    ArrayBound {
        key: b"head_txids",
        max: MAX_HAVE_HEADS,
        label: "have_heads",
    },
    ArrayBound {
        key: b"directive_ids",
        max: MAX_HAVE_HEADS,
        label: "have_heads",
    },
];

/// Bound every array in a frame BEFORE the buffering decode (T43, T43b).
///
/// `WireMessage` is internally tagged, so serde must `Content`-buffer the whole
/// value tree before it can dispatch on `"type"` — which means
/// `check_cardinality` only ever ran *after* a frame claiming millions of
/// elements had already been materialised at tens of bytes of `Content` per
/// element. The amplification belongs to the enum, not to one variant, so this
/// gate covers all four:
///
/// * a frame carrying the `Supply` discriminator goes to
///   [`prescan_supply_entries`], which requires an `entries` array and bounds it;
/// * every other frame goes to [`cbor_scan::scan_bounded_arrays`] with
///   [`NON_SUPPLY_ARRAY_BOUNDS`], which bounds whichever of `ids`,
///   `head_txids` and `directive_ids` the frame actually carries and tolerates a
///   frame that carries none.
///
/// Either way an over-count is reported as the same [`WireError::BatchTooLarge`]
/// the post-decode cap would have produced, with the same `kind`, because it is
/// the same rule — only enforced earlier — and every caller already classifies
/// it. A scan that cannot *answer* is [`WireError::FramePrescan`] instead.
///
/// See [`crate::cbor_scan`] for the scan's bounds, its element-skip allowance,
/// and why each of its rejections is unreachable for an honest peer.
fn prescan_frame(data: &[u8]) -> Result<(), WireError> {
    if carries_supply_discriminator(data) {
        return prescan_supply_entries(data);
    }
    match cbor_scan::scan_bounded_arrays(data, NON_SUPPLY_ARRAY_BOUNDS)
        .map_err(WireError::FramePrescan)?
    {
        ScanOutcome::WithinBounds => Ok(()),
        ScanOutcome::OverBound {
            label,
            claimed,
            max,
        } => Err(WireError::BatchTooLarge {
            kind: label,
            count: saturating_count(claimed),
            max,
        }),
    }
}

/// The `Supply` arm of [`prescan_frame`] (T43).
///
/// Split out because its contract is genuinely stricter than the general scan's:
/// a `Supply` that carries no `entries` array is malformed and is refused,
/// whereas a frame with no `ids` is just some other variant. T26's peek gate
/// already bounds every non-`Supply` frame's BYTES, so this is the one variant
/// that gate must let through at full size and therefore the one whose element
/// count has to be proven before serde sees it.
fn prescan_supply_entries(data: &[u8]) -> Result<(), WireError> {
    let claimed = cbor_scan::supply_entry_count(data).map_err(WireError::FramePrescan)?;
    if claimed > MAX_SUPPLY_ENTRIES as u64 {
        return Err(WireError::BatchTooLarge {
            kind: "supply",
            count: saturating_count(claimed),
            max: MAX_SUPPLY_ENTRIES,
        });
    }
    Ok(())
}

/// A claimed element count as a `usize`, saturating rather than truncating.
///
/// The count is only ever reported, and a wrapped value would understate the
/// frame in the one message an operator reads to size the attack.
fn saturating_count(claimed: u64) -> usize {
    usize::try_from(claimed).unwrap_or(usize::MAX)
}

/// Wire protocol errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    InsufficientData,
    MessageTooLarge(usize),
    CborDecode(String),
    UnsupportedVersion(u64),
    /// The pre-scan could not cheaply prove a frame's arrays were within their
    /// cardinality caps, so the frame was refused before serde saw it (T43,
    /// widened to every variant by T43b).
    ///
    /// Distinct from [`Self::CborDecode`] on purpose: this is the guard
    /// declining to answer, not ciborium reporting malformed CBOR, and the two
    /// have very different operational meanings in a log.
    FramePrescan(CborScanError),
    BatchTooLarge {
        kind: &'static str,
        count: usize,
        max: usize,
    },
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
            WireError::FramePrescan(error) => {
                write!(f, "frame refused by pre-scan: {error}")
            }
            WireError::BatchTooLarge { kind, count, max } => {
                write!(f, "{kind} batch too large: {count} (max {max})")
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
            economic_bean:
                "2024-01-15 * \"Test\"\n  Assets:Cash 100 USD\n  Equity:Opening -100 USD".to_owned(),
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
    fn test_decode_checked_rejects_oversize() {
        let oversized = vec![0u8; MAX_MESSAGE_SIZE as usize + 1];
        assert!(matches!(
            WireMessage::decode_checked(&oversized),
            Err(WireError::MessageTooLarge(_))
        ));
    }

    #[test]
    fn test_decode_checked_rejects_unsupported_version() {
        let msg = WireMessage::Announce {
            v: 99,
            id: "test".to_owned(),
            kind: DirectiveKind::Transaction,
        };
        let cbor = msg.to_cbor().unwrap();
        assert_eq!(
            WireMessage::decode_checked(&cbor).unwrap_err(),
            WireError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn test_decode_checked_rejects_oversized_supply_batch() {
        let entries = vec![
            SupplyEntry {
                id: "x".to_owned(),
                kind: DirectiveKind::Open,
                economic_bean: "open".to_owned(),
                envelope: BTreeMap::new(),
            };
            MAX_SUPPLY_ENTRIES + 1
        ];
        let msg = WireMessage::supply(entries);
        let cbor = msg.to_cbor().unwrap();
        assert!(matches!(
            WireMessage::decode_checked(&cbor),
            Err(WireError::BatchTooLarge { kind: "supply", .. })
        ));
    }

    /// H-02: `more` is omitted when false, so a paginating peer stays readable
    /// by one that predates the field (and vice versa: it defaults to false).
    #[test]
    fn test_have_heads_more_is_wire_compatible() {
        let msg = WireMessage::have_heads(vec!["tx1".to_owned()], vec!["dir1".to_owned()]);
        let cbor = msg.to_cbor().unwrap();
        assert!(
            !cbor.windows(4).any(|window| window == b"more"),
            "more: false must not appear on the wire"
        );
        assert_eq!(WireMessage::decode_checked(&cbor).unwrap(), msg);

        let paged =
            WireMessage::have_heads_page(vec!["tx1".to_owned()], vec!["dir1".to_owned()], true);
        let cbor = paged.to_cbor().unwrap();
        assert_eq!(WireMessage::decode_checked(&cbor).unwrap(), paged);
    }

    /// H-02: `to_wire` refuses a frame that every receiver would reject.
    #[test]
    fn test_to_wire_rejects_oversized_frame() {
        let entries: Vec<SupplyEntry> = (0..17)
            .map(|index| SupplyEntry {
                id: format!("{index:064x}"),
                kind: DirectiveKind::Open,
                economic_bean: "x".repeat(1024 * 1024),
                envelope: BTreeMap::new(),
            })
            .collect();
        let error = WireMessage::supply(entries).to_wire().unwrap_err();
        assert!(error.contains("max"), "unexpected error: {error}");
    }

    /// M-16: pins the coupling between serde's tag-first, definite-length-map
    /// encoding and `SUPPLY_TYPE_DISCRIMINATOR`. A genuine `Supply` frame carries
    /// the discriminator at byte offset `[1..]` (skipping the map header byte);
    /// every other variant must NOT match at that offset, so the oversized-frame
    /// gate in `read_message` can only ever fast-path a real `Supply`. If the
    /// wire encoding drifts (tag no longer first, indefinite-length map, renamed
    /// variant), this test fails rather than silently defeating the M-16 guard.
    #[test]
    fn supply_discriminator_pins_wire_format() {
        let discriminator = SUPPLY_TYPE_DISCRIMINATOR;
        let range = 1..1 + discriminator.len();

        // A real Supply (with an entry, to exercise the populated shape) matches.
        let supply = WireMessage::supply(vec![SupplyEntry {
            id: "id".to_owned(),
            kind: DirectiveKind::Open,
            economic_bean: "2024-01-01 open Assets:Cash".to_owned(),
            envelope: BTreeMap::new(),
        }]);
        let supply_cbor = supply.to_cbor().unwrap();
        assert_eq!(
            &supply_cbor[range.clone()],
            discriminator,
            "Supply frame must carry the discriminator at [1..] (map header at [0])"
        );
        // An empty Supply matches too — the discriminator is independent of the
        // entry vector.
        let empty_supply = WireMessage::supply(vec![]).to_cbor().unwrap();
        assert_eq!(&empty_supply[range.clone()], discriminator);

        // No non-Supply variant may match at the same offset.
        let non_supply = [
            WireMessage::want(vec!["id".to_owned()]),
            WireMessage::have_heads(vec!["tx".to_owned()], vec!["dir".to_owned()]),
            WireMessage::have_heads_page(vec!["tx".to_owned()], vec![], true),
            WireMessage::announce("id".to_owned(), DirectiveKind::Transaction),
        ];
        for message in non_supply {
            let cbor = message.to_cbor().unwrap();
            assert_ne!(
                &cbor[range.clone()],
                discriminator,
                "non-Supply variant unexpectedly matched the Supply discriminator: {message:?}"
            );
        }
    }

    // ─── T43: full M-16 closure — the pre-decode entry-count gate ────────────

    fn supply_entry(index: usize) -> SupplyEntry {
        SupplyEntry {
            id: format!("{index:064x}"),
            kind: DirectiveKind::Open,
            economic_bean: "2024-01-01 open Assets:Cash USD".to_owned(),
            envelope: BTreeMap::new(),
        }
    }

    /// The `{"type": "supply", "v": 1, "entries": ` prefix exactly as ciborium
    /// emits it, so a crafted frame is a genuine `Supply` up to the point where
    /// `entries_tail` lies about the array.
    fn forged_supply_frame(entries_tail: &[u8]) -> Vec<u8> {
        let mut frame = vec![0xa3];
        frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        frame.extend_from_slice(b"\x61v\x01");
        frame.extend_from_slice(b"\x67entries");
        frame.extend_from_slice(entries_tail);
        frame
    }

    /// An `entries` array header claiming `count` elements, with no element
    /// bytes behind it at all.
    fn entries_header_claiming(count: u32) -> Vec<u8> {
        let mut tail = vec![0x9a];
        tail.extend_from_slice(&count.to_be_bytes());
        tail
    }

    /// The T43 hole, closed: a ~30-byte frame whose `entries` array header
    /// claims ten million elements is refused from the header alone, with no
    /// element bytes present at all — so serde was never handed the buffer.
    ///
    /// The absent body is what makes this a PRE-decode proof rather than a
    /// restatement of the post-decode cap. Before the gate, ciborium would have
    /// run out of input part way through building a ten-million-element
    /// `Vec<Content>` and reported a decode error; the frame is now answered by
    /// `BatchTooLarge` naming the claimed count.
    #[test]
    fn prescan_rejects_a_forged_entry_count_before_serde_sees_the_body() {
        let frame = forged_supply_frame(&entries_header_claiming(10_000_000));
        assert!(frame.len() < 64, "the whole attack fits in a tiny frame");
        assert_eq!(
            WireMessage::decode_checked(&frame).unwrap_err(),
            WireError::BatchTooLarge {
                kind: "supply",
                count: 10_000_000,
                max: MAX_SUPPLY_ENTRIES,
            }
        );
    }

    /// The boundary is inclusive both ways, against REAL encoded frames: exactly
    /// `MAX_SUPPLY_ENTRIES` still round-trips, and one more is refused.
    #[test]
    fn prescan_accepts_the_entry_cap_and_rejects_one_over() {
        let at_cap = WireMessage::supply((0..MAX_SUPPLY_ENTRIES).map(supply_entry).collect());
        let cbor = at_cap.to_cbor().unwrap();
        assert_eq!(WireMessage::decode_checked(&cbor).unwrap(), at_cap);

        let over_cap = WireMessage::supply((0..MAX_SUPPLY_ENTRIES + 1).map(supply_entry).collect());
        assert_eq!(
            WireMessage::decode_checked(&over_cap.to_cbor().unwrap()).unwrap_err(),
            WireError::BatchTooLarge {
                kind: "supply",
                count: MAX_SUPPLY_ENTRIES + 1,
                max: MAX_SUPPLY_ENTRIES,
            }
        );
    }

    /// A hand-rolled indefinite-length `entries` array is refused by the scan
    /// rather than followed. ciborium emits definite lengths for every serde
    /// type (pinned by `honest_supply_frames_scan_to_their_entry_count` in
    /// `cbor_scan`), so no honest peer can produce this frame.
    #[test]
    fn prescan_rejects_an_indefinite_length_entries_array() {
        let frame = forged_supply_frame(b"\x9f\xff");
        assert_eq!(
            WireMessage::decode_checked(&frame).unwrap_err(),
            WireError::FramePrescan(CborScanError::IndefiniteLength)
        );
    }

    /// The ENTRY-COUNT scan is keyed on the `Supply` discriminator: a `Want` is
    /// decoded exactly as before even though that scan, if it ran, would refuse
    /// it for having no `entries` key.
    ///
    /// T43b did not change this. A non-`Supply` frame now goes to
    /// `cbor_scan::scan_bounded_arrays` instead — tolerant of absent keys, and
    /// with an element-skip allowance for walking id arrays — which is a
    /// different scan with different semantics, not a widening of this one.
    /// Routing a `Want` through `supply_entry_count` would still refuse it, and
    /// this pins that it never happens.
    #[test]
    fn prescan_only_runs_on_supply_discriminator_frames() {
        for count in [2usize, 1_000] {
            let want = WireMessage::want((0..count).map(|index| format!("{index:064x}")).collect());
            let cbor = want.to_cbor().unwrap();
            assert!(!carries_supply_discriminator(&cbor));
            // The entry-count scan would refuse this frame — a small Want for
            // having no `entries` key, a large one on the visit budget while
            // skipping the id vector as an unrecognised value. The discriminator
            // split is what spares both.
            assert!(cbor_scan::supply_entry_count(&cbor).is_err());
            assert_eq!(WireMessage::decode_checked(&cbor).unwrap(), want);
        }
        let small = WireMessage::want(vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(
            cbor_scan::supply_entry_count(&small.to_cbor().unwrap()),
            Err(CborScanError::MissingEntries)
        );
    }

    /// `carries_supply_discriminator` is the single statement of where the tag
    /// entry sits, shared with `anti_entropy_alpn`'s T26 peek gate.
    #[test]
    fn carries_supply_discriminator_matches_only_supply() {
        assert!(carries_supply_discriminator(
            &WireMessage::supply(vec![]).to_cbor().unwrap()
        ));
        assert!(carries_supply_discriminator(
            &WireMessage::supply(vec![supply_entry(0)])
                .to_cbor()
                .unwrap()
        ));
        for message in [
            WireMessage::want(vec!["id".to_owned()]),
            WireMessage::have_heads(vec!["tx".to_owned()], vec!["dir".to_owned()]),
            WireMessage::announce("id".to_owned(), DirectiveKind::Transaction),
        ] {
            assert!(!carries_supply_discriminator(&message.to_cbor().unwrap()));
        }
        // Too short to hold the discriminator is not a Supply.
        assert!(!carries_supply_discriminator(&[0xa3]));
        assert!(!carries_supply_discriminator(&[]));
    }

    /// The gossip path shares the choke point, so it inherits the same gate —
    /// gossip frames carry no length prefix and never saw T26's peek gate at
    /// all, which is precisely why the scan lives in `decode_checked`.
    #[test]
    fn gossip_decode_inherits_the_prescan() {
        let frame = forged_supply_frame(&entries_header_claiming(10_000_000));
        let error = crate::gossip::decode_broadcast(&frame).unwrap_err();
        assert!(
            error.contains("supply batch too large: 10000000"),
            "unexpected error: {error}"
        );
    }

    // ─── T43b: the same gate over `Want` and `HaveHeads` id arrays ──────────

    fn hex_ids(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("{index:064x}")).collect()
    }

    /// An array header claiming `count` elements, with no element bytes behind
    /// it at all — the shape that makes a rejection a PRE-decode proof.
    fn array_header_claiming(count: u32) -> Vec<u8> {
        let mut header = vec![0x9a];
        header.extend_from_slice(&count.to_be_bytes());
        header
    }

    /// `{"type": "want", "v": 1, "ids": ` exactly as ciborium emits it, then
    /// whatever `ids_tail` claims. Pinned against real bytes by
    /// `cbor_scan::tests::crafted_non_supply_prefixes_match_real_encodings`.
    fn forged_want_frame(ids_tail: &[u8]) -> Vec<u8> {
        let mut frame = vec![0xa3];
        frame.extend_from_slice(b"\x64type\x64want");
        frame.extend_from_slice(b"\x61v\x01");
        frame.extend_from_slice(b"\x63ids");
        frame.extend_from_slice(ids_tail);
        frame
    }

    /// `{"type": "have_heads", "v": 1, "head_txids": …, "directive_ids": …}`
    /// with both arrays supplied by the caller.
    fn forged_have_heads_frame(head_tail: &[u8], directive_tail: &[u8]) -> Vec<u8> {
        let mut frame = vec![0xa4];
        frame.extend_from_slice(b"\x64type\x6ahave_heads");
        frame.extend_from_slice(b"\x61v\x01");
        frame.extend_from_slice(b"\x6ahead_txids");
        frame.extend_from_slice(head_tail);
        frame.extend_from_slice(b"\x6ddirective_ids");
        frame.extend_from_slice(directive_tail);
        frame
    }

    /// Honest maximal traffic still round-trips through the widened gate,
    /// against REAL encoded frames at exactly the caps production emits.
    ///
    /// The compatibility half of T43b: `paginate_have_heads` really does emit
    /// pages that are full in BOTH id arrays with `more` set, and
    /// `MAX_WANT_IDS` really is the size of a maximal request, so these are the
    /// frames a gate this strict is most likely to break. None of them may
    /// change behaviour by so much as a byte.
    #[test]
    fn prescan_accepts_honest_want_and_have_heads_frames_at_their_caps() {
        let frames = [
            WireMessage::want(hex_ids(1)),
            WireMessage::want(hex_ids(MAX_WANT_IDS)),
            // A full intermediate page, exactly as `paginate_have_heads` emits
            // it: both arrays at the cap, `more` set because a page follows.
            WireMessage::have_heads_page(hex_ids(MAX_HAVE_HEADS), hex_ids(MAX_HAVE_HEADS), true),
            // …and the final page, where `more` is false and omitted entirely.
            WireMessage::have_heads(hex_ids(MAX_HAVE_HEADS), hex_ids(MAX_HAVE_HEADS)),
        ];
        for message in frames {
            let cbor = message.to_cbor().unwrap();
            assert_eq!(
                WireMessage::decode_checked(&cbor).unwrap(),
                message,
                "the T43b gate must not disturb an honest maximal frame"
            );
            // The full wire path, length prefix and all.
            let wire = message.to_wire().unwrap();
            assert_eq!(WireMessage::from_wire(&wire).unwrap().0, message);
        }
    }

    /// The T43b hole, closed for `Want`: a ~25-byte frame whose `ids` array
    /// header claims ten million elements is refused from the header alone.
    ///
    /// The frame carries NO element bytes, so before the gate ciborium would
    /// have run out of input part way through building a ten-million-element
    /// `Vec<Content>` and reported a decode error. The refusal now names the
    /// claimed count, with the same `kind` the post-decode cap uses.
    #[test]
    fn prescan_rejects_a_forged_want_id_count_before_serde_sees_the_body() {
        let frame = forged_want_frame(&array_header_claiming(10_000_000));
        assert!(frame.len() < 64, "the whole attack fits in a tiny frame");
        assert_eq!(
            WireMessage::decode_checked(&frame).unwrap_err(),
            WireError::BatchTooLarge {
                kind: "want",
                count: 10_000_000,
                max: MAX_WANT_IDS,
            }
        );
    }

    /// The same, for each of `HaveHeads`' two id arrays independently.
    #[test]
    fn prescan_rejects_forged_have_heads_id_counts_before_serde_sees_the_body() {
        let expected = WireError::BatchTooLarge {
            kind: "have_heads",
            count: 10_000_000,
            max: MAX_HAVE_HEADS,
        };
        // Forged first array; the second is never reached.
        let head_forged = forged_have_heads_frame(&array_header_claiming(10_000_000), &[0x80][..]);
        assert!(head_forged.len() < 80);
        assert_eq!(
            WireMessage::decode_checked(&head_forged).unwrap_err(),
            expected
        );
        // Forged second array, behind an honest empty first one.
        let directive_forged =
            forged_have_heads_frame(&[0x80][..], &array_header_claiming(10_000_000));
        assert!(directive_forged.len() < 80);
        assert_eq!(
            WireMessage::decode_checked(&directive_forged).unwrap_err(),
            expected
        );
    }

    /// The case the element-skip allowance exists for, at the protocol level: a
    /// REAL, honest-full first array with a forged second one spliced on behind
    /// it.
    ///
    /// `head_txids` here is byte-for-byte what the production serializer emits
    /// for a maximal page — 4,096 sixty-four-hex ids, three orders of magnitude
    /// past the 64-visit budget T43's scan ran on. Only a walker that steps
    /// through all of it reaches the `directive_ids` header that lies.
    #[test]
    fn prescan_reaches_the_second_have_heads_array_through_a_full_first() {
        let mut frame = WireMessage::have_heads(hex_ids(MAX_HAVE_HEADS), Vec::new())
            .to_cbor()
            .unwrap();
        // `directive_ids` is omitted when empty, so the real frame is a 3-pair
        // map; widen the header and splice the forged fourth pair on.
        assert_eq!(frame[0], 0xa3, "expected a 3-pair have_heads map");
        frame[0] = 0xa4;
        frame.extend_from_slice(b"\x6ddirective_ids");
        frame.extend_from_slice(&array_header_claiming(10_000_000));
        assert_eq!(
            WireMessage::decode_checked(&frame).unwrap_err(),
            WireError::BatchTooLarge {
                kind: "have_heads",
                count: 10_000_000,
                max: MAX_HAVE_HEADS,
            }
        );
    }

    /// One over the cap, on REAL encoded frames, is refused before the decode —
    /// with exactly the verdict `check_cardinality` would have returned after
    /// it.
    ///
    /// Asserting equality against the post-decode error rather than against a
    /// literal is the point: the pre-scan is the same rule moved earlier, so the
    /// two must agree on `kind`, `count` and `max` by construction. A drifting
    /// `kind` string would silently reclassify a refusal in every caller that
    /// matches on it.
    #[test]
    fn prescan_refuses_one_over_cap_with_the_post_decode_verdict() {
        let over_cap = [
            WireMessage::want(hex_ids(MAX_WANT_IDS + 1)),
            WireMessage::have_heads(hex_ids(MAX_HAVE_HEADS + 1), Vec::new()),
            WireMessage::have_heads(Vec::new(), hex_ids(MAX_HAVE_HEADS + 1)),
        ];
        for message in over_cap {
            let post_decode = message
                .check_cardinality()
                .expect_err("the fixture must be over cap");
            assert_eq!(
                WireMessage::decode_checked(&message.to_cbor().unwrap()).unwrap_err(),
                post_decode,
                "pre-scan and post-decode must refuse identically"
            );
        }
    }

    /// A bomb nested inside an id element is refused by the scan's structure
    /// rules, not walked.
    ///
    /// Every bounded array is a `Vec<String>`, so a non-text element could never
    /// have decoded; refusing it keeps the element walk exactly one header per
    /// element, which is what the allowance is sized for.
    #[test]
    fn prescan_rejects_a_nesting_bomb_inside_a_want_id_element() {
        // "ids": [ [[[[…]]]] ] — one element, 64 arrays deep.
        let mut ids_tail = vec![0x81];
        ids_tail.extend(std::iter::repeat_n(0x81u8, 64));
        ids_tail.push(0x00);
        let frame = forged_want_frame(&ids_tail);
        assert!(frame.len() < 128, "a tiny frame, however deep it nests");
        assert_eq!(
            WireMessage::decode_checked(&frame).unwrap_err(),
            WireError::FramePrescan(CborScanError::NonTextArrayElement("want"))
        );
    }

    /// An `Announce` carries no bounded array at all, and passes untouched —
    /// the tolerance that lets one gate cover every non-`Supply` variant.
    #[test]
    fn prescan_tolerates_variants_with_no_id_arrays() {
        let announce = WireMessage::announce("f".repeat(64), DirectiveKind::Price);
        let cbor = announce.to_cbor().unwrap();
        assert!(!carries_supply_discriminator(&cbor));
        assert_eq!(WireMessage::decode_checked(&cbor).unwrap(), announce);
        // The gossip path shares the choke point, and `Announce` is what it
        // actually carries.
        assert_eq!(crate::gossip::decode_broadcast(&cbor).unwrap(), announce);
    }

    /// The gossip choke point inherits the widened gate too: a forged `Want`
    /// broadcast is refused there without a length prefix ever being involved.
    #[test]
    fn gossip_decode_inherits_the_want_prescan() {
        let frame = forged_want_frame(&array_header_claiming(10_000_000));
        let error = crate::gossip::decode_broadcast(&frame).unwrap_err();
        assert!(
            error.contains("want batch too large: 10000000"),
            "unexpected error: {error}"
        );
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
