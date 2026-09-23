//! Wire protocol types for §3.4.1 (anti-entropy + gossip).
//!
//! All messages are CBOR-encoded with `uint32_be length || cbor_body`.
//! Every message includes `"v": 1`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::cbor_scan::{self, ArrayBound, CborScanError, ElementKind, ScanOutcome};

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

/// Characters in a content id.
///
/// `ledger::hash::compute_content_id` is a SHA-256 rendered as lowercase hex,
/// so every txid and every directive id is exactly this long — which is what
/// lets a receiver state an id budget in BYTES rather than only in ids (M-26).
pub const CONTENT_ID_LEN: usize = 64;

/// Is `id` a well-formed content id — exactly `^[0-9a-f]{64}$` (L-29, M-26, L-53)?
///
/// THE one spelling of a rule the codebase was applying in one place and
/// missing in two. `union_merge`'s `openledger-parents` check has enforced it
/// since L-29/M-05; the anti-entropy advert reader (M-26) and the gossip
/// `Announce` id (L-53) did not, and both feed attacker-chosen strings into
/// structures that retain them — an accumulator plus a dedup set in the first
/// case, a negative-cache key in the second.
///
/// Uppercase is rejected as firmly as punctuation, for the reason L-29 gives:
/// stored ids are lowercase and lookups are exact, so an uppercased spelling of
/// a real id would pass a case-insensitive check and then resolve to nothing,
/// forever.
///
/// Byte-wise rather than `char`-wise on purpose: the length test is on bytes, so
/// a multi-byte character would otherwise make `len()` and "64 characters"
/// disagree. Restricting to ASCII hex makes the two the same statement.
pub fn is_content_id(id: &str) -> bool {
    id.len() == CONTENT_ID_LEN
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Sender-side byte budget for one `Supply` frame (H-02).
///
/// `MAX_SUPPLY_ENTRIES` alone does not bound the frame: 256 entries with a
/// 1 MiB `economic_bean` each is far past `MAX_MESSAGE_SIZE`. Senders fill a
/// `Supply` up to this budget, leaving 1 MiB of headroom under the 16 MiB
/// receive cap for CBOR framing overhead.
pub const SUPPLY_FRAME_BUDGET_BYTES: usize = 15 * 1024 * 1024;

/// Per-value cap on an envelope value, as `union_merge::MAX_ENVELOPE_VALUE_LEN`
/// enforces it on every arriving entry (M-4). Restated here only because that
/// constant is module-private; it feeds [`MAX_LEGAL_SUPPLY_ENTRY_BYTES`] and
/// must be kept in step with it (making that one `pub(crate)` and aliasing it
/// here would remove the restatement).
const LEGAL_ENVELOPE_VALUE_BYTES: usize = 32 * 1024;

/// Per-entry CBOR framing allowance, as `anti_entropy::estimated_entry_bytes`
/// adds it (`SUPPLY_ENTRY_OVERHEAD_BYTES`). Restated for the same reason as
/// [`LEGAL_ENVELOPE_VALUE_BYTES`].
const LEGAL_SUPPLY_ENTRY_FRAMING_BYTES: usize = 128;

/// Sum of the lengths of every envelope key a legal entry may carry.
const fn envelope_key_bytes(keys: &[&str]) -> usize {
    let mut total = 0;
    let mut index = 0;
    while index < keys.len() {
        total += keys[index].len();
        index += 1;
    }
    total
}

/// The largest single `SupplyEntry` any peer will accept, measured the way
/// `anti_entropy::truncate_supply` measures it: the economic body at its cap,
/// every allowed envelope key present with its value at the cap, a content id,
/// and the per-entry CBOR framing allowance.
const MAX_LEGAL_SUPPLY_ENTRY_BYTES: usize = ledger::service::MAX_ECONOMIC_BEAN_LENGTH
    + envelope_key_bytes(ledger::service::ENVELOPE_KEYS)
    + ledger::service::ENVELOPE_KEYS.len() * LEGAL_ENVELOPE_VALUE_BYTES
    + CONTENT_ID_LEN
    + LEGAL_SUPPLY_ENTRY_FRAMING_BYTES;

// Pins the cross-crate coupling between the ledger's body cap and this frame
// budget (T60; see the audit's §5 coupling note).
//
// `truncate_supply` never splits an entry: one whose estimated size exceeds
// `SUPPLY_FRAME_BUDGET_BYTES` on its own is dropped, and the `Supply` goes out
// *empty*. The requester (`gl-node`'s `fetch_want_chunk`) reads an empty answer as
// `stalled` and ends the exchange; every later exchange ends the same way, so
// that directive never propagates and the two ledgers diverge for good, quietly
// — an H-03-class silent divergence.
// It cannot happen today only because the largest legal entry (~1.1 MiB, set by
// `ledger::service::MAX_ECONOMIC_BEAN_LENGTH`) is far below the 15 MiB budget,
// and those two numbers live in different crates with nothing else tying them
// together. This makes the build fail instead of the mesh.
//
// A Format-v2 (or any) raise of the bean cap, the envelope key set, or the
// envelope value cap must revisit this: either keep the largest entry inside
// the budget, or teach `truncate_supply`/the requester to carry an oversized
// entry rather than silently dropping it.
const _: () = assert!(
    MAX_LEGAL_SUPPLY_ENTRY_BYTES <= SUPPLY_FRAME_BUDGET_BYTES,
    "the largest legal SupplyEntry no longer fits SUPPLY_FRAME_BUDGET_BYTES: \
     truncate_supply would send an empty Supply for it and the peer would abandon it (T60)"
);

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

impl WireMessage {
    /// The frame's wire discriminator, and nothing else (M-41).
    ///
    /// For a log line that says "expected X, got Y": `?message` renders the
    /// whole frame — a 4,096-id `HaveHeads` page or a 16 MiB `Supply` — into
    /// a log line the peer wrote. The discriminator is the only thing the log
    /// needs to say which arm was taken, and it is a constant.
    pub fn variant_name(&self) -> &'static str {
        match self {
            WireMessage::Announce { .. } => "announce",
            WireMessage::HaveHeads { .. } => "have_heads",
            WireMessage::Want { .. } => "want",
            WireMessage::Supply { .. } => "supply",
        }
    }
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
    ///
    /// The error is [`elide_decode_error`]'d rather than `to_string`'d: serde
    /// puts the offending VALUE in a type-mismatch message, so a 16 MiB text
    /// string under a declared key returns a 16 MiB error (T49).
    pub fn from_cbor(data: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(data).map_err(|error| elide_decode_error(&error))
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
        elements: ElementKind::Text,
    },
    ArrayBound {
        key: b"head_txids",
        max: MAX_HAVE_HEADS,
        label: "have_heads",
        elements: ElementKind::Text,
    },
    ArrayBound {
        key: b"directive_ids",
        max: MAX_HAVE_HEADS,
        label: "have_heads",
        elements: ElementKind::Text,
    },
];

/// CBOR items one honestly-encoded [`SupplyEntry`] is worth (H-09).
///
/// Counted off the encoding, not guessed: the entry's own map header (1), a key
/// and a value for each of `id`, `kind` and `economic_bean` (6), the `envelope`
/// key and the envelope map's own header (2), and a key and a value per envelope
/// pair. The envelope is not open-ended — `gossip::extract_envelope` emits only
/// `ledger::service::ENVELOPE_KEYS` and `union_merge::validate_supply_envelope`
/// refuses anything else on arrival — so it is read from that set rather than
/// restated, the same single-sourcing both of those use. Four keys today, so 17.
const SUPPLY_ENTRY_ITEMS: usize = 9 + 2 * ledger::service::ENVELOPE_KEYS.len();

/// Maximum CBOR items the pre-scan will let one `Supply` entry spend (H-09).
///
/// The bound that stops a frame from hiding its amplification INSIDE `entries`
/// rather than beside it. `MAX_SUPPLY_ENTRIES` caps how many entries a frame may
/// declare but says nothing about what one entry may contain, and a single entry
/// holding a sixteen-million-element array is a 50× `Content` tree that the
/// entry cap passes by a factor of 256. With this, the whole frame is worth at
/// most `MAX_SUPPLY_ENTRIES × MAX_SUPPLY_ENTRY_ITEMS` = 17,408 `Content` nodes
/// whatever its bytes look like.
///
/// 4× what the real encoding spends. The headroom is for a future field or a
/// fifth envelope key, not for a shape the wire struct cannot produce:
/// `prescan_accepts_an_entry_with_every_envelope_key` measures the honest cost
/// against real encoded bytes, so drift is a test failure rather than a refused
/// peer.
pub(crate) const MAX_SUPPLY_ENTRY_ITEMS: usize = 4 * SUPPLY_ENTRY_ITEMS;

/// The `Supply` frame's one unbounded-cardinality array (T43, H-09).
///
/// Kept apart from [`NON_SUPPLY_ARRAY_BOUNDS`] because the scan it feeds is the
/// stricter one — [`cbor_scan::scan_supply_frame`] requires the key to be
/// present, where the general scan tolerates its absence — and because its
/// elements are structs rather than ids, which is what
/// [`ElementKind::Struct`] says. `label` is again the `BatchTooLarge` kind
/// `check_cardinality` reports, so the two enforcement points refuse identically
/// by construction.
pub(crate) const SUPPLY_ARRAY_BOUNDS: &[ArrayBound] = &[ArrayBound {
    key: b"entries",
    max: MAX_SUPPLY_ENTRIES,
    label: "supply",
    elements: ElementKind::Struct {
        items: MAX_SUPPLY_ENTRY_ITEMS,
    },
}];

/// Every top-level key a `Supply` frame may carry (H-09).
///
/// The wire struct's real field set: serde's internal tag, plus the two fields
/// of `WireMessage::Supply`. serde `Content`-buffers every pair of an
/// internally-tagged map — keys the variant has no field for included — so a
/// frame carrying anything else is asking the decoder to build a tree it will
/// then discard, which is amplification with no honest sender. The list is three
/// lines from the variant it describes so that adding a field is one edit.
pub(crate) const SUPPLY_TOP_LEVEL_KEYS: &[&[u8]] = &[b"type", b"v", b"entries"];

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
///   [`cbor_scan::scan_supply_frame`] with [`SUPPLY_ARRAY_BOUNDS`] and
///   [`SUPPLY_TOP_LEVEL_KEYS`], which requires an `entries` array, bounds it,
///   bounds what each of its elements may nest, and refuses any top-level key
///   the variant does not define (H-09);
/// * every other frame goes to [`cbor_scan::scan_bounded_arrays`] with
///   [`NON_SUPPLY_ARRAY_BOUNDS`], which bounds whichever of `ids`,
///   `head_txids` and `directive_ids` the frame actually carries and tolerates a
///   frame that carries none.
///
/// The split is about strictness, not about mechanism: since H-09 both arms are
/// the same walk over the whole top-level map, differing only in the policy they
/// are handed. T26's peek gate caps a non-`Supply` frame at 1 MiB of bytes and
/// lets a `Supply` through at the full 16 MiB, so the `Supply` arm is the one
/// that has to account for every byte itself — which is exactly why it was the
/// wrong arm to have a scan that stopped early.
///
/// Either way an over-count is reported as the same [`WireError::BatchTooLarge`]
/// the post-decode cap would have produced, with the same `kind`, because it is
/// the same rule — only enforced earlier — and every caller already classifies
/// it. A scan that cannot *answer* is [`WireError::FramePrescan`] instead.
///
/// See [`crate::cbor_scan`] for the scan's bounds, its element-skip allowance,
/// and why each of its rejections is unreachable for an honest peer.
fn prescan_frame(data: &[u8]) -> Result<(), WireError> {
    let outcome = if carries_supply_discriminator(data) {
        cbor_scan::scan_supply_frame(data, SUPPLY_ARRAY_BOUNDS, SUPPLY_TOP_LEVEL_KEYS)
    } else {
        cbor_scan::scan_bounded_arrays(data, NON_SUPPLY_ARRAY_BOUNDS)
    }
    .map_err(WireError::FramePrescan)?;
    match outcome {
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

/// A claimed element count as a `usize`, saturating rather than truncating.
///
/// The count is only ever reported, and a wrapped value would understate the
/// frame in the one message an operator reads to size the attack.
fn saturating_count(claimed: u64) -> usize {
    usize::try_from(claimed).unwrap_or(usize::MAX)
}

/// Longest decode-error detail this crate will carry out of ciborium (T49).
///
/// Enough to name the type mismatch and where it happened; far too short to be
/// worth using as a channel. Since T66 it is also the budget every
/// attacker-reachable error is rendered under on the intake path (H-18, M-41):
/// one number for "how much of a peer's text may reach a log line".
pub const MAX_DECODE_ERROR_CHARS: usize = 256;

/// What [`BoundedSink::finish`] appends when the budget cut something off.
pub const TRUNCATION_MARKER: &str = "… (error truncated)";

/// A [`std::fmt::Write`] sink that keeps at most `budget` characters (T49).
///
/// Character-counted, not byte-counted, and it only ever cuts on a character
/// boundary — so the result is always valid UTF-8 and always printable.
///
/// `pub` since T66 (H-18, M-41): the wire crate's parse-error rendering and
/// `gl-node`'s intake `warn!` sites format through it, so a `MergeError`
/// wrapping a peer's body can never become a log line the size of that body.
/// Prefer [`bounded_display`] unless the write sequence itself matters.
pub struct BoundedSink {
    kept: String,
    budget: usize,
    elided: bool,
}

impl BoundedSink {
    /// An empty sink that keeps at most `budget` characters.
    pub fn new(budget: usize) -> Self {
        Self {
            kept: String::new(),
            budget,
            elided: false,
        }
    }

    /// Whether anything written so far was cut off.
    pub fn elided(&self) -> bool {
        self.elided
    }

    /// The kept text, with [`TRUNCATION_MARKER`] appended if anything was cut.
    ///
    /// The marker is appended AFTER the budget is spent, so a caller sizing a
    /// buffer sees at most `budget + TRUNCATION_MARKER.chars().count()`.
    pub fn finish(mut self) -> String {
        if self.elided {
            self.kept.push_str(TRUNCATION_MARKER);
        }
        self.kept
    }
}

/// Render `value` through a [`BoundedSink`] of `budget` characters (T66).
///
/// The truncation happens as the value is FORMATTED: nothing downstream ever
/// holds a full-size rendering, which is the difference between "a bounded log
/// line" and "an unbounded `String` we then shorten". A `Display` impl can only
/// fail through its sink and the sink never fails, so the `write!` result is
/// ignored rather than unwrapped — a panic while formatting an attacker's error
/// would be the worse of the two outcomes.
pub fn bounded_display(value: &impl std::fmt::Display, budget: usize) -> String {
    use std::fmt::Write as _;
    let mut sink = BoundedSink::new(budget);
    let _ = write!(sink, "{value}");
    sink.finish()
}

impl std::fmt::Write for BoundedSink {
    fn write_str(&mut self, chunk: &str) -> std::fmt::Result {
        if self.budget == 0 {
            self.elided |= !chunk.is_empty();
            return Ok(());
        }
        let mut bytes_taken = 0usize;
        let mut chars_taken = 0usize;
        for (offset, character) in chunk.char_indices() {
            if chars_taken == self.budget {
                break;
            }
            chars_taken += 1;
            bytes_taken = offset + character.len_utf8();
        }
        self.kept.push_str(&chunk[..bytes_taken]);
        self.budget -= chars_taken;
        self.elided |= bytes_taken < chunk.len();
        Ok(())
    }
}

/// Render a decode error, truncated to [`MAX_DECODE_ERROR_CHARS`] (T49).
///
/// serde's type-mismatch errors embed the value that did not fit the field —
/// `invalid type: string "…", expected u64` — and ciborium hands that message
/// straight through. So `{"type":"supply","v":"<16 MiB of text>","entries":[]}`
/// decodes to a *sixteen-megabyte error string*: a `v` key the variant declares,
/// carrying the wrong CBOR type. The pre-scan cannot refuse it (the key is
/// declared and there is no array to over-count), and the frame is a legal
/// `Supply` by every byte-level rule, so the whole cost lands in the error —
/// which `serve_anti_entropy` and the gossip loop then hand to `warn!`, turning
/// a 16 MiB frame into a 16 MiB log line an attacker wrote.
///
/// Truncation happens as the message is FORMATTED, through [`BoundedSink`],
/// rather than by trimming an already-materialized `String`: the oversized
/// message exists inside ciborium either way, but nothing downstream ever gets a
/// second copy of it, and nothing retains one.
///
/// Note what this does not claim to fix: the peak allocation during the decode
/// itself. That is `Content` buffering plus serde's own message, both inside
/// ciborium, and bounding it belongs with the frame caps (M-16/H-09), not here.
pub fn elide_decode_error(error: &impl std::fmt::Display) -> String {
    bounded_display(error, MAX_DECODE_ERROR_CHARS)
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
    // ─── T49: a decode error is not an attacker's log channel ─────────────

    /// A 4 MiB text string under the DECLARED key `v`.
    ///
    /// Every byte-level rule passes it: the `Supply` discriminator is genuine,
    /// `v` is a key the variant defines (so H-09's unknown-key gate does not
    /// fire), `entries` is present and empty (so no array is over-count), and
    /// the frame is inside `MAX_MESSAGE_SIZE`. The only thing wrong with it is
    /// the CBOR *type* of `v` — which is discovered by serde, which reports it
    /// by quoting the offending value.
    fn wrong_typed_declared_key_frame(payload_bytes: usize) -> Vec<u8> {
        use ciborium::value::Value;
        let frame = Value::Map(vec![
            (
                Value::Text("type".to_owned()),
                Value::Text("supply".to_owned()),
            ),
            (
                Value::Text("v".to_owned()),
                Value::Text("x".repeat(payload_bytes)),
            ),
            (Value::Text("entries".to_owned()), Value::Array(Vec::new())),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&frame, &mut bytes).expect("encode the forged frame");
        assert!(carries_supply_discriminator(&bytes));
        assert!(bytes.len() <= MAX_MESSAGE_SIZE as usize);
        bytes
    }

    /// T49: the decode error must not carry the attacker's payload.
    ///
    /// serde's type-mismatch message embeds the value that did not fit, so
    /// before [`elide_decode_error`] this frame produced a multi-megabyte
    /// `WireError::CborDecode(String)` — which the anti-entropy serve loop and
    /// the gossip loop then hand to `warn!`, turning a 4 MiB frame into a 4 MiB
    /// log line written by a peer. (At the full `MAX_MESSAGE_SIZE` the same
    /// shape was measured at 80,000,161 bytes of peak allocation, 5.00× the
    /// frame — most of it this string.) 4 MiB here keeps the test quick; the
    /// property is a constant bound, so the payload size cannot matter.
    #[test]
    fn a_decode_error_cannot_carry_a_multi_megabyte_payload() {
        let payload_bytes = 4 * 1024 * 1024;
        let frame = wrong_typed_declared_key_frame(payload_bytes);

        let error = WireMessage::decode_checked(&frame)
            .expect_err("a text `v` where a u64 belongs must not decode");
        let WireError::CborDecode(detail) = &error else {
            panic!("expected a CBOR decode error, got {error:?}");
        };

        assert!(
            detail.chars().count()
                <= MAX_DECODE_ERROR_CHARS + "… (error truncated)".chars().count(),
            "the decode error is {} characters — it is carrying the payload",
            detail.chars().count()
        );
        assert!(
            detail.ends_with("… (error truncated)"),
            "a truncated error must say so: {detail}"
        );
        // And the whole rendered `WireError` stays small, since that is what a
        // log line actually contains.
        assert!(error.to_string().len() < 1024);
        // Sanity: the payload really is in the frame, so the test is not passing
        // because the frame was rejected before serde ever saw it.
        assert!(frame.len() > payload_bytes);
    }

    /// T66 (M-41): `bounded_display` keeps a short value verbatim, cuts a long
    /// one at the budget and says so, and its output is sized by the budget
    /// alone — never by the value.
    #[test]
    fn bounded_display_is_sized_by_the_budget_not_the_value() {
        assert_eq!(bounded_display(&"short", 16), "short");
        let long = "é".repeat(4 * 1024 * 1024);
        let rendered = bounded_display(&long, 256);
        assert!(rendered.ends_with(TRUNCATION_MARKER));
        assert_eq!(
            rendered.chars().count(),
            256 + TRUNCATION_MARKER.chars().count()
        );
        assert!(rendered.len() < 1024);
    }

    /// T66 (M-41): a full `HaveHeads` page where a `Supply` was expected used
    /// to be `?other`-rendered into the log. What the log carries now is the
    /// discriminator, a constant far under the 512-char bar for every variant.
    #[test]
    fn a_full_have_heads_page_logs_as_its_variant_name() {
        let ids: Vec<String> = (0..MAX_HAVE_HEADS).map(|i| format!("{i:064x}")).collect();
        let page = WireMessage::have_heads_page(ids.clone(), ids, true);
        assert!(
            format!("{page:?}").len() > 512 * 1024,
            "the frame itself is huge"
        );
        assert_eq!(page.variant_name(), "have_heads");
        assert!(page.variant_name().len() < 512);
        assert_eq!(WireMessage::want(Vec::new()).variant_name(), "want");
        assert_eq!(
            WireMessage::Supply {
                v: WIRE_VERSION,
                entries: Vec::new()
            }
            .variant_name(),
            "supply"
        );
        assert_eq!(
            WireMessage::Announce {
                v: WIRE_VERSION,
                id: String::new(),
                kind: DirectiveKind::Open
            }
            .variant_name(),
            "announce"
        );
    }

    /// The sink cuts on character boundaries and reports whether it cut.
    #[test]
    fn bounded_sink_never_splits_a_character() {
        use std::fmt::Write as _;

        // Multi-byte characters straddling the budget: a byte-wise truncation
        // would panic or produce invalid UTF-8 here.
        let mut sink = BoundedSink {
            kept: String::new(),
            budget: 3,
            elided: false,
        };
        write!(sink, "héllo").expect("bounded sink never fails");
        assert_eq!(sink.kept, "hél");
        assert!(sink.elided);

        // Exactly at the budget is not elided.
        let mut exact = BoundedSink {
            kept: String::new(),
            budget: 5,
            elided: false,
        };
        write!(exact, "héllo").expect("bounded sink never fails");
        assert_eq!(exact.kept, "héllo");
        assert!(!exact.elided);

        // Writes past exhaustion are dropped, not panicked on.
        let mut spent = BoundedSink {
            kept: String::new(),
            budget: 0,
            elided: false,
        };
        write!(spent, "anything").expect("bounded sink never fails");
        assert!(spent.kept.is_empty());
        assert!(spent.elided);
    }

    /// An error small enough to keep is kept verbatim — truncation must not
    /// cost an operator the ordinary message.
    #[test]
    fn a_short_decode_error_is_untouched() {
        // Not CBOR at all: ciborium's message names the fault and nothing else.
        let error =
            WireMessage::decode_checked(&[0xff, 0xff, 0xff]).expect_err("garbage must not decode");
        let rendered = error.to_string();
        assert!(!rendered.contains("(error truncated)"), "got: {rendered}");
        assert!(rendered.len() < 200, "got: {rendered}");
    }

    /// The content-id rule the wire, the advert reader and the parents check all
    /// share (L-29, M-26, L-53).
    #[test]
    fn content_id_rule_is_exactly_sixty_four_lowercase_hex() {
        assert!(is_content_id(&"0".repeat(CONTENT_ID_LEN)));
        assert!(is_content_id(&"abcdef0123456789".repeat(4)));

        assert!(!is_content_id(""));
        assert!(!is_content_id(&"0".repeat(CONTENT_ID_LEN - 1)));
        assert!(!is_content_id(&"0".repeat(CONTENT_ID_LEN + 1)));
        assert!(!is_content_id(&"0".repeat(255)));
        // Uppercase would pass a case-insensitive check and then resolve to
        // nothing, forever — L-29's reasoning, pinned.
        assert!(!is_content_id(&format!(
            "{}A",
            "0".repeat(CONTENT_ID_LEN - 1)
        )));
        assert!(!is_content_id(&format!(
            "{}g",
            "0".repeat(CONTENT_ID_LEN - 1)
        )));
        // 63 chars + one two-byte character is 64 BYTES but not 64 hex digits.
        assert!(!is_content_id(&format!(
            "{}é",
            "0".repeat(CONTENT_ID_LEN - 2)
        )));
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

    /// The STRICT scan is keyed on the `Supply` discriminator: a `Want` is
    /// decoded exactly as before even though that scan, if it ran, would refuse
    /// it for having no `entries` key.
    ///
    /// Neither T43b nor H-09 changed this. A non-`Supply` frame goes to
    /// `cbor_scan::scan_bounded_arrays` instead — tolerant of absent keys and of
    /// keys its three variants do not share — which is the same walk under a
    /// looser policy, not a widening of this one. Routing a `Want` through the
    /// `Supply` policy would refuse it on both counts, and this pins that it
    /// never happens.
    #[test]
    fn prescan_only_runs_on_supply_discriminator_frames() {
        for count in [2usize, 1_000] {
            let want = WireMessage::want((0..count).map(|index| format!("{index:064x}")).collect());
            let cbor = want.to_cbor().unwrap();
            assert!(!carries_supply_discriminator(&cbor));
            // The Supply policy would refuse this frame: `ids` is not a key the
            // variant declares, and a small Want has no `entries` besides. The
            // discriminator split is what spares both.
            assert!(cbor_scan::scan_supply_frame(
                &cbor,
                SUPPLY_ARRAY_BOUNDS,
                SUPPLY_TOP_LEVEL_KEYS
            )
            .is_err());
            assert_eq!(WireMessage::decode_checked(&cbor).unwrap(), want);
        }
        // `type` and `v` are shared, so the first key a `Want` carries that the
        // `Supply` policy has no field for is `ids` — an undeclared key, which
        // the strict scan reaches before it can notice the missing `entries`.
        let small = WireMessage::want(vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(
            cbor_scan::scan_supply_frame(
                &small.to_cbor().unwrap(),
                SUPPLY_ARRAY_BOUNDS,
                SUPPLY_TOP_LEVEL_KEYS
            ),
            Err(CborScanError::UnknownKey)
        );
        // With the undeclared key gone, the absence is what refuses it.
        let no_entries = vec![0xa2u8]
            .into_iter()
            .chain(SUPPLY_TYPE_DISCRIMINATOR.iter().copied())
            .chain(b"\x61v\x01".iter().copied())
            .collect::<Vec<u8>>();
        assert_eq!(
            cbor_scan::scan_supply_frame(&no_entries, SUPPLY_ARRAY_BOUNDS, SUPPLY_TOP_LEVEL_KEYS),
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

    // ─── H-09: the `Supply` arm walks the whole map ─────────────────────────

    /// The H-09 frame, at the choke point: a 16 MiB `Supply` whose payload sits
    /// BEHIND an empty `entries`.
    ///
    /// T43's scan answered `Ok(0)` from the `entries` header and never read
    /// another pair, so this decoded — successfully, as an empty `Supply` — after
    /// building a `Content` tree 50× the frame. There was no error to log and no
    /// cap to trip: just one budget unit spent against a 100k per-connection
    /// allowance, ×32 connections per peer. `decode_memory.rs` measures the
    /// peak; this pins the verdict.
    #[test]
    fn prescan_rejects_a_supply_frame_that_hides_its_payload_after_entries() {
        // {"type": "supply", "entries": [], "v": 1, "z": [10 M items]}
        let mut frame = vec![0xa4];
        frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        frame.extend_from_slice(b"\x67entries\x80");
        frame.extend_from_slice(b"\x61v\x01");
        frame.extend_from_slice(b"\x61z");
        frame.extend_from_slice(&array_header_claiming(10_000_000));
        assert!(frame.len() < 64, "the whole attack fits in a tiny frame");
        assert!(
            carries_supply_discriminator(&frame),
            "the frame must reach the Supply arm, as it does at T26's peek gate"
        );
        assert_eq!(
            WireMessage::decode_checked(&frame).unwrap_err(),
            WireError::FramePrescan(CborScanError::UnknownKey)
        );
        // The gossip choke point inherits it, as it does every other pre-scan
        // rule — and gossip never saw T26's byte cap at all.
        assert!(crate::gossip::decode_broadcast(&frame)
            .unwrap_err()
            .contains("undeclared top-level key"));
    }

    /// The same payload hidden INSIDE `entries` rather than after it.
    ///
    /// One element is inside `MAX_SUPPLY_ENTRIES` by a factor of 256, so the
    /// entry-count cap passes this frame however it is enforced: the header's
    /// claim of `1` is perfectly true. Only `MAX_SUPPLY_ENTRY_ITEMS` — a bound
    /// on what one entry may be WORTH, which T43 had no notion of — refuses it.
    #[test]
    fn prescan_rejects_a_supply_frame_that_hides_its_payload_inside_entries() {
        // {"type": "supply", "v": 1, "entries": [[1,000 empty strings]]}
        let mut ids_tail = vec![0x81, 0x99];
        ids_tail.extend_from_slice(&1000u16.to_be_bytes());
        ids_tail.extend(std::iter::repeat_n(0x60u8, 1000));
        let frame = forged_supply_frame(&ids_tail);
        assert_eq!(
            WireMessage::decode_checked(&frame).unwrap_err(),
            WireError::FramePrescan(CborScanError::VisitBudgetExhausted)
        );
    }

    /// The compatibility half of H-09, against REAL encoded frames: a maximal
    /// `Supply` whose every entry carries every envelope key the protocol allows
    /// still passes the walk, at the cap, through the full wire path.
    ///
    /// This is what `MAX_SUPPLY_ENTRY_ITEMS` is sized against. The per-entry item
    /// budget is the one bound H-09 added that an honest sender can reach, so
    /// the frame it has to pass is the widest one `gossip::to_wire_entry` can
    /// produce: `ENVELOPE_KEYS` in full, `MAX_SUPPLY_ENTRIES` times over. A
    /// budget the encoder could outgrow would refuse live traffic rather than an
    /// attack.
    #[test]
    fn prescan_accepts_an_entry_with_every_envelope_key() {
        let entries: Vec<SupplyEntry> = (0..MAX_SUPPLY_ENTRIES)
            .map(|index| SupplyEntry {
                id: format!("{index:064x}"),
                kind: DirectiveKind::Transaction,
                economic_bean: "2024-01-15 * \"x\"\n  Assets:Cash 1 USD".to_owned(),
                envelope: ledger::service::ENVELOPE_KEYS
                    .iter()
                    .map(|key| ((*key).to_owned(), format!("{index}")))
                    .collect(),
            })
            .collect();
        let message = WireMessage::supply(entries);
        let wire = message.to_wire().unwrap();
        assert_eq!(
            WireMessage::from_wire(&wire).unwrap().0,
            message,
            "the H-09 item budget must not refuse the widest honest Supply"
        );
        // And the budget has real headroom over it, rather than just clearing.
        assert!(
            MAX_SUPPLY_ENTRY_ITEMS >= 4 * (9 + 2 * ledger::service::ENVELOPE_KEYS.len()),
            "MAX_SUPPLY_ENTRY_ITEMS has lost its margin over the real encoding"
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
