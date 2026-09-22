//! Bounded CBOR header scan for the M-16 pre-decode gate (T43, T43b, H-09).
//!
//! # Why this exists
//!
//! [`crate::protocol::WireMessage`] is `#[serde(tag = "type")]` — internally
//! tagged. Serde cannot dispatch on an internal tag while streaming, because the
//! tag may appear at any position in the map, so `Deserialize` for such an enum
//! buffers the **entire** value tree into `serde::__private::de::Content` first
//! and only then re-plays it into the chosen variant. `Content` is an owned enum
//! roughly 32 bytes wide with an owned `Vec`/`String` per container, so a CBOR
//! array of N one-byte elements costs N × tens of bytes *before* any of this
//! crate's caps can look at it. At the 16 MiB frame cap that is ~16.7 M elements
//! and a transient allocation in the hundreds of megabytes — GiB-scale once the
//! `Vec<Content>` doubling and the per-element payloads are counted.
//!
//! T26 closed most of this by refusing any **non**-`Supply` frame over
//! `NON_SUPPLY_FRAME_CAP` from a ~13-byte peek (see
//! [`crate::protocol::SUPPLY_TYPE_DISCRIMINATOR`]). The residual it left, and
//! the reason this module exists, is a frame that genuinely *carries* the
//! `Supply` discriminator: it passes the pre-cap because it "is" a `Supply`,
//! and `MAX_SUPPLY_ENTRIES` (256) only applies **after** the buffering decode
//! has already built the multi-million-element `Content` tree.
//!
//! [`scan_supply_frame`] answers "does this frame declare more than
//! `MAX_SUPPLY_ENTRIES` entries, or anything else serde would have to buffer?"
//! by walking CBOR **headers only**, touching no payload bytes beyond the map
//! keys and allocating nothing at all. The answer comes back before serde is
//! handed the buffer, so the cardinality cap now runs where it always should
//! have: on the wire bytes, not on the materialised tree.
//!
//! This is option (a) from T43. Option (b) — moving `WireMessage` to an
//! externally- or adjacently-tagged encoding so serde can dispatch without
//! buffering at all — is a coordinated wire-format upgrade and stays deferred;
//! nothing here changes a single byte of what an honest peer sends or expects.
//!
//! # T43b: the same gate for `Want` and `HaveHeads`
//!
//! T43 left a quantified residual. The `Content`-buffering is a property of the
//! **enum**, not of the `Supply` variant, so `Want.ids` and `HaveHeads`'
//! `head_txids` / `directive_ids` amplify the same way — measured at **80×** on
//! a frame packed with one-byte ids, i.e. ~84 MB of transient allocation for a
//! 1 MiB `Want` that `MAX_WANT_IDS` then rejects *post*-decode. That was
//! bounded, not closed: T26's `NON_SUPPLY_FRAME_CAP` (1 MiB) caps one frame, but
//! `ConnectionLimiter`'s 256 concurrent inbound connections multiply it to
//! ~21 GB from allowlisted peers.
//!
//! [`scan_bounded_arrays`] closes it with the same walker. Its semantics differ
//! from [`scan_supply_frame`] in exactly one deliberate way: a `Supply` **must**
//! have an `entries` key, so a missing one is a refusal, whereas a non-`Supply`
//! frame need carry no bounded array at all (an `Announce` carries none), so
//! absent keys are simply tolerated. Everything else stays fail-closed —
//! indefinite lengths, non-text keys, budgets and depth all reject exactly as
//! they do for a `Supply`.
//!
//! # Why bounding the element COUNT is enough
//!
//! The amplification is per-element structure overhead × element count, and the
//! two bounds now compose:
//!
//! * `MAX_MESSAGE_SIZE` (16 MiB) bounds the **bytes** a frame may carry, so the
//!   payload serde copies out of it is bounded whatever its shape.
//! * The cardinality caps — `MAX_SUPPLY_ENTRIES` (256), `MAX_WANT_IDS` (1,024),
//!   `MAX_HAVE_HEADS` (4,096) — enforced here before the decode, bound the
//!   **elements** of every unbounded-cardinality array a `WireMessage` has.
//!
//! The `Want` and `HaveHeads` arrays are `Vec<String>` — leaves, so nothing can
//! nest inside them and the element count IS the node count.
//!
//! `Supply.entries` is not a leaf array, and T43's version of this paragraph got
//! it wrong. It argued that "a `SupplyEntry` is a fixed four-field struct of
//! scalars plus one `BTreeMap<String, String>`, so its nested structure is
//! bounded by the frame's byte length, not by a second independent count" — but
//! bounded by the frame's byte length is precisely what does NOT bound the
//! amplification. Every CBOR item costs one byte on the wire and ~32 bytes of
//! `Content`, so a frame whose bytes are all *items* is the 50× case whether
//! those items sit at the top level or inside an entry, and ONE entry holding a
//! sixteen-million-element array is inside `MAX_SUPPLY_ENTRIES` by a factor of
//! 256. [`ElementKind::Struct`] supplies the missing bound: an entry may spend
//! at most `items` CBOR headers, so the frame's node count is bounded by
//! `MAX_SUPPLY_ENTRIES × items` — 17,408 — rather than by its byte length. That
//! is the constant multiple of the frame `decode_memory.rs` asserts.
//!
//! # The element-skip allowance (T43b)
//!
//! No scan here can stop at the first array it recognises. A `HaveHeads` has
//! **two**, and an honest-full `head_txids` sits between the scan and
//! `directive_ids`; a `Supply` has one, and H-09 showed that stopping at it
//! hides the entire rest of the map. Walking past 4,096 element headers on a
//! 64-visit budget is impossible, so the walk carries a second, separate
//! allowance:
//!
//! * A recognised array is bounded **at its header**: a claim over its cap is
//!   refused before a single element byte is touched, so an over-cap array is
//!   never walked and never paid for.
//! * A claim **within** its cap is already proven bounded by the cap, so the
//!   scan grants itself `count × ` the element's header cost to step over that
//!   array's elements — and spends no more than it granted, because an element
//!   is either a definite-length text string ([`ElementKind::Text`]: exactly one
//!   header, then a length jump over the payload, nothing nested possible to
//!   spend more) or a whole value walked under a per-element item budget
//!   ([`ElementKind::Struct`]: whatever it does not spend is handed back, so a
//!   frame of cheap entries cannot bank the difference).
//! * The grants are drawn from one frame-wide pool sized from the caps
//!   themselves — 9,216 headers for the three id arrays, 17,408 for the 256
//!   entries of a `Supply`. A frame that repeats a recognised key to ask for the
//!   allowance twice runs the pool dry and is refused on the visit budget.
//!
//! So the walk is bounded by the caps themselves, by construction, rather than
//! by a hand-picked number: at most `MAX_SCAN_VISITS + Σ(bound.max × cost)`
//! header reads, each consuming at least one byte of a frame the receive path
//! has already read. The top-level visit, key-count and key-length budgets stay
//! exactly as tight as T43 set them.
//!
//! # H-09: the short-circuit, and the keys serde buffers anyway
//!
//! T43's `supply_entry_count` returned at the **first** `entries` key it found
//! and never read another pair. [`scan_bounded_arrays`] never had that hole — it
//! walks every pair under the visit budget — so the asymmetry was the bug: the
//! one variant T26 deliberately admits at the full 16 MiB cap was the one whose
//! scan short-circuited. A frame shaped
//! `{"type": "supply", "entries": [], "v": 1, "z": [16 M items]}` was answered
//! `Ok(0)` by the gate and then cost **805 MB** of transient `Content` for its
//! 16 MB of input — 50.33×, the same factor the unguarded path reaches — and it
//! *decoded successfully*, as an empty `Supply`. No error, no log, nothing: one
//! budget unit per frame against a 100k per-connection budget, ×32 connections
//! per peer.
//!
//! Three changes close it, and two of them are just the general walk:
//!
//! * The `Supply` scan is now the same private `walk` as the general one, so it
//!   reads **every** top-level pair and puts every value it does not recognise
//!   through `Scanner::skip_value` under [`MAX_SCAN_VISITS`] — which is what
//!   refuses a sixteen-million-item array however it is keyed, and wherever in
//!   the map it is hidden.
//! * `entries` is now an [`ArrayBound`] like any other, carrying
//!   [`ElementKind::Struct`] rather than [`ElementKind::Text`], so it is judged
//!   at its header and then STEPPED OVER on the allowance instead of being
//!   returned from. That also bounds what one entry may nest, which the header
//!   claim alone never did.
//! * A `Supply` frame carrying a top-level key the variant does not define is
//!   refused ([`CborScanError::UnknownKey`]), and so is one that repeats a key it
//!   does ([`CborScanError::DuplicateKey`]). serde's internally-tagged
//!   `TaggedContentVisitor` buffers **every** pair of such a map into
//!   `Content` — unknown keys included — and discards them only once the variant
//!   has been chosen and replayed, so an undeclared key is pure amplification
//!   that no honest sender has any reason to emit. ciborium's own guard is a
//!   256-level *recursion* limit, which bounds nothing about cardinality. The
//!   allowlist is the wire struct's real field set (`type`, `v`, `entries`),
//!   owned by `crate::protocol` beside the bounds so the two cannot drift.
//!
//! # Fail-closed, and why that is safe for honest peers
//!
//! Every bound below rejects rather than tolerates: an indefinite-length item,
//! a non-text map key, a key longer than [`MAX_SCAN_KEY_BYTES`], a map with more
//! than [`MAX_SCAN_MAP_KEYS`] pairs, nesting past [`MAX_SCAN_DEPTH`], more than
//! [`MAX_SCAN_VISITS`] headers, a missing `entries` key, or an `entries` value
//! that is not a definite-length array. None of those can come from an honest
//! peer:
//!
//! * ciborium's serializer emits **definite** lengths for every serde type
//!   (`serialize_map(Some(n))` / `serialize_seq(Some(n))` are what serde's
//!   derived impls and its internally-tagged `TaggedSerializer` call), so an
//!   indefinite-length head cannot appear in a frame this codebase produced.
//!   `honest_supply_frames_scan_to_their_entry_count` proves that against real
//!   encoded bytes rather than against the claim.
//! * A real `Supply` is a three-pair map — `"type"`, `"v"`, `"entries"` — whose
//!   longest key is seven bytes and whose only skipped values are a short text
//!   string and a small integer. The honest scan reads **seven** headers at
//!   depth zero, so every top-level bound here sits at least an order of
//!   magnitude above the traffic it has to pass. The entries walk H-09 added is
//!   paid for separately, out of the allowance above: a real entry spends 17
//!   headers (its map, three scalar fields, and an envelope whose keys are the
//!   closed `ledger::service::ENVELOPE_KEYS` set) against a per-entry budget of
//!   68.
//!
//! The scan deliberately does not assume field ORDER. serde emits the tag first
//! and ciborium preserves struct order (`type`, `v`, `entries` — verified by
//! inspecting real encoded bytes), but the loop reads keys generically, so a
//! reordered map walks exactly as well. It is no longer tolerant of an EXTENDED
//! one on the `Supply` path: since H-09 an undeclared top-level key is a
//! refusal, because serde buffers it whether or not the struct wants it. Adding
//! a field to `Supply` therefore means adding it to the allowlist, which is the
//! same edit as adding it to the struct and sits three lines away from it.
//!
//! T43b widens those same rules from "every `Supply` frame" to "every frame",
//! which raises the bar for a future `WireMessage` variant: it must still encode
//! as a definite-length map of at most [`MAX_SCAN_MAP_KEYS`] text keys of at most
//! [`MAX_SCAN_KEY_BYTES`] bytes, and any new unbounded array it adds wants a
//! [`ArrayBound`] beside the others — with the [`ElementKind`] that says how its
//! elements may be stepped over. Every variant today is a three-to-five-field
//! struct whose longest key is `"directive_ids"` (13 bytes), so the headroom is
//! an order of magnitude; `honest_non_supply_frames_scan_within_their_bounds`
//! pins it against real encoded bytes rather than against this paragraph.

/// Maximum CBOR headers the scan may read before giving up (T43).
///
/// The honest path reads exactly seven: the top-level map header, the `"type"`
/// key and its `"supply"` value, the `"v"` key and its integer value, the
/// `"entries"` key, and the `entries` array header. 64 leaves room for a future
/// field or two while keeping the scan's cost a small constant — a crafted frame
/// cannot make the guard itself the expensive part, which is the failure mode a
/// hand-rolled scanner most easily introduces.
///
/// T43b does **not** relax this, and neither does H-09. A walk has to step over
/// the elements of arrays it has already proven to be within cap — `entries`
/// among them since H-09 — and pays for that out of a separate per-array
/// allowance (see the module docs) rather than out of this budget, so the bound
/// on everything *else* the walk does — map header, keys, unrecognised values —
/// stays exactly where T43 put it. That is what refuses a frame which hides a
/// sixteen-million-item array behind an empty `entries`: the array is an
/// unrecognised value, and unrecognised values still get 64 headers between
/// them.
pub const MAX_SCAN_VISITS: usize = 64;

/// Maximum container nesting the skipper may enter (T43).
///
/// The honest path never enters one: the two values skipped before `entries` is
/// reached are a text string and an integer, both leaves. Anything deeper is a
/// nesting bomb aimed at the scan.
pub const MAX_SCAN_DEPTH: usize = 4;

/// Maximum pairs the top-level map may declare (T43).
///
/// The widest `WireMessage` variant is a five-pair map (`have_heads` with
/// `more`); a `Supply` is three. 16 is generous headroom, and refusing an
/// absurd count up front stops a header claiming `u64::MAX` pairs from turning
/// the key loop into the attack.
pub const MAX_SCAN_MAP_KEYS: u64 = 16;

/// Maximum byte length of a top-level map key the scan will read (T43).
///
/// The longest real key on any variant is `"directive_ids"` (13 bytes);
/// `"entries"` is seven.
pub const MAX_SCAN_KEY_BYTES: u64 = 64;

/// What the elements of a bounded array are, and therefore how a walk may step
/// over one it has already proven to be within cap (T43b, H-09).
///
/// The distinction is about COST, not about types. A text element is priced
/// exactly — one header, then a jump over its payload — so an array of them can
/// be stepped over for a price the cap itself pays. A struct element has no
/// such price: a `SupplyEntry` nests a `BTreeMap<String, String>`, so the
/// headers one element spends are bounded by the frame's bytes rather than by
/// any cap, and the walk has to impose a budget of its own to step over it at
/// all. T43 sidestepped that by never stepping over `entries`, which is exactly
/// the short-circuit H-09 found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementKind {
    /// Definite-length text strings — every `Vec<String>` array on the wire.
    ///
    /// Refused if an element is anything else, which is what makes the walk
    /// provably one header plus one length jump per element with nothing nested
    /// inside to spend the allowance or the depth budget on.
    Text,
    /// Whole CBOR values, each allowed at most `items` headers (H-09).
    ///
    /// `Supply.entries` is a `Vec<SupplyEntry>`: a four-field struct whose
    /// `envelope` is a map, so an element is a subtree rather than a leaf and
    /// the scan cannot price it from the array's cap alone. `items` is the
    /// caller's statement of how many CBOR items one element may be worth —
    /// enough for the encoding the wire struct really produces, and low enough
    /// that `max × items` is a constant the walk can afford. An element over
    /// budget is [`CborScanError::VisitBudgetExhausted`], not a decode later.
    Struct {
        /// Maximum CBOR headers one element may spend.
        items: usize,
    },
}

impl ElementKind {
    /// Header reads one element of this kind may cost the allowance.
    fn header_cost(self) -> usize {
        match self {
            Self::Text => 1,
            Self::Struct { items } => items,
        }
    }
}

/// One top-level array a walk knows how to bound (T43b, H-09).
///
/// The caller owns the whole policy — which keys are arrays, what each one's cap
/// is, and what to call it in an error — so this module stays a CBOR walker with
/// no opinion about the protocol. `crate::protocol` builds the list from the
/// same `MAX_WANT_IDS` / `MAX_HAVE_HEADS` constants its post-decode cardinality
/// check uses, which is what keeps the two enforcement points from drifting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArrayBound {
    /// The top-level map key whose value is the array.
    pub key: &'static [u8],
    /// Maximum element count the array's header may claim.
    pub max: usize,
    /// The caller's name for this bound, echoed back in
    /// [`ScanOutcome::OverBound`]. Opaque here: the scan never interprets it.
    pub label: &'static str,
    /// What the array's elements are, and so how the walk may step over them
    /// once the header's claim has been proven within [`Self::max`] (H-09).
    pub elements: ElementKind,
}

/// What [`scan_bounded_arrays`] found, for a frame it was able to walk (T43b).
///
/// Being over cap is an [`Ok`] outcome, not a [`CborScanError`], and the split is
/// deliberate: "this frame declares more ids than the protocol allows" is a
/// cardinality verdict the caller reports as its ordinary batch-too-large error,
/// while a `CborScanError` means the guard could not answer the question at all.
/// Collapsing the two would lose that distinction in exactly the place — a
/// serve-loop log — where it is worth the most.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    /// Every recognised array's header claimed a count within its bound. Arrays
    /// the caller did not name, and keys the frame did not carry, are not this
    /// scan's business.
    WithinBounds,
    /// A recognised array's header claimed more than its bound. The scan stopped
    /// at that header, having walked none of the array.
    OverBound {
        /// The offending bound's [`ArrayBound::label`].
        label: &'static str,
        /// The element count the array header CLAIMED.
        claimed: u64,
        /// The bound it broke.
        max: usize,
    },
}

/// Why a bounded scan refused a frame (T43).
///
/// Every variant is a refusal to answer, not a claim about the frame's
/// semantics: the scan's contract is "prove this frame's array cardinalities are
/// within their caps, cheaply, or reject it".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborScanError {
    /// A header or payload ran off the end of the buffer.
    Truncated,
    /// The frame does not open with a CBOR map.
    NotAMap,
    /// An indefinite-length item (or a stray break code) was encountered.
    ///
    /// ciborium never emits one for a serde type, so this is always hostile or
    /// hand-rolled — see the module docs.
    IndefiniteLength,
    /// A header used a reserved additional-info value (28–30).
    MalformedHeader(u8),
    /// The top-level map declared more than [`MAX_SCAN_MAP_KEYS`] pairs.
    TooManyMapKeys(u64),
    /// A top-level map key was not a text string.
    NonTextKey,
    /// A top-level map key declared more than [`MAX_SCAN_KEY_BYTES`] bytes.
    KeyTooLong(u64),
    /// The `entries` key's value was not a definite-length array.
    EntriesNotAnArray,
    /// The top-level map held no `entries` key.
    MissingEntries,
    /// A frame carried a top-level key its variant does not define (H-09).
    ///
    /// Only the allowlisted scans refuse this — see [`scan_supply_frame`]. The
    /// offending key is deliberately NOT carried: it is attacker-chosen text,
    /// this error is `Copy` and allocates nothing, and the variant's field set
    /// is three names an operator can read off the struct. What matters in a log
    /// is that the frame claimed to be something it was not shaped like.
    UnknownKey,
    /// A frame repeated a top-level key (H-09).
    ///
    /// ciborium serialises struct fields once each, so a repeat cannot come from
    /// an honest peer. Refusing it — rather than picking a winner the way a
    /// decoder would — is what keeps "this frame declares N entries"
    /// unambiguous, and stops a second `entries` from being smuggled past a
    /// harmless first one.
    DuplicateKey,
    /// The scan read [`MAX_SCAN_VISITS`] headers without finishing the walk.
    ///
    /// Also how an over-budget [`ElementKind::Struct`] element is refused, and
    /// how a frame that repeats a recognised key to draw the element-skip
    /// allowance twice runs the frame-wide pool dry (T43b, H-09).
    VisitBudgetExhausted,
    /// A skipped value nested deeper than [`MAX_SCAN_DEPTH`].
    DepthExceeded,
    /// A key named by an [`ArrayBound`] held something other than a
    /// definite-length array (T43b).
    ///
    /// The [`ArrayBound::EntriesNotAnArray`]-shaped counterpart for the general
    /// scan, carrying the bound's label so a log names the offending field.
    ///
    /// [`ArrayBound::EntriesNotAnArray`]: CborScanError::EntriesNotAnArray
    BoundedKeyNotAnArray(&'static str),
    /// An element of a bounded array was not a definite-length text string
    /// (T43b).
    ///
    /// Every array an [`ArrayBound`] names is a `Vec<String>` on the Rust side,
    /// so an element that is not text cannot decode anyway and cannot come from
    /// an honest peer. Refusing it — rather than skipping it like an
    /// unrecognised top-level value — is what makes the element walk provably
    /// one header plus one length jump per element, with nothing nested inside
    /// an array to spend the allowance or the depth budget on.
    NonTextArrayElement(&'static str),
}

impl std::fmt::Display for CborScanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(formatter, "truncated CBOR header"),
            Self::NotAMap => write!(formatter, "frame does not open with a CBOR map"),
            Self::IndefiniteLength => {
                write!(formatter, "indefinite-length CBOR item in a wire frame")
            }
            Self::MalformedHeader(byte) => {
                write!(formatter, "malformed CBOR header byte 0x{byte:02x}")
            }
            Self::TooManyMapKeys(pairs) => {
                write!(
                    formatter,
                    "map declares {pairs} pairs (max {MAX_SCAN_MAP_KEYS})"
                )
            }
            Self::NonTextKey => write!(formatter, "non-text map key"),
            Self::KeyTooLong(len) => {
                write!(
                    formatter,
                    "map key is {len} bytes (max {MAX_SCAN_KEY_BYTES})"
                )
            }
            Self::EntriesNotAnArray => {
                write!(formatter, "entries is not a definite-length array")
            }
            Self::MissingEntries => write!(formatter, "no entries key in the frame"),
            Self::UnknownKey => {
                write!(formatter, "undeclared top-level key in a wire frame")
            }
            Self::DuplicateKey => write!(formatter, "repeated top-level map key"),
            Self::VisitBudgetExhausted => {
                write!(
                    formatter,
                    "scan budget exhausted after {MAX_SCAN_VISITS} headers"
                )
            }
            Self::DepthExceeded => {
                write!(formatter, "CBOR nesting deeper than {MAX_SCAN_DEPTH}")
            }
            Self::BoundedKeyNotAnArray(label) => {
                write!(formatter, "{label} ids are not a definite-length array")
            }
            Self::NonTextArrayElement(label) => {
                write!(formatter, "non-text element in the {label} id array")
            }
        }
    }
}

impl std::error::Error for CborScanError {}

/// One parsed CBOR header, with its argument already consumed.
///
/// Payload bytes (for byte/text strings) are NOT consumed here — the caller
/// decides whether to read or skip them, which is what keeps the scan O(1) per
/// header regardless of how large a string a frame declares.
#[derive(Debug, Clone, Copy)]
enum Head {
    /// Major 0/1: an integer. Fully consumed.
    Integer,
    /// Major 2: byte string of this many bytes.
    Bytes(u64),
    /// Major 3: text string of this many bytes.
    Text(u64),
    /// Major 4: array of this many items.
    Array(u64),
    /// Major 5: map of this many pairs.
    Map(u64),
    /// Major 6: a tag; exactly one item follows it.
    Tag,
    /// Major 7: simple value or float. Fully consumed.
    Simple,
}

/// A budgeted, non-allocating cursor over CBOR headers.
struct Scanner<'a> {
    data: &'a [u8],
    pos: usize,
    visits: usize,
    /// Extra header reads granted for stepping over the elements of arrays whose
    /// counts have already been proven within cap (T43b).
    ///
    /// Separate from [`MAX_SCAN_VISITS`] so that proving a 4,096-id
    /// `head_txids` is within cap — and then walking past it to reach
    /// `directive_ids` — cannot buy a hostile frame any extra budget for the
    /// parts of the walk that are *not* bounded by a cap. See the module docs.
    granted: usize,
}

impl<'a> Scanner<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            visits: 0,
            granted: 0,
        }
    }

    /// Consume `N` bytes as a fixed array. No indexing, so no panic path.
    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CborScanError> {
        let end = self.pos.checked_add(N).ok_or(CborScanError::Truncated)?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(CborScanError::Truncated)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        self.pos = end;
        Ok(out)
    }

    /// Consume and return `len` payload bytes.
    fn take(&mut self, len: u64) -> Result<&'a [u8], CborScanError> {
        let len = usize::try_from(len).map_err(|_| CborScanError::Truncated)?;
        let end = self.pos.checked_add(len).ok_or(CborScanError::Truncated)?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(CborScanError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Skip `len` payload bytes without reading them.
    fn skip(&mut self, len: u64) -> Result<(), CborScanError> {
        self.take(len).map(|_| ())
    }

    /// Read one CBOR header, charging it to the visit budget.
    ///
    /// Indefinite-length items (additional info 31, including major 7's break
    /// code) are refused rather than followed — see the module docs for why an
    /// honest peer never sends one.
    fn head(&mut self) -> Result<Head, CborScanError> {
        self.visits += 1;
        if self.visits > MAX_SCAN_VISITS.saturating_add(self.granted) {
            return Err(CborScanError::VisitBudgetExhausted);
        }
        let initial = u8::from_be_bytes(self.take_array::<1>()?);
        let major = initial >> 5;
        let info = initial & 0x1f;
        let argument: u64 = match info {
            0..=23 => u64::from(info),
            24 => u64::from(u8::from_be_bytes(self.take_array::<1>()?)),
            25 => u64::from(u16::from_be_bytes(self.take_array::<2>()?)),
            26 => u64::from(u32::from_be_bytes(self.take_array::<4>()?)),
            27 => u64::from_be_bytes(self.take_array::<8>()?),
            31 => return Err(CborScanError::IndefiniteLength),
            _ => return Err(CborScanError::MalformedHeader(initial)),
        };
        Ok(match major {
            0 | 1 => Head::Integer,
            2 => Head::Bytes(argument),
            3 => Head::Text(argument),
            4 => Head::Array(argument),
            5 => Head::Map(argument),
            6 => Head::Tag,
            // `major` is three bits, so 7 (simple values and floats) is the only
            // remaining case; its payload, when it has one, was consumed as
            // `argument` above.
            _ => Head::Simple,
        })
    }

    /// Skip exactly one CBOR value, iteratively.
    ///
    /// Iterative rather than recursive on purpose: recursion on attacker-chosen
    /// nesting is a stack-overflow primitive, and a stack overflow is an abort,
    /// not an error. The explicit frame stack makes the depth bound checkable
    /// and the failure a [`CborScanError`].
    fn skip_value(&mut self) -> Result<(), CborScanError> {
        // Remaining item counts for each enclosing container. A fixed array
        // rather than a `Vec` because [`MAX_SCAN_DEPTH`] already bounds how deep
        // this can go, and because the scan's contract is that it allocates
        // NOTHING: T43 could honour that with a `Vec` only because every value
        // it skipped was a leaf, and H-09 sends it through `Supply` entries,
        // which are maps. A heap allocation per entry would be a small
        // allocation the guard performs on behalf of a hostile frame — the one
        // thing this module exists to avoid — and would land in
        // `decode_memory.rs`'s measurement besides.
        let mut enclosing = [0u64; MAX_SCAN_DEPTH];
        let mut depth: usize = 0;
        let mut remaining: u64 = 1;
        loop {
            // Unwind finished containers. Bounded by MAX_SCAN_DEPTH per turn.
            while remaining == 0 {
                let Some(outer) = depth.checked_sub(1) else {
                    return Ok(());
                };
                depth = outer;
                // `outer` is the depth just left, so it is below the depth
                // the push path bounded at MAX_SCAN_DEPTH and the slot is
                // always there. `get` states that rather than asserting it,
                // keeping the scanner free of indexing panics.
                remaining = *enclosing.get(outer).ok_or(CborScanError::DepthExceeded)?;
            }
            remaining -= 1;
            let items = match self.head()? {
                Head::Integer | Head::Simple => continue,
                Head::Bytes(len) | Head::Text(len) => {
                    self.skip(len)?;
                    continue;
                }
                // A tag is a prefix, not a container: one more item follows it
                // at this same level.
                Head::Tag => {
                    remaining = remaining
                        .checked_add(1)
                        .ok_or(CborScanError::MalformedHeader(0xc0))?;
                    continue;
                }
                Head::Array(count) => count,
                Head::Map(pairs) => pairs
                    .checked_mul(2)
                    .ok_or(CborScanError::MalformedHeader(0xa0))?,
            };
            if items == 0 {
                continue;
            }
            // The bounds check IS the depth check: `enclosing` is exactly
            // MAX_SCAN_DEPTH long, so a frame nesting past it lands on `None`.
            let slot = enclosing
                .get_mut(depth)
                .ok_or(CborScanError::DepthExceeded)?;
            *slot = remaining;
            depth += 1;
            remaining = items;
        }
    }

    /// Read the top-level map header and return its declared pair count.
    ///
    /// Shared by both public scans so "a frame is a definite-length map of at
    /// most [`MAX_SCAN_MAP_KEYS`] pairs" is stated once. Refusing an absurd pair
    /// count here, before the key loop, is what stops a header claiming
    /// `u64::MAX` pairs from turning the loop itself into the attack.
    fn open_top_level_map(&mut self) -> Result<u64, CborScanError> {
        let pairs = match self.head()? {
            Head::Map(pairs) => pairs,
            _ => return Err(CborScanError::NotAMap),
        };
        if pairs > MAX_SCAN_MAP_KEYS {
            return Err(CborScanError::TooManyMapKeys(pairs));
        }
        Ok(pairs)
    }

    /// Read one top-level map key and return its bytes.
    ///
    /// The only payload bytes either scan ever reads: at most
    /// [`MAX_SCAN_KEY_BYTES`] of them, and only so the key can be compared.
    fn map_key(&mut self) -> Result<&'a [u8], CborScanError> {
        let len = match self.head()? {
            Head::Text(len) => len,
            _ => return Err(CborScanError::NonTextKey),
        };
        if len > MAX_SCAN_KEY_BYTES {
            return Err(CborScanError::KeyTooLong(len));
        }
        self.take(len)
    }

    /// Step over `count` definite-length text strings — the elements of an array
    /// whose count is already proven within its cap (T43b).
    ///
    /// Grants itself the `count` header reads it needs and then consumes them
    /// **exactly**, because each element costs one header plus a jump over its
    /// payload and a non-text element is refused rather than descended into.
    /// That exactness is the whole reason the allowance can be handed out per
    /// array without leaking budget to the rest of the walk — and granting it
    /// here, rather than at the call site, is what keeps the grant and the walk
    /// it pays for from ever drifting apart.
    ///
    /// The caller owes one thing: `count` must already be within the array's
    /// cap, so that the grant is a constant derived from the caps rather than a
    /// number the frame chose.
    fn skip_text_elements(
        &mut self,
        count: usize,
        label: &'static str,
    ) -> Result<(), CborScanError> {
        self.granted = self.granted.saturating_add(count);
        for _ in 0..count {
            match self.head()? {
                Head::Text(len) => self.skip(len)?,
                _ => return Err(CborScanError::NonTextArrayElement(label)),
            }
        }
        Ok(())
    }

    /// Step over `count` whole CBOR values, each allowed at most `items` header
    /// reads — the elements of an array whose count is already proven within its
    /// cap (H-09).
    ///
    /// The counterpart of [`Self::skip_text_elements`] for
    /// [`ElementKind::Struct`], and the reason a `Supply`'s `entries` can be
    /// walked past at all. A struct element is a subtree of unbounded shape, so
    /// unlike a text element it cannot be priced from the cap: the budget has to
    /// be imposed. Each element gets `items`, and then two things happen to it:
    ///
    /// * **It is a ceiling, not just an allowance.** A grant only widens
    ///   [`Self::head`]'s comparison against `MAX_SCAN_VISITS + granted`, so an
    ///   element could otherwise also draw on however much of the top-level
    ///   budget the walk had not spent — which would make the per-element bound
    ///   `items + 64`, and a different number for every frame shape. Comparing
    ///   the spend against `items` afterwards makes it the flat bound the caller
    ///   sized `max × items` from. The overshoot before the comparison is
    ///   bounded by the same 64 and costs nothing but header reads.
    /// * **What it does not spend is handed back**, so `granted` ends up equal
    ///   to what the elements ACTUALLY spent. Without that, a frame of 256 empty
    ///   maps would bank ~17,000 unspent headers and could spend them on the
    ///   parts of the walk no cap covers; with it, [`MAX_SCAN_VISITS`] keeps
    ///   governing everything outside these arrays exactly as it did before.
    ///
    /// The caller owes the same thing [`Self::skip_text_elements`] is owed:
    /// `count` must already be within the array's cap, so the total is a
    /// constant derived from the caps rather than a number the frame chose.
    fn skip_struct_elements(&mut self, count: usize, items: usize) -> Result<(), CborScanError> {
        for _ in 0..count {
            let before = self.visits;
            self.granted = self.granted.saturating_add(items);
            self.skip_value()?;
            let spent = self.visits.saturating_sub(before);
            if spent > items {
                return Err(CborScanError::VisitBudgetExhausted);
            }
            self.granted = self.granted.saturating_sub(items - spent);
        }
        Ok(())
    }
}

/// The top-level keys a frame's variant defines, and which of them it has used
/// (H-09).
///
/// serde's `TaggedContentVisitor::visit_map` buffers EVERY pair of an
/// internally-tagged map into `Content` — keys the chosen variant has no field
/// for included, discarded only after the whole tree has been built — so an
/// undeclared key is amplification an honest sender has no reason to emit.
/// Refusing one is therefore free of compatibility cost in the direction that
/// matters: the frames it rejects are frames whose extra bytes the decoder was
/// going to throw away anyway.
///
/// The general scan over three variants at once cannot use this (their field
/// sets differ, so the union would be a weak allowlist and a new variant would
/// silently widen it); T26's 1 MiB byte cap and the visit budget bound that path
/// instead. The `Supply` path, which is the one admitted at the full 16 MiB, is
/// a single variant with a three-name field set.
struct KeyAllowlist<'a> {
    /// The keys the frame may carry, or `None` to tolerate any.
    keys: Option<&'a [&'static [u8]]>,
    /// Bit `i` set once `keys[i]` has been seen, for the duplicate check and
    /// for the "was it present?" question [`scan_supply_frame`] asks afterwards.
    seen: u16,
}

impl<'a> KeyAllowlist<'a> {
    /// Tolerate any top-level key (T43b's general scan).
    fn any() -> Self {
        Self {
            keys: None,
            seen: 0,
        }
    }

    /// Admit only `keys`, each at most once (H-09).
    ///
    /// The assertion is on the ALLOWLIST, never on the frame: it depends on a
    /// `&'static` constant this crate writes, so it either always holds or never
    /// does and no peer can reach it. [`MAX_SCAN_MAP_KEYS`] caps a frame at 16
    /// pairs, so an allowlist longer than `seen` can track would be pointless as
    /// well as untrackable.
    fn of(keys: &'a [&'static [u8]]) -> Self {
        assert!(
            keys.len() <= u16::BITS as usize,
            "a scan allowlist may name at most {} keys",
            u16::BITS
        );
        Self {
            keys: Some(keys),
            seen: 0,
        }
    }

    /// Position of `key` in the allowlist.
    ///
    /// Linear over a handful of entries, which is cheaper than any index at this
    /// size — the same reasoning `bounds` is searched on.
    fn position(&self, key: &[u8]) -> Option<usize> {
        self.keys?.iter().position(|allowed| *allowed == key)
    }

    /// Record one top-level key, refusing an undeclared or repeated one.
    fn admit(&mut self, key: &[u8]) -> Result<(), CborScanError> {
        if self.keys.is_none() {
            return Ok(());
        }
        let index = self.position(key).ok_or(CborScanError::UnknownKey)?;
        // `of` bounded the allowlist below `u16::BITS`, so the shift is in range.
        let bit = 1u16 << index;
        if self.seen & bit != 0 {
            return Err(CborScanError::DuplicateKey);
        }
        self.seen |= bit;
        Ok(())
    }

    /// Whether the frame carried `key`. Always false without an allowlist,
    /// which is why only [`scan_supply_frame`] asks.
    fn holds(&self, key: &[u8]) -> bool {
        self.position(key)
            .is_some_and(|index| self.seen & (1u16 << index) != 0)
    }
}

/// Walk a frame's whole top-level map, bounding every array in `bounds` that it
/// carries (T43, T43b, H-09).
///
/// The single mechanism behind both public scans, and the reason there is no
/// longer a second one to drift: T43's `supply_entry_count` was a separate walk
/// that returned at the first `entries` key, which is precisely the hole H-09
/// records. Everything either scan does — the map header, the key budget, the
/// unrecognised-value skip, the array headers, the element-skip allowance — is
/// here, once.
///
/// Every value is accounted for exactly one of three ways, and that exhaustive
/// split is what makes "nothing in this frame is unbounded" checkable:
///
/// * a value under a key no [`ArrayBound`] names goes through
///   [`Scanner::skip_value`] on the ordinary [`MAX_SCAN_VISITS`] budget, so a
///   wide or deep one is refused wherever in the map it sits;
/// * a bounded array over its cap is refused AT ITS HEADER, before an element
///   byte is touched;
/// * a bounded array within its cap is stepped over on the frame-wide allowance,
///   sized `Σ(bound.max × element cost)` from the caps themselves.
fn walk(
    body: &[u8],
    bounds: &[ArrayBound],
    keys: &mut KeyAllowlist<'_>,
) -> Result<ScanOutcome, CborScanError> {
    let mut scanner = Scanner::new(body);
    let pairs = scanner.open_top_level_map()?;
    // One frame-wide pool, sized from the caps themselves. An honest frame draws
    // from it once per array it carries and can never exhaust it, because the
    // arrays it carries are distinct and each is within its own cap. A frame
    // that repeats a recognised key to draw twice runs it dry, and the ordinary
    // visit budget then refuses the walk.
    let mut allowance: usize = bounds
        .iter()
        .map(|bound| bound.max.saturating_mul(bound.elements.header_cost()))
        .fold(0usize, usize::saturating_add);
    for _ in 0..pairs {
        let key = scanner.map_key()?;
        keys.admit(key)?;
        let Some(bound) = bounds.iter().find(|bound| bound.key == key) else {
            scanner.skip_value()?;
            continue;
        };
        let claimed = match scanner.head()? {
            Head::Array(count) => count,
            _ => return Err(CborScanError::BoundedKeyNotAnArray(bound.label)),
        };
        // A claim too large for `usize` is over any cap by definition, so this
        // needs no separate arm — and no cast that could wrap.
        let over_bound = || ScanOutcome::OverBound {
            label: bound.label,
            claimed,
            max: bound.max,
        };
        let Ok(count) = usize::try_from(claimed) else {
            return Ok(over_bound());
        };
        if count > bound.max {
            return Ok(over_bound());
        }
        // `count <= bound.max` from here, so the allowance this array draws is
        // bounded by the cap rather than by the frame's claim.
        let draw = count.saturating_mul(bound.elements.header_cost());
        let Some(remaining) = allowance.checked_sub(draw) else {
            return Err(CborScanError::VisitBudgetExhausted);
        };
        allowance = remaining;
        match bound.elements {
            ElementKind::Text => scanner.skip_text_elements(count, bound.label)?,
            ElementKind::Struct { items } => scanner.skip_struct_elements(count, items)?,
        }
    }
    Ok(ScanOutcome::WithinBounds)
}

/// Bound a frame that claims to be a `Supply`, from its array headers and its
/// key set alone (T43, rewritten by H-09).
///
/// The strict counterpart of [`scan_bounded_arrays`], for the one variant T26's
/// peek gate deliberately admits at the full 16 MiB `MAX_MESSAGE_SIZE` — and
/// therefore the one whose every byte has to be accounted for here rather than
/// by a byte cap. It is the same `walk`, with two rules added:
///
/// * **Every bound's key must be PRESENT.** A `Supply` without `entries` is
///   malformed, where a frame without `ids` is simply some other variant, so an
///   absent bound is [`CborScanError::MissingEntries`] rather than tolerated.
/// * **No key outside `allowed_keys`, and none of them twice.** serde buffers
///   undeclared keys into `Content` regardless of whether the variant wants
///   them, so they are amplification with no honest sender — see the module
///   docs. `allowed_keys` is the wire struct's real field set and must be a
///   superset of `bounds`' keys, or a bounded key could never be admitted.
///
/// T43's `supply_entry_count` stood here and returned the `entries` claim the
/// moment it found the key, never reading another pair; a frame that put
/// `"entries": []` SECOND hid everything behind it from the guard. This returns
/// the same verdicts through the general walk instead, so the `Supply` path can
/// no longer be the loose one.
pub fn scan_supply_frame(
    body: &[u8],
    bounds: &[ArrayBound],
    allowed_keys: &[&'static [u8]],
) -> Result<ScanOutcome, CborScanError> {
    debug_assert!(
        bounds.iter().all(|bound| allowed_keys.contains(&bound.key)),
        "a bounded key outside the allowlist could never be admitted"
    );
    let mut keys = KeyAllowlist::of(allowed_keys);
    let outcome = walk(body, bounds, &mut keys).map_err(|error| match error {
        // T43 named this case for `entries` specifically and callers log it by
        // that name. The general walk cannot know the key it refused is
        // `entries`, so the taxonomy is restored here rather than changed under
        // them.
        CborScanError::BoundedKeyNotAnArray(_) => CborScanError::EntriesNotAnArray,
        other => other,
    })?;
    for bound in bounds {
        if !keys.holds(bound.key) {
            return Err(CborScanError::MissingEntries);
        }
    }
    Ok(outcome)
}

/// Bound EVERY array in `bounds` that the frame actually carries, from the
/// array headers alone (T43b).
///
/// The tolerant counterpart to [`scan_supply_frame`], covering the three
/// non-`Supply` variants with one call. Two semantic differences, both
/// deliberate:
///
/// * **Tolerant of absence.** A `Supply` without `entries` is malformed; a frame
///   without `ids` is simply an `Announce`. A key no frame carries is not an
///   error here, and neither is a frame carrying none of them.
/// * **Tolerant of unrecognised keys.** Three variants share this scan, so an
///   allowlist could only be their union — weak, and silently widened by every
///   variant added. T26's `NON_SUPPLY_FRAME_CAP` bounds these frames to 1 MiB of
///   BYTES, which is the bound the `Supply` path cannot have and the reason it
///   needs the allowlist instead.
///
/// Everything else is T43's contract unchanged: headers only, no allocation, no
/// assumption about field order, and fail-closed on every structural hostility.
/// `bounds` is expected to be a handful of entries; it is searched linearly per
/// key, which is cheaper than any index at this size.
pub fn scan_bounded_arrays(
    body: &[u8],
    bounds: &[ArrayBound],
) -> Result<ScanOutcome, CborScanError> {
    walk(body, bounds, &mut KeyAllowlist::any())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        DirectiveKind, SupplyEntry, WireMessage, MAX_HAVE_HEADS, MAX_SUPPLY_ENTRIES,
        MAX_SUPPLY_ENTRY_ITEMS, MAX_WANT_IDS, NON_SUPPLY_ARRAY_BOUNDS, SUPPLY_ARRAY_BOUNDS,
        SUPPLY_TOP_LEVEL_KEYS, SUPPLY_TYPE_DISCRIMINATOR,
    };

    /// A maximal honest entry: every key the closed envelope set allows, which
    /// is the most CBOR items an entry can honestly be worth and therefore what
    /// `MAX_SUPPLY_ENTRY_ITEMS` has to cover (H-09).
    fn entry(index: usize) -> SupplyEntry {
        SupplyEntry {
            id: format!("{index:064x}"),
            kind: DirectiveKind::Open,
            economic_bean: "2024-01-01 open Assets:Cash USD".to_owned(),
            envelope: ledger::service::ENVELOPE_KEYS
                .iter()
                .map(|key| ((*key).to_owned(), format!("{index}")))
                .collect(),
        }
    }

    /// The `Supply` policy, as `prescan_frame` hands it over.
    fn scan_supply(frame: &[u8]) -> Result<ScanOutcome, CborScanError> {
        scan_supply_frame(frame, SUPPLY_ARRAY_BOUNDS, SUPPLY_TOP_LEVEL_KEYS)
    }

    /// The `"type": "supply"` + `"v": 1` prefix a real frame opens with, as
    /// ciborium emits it, followed by the `"entries"` key. Crafted frames append
    /// their own array header so the scan sees a genuine `Supply` shape.
    fn supply_prefix() -> Vec<u8> {
        let mut bytes = vec![0xa3];
        bytes.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        bytes.extend_from_slice(b"\x61v\x01");
        bytes.extend_from_slice(b"\x67entries");
        bytes
    }

    /// The honest path: real encoded frames pass the scan and still decode
    /// identically afterwards.
    ///
    /// This is also the proof the module's fail-closed rules rest on — it runs
    /// against bytes ciborium actually produced, so it pins that the top-level
    /// map and the `entries` array are BOTH definite-length (an indefinite head
    /// would make the scan return `IndefiniteLength` and the `unwrap` below
    /// fail), that the keys are text strings and all three are allowlisted, and
    /// that the whole map is walkable within the budgets at the field order
    /// serde emits.
    ///
    /// Since H-09 it pins one thing more, and the expensive-looking part is the
    /// point: every entry is a maximal one, so a 256-entry frame is walked
    /// element by element and every one of them has to fit
    /// `MAX_SUPPLY_ENTRY_ITEMS`. A budget the real encoding could not meet would
    /// break honest traffic on the next `Supply` a peer sent.
    #[test]
    fn honest_supply_frames_scan_within_their_bounds() {
        // 23/24 and 255/256 straddle CBOR's additional-info encoding boundaries
        // (inline, one-byte, two-byte), so all three argument widths are covered.
        for count in [0usize, 1, 23, 24, 255, MAX_SUPPLY_ENTRIES] {
            let message = WireMessage::supply((0..count).map(entry).collect());
            let cbor = message.to_cbor().unwrap();
            assert_eq!(
                scan_supply(&cbor),
                Ok(ScanOutcome::WithinBounds),
                "scan refused the real encoding at {count} entries"
            );
            assert_eq!(
                WireMessage::decode_checked(&cbor).unwrap(),
                message,
                "pre-scan must not disturb an honest round-trip at {count} entries"
            );
        }
        // The claim is read off the array the frame really carries, not guessed:
        // one entry over the cap is refused naming the count ciborium wrote.
        let over_cap = WireMessage::supply((0..MAX_SUPPLY_ENTRIES + 1).map(entry).collect());
        assert_eq!(
            scan_supply(&over_cap.to_cbor().unwrap()),
            Ok(ScanOutcome::OverBound {
                label: "supply",
                claimed: MAX_SUPPLY_ENTRIES as u64 + 1,
                max: MAX_SUPPLY_ENTRIES,
            })
        );
    }

    /// What an honestly-encoded entry actually costs the element-skip allowance,
    /// measured rather than assumed (H-09).
    ///
    /// `MAX_SUPPLY_ENTRY_ITEMS` is the bound that stops a frame hiding its
    /// amplification inside `entries`, so it has to sit above what the real
    /// encoder emits and well below anything that would let one entry matter.
    /// Binary-searching the budget an entry needs pins both halves: if a field
    /// or an envelope key is ever added, this fails with the new number rather
    /// than a peer being refused in production.
    #[test]
    fn an_honest_entry_costs_far_less_than_its_item_budget() {
        let frame = WireMessage::supply(vec![entry(0)]).to_cbor().unwrap();
        let needed = (1..=MAX_SUPPLY_ENTRY_ITEMS)
            .find(|items| {
                let bounds = [ArrayBound {
                    key: b"entries",
                    max: MAX_SUPPLY_ENTRIES,
                    label: "supply",
                    elements: ElementKind::Struct { items: *items },
                }];
                scan_supply_frame(&frame, &bounds, SUPPLY_TOP_LEVEL_KEYS)
                    == Ok(ScanOutcome::WithinBounds)
            })
            .expect("an honest entry must fit its own budget");
        assert_eq!(
            needed, 17,
            "an honest entry's item count changed: map header, 3 scalar fields, \
             the envelope key and header, and 2 per envelope key"
        );
        assert!(
            needed * 4 <= MAX_SUPPLY_ENTRY_ITEMS,
            "the budget must keep a 4x margin over the real encoding"
        );
    }

    /// The T43 hole itself: a ~30-byte frame whose `entries` header claims ten
    /// million elements is answered from the header alone, with no element bytes
    /// present at all.
    #[test]
    fn scan_refuses_a_forged_ten_million_element_claim_from_the_header() {
        let mut frame = supply_prefix();
        frame.extend_from_slice(&[0x9a]);
        frame.extend_from_slice(&10_000_000u32.to_be_bytes());
        assert!(frame.len() < 64, "the whole attack fits in a tiny frame");
        assert_eq!(
            scan_supply(&frame),
            Ok(ScanOutcome::OverBound {
                label: "supply",
                claimed: 10_000_000,
                max: MAX_SUPPLY_ENTRIES,
            })
        );
    }

    /// Field order is not assumed: `entries` is found wherever it sits, and —
    /// since H-09 — the walk carries on past it to the pairs behind.
    #[test]
    fn scan_finds_entries_at_any_key_position() {
        // {"entries": [], "type": "supply", "v": 1} — tag last, entries first.
        let mut frame = vec![0xa3];
        frame.extend_from_slice(b"\x67entries\x80");
        frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        frame.extend_from_slice(b"\x61v\x01");
        assert_eq!(scan_supply(&frame), Ok(ScanOutcome::WithinBounds));
    }

    // ─── H-09: the short-circuit, and the keys serde buffers anyway ──────────

    /// THE H-09 frame: `"entries": []` placed second, with the payload behind
    /// it.
    ///
    /// T43's scan returned `Ok(0)` here and never read another pair, so a
    /// sixteen-million-item array sitting two keys later reached serde intact —
    /// 805 MB of `Content` for 16 MB of input, decoding SUCCESSFULLY as an empty
    /// `Supply` so that nothing was logged and nothing failed. Refused twice
    /// over now: the key is undeclared, and the array behind it would have blown
    /// the visit budget anyway. `decode_memory.rs` measures the peak; this pins
    /// the verdict on a fixture small enough to read.
    #[test]
    fn scan_sees_past_an_empty_entries_array_to_the_rest_of_the_map() {
        // {"type": "supply", "entries": [], "v": 1, "z": [10 M items]}
        let mut frame = vec![0xa4];
        frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        frame.extend_from_slice(b"\x67entries\x80");
        frame.extend_from_slice(b"\x61v\x01");
        frame.extend_from_slice(b"\x61z");
        frame.extend_from_slice(&array_header_claiming(10_000_000));
        assert!(frame.len() < 64, "the whole attack fits in a tiny frame");
        assert_eq!(scan_supply(&frame), Err(CborScanError::UnknownKey));

        // The same payload under a key the variant DOES define, so the
        // allowlist cannot be what refuses it: the walk still has to reach the
        // value and hold it to the visit budget.
        let mut declared_key = vec![0xa3];
        declared_key.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        declared_key.extend_from_slice(b"\x67entries\x80");
        declared_key.extend_from_slice(b"\x61v");
        declared_key.extend_from_slice(&empty_string_array(1_000));
        assert_eq!(
            scan_supply(&declared_key),
            Err(CborScanError::VisitBudgetExhausted)
        );
    }

    /// The other half of the same hole: the payload hidden INSIDE `entries`.
    ///
    /// One element is within `MAX_SUPPLY_ENTRIES` by a factor of 256, so no
    /// bound on the entry COUNT can see this — T43's header claim said `1` and
    /// was perfectly true. `ElementKind::Struct` is what refuses it: the entry
    /// is walked, and it runs out of its item budget long before its ten
    /// millionth item.
    #[test]
    fn scan_bounds_what_one_entry_may_nest() {
        // {"type": "supply", "v": 1, "entries": [[1,000 items]]} — one entry,
        // holding an array of a thousand. A real one is worth 17 items.
        let mut frame = supply_prefix();
        frame.push(0x81); // entries: exactly one element…
        frame.extend_from_slice(&empty_string_array(1_000)); // …a bomb.
        assert_eq!(
            scan_supply(&frame),
            Err(CborScanError::VisitBudgetExhausted)
        );

        // The same shape with nothing behind the claim is refused too, just by
        // the buffer rather than the budget: the walk never gets to spend the
        // ten million header reads the array asks for.
        let mut truncated = supply_prefix();
        truncated.push(0x81);
        truncated.extend_from_slice(&array_header_claiming(10_000_000));
        assert!(
            truncated.len() < 64,
            "the whole attack fits in a tiny frame"
        );
        assert_eq!(scan_supply(&truncated), Err(CborScanError::Truncated));

        // Flat rather than nested, and spread over the full entry cap: 256
        // entries of 1,000 items each. Every entry is a legal CBOR array and
        // the count is exactly at the cap, so only the per-entry budget
        // separates this from honest traffic.
        let mut spread = supply_prefix();
        spread.push(0x99);
        spread.extend_from_slice(&(MAX_SUPPLY_ENTRIES as u16).to_be_bytes());
        for _ in 0..MAX_SUPPLY_ENTRIES {
            spread.extend_from_slice(&empty_string_array(1_000));
        }
        assert_eq!(
            scan_supply(&spread),
            Err(CborScanError::VisitBudgetExhausted)
        );
    }

    /// An entry cheaper than its budget does not bank the difference.
    ///
    /// 256 empty maps cost one header each against a budget of 68, so a walker
    /// that granted the budget rather than the spend would leave ~17,000 header
    /// reads on the table — enough to step over a bomb behind them. The reclaim
    /// in `skip_struct_elements` is what keeps the ordinary 64-visit budget
    /// governing everything outside the array.
    #[test]
    fn scan_hands_back_the_item_budget_an_entry_does_not_spend() {
        // {"type": "supply", "entries": [{} × 256], "v": [0 × 1000]}
        let mut frame = vec![0xa3];
        frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        frame.extend_from_slice(b"\x67entries\x99");
        frame.extend_from_slice(&(MAX_SUPPLY_ENTRIES as u16).to_be_bytes());
        frame.extend(std::iter::repeat_n(0xa0u8, MAX_SUPPLY_ENTRIES));
        frame.extend_from_slice(b"\x61v");
        frame.push(0x99);
        frame.extend_from_slice(&1000u16.to_be_bytes());
        frame.extend(std::iter::repeat_n(0x00u8, 1000));
        assert_eq!(
            scan_supply(&frame),
            Err(CborScanError::VisitBudgetExhausted)
        );
    }

    /// Undeclared and repeated top-level keys are both refused (H-09).
    ///
    /// serde buffers either one into `Content` regardless of whether the variant
    /// wants it, so neither has an honest sender — and a repeated `entries`
    /// would additionally make "how many entries does this frame declare?"
    /// ambiguous, which is the question the whole gate exists to answer.
    #[test]
    fn scan_rejects_undeclared_and_repeated_supply_keys() {
        // A single undeclared key, with a harmless value.
        let mut undeclared = vec![0xa4];
        undeclared.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        undeclared.extend_from_slice(b"\x61v\x01");
        undeclared.extend_from_slice(b"\x67entries\x80");
        undeclared.extend_from_slice(b"\x61z\x01");
        assert_eq!(scan_supply(&undeclared), Err(CborScanError::UnknownKey));

        // A 16 MiB text string under an undeclared key: cheap for the scan to
        // skip (one header and a length jump), a 16 MiB `Content::String` for
        // serde. Skipping it is exactly what the allowlist is for.
        let mut fat_value = vec![0xa4];
        fat_value.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        fat_value.extend_from_slice(b"\x61v\x01");
        fat_value.extend_from_slice(b"\x67entries\x80");
        fat_value.extend_from_slice(b"\x61z\x7a");
        fat_value.extend_from_slice(&(16u32 * 1024 * 1024).to_be_bytes());
        assert_eq!(scan_supply(&fat_value), Err(CborScanError::UnknownKey));

        // `entries` twice: the first empty and harmless, the second the payload.
        let mut repeated = vec![0xa4];
        repeated.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        repeated.extend_from_slice(b"\x61v\x01");
        repeated.extend_from_slice(b"\x67entries\x80");
        repeated.extend_from_slice(b"\x67entries");
        repeated.extend_from_slice(&array_header_claiming(10_000_000));
        assert_eq!(scan_supply(&repeated), Err(CborScanError::DuplicateKey));

        // A repeat of an ordinary key is refused on the same rule.
        let mut repeated_scalar = vec![0xa4];
        repeated_scalar.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        repeated_scalar.extend_from_slice(b"\x61v\x01");
        repeated_scalar.extend_from_slice(b"\x61v\x01");
        repeated_scalar.extend_from_slice(b"\x67entries\x80");
        assert_eq!(
            scan_supply(&repeated_scalar),
            Err(CborScanError::DuplicateKey)
        );
    }

    /// An indefinite-length `entries` array is refused, not followed. ciborium
    /// never emits one (see `honest_supply_frames_scan_within_their_bounds`),
    /// so this can only be hand-rolled.
    #[test]
    fn scan_rejects_an_indefinite_length_entries_array() {
        let mut frame = supply_prefix();
        frame.push(0x9f); // array(*)
        frame.push(0xff); // break
        assert_eq!(scan_supply(&frame), Err(CborScanError::IndefiniteLength));
    }

    /// Same rule at the top level: an indefinite-length map is refused before
    /// any key is read.
    #[test]
    fn scan_rejects_an_indefinite_length_top_level_map() {
        let mut frame = vec![0xbf]; // map(*)
        frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        frame.push(0xff);
        assert_eq!(scan_supply(&frame), Err(CborScanError::IndefiniteLength));
    }

    /// A nesting bomb in a SKIPPED value dies on the depth bound, not on the
    /// call stack.
    #[test]
    fn scan_rejects_a_nesting_bomb_in_a_skipped_value() {
        // {"v": [[[[[...]]]]], ...} — 64 nested single-element arrays.
        let mut frame = vec![0xa3];
        frame.extend_from_slice(b"\x61v");
        frame.extend(std::iter::repeat_n(0x81u8, 64));
        frame.push(0x00);
        assert_eq!(scan_supply(&frame), Err(CborScanError::DepthExceeded));
    }

    /// A WIDE skipped value dies on the visit budget: the scan cannot be made
    /// expensive by a value it never needed to look at.
    #[test]
    fn scan_rejects_a_wide_skipped_value_on_the_visit_budget() {
        // {"v": [0 × 1000], "entries": [...]} — flat, shallow, and far past the
        // budget, so depth alone would not have caught it.
        let mut frame = vec![0xa3];
        frame.extend_from_slice(b"\x61v");
        frame.push(0x99);
        frame.extend_from_slice(&1000u16.to_be_bytes());
        frame.extend(std::iter::repeat_n(0x00u8, 1000));
        frame.extend_from_slice(b"\x67entries\x80");
        assert_eq!(
            scan_supply(&frame),
            Err(CborScanError::VisitBudgetExhausted)
        );
    }

    /// A map header claiming a colossal pair count is refused up front rather
    /// than driving the key loop.
    #[test]
    fn scan_rejects_an_absurd_top_level_key_count() {
        let mut frame = vec![0xbb]; // map, 8-byte argument
        frame.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            scan_supply(&frame),
            Err(CborScanError::TooManyMapKeys(u64::MAX))
        );
    }

    /// Structural refusals, one per fail-closed rule.
    #[test]
    fn scan_rejects_malformed_frame_shapes() {
        assert_eq!(scan_supply(&[]), Err(CborScanError::Truncated));
        // An array, not a map.
        assert_eq!(scan_supply(&[0x80]), Err(CborScanError::NotAMap));
        // Reserved additional info (28).
        assert_eq!(
            scan_supply(&[0xbc]),
            Err(CborScanError::MalformedHeader(0xbc))
        );
        // Integer key instead of a text key.
        assert_eq!(
            scan_supply(&[0xa1, 0x01, 0x01]),
            Err(CborScanError::NonTextKey)
        );
        // A key claiming 65_535 bytes.
        assert_eq!(
            scan_supply(&[0xa1, 0x79, 0xff, 0xff]),
            Err(CborScanError::KeyTooLong(65_535))
        );
        // `entries` present but not an array.
        let mut not_an_array = vec![0xa1];
        not_an_array.extend_from_slice(b"\x67entries\x01");
        assert_eq!(
            scan_supply(&not_an_array),
            Err(CborScanError::EntriesNotAnArray)
        );
        // A well-formed map with no `entries` key at all.
        let mut no_entries = vec![0xa1];
        no_entries.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        assert_eq!(scan_supply(&no_entries), Err(CborScanError::MissingEntries));
        // The `entries` key is there but its value is cut off.
        let mut truncated = supply_prefix();
        truncated.push(0x9a);
        assert_eq!(scan_supply(&truncated), Err(CborScanError::Truncated));
    }

    /// Tags and empty containers are skipped correctly — a tagged value ahead of
    /// `entries` must not desynchronise the key loop.
    #[test]
    fn scan_skips_tagged_and_empty_values() {
        // {"v": 0("x"), "type": [], "entries": [1 element]} — the tag's value
        // is an empty array rather than text, which the scan does not care
        // about: only that skipping it leaves the cursor on the next key.
        let mut frame = vec![0xa3];
        frame.extend_from_slice(b"\x61v\xc0\x61x");
        frame.extend_from_slice(b"\x64type\x80");
        frame.extend_from_slice(b"\x67entries\x81\x00");
        assert_eq!(scan_supply(&frame), Ok(ScanOutcome::WithinBounds));
    }

    // ─── T43b: the general walk over every bounded array ─────────────────────

    /// An array header claiming `count` elements, in CBOR's four-byte argument
    /// form, with no element bytes behind it.
    fn array_header_claiming(count: u32) -> Vec<u8> {
        let mut header = vec![0x9a];
        header.extend_from_slice(&count.to_be_bytes());
        header
    }

    /// An honest-looking array of `count` empty text strings (`0x60` each) —
    /// cardinality without bulk, so a full 4,096-element page stays a 4 KiB
    /// fixture.
    fn empty_string_array(count: u32) -> Vec<u8> {
        let mut array = array_header_claiming(count);
        array.extend(std::iter::repeat_n(0x60u8, count as usize));
        array
    }

    fn hex_ids(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("{index:064x}")).collect()
    }

    fn scan(frame: &[u8]) -> Result<ScanOutcome, CborScanError> {
        scan_bounded_arrays(frame, NON_SUPPLY_ARRAY_BOUNDS)
    }

    /// The honest path for every non-`Supply` variant, against REAL encoded
    /// bytes at the cardinality boundaries production actually emits.
    ///
    /// This is the T43b counterpart of
    /// `honest_supply_frames_scan_to_their_entry_count`, and carries the same
    /// burden of proof: it pins that ciborium emits definite lengths for these
    /// variants too (an indefinite head anywhere would make `scan` return
    /// `IndefiniteLength`), that their keys are text and within
    /// `MAX_SCAN_KEY_BYTES`, that their maps are within `MAX_SCAN_MAP_KEYS`, and
    /// — the T43b-specific part — that the element-skip allowance is enough to
    /// walk a page that is full in BOTH of `HaveHeads`' arrays, with `more` set
    /// exactly as `paginate_have_heads` sets it.
    #[test]
    fn honest_non_supply_frames_scan_within_their_bounds() {
        let mut frames = vec![
            WireMessage::announce("f".repeat(64), DirectiveKind::Transaction),
            WireMessage::want(Vec::new()),
        ];
        // 23/24 and 255/256 straddle CBOR's additional-info encoding boundaries.
        for count in [1usize, 23, 24, 255, 256, MAX_WANT_IDS] {
            frames.push(WireMessage::want(hex_ids(count)));
        }
        for count in [0usize, 1, MAX_HAVE_HEADS] {
            for more in [false, true] {
                frames.push(WireMessage::have_heads_page(
                    hex_ids(count),
                    hex_ids(count),
                    more,
                ));
            }
        }
        // The asymmetric pages `paginate_have_heads` produces when one list runs
        // out before the other: a full array beside an absent one.
        frames.push(WireMessage::have_heads(hex_ids(MAX_HAVE_HEADS), Vec::new()));
        frames.push(WireMessage::have_heads(Vec::new(), hex_ids(MAX_HAVE_HEADS)));

        for message in frames {
            let cbor = message.to_cbor().unwrap();
            assert_eq!(
                scan(&cbor),
                Ok(ScanOutcome::WithinBounds),
                "scan refused an honest frame: {message:?}"
            );
            assert_eq!(
                WireMessage::decode_checked(&cbor).unwrap(),
                message,
                "the pre-scan must not disturb an honest round-trip"
            );
        }
    }

    /// The case the element-skip allowance exists for: `HaveHeads` has TWO
    /// arrays, so a forged second one is only reachable by walking all the way
    /// through an honest-full first one.
    ///
    /// The first array holds exactly `MAX_HAVE_HEADS` elements — far past the
    /// 64-visit budget the T43 scan ran on — and the second claims ten million
    /// with no elements at all behind it. A walker that stopped at the first
    /// array, or that ran out of budget inside it, would return `WithinBounds`
    /// or `VisitBudgetExhausted` here rather than naming the second array.
    #[test]
    fn scan_reaches_the_second_bounded_array_through_a_full_first() {
        let mut frame = vec![0xa4];
        frame.extend_from_slice(b"\x64type\x6ahave_heads");
        frame.extend_from_slice(b"\x61v\x01");
        frame.extend_from_slice(b"\x6ahead_txids");
        frame.extend_from_slice(&empty_string_array(MAX_HAVE_HEADS as u32));
        frame.extend_from_slice(b"\x6ddirective_ids");
        frame.extend_from_slice(&array_header_claiming(10_000_000));
        assert_eq!(
            scan(&frame),
            Ok(ScanOutcome::OverBound {
                label: "have_heads",
                claimed: 10_000_000,
                max: MAX_HAVE_HEADS,
            })
        );
    }

    /// An over-cap array is refused at its HEADER, so its elements are never
    /// walked and never have to exist.
    ///
    /// The frame claims ten million ids and then simply stops. `Truncated` here
    /// would mean the scan had started walking the array before judging it — the
    /// exact cost the gate exists to avoid.
    #[test]
    fn scan_refuses_an_over_cap_array_without_walking_it() {
        let mut frame = vec![0xa3];
        frame.extend_from_slice(b"\x64type\x64want");
        frame.extend_from_slice(b"\x61v\x01");
        frame.extend_from_slice(b"\x63ids");
        frame.extend_from_slice(&array_header_claiming(10_000_000));
        assert!(frame.len() < 64, "the whole attack fits in a tiny frame");
        assert_eq!(
            scan(&frame),
            Ok(ScanOutcome::OverBound {
                label: "want",
                claimed: 10_000_000,
                max: MAX_WANT_IDS,
            })
        );
    }

    /// The element-skip allowance is drawn from ONE frame-wide pool sized
    /// `Σ(bound.max)` = 9,216, so a frame cannot mint budget by repeating a
    /// recognised key.
    ///
    /// Three full `head_txids` arrays ask for 12,288 element reads. The first
    /// two are granted (8,192) and the third runs the pool dry — which is the
    /// property that makes the general walk bounded by the caps rather than by
    /// how many times a frame is willing to repeat itself.
    #[test]
    fn scan_element_allowance_is_capped_across_the_whole_frame() {
        let mut frame = vec![0xa3];
        for _ in 0..3 {
            frame.extend_from_slice(b"\x6ahead_txids");
            frame.extend_from_slice(&empty_string_array(MAX_HAVE_HEADS as u32));
        }
        assert_eq!(scan(&frame), Err(CborScanError::VisitBudgetExhausted));
    }

    /// The allowance does not leak into the rest of the walk: an UNRECOGNISED
    /// value is still held to the tight 64-visit budget even in a frame that
    /// also carries a bounded array.
    ///
    /// Without this the grant would be a way to buy budget for the skipper,
    /// which is the part of the scan an attacker actually controls the shape of.
    #[test]
    fn scan_allowance_does_not_relax_the_top_level_visit_budget() {
        // {"ids": [4 elements], "v": [0 × 1000]} — the array is honest and tiny,
        // the skipped value is flat, shallow and far past the budget.
        let mut frame = vec![0xa2];
        frame.extend_from_slice(b"\x63ids");
        frame.extend_from_slice(&empty_string_array(4));
        frame.extend_from_slice(b"\x61v");
        frame.push(0x99);
        frame.extend_from_slice(&1000u16.to_be_bytes());
        frame.extend(std::iter::repeat_n(0x00u8, 1000));
        assert_eq!(scan(&frame), Err(CborScanError::VisitBudgetExhausted));
    }

    /// Elements of a bounded array must be definite-length text strings, so a
    /// bomb nested inside one is refused at its first header rather than walked.
    ///
    /// Every bounded array is a `Vec<String>`, so a non-text element could never
    /// have decoded anyway. Refusing it (rather than skipping it the way an
    /// unrecognised top-level value is skipped) is what makes the element walk
    /// exactly one header plus one length jump per element — the accounting the
    /// allowance depends on.
    #[test]
    fn scan_rejects_a_non_text_element_in_a_bounded_array() {
        // {"ids": [[[[[...]]]]]} — one element, 64 nested single-element arrays.
        let mut nested = vec![0xa1];
        nested.extend_from_slice(b"\x63ids\x81");
        nested.extend(std::iter::repeat_n(0x81u8, 64));
        nested.push(0x00);
        assert_eq!(
            scan(&nested),
            Err(CborScanError::NonTextArrayElement("want"))
        );

        // {"head_txids": [0]} — a flat integer element, refused on the same rule.
        let mut integer_element = vec![0xa1];
        integer_element.extend_from_slice(b"\x6ahead_txids\x81\x00");
        assert_eq!(
            scan(&integer_element),
            Err(CborScanError::NonTextArrayElement("have_heads"))
        );
    }

    /// A recognised key whose value is not a definite-length array is refused,
    /// naming the bound it broke.
    #[test]
    fn scan_rejects_a_bounded_key_that_is_not_an_array() {
        // {"ids": 1}
        let mut integer = vec![0xa1];
        integer.extend_from_slice(b"\x63ids\x01");
        assert_eq!(
            scan(&integer),
            Err(CborScanError::BoundedKeyNotAnArray("want"))
        );
        // {"directive_ids": [*...]} — indefinite length, which ciborium never
        // emits for a serde type.
        let mut indefinite = vec![0xa1];
        indefinite.extend_from_slice(b"\x6ddirective_ids\x9f\xff");
        assert_eq!(scan(&indefinite), Err(CborScanError::IndefiniteLength));
    }

    /// Absent keys are TOLERATED — the one semantic difference from
    /// [`scan_supply_frame`], which treats a missing `entries` as malformed.
    ///
    /// A non-`Supply` frame need carry no bounded array at all: that is what an
    /// `Announce` is. Structural hostility is still refused, so the tolerance is
    /// about which keys are present, not about how well-formed the frame is.
    #[test]
    fn scan_tolerates_frames_carrying_no_bounded_array() {
        // An empty map: no `ids`, no error — where the `Supply` scan refuses.
        assert_eq!(scan(&[0xa0]), Ok(ScanOutcome::WithinBounds));
        assert_eq!(scan_supply(&[0xa0]), Err(CborScanError::MissingEntries));
        // A map of unrecognised keys with leaf values.
        let mut announce_shaped = vec![0xa2];
        announce_shaped.extend_from_slice(b"\x64type\x68announce");
        announce_shaped.extend_from_slice(b"\x62id\x61x");
        assert_eq!(scan(&announce_shaped), Ok(ScanOutcome::WithinBounds));
        // Tolerance stops at structure: the same rules T43 fails closed on.
        assert_eq!(scan(&[]), Err(CborScanError::Truncated));
        assert_eq!(scan(&[0x80]), Err(CborScanError::NotAMap));
        assert_eq!(scan(&[0xbf]), Err(CborScanError::IndefiniteLength));
        assert_eq!(scan(&[0xa1, 0x01, 0x01]), Err(CborScanError::NonTextKey));
        let mut absurd = vec![0xbb];
        absurd.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(scan(&absurd), Err(CborScanError::TooManyMapKeys(u64::MAX)));
    }

    /// The crafted prefixes the T43b tests build by hand are the bytes ciborium
    /// really emits, so a forged frame is a genuine `Want`/`HaveHeads` right up
    /// to the array header that lies.
    ///
    /// The T43b analogue of `supply_discriminator_pins_wire_format`: if the
    /// encoding ever drifts, the crafted frames stop testing what they claim to,
    /// and this fails rather than quietly passing.
    #[test]
    fn crafted_non_supply_prefixes_match_real_encodings() {
        assert_eq!(
            WireMessage::want(Vec::new()).to_cbor().unwrap(),
            b"\xa3\x64type\x64want\x61v\x01\x63ids\x80",
            "a `Want` must encode as a 3-pair map ending in an empty ids array"
        );
        let paged = WireMessage::have_heads_page(Vec::new(), vec!["x".to_owned()], true)
            .to_cbor()
            .unwrap();
        assert!(
            paged.starts_with(b"\xa5\x64type\x6ahave_heads\x61v\x01\x6ahead_txids"),
            "unexpected have_heads prefix: {paged:02x?}"
        );
        assert!(
            paged
                .windows(14)
                .any(|window| window == b"\x6ddirective_ids"),
            "unexpected directive_ids key encoding: {paged:02x?}"
        );
        // A 4-pair map when `more` is false, 3 when `directive_ids` is empty too
        // — which is why the crafted frames set their own header byte.
        assert_eq!(
            WireMessage::have_heads(Vec::new(), vec!["x".to_owned()])
                .to_cbor()
                .unwrap()[0],
            0xa4
        );
        assert_eq!(
            WireMessage::have_heads(Vec::new(), Vec::new())
                .to_cbor()
                .unwrap()[0],
            0xa3
        );
    }
}
