//! Bounded CBOR header scan for the M-16 pre-decode gate (T43).
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
//! [`supply_entry_count`] answers "how many elements does this frame's
//! `entries` array header claim?" by walking CBOR **headers only**, touching no
//! payload bytes and allocating nothing on the honest path. The answer is
//! compared against `MAX_SUPPLY_ENTRIES` before serde is handed the buffer, so
//! the cardinality cap now runs where it always should have: on the wire bytes,
//! not on the materialised tree.
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
//! from [`supply_entry_count`] in exactly one deliberate way: a `Supply` **must**
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
//! A `SupplyEntry` is a fixed four-field struct of scalars plus one
//! `BTreeMap<String, String>`; its nested structure is therefore bounded by the
//! frame's byte length, not by a second independent count. 256 entries inside
//! 16 MiB is at most a few thousand `Content` nodes — a constant multiple of the
//! frame, which is exactly what `decode_memory.rs` asserts. The `Want` and
//! `HaveHeads` arrays are `Vec<String>`: leaves, so the same argument applies
//! with nothing nested at all.
//!
//! # The element-skip allowance (T43b)
//!
//! [`supply_entry_count`] answers and returns the moment it finds `entries`, so
//! it never walks an array's elements and [`MAX_SCAN_VISITS`] alone bounds it.
//! [`scan_bounded_arrays`] cannot stop at the first array: a `HaveHeads` has
//! **two**, and an honest-full `head_txids` sits between the scan and
//! `directive_ids`. Walking past 4,096 element headers on a 64-visit budget is
//! impossible, so the general scan carries a second, separate allowance:
//!
//! * A recognised array is bounded **at its header**: a claim over its cap is
//!   refused before a single element byte is touched, so an over-cap array is
//!   never walked and never paid for.
//! * A claim **within** its cap is already proven bounded by the cap, so the
//!   scan grants itself exactly `count` extra header reads to step over that
//!   array's elements — and consumes them exactly, because every element must be
//!   a definite-length text string (one header, then a length jump over the
//!   payload). Nothing nested can appear inside to spend more.
//! * The grants are drawn from one frame-wide pool of `Σ(bound.max)` — 9,216
//!   headers for the three arrays `WireMessage` has. A frame that repeats a
//!   recognised key to ask for the allowance twice runs the pool dry and is
//!   refused on the visit budget.
//!
//! So the general walk is bounded by the caps themselves, by construction,
//! rather than by a hand-picked number: at most `MAX_SCAN_VISITS + Σ(bound.max)`
//! header reads, each consuming at least one byte of a frame the receive path
//! has already read. The top-level visit, key-count and key-length budgets stay
//! exactly as tight as T43 set them.
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
//!   depth zero, so every bound here sits at least an order of magnitude above
//!   the traffic it has to pass.
//!
//! The scan deliberately does not assume field ORDER. serde emits the tag first
//! and ciborium preserves struct order (`type`, `v`, `entries` — verified by
//! inspecting real encoded bytes), but the loop reads keys generically and skips
//! whatever it does not recognise, so a reordered or extended map still finds
//! `entries` as long as it stays inside the budget.
//!
//! T43b widens those same rules from "every `Supply` frame" to "every frame",
//! which raises the bar for a future `WireMessage` variant: it must still encode
//! as a definite-length map of at most [`MAX_SCAN_MAP_KEYS`] text keys of at most
//! [`MAX_SCAN_KEY_BYTES`] bytes, and any new unbounded array it adds wants a
//! [`ArrayBound`] beside the others. Every variant today is a three-to-five-field
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
/// T43b does **not** relax this. [`scan_bounded_arrays`] has to step over the
/// elements of arrays it has already proven to be within cap, and pays for that
/// out of a separate per-array allowance (see the module docs) rather than out
/// of this budget, so the bound on everything *else* the general walk does — map
/// header, keys, unrecognised values — stays exactly where T43 put it.
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

/// The map key whose array header carries the `Supply` entry count.
const ENTRIES_KEY: &[u8] = b"entries";

/// One top-level array [`scan_bounded_arrays`] knows how to bound (T43b).
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
    /// The scan read [`MAX_SCAN_VISITS`] headers without reaching `entries`.
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
        // Remaining item counts for each enclosing container. Never allocates on
        // the honest path, where every skipped value is a leaf.
        let mut enclosing: Vec<u64> = Vec::new();
        let mut remaining: u64 = 1;
        loop {
            // Unwind finished containers. Bounded by MAX_SCAN_DEPTH per turn.
            while remaining == 0 {
                match enclosing.pop() {
                    Some(outer) => remaining = outer,
                    None => return Ok(()),
                }
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
            if enclosing.len() >= MAX_SCAN_DEPTH {
                return Err(CborScanError::DepthExceeded);
            }
            enclosing.push(remaining);
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
}

/// Read the element count the frame's `entries` array header CLAIMS, without
/// decoding the frame (T43).
///
/// The returned count is the header's claim, not a verified element count —
/// that is the point: it is available after ~7 header reads, before serde has
/// allocated anything, and a claim above `MAX_SUPPLY_ENTRIES` is sufficient
/// grounds to refuse the frame. A claim *within* the cap still has to survive
/// the ordinary decode, which will fail on a frame whose body does not match.
///
/// Fails closed: see the module docs for why every rejection below is
/// unreachable for an honest peer.
pub fn supply_entry_count(body: &[u8]) -> Result<u64, CborScanError> {
    let mut scanner = Scanner::new(body);
    let pairs = scanner.open_top_level_map()?;
    for _ in 0..pairs {
        if scanner.map_key()? == ENTRIES_KEY {
            return match scanner.head()? {
                Head::Array(count) => Ok(count),
                _ => Err(CborScanError::EntriesNotAnArray),
            };
        }
        scanner.skip_value()?;
    }
    Err(CborScanError::MissingEntries)
}

/// Bound EVERY array in `bounds` that the frame actually carries, from the
/// array headers alone (T43b).
///
/// The general counterpart to [`supply_entry_count`], and the reason this module
/// now covers the whole `WireMessage` enum rather than its one worst variant.
/// Two semantic differences, both deliberate:
///
/// * **Tolerant of absence.** A `Supply` without `entries` is malformed; a frame
///   without `ids` is simply an `Announce`. A key no frame carries is not an
///   error here, and neither is a frame carrying none of them.
/// * **It enforces, rather than reports.** [`supply_entry_count`] returns a claim
///   for the caller to judge, because it stops at the first array. This one has
///   to keep walking to reach a second array, so it judges each claim **at the
///   header** — an over-cap array is refused with [`ScanOutcome::OverBound`]
///   before a single one of its elements is touched — and only then spends the
///   element-skip allowance described in the module docs to step over an array
///   it has proven safe.
///
/// Everything else is T43's contract unchanged: headers only, no allocation, no
/// assumption about field order, and fail-closed on every structural hostility.
/// `bounds` is expected to be a handful of entries; it is searched linearly per
/// key, which is cheaper than any index at this size.
pub fn scan_bounded_arrays(
    body: &[u8],
    bounds: &[ArrayBound],
) -> Result<ScanOutcome, CborScanError> {
    let mut scanner = Scanner::new(body);
    let pairs = scanner.open_top_level_map()?;
    // One frame-wide pool, sized from the caps themselves. An honest frame draws
    // from it once per array it carries and can never exhaust it, because the
    // arrays it carries are distinct and each is within its own cap. A frame
    // that repeats a recognised key to draw twice runs it dry, and the ordinary
    // visit budget then refuses the walk.
    let mut allowance: usize = bounds.iter().map(|bound| bound.max).sum();
    for _ in 0..pairs {
        let key = scanner.map_key()?;
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
        let Some(remaining) = allowance.checked_sub(count) else {
            return Err(CborScanError::VisitBudgetExhausted);
        };
        allowance = remaining;
        scanner.skip_text_elements(count, bound.label)?;
    }
    Ok(ScanOutcome::WithinBounds)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        DirectiveKind, SupplyEntry, WireMessage, MAX_HAVE_HEADS, MAX_SUPPLY_ENTRIES, MAX_WANT_IDS,
        NON_SUPPLY_ARRAY_BOUNDS, SUPPLY_TYPE_DISCRIMINATOR,
    };
    use std::collections::BTreeMap;

    fn entry(index: usize) -> SupplyEntry {
        SupplyEntry {
            id: format!("{index:064x}"),
            kind: DirectiveKind::Open,
            economic_bean: "2024-01-01 open Assets:Cash USD".to_owned(),
            envelope: BTreeMap::from([("openledger-author".to_owned(), "peer-1".to_owned())]),
        }
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

    /// The honest path: real encoded frames scan to exactly their entry count,
    /// and still decode identically afterwards.
    ///
    /// This is also the proof the module's fail-closed rules rest on — it runs
    /// against bytes ciborium actually produced, so it pins that the top-level
    /// map and the `entries` array are BOTH definite-length (an indefinite head
    /// would make the scan return `IndefiniteLength` and the `unwrap` below
    /// fail), that the keys are text strings, and that `entries` is reachable
    /// within the visit budget at the field order serde emits.
    #[test]
    fn honest_supply_frames_scan_to_their_entry_count() {
        // 23/24 and 255/256 straddle CBOR's additional-info encoding boundaries
        // (inline, one-byte, two-byte), so all three argument widths are covered.
        for count in [0usize, 1, 23, 24, 255, MAX_SUPPLY_ENTRIES] {
            let message = WireMessage::supply((0..count).map(entry).collect());
            let cbor = message.to_cbor().unwrap();
            assert_eq!(
                supply_entry_count(&cbor),
                Ok(count as u64),
                "scan disagreed with the real encoding at {count} entries"
            );
            assert_eq!(
                WireMessage::decode_checked(&cbor).unwrap(),
                message,
                "pre-scan must not disturb an honest round-trip at {count} entries"
            );
        }
    }

    /// The T43 hole itself: a ~30-byte frame whose `entries` header claims ten
    /// million elements is answered from the header alone.
    #[test]
    fn scan_reads_a_forged_ten_million_element_claim_from_the_header() {
        let mut frame = supply_prefix();
        frame.extend_from_slice(&[0x9a]);
        frame.extend_from_slice(&10_000_000u32.to_be_bytes());
        assert!(frame.len() < 64, "the whole attack fits in a tiny frame");
        assert_eq!(supply_entry_count(&frame), Ok(10_000_000));
    }

    /// Field order is not assumed: `entries` is found wherever it sits.
    #[test]
    fn scan_finds_entries_at_any_key_position() {
        // {"entries": [], "type": "supply", "v": 1} — tag last, entries first.
        let mut frame = vec![0xa3];
        frame.extend_from_slice(b"\x67entries\x80");
        frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        frame.extend_from_slice(b"\x61v\x01");
        assert_eq!(supply_entry_count(&frame), Ok(0));
    }

    /// An indefinite-length `entries` array is refused, not followed. ciborium
    /// never emits one (see `honest_supply_frames_scan_to_their_entry_count`),
    /// so this can only be hand-rolled.
    #[test]
    fn scan_rejects_an_indefinite_length_entries_array() {
        let mut frame = supply_prefix();
        frame.push(0x9f); // array(*)
        frame.push(0xff); // break
        assert_eq!(
            supply_entry_count(&frame),
            Err(CborScanError::IndefiniteLength)
        );
    }

    /// Same rule at the top level: an indefinite-length map is refused before
    /// any key is read.
    #[test]
    fn scan_rejects_an_indefinite_length_top_level_map() {
        let mut frame = vec![0xbf]; // map(*)
        frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        frame.push(0xff);
        assert_eq!(
            supply_entry_count(&frame),
            Err(CborScanError::IndefiniteLength)
        );
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
        assert_eq!(
            supply_entry_count(&frame),
            Err(CborScanError::DepthExceeded)
        );
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
            supply_entry_count(&frame),
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
            supply_entry_count(&frame),
            Err(CborScanError::TooManyMapKeys(u64::MAX))
        );
    }

    /// Structural refusals, one per fail-closed rule.
    #[test]
    fn scan_rejects_malformed_frame_shapes() {
        assert_eq!(supply_entry_count(&[]), Err(CborScanError::Truncated));
        // An array, not a map.
        assert_eq!(supply_entry_count(&[0x80]), Err(CborScanError::NotAMap));
        // Reserved additional info (28).
        assert_eq!(
            supply_entry_count(&[0xbc]),
            Err(CborScanError::MalformedHeader(0xbc))
        );
        // Integer key instead of a text key.
        assert_eq!(
            supply_entry_count(&[0xa1, 0x01, 0x01]),
            Err(CborScanError::NonTextKey)
        );
        // A key claiming 65_535 bytes.
        assert_eq!(
            supply_entry_count(&[0xa1, 0x79, 0xff, 0xff]),
            Err(CborScanError::KeyTooLong(65_535))
        );
        // `entries` present but not an array.
        let mut not_an_array = vec![0xa1];
        not_an_array.extend_from_slice(b"\x67entries\x01");
        assert_eq!(
            supply_entry_count(&not_an_array),
            Err(CborScanError::EntriesNotAnArray)
        );
        // A well-formed map with no `entries` key at all.
        let mut no_entries = vec![0xa1];
        no_entries.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
        assert_eq!(
            supply_entry_count(&no_entries),
            Err(CborScanError::MissingEntries)
        );
        // The `entries` key is there but its value is cut off.
        let mut truncated = supply_prefix();
        truncated.push(0x9a);
        assert_eq!(
            supply_entry_count(&truncated),
            Err(CborScanError::Truncated)
        );
    }

    /// Tags and empty containers are skipped correctly — a tagged value ahead of
    /// `entries` must not desynchronise the key loop.
    #[test]
    fn scan_skips_tagged_and_empty_values() {
        // {"v": 0("x"), "e": [], "entries": [1 element]}
        let mut frame = vec![0xa3];
        frame.extend_from_slice(b"\x61v\xc0\x61x");
        frame.extend_from_slice(b"\x61e\x80");
        frame.extend_from_slice(b"\x67entries\x81\x00");
        assert_eq!(supply_entry_count(&frame), Ok(1));
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
    /// [`supply_entry_count`], which treats a missing `entries` as malformed.
    ///
    /// A non-`Supply` frame need carry no bounded array at all: that is what an
    /// `Announce` is. Structural hostility is still refused, so the tolerance is
    /// about which keys are present, not about how well-formed the frame is.
    #[test]
    fn scan_tolerates_frames_carrying_no_bounded_array() {
        // An empty map: no `ids`, no error — where `supply_entry_count` refuses.
        assert_eq!(scan(&[0xa0]), Ok(ScanOutcome::WithinBounds));
        assert_eq!(
            supply_entry_count(&[0xa0]),
            Err(CborScanError::MissingEntries)
        );
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
