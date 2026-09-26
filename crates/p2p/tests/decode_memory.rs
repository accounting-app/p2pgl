//! T43 / T43b / H-09 — the memory assertions for the full M-16 closure.
//!
//! A frame claiming millions of array elements used to reach serde's
//! internally-tagged decode, which `Content`-buffers the entire value tree
//! before any cardinality cap can look at it. This binary measures what
//! `decode_checked` actually allocates for exactly those frames: the
//! `Supply`-discriminator one T43 closed, the `Want` one T43b closed, and the
//! one H-09 found still open behind both of them.
//!
//! H-09 is the reason this file is written the way it is. T43 and T43b each
//! measured the ONE frame shape they had just fixed, so the pre-scan's own
//! coverage was never the thing under test — and a frame that moved its payload
//! two keys to the right walked straight through the gate and past both
//! measurements. Every shape added here is therefore a shape the guard is
//! claimed to bound, not a shape a particular change happened to be about.
//!
//! Its own binary on purpose: the counting `#[global_allocator]` below is
//! process-wide, so putting it beside ordinary tests would make every unrelated
//! allocation part of the measurement — and would make the measurement depend on
//! how many tests happened to run in parallel.
//!
//! T43 kept that honest by holding the file to exactly ONE `#[test]`, since
//! cargo runs tests in parallel threads and a second test would be a second
//! allocator client racing the one being measured. T43b needs a second
//! measurement, so the discipline is now enforced explicitly instead: every
//! measuring test holds [`MEASUREMENT`] for its whole body, so only one is ever
//! allocating, and a test waiting on the lock holds nothing and allocates
//! nothing. That keeps both measurements as clean as the single-test rule made
//! the first one, without either test having to know about the other.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use p2p::cbor_scan::CborScanError;
use p2p::protocol::{
    DirectiveKind, SupplyEntry, WireError, WireMessage, MAX_MESSAGE_SIZE, MAX_SUPPLY_ENTRIES,
    MAX_WANT_IDS, SUPPLY_TYPE_DISCRIMINATOR,
};
use p2p::union_merge::{validate_supply_entry, MergeError, MAX_REPORTED_PARSE_ERRORS};

/// Serializes the measuring tests in this binary — see the module docs.
static MEASUREMENT: Mutex<()> = Mutex::new(());

/// Take [`MEASUREMENT`], ignoring poisoning.
///
/// A poisoned lock means the OTHER test already failed and is reporting its own
/// panic; refusing to measure here would replace that report with a less useful
/// one.
fn measurement_lock() -> MutexGuard<'static, ()> {
    MEASUREMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ─── Counting allocator ──────────────────────────────────────────────────────

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

/// `System`, with live and peak byte counters around it.
///
/// `realloc` is deliberately NOT overridden: the `GlobalAlloc` default
/// implementation allocates the new block, copies, then frees the old one, so a
/// `Vec` growing from 256 MiB to 512 MiB is counted with **both** buffers live.
/// That is the transient footprint this test exists to bound — an in-place
/// `realloc` accounted as a delta would hide exactly the spike that makes the
/// M-16 amplification dangerous.
struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding an unchanged layout to the system allocator.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: the pointer and layout come straight from a matching `alloc`.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Run `call` with the peak counter rebased, and report the peak ABOVE the
/// live-byte level at entry.
fn peak_allocated_during<T>(call: impl FnOnce() -> T) -> (T, usize) {
    let baseline = LIVE_BYTES.load(Ordering::SeqCst);
    PEAK_BYTES.store(baseline, Ordering::SeqCst);
    let value = call();
    let peak = PEAK_BYTES.load(Ordering::SeqCst);
    (value, peak.saturating_sub(baseline))
}

// ─── Frames ──────────────────────────────────────────────────────────────────

/// Elements in the crafted frame's `entries` array header.
///
/// One CBOR byte each (`0x00`, integer zero), so the frame lands just under the
/// 16 MiB `MAX_MESSAGE_SIZE` — the largest frame the receive path will even
/// consider, which is where the amplification is worst.
const FORGED_ENTRIES: u32 = 16_000_000;

/// Peak allocation permitted inside one guarded `decode_checked`, as a multiple
/// of the frame's byte length.
///
/// Justified from the honest side, which the test measures alongside the attack:
/// a legitimate decode copies the frame's strings once into serde's `Content`
/// buffer and once more into the `SupplyEntry` fields, so ~2× the frame is
/// structural and unavoidable while `WireMessage` stays internally tagged. 4×
/// leaves room for `Vec` growth doubling on top of that without being anywhere
/// near the hundreds of megabytes the unguarded path reaches for the same 16 MiB
/// of input — the gap between "a constant multiple of the frame" and "a multiple
/// of the frame's ELEMENT COUNT" is the whole of M-16.
const PEAK_BUDGET_MULTIPLE: usize = 4;

/// A ~16 MiB frame that carries the `Supply` discriminator and then claims
/// sixteen million one-byte entries.
///
/// Byte-for-byte the prefix ciborium emits for a real `Supply` — `a3`, then
/// `"type": "supply"`, `"v": 1`, `"entries"` — so it passes T26's oversized-frame
/// peek gate exactly as a genuine `Supply` would. Only the array header lies.
fn forged_supply_frame() -> Vec<u8> {
    let mut frame = Vec::with_capacity(FORGED_ENTRIES as usize + 32);
    frame.push(0xa3);
    frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
    frame.extend_from_slice(b"\x61v\x01");
    frame.extend_from_slice(b"\x67entries\x9a");
    frame.extend_from_slice(&FORGED_ENTRIES.to_be_bytes());
    frame.resize(frame.len() + FORGED_ENTRIES as usize, 0x00);
    frame
}

/// A real, maximal-cardinality `Supply`: `MAX_SUPPLY_ENTRIES` entries with a
/// 32 KiB economic body each, encoded by the production serializer.
///
/// Every entry carries every key the closed envelope set allows (H-09), which is
/// the widest an honest entry gets: the per-entry item budget the pre-scan now
/// walks against is sized for exactly this, so a frame that decodes here is a
/// frame the gate cannot be refusing in production.
fn honest_supply_frame() -> Vec<u8> {
    let entries: Vec<SupplyEntry> = (0..MAX_SUPPLY_ENTRIES)
        .map(|index| SupplyEntry {
            id: format!("{index:064x}"),
            kind: DirectiveKind::Open,
            economic_bean: "x".repeat(32 * 1024),
            envelope: ledger::service::ENVELOPE_KEYS
                .iter()
                .map(|key| ((*key).to_owned(), format!("peer-{index}")))
                .collect(),
        })
        .collect();
    WireMessage::supply(entries).to_cbor().unwrap()
}

// ─── The assertion ───────────────────────────────────────────────────────────

/// A 16 MiB `Supply`-discriminator frame claiming sixteen million entries is
/// rejected, and rejecting it costs a bounded multiple of the frame — not a
/// multiple of the count it claims.
///
/// Reverting the `prescan_supply_entries` call in `WireMessage::decode_checked`
/// is what this test is calibrated against. Measured on the same machine, same
/// debug profile, same frame:
///
/// * pre-scan wired in — peak **0 bytes**, rejected as
///   `BatchTooLarge { count: 16_000_000 }`;
/// * pre-scan reverted — peak **805,306,568 bytes** (50.33× the frame), and the
///   frame is refused only at the far end of the decode, by serde noticing that
///   an integer is not a `SupplyEntry` — i.e. after the whole sixteen-million-
///   element `Content` tree had already been built.
///
/// Both of this test's assertions fail on that revert: the rejection is the
/// wrong error, and the peak is over the budget by an order of magnitude.
#[test]
fn oversized_supply_frame_is_rejected_within_a_bounded_peak() {
    let _measuring = measurement_lock();

    // ── The attack ──────────────────────────────────────────────────────────
    let frame = forged_supply_frame();
    assert!(
        frame.len() <= MAX_MESSAGE_SIZE as usize,
        "the frame must be one the receive path would accept on size"
    );
    let budget = frame.len() * PEAK_BUDGET_MULTIPLE;

    let (result, peak) = peak_allocated_during(|| WireMessage::decode_checked(&frame));

    println!(
        "forged frame: {} bytes, {FORGED_ENTRIES} claimed entries, peak {peak} bytes \
         ({:.2}× frame, budget {budget})",
        frame.len(),
        peak as f64 / frame.len() as f64,
    );
    assert_eq!(
        result.unwrap_err(),
        WireError::BatchTooLarge {
            kind: "supply",
            count: FORGED_ENTRIES as usize,
            max: MAX_SUPPLY_ENTRIES,
        },
        "the frame must be REJECTED, not merely rejected cheaply"
    );
    assert!(
        peak <= budget,
        "decoding a {}-byte forged frame peaked at {peak} bytes, over the \
         {PEAK_BUDGET_MULTIPLE}× budget of {budget}",
        frame.len(),
    );

    // ── The same budget, measured against honest traffic ────────────────────
    // The bound above is only meaningful if a real maximal `Supply` fits inside
    // it: a budget no legitimate frame could meet would be a bound on nothing.
    let honest = honest_supply_frame();
    let honest_budget = honest.len() * PEAK_BUDGET_MULTIPLE;
    let (decoded, honest_peak) = peak_allocated_during(|| WireMessage::decode_checked(&honest));

    println!(
        "honest frame: {} bytes, {MAX_SUPPLY_ENTRIES} entries, peak {honest_peak} bytes \
         ({:.2}× frame, budget {honest_budget})",
        honest.len(),
        honest_peak as f64 / honest.len() as f64,
    );
    let Ok(WireMessage::Supply { entries, .. }) = decoded else {
        panic!("a maximal honest Supply must still decode");
    };
    assert_eq!(entries.len(), MAX_SUPPLY_ENTRIES);
    assert!(
        honest_peak <= honest_budget,
        "an honest {}-byte Supply peaked at {honest_peak} bytes, over the \
         {PEAK_BUDGET_MULTIPLE}× budget of {honest_budget} — the budget the \
         attack is held to must be one honest traffic meets",
        honest.len(),
    );
}

// ─── T43b: the same assertion for the `Want` arm ─────────────────────────────

/// Byte length of the crafted `Want` prefix, up to and including the four-byte
/// `ids` array header: `a3` · `"type"`/`"want"` · `"v"`/`1` · `"ids"` · `9a` +
/// `u32`.
const WANT_PREFIX_BYTES: u32 = 23;

/// The forged `Want`'s id count — one one-byte element per remaining byte of a
/// frame exactly 1 MiB long.
///
/// 1 MiB because that is T26's `NON_SUPPLY_FRAME_CAP`: the largest non-`Supply`
/// frame the ALPN read path will accept, and therefore the worst case for this
/// arm. (The `gl-node` constant is not reachable from a `p2p` test, so the
/// number is restated here rather than imported.)
const FORGED_WANT_IDS: u32 = 1024 * 1024 - WANT_PREFIX_BYTES;

/// A ~1 MiB frame that is a genuine `Want` right up to its `ids` array header,
/// which then claims a million one-byte elements.
///
/// `0x60` is `text(0)`, the empty string: a legal `Vec<String>` element in one
/// byte, which is what makes this the densest element count a frame of this size
/// can carry — and the shape the T43 residual note measured at 80×.
fn forged_want_frame() -> Vec<u8> {
    let mut frame = Vec::with_capacity(FORGED_WANT_IDS as usize + WANT_PREFIX_BYTES as usize);
    frame.push(0xa3);
    frame.extend_from_slice(b"\x64type\x64want");
    frame.extend_from_slice(b"\x61v\x01");
    frame.extend_from_slice(b"\x63ids\x9a");
    frame.extend_from_slice(&FORGED_WANT_IDS.to_be_bytes());
    assert_eq!(frame.len(), WANT_PREFIX_BYTES as usize);
    frame.resize(frame.len() + FORGED_WANT_IDS as usize, 0x60);
    frame
}

/// A real, maximal-cardinality `Want`: `MAX_WANT_IDS` sixty-four-hex ids,
/// encoded by the production serializer.
fn honest_want_frame() -> Vec<u8> {
    let ids = (0..MAX_WANT_IDS)
        .map(|index| format!("{index:064x}"))
        .collect();
    WireMessage::want(ids).to_cbor().unwrap()
}

/// T43b: a 1 MiB `Want` claiming a million ids is rejected, and rejecting it
/// costs a bounded multiple of the frame rather than 80× it.
///
/// This is the residual T43 quantified and left open. `Want` and `HaveHeads`
/// amplify for exactly the same reason `Supply` did — the `Content` buffering
/// belongs to the internally-tagged enum, not to one variant — and T26's
/// `NON_SUPPLY_FRAME_CAP` bounded a single frame without bounding the fleet:
/// 256 concurrent inbound connections × ~84 MB is ~21 GB from allowlisted peers.
///
/// Reverting the non-`Supply` arm of `protocol::prescan_frame` (returning `Ok`
/// instead of calling `cbor_scan::scan_bounded_arrays`) is what this test is
/// calibrated against. Measured on the same machine, same debug profile, same
/// frame:
///
/// * pre-scan wired in — peak **0 bytes**, rejected as
///   `BatchTooLarge { kind: "want", count: 1_048_553 }`;
/// * non-`Supply` arm reverted — peak **83,885,504 bytes**, exactly **80.00×**
///   the frame, matching the figure T43's residual note quantified. The frame is
///   refused only by `check_cardinality` at the far end of the decode, after the
///   whole million-element id vector had been materialised twice over: once as
///   serde's `Content` tree, once as the variant's own `Vec<String>`.
///
/// Note which assertion catches that, because it is the opposite of the `Supply`
/// case above. The forged `Want` is WELL-FORMED — a real million-element array
/// of empty strings — so the post-decode cap returns the identical
/// `BatchTooLarge` verdict and the error assertion passes either way. Only the
/// PEAK separates "refused from a 23-byte header" from "refused after 84 MB of
/// transient allocation", which is why this measurement, and not a unit test on
/// the error, is the regression guard for the T43b residual.
#[test]
fn oversized_want_frame_is_rejected_within_a_bounded_peak() {
    let _measuring = measurement_lock();

    // ── The attack ──────────────────────────────────────────────────────────
    let frame = forged_want_frame();
    assert_eq!(
        frame.len(),
        1024 * 1024,
        "the frame must be exactly the largest non-Supply frame the read path accepts"
    );
    let budget = frame.len() * PEAK_BUDGET_MULTIPLE;

    let (result, peak) = peak_allocated_during(|| WireMessage::decode_checked(&frame));

    println!(
        "forged want: {} bytes, {FORGED_WANT_IDS} claimed ids, peak {peak} bytes \
         ({:.2}× frame, budget {budget})",
        frame.len(),
        peak as f64 / frame.len() as f64,
    );
    assert_eq!(
        result.unwrap_err(),
        WireError::BatchTooLarge {
            kind: "want",
            count: FORGED_WANT_IDS as usize,
            max: MAX_WANT_IDS,
        },
        "the frame must be REJECTED, not merely rejected cheaply"
    );
    assert!(
        peak <= budget,
        "decoding a {}-byte forged Want peaked at {peak} bytes, over the \
         {PEAK_BUDGET_MULTIPLE}× budget of {budget}",
        frame.len(),
    );

    // ── The same budget, measured against honest traffic ────────────────────
    // A maximal real `Want` has to fit inside the bound the attack is held to,
    // or the bound is a bound on nothing.
    let honest = honest_want_frame();
    let honest_budget = honest.len() * PEAK_BUDGET_MULTIPLE;
    let (decoded, honest_peak) = peak_allocated_during(|| WireMessage::decode_checked(&honest));

    println!(
        "honest want: {} bytes, {MAX_WANT_IDS} ids, peak {honest_peak} bytes \
         ({:.2}× frame, budget {honest_budget})",
        honest.len(),
        honest_peak as f64 / honest.len() as f64,
    );
    let Ok(WireMessage::Want { ids, .. }) = decoded else {
        panic!("a maximal honest Want must still decode");
    };
    assert_eq!(ids.len(), MAX_WANT_IDS);
    assert!(
        honest_peak <= honest_budget,
        "an honest {}-byte Want peaked at {honest_peak} bytes, over the \
         {PEAK_BUDGET_MULTIPLE}× budget of {honest_budget} — the budget the \
         attack is held to must be one honest traffic meets",
        honest.len(),
    );
}

// ─── H-09: the payload the entry count could not see ─────────────────────────

/// Elements in the crafted frame's HIDDEN array header.
///
/// One CBOR byte each, so both frames below land just under the 16 MiB
/// `MAX_MESSAGE_SIZE` — the largest frame the receive path will consider, and
/// the size T26's peek gate deliberately admits for a `Supply`. This is the same
/// count `FORGED_ENTRIES` uses, for the same reason: it is the densest element
/// count a frame of this size can carry.
const HIDDEN_ITEMS: u32 = 16_000_000;

/// A ~16 MiB `Supply` whose payload sits AFTER an empty `entries` array.
///
/// `{"type": "supply", "entries": [], "v": 1, "z": [16 M items]}`, byte for byte
/// the prefix ciborium emits for a real `Supply` up to the point where `entries`
/// truthfully declares nothing. T43's `supply_entry_count` returned `Ok(0)` from
/// that header and never read another pair, so the three pairs behind it —
/// including a sixteen-million-element array — were invisible to the gate.
fn hidden_tail_supply_frame() -> Vec<u8> {
    let mut frame = Vec::with_capacity(HIDDEN_ITEMS as usize + 32);
    frame.push(0xa4);
    frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
    frame.extend_from_slice(b"\x67entries\x80");
    frame.extend_from_slice(b"\x61v\x01");
    frame.extend_from_slice(b"\x61z\x9a");
    frame.extend_from_slice(&HIDDEN_ITEMS.to_be_bytes());
    assert_eq!(frame.len(), 32, "the prefix must be the one H-09 measured");
    frame.resize(frame.len() + HIDDEN_ITEMS as usize, 0x00);
    frame
}

/// A ~16 MiB `Supply` whose payload sits INSIDE `entries`, as its one element.
///
/// `{"type": "supply", "v": 1, "entries": [[16 M items]]}`. The `entries` header
/// claims exactly one element and is telling the truth, so no bound on the entry
/// COUNT can see this frame — it is inside `MAX_SUPPLY_ENTRIES` by a factor of
/// 256. Only a bound on what one entry may be WORTH refuses it.
fn hidden_entry_supply_frame() -> Vec<u8> {
    let mut frame = Vec::with_capacity(HIDDEN_ITEMS as usize + 32);
    frame.push(0xa3);
    frame.extend_from_slice(SUPPLY_TYPE_DISCRIMINATOR);
    frame.extend_from_slice(b"\x61v\x01");
    frame.extend_from_slice(b"\x67entries\x81\x9a");
    frame.extend_from_slice(&HIDDEN_ITEMS.to_be_bytes());
    assert_eq!(frame.len(), 30);
    frame.resize(frame.len() + HIDDEN_ITEMS as usize, 0x00);
    frame
}

/// H-09: a 16 MiB `Supply` that hides its payload where the `entries` header
/// cannot see it is rejected, and rejecting it costs a bounded multiple of the
/// frame rather than fifty times it.
///
/// The hole T43 and T43b both left, and the reason it survived two rounds of
/// this file: each of those tests measured the one frame shape its own change
/// was about — an over-claiming `entries` header, an over-claiming `ids` header
/// — so the guard's COVERAGE was never under test. Neither shape here
/// over-claims anything. Both are honest about every number they state, and both
/// were waved through.
///
/// Reverting the H-09 half of `cbor_scan::walk` — returning the `entries` claim
/// at the key that carries it, the way `supply_entry_count` did, instead of
/// walking the rest of the map — is what this test is calibrated against.
/// Measured on the same machine, same debug profile, same frames:
///
/// * fix in place — peak **0 bytes** for both, refused by the pre-scan as
///   `UnknownKey` and `VisitBudgetExhausted` respectively;
/// * short-circuit restored — the hidden-tail frame peaks at **805,306,633
///   bytes**, 50.33× the frame, and then DECODES SUCCESSFULLY as
///   `Supply { v: 1, entries: [] }`. That is the part worth keeping in view: no
///   error, no log, no cap tripped, one budget unit spent against a 100k
///   per-connection allowance — ×32 connections per peer.
///
/// Note which assertion catches it, because only one of them can. The frame is
/// well-formed, so there is no post-decode verdict to disagree with and
/// `check_cardinality` is perfectly happy with an empty `Supply`: the ERROR
/// assertion is what fails on that revert, and the peak is what says how much it
/// cost. For the nested frame the decode fails either way (an integer is not a
/// `SupplyEntry`) and only the peak separates "refused from a 30-byte header"
/// from "refused after 805 MB of transient allocation".
#[test]
fn supply_payload_hidden_from_the_entry_count_is_rejected_within_a_bounded_peak() {
    let _measuring = measurement_lock();

    // ── Hidden behind an empty `entries` ────────────────────────────────────
    let frame = hidden_tail_supply_frame();
    assert!(
        frame.len() <= MAX_MESSAGE_SIZE as usize,
        "the frame must be one the receive path would accept on size"
    );
    let budget = frame.len() * PEAK_BUDGET_MULTIPLE;
    let (result, peak) = peak_allocated_during(|| WireMessage::decode_checked(&frame));

    println!(
        "hidden tail: {} bytes, {HIDDEN_ITEMS} items behind an empty entries, peak {peak} bytes \
         ({:.2}× frame, budget {budget})",
        frame.len(),
        peak as f64 / frame.len() as f64,
    );
    assert_eq!(
        result.unwrap_err(),
        WireError::FramePrescan(CborScanError::UnknownKey),
        "the frame must be REJECTED — the short-circuit DECODED it, as an empty Supply"
    );
    assert!(
        peak <= budget,
        "decoding a {}-byte frame with a hidden tail peaked at {peak} bytes, over the \
         {PEAK_BUDGET_MULTIPLE}× budget of {budget}",
        frame.len(),
    );

    // ── Hidden inside `entries`, as its one truthful element ────────────────
    let nested = hidden_entry_supply_frame();
    let nested_budget = nested.len() * PEAK_BUDGET_MULTIPLE;
    let (nested_result, nested_peak) =
        peak_allocated_during(|| WireMessage::decode_checked(&nested));

    println!(
        "hidden entry: {} bytes, {HIDDEN_ITEMS} items inside one entry, peak {nested_peak} bytes \
         ({:.2}× frame, budget {nested_budget})",
        nested.len(),
        nested_peak as f64 / nested.len() as f64,
    );
    assert_eq!(
        nested_result.unwrap_err(),
        WireError::FramePrescan(CborScanError::VisitBudgetExhausted),
        "the frame must be refused by the GATE, not by serde at the far end"
    );
    assert!(
        nested_peak <= nested_budget,
        "decoding a {}-byte frame with a bomb inside one entry peaked at {nested_peak} \
         bytes, over the {PEAK_BUDGET_MULTIPLE}× budget of {nested_budget}",
        nested.len(),
    );

    // ── The same budget, measured against honest traffic ────────────────────
    // H-09 tightened the `Supply` path in the two ways an honest frame could
    // notice — every top-level key is now checked against the variant's field
    // set, and every entry is walked against an item budget — so the maximal
    // real frame has to be measured through the SAME gate, not assumed past it.
    let honest = honest_supply_frame();
    let honest_budget = honest.len() * PEAK_BUDGET_MULTIPLE;
    let (decoded, honest_peak) = peak_allocated_during(|| WireMessage::decode_checked(&honest));

    println!(
        "honest supply: {} bytes, {MAX_SUPPLY_ENTRIES} entries with a full envelope, peak \
         {honest_peak} bytes ({:.2}× frame, budget {honest_budget})",
        honest.len(),
        honest_peak as f64 / honest.len() as f64,
    );
    let Ok(WireMessage::Supply { entries, .. }) = decoded else {
        panic!("a maximal honest Supply must still decode");
    };
    assert_eq!(entries.len(), MAX_SUPPLY_ENTRIES);
    assert_eq!(
        entries[0].envelope.len(),
        ledger::service::ENVELOPE_KEYS.len(),
        "the honest frame must carry the widest envelope the protocol allows"
    );
    assert!(
        honest_peak <= honest_budget,
        "an honest {}-byte Supply peaked at {honest_peak} bytes, over the \
         {PEAK_BUDGET_MULTIPLE}× budget of {honest_budget} — the budget the \
         attack is held to must be one honest traffic meets",
        honest.len(),
    );
}

// ─── T66 / H-18: the parse-error amplifier behind every frame cap ───────────

/// A `Supply` entry whose body is exactly `body`, under a well-formed id that
/// is not its hash — the id-form check passes and the body is what decides.
fn entry_with_body(body: String) -> SupplyEntry {
    SupplyEntry {
        id: "0".repeat(64),
        kind: DirectiveKind::Open,
        economic_bean: body,
        envelope: std::collections::BTreeMap::new(),
    }
}

/// Peak allocation permitted while validating one entry, as a multiple of the
/// entry's body — the same 4× bar the frame decodes are held to.
const ENTRY_PEAK_BUDGET_MULTIPLE: usize = 4;

/// H-18: the three bodies the audit measured — `"x\n"` × 512k at 194,924,029 B
/// (185.9×) with a 55,463,434 B error; `"x\n\n"` × 349k at 131.9×; `" x\n"` ×
/// 349k at 145.6× — validated under the counting allocator. Each must peak
/// within 4× its body and render its error under 1,024 bytes.
///
/// Three shapes because the fix has two layers and the shapes split across
/// them: the first two are many directive BLOCKS and are refused by the
/// header count without parsing; the third is many stray indented lines and
/// no block at all — also refused by the count. `parse_file_bounded` itself is
/// measured separately below, on a body that gets past the count.
#[test]
fn a_thousand_block_body_is_refused_within_a_bounded_peak_and_a_small_error() {
    let _measuring = measurement_lock();
    let mib = 1024 * 1024;
    let shapes = [
        ("\"x\\n\" x 512k", "x\n".repeat(mib / 2)),
        ("\"x\\n\\n\" x 349k", "x\n\n".repeat(mib / 3)),
        ("\" x\\n\" x 349k", " x\n".repeat(mib / 3)),
    ];
    for (name, body) in shapes {
        let body_len = body.len();
        let entry = entry_with_body(body);
        let budget = body_len * ENTRY_PEAK_BUDGET_MULTIPLE;
        let (result, peak) = peak_allocated_during(|| validate_supply_entry(&entry));
        let error = result.expect_err("a body of bad blocks must be refused");
        let rendered = error.to_string();
        println!(
            "{name}: body {body_len} bytes, peak {peak} bytes ({:.2}× body, budget {budget}), \
             error {} bytes",
            peak as f64 / body_len as f64,
            rendered.len()
        );
        assert!(
            matches!(error, MergeError::ParseError(_)),
            "{name}: {error}"
        );
        assert!(
            peak <= budget,
            "{name}: validating a {body_len}-byte body peaked at {peak} bytes, over the \
             {ENTRY_PEAK_BUDGET_MULTIPLE}× budget of {budget}"
        );
        assert!(
            rendered.len() < 1024,
            "{name}: the error is {} bytes — it is carrying the body",
            rendered.len()
        );
    }
}

/// H-18, the bounded parser on its own: a body that PASSES the block count
/// (one header) and then fails 349k times inside `parse_file_bounded` — stray
/// indented lines before a bad header. This is the layer that used to keep
/// one `ParseError` per failure; it now keeps `MAX_REPORTED_PARSE_ERRORS`
/// and counts the rest, so the peak is bounded by the body, not by the
/// failure count, and the rendered error is a constant size.
#[test]
fn the_bounded_parser_peaks_within_budget_on_a_body_the_block_count_admits() {
    let _measuring = measurement_lock();
    let mib = 1024 * 1024;
    // `mib / 3 - 1` stray lines plus the header: just under the 1 MiB bean cap.
    let body = format!("{}x\n", " x\n".repeat(mib / 3 - 1));
    assert!(body.len() <= mib && body.len() > mib - 8, "{}", body.len());
    let body_len = body.len();
    assert_eq!(ledger::parse::count_directive_headers(&body), 1);
    let entry = entry_with_body(body);
    let budget = body_len * ENTRY_PEAK_BUDGET_MULTIPLE;

    let (result, peak) = peak_allocated_during(|| validate_supply_entry(&entry));
    let error = result.expect_err("a body of stray lines must be refused");
    let rendered = error.to_string();
    println!(
        "stray-lines-then-header: body {body_len} bytes, peak {peak} bytes ({:.2}× body, \
         budget {budget}), error {} bytes",
        peak as f64 / body_len as f64,
        rendered.len()
    );
    let MergeError::ParseError(detail) = &error else {
        panic!("expected a parse error, got {error}");
    };
    assert!(
        detail.starts_with(&format!("{} parse error(s); first: ", mib / 3)),
        "{detail}"
    );
    assert_eq!(
        detail.matches("Unexpected indented line").count(),
        MAX_REPORTED_PARSE_ERRORS
    );
    assert!(
        peak <= budget,
        "peaked at {peak} bytes, over the budget of {budget}"
    );
    assert!(rendered.len() < 1024, "{}", rendered.len());

    // And `parse_file_bounded` directly, without the wire path's other checks.
    let (bounded, parser_peak) = peak_allocated_during(|| {
        ledger::parse::parse_file_bounded(
            &entry.economic_bean,
            MAX_REPORTED_PARSE_ERRORS,
            ledger::parse::ParseLimits::RESOURCE,
        )
    });
    let bounded = bounded.expect_err("must fail");
    println!(
        "parse_file_bounded alone: peak {parser_peak} bytes ({:.2}× body), kept {} of {}",
        parser_peak as f64 / body_len as f64,
        bounded.errors.len(),
        bounded.total
    );
    assert_eq!(bounded.errors.len(), MAX_REPORTED_PARSE_ERRORS);
    assert_eq!(bounded.total, mib / 3);
    assert!(parser_peak <= budget);
}

// ─── T75 / M-48: bodies that PARSE, and the frame that queues them ──────────

const MIB: usize = 1024 * 1024;

/// A `Supply` entry for `body` under its TRUE id and a transaction envelope,
/// so nothing but a cardinality cap can refuse it — exactly the entry the
/// audit measured `Ok` at 41.7×.
fn entry_with_true_id(body: String) -> SupplyEntry {
    let parsed = ledger::parse::parse_file(&body).expect("the shape parses on the file path");
    assert_eq!(parsed.len(), 1);
    SupplyEntry {
        id: ledger::hash::compute_content_id(&parsed[0]),
        kind: DirectiveKind::from_directive(&parsed[0]),
        economic_bean: body,
        envelope: std::collections::BTreeMap::from([
            ("openledger-author".to_owned(), "author".to_owned()),
            ("openledger-lamport".to_owned(), "1".to_owned()),
            ("openledger-parents".to_owned(), String::new()),
        ]),
    }
}

/// 41,941 postings with one metadata line each — the audit's worst shape.
fn postings_with_metadata_body(narration: &str) -> String {
    let line = "  Assets:A 1 USD\n  k: \"\"\n";
    format!(
        "2024-01-01 * \"{narration}\"\n{}",
        line.repeat((MIB - 60) / line.len())
    )
}

/// M-48: the four valid 1 MiB bodies the audit measured — every one `Ok` with
/// a correct id and refused only at stage — plus the two floods it found
/// beside them, validated under the counting allocator. Each must now be
/// REFUSED, as a resource limit, within the same 4× bar the refused shapes
/// above are held to.
///
/// Measured before T75 (release, same allocator): 61,678 postings 19.94×;
/// 41,941 postings + meta 41.72×; 349,518 tags 30.63×; 349,515 currencies
/// 24.00×; 74,896 posting-metadata keys 10.21×; 262,144 junk body lines 9.00×.
/// After T75: every one ≤ 0.08× — the parse stops at the first item past a
/// cap, and the lazy scanner no longer materialises the rest of a flooded
/// header. T81 raised the wire's body-line cap to 5,196 (the legacy posting-
/// metadata ceiling), so the line floods now read up to that many lines
/// before stopping: measured ≤ 0.28× (0925 A3), still well inside the 4×
/// bar.
///
/// Reverting the parse-time limits (`ParseLimits::UNLIMITED` in
/// `validate_supply_entry`) fails this test on the peak for all four audited
/// shapes, even though the post-parse `enforce_resource_limits` still refuses
/// them: the refusal comes after the directive was built. Reverting the lazy
/// scanner (`Scanner::new` collecting the whole line up front) fails it on the
/// tag and currency floods at 6.00×: the counts stop at the 101st tag and the
/// 65th currency, but an eager scanner has already paid four to six bytes per
/// character of the 1 MiB header.
#[test]
fn parsed_flood_bodies_are_refused_within_the_entry_budget() {
    let _measuring = measurement_lock();
    let posting = "  Assets:A 1 USD\n";
    let mut posting_metadata = String::from("2024-01-01 *\n  Assets:A 1 USD\n");
    let mut key = 0usize;
    while posting_metadata.len() + 14 < MIB {
        posting_metadata.push_str(&format!("  k{key:06}: \"\"\n"));
        key += 1;
    }
    let shapes = [
        (
            "61678 postings",
            format!(
                "2024-01-01 *\n{}",
                posting.repeat((MIB - 40) / posting.len())
            ),
        ),
        (
            "41941 postings + 1 meta each",
            postings_with_metadata_body("x"),
        ),
        (
            "349518 tags",
            format!("2024-01-01 *{}\n", " #a".repeat((MIB - 20) / 3)),
        ),
        (
            "open + 349515 currencies",
            format!(
                "2024-01-01 open Assets:A US{}\n",
                ",US".repeat((MIB - 30) / 3)
            ),
        ),
        ("74896 posting metadata keys", posting_metadata),
    ];
    // Every shape is measured before anything is asserted, so a failure
    // reports all of them rather than the first.
    let mut failures = Vec::new();
    for (name, body) in shapes {
        let body_len = body.len();
        assert!(
            body_len <= ledger::service::MAX_ECONOMIC_BEAN_LENGTH,
            "{name}"
        );
        let entry = entry_with_true_id(body);
        let budget = body_len * ENTRY_PEAK_BUDGET_MULTIPLE;
        let (result, peak) = peak_allocated_during(|| validate_supply_entry(&entry));
        let verdict = result.as_ref().map(|_| "Ok").map_err(ToString::to_string);
        println!(
            "{name}: body {body_len} bytes, peak {peak} bytes ({:.2}× body, budget {budget}): \
             {verdict:?}",
            peak as f64 / body_len as f64,
        );
        if !matches!(result, Err(MergeError::ResourceLimitExceeded(_))) {
            failures.push(format!(
                "{name}: not refused as a resource limit: {verdict:?}"
            ));
        }
        if peak > budget {
            failures.push(format!(
                "{name}: validating a {body_len}-byte body peaked at {peak} bytes ({:.2}×), \
                 over the {ENTRY_PEAK_BUDGET_MULTIPLE}× budget of {budget}",
                peak as f64 / body_len as f64
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // The refused-path flood beside them: 262k junk body lines under one
    // header (the audit's 9.0×), stopped while the lines are collected.
    let junk = format!(
        "2024-01-01 open Assets:A\n{}",
        "  x\n".repeat((MIB - 30) / 4)
    );
    let junk_len = junk.len();
    let entry = entry_with_body(junk);
    let (result, peak) = peak_allocated_during(|| validate_supply_entry(&entry));
    println!(
        "262k junk body lines: body {junk_len} bytes, peak {peak} bytes ({:.2}× body)",
        peak as f64 / junk_len as f64
    );
    assert!(matches!(result, Err(MergeError::ResourceLimitExceeded(_))));
    assert!(peak <= junk_len * ENTRY_PEAK_BUDGET_MULTIPLE);
}

/// Peak permitted while phase 1 of `apply_supply_entries` runs over an
/// HONEST maximal frame, as a multiple of the frame.
///
/// Not the 4× bar, and deliberately stated separately rather than loosening
/// it: honest entries are ACCEPTED, so phase 1 keeps every parsed directive for
/// phase 2, and a parsed directive is larger than its body — a 1000-posting
/// transaction's `Vec<Posting>` alone is 184 B a posting against ~36 B of text.
/// The audit measured 6.1× for 256 honest 1000-posting transactions; T75
/// cannot and does not change that (nothing honest is refused). The hostile
/// bound below stays at 4×.
///
/// T88 / L-102, decision (29): 8× was calibrated on that one shape. The
/// densest frame the wire ADMITS — 256 transactions of 1,000 shortest-line
/// postings, 96 directive and 4,096 posting metadata keys (T81's legacy
/// ceiling) — parses at 14.4× (0925 A3, release) and is now the second control
/// below; 16× is that measurement plus the same headroom for allocator-growth
/// jitter. Decision (29) keeps the 4,096 ceiling and states the multiple.
const HONEST_FRAME_PEAK_MULTIPLE: usize = 16;

/// The densest transaction the wire admits (T88 / L-102): `postings`
/// shortest-line postings, `dir_meta` directive metadata keys and
/// `posting_meta` posting metadata keys spread across the postings (0925 A3's
/// generator).
fn densest_admitted_transaction(
    postings: usize,
    dir_meta: usize,
    posting_meta: usize,
    tag: usize,
) -> String {
    let mut body = format!("2024-01-01 * \"{tag}\"\n");
    for key in 0..dir_meta {
        body.push_str(&format!("  m{key}: \"\"\n"));
    }
    let per_posting = posting_meta / postings;
    let mut extra = posting_meta - per_posting * postings;
    for index in 0..postings {
        let number = if index == 0 {
            (postings as i64 - 1).to_string()
        } else {
            "-1".to_owned()
        };
        body.push_str(&format!("  Assets:A {number} US\n"));
        let mut here = per_posting;
        if extra > 0 {
            here += 1;
            extra -= 1;
        }
        for key in 0..here {
            body.push_str(&format!("  p{key}: \"\"\n"));
        }
    }
    body
}

/// Run phase 1 of `apply_supply_entries` over `entries` — validate each and
/// keep what passes — and report `(staged, peak)`. The entries stay live
/// throughout (the decoded frame), which is the conservative accounting: the
/// node frees each entry as it goes, so its real peak is at most this.
fn phase_one(entries: &[SupplyEntry]) -> (usize, usize) {
    let (staged, peak) = peak_allocated_during(|| {
        let mut staged = Vec::new();
        for entry in entries {
            if let Ok(directive) = validate_supply_entry(entry) {
                staged.push(directive);
            }
        }
        staged
    });
    (staged.len(), peak)
}

/// M-48: a 15 MiB `Supply` of fifteen distinct 41,941-posting bodies held
/// **546 MB (34.7×)** through phase 1 before T75, because every entry parsed
/// `Ok` and was queued for phase 2, where the caps finally refused them. It
/// must now peak within 4× the frame, with nothing queued.
///
/// Two mechanisms each close this on their own, and this test fails only with
/// BOTH reverted: the parse-time limits refuse every entry before it is built,
/// and the post-parse `enforce_resource_limits` refuses it before it is queued
/// (with only the latter, each entry still peaks at ~42× its own body inside
/// the parser — which `parsed_flood_bodies_are_refused_within_the_entry_budget`
/// catches — but none accumulates, so the frame stays at ~2.8×).
///
/// The honest control is 256 real 1000-posting transactions — the largest
/// honest entry the caps allow, the most of them a frame carries — held to
/// [`HONEST_FRAME_PEAK_MULTIPLE`] and every one staged.
#[test]
fn a_frame_of_flood_bodies_is_refused_within_the_frame_budget() {
    let _measuring = measurement_lock();

    // ── The attack ──────────────────────────────────────────────────────────
    let entries: Vec<SupplyEntry> = (0..15)
        .map(|index| entry_with_true_id(postings_with_metadata_body(&format!("{index:03}"))))
        .collect();
    let frame = WireMessage::supply(entries.clone()).to_cbor().unwrap();
    assert!(frame.len() <= MAX_MESSAGE_SIZE as usize);
    let budget = frame.len() * ENTRY_PEAK_BUDGET_MULTIPLE;
    let (staged, peak) = phase_one(&entries);
    println!(
        "15 x 41941-posting frame: {} bytes, phase-1 peak {peak} bytes ({:.2}× frame, \
         budget {budget}), staged {staged}",
        frame.len(),
        peak as f64 / frame.len() as f64,
    );
    assert_eq!(staged, 0, "no flood entry may be queued for phase 2");
    assert!(
        peak <= budget,
        "phase 1 over a {}-byte flood frame peaked at {peak} bytes, over the \
         {ENTRY_PEAK_BUDGET_MULTIPLE}× budget of {budget}",
        frame.len(),
    );
    drop(entries);

    // ── Honest traffic ──────────────────────────────────────────────────────
    let honest: Vec<SupplyEntry> = (0..MAX_SUPPLY_ENTRIES)
        .map(|index| {
            let mut body = format!("2024-01-01 * \"Grocer\" \"weekly shop {index}\"\n");
            for item in 0..ledger::service::MAX_POSTINGS_PER_TRANSACTION - 1 {
                body.push_str(&format!("  Expenses:Food:Item{item:04}   1.00 USD\n"));
            }
            body.push_str("  Assets:Cash  -999.00 USD\n");
            entry_with_true_id(body)
        })
        .collect();
    let honest_frame = WireMessage::supply(honest.clone()).to_cbor().unwrap();
    assert!(honest_frame.len() <= MAX_MESSAGE_SIZE as usize);
    let honest_budget = honest_frame.len() * HONEST_FRAME_PEAK_MULTIPLE;
    let (honest_staged, honest_peak) = phase_one(&honest);
    println!(
        "256 x honest 1000-posting frame: {} bytes, phase-1 peak {honest_peak} bytes \
         ({:.2}× frame, budget {honest_budget}), staged {honest_staged}",
        honest_frame.len(),
        honest_peak as f64 / honest_frame.len() as f64,
    );
    assert_eq!(
        honest_staged, MAX_SUPPLY_ENTRIES,
        "every honest entry is staged"
    );
    assert!(
        honest_peak <= honest_budget,
        "an honest {}-byte frame peaked at {honest_peak} bytes, over the \
         {HONEST_FRAME_PEAK_MULTIPLE}× budget of {honest_budget}",
        honest_frame.len(),
    );
    drop(honest);

    // ── The densest frame the wire admits (T88 / L-102) ────────────────────
    let densest: Vec<SupplyEntry> = (0..MAX_SUPPLY_ENTRIES)
        .map(|index| {
            entry_with_true_id(densest_admitted_transaction(
                ledger::service::MAX_POSTINGS_PER_TRANSACTION,
                96,
                ledger::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY,
                index,
            ))
        })
        .collect();
    let densest_frame = WireMessage::supply(densest.clone()).to_cbor().unwrap();
    assert!(densest_frame.len() <= MAX_MESSAGE_SIZE as usize);
    let densest_budget = densest_frame.len() * HONEST_FRAME_PEAK_MULTIPLE;
    let (densest_staged, densest_peak) = phase_one(&densest);
    println!(
        "256 x densest admitted (1000 postings, 96 + 4096 metadata keys): {} bytes, phase-1 \
         peak {densest_peak} bytes ({:.2}× frame, budget {densest_budget}), staged {densest_staged}",
        densest_frame.len(),
        densest_peak as f64 / densest_frame.len() as f64,
    );
    assert_eq!(
        densest_staged, MAX_SUPPLY_ENTRIES,
        "every admitted entry is staged"
    );
    assert!(
        densest_peak <= densest_budget,
        "the densest admitted {}-byte frame peaked at {densest_peak} bytes, over the \
         {HONEST_FRAME_PEAK_MULTIPLE}× budget of {densest_budget}",
        densest_frame.len(),
    );
}
