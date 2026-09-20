//! T43 / T43b — the memory assertions for the full M-16 closure.
//!
//! A frame claiming millions of array elements used to reach serde's
//! internally-tagged decode, which `Content`-buffers the entire value tree
//! before any cardinality cap can look at it. This binary measures what
//! `decode_checked` actually allocates for exactly those frames: the
//! `Supply`-discriminator one T43 closed, and the `Want` one T43b closed.
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
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use p2p::protocol::{
    DirectiveKind, SupplyEntry, WireError, WireMessage, MAX_MESSAGE_SIZE, MAX_SUPPLY_ENTRIES,
    MAX_WANT_IDS, SUPPLY_TYPE_DISCRIMINATOR,
};

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
fn honest_supply_frame() -> Vec<u8> {
    let entries: Vec<SupplyEntry> = (0..MAX_SUPPLY_ENTRIES)
        .map(|index| SupplyEntry {
            id: format!("{index:064x}"),
            kind: DirectiveKind::Open,
            economic_bean: "x".repeat(32 * 1024),
            envelope: BTreeMap::from([("openledger-author".to_owned(), "peer-1".to_owned())]),
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
