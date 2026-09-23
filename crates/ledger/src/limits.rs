//! §3.12 resource limits that the parser needs as well as the write paths
//! (T75 / M-48, L-78).
//!
//! The older §3.12 caps — `MAX_POSTINGS_PER_TRANSACTION`,
//! `MAX_TAGS_PER_TRANSACTION`, `MAX_LINKS_PER_TRANSACTION`,
//! `MAX_METADATA_KEYS_PER_DIRECTIVE` — stay where they have always been, in
//! [`crate::service`], and are referenced from there by
//! [`crate::parse::ParseLimits`]. The two below are new with T75 and live here
//! so the parser can see them without the numbers moving into `service.rs`;
//! [`crate::service::enforce_resource_limits`] refers to the same constants,
//! so the wire's parse-time refusal and the write paths' refusal are one rule.

use crate::service::MAX_METADATA_KEYS_PER_DIRECTIVE;

/// Maximum currencies in one `open` directive's constraint list (L-78).
///
/// An `open`'s currency list restricts what the account may hold. Beancount
/// ledgers list a handful — a cash account one, a brokerage account the few
/// securities it trades — and a list long enough to approach this is not a
/// constraint any more, it is the absence of one (which an empty list already
/// says). 64 is several times the longest honest list and still tiny: 64
/// currency codes are at most ~1.6 KB of body.
///
/// Before T75 the list had no cap at all: a 786 KB `open` of 262,137
/// currencies passed every check, staged, and stayed on every replica
/// permanently at ~5.2 MB resident each — and, parsed, it peaked at 17× its
/// body on the way in.
pub const MAX_CURRENCIES_PER_OPEN: usize = 64;

/// Maximum posting-level metadata keys in one transaction, summed over all of
/// its postings (T75 / M-48).
///
/// `MAX_METADATA_KEYS_PER_DIRECTIVE` bounded the directive's own metadata map
/// and nothing bounded its postings' maps: a 1 MiB transaction carrying 74,896
/// posting-level keys passed every §3.12 check — nothing counted them — after
/// peaking at 10.2× its body in the parser. The cap is
/// on the SUM rather than per posting because the cost is per key: a
/// per-posting cap of 100 would still admit 1,000 postings × 100 keys. It is
/// the directive cap restated as a total, so a transaction's postings together
/// may carry as much metadata as one directive may.
///
/// No honest writer this node ships produces posting metadata at all — the
/// local API has no field for it — so the cap only ever meets hand-edited files
/// (at reconcile) and peers.
pub const MAX_POSTING_METADATA_KEYS_PER_TRANSACTION: usize = MAX_METADATA_KEYS_PER_DIRECTIVE;

/// The largest magnitude any summed amount may carry: `|amount| ≤ 10^21`, at
/// any precision (T76, M-50; replaces H-17's 21-significant-digit cap).
///
/// "Summed" means every amount the read model adds into a balance or that
/// feeds one: a posting's units, its `{cost}`, its `@`/`@@` price, and the
/// resolved amount of an elided leg. `balance` and `price` directive amounts
/// are never summed — a `balance` is compared exactly against a sum, a `price`
/// is a quote — so they are not capped.
///
/// # One rule on every path
///
/// The bound is a property of the content alone, applied identically by the
/// `.bean` number reader (so on the wire, at boot, in journal replay and on
/// reconcile, which all parse), by `validate_transaction` (the local API, peer
/// staging, reconcile and boot's salvage path), and by the GraphQL `Decimal`
/// scalar. A directive one node accepts, every node accepts.
///
/// # Why a magnitude, and why `10^21`
///
/// Balances are exact per-scale `i128` partial sums
/// ([`crate::read_model`]), so the cap is not what keeps them exact. What it
/// buys is that **no reported total can be unrepresentable**, for anyone: a
/// ledger holds at most ~9.6 × 10^6 postings (a 64 MiB file plus a 64 MiB
/// journal at ≥ 15 bytes a posting line, M-35), so any total — one account, a
/// trial-balance column, a net income — has magnitude at most
/// `9.6 × 10^6 × 10^21 < 10^28 < 2^96`, and fits a `Decimal` at scale 0. (Even
/// the crude one-byte-per-posting bound, `2^26 × 10^21 ≈ 6.7 × 10^28`, fits.)
/// Without a cap, two `Decimal::MAX` postings from one allowlisted peer would
/// make an account and every report containing it unreadable on every replica.
///
/// A magnitude rather than a digit count, because a digit count refused
/// ordinary content: the 21-digit cap counted trailing zeros, so
/// `1.00000000 BTC @ 100000.00000000 USD` (resolved leg
/// `-100000.0000000000000000`, 22 digits) was refused and pre-T65 history
/// holding such legs was quarantined on upgrade (M-50); and a genuinely
/// precise product such as `12.12345678 BTC @ 45123.45678901 USD`
/// (`-547052.2781457603139878`) had no balanced rounded spelling at all,
/// because I1 has no tolerance. Precision costs nothing here — a total that
/// does not fit 96 bits at its printed scale is rounded once and flagged
/// (`read_model::ExactAmount::reported`) — so only magnitude is bounded.
///
/// Inclusive: `10^21` itself is admitted (it is what pre-T65 nodes stored in
/// the M-50 fixture). At scale 8 and finer the bound is wider than any
/// `Decimal` (`10^21 × 10^8 > 2^96`), so every amount with eight or more
/// fractional digits is inside it.
pub const MAX_AMOUNT_MAGNITUDE: u128 = 10u128.pow(21);
