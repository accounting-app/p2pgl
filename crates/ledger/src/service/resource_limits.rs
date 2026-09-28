//! Resource limits every path holds a directive to (§3.12): the per-field caps, the
//! wire body cap, the date range, and the body checks behind them.

use super::*;

// ─── Resource limits (§3.12) ─────────────────────────────────────────────────

/// Maximum number of postings per transaction.
pub const MAX_POSTINGS_PER_TRANSACTION: usize = 1000;
/// Maximum narration length in UTF-8 bytes.
pub const MAX_NARRATION_LENGTH: usize = 10_000;
/// Maximum payee length in UTF-8 bytes.
pub const MAX_PAYEE_LENGTH: usize = 1_000;
/// Maximum tags per transaction.
pub const MAX_TAGS_PER_TRANSACTION: usize = 100;
/// Maximum links per transaction.
pub const MAX_LINKS_PER_TRANSACTION: usize = 100;
/// Maximum metadata keys per directive.
pub const MAX_METADATA_KEYS_PER_DIRECTIVE: usize = 100;
/// Maximum UTF-8 bytes of a remote `economic_bean` body (M-4).
pub const MAX_ECONOMIC_BEAN_LENGTH: usize = 1_048_576;
/// The two §3.12 limits T75 added (L-78, M-48). They are defined in
/// [`crate::limits`] so the parser can count them without the numbers moving
/// here; re-exported so every §3.12 limit is still readable in one place.
pub use crate::limits::{MAX_CURRENCIES_PER_OPEN, MAX_POSTING_METADATA_KEYS_PER_TRANSACTION};
/// Maximum ledger file size on boot, reconcile, and persist (§3.12).
///
/// T44: this bounds the canonical `.bean` **and** the commit journal together —
/// the journal's read budget is whatever is left of this after the canonical
/// file, and an append that would push the pair past it is refused before any
/// bytes are written. So the compacted file can never exceed the cap, and a
/// journal this node wrote can always be booted.
pub const MAX_LEDGER_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Canonical-file size below which every commit simply rewrites the whole
/// `.bean` and no journal is created (T44).
///
/// The journal exists to stop one appended directive costing a whole-file
/// rewrite. Below 64 KiB that rewrite is a single small write plus an fsync —
/// the fsync dominates either way, so the journal would buy nothing and cost a
/// second file, a second failure mode, and a lagging canonical file. Above it
/// the rewrite is what T44 is about.
///
/// A ledger therefore behaves *exactly* as it did before T44 until it grows
/// past this point: same bytes, same write path, no sidecar on disk.
pub const COMPACTION_MIN_CANONICAL_BYTES: u64 = 64 * 1024;

/// Compact once the journal reaches 1/this of the canonical file's size (T44).
///
/// Two is the ratio that makes the amortised cost a constant rather than a
/// function of ledger size: each compaction rewrites `canonical × 3/2` bytes
/// after absorbing `canonical / 2` bytes of journal, so every appended byte
/// costs a bounded ~3 bytes of eventual rewrite however large the ledger gets.
/// A larger ratio would leave more state in the journal (slower boots, longer
/// crash-window replay) for a win that is already constant.
pub(super) const COMPACTION_JOURNAL_RATIO: u64 = 2;

/// Which §3.12 rule set a directive is held to (T81 / M-51, decision (6)).
///
/// Every cap is the same for both except the two T75 introduced — currencies
/// per `open` and posting metadata keys per transaction. What this node
/// AUTHORS keeps T75's caps (64, 100); what it takes as HISTORY — a peer's
/// directive on the wire and at staging, an enveloped record at boot or
/// pasted into the file — is held to the legacy ceilings
/// ([`crate::limits::MAX_CURRENCIES_PER_OPEN_LEGACY`],
/// [`crate::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY`]), so
/// history written before T75 replicates instead of partitioning every
/// replica that lacks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceRule {
    /// What this node writes: the local API and operator input.
    Authoring,
    /// What this node takes from elsewhere: peers, and enveloped history.
    History,
}

/// §3.12 limits for what this node authors — [`ResourceRule::Authoring`].
pub fn enforce_resource_limits(directive: &Directive) -> Result<(), ServiceError> {
    enforce_resource_limits_for(directive, ResourceRule::Authoring)
}

/// §3.12 limits for operator input, counted as the record will be STORED
/// (T81 / M-55, decision (10)).
///
/// The metadata-key cap counts the whole map, envelope included, on every
/// path, and a peer counts the map it receives: body keys plus the full
/// envelope (author, lamport, signature, and parents for a transaction). The
/// file path used to count before the signature was added — 97 body keys on a
/// transaction passed here and arrived at every peer as 101, refused for
/// good, with every later write of this node naming it as a parent. Counting
/// the envelope the stored record will carry closes that gap without changing
/// the wire rule.
pub fn enforce_resource_limits_as_stored(directive: &Directive) -> Result<(), ServiceError> {
    let mut stored = directive.clone();
    let is_transaction = matches!(stored, Directive::Transaction(_));
    let metadata = directive_metadata_mut(&mut stored);
    for key in [
        ENVELOPE_KEY_AUTHOR,
        ENVELOPE_KEY_LAMPORT,
        ENVELOPE_KEY_SIGNATURE,
    ] {
        metadata.entry(key.to_owned()).or_default();
    }
    if is_transaction {
        metadata.entry(ENVELOPE_KEY_PARENTS.to_owned()).or_default();
    }
    enforce_resource_limits_for(&stored, ResourceRule::Authoring)
}

/// §3.12 limits under `rule` — see [`ResourceRule`].
pub fn enforce_resource_limits_for(
    directive: &Directive,
    rule: ResourceRule,
) -> Result<(), ServiceError> {
    let (max_currencies, max_posting_metadata_keys) = match rule {
        ResourceRule::Authoring => (
            MAX_CURRENCIES_PER_OPEN,
            MAX_POSTING_METADATA_KEYS_PER_TRANSACTION,
        ),
        ResourceRule::History => (
            crate::limits::MAX_CURRENCIES_PER_OPEN_LEGACY,
            crate::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY,
        ),
    };
    if directive.metadata().len() > MAX_METADATA_KEYS_PER_DIRECTIVE {
        return Err(ServiceError::ResourceLimitExceeded {
            message: format!(
                "Too many metadata keys: {} (max {})",
                directive.metadata().len(),
                MAX_METADATA_KEYS_PER_DIRECTIVE
            ),
        });
    }

    // L-78 (T75): an `open`'s currency list had no cap at all — a 786 KB
    // `open` of 262,137 currencies staged `Ok` and stayed on every replica.
    // The wire's parser refuses the same count while it reads
    // (`ParseLimits::RESOURCE`); this is the rule for every write path.
    if let Directive::Open(open) = directive {
        if open.currencies.len() > max_currencies {
            return Err(ServiceError::ResourceLimitExceeded {
                message: format!(
                    "Too many currencies in one open: {} (max {max_currencies})",
                    open.currencies.len(),
                ),
            });
        }
    }

    // The amount cap (H-17, T76) is not applied here. It caps what is summed
    // — a transaction's units, costs, prices and resolved leg — and every
    // transaction on every write path goes through `validate_transaction`,
    // which applies it and keeps its `INVALID_POSTING` code. A `balance` or
    // `price` directive's amount is never summed, so it is not capped at all.
    let Directive::Transaction(transaction) = directive else {
        return Ok(());
    };

    if transaction.postings.len() > MAX_POSTINGS_PER_TRANSACTION {
        return Err(ServiceError::ResourceLimitExceeded {
            message: format!(
                "Too many postings: {} (max {})",
                transaction.postings.len(),
                MAX_POSTINGS_PER_TRANSACTION
            ),
        });
    }
    if let Some(ref narration) = transaction.narration {
        if narration.len() > MAX_NARRATION_LENGTH {
            return Err(ServiceError::ResourceLimitExceeded {
                message: format!(
                    "Narration too long: {} bytes (max {})",
                    narration.len(),
                    MAX_NARRATION_LENGTH
                ),
            });
        }
    }
    if let Some(ref payee) = transaction.payee {
        if payee.len() > MAX_PAYEE_LENGTH {
            return Err(ServiceError::ResourceLimitExceeded {
                message: format!(
                    "Payee too long: {} bytes (max {})",
                    payee.len(),
                    MAX_PAYEE_LENGTH
                ),
            });
        }
    }
    if transaction.tags.len() > MAX_TAGS_PER_TRANSACTION {
        return Err(ServiceError::ResourceLimitExceeded {
            message: format!(
                "Too many tags: {} (max {})",
                transaction.tags.len(),
                MAX_TAGS_PER_TRANSACTION
            ),
        });
    }
    if transaction.links.len() > MAX_LINKS_PER_TRANSACTION {
        return Err(ServiceError::ResourceLimitExceeded {
            message: format!(
                "Too many links: {} (max {})",
                transaction.links.len(),
                MAX_LINKS_PER_TRANSACTION
            ),
        });
    }
    // T75 / M-48: posting-level metadata, summed over the postings — see
    // `MAX_POSTING_METADATA_KEYS_PER_TRANSACTION` for why a sum. Nothing
    // counted these before; the local API cannot write them, so this meets
    // only reconciled hand edits and peers.
    let posting_metadata_keys: usize = transaction
        .postings
        .iter()
        .map(|posting| posting.metadata.len())
        .sum();
    if posting_metadata_keys > max_posting_metadata_keys {
        return Err(ServiceError::ResourceLimitExceeded {
            message: format!(
                "Too many posting metadata keys in one transaction: {posting_metadata_keys} \
                 (max {max_posting_metadata_keys})"
            ),
        });
    }
    Ok(())
}

/// Refuse a directive whose canonical economic body exceeds the wire cap (L-02).
///
/// [`MAX_ECONOMIC_BEAN_LENGTH`] is the limit `p2p::union_merge::
/// validate_supply_entry` applies to every arriving `economic_bean`, and it is
/// the *same constant* here on purpose: a directive this node writes but no peer
/// will accept is worse than a rejected write. It persists locally, it is served
/// on every Want, and every peer refuses it forever — a permanent divergence
/// seed planted by a request the API happily answered `200` to. The per-field
/// caps do not bound the body on their own: account names, tag bodies and link
/// bodies have a charset but no length limit, so 1,000 postings (the cap) with
/// kilobyte-long account names, or 100 tags (the cap) of 12 KB each, clear every
/// existing check and still produce a megabytes-long body.
///
/// Costs one canonical serialization of the directive. That is the same order as
/// the `compute_content_id` the caller is about to do anyway and far less than
/// the whole-file rewrite the persist does, so it is not worth caching.
pub fn enforce_economic_bean_limit(directive: &Directive) -> Result<(), ServiceError> {
    let length = crate::serialize::economic_canonical_serialize(directive).len();
    if length > MAX_ECONOMIC_BEAN_LENGTH {
        return Err(ServiceError::ResourceLimitExceeded {
            message: format!(
                "economic body is {length} bytes (max {MAX_ECONOMIC_BEAN_LENGTH}); \
                 a larger directive would be refused by every peer"
            ),
        });
    }
    Ok(())
}

/// Reject an `openledger-parents` entry that is not a well-formed txid (L-29).
///
/// [`parent_txid_is_well_formed`] had exactly **one** production call site —
/// `stage_remote_directive` — so the rule was a wire rule only, and the file was
/// a sibling ingest path with no form check at all. `openledger-parents` is
/// envelope metadata, stripped before the content hash is taken, so a text
/// editor can rewrite a parent to an uppercase spelling of a real txid and **no
/// content id changes**: nothing downstream notices, validation passes, and
/// `LedgerDag::insert` does not check form either.
///
/// Only transactions carry parents, so nothing else can fail this.
pub(super) fn validate_parent_txid_form(directive: &Directive) -> Result<(), ServiceError> {
    let Directive::Transaction(transaction) = directive else {
        return Ok(());
    };
    for parent_id in transaction.parent_ids() {
        if !parent_txid_is_well_formed(parent_id) {
            return Err(ServiceError::InvalidInput {
                message: format!(
                    "openledger-parents entry must be a 64-character lowercase hex txid, \
                     got {parent_id}"
                ),
            });
        }
    }
    Ok(())
}

/// Reject an `openledger-lamport` this node cannot read back as a decimal
/// `u64` (M-20).
///
/// The **format** half of the wire rule in `p2p::union_merge::
/// validate_supply_entry`: non-empty, ASCII digits only, and in `u64` range.
/// `str::parse::<u64>` on its own is not that rule — it accepts `+7` — so the
/// digit scan is load-bearing and is spelled the same way on both sides.
///
/// The **range** half is [`LAMPORT_CEILING`] and is deliberately NOT repeated
/// here: T46 owns that bound and already applies it through [`checked_lamport`]
/// on every path that writes `lamport_clock`, including both file paths. Two
/// spellings of one cap is exactly how the H-07 off-by-one happened.
///
/// Why format matters on the file path at all: reconcile read this value with
/// `.parse::<u64>().ok()` and treated `None` as "leave the clock alone", so a
/// hand-edited `openledger-lamport: "seven"` was adopted, **signed with this
/// node's key**, persisted and served — and then refused by every peer forever
/// on the line above. It also silently unmoored the entry from the
/// `(author, lamport)` uniqueness M-18 depends on, because a value the clock
/// never saw cannot bound what this node stamps next.
pub(super) fn validate_envelope_lamport_form(directive: &Directive) -> Result<(), ServiceError> {
    let Some(value) = directive.metadata().get(ENVELOPE_KEY_LAMPORT) else {
        return Ok(());
    };
    let well_formed = !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok();
    if !well_formed {
        return Err(ServiceError::InvalidInput {
            message: format!(
                "openledger-lamport must be a decimal u64, got {value:?}; \
                 a directive carrying anything else is refused by every peer"
            ),
        });
    }
    Ok(())
}

/// The two ENVELOPE-form rules the wire enforces and the **file** paths did not
/// (M-20).
///
/// `reconcile_content` and `boot` are ingest paths like any other, and since
/// L-11 reconcile *signs* what it adopts — so anything the file accepts and the
/// wire refuses is adopted, signed with this node's key, persisted, served, and
/// then rejected by every peer forever while this node keeps advertising it.
/// That is the permanent-divergence-plus-re-Want-churn shape H-03 and H-06
/// describe, reached through a text editor instead of a peer; the comment on
/// [`enforce_economic_bean_limit`] states the same conclusion for its own cap.
/// Neither is detectable after the fact: both live in `openledger-*` metadata
/// that the content hash strips, so editing them changes no content id and
/// breaks no signature.
///
/// Applied by **both** file paths — [`LedgerService::boot`] (as a quarantine)
/// and [`LedgerService::reconcile_content`] (as a rejection) — from this one
/// definition, so they cannot drift apart from each other the way they both
/// drifted from the wire. Each check is the *same* rule the wire path applies,
/// never a second spelling of it.
///
/// Costs two metadata lookups.
pub(super) fn validate_file_envelope_form(directive: &Directive) -> Result<(), ServiceError> {
    // L-29.
    validate_parent_txid_form(directive)?;
    // M-20's lamport half.
    validate_envelope_lamport_form(directive)?;
    Ok(())
}

/// [`validate_file_envelope_form`] plus the body-size cap — the full wire check
/// set, for the file path that ADMITS NEW RECORDS (M-20, L-02).
///
/// ## Why the bean cap is here — and, since T85, at boot too
///
/// T51 kept it off boot, for the reason below; T85 (L-101, decision (19))
/// applies it there as a content rule that seeds the closure quarantine,
/// because an over-cap record a node serves is not merely refused by peers: it
/// strands everything written on top of it on every replica that lacks it
/// (M-51's shape). The reasoning T51 recorded, kept for the history:
///
/// `reconcile_content` admits records that are not yet part of this ledger and
/// **signs them with this node's key**, so an over-cap body it accepts is a
/// divergence seed this node manufactures: signed here, refused by every peer
/// forever, re-Wanted forever. Refusing it costs nothing that was ever in the
/// ledger.
///
/// `boot` loads records that ARE already this ledger's history. Quarantining an
/// over-cap directive there would take a real transaction out of this node's
/// balances on a file that a pre-L-02 build wrote perfectly legitimately — a
/// much larger consequence than the two envelope-form checks above, which only
/// ever remove a directive whose parents or clock **nobody, including this
/// node, can resolve**. Boot's standing rule is that it applies no write caps
/// (`close_account`'s own size check is reachable precisely because of that),
/// and T51 does not change it.
///
/// T51's residual — an over-cap directive already on disk still loaded and
/// served, refused by every peer — is closed by T85: boot quarantines it with
/// its descendants, named, kept in the file.
///
/// Costs one canonical serialization on top of
/// [`validate_file_envelope_form`] — the same order as the
/// `compute_content_id` the caller does anyway.
pub(super) fn validate_file_ingest_parity(directive: &Directive) -> Result<(), ServiceError> {
    // L-02: nothing else bounds body length on this path — the parser caps
    // charsets, not lengths.
    enforce_economic_bean_limit(directive)?;
    validate_file_envelope_form(directive)?;
    Ok(())
}

/// Re-check account/tag/link charsets on an ingested directive (T37 follow-up).
///
/// **Redundant by design.** On the wire path `validate_supply_entry` re-parses
/// the canonical body through `parse_file` before anything else, and since L-25
/// the parser enforces exactly these rules — so nothing reaching
/// [`LedgerService::stage_remote_directive`] through the P2P stack can fail
/// here. It exists for the same reason T21 duplicated the envelope-key and
/// control-character checks at that boundary: `stage_remote_directive` is a
/// `pub` entry point, the invariant is enforced at ingress rather than by the
/// type (`Posting::account` is a plain `String`), and a future caller that
/// hands it a directive it built in memory rather than parsed would otherwise
/// plant a confusable account with nothing to stop it.
pub fn validate_body_names(directive: &Directive) -> Result<(), ServiceError> {
    let check_account = |account: &String| {
        validate_account_name(account).map_err(|_| ServiceError::InvalidAccountName {
            account: account.clone(),
        })
    };

    match directive {
        Directive::Transaction(transaction) => {
            for tag in &transaction.tags {
                validate_tag(tag).map_err(|_| ServiceError::InvalidTag { tag: tag.clone() })?;
            }
            for link in &transaction.links {
                validate_link(link)
                    .map_err(|_| ServiceError::InvalidLink { link: link.clone() })?;
            }
            for posting in &transaction.postings {
                check_account(&posting.account)?;
            }
        }
        Directive::Open(open) => check_account(&open.account)?,
        Directive::Close(close) => check_account(&close.account)?,
        Directive::Pad(pad) => {
            check_account(&pad.account)?;
            check_account(&pad.source_account)?;
        }
        Directive::Balance(balance) => check_account(&balance.account)?,
        Directive::Note(note) => check_account(&note.account)?,
        Directive::Document(document) => check_account(&document.account)?,
        // Commodity, Event and Price carry no account, tag or link.
        Directive::Commodity(_) | Directive::Event(_) | Directive::Price(_) => {}
    }
    Ok(())
}

// ─── Date range (H-04) ───────────────────────────────────────────────────────

/// Smallest year the `.bean` file grammar can express.
pub const MIN_LEDGER_YEAR: i32 = 1;
/// Largest year the `.bean` file grammar can express.
pub const MAX_LEDGER_YEAR: i32 = 9999;

/// Reject a date the ledger file grammar could never read back (H-04).
///
/// `read_date` in `crate::parse` requires exactly four leading ASCII digits, but
/// `chrono` formats every year outside `0..=9999` with an explicit sign
/// (`+10000-01-01`, `-0001-01-01`). Serializing such a date therefore writes a
/// `.bean` file that no later [`LedgerService::boot`] can parse — a permanent
/// brick. The GraphQL `Date` scalar is the reachable injection point and clamps
/// first; this is the same guarantee for direct callers of the library API.
pub(super) fn validate_ledger_date(date: NaiveDate) -> Result<(), ServiceError> {
    if (MIN_LEDGER_YEAR..=MAX_LEDGER_YEAR).contains(&date.year()) {
        Ok(())
    } else {
        Err(ServiceError::DateOutOfRange { date })
    }
}

/// Check every date a directive will serialize (H-04).
///
/// That is the directive's own date plus, for transactions, each posting's cost
/// date — cost dates are written with the same `%Y-%m-%d` format and brick the
/// file in exactly the same way.
pub fn validate_directive_dates(directive: &Directive) -> Result<(), ServiceError> {
    validate_ledger_date(directive.date())?;

    if let Directive::Transaction(transaction) = directive {
        for posting in &transaction.postings {
            if let Some(cost_date) = posting.cost.as_ref().and_then(|cost| cost.date) {
                validate_ledger_date(cost_date)?;
            }
        }
    }
    Ok(())
}
