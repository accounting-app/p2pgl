//! Envelope keys and body canonicalization (H-03 / H-06 / L-26): parent ids,
//! fan-in, parent selection, and the body string and key checks.

use super::*;

/// True for the exact shape a stored txid has: 64 **lowercase** hex characters.
///
/// `is_ascii_hexdigit` also admits uppercase, but every id the ledger stores is
/// lowercase and every lookup is exact — so an uppercase spelling of a real
/// txid passes validation and then never resolves, leaving the directive an
/// orphan that squats buffer space for its full TTL and re-Wants forever
/// (L-29).
pub(super) fn parent_txid_is_well_formed(parent_id: &str) -> bool {
    parent_id.len() == 64
        && parent_id
            .chars()
            .all(|character| matches!(character, '0'..='9' | 'a'..='f'))
}

// ─── Envelope keys and body canonicalization (H-03 / H-06 / L-26) ────────────

/// Prefix that marks a metadata key as envelope (§3.3.1) rather than economic.
///
/// The economic canonical serializer strips every key with this prefix, so a
/// key carried here is invisible to the content hash.
pub(super) const ENVELOPE_KEY_PREFIX: &str = "openledger-";

/// `openledger-author` — the writing peer's Iroh `EndpointId`.
pub(super) const ENVELOPE_KEY_AUTHOR: &str = "openledger-author";
/// `openledger-lamport` — the writer's Lamport clock value.
pub(super) const ENVELOPE_KEY_LAMPORT: &str = "openledger-lamport";
/// `openledger-parents` — comma-separated parent txids.
pub(super) const ENVELOPE_KEY_PARENTS: &str = "openledger-parents";
/// `openledger-signature` — hex Ed25519 signature over the envelope binding.
pub(super) const ENVELOPE_KEY_SIGNATURE: &str = "openledger-signature";

/// The closed set of envelope metadata keys (§3.3.1).
///
/// These four keys — and only these — are written by
/// [`LedgerService::stamp_transaction_envelope`] and
/// [`LedgerService::stamp_directive_envelope`], accepted in a remote `Supply`
/// envelope (`p2p::union_merge::ALLOWED_ENVELOPE_KEYS` aliases this slice, so
/// the wire set can never drift from the stamped set), and permitted at
/// directive level in a `.bean` file. Anything else with the
/// `openledger-` prefix is unvalidated metadata masquerading as envelope, and
/// is rejected on every ingest path (H-06).
pub const ENVELOPE_KEYS: &[&str] = &[
    ENVELOPE_KEY_AUTHOR,
    ENVELOPE_KEY_LAMPORT,
    ENVELOPE_KEY_PARENTS,
    ENVELOPE_KEY_SIGNATURE,
];

/// Maximum number of entries in `openledger-parents` (M-4, L-14, T41).
///
/// Each parent becomes a distinct `waiting_on` entry in a receiving peer's
/// orphan buffer, and each is a node the DAG's cycle check may have to walk, so
/// an unbounded list is both a memory-exhaustion vector and a CPU one. Real DAG
/// head counts are tiny — concurrent in-flight writers — and 256 is generous.
///
/// Single-sourced here and aliased by `p2p::union_merge`, for the same reason
/// [`ENVELOPE_KEYS`] is: the wire path and the file path must not be able to
/// drift apart about what a legal envelope looks like. Until T41 the cap lived
/// in `p2p` and applied to the wire ONLY, so a hand-written `.bean` could carry
/// an `openledger-parents` list of any length — which is precisely what L-14's
/// decoy transaction does, naming every id in the chain that follows it.
pub const MAX_PARENTS: usize = 256;

// There is deliberately NO remote per-author head bound any more (T72 / H-21;
// decided 2026-09-23). T64 refused a parentless remote transaction once its
// author owned 256 heads *on this replica* — a number only this replica holds,
// so two honest replicas served disjoint 256-subsets of one 257-flood each
// refused the one the other held, and anti-entropy between them could never
// repair it: same available set, two permanently different DAGs, healed only
// by a local append on EACH. Frontier size is a convergent cost; membership
// divergence is not. H-16's actual brick — the victim's own append naming 257
// parents — is closed by [`LedgerService::choose_parents`]'s truncation plus
// [`validate_parent_fan_in`], neither of which reads a per-replica count.

/// Reject a directive whose `openledger-parents` fan-in exceeds
/// [`MAX_PARENTS`] (T41).
///
/// Only transactions carry parents, so nothing else can fail this.
pub fn validate_parent_fan_in(directive: &Directive) -> Result<(), ServiceError> {
    let Directive::Transaction(transaction) = directive else {
        return Ok(());
    };
    let count = transaction.parent_ids().len();
    if count > MAX_PARENTS {
        return Err(ServiceError::InvalidInput {
            message: format!("openledger-parents has {count} entries (max {MAX_PARENTS})"),
        });
    }
    Ok(())
}

/// Which of the admissible heads a locally stamped transaction names as its
/// parents (T64 / H-16; T72 / L-68) — at most [`MAX_PARENTS`] of them.
///
/// `candidates` is every admissible head with its author; it is sorted here,
/// so callers may pass it in any order. Returns the chosen ids in ascending
/// order.
///
/// # The rule
///
/// When the heads fit, all of them. Otherwise, with `A` distinct head authors:
///
/// 1. **Author diversity first.** Walking the heads smallest-id first, take a
///    head while its author has fewer than `max(1, MAX_PARENTS / A)` taken.
/// 2. **Then smallest id.** Fill the remaining slots with the smallest-id heads
///    not yet taken.
///
/// Deterministic — a pure function of the head set — so every replica holding
/// the same heads names the same parents, which the local stamp's replication
/// depends on (a peer re-derives nothing; it checks the count).
///
/// # Why not smallest id alone (L-68)
///
/// T64 named the `MAX_PARENTS` lexicographically smallest heads. A content id
/// is a SHA-256 over the body, and a narration field is free text, so an
/// author can grind ids: ~10 candidate bodies per head kept every attacker
/// head below every honest one, and the victim's appends named only attacker
/// heads. Each honest append then became a permanent head mesh-wide — never
/// merged by anyone — and the frontier grew by one per honest write. Under
/// rule 1 the attacker's share of one append is capped at `MAX_PARENTS / A`
/// however small its ids are, so an honest author's head (at most a few per
/// author, since every append merges that author's previous ones) is always
/// named; grinding ids buys the attacker nothing but which of its own heads
/// are merged first.
pub fn select_parents<'a>(candidates: &mut [(&'a str, Option<&'a str>)]) -> Vec<&'a str> {
    candidates.sort_unstable();
    if candidates.len() <= MAX_PARENTS {
        return candidates.iter().map(|(id, _)| *id).collect();
    }
    let distinct_authors = candidates
        .iter()
        .map(|(_, author)| *author)
        .collect::<HashSet<Option<&str>>>()
        .len()
        .max(1);
    let per_author = (MAX_PARENTS / distinct_authors).max(1);
    let mut taken_by_author: HashMap<Option<&str>, usize> = HashMap::new();
    let mut chosen = vec![false; candidates.len()];
    let mut taken = 0usize;
    for (index, (_, author)) in candidates.iter().enumerate() {
        if taken == MAX_PARENTS {
            break;
        }
        let count = taken_by_author.entry(*author).or_insert(0);
        if *count < per_author {
            *count += 1;
            chosen[index] = true;
            taken += 1;
        }
    }
    for flag in chosen.iter_mut() {
        if taken == MAX_PARENTS {
            break;
        }
        if !*flag {
            *flag = true;
            taken += 1;
        }
    }
    candidates
        .iter()
        .zip(chosen)
        .filter(|(_, chosen)| *chosen)
        .map(|((id, _), _)| *id)
        .collect()
}

/// Reject `openledger-*` metadata the envelope rules do not permit (H-06).
///
/// The content hash strips every `openledger-*` key, so such a key smuggled in
/// an economic body is validated by nothing, is persisted into the receiving
/// replica's `.bean`, and is promoted back into the envelope when that replica
/// re-serves the directive — where the next hop's closed-set check rejects it
/// forever. Directive-level keys must be in `allowed_directive_level` (pass
/// [`ENVELOPE_KEYS`] where a merged envelope legitimately sits at directive
/// level, `&[]` on the wire path where the body must carry none). Posting-level
/// metadata never carries an envelope key: `extract_envelope` would promote one
/// just the same, and no writer produces one.
pub fn validate_body_envelope_keys(
    directive: &Directive,
    allowed_directive_level: &[&str],
) -> Result<(), ServiceError> {
    for key in directive.metadata().keys() {
        if key.starts_with(ENVELOPE_KEY_PREFIX) && !allowed_directive_level.contains(&key.as_str())
        {
            return Err(ServiceError::BodyEnvelopeKey { key: key.clone() });
        }
    }

    if let Directive::Transaction(transaction) = directive {
        for posting in &transaction.postings {
            for key in posting.metadata.keys() {
                if key.starts_with(ENVELOPE_KEY_PREFIX) {
                    return Err(ServiceError::BodyEnvelopeKey { key: key.clone() });
                }
            }
        }
    }
    Ok(())
}

/// Drop every `openledger-*` key a node-written record may not carry — at
/// directive level, one that is not one of the four [`ENVELOPE_KEYS`]; at
/// posting level, every one — and return what was dropped, posting-level keys
/// prefixed `posting:` (T83 / L-89; T89 / L-109, L-112, decision (34)).
///
/// None of them is hashed (`economic_canonical_serialize` omits every
/// `openledger-*` key) or signed, and no peer ever receives one
/// (`extract_envelope` keeps the closed set), so the record keeps its id, its
/// signature and its place in every balance. Boot and the live reconcile both
/// strip a complete envelope this way; operator input keeps H-06's refusal.
pub(super) fn strip_stray_envelope_keys(directive: &mut Directive) -> Vec<String> {
    let mut stripped = Vec::new();
    let metadata = directive_metadata_mut(directive);
    let stray: Vec<String> = metadata
        .keys()
        .filter(|key| {
            key.starts_with(ENVELOPE_KEY_PREFIX) && !ENVELOPE_KEYS.contains(&key.as_str())
        })
        .cloned()
        .collect();
    for key in stray {
        metadata.remove(&key);
        stripped.push(key);
    }
    if let Directive::Transaction(transaction) = directive {
        for posting in &mut transaction.postings {
            let stray: Vec<String> = posting
                .metadata
                .keys()
                .filter(|key| key.starts_with(ENVELOPE_KEY_PREFIX))
                .cloned()
                .collect();
            for key in stray {
                posting.metadata.remove(&key);
                stripped.push(format!("posting:{key}"));
            }
        }
    }
    stripped
}

/// Reject control characters in every string a directive carries (L-26).
///
/// [`reject_control_characters`] guards the local append path only, but a
/// directive also arrives from peers and from hand-edited files, and every
/// string it carries is written verbatim on the next persist — so an ESC, NUL
/// or TAB accepted here lands in every replica's `.bean`. Envelope values are
/// hex/decimal/CSV and pass naturally, so nothing is special-cased.
pub fn validate_body_strings(directive: &Directive) -> Result<(), ServiceError> {
    validate_metadata_strings(directive.metadata())?;

    match directive {
        Directive::Transaction(transaction) => {
            if let Some(ref payee) = transaction.payee {
                validate_body_string("payee", payee)?;
            }
            if let Some(ref narration) = transaction.narration {
                validate_body_string("narration", narration)?;
            }
            for tag in &transaction.tags {
                validate_body_string("tag", tag)?;
            }
            for link in &transaction.links {
                validate_body_string("link", link)?;
            }
            for posting in &transaction.postings {
                validate_body_string("account name", &posting.account)?;
                if let Some(ref amount) = posting.amount {
                    validate_body_string("currency", &amount.currency)?;
                }
                if let Some(cost_amount) =
                    posting.cost.as_ref().and_then(|cost| cost.amount.as_ref())
                {
                    validate_body_string("currency", &cost_amount.currency)?;
                }
                if let Some(ref price) = posting.price {
                    let currency = match price {
                        PriceSpec::Unit(amount) | PriceSpec::Total(amount) => &amount.currency,
                    };
                    validate_body_string("currency", currency)?;
                }
                validate_metadata_strings(&posting.metadata)?;
            }
        }
        Directive::Open(open) => {
            validate_body_string("account name", &open.account)?;
            for currency in &open.currencies {
                validate_body_string("currency", currency)?;
            }
        }
        Directive::Close(close) => validate_body_string("account name", &close.account)?,
        Directive::Commodity(commodity) => validate_body_string("currency", &commodity.currency)?,
        Directive::Pad(pad) => {
            validate_body_string("account name", &pad.account)?;
            validate_body_string("account name", &pad.source_account)?;
        }
        Directive::Balance(balance) => {
            validate_body_string("account name", &balance.account)?;
            validate_body_string("currency", &balance.amount.currency)?;
        }
        Directive::Note(note) => {
            validate_body_string("account name", &note.account)?;
            validate_body_string("note comment", &note.comment)?;
        }
        Directive::Document(document) => {
            validate_body_string("account name", &document.account)?;
            validate_body_string("document path", &document.path)?;
        }
        Directive::Event(event) => {
            validate_body_string("event type", &event.event_type)?;
            validate_body_string("event description", &event.description)?;
        }
        Directive::Price(price) => {
            validate_body_string("currency", &price.currency)?;
            validate_body_string("currency", &price.amount.currency)?;
        }
    }
    Ok(())
}

pub(super) fn validate_body_string(label: &str, value: &str) -> Result<(), ServiceError> {
    reject_control_characters(label, value)
        .map_err(|message| ServiceError::InvalidInput { message })
}

pub(super) fn validate_metadata_strings(metadata: &Metadata) -> Result<(), ServiceError> {
    for (key, value) in metadata {
        validate_body_string("metadata key", key)?;
        // T41: the L-25 charset rule, extended to metadata KEYS. Single-sourced
        // in `parse::validate_metadata_key` and enforced from both sides, the
        // way L-25 single-sources the account/tag/link predicates — the parser
        // covers the file and (via `validate_supply_entry`'s re-parse) the wire,
        // and this covers a library caller that builds a `Directive` in memory.
        validate_metadata_key(key).map_err(|message| ServiceError::InvalidInput { message })?;
        validate_body_string("metadata value", value)?;
    }
    Ok(())
}

/// Count the postings whose amount is elided (I2), i.e. `amount: None` (H-03).
///
/// An ingested directive must arrive resolved: the content id is computed over
/// the as-sent body, but the resolved postings are what gets stored and
/// re-hashed, so an elided body is accepted under one id and stored under
/// another — a directive that can never propagate.
pub fn elided_posting_count(transaction: &Transaction) -> usize {
    transaction
        .postings
        .iter()
        .filter(|posting| posting.amount.is_none())
        .count()
}
