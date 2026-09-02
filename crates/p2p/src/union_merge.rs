//! Union merge — G-Set merge for remote directives (§3.4, §3.5).
//!
//! Validates incoming directives from peers (same acceptance laws as local
//! writes), inserts into the DAG, updates the read model, and adopts
//! the Lamport clock.

use std::collections::BTreeMap;
use std::str::FromStr;

use iroh::EndpointId;
use ledger::hash::compute_content_id;
use ledger::model::*;
use ledger::parse::parse_file;

use crate::allowlist::PeerAllowlist;
use crate::protocol::{DirectiveKind, SupplyEntry};

/// Closed set of envelope keys accepted on remote `Supply` (§3.3.1).
const ALLOWED_ENVELOPE_KEYS: &[&str] = &[
    "openledger-author",
    "openledger-lamport",
    "openledger-parents",
    "openledger-signature",
];

/// Maximum byte length of any single envelope value (M-4 DoS bound).
///
/// The largest legitimate value is `openledger-parents` at
/// `MAX_PARENTS × (64-hex + comma)` ≈ 16.6 KiB; 32 KiB leaves headroom while
/// cheaply rejecting the ~16 MiB blobs that would otherwise be split into an
/// enormous parent list.
const MAX_ENVELOPE_VALUE_LEN: usize = 32 * 1024;

/// Maximum number of parents in `openledger-parents`.
///
/// Each parent becomes a distinct `waiting_on` entry in the orphan buffer, so an
/// unbounded list is a memory-exhaustion vector (M-4). Real DAG head counts are
/// tiny (concurrent in-flight writers); 256 is generous.
const MAX_PARENTS: usize = 256;

/// Maximum accepted remote `openledger-lamport` value (0820-M3 completion).
///
/// The clock update saturates, so without an inbound bound a single peer
/// sending `u64::MAX` would pin every replica's clock at the saturation point
/// forever, degenerating Lamport ordering to all-ties. Legitimate clocks track
/// mesh event counts (the 64 MiB file cap bounds directives to well under a
/// million), so 2^53 is absurd headroom for honest traffic while keeping
/// `u64::MAX` unreachable — from this cap the clock would need 2^63 further
/// single-step increments to saturate.
const MAX_REMOTE_LAMPORT: u64 = 1 << 53;

/// Errors that can occur during merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// Content hash mismatch (I5).
    ContentHashMismatch { claimed: String, computed: String },
    /// Failed to parse the economic body.
    ParseError(String),
    /// Invariant validation failed.
    ValidationError(String),
    /// Missing required envelope fields.
    EnvelopeMissing(String),
    /// Signature missing or invalid when signing is enabled (C-3 / §3.8.1).
    InvalidSignature(String),
    /// Economic body or envelope exceeds §3.12 limits (M-4).
    ResourceLimitExceeded(String),
    /// DAG cycle detected (I8).
    CycleDetected,
    /// Envelope key, control character, or kind mismatch (H-8).
    InvalidEnvelope(String),
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergeError::ContentHashMismatch { claimed, computed } => {
                write!(
                    f,
                    "Content hash mismatch: claimed {claimed}, computed {computed}"
                )
            }
            MergeError::ParseError(e) => write!(f, "Parse error: {e}"),
            MergeError::ValidationError(e) => write!(f, "Validation error: {e}"),
            MergeError::EnvelopeMissing(field) => {
                write!(f, "Missing required envelope field: {field}")
            }
            MergeError::InvalidSignature(reason) => write!(f, "Invalid signature: {reason}"),
            MergeError::ResourceLimitExceeded(reason) => {
                write!(f, "Resource limit exceeded: {reason}")
            }
            MergeError::CycleDetected => write!(f, "DAG cycle detected (I8)"),
            MergeError::InvalidEnvelope(reason) => write!(f, "Invalid envelope: {reason}"),
        }
    }
}

impl std::error::Error for MergeError {}

/// The result of merging a single supply entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeResult {
    /// The entry was new and successfully merged.
    Inserted { id: String },
    /// The entry was already present (idempotent, I4).
    Duplicate { id: String },
    /// The entry was rejected for a validation reason.
    Rejected { id: String, reason: MergeError },
    /// The entry's parents are missing; buffered as an orphan.
    Orphaned {
        id: String,
        missing_parents: Vec<String>,
    },
}

/// Parse and validate a supply entry from a remote peer.
///
/// This is the first half of the merge process: parse the economic body,
/// verify the content hash (I5), and attach envelope metadata.
///
/// Returns the fully-assembled directive ready for DAG insertion.
pub fn validate_supply_entry(entry: &SupplyEntry) -> Result<Directive, MergeError> {
    if entry.economic_bean.len() > ledger::service::MAX_ECONOMIC_BEAN_LENGTH {
        return Err(MergeError::ResourceLimitExceeded(format!(
            "economic_bean is {} bytes (max {})",
            entry.economic_bean.len(),
            ledger::service::MAX_ECONOMIC_BEAN_LENGTH
        )));
    }

    // 1. Parse the economic body.
    let directives = parse_file(&entry.economic_bean).map_err(|errors| {
        let msgs: Vec<String> = errors.iter().map(|e| format!("{e:?}")).collect();
        MergeError::ParseError(msgs.join("; "))
    })?;

    if directives.len() != 1 {
        return Err(MergeError::ParseError(
            "economic_bean must contain exactly one directive".to_owned(),
        ));
    }

    let mut directive = directives.into_iter().next().unwrap();

    if DirectiveKind::from_directive(&directive) != entry.kind {
        return Err(MergeError::InvalidEnvelope(
            "entry kind does not match economic body".to_owned(),
        ));
    }

    // 2. Verify content hash (I5): id == hash(economic_bean).
    let computed = compute_content_id(&directive);
    if computed != entry.id {
        return Err(MergeError::ContentHashMismatch {
            claimed: entry.id.clone(),
            computed,
        });
    }

    validate_supply_envelope(&entry.envelope)?;

    // 3. Attach envelope metadata.
    let metadata = directive_metadata_mut(&mut directive);
    for (key, value) in &entry.envelope {
        metadata.insert(key.clone(), value.clone());
    }

    // 4. Validate required envelope fields for transactions.
    if let Directive::Transaction(_) = &directive {
        if !entry.envelope.contains_key("openledger-author") {
            return Err(MergeError::EnvelopeMissing("openledger-author".to_owned()));
        }
        if !entry.envelope.contains_key("openledger-lamport") {
            return Err(MergeError::EnvelopeMissing("openledger-lamport".to_owned()));
        }
        // openledger-parents may be empty string for genesis.
    }

    // 5. Strict envelope value validation — for every directive kind carrying
    // these keys, not just transactions: `insert_remote_directive` adopts the
    // Lamport clock from every kind's metadata, so a bound enforced only on
    // transactions is bypassable with a signed `open`/`note`/… directive
    // (0820-M3 completion). Checked on the merged metadata so body-embedded
    // values are covered as well as envelope-supplied ones.
    let metadata = directive_metadata(&directive);

    if let Some(parents_value) = metadata.get("openledger-parents") {
        // Bound parent fan-in (M-4): each parent becomes a `waiting_on` entry
        // in the orphan buffer, so an unbounded list is a memory-exhaustion
        // vector. Split identically to `Transaction::parent_ids`.
        let parent_ids: Vec<&str> = parents_value
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect();
        if parent_ids.len() > MAX_PARENTS {
            return Err(MergeError::ResourceLimitExceeded(format!(
                "openledger-parents has {} entries (max {MAX_PARENTS})",
                parent_ids.len()
            )));
        }

        // Every parent must be a well-formed 64-hex txid (0820-L8/M-05). The
        // DAG insert enforces this anyway, but checking here — before the
        // orphan buffer — stops a directive waiting on garbage parents that can
        // never arrive from squatting buffer space for the full TTL.
        for parent_id in &parent_ids {
            if parent_id.len() != 64 || !parent_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(MergeError::InvalidEnvelope(
                    "openledger-parents contains a malformed txid".to_owned(),
                ));
            }
        }
    }

    if let Some(lamport) = metadata.get("openledger-lamport") {
        // Strict inbound Lamport validation (0820-M3 completion): the value must
        // be a plain decimal u64 within the plausibility cap. Without this, a
        // garbage string is silently persisted verbatim, and a huge value pins
        // every replica's saturating clock permanently.
        let lamport_ok = !lamport.is_empty()
            && lamport.bytes().all(|b| b.is_ascii_digit())
            && lamport
                .parse::<u64>()
                .is_ok_and(|value| value <= MAX_REMOTE_LAMPORT);
        if !lamport_ok {
            return Err(MergeError::InvalidEnvelope(format!(
                "openledger-lamport must be a decimal u64 ≤ {MAX_REMOTE_LAMPORT}"
            )));
        }
    }

    Ok(directive)
}

fn validate_supply_envelope(envelope: &BTreeMap<String, String>) -> Result<(), MergeError> {
    for (key, value) in envelope {
        if !ALLOWED_ENVELOPE_KEYS.contains(&key.as_str()) {
            return Err(MergeError::InvalidEnvelope(format!(
                "unsupported envelope key: {key}"
            )));
        }
        // Reject oversized values before any downstream parsing (M-4). This
        // caps the giant `openledger-parents` blobs cheaply, before the parent
        // list is split/collected.
        if value.len() > MAX_ENVELOPE_VALUE_LEN {
            return Err(MergeError::ResourceLimitExceeded(format!(
                "envelope value for {key} is {} bytes (max {MAX_ENVELOPE_VALUE_LEN})",
                value.len()
            )));
        }
        if key.chars().any(char::is_control) || value.chars().any(char::is_control) {
            return Err(MergeError::InvalidEnvelope(
                "envelope key or value contains control characters".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Verify `openledger-signature` when signing is enabled (§3.5 step 4 / C-3).
///
/// Signing off: unsigned entries are accepted. Signing on: missing or invalid
/// signatures are rejected. The author's public key is `openledger-author`
/// (Iroh `EndpointId` hex). `mesh_id` is the verifying node's own mesh identity
/// (swarm topic); a signature made for a different mesh will not verify (L2).
pub fn verify_remote_signature(
    directive: &Directive,
    signing_enabled: bool,
    mesh_id: &str,
) -> Result<(), MergeError> {
    if !signing_enabled {
        return Ok(());
    }

    let metadata = directive_metadata(directive);
    let author = metadata
        .get("openledger-author")
        .ok_or_else(|| MergeError::EnvelopeMissing("openledger-author".to_owned()))?;
    let signature = metadata
        .get("openledger-signature")
        .ok_or_else(|| MergeError::EnvelopeMissing("openledger-signature".to_owned()))?;

    let content_id = compute_content_id(directive);
    let is_transaction = matches!(directive, Directive::Transaction(_));
    let parents = metadata
        .get("openledger-parents")
        .map(String::as_str)
        .unwrap_or("");
    let lamport = metadata
        .get("openledger-lamport")
        .ok_or_else(|| MergeError::EnvelopeMissing("openledger-lamport".to_owned()))?;
    security::signing::verify_signature(
        &security::signing::SignableMessage {
            content_id: &content_id,
            is_transaction,
            parents,
            lamport,
        },
        signature,
        author,
        mesh_id,
    )
    .map_err(|error| MergeError::InvalidSignature(error.to_string()))
}

/// Require `openledger-author` to be a bootstrap `EndpointId` (H-14).
///
/// ALPN write path: the connection peer is authenticated separately; this
/// check stops a trusted replica from inserting directives claimed by a
/// stranger.
pub fn verify_author_allowlisted(
    directive: &Directive,
    allowlist: &PeerAllowlist,
) -> Result<(), MergeError> {
    let author = directive_metadata(directive)
        .get("openledger-author")
        .ok_or_else(|| MergeError::EnvelopeMissing("openledger-author".to_owned()))?;
    let endpoint_id = EndpointId::from_str(author).map_err(|error| {
        MergeError::InvalidEnvelope(format!(
            "openledger-author is not a valid EndpointId: {error}"
        ))
    })?;
    if !allowlist.admits(endpoint_id) {
        return Err(MergeError::InvalidEnvelope(
            "openledger-author is not on the peer allowlist".to_owned(),
        ));
    }
    Ok(())
}

/// Immutable envelope metadata on any directive.
fn directive_metadata(directive: &Directive) -> &BTreeMap<String, String> {
    match directive {
        Directive::Transaction(d) => &d.metadata,
        Directive::Open(d) => &d.metadata,
        Directive::Close(d) => &d.metadata,
        Directive::Commodity(d) => &d.metadata,
        Directive::Pad(d) => &d.metadata,
        Directive::Balance(d) => &d.metadata,
        Directive::Note(d) => &d.metadata,
        Directive::Document(d) => &d.metadata,
        Directive::Event(d) => &d.metadata,
        Directive::Price(d) => &d.metadata,
    }
}

/// Extract the Lamport clock value from a directive's metadata.
pub fn extract_lamport(directive: &Directive) -> Option<u64> {
    if let Directive::Transaction(txn) = directive {
        txn.lamport_clock()
    } else {
        let metadata = match directive {
            Directive::Open(d) => &d.metadata,
            Directive::Close(d) => &d.metadata,
            Directive::Commodity(d) => &d.metadata,
            Directive::Pad(d) => &d.metadata,
            Directive::Balance(d) => &d.metadata,
            Directive::Note(d) => &d.metadata,
            Directive::Document(d) => &d.metadata,
            Directive::Event(d) => &d.metadata,
            Directive::Price(d) => &d.metadata,
            Directive::Transaction(_) => unreachable!(),
        };
        metadata
            .get("openledger-lamport")
            .and_then(|v| v.parse().ok())
    }
}

/// Extract the parent txids from a directive's metadata.
pub fn extract_parents(directive: &Directive) -> Vec<String> {
    let metadata = match directive {
        Directive::Transaction(txn) => &txn.metadata,
        Directive::Open(d) => &d.metadata,
        Directive::Close(d) => &d.metadata,
        Directive::Commodity(d) => &d.metadata,
        Directive::Pad(d) => &d.metadata,
        Directive::Balance(d) => &d.metadata,
        Directive::Note(d) => &d.metadata,
        Directive::Document(d) => &d.metadata,
        Directive::Event(d) => &d.metadata,
        Directive::Price(d) => &d.metadata,
    };

    match metadata.get("openledger-parents") {
        Some(v) if v.is_empty() => vec![],
        Some(v) => v.split(',').map(|s| s.trim().to_owned()).collect(),
        None => vec![],
    }
}

/// Get a mutable reference to a directive's metadata.
fn directive_metadata_mut(directive: &mut Directive) -> &mut BTreeMap<String, String> {
    match directive {
        Directive::Transaction(d) => &mut d.metadata,
        Directive::Open(d) => &mut d.metadata,
        Directive::Close(d) => &mut d.metadata,
        Directive::Commodity(d) => &mut d.metadata,
        Directive::Pad(d) => &mut d.metadata,
        Directive::Balance(d) => &mut d.metadata,
        Directive::Note(d) => &mut d.metadata,
        Directive::Document(d) => &mut d.metadata,
        Directive::Event(d) => &mut d.metadata,
        Directive::Price(d) => &mut d.metadata,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ledger::hash::compute_content_id;
    use ledger::serialize::economic_canonical_serialize;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_valid_supply_entry() -> SupplyEntry {
        let txn = Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            flag: Flag::Complete,
            payee: Some("Acme Corp".to_owned()),
            narration: Some("Test merge".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };
        let directive = Directive::Transaction(txn);
        let id = compute_content_id(&directive);
        let economic_bean = economic_canonical_serialize(&directive);

        SupplyEntry {
            id,
            kind: DirectiveKind::Transaction,
            economic_bean,
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "peer-1".to_owned()),
                ("openledger-lamport".to_owned(), "5".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        }
    }

    fn sign_supply_entry(
        provider: &security::signing::PeerKeySignatureProvider,
        entry: &SupplyEntry,
    ) -> String {
        use security::signing::{SignableMessage, SignatureProvider};
        let is_transaction = entry.kind == DirectiveKind::Transaction;
        let parents = entry
            .envelope
            .get("openledger-parents")
            .map(String::as_str)
            .unwrap_or("");
        let lamport = entry
            .envelope
            .get("openledger-lamport")
            .map(String::as_str)
            .unwrap_or("");
        provider
            .sign(&SignableMessage {
                content_id: &entry.id,
                is_transaction,
                parents,
                lamport,
            })
            .unwrap()
    }

    #[test]
    fn test_validate_supply_entry_success() {
        let entry = make_valid_supply_entry();
        let result = validate_supply_entry(&entry);
        assert!(result.is_ok(), "Valid entry should pass: {result:?}");

        let directive = result.unwrap();
        // Envelope metadata should be attached.
        if let Directive::Transaction(txn) = &directive {
            assert_eq!(
                txn.metadata.get("openledger-author"),
                Some(&"peer-1".to_owned())
            );
            assert_eq!(
                txn.metadata.get("openledger-lamport"),
                Some(&"5".to_owned())
            );
        } else {
            panic!("Expected Transaction");
        }
    }

    #[test]
    fn test_validate_content_hash_mismatch() {
        let mut entry = make_valid_supply_entry();
        entry.id = "0000000000000000000000000000000000000000000000000000000000000000".to_owned();

        let result = validate_supply_entry(&entry);
        assert!(matches!(
            result,
            Err(MergeError::ContentHashMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_missing_author() {
        let mut entry = make_valid_supply_entry();
        entry.envelope.remove("openledger-author");

        let result = validate_supply_entry(&entry);
        assert!(matches!(
            result,
            Err(MergeError::EnvelopeMissing(ref field)) if field == "openledger-author"
        ));
    }

    #[test]
    fn test_validate_missing_lamport() {
        let mut entry = make_valid_supply_entry();
        entry.envelope.remove("openledger-lamport");

        let result = validate_supply_entry(&entry);
        assert!(matches!(
            result,
            Err(MergeError::EnvelopeMissing(ref field)) if field == "openledger-lamport"
        ));
    }

    #[test]
    fn test_validate_empty_body() {
        let entry = SupplyEntry {
            id: "abc".to_owned(),
            kind: DirectiveKind::Transaction,
            economic_bean: "".to_owned(),
            envelope: BTreeMap::new(),
        };

        let result = validate_supply_entry(&entry);
        assert!(matches!(result, Err(MergeError::ParseError(_))));
    }

    #[test]
    fn test_validate_unparseable_body() {
        let entry = SupplyEntry {
            id: "abc".to_owned(),
            kind: DirectiveKind::Transaction,
            economic_bean: "this is not valid beancount".to_owned(),
            envelope: BTreeMap::new(),
        };

        let result = validate_supply_entry(&entry);
        assert!(matches!(result, Err(MergeError::ParseError(_))));
    }

    #[test]
    fn test_extract_lamport() {
        let entry = make_valid_supply_entry();
        let directive = validate_supply_entry(&entry).unwrap();
        let lamport = extract_lamport(&directive);
        assert_eq!(lamport, Some(5));
    }

    #[test]
    fn test_extract_parents_empty() {
        let entry = make_valid_supply_entry();
        let directive = validate_supply_entry(&entry).unwrap();
        let parents = extract_parents(&directive);
        assert!(parents.is_empty(), "Genesis has empty parents");
    }

    #[test]
    fn test_extract_parents_multiple() {
        // Parents must be well-formed 64-hex txids (enforced pre-buffer).
        let parent_a = "a".repeat(64);
        let parent_b = "b".repeat(64);
        let parent_c = "c".repeat(64);
        let mut entry = make_valid_supply_entry();
        entry.envelope.insert(
            "openledger-parents".to_owned(),
            format!("{parent_a},{parent_b},{parent_c}"),
        );
        let directive = validate_supply_entry(&entry).unwrap();
        let parents = extract_parents(&directive);
        assert_eq!(parents, vec![parent_a, parent_b, parent_c]);
    }

    #[test]
    fn test_validate_rejects_malformed_parent_txid() {
        // 0820-L8 completion: garbage parents must be rejected before the
        // orphan buffer, not an hour after.
        let mut entry = make_valid_supply_entry();
        entry
            .envelope
            .insert("openledger-parents".to_owned(), "not-a-txid".to_owned());
        let err = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(err, MergeError::InvalidEnvelope(_)),
            "expected InvalidEnvelope, got {err:?}"
        );
    }

    #[test]
    fn test_validate_rejects_lamport_u64_max() {
        // 0820-M3 completion: a saturating-clock pin at u64::MAX must be
        // rejected at the door.
        let mut entry = make_valid_supply_entry();
        entry
            .envelope
            .insert("openledger-lamport".to_owned(), u64::MAX.to_string());
        let err = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(err, MergeError::InvalidEnvelope(_)),
            "expected InvalidEnvelope, got {err:?}"
        );
    }

    #[test]
    fn test_validate_rejects_non_numeric_lamport() {
        let mut entry = make_valid_supply_entry();
        for bad in ["", "garbage", "+5", "-1", "5.0", "1e9"] {
            entry
                .envelope
                .insert("openledger-lamport".to_owned(), bad.to_owned());
            assert!(
                matches!(
                    validate_supply_entry(&entry),
                    Err(MergeError::InvalidEnvelope(_))
                ),
                "lamport {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_validate_accepts_plain_decimal_lamport() {
        let mut entry = make_valid_supply_entry();
        entry
            .envelope
            .insert("openledger-lamport".to_owned(), "123456".to_owned());
        assert!(validate_supply_entry(&entry).is_ok());
    }

    fn make_open_supply_entry() -> SupplyEntry {
        let directive = Directive::Open(Open {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            account: "Assets:Cash".to_owned(),
            currencies: vec![],
            metadata: BTreeMap::new(),
        });
        SupplyEntry {
            id: compute_content_id(&directive),
            kind: DirectiveKind::Open,
            economic_bean: economic_canonical_serialize(&directive),
            envelope: BTreeMap::new(),
        }
    }

    #[test]
    fn test_validate_bounds_lamport_on_non_transaction_directives() {
        // The Lamport clock is adopted from EVERY directive kind's metadata, so
        // the strict bound must apply beyond transactions — otherwise a signed
        // `open` with u64::MAX pins every replica's clock (0820-M3 completion).
        let mut entry = make_open_supply_entry();
        for bad in [u64::MAX.to_string(), "garbage".to_owned(), "+5".to_owned()] {
            entry
                .envelope
                .insert("openledger-lamport".to_owned(), bad.clone());
            assert!(
                matches!(
                    validate_supply_entry(&entry),
                    Err(MergeError::InvalidEnvelope(_))
                ),
                "non-transaction lamport {bad:?} must be rejected"
            );
        }
        entry
            .envelope
            .insert("openledger-lamport".to_owned(), "42".to_owned());
        assert!(validate_supply_entry(&entry).is_ok());
    }

    #[test]
    fn test_validate_bounds_parents_on_non_transaction_directives() {
        let mut entry = make_open_supply_entry();
        entry
            .envelope
            .insert("openledger-parents".to_owned(), "not-a-txid".to_owned());
        assert!(
            matches!(
                validate_supply_entry(&entry),
                Err(MergeError::InvalidEnvelope(_))
            ),
            "malformed parents on a non-transaction directive must be rejected"
        );
    }

    #[test]
    fn test_validate_rejects_excessive_parents() {
        // M-4 regression: a parent list over MAX_PARENTS (but under the value
        // length cap) must be rejected before it reaches the orphan buffer.
        let mut entry = make_valid_supply_entry();
        let parent = "a".repeat(64);
        let parents = std::iter::repeat_n(parent.as_str(), MAX_PARENTS + 1)
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            parents.len() <= MAX_ENVELOPE_VALUE_LEN,
            "test should hit the count cap, not the length cap"
        );
        entry
            .envelope
            .insert("openledger-parents".to_owned(), parents);
        let err = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(err, MergeError::ResourceLimitExceeded(_)),
            "expected ResourceLimitExceeded, got {err:?}"
        );
    }

    #[test]
    fn test_validate_rejects_oversized_envelope_value() {
        // M-4 regression: an oversized envelope value is rejected cheaply by the
        // length cap, before the parent list is split/collected.
        let mut entry = make_valid_supply_entry();
        entry.envelope.insert(
            "openledger-parents".to_owned(),
            "a".repeat(MAX_ENVELOPE_VALUE_LEN + 1),
        );
        let err = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(err, MergeError::ResourceLimitExceeded(_)),
            "expected ResourceLimitExceeded, got {err:?}"
        );
    }

    #[test]
    fn test_validate_open_directive() {
        let open = Open {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        };
        let directive = Directive::Open(open);
        let id = compute_content_id(&directive);
        let economic_bean = economic_canonical_serialize(&directive);

        let entry = SupplyEntry {
            id,
            kind: DirectiveKind::Open,
            economic_bean,
            envelope: BTreeMap::from([("openledger-author".to_owned(), "peer-2".to_owned())]),
        };

        let result = validate_supply_entry(&entry);
        assert!(result.is_ok(), "Open directive should validate: {result:?}");
    }

    // ── CT-4: merge commutativity (I6) ──────────────────────────────────

    #[test]
    fn ct4_union_merge_commutativity() {
        // Two distinct transactions. Merging A then B should produce the
        // same aggregate balances as merging B then A.
        let txn_a = Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 10).unwrap(),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Transaction A".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(500),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-500),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let txn_b = Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 20).unwrap(),
            flag: Flag::Complete,
            payee: Some("Vendor".to_owned()),
            narration: Some("Transaction B".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(300),
                        currency: "EUR".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-300),
                        currency: "EUR".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let dir_a = Directive::Transaction(txn_a.clone());
        let dir_b = Directive::Transaction(txn_b.clone());
        let id_a = compute_content_id(&dir_a);
        let id_b = compute_content_id(&dir_b);
        let bean_a = economic_canonical_serialize(&dir_a);
        let bean_b = economic_canonical_serialize(&dir_b);

        let entry_a = SupplyEntry {
            id: id_a.clone(),
            kind: DirectiveKind::Transaction,
            economic_bean: bean_a,
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "peer-a".to_owned()),
                ("openledger-lamport".to_owned(), "1".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        };

        let entry_b = SupplyEntry {
            id: id_b.clone(),
            kind: DirectiveKind::Transaction,
            economic_bean: bean_b,
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "peer-b".to_owned()),
                ("openledger-lamport".to_owned(), "2".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        };

        // Order 1: A then B.
        let validated_a1 = validate_supply_entry(&entry_a).unwrap();
        let validated_b1 = validate_supply_entry(&entry_b).unwrap();
        let mut dag1 = ledger::dag::LedgerDag::new();
        dag1.insert(validated_a1, false).unwrap();
        dag1.insert(validated_b1, false).unwrap();

        // Order 2: B then A.
        let validated_a2 = validate_supply_entry(&entry_a).unwrap();
        let validated_b2 = validate_supply_entry(&entry_b).unwrap();
        let mut dag2 = ledger::dag::LedgerDag::new();
        dag2.insert(validated_b2, false).unwrap();
        dag2.insert(validated_a2, false).unwrap();

        // Both DAGs should contain exactly the same content IDs.
        let mut ids1: Vec<&str> = dag1.content_ids().into_iter().collect();
        let mut ids2: Vec<&str> = dag2.content_ids().into_iter().collect();
        ids1.sort();
        ids2.sort();
        assert_eq!(ids1, ids2, "Same entries regardless of merge order");

        // Both should produce the same read model balances.
        let mut rm1 = ledger::read_model::ReadModel::default();
        for id in &ids1 {
            if let Some(d) = dag1.get(id) {
                rm1.index_directive(d);
            }
        }
        let mut rm2 = ledger::read_model::ReadModel::default();
        for id in &ids2 {
            if let Some(d) = dag2.get(id) {
                rm2.index_directive(d);
            }
        }

        let date = chrono::NaiveDate::from_ymd_opt(2024, 12, 31).unwrap();
        let tb1 = rm1.trial_balance(date);
        let tb2 = rm2.trial_balance(date);
        assert_eq!(tb1.total_debit, tb2.total_debit, "Debit totals must match");
        assert_eq!(
            tb1.total_credit, tb2.total_credit,
            "Credit totals must match"
        );
        assert_eq!(tb1.rows.len(), tb2.rows.len(), "Same number of accounts");

        // Idempotency: inserting A again into dag1 should be a no-op.
        let validated_a_dup = validate_supply_entry(&entry_a).unwrap();
        let dup_result = dag1.insert(validated_a_dup, false).unwrap();
        assert!(
            matches!(dup_result, ledger::dag::InsertResult::Duplicate { .. }),
            "Duplicate insert should be idempotent"
        );
    }

    // ── CT-14: remote validation rejects I1 / I3 violations (§3.5) ──────

    #[test]
    fn ct14_remote_unbalanced_transaction_detected() {
        // Construct a supply entry with an unbalanced transaction.
        // validate_supply_entry only checks hash + envelope, but the caller
        // must validate I1–I3 before DAG insert. This test verifies the
        // content hash still works correctly and the unbalanced nature
        // is detectable by the validation layer.
        let unbalanced_txn = Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 2, 1).unwrap(),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Unbalanced remote".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(999),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-500),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let directive = Directive::Transaction(unbalanced_txn.clone());
        let id = compute_content_id(&directive);
        let bean = economic_canonical_serialize(&directive);

        let entry = SupplyEntry {
            id,
            kind: DirectiveKind::Transaction,
            economic_bean: bean,
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "bad-peer".to_owned()),
                ("openledger-lamport".to_owned(), "1".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        };

        // validate_supply_entry should pass (it checks hash + envelope, not balance).
        let parsed = validate_supply_entry(&entry).unwrap();

        // But I1 validation should catch the imbalance.
        if let Directive::Transaction(txn) = &parsed {
            let account_state = ledger::validate::AccountState::new();
            let result = ledger::validate::validate_transaction(txn, &account_state);
            assert!(
                result.is_err(),
                "Remote unbalanced transaction must be rejected by I1 validation"
            );
        } else {
            panic!("Expected Transaction");
        }
    }

    #[test]
    fn ct14_remote_unopened_account_detected() {
        // A remote transaction referencing an account not in the account state
        // should be rejected by I3 validation.
        let entry = make_valid_supply_entry();
        let parsed = validate_supply_entry(&entry).unwrap();

        if let Directive::Transaction(txn) = &parsed {
            // Use an empty account state (no accounts opened).
            let account_state = ledger::validate::AccountState::new();
            let result = ledger::validate::validate_transaction(txn, &account_state);
            assert!(
                result.is_err(),
                "Remote transaction to unopened account must be rejected by I3 validation"
            );
        } else {
            panic!("Expected Transaction");
        }
    }

    #[test]
    fn test_unsigned_accepted_when_signing_disabled() {
        let entry = make_valid_supply_entry();
        let directive = validate_supply_entry(&entry).unwrap();
        assert!(verify_remote_signature(&directive, false, "").is_ok());
    }

    #[test]
    fn test_unsigned_rejected_when_signing_enabled() {
        let entry = make_valid_supply_entry();
        let directive = validate_supply_entry(&entry).unwrap();
        let result = verify_remote_signature(&directive, true, "");
        assert!(matches!(
            result,
            Err(MergeError::EnvelopeMissing(ref field)) if field == "openledger-signature"
        ));
    }

    #[test]
    fn test_valid_signature_accepted_when_signing_enabled() {
        use security::signing::PeerKeySignatureProvider;

        let provider = PeerKeySignatureProvider::generate();
        let mut entry = make_valid_supply_entry();
        let author = provider.public_key_hex();
        let signature = sign_supply_entry(&provider, &entry);
        entry
            .envelope
            .insert("openledger-author".to_owned(), author);
        entry
            .envelope
            .insert("openledger-signature".to_owned(), signature);

        let directive = validate_supply_entry(&entry).unwrap();
        assert!(verify_remote_signature(&directive, true, "").is_ok());
    }

    #[test]
    fn test_forged_signature_rejected_when_signing_enabled() {
        use security::signing::PeerKeySignatureProvider;

        let author = PeerKeySignatureProvider::generate();
        let attacker = PeerKeySignatureProvider::generate();
        let mut entry = make_valid_supply_entry();
        let forged = sign_supply_entry(&attacker, &entry);
        entry
            .envelope
            .insert("openledger-author".to_owned(), author.public_key_hex());
        entry
            .envelope
            .insert("openledger-signature".to_owned(), forged);

        let directive = validate_supply_entry(&entry).unwrap();
        assert!(matches!(
            verify_remote_signature(&directive, true, ""),
            Err(MergeError::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_rewritten_parents_fail_signature_verification() {
        use security::signing::PeerKeySignatureProvider;

        let provider = PeerKeySignatureProvider::generate();
        let mut entry = make_valid_supply_entry();
        let signature = sign_supply_entry(&provider, &entry);
        entry
            .envelope
            .insert("openledger-author".to_owned(), provider.public_key_hex());
        entry
            .envelope
            .insert("openledger-signature".to_owned(), signature);
        entry.envelope.insert(
            "openledger-parents".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        );

        let directive = validate_supply_entry(&entry).unwrap();
        assert!(
            matches!(
                verify_remote_signature(&directive, true, ""),
                Err(MergeError::InvalidSignature(_))
            ),
            "rewritten parents must fail verification while content hash still matches"
        );
    }

    #[test]
    fn test_rewritten_lamport_fail_signature_verification() {
        use security::signing::PeerKeySignatureProvider;

        let provider = PeerKeySignatureProvider::generate();
        let mut entry = make_valid_supply_entry();
        let signature = sign_supply_entry(&provider, &entry);
        entry
            .envelope
            .insert("openledger-author".to_owned(), provider.public_key_hex());
        entry
            .envelope
            .insert("openledger-signature".to_owned(), signature);
        entry
            .envelope
            .insert("openledger-lamport".to_owned(), "999".to_owned());

        let directive = validate_supply_entry(&entry).unwrap();
        assert!(
            matches!(
                verify_remote_signature(&directive, true, ""),
                Err(MergeError::InvalidSignature(_))
            ),
            "rewritten lamport must fail verification while content hash still matches"
        );
    }

    #[test]
    fn test_author_not_on_allowlist_rejected() {
        let entry = make_valid_supply_entry();
        let directive = validate_supply_entry(&entry).unwrap();
        let trusted = iroh::SecretKey::generate().public().to_string();
        let allowlist = PeerAllowlist::parse(&[trusted]).unwrap();
        let result = verify_author_allowlisted(&directive, &allowlist);
        assert!(
            matches!(result, Err(MergeError::InvalidEnvelope(_))),
            "stranger author must be rejected: {result:?}"
        );
    }

    #[test]
    fn test_author_on_allowlist_accepted() {
        let trusted = iroh::SecretKey::generate().public().to_string();
        let mut entry = make_valid_supply_entry();
        entry
            .envelope
            .insert("openledger-author".to_owned(), trusted.clone());
        let directive = validate_supply_entry(&entry).unwrap();
        let allowlist = PeerAllowlist::parse(&[trusted]).unwrap();
        assert!(verify_author_allowlisted(&directive, &allowlist).is_ok());
    }

    #[test]
    fn test_oversized_economic_bean_rejected() {
        let mut entry = make_valid_supply_entry();
        entry.economic_bean = "x".repeat(ledger::service::MAX_ECONOMIC_BEAN_LENGTH + 1);
        assert!(matches!(
            validate_supply_entry(&entry),
            Err(MergeError::ResourceLimitExceeded(_))
        ));
    }

    #[test]
    fn test_unknown_envelope_key_rejected() {
        let mut entry = make_valid_supply_entry();
        entry.envelope.insert(
            "evil\n2024-01-01 open Assets:Hacked".to_owned(),
            "x".to_owned(),
        );
        assert!(matches!(
            validate_supply_entry(&entry),
            Err(MergeError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn test_envelope_control_character_rejected() {
        let mut entry = make_valid_supply_entry();
        entry
            .envelope
            .insert("openledger-author".to_owned(), "peer\n1".to_owned());
        assert!(matches!(
            validate_supply_entry(&entry),
            Err(MergeError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn test_kind_mismatch_rejected() {
        let mut entry = make_valid_supply_entry();
        entry.kind = DirectiveKind::Open;
        assert!(matches!(
            validate_supply_entry(&entry),
            Err(MergeError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn test_multi_directive_economic_bean_rejected() {
        let mut entry = make_valid_supply_entry();
        entry
            .economic_bean
            .push_str("\n2024-01-01 open Assets:Injected USD\n");
        assert!(matches!(
            validate_supply_entry(&entry),
            Err(MergeError::ParseError(_) | MergeError::ContentHashMismatch { .. })
        ));
    }
}
