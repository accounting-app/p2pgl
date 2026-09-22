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
use crate::protocol::{is_content_id, DirectiveKind, SupplyEntry};

/// Closed set of envelope keys accepted on remote `Supply` (§3.3.1).
///
/// Aliases the ledger's stamping set rather than repeating it, so the keys this
/// side accepts can never drift from the keys the writer produces (H-06).
const ALLOWED_ENVELOPE_KEYS: &[&str] = ledger::service::ENVELOPE_KEYS;

/// Maximum byte length of any single envelope value (M-4 DoS bound).
///
/// The largest legitimate value is `openledger-parents` at
/// `MAX_PARENTS × (64-hex + comma)` ≈ 16.6 KiB; 32 KiB leaves headroom while
/// cheaply rejecting the ~16 MiB blobs that would otherwise be split into an
/// enormous parent list.
const MAX_ENVELOPE_VALUE_LEN: usize = 32 * 1024;

/// Maximum number of parents in `openledger-parents`.
///
/// Aliases the ledger's constant rather than repeating the number, so the wire
/// path and the file path cannot drift apart about the fan-in cap — the same
/// rule (and the same reason) as [`ALLOWED_ENVELOPE_KEYS`]. The cap lived here
/// alone until T41, which is why it applied to arriving `Supply` entries and
/// not to a hand-written file.
use ledger::service::MAX_PARENTS;

/// Exclusive ceiling on an accepted remote `openledger-lamport` (0820-M3
/// completion, H-07).
///
/// Aliases the ledger's constant rather than repeating the number, so what a
/// peer may send can never drift from what this node's own clock and stamp
/// sites are bounded by — the same rule (and the same reason) as
/// [`ALLOWED_ENVELOPE_KEYS`] and [`MAX_PARENTS`]. The cap lived here alone until
/// T46, which is exactly why it bounded what a node *accepted* while nothing
/// bounded what it *stamped*.
///
/// See `ledger::service::LAMPORT_CEILING` for the single rule both sides now
/// share, and for why this bound is exclusive: adoption is
/// `max(local, remote) + 1`, so a value accepted *at* the cap would carry the
/// receiver's clock past it.
use ledger::service::LAMPORT_CEILING;

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
    /// The economic body carries an `openledger-*` metadata key (H-06).
    BodyEnvelopeKey(String),
    /// A string in the economic body contains control characters (L-26).
    BodyControlCharacter(String),
    /// A transaction body arrived with an elided posting amount (H-03).
    ElidedPosting,
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
            MergeError::BodyEnvelopeKey(reason) => {
                write!(f, "Envelope key in economic body: {reason}")
            }
            MergeError::BodyControlCharacter(reason) => {
                write!(f, "Control character in economic body: {reason}")
            }
            MergeError::ElidedPosting => write!(
                f,
                "Elided posting in economic body: remote bodies must arrive with every posting amount resolved"
            ),
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

    // 3. Canonicalize the wire body, on the freshly parsed directive and BEFORE
    // the envelope merge below. The ordering is load-bearing: once the envelope
    // has been merged into the directive's metadata, a body-smuggled
    // `openledger-signature`/`openledger-author` is indistinguishable from the
    // legitimately merged one, so an allowed *name* would slip through. An
    // honest wire body carries no `openledger-*` key at all — the canonical
    // serializer that produces it strips every one.
    if let Directive::Transaction(transaction) = &directive {
        // H-03: the id is checked against the as-sent body, but
        // `insert_remote_directive` stores the *resolved* postings — so an
        // elided body would be accepted under one id and stored (and re-hashed)
        // under another. That directive can never propagate: its signature is
        // bound to the accepted id, so every other node rejects it, leaving
        // permanent replica divergence and perpetual re-Want churn. Honest
        // senders always ship resolved postings.
        if ledger::service::elided_posting_count(transaction) > 0 {
            return Err(MergeError::ElidedPosting);
        }
    }
    // H-06: the content hash strips every `openledger-*` key, so one smuggled
    // in the body is validated by nothing, persists into the victim's `.bean`,
    // and is promoted back into the envelope on re-serve — where the next hop's
    // closed-set check rejects the directive forever.
    ledger::service::validate_body_envelope_keys(&directive, &[])
        .map_err(|error| MergeError::BodyEnvelopeKey(error.to_string()))?;
    // L-26: `reject_control_characters` guards the local API only; without this
    // an ESC/NUL/TAB in a remote body reaches every replica's file.
    ledger::service::validate_body_strings(&directive)
        .map_err(|error| MergeError::BodyControlCharacter(error.to_string()))?;

    // 4. Attach envelope metadata.
    let metadata = directive_metadata_mut(&mut directive);
    for (key, value) in &entry.envelope {
        metadata.insert(key.clone(), value.clone());
    }

    // 5. Validate required envelope fields for transactions.
    if let Directive::Transaction(_) = &directive {
        if !entry.envelope.contains_key("openledger-author") {
            return Err(MergeError::EnvelopeMissing("openledger-author".to_owned()));
        }
        if !entry.envelope.contains_key("openledger-lamport") {
            return Err(MergeError::EnvelopeMissing("openledger-lamport".to_owned()));
        }
        // openledger-parents may be empty string for genesis.
    }

    // 6. Strict envelope value validation — for every directive kind carrying
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

        // Every parent must be a well-formed 64-lowercase-hex txid
        // (0820-L8/M-05, L-29). The DAG insert enforces this anyway, but
        // checking here — before the orphan buffer — stops a directive waiting
        // on garbage parents that can never arrive from squatting buffer space
        // for the full TTL. Uppercase is garbage too: stored ids are always
        // lowercase and lookups exact, so an uppercased spelling of a real txid
        // would pass a case-insensitive check and then never resolve.
        //
        // T49: the predicate moved to `protocol::is_content_id` unchanged, so
        // the advert reader (M-26) and the gossip `Announce` id (L-53) — which
        // had no form check at all — enforce the SAME rule as this one rather
        // than a second spelling of it that can drift.
        for parent_id in &parent_ids {
            if !is_content_id(parent_id) {
                return Err(MergeError::InvalidEnvelope(
                    "openledger-parents contains a malformed txid (expected 64 lowercase hex characters)"
                        .to_owned(),
                ));
            }
        }
    }

    if let Some(lamport) = metadata.get("openledger-lamport") {
        // Strict inbound Lamport validation (0820-M3 completion): the value must
        // be a plain decimal u64 below the plausibility cap. Without this, a
        // garbage string is silently persisted verbatim, and a huge value pins
        // every replica's saturating clock permanently.
        //
        // EXCLUSIVE since T46 (H-07). The receiver adopts
        // `max(local, remote) + 1`, so a value accepted *at* the cap lands the
        // receiver's clock above it — and every directive that receiver goes on
        // to stamp is then rejected here, on this very line, by every peer it
        // has. The cap and the arithmetic around it are one rule, stated once on
        // `ledger::service::LAMPORT_CEILING`; the ledger re-checks the same
        // bound as it adopts, for the callers that reach it without the wire.
        let lamport_ok = !lamport.is_empty()
            && lamport.bytes().all(|b| b.is_ascii_digit())
            && lamport
                .parse::<u64>()
                .is_ok_and(|value| value < LAMPORT_CEILING);
        if !lamport_ok {
            return Err(MergeError::InvalidEnvelope(format!(
                "openledger-lamport must be a decimal u64 < {LAMPORT_CEILING}"
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
///
/// ## Migration: directives written before signing was turned on (T41)
///
/// There is no migration, and this is where that becomes visible. A directive
/// is signed once, by its author, at the moment it is first written
/// (`append_transaction_signing` and friends stamp the signature before the
/// first persist, M-11). A node that ran with `signing.enabled: false` — or
/// with `p2p.enabled: false`, which is the common case, since config validation
/// forces signing on whenever P2P is — has a `.bean` full of directives with no
/// `openledger-signature`, and turning signing on later does not and cannot
/// change that: the signature covers the content id, so only the *original
/// author* could produce one, and a node re-signing another author's history
/// would be manufacturing provenance.
///
/// The practical consequence, stated plainly so it is not discovered in
/// production: **pre-signing history does not replicate to a signing mesh.** It
/// is rejected here, one `MergeError::EnvelopeMissing` per directive, on every
/// peer with signing enabled. The node holding it keeps serving it and keeps
/// being refused.
///
/// The three options, none of which this code takes on its own:
///
/// * Bring the whole mesh up with signing on from the first directive. This is
///   the supported path and what the shipped configs do.
/// * Enable signing at a point where the pre-signing history is disposable
///   (a dev ledger) and start the mesh from a fresh file.
/// * Re-author the history through the local API on one node, which produces
///   NEW directives with new ids under that node's authorship. That is an
///   honest re-statement, not a migration, and the old ids never become valid.
///
/// A fourth option — a signed "attestation" directive by which one node vouches
/// for a batch of unsigned ancestors — would be a content-format change and
/// belongs with the coordinated bump that closes M-10/L-06, not here.
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
pub(crate) fn directive_metadata(directive: &Directive) -> &BTreeMap<String, String> {
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

    // ── T21: wire body canonicalization (H-03 / H-06 / L-26 / L-29) ─────

    fn sample_transaction(narration: &str, elide_second_amount: bool) -> Transaction {
        Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            flag: Flag::Complete,
            payee: Some("Acme Corp".to_owned()),
            narration: Some(narration.to_owned()),
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
                    amount: if elide_second_amount {
                        None
                    } else {
                        Some(Amount {
                            number: dec!(-100),
                            currency: "USD".to_owned(),
                        })
                    },
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        }
    }

    /// Wrap a hostile body in the entry an attacker would actually ship.
    ///
    /// The id is the hash of the body exactly as sent, so the I5 content-hash
    /// check passes by construction — these attacks live entirely inside what
    /// the hash covers (or, for `openledger-*` keys, inside what it strips).
    fn entry_for_body(kind: DirectiveKind, economic_bean: String) -> SupplyEntry {
        let parsed = parse_file(&economic_bean)
            .expect("attack body must parse")
            .into_iter()
            .next()
            .expect("attack body must hold exactly one directive");
        SupplyEntry {
            id: compute_content_id(&parsed),
            kind,
            economic_bean,
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "peer-1".to_owned()),
                ("openledger-lamport".to_owned(), "5".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        }
    }

    /// Splice a metadata line in directly below the transaction header, where
    /// `parse_transaction_body` reads it as directive-level metadata.
    fn with_directive_metadata_line(body: &str, metadata_line: &str) -> String {
        let mut lines: Vec<String> = body.lines().map(str::to_owned).collect();
        lines.insert(1, format!("  {metadata_line}"));
        format!("{}\n", lines.join("\n"))
    }

    /// Append a metadata line below the last posting, where the parser attaches
    /// it to that posting.
    fn with_posting_metadata_line(body: &str, metadata_line: &str) -> String {
        format!("{body}    {metadata_line}\n")
    }

    #[test]
    fn test_validate_rejects_elided_posting_in_body() {
        // H-03: the id is checked against the as-sent (elided) body, but the
        // insert stores the *resolved* postings — so this entry would be
        // accepted under one id and stored under another, never to propagate.
        let directive = Directive::Transaction(sample_transaction("Elided", true));
        let entry = entry_for_body(
            DirectiveKind::Transaction,
            economic_canonical_serialize(&directive),
        );
        assert_eq!(
            entry.id,
            compute_content_id(&directive),
            "the elided body hashes to exactly the id shipped with it"
        );

        let error = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(error, MergeError::ElidedPosting),
            "expected ElidedPosting, got {error:?}"
        );
    }

    #[test]
    fn test_validate_rejects_directive_level_body_envelope_key() {
        // H-06: the content hash strips `openledger-*`, so the smuggled key
        // rides along invisibly — the id still matches the clean body.
        let clean = Directive::Transaction(sample_transaction("Smuggled", false));
        let body = with_directive_metadata_line(
            &economic_canonical_serialize(&clean),
            "openledger-x: \"y\"",
        );
        let entry = entry_for_body(DirectiveKind::Transaction, body);
        assert_eq!(
            entry.id,
            compute_content_id(&clean),
            "the smuggled key is invisible to the content hash"
        );

        let error = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(error, MergeError::BodyEnvelopeKey(ref reason) if reason.contains("openledger-x")),
            "expected BodyEnvelopeKey naming the key, got {error:?}"
        );
    }

    #[test]
    fn test_validate_rejects_posting_level_body_envelope_key() {
        // A metadata line written after a posting binds to that posting —
        // `extract_envelope` promotes it on re-serve just the same.
        let clean = Directive::Transaction(sample_transaction("Smuggled", false));
        let body = with_posting_metadata_line(
            &economic_canonical_serialize(&clean),
            "openledger-x: \"y\"",
        );
        let entry = entry_for_body(DirectiveKind::Transaction, body);

        let error = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(error, MergeError::BodyEnvelopeKey(_)),
            "expected BodyEnvelopeKey, got {error:?}"
        );
    }

    #[test]
    fn test_validate_rejects_body_smuggled_allowed_envelope_name() {
        // The check runs *before* the envelope merge for exactly this case: an
        // allowed key *name* in the body is still a forgery, and after the
        // merge it would be indistinguishable from the real envelope value.
        let clean = Directive::Transaction(sample_transaction("Smuggled", false));
        for metadata_line in [
            "openledger-author: \"attacker\"",
            "openledger-signature: \"deadbeef\"",
        ] {
            let body =
                with_directive_metadata_line(&economic_canonical_serialize(&clean), metadata_line);
            let entry = entry_for_body(DirectiveKind::Transaction, body);
            let error = validate_supply_entry(&entry).unwrap_err();
            assert!(
                matches!(error, MergeError::BodyEnvelopeKey(_)),
                "body {metadata_line:?} must be rejected, got {error:?}"
            );
        }
    }

    #[test]
    fn test_validate_rejects_control_characters_in_body() {
        // L-26: `reject_control_characters` guards the local API only; an ESC
        // or NUL accepted here is written verbatim into every replica's file.
        for narration in ["wipe\u{1b}[2J screen", "nul\u{0}terminated"] {
            let directive = Directive::Transaction(sample_transaction(narration, false));
            let entry = entry_for_body(
                DirectiveKind::Transaction,
                economic_canonical_serialize(&directive),
            );
            let error = validate_supply_entry(&entry).unwrap_err();
            assert!(
                matches!(error, MergeError::BodyControlCharacter(_)),
                "narration {narration:?} must be rejected, got {error:?}"
            );
        }
    }

    #[test]
    fn test_validate_rejects_mixed_script_account_in_body() {
        // L-25: `Assets:Cаsh` (Cyrillic а, U+0430) used to parse as an account
        // distinct from — and pixel-identical to — `Assets:Cash`, so a peer
        // could plant a confusable account in every replica's `.bean` file and
        // in every trial balance drawn from it. The wire path re-parses the
        // canonical body through `parse_file`, so the parser's ASCII-only rule
        // covers the mesh as well as the disk.
        let mut txn = sample_transaction("Homoglyph", false);
        txn.postings[0].account = "Assets:C\u{0430}sh".to_owned();
        let directive = Directive::Transaction(txn);

        // The account name is inside what the content hash covers, so the
        // entry's I5 check passes by construction: only the charset rule
        // rejects it.
        let clean = Directive::Transaction(sample_transaction("Homoglyph", false));
        assert_ne!(
            compute_content_id(&directive),
            compute_content_id(&clean),
            "the confusable account must be part of the hashed body"
        );

        let entry = SupplyEntry {
            id: compute_content_id(&directive),
            kind: DirectiveKind::Transaction,
            economic_bean: economic_canonical_serialize(&directive),
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "peer-1".to_owned()),
                ("openledger-lamport".to_owned(), "5".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        };

        let error = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(error, MergeError::ParseError(ref reason) if reason.contains("U+0430")),
            "expected a ParseError naming the offending character, got {error:?}"
        );

        // Control: the all-ASCII spelling of the same entry is still accepted.
        assert!(validate_supply_entry(&entry_for_body(
            DirectiveKind::Transaction,
            economic_canonical_serialize(&clean),
        ))
        .is_ok());
    }

    #[test]
    fn test_validate_rejects_zero_cost_in_body() {
        // L-16: `{0 USD}` weighs zero whatever the posting says, so a peer can
        // mint an arbitrary commodity position in a transaction that balances
        // perfectly under I1. Like L-25, the wire path inherits the rule for
        // free because `validate_supply_entry` re-parses the canonical body
        // through `parse_file` before anything else runs.
        let mut txn = sample_transaction("Minting", false);
        txn.postings[0].amount = Some(Amount {
            number: dec!(10_000_000),
            currency: "AAPL".to_owned(),
        });
        txn.postings[0].cost = Some(ledger::model::CostSpec {
            amount: Some(Amount {
                number: dec!(0),
                currency: "USD".to_owned(),
            }),
            date: None,
        });
        txn.postings[1].amount = Some(Amount {
            number: dec!(0),
            currency: "USD".to_owned(),
        });
        let directive = Directive::Transaction(txn);

        // The cost is inside what the content hash covers, so the entry's I5
        // check passes by construction: only the L-16 rule rejects it.
        let entry = SupplyEntry {
            id: compute_content_id(&directive),
            kind: DirectiveKind::Transaction,
            economic_bean: economic_canonical_serialize(&directive),
            envelope: BTreeMap::from([
                ("openledger-author".to_owned(), "peer-1".to_owned()),
                ("openledger-lamport".to_owned(), "5".to_owned()),
                ("openledger-parents".to_owned(), "".to_owned()),
            ]),
        };
        assert!(
            entry.economic_bean.contains("{0 USD}"),
            "fixture must actually ship a zero cost: {}",
            entry.economic_bean
        );

        let error = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(error, MergeError::ParseError(ref reason)
                if reason.contains("Cost must be greater than zero")),
            "expected a ParseError naming the rule, got {error:?}"
        );

        // Control: the same shape at an honest rate is still accepted.
        let mut honest = sample_transaction("Minting", false);
        honest.postings[0].amount = Some(Amount {
            number: dec!(10),
            currency: "AAPL".to_owned(),
        });
        honest.postings[0].cost = Some(ledger::model::CostSpec {
            amount: Some(Amount {
                number: dec!(150),
                currency: "USD".to_owned(),
            }),
            date: None,
        });
        honest.postings[1].amount = Some(Amount {
            number: dec!(-1500),
            currency: "USD".to_owned(),
        });
        assert!(validate_supply_entry(&entry_for_body(
            DirectiveKind::Transaction,
            economic_canonical_serialize(&Directive::Transaction(honest)),
        ))
        .is_ok());
    }

    #[test]
    fn test_validate_rejects_uppercase_hex_parent() {
        // L-29: stored ids are lowercase and lookups are exact, so an uppercase
        // spelling of a real txid validates and then never resolves — a
        // TTL-long orphan and perpetual re-Want churn.
        let real_parent =
            compute_content_id(&Directive::Transaction(sample_transaction("parent", false)));
        let uppercase = real_parent.to_ascii_uppercase();
        assert_ne!(real_parent, uppercase, "fixture must contain hex letters");

        let mut entry = make_valid_supply_entry();
        entry
            .envelope
            .insert("openledger-parents".to_owned(), uppercase);
        let error = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(error, MergeError::InvalidEnvelope(_)),
            "expected InvalidEnvelope, got {error:?}"
        );

        entry
            .envelope
            .insert("openledger-parents".to_owned(), real_parent);
        assert!(
            validate_supply_entry(&entry).is_ok(),
            "the lowercase form of the same txid must still be accepted"
        );
    }

    #[test]
    fn test_make_supply_entry_output_is_accepted() {
        // No over-rejection: an entry built by our own serve path from a
        // properly stamped directive still validates.
        let mut txn = sample_transaction("Honest", false);
        txn.metadata
            .insert("openledger-author".to_owned(), "peer-1".to_owned());
        txn.metadata
            .insert("openledger-lamport".to_owned(), "7".to_owned());
        txn.metadata
            .insert("openledger-parents".to_owned(), "".to_owned());
        txn.metadata
            .insert("openledger-signature".to_owned(), "ab".repeat(64));

        let entry = crate::gossip::make_supply_entry(&Directive::Transaction(txn));
        let result = validate_supply_entry(&entry);
        assert!(result.is_ok(), "honest entry must pass: {result:?}");
    }

    // ── L-11: a hand edit adopted at reconcile must replicate ────────────

    const RECONCILE_MESH: &str = "mesh-for-reconcile";

    fn temp_bean_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("openledger-l11-{tag}-{nanos}.bean"))
    }

    /// A booted service whose reconcile signs with `key_seed`'s key, authored by
    /// that key — i.e. a node exactly as `main` wires one when signing is on.
    fn signing_service(
        path: &std::path::Path,
        key_seed: u8,
    ) -> (
        ledger::service::LedgerService,
        std::sync::Arc<security::signing::PeerKeySignatureProvider>,
    ) {
        let provider =
            std::sync::Arc::new(security::signing::PeerKeySignatureProvider::from_bytes(
                &[key_seed; 32],
                RECONCILE_MESH.to_owned(),
            ));
        let mut service =
            ledger::service::LedgerService::boot(path, provider.public_key_hex()).unwrap();
        let for_signer = std::sync::Arc::clone(&provider);
        service.set_signer(std::sync::Arc::new(
            move |content_id: &str, is_transaction: bool, parents: &str, lamport: &str| {
                use security::signing::SignatureProvider;
                for_signer.sign(&security::signing::SignableMessage {
                    content_id,
                    is_transaction,
                    parents,
                    lamport,
                })
            },
        ));
        (service, provider)
    }

    /// Two open accounts plus a hand-appended, envelope-less transaction —
    /// exactly what a human adding a line in an editor produces.
    const HAND_EDIT: &str = "\n2024-01-15 * \"Corner Shop\" \"Coffee\"\n  \
                             Expenses:Food                                        4.50 USD\n  \
                             Assets:Cash                                         -4.50 USD\n";

    /// Run the FULL remote receive-path validation on a directive, the way a
    /// peer would after this node served it.
    fn peer_would_accept(directive: &Directive) -> Result<(), MergeError> {
        let entry = crate::gossip::make_supply_entry(directive);
        let parsed = validate_supply_entry(&entry)?;
        verify_remote_signature(&parsed, true, RECONCILE_MESH)
    }

    #[test]
    fn test_reconcile_signs_hand_edits_so_peers_accept_them() {
        // L-11: with signing on, an adopted hand edit used to carry no
        // signature at all. It was in this node's DAG, in its `.bean`, in every
        // report — and every peer refused it forever, silently. Split-brain by
        // text editor.
        let path = temp_bean_path("signed");
        let (mut service, provider) = signing_service(&path, 11);
        let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        service
            .open_account("Expenses:Food".to_owned(), date, vec![])
            .unwrap();
        service
            .open_account("Assets:Cash".to_owned(), date, vec![])
            .unwrap();
        let before = service.directive_count();

        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(HAND_EDIT);
        std::fs::write(&path, &content).unwrap();

        let result = service.reconcile_file().unwrap();
        assert_eq!(result.new_directives, 1, "the hand edit must be adopted");
        assert_eq!(result.rejected, 0);
        assert_eq!(service.directive_count(), before + 1);

        let adopted = service
            .dag()
            .directives()
            .into_iter()
            .find(|d| matches!(d, Directive::Transaction(_)))
            .expect("the adopted transaction")
            .clone();

        // It is ours, and it is signed.
        let metadata = directive_metadata(&adopted);
        assert_eq!(
            metadata.get("openledger-author"),
            Some(&provider.public_key_hex()),
            "operator input is a local append: this node is the author"
        );
        assert!(metadata.contains_key("openledger-signature"));

        // And — the point of the whole item — a peer running the real receive
        // path accepts it.
        assert!(
            peer_would_accept(&adopted).is_ok(),
            "a peer must accept the adopted entry: {:?}",
            peer_would_accept(&adopted)
        );

        // The signature is over the id the DAG actually stores it under.
        assert!(service
            .get_directive(&compute_content_id(&adopted))
            .is_some());

        std::fs::remove_file(path).ok();
    }

    /// T44b: the same proof, with an L-13 recovery in the middle.
    ///
    /// A commit fails, `recover_failed_commit` rebuilds the service from disk,
    /// and the hand edit adopted **after** that recovery must still be one a
    /// peer accepts. Until T44b the reload went through `boot`, which sets
    /// `signer: None`, so the entry was adopted unsigned and `peer_would_accept`
    /// refused it — L-11's exact failure, reachable from any node that ever had
    /// a disk error.
    ///
    /// The failure seam is a read-only ledger *directory*: `persist_atomically`
    /// cannot create its sibling `.tmp`, so the commit fails on the real I/O
    /// path, while the `.bean` stays readable for the reload. The directory is
    /// this test's own, so nothing else is affected by the mode change.
    #[cfg(unix)]
    #[test]
    fn test_a_recovered_commit_failure_still_signs_the_next_adoption() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temp_bean_path("recovered").with_extension("dir");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("ledger.bean");
        let (mut service, provider) = signing_service(&path, 14);
        let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        service
            .open_account("Expenses:Food".to_owned(), date, vec![])
            .unwrap();
        service
            .open_account("Assets:Cash".to_owned(), date, vec![])
            .unwrap();
        let durable = service.directive_count();

        // Fail a commit for real, and recover from it.
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
        let error = service
            .open_account("Assets:Vault".to_owned(), date, vec![])
            .unwrap_err();
        assert_eq!(error.error_code(), "IO_ERROR", "got {error}");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            service.directive_count(),
            durable,
            "L-13: the failed write must have been rolled back, i.e. the reload ran"
        );

        // Now the hand edit, on the far side of the recovery.
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(HAND_EDIT);
        std::fs::write(&path, &content).unwrap();

        let result = service.reconcile_file().unwrap();
        assert_eq!(result.new_directives, 1, "the hand edit must be adopted");
        assert_eq!(result.rejected, 0);

        let adopted = service
            .dag()
            .directives()
            .into_iter()
            .find(|d| matches!(d, Directive::Transaction(_)))
            .expect("the adopted transaction")
            .clone();
        assert_eq!(
            directive_metadata(&adopted).get("openledger-author"),
            Some(&provider.public_key_hex()),
        );
        assert!(
            peer_would_accept(&adopted).is_ok(),
            "a peer must accept an entry adopted after a recovered commit failure: {:?}",
            peer_would_accept(&adopted)
        );

        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn test_reconcile_refuses_an_uppercase_parent_the_mesh_would_refuse() {
        // M-20 / L-29, proven by the real mechanism rather than by inspecting
        // an `if`.
        //
        // Before T51, `reconcile_content` had no parent-txid FORM check — the
        // rule lived only on the wire and at `stage_remote_directive` — so a
        // hand edit that uppercased a parent id was adopted, **signed with this
        // node's key** (L-11), persisted and served, and then refused by
        // exactly the validator below, on every peer, forever, while this node
        // kept advertising it. `openledger-parents` is envelope metadata and is
        // stripped before hashing, so the edit changes no content id and breaks
        // no signature: nothing local could ever notice.
        //
        // This test is written so that removing the guard does not merely fail
        // an equality — it walks the divergence and reports it. The `if let`
        // arm below is dead in a correct build and is the whole bug-catch
        // apparatus: it takes the entry reconcile actually adopted, proves it
        // carries this node's signature, and hands it to the real
        // `validate_supply_entry` + `verify_remote_signature` pair a peer runs.
        let path = temp_bean_path("uppercase-parent");
        let (mut service, provider) = signing_service(&path, 13);
        let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        service
            .open_account("Expenses:Food".to_owned(), date, vec![])
            .unwrap();
        service
            .open_account("Assets:Cash".to_owned(), date, vec![])
            .unwrap();

        // A real, well-formed parent id — uppercased. `is_content_id` rejects
        // this spelling precisely because stored ids are lowercase and lookups
        // are exact, so it would never resolve anywhere.
        let lowercase = "ab".repeat(32);
        let shouted = lowercase.to_uppercase();
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(&format!(
            "\n2024-01-15 * \"Corner Shop\" \"Shouted parent\"\n  \
             openledger-parents: \"{shouted}\"\n  \
             Expenses:Food                                        4.50 USD\n  \
             Assets:Cash                                         -4.50 USD\n"
        ));
        std::fs::write(&path, &content).unwrap();

        let result = service.reconcile_file().unwrap();

        if let Some(adopted) = service
            .dag()
            .directives()
            .into_iter()
            .find(|d| matches!(d, Directive::Transaction(t) if t.narration.as_deref() == Some("Shouted parent")))
            .cloned()
        {
            // Unreachable while T51's guard stands. Reached, it means the guard
            // is gone, and everything below is the finding happening for real.
            let metadata = directive_metadata(&adopted);
            let author = metadata.get("openledger-author").cloned().unwrap_or_default();
            let signature = metadata
                .get("openledger-signature")
                .cloned()
                .unwrap_or_default();
            assert_eq!(
                author,
                provider.public_key_hex(),
                "the divergence needs this node to be the author"
            );
            let verdict = peer_would_accept(&adopted);
            panic!(
                "M-20/L-29: reconcile ADOPTED and SIGNED an entry the mesh refuses.\n  \
                 author    = {author}\n  \
                 signature = {signature}\n  \
                 parents   = {parents:?}\n  \
                 peer says = {verdict:?}\n\
                 This node now serves a directive every peer rejects forever, \
                 while advertising it on every anti-entropy tick.",
                parents = metadata.get("openledger-parents"),
            );
        }

        assert_eq!(
            result.rejected, 1,
            "the malformed parent must be refused by reconcile"
        );
        assert_eq!(result.new_directives, 0);

        // The control: the identical entry with the parent in lowercase is
        // adopted, signed, and accepted by the same validator — so the guard is
        // a form check, not a refusal of hand-written parents.
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(&format!(
            "\n2024-01-16 * \"Corner Shop\" \"Quiet parent\"\n  \
             openledger-parents: \"{lowercase}\"\n  \
             Expenses:Food                                        4.50 USD\n  \
             Assets:Cash                                         -4.50 USD\n"
        ));
        std::fs::write(&path, &content).unwrap();
        assert_eq!(service.reconcile_file().unwrap().new_directives, 1);
        let quiet = service
            .dag()
            .directives()
            .into_iter()
            .find(|d| matches!(d, Directive::Transaction(t) if t.narration.as_deref() == Some("Quiet parent")))
            .expect("the lowercase-parent entry must be adopted")
            .clone();
        assert!(
            directive_metadata(&quiet).contains_key("openledger-signature"),
            "premise: the control really is signed by this node"
        );
        assert!(
            peer_would_accept(&quiet).is_ok(),
            "a peer must accept the lowercase control: {:?}",
            peer_would_accept(&quiet)
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reconcile_signs_an_adopted_hand_edit_with_an_elided_posting() {
        // The sharp edge of "sign what will be stored": I2 resolves the elided
        // amount, so the STORED body hashes differently from the parsed one. A
        // signature over the pre-resolution id verifies nowhere.
        let path = temp_bean_path("elided");
        let (mut service, _provider) = signing_service(&path, 12);
        let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        service
            .open_account("Expenses:Food".to_owned(), date, vec![])
            .unwrap();
        service
            .open_account("Assets:Cash".to_owned(), date, vec![])
            .unwrap();

        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(
            "\n2024-01-15 * \"Corner Shop\" \"Elided coffee\"\n  \
             Expenses:Food                                        4.50 USD\n  \
             Assets:Cash\n",
        );
        std::fs::write(&path, &content).unwrap();

        assert_eq!(service.reconcile_file().unwrap().new_directives, 1);
        let adopted = service
            .dag()
            .directives()
            .into_iter()
            .find(|d| matches!(d, Directive::Transaction(_)))
            .expect("the adopted transaction")
            .clone();

        assert!(
            peer_would_accept(&adopted).is_ok(),
            "signature must cover the RESOLVED body: {:?}",
            peer_would_accept(&adopted)
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reconcile_leaves_an_already_signed_entry_untouched() {
        // An entry that arrived from a peer (or round-tripped through our own
        // file) keeps its own author and its own signature — re-signing would
        // destroy a valid one and claim someone else's write.
        let path = temp_bean_path("preserved");
        let (mut service, _provider) = signing_service(&path, 13);
        let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        service
            .open_account("Expenses:Food".to_owned(), date, vec![])
            .unwrap();
        service
            .open_account("Assets:Cash".to_owned(), date, vec![])
            .unwrap();

        // Build a peer's signed directive the way that peer would.
        let peer = security::signing::PeerKeySignatureProvider::from_bytes(
            &[99u8; 32],
            RECONCILE_MESH.to_owned(),
        );
        let mut txn = sample_transaction("Peer entry", false);
        txn.postings[0].account = "Expenses:Food".to_owned();
        txn.postings[1].account = "Assets:Cash".to_owned();
        txn.metadata
            .insert("openledger-author".to_owned(), peer.public_key_hex());
        txn.metadata
            .insert("openledger-lamport".to_owned(), "77".to_owned());
        txn.metadata
            .insert("openledger-parents".to_owned(), String::new());
        let directive = Directive::Transaction(txn.clone());
        use security::signing::SignatureProvider;
        let signature = peer
            .sign(&security::signing::SignableMessage {
                content_id: &compute_content_id(&directive),
                is_transaction: true,
                parents: "",
                lamport: "77",
            })
            .unwrap();
        txn.metadata
            .insert("openledger-signature".to_owned(), signature.clone());

        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push('\n');
        content.push_str(&ledger::serialize::full_file_serialize(
            &[Directive::Transaction(txn)],
            &[],
        ));
        std::fs::write(&path, &content).unwrap();

        assert_eq!(service.reconcile_file().unwrap().new_directives, 1);
        let adopted = service
            .dag()
            .directives()
            .into_iter()
            .find(|d| matches!(d, Directive::Transaction(_)))
            .expect("the adopted transaction")
            .clone();

        let metadata = directive_metadata(&adopted);
        assert_eq!(
            metadata.get("openledger-author"),
            Some(&peer.public_key_hex()),
            "the peer's authorship must survive adoption"
        );
        assert_eq!(metadata.get("openledger-signature"), Some(&signature));
        assert_eq!(metadata.get("openledger-lamport"), Some(&"77".to_owned()));
        assert!(peer_would_accept(&adopted).is_ok());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reconcile_without_a_signer_is_unchanged() {
        // Signing disabled: no signer is installed, adoption is byte-for-byte
        // what it was, and nothing claims a signature it does not have.
        let path = temp_bean_path("unsigned");
        let mut service =
            ledger::service::LedgerService::boot(&path, "plain-node".to_owned()).unwrap();
        let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        service
            .open_account("Expenses:Food".to_owned(), date, vec![])
            .unwrap();
        service
            .open_account("Assets:Cash".to_owned(), date, vec![])
            .unwrap();

        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(HAND_EDIT);
        std::fs::write(&path, &content).unwrap();

        assert_eq!(service.reconcile_file().unwrap().new_directives, 1);
        let adopted = service
            .dag()
            .directives()
            .into_iter()
            .find(|d| matches!(d, Directive::Transaction(_)))
            .expect("the adopted transaction")
            .clone();
        let metadata = directive_metadata(&adopted);
        assert_eq!(
            metadata.get("openledger-author"),
            Some(&"plain-node".to_owned())
        );
        assert!(
            !metadata.contains_key("openledger-signature"),
            "nothing may be signed when no signer is installed"
        );
        // With signing off the same entry is accepted by a peer anyway.
        let entry = crate::gossip::make_supply_entry(&adopted);
        let parsed = validate_supply_entry(&entry).unwrap();
        assert!(verify_remote_signature(&parsed, false, RECONCILE_MESH).is_ok());

        std::fs::remove_file(path).ok();
    }

    // ── H-07 / T46: the Lamport ceiling, both sides of it ────────────────

    /// The envelope half of the remote receive path, as the next hop runs it.
    ///
    /// No signature check: the node under test runs without a signer, which is
    /// the `signing.enabled: false` case. `peer_would_accept` above is the
    /// signed variant.
    fn peer_envelope_check(directive: &Directive) -> Result<Directive, MergeError> {
        validate_supply_entry(&crate::gossip::make_supply_entry(directive))
    }

    /// The whole attack in one directive: an otherwise-valid `open` that a peer
    /// has stamped at `lamport`.
    fn hostile_open(account: &str, lamport: u64) -> Directive {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "hostile-peer".to_owned());
        metadata.insert("openledger-lamport".to_owned(), lamport.to_string());
        Directive::Open(Open {
            date: chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            account: account.to_owned(),
            currencies: Vec::new(),
            metadata,
        })
    }

    #[test]
    fn test_ingest_at_the_ceiling_cannot_brick_local_authoring() {
        // H-07 end to end. One allowlisted peer sends a directive stamped at
        // exactly the inbound cap. Before T46 the bound was inclusive, so it was
        // accepted; adoption's `+1` put the victim's clock one step ABOVE the
        // cap; the stamp sites had no cap at all; and from then on every
        // directive the victim authored was refused by every peer — silently,
        // because the mutation still returned success, and permanently, because
        // boot re-derives the clock from the file.
        let path = temp_bean_path("lamport-ceiling");
        let mut service =
            ledger::service::LedgerService::boot(&path, "victim-node".to_owned()).unwrap();
        let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();

        // Delivered as the attack would be: staged AND persisted, so a node
        // without the fix carries the poisoned clock across the restart below.
        let ingest = service.insert_remote_directive(hostile_open(
            "Assets:Poison",
            ledger::service::LAMPORT_CEILING,
        ));

        // The consequence that matters: this node can still author, and what it
        // authors is accepted by the next hop.
        let id = service
            .open_account("Assets:Cash".to_owned(), date, vec!["USD".to_owned()])
            .expect("authoring must still succeed after the ingest");
        let authored = service.get_directive(&id).expect("just authored").clone();
        assert!(
            peer_envelope_check(&authored).is_ok(),
            "a locally-authored directive must pass the peer-side envelope check; \
             lamport {:?} gave {:?}",
            authored.lamport_clock(),
            peer_envelope_check(&authored),
        );

        // And again after a restart, because a poisoned value that reached the
        // file would be re-derived into the clock on every later boot.
        drop(service);
        let mut rebooted =
            ledger::service::LedgerService::boot(&path, "victim-node".to_owned()).unwrap();
        let id = rebooted
            .open_account("Assets:Savings".to_owned(), date, vec!["USD".to_owned()])
            .expect("authoring must still succeed after a restart");
        let authored = rebooted.get_directive(&id).expect("just authored").clone();
        assert!(
            peer_envelope_check(&authored).is_ok(),
            "after a restart, a locally-authored directive must still pass the peer-side \
             envelope check; lamport {:?} gave {:?}",
            authored.lamport_clock(),
            peer_envelope_check(&authored),
        );

        // Why those two hold: the poison is refused on both sides of the same
        // rule — here on the wire (exclusive, so the `+1` cannot carry a
        // receiver past the cap) and again as the ledger adopts.
        assert!(
            ingest.is_err(),
            "a remote lamport at the ceiling must be refused, not adopted"
        );
        let entry = crate::gossip::make_supply_entry(&hostile_open(
            "Assets:Poison",
            ledger::service::LAMPORT_CEILING,
        ));
        assert!(
            matches!(
                validate_supply_entry(&entry),
                Err(MergeError::InvalidEnvelope(_))
            ),
            "the wire bound is exclusive: {:?}",
            validate_supply_entry(&entry)
        );

        // One step lower is still accepted on the wire — a bound, not a blanket
        // refusal.
        let entry = crate::gossip::make_supply_entry(&hostile_open(
            "Assets:Fine",
            ledger::service::LAMPORT_CEILING - 1,
        ));
        assert!(validate_supply_entry(&entry).is_ok());

        std::fs::remove_file(path).ok();
    }

    /// A directive exactly as a victim's DAG would hold it if a body-smuggled
    /// `openledger-*` key had ever been accepted. Built directly, because the
    /// public ingest path refuses it (H-06).
    fn poisoned_directive() -> Directive {
        let mut txn = sample_transaction("Poisoned", false);
        txn.metadata
            .insert("openledger-author".to_owned(), "peer-1".to_owned());
        txn.metadata
            .insert("openledger-lamport".to_owned(), "5".to_owned());
        txn.metadata
            .insert("openledger-parents".to_owned(), "".to_owned());
        txn.metadata
            .insert("openledger-custom".to_owned(), "x".to_owned());
        Directive::Transaction(txn)
    }

    #[test]
    fn test_serve_side_does_not_promote_a_stray_openledger_key() {
        // T21 follow-up: `extract_envelope` now filters to the closed
        // `ENVELOPE_KEYS` set rather than to the `openledger-` prefix, so the
        // serve side cannot hand the next hop a key nobody validated — even
        // from a DAG that (impossibly, today) holds one.
        let entry = crate::gossip::make_supply_entry(&poisoned_directive());

        assert!(
            !entry.envelope.contains_key("openledger-custom"),
            "a stray body key must not be promoted into the outbound envelope: {:?}",
            entry.envelope
        );
        // The four real envelope keys still ride out, unchanged.
        assert_eq!(
            entry
                .envelope
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "openledger-author",
                "openledger-lamport",
                "openledger-parents"
            ],
        );
        // And what we serve is accepted by the next hop, rather than rejected
        // forever — which is the whole point of not promoting it.
        assert!(
            validate_supply_entry(&entry).is_ok(),
            "the filtered entry must pass the receiving side: {:?}",
            validate_supply_entry(&entry)
        );
    }

    #[test]
    fn test_body_smuggled_key_poisons_the_next_hop_on_re_serve() {
        // H-06 mechanism test — the livelock the ingest check prevents, and the
        // reason the serve-side filter above is worth having as well.
        //
        // Promotion is what used to happen; reconstruct it by hand (the real
        // serve path no longer does it) and show where it led.
        let directive = poisoned_directive();
        let mut entry = crate::gossip::make_supply_entry(&directive);
        entry
            .envelope
            .insert("openledger-custom".to_owned(), "x".to_owned());

        // The next hop's closed-set check rejects the whole directive, every
        // time it is offered, forever.
        let error = validate_supply_entry(&entry).unwrap_err();
        assert!(
            matches!(error, MergeError::InvalidEnvelope(ref reason) if reason.contains("openledger-custom")),
            "expected the unsupported-envelope-key rejection, got {error:?}"
        );
    }
}
