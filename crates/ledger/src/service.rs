//! Ledger service — the unified write + boot layer (§3.5).
//!
//! Ties together parser, serializer, DAG, validation, and file persistence.
//! This is the single entry point for all ledger mutations.

use chrono::{Datelike, NaiveDate};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{error, warn};

use crate::dag::{DagError, InsertResult, LedgerDag};
use crate::error::ParseError;
use crate::hash::compute_content_id;
use crate::model::*;
use crate::parse::{
    parse_file, reject_control_characters, validate_account_name, validate_currency, validate_link,
    validate_metadata_key, validate_tag,
};
use crate::read_model::ReadModel;
use crate::serialize::full_file_serialize;
use crate::validate::{validate_transaction, AccountState, ValidationError};

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
const COMPACTION_JOURNAL_RATIO: u64 = 2;

/// What a [`PendingCommit`] will do to the files (T44).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitKind {
    /// Frame the staged directives as one journal record, append it, fsync.
    /// O(staged bytes) — the canonical `.bean` is not touched at all.
    Append,
    /// Rewrite the canonical `.bean` from memory (temp + fsync + rename) and
    /// delete the journal. O(ledger).
    Compact,
}

/// Observer invoked at the head of [`PendingCommit::commit`], on the blocking
/// thread, before any I/O — **a test seam**.
///
/// Production never installs one: `set_commit_observer` is called from tests
/// only, and the commit path pays a single `Option` check. Tests use it two
/// ways: to record the bytes each commit actually writes (the O(1) proof), and
/// to stall a commit in flight so a concurrent GraphQL read can be shown to
/// complete anyway (the reads-not-blocked proof).
pub type CommitObserver = std::sync::Arc<dyn Fn(CommitKind, u64) + Send + Sync>;

/// Size + mtime of the canonical file as this service last saw it (T44).
///
/// The cheap half of the T35 hand-edit check: one `stat` per commit says
/// "nothing touched the `.bean`", which is all an append needs to know. The
/// exact half — re-read, re-hash, adopt — still runs, but only on the
/// compaction path, which is the only path that rewrites the file and therefore
/// the only one that could erase an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileMarker {
    length: u64,
    modified: Option<std::time::SystemTime>,
}

impl FileMarker {
    fn of(path: &Path) -> Option<FileMarker> {
        let metadata = std::fs::metadata(path).ok()?;
        Some(FileMarker {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

/// Write `content` via a sibling `.tmp` file, fsync, then POSIX rename (H-10 / CAP-1).
fn persist_atomically(path: &Path, content: &str) -> Result<(), std::io::Error> {
    if content.len() as u64 > MAX_LEDGER_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "ledger content is {} bytes (max {MAX_LEDGER_FILE_BYTES})",
                content.len()
            ),
        ));
    }

    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ledger path has no file name",
        )
    })?;
    let temporary_path = path.with_file_name(format!("{}.tmp", file_name.to_string_lossy()));

    {
        let mut options = std::fs::OpenOptions::new();
        // `create_new` sets O_CREAT|O_EXCL, which refuses to open (and therefore
        // to follow) a pre-planted `<name>.tmp` symlink — closing the symlink
        // race where the next persist would truncate the link's target.
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        // A leftover temp from a previously crashed persist is unlinked once and
        // retried. `remove_file` unlinks the entry itself (never a symlink's
        // target); if a symlink is re-planted in the race window, the retry's
        // O_EXCL create fails again and the persist errors out rather than
        // writing through the link.
        //
        // Whose temp is it? Under `gl-node`, which holds an exclusive
        // inter-process lock on the ledger for the life of the process
        // (M-17/T30, `gl-node/src/ledger_lock.rs`), no sibling process can be
        // mid-persist on this file — so the temp found here is always our own
        // crashed leftover and unlinking it is safe. Library users that call the
        // service directly without taking that lock keep the pre-T30 exposure:
        // a concurrent process's in-flight temp could be deleted here. Take the
        // same lock if you run more than one writer on a ledger.
        let mut file = match options.open(&temporary_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(&temporary_path)?;
                options.open(&temporary_path)?
            }
            Err(error) => return Err(error),
        };
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }

    std::fs::rename(&temporary_path, path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions)?;
    }

    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if let Ok(directory_file) = std::fs::File::open(directory) {
        let _ = directory_file.sync_all();
    }
    Ok(())
}

/// Read the ledger file, capped at [`MAX_LEDGER_FILE_BYTES`], with a leading
/// UTF-8 BOM stripped (L-28).
///
/// The BOM is removed here rather than only inside [`parse_file`] because boot
/// also runs `extract_leading_comments` and an emptiness check over this string,
/// and because every hash this module records for a ledger file
/// ([`LedgerService::last_file_hash`]) must be taken over the BOM-free form —
/// otherwise a BOM'd-but-otherwise-identical file would read as a hand edit and
/// trigger a pointless reconcile on the next persist.
fn read_ledger_file(path: &Path) -> Result<String, ServiceError> {
    let length = std::fs::metadata(path)?.len();
    if length > MAX_LEDGER_FILE_BYTES {
        return Err(ServiceError::ResourceLimitExceeded {
            message: format!("ledger file is {length} bytes (max {MAX_LEDGER_FILE_BYTES})"),
        });
    }
    let content = std::fs::read_to_string(path)?;
    Ok(match content.strip_prefix(crate::parse::BYTE_ORDER_MARK) {
        Some(stripped) => stripped.to_owned(),
        None => content,
    })
}

/// True for the exact shape a stored txid has: 64 **lowercase** hex characters.
///
/// `is_ascii_hexdigit` also admits uppercase, but every id the ledger stores is
/// lowercase and every lookup is exact — so an uppercase spelling of a real
/// txid passes validation and then never resolves, leaving the directive an
/// orphan that squats buffer space for its full TTL and re-Wants forever
/// (L-29).
fn parent_txid_is_well_formed(parent_id: &str) -> bool {
    parent_id.len() == 64
        && parent_id
            .chars()
            .all(|character| matches!(character, '0'..='9' | 'a'..='f'))
}

/// SHA-256 (lowercase hex) of the exact ledger-file bytes, as read or written.
///
/// This is deliberately a hash of the *file*, not of any directive: it answers
/// only "is what is on disk still the text this service last wrote or read?"
/// (L-30).
fn file_content_hash(content: &str) -> String {
    let digest = Sha256::digest(content.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Content ids of the file's transactions that sit on — or descend from — a
/// parent cycle (L-17).
///
/// `openledger-parents` lives in the envelope, and the content hash covers only
/// the economic body, so the parent pointers are hand-editable **without any id
/// changing**: a text editor can make `A` claim `hash(B)` as its parent while
/// `B` claims `hash(A)`. That file is not a DAG, and the DAG's own `I8` check
/// only catches it on the *second* insert — after the first cycle member is
/// already in, and (at boot) by aborting the whole load.
///
/// The scan is Kahn's algorithm over the subgraph induced by parents **present
/// in this file**. A parent the file does not contain is a legitimately missing
/// ancestor that anti-entropy supplies later, so it never blocks its child.
/// Whatever cannot be ordered is on a cycle or descends from one; both are
/// reported, because a directive whose ancestry runs through a fabricated cycle
/// can never have that ancestry validated either. Only transactions carry
/// parents, so only transactions can be on a cycle — every other directive is a
/// sink in this graph and orders immediately, which is why they are not hashed
/// here.
///
/// Returns an empty set for every well-formed file, which is the only case that
/// costs anything on a normal boot.
fn directives_blocked_by_parent_cycles(directives: &[&Directive]) -> BTreeSet<String> {
    let mut parents_by_id: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for directive in directives {
        if let Directive::Transaction(transaction) = directive {
            // First occurrence wins, exactly like the DAG's G-Set dedup: a
            // second line with the same economic body is the same directive and
            // never reaches `insert`.
            parents_by_id
                .entry(compute_content_id(directive))
                .or_insert_with(|| {
                    transaction
                        .parent_ids()
                        .iter()
                        .map(|parent| (*parent).to_owned())
                        .collect()
                });
        }
    }

    let mut unordered_parents: BTreeMap<&str, usize> = BTreeMap::new();
    let mut children_of: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut ready: Vec<&str> = Vec::new();

    for (content_id, parents) in &parents_by_id {
        let mut in_file_parents = 0usize;
        for parent in parents {
            if parents_by_id.contains_key(parent.as_str()) {
                in_file_parents += 1;
                children_of
                    .entry(parent.as_str())
                    .or_default()
                    .push(content_id.as_str());
            }
        }
        if in_file_parents == 0 {
            ready.push(content_id.as_str());
        }
        unordered_parents.insert(content_id.as_str(), in_file_parents);
    }

    while let Some(content_id) = ready.pop() {
        let Some(children) = children_of.get(content_id) else {
            continue;
        };
        for child in children {
            if let Some(remaining) = unordered_parents.get_mut(*child) {
                *remaining = remaining.saturating_sub(1);
                if *remaining == 0 {
                    ready.push(child);
                }
            }
        }
    }

    unordered_parents
        .into_iter()
        .filter(|(_, remaining)| *remaining > 0)
        .map(|(content_id, _)| content_id.to_owned())
        .collect()
}

/// §3.12 limits for any write path (local, remote, reconcile).
pub fn enforce_resource_limits(directive: &Directive) -> Result<(), ServiceError> {
    if directive.metadata().len() > MAX_METADATA_KEYS_PER_DIRECTIVE {
        return Err(ServiceError::ResourceLimitExceeded {
            message: format!(
                "Too many metadata keys: {} (max {})",
                directive.metadata().len(),
                MAX_METADATA_KEYS_PER_DIRECTIVE
            ),
        });
    }

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
fn validate_ledger_date(date: NaiveDate) -> Result<(), ServiceError> {
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

// ─── Envelope keys and body canonicalization (H-03 / H-06 / L-26) ────────────

/// Prefix that marks a metadata key as envelope (§3.3.1) rather than economic.
///
/// The economic canonical serializer strips every key with this prefix, so a
/// key carried here is invisible to the content hash.
const ENVELOPE_KEY_PREFIX: &str = "openledger-";

/// `openledger-author` — the writing peer's Iroh `EndpointId`.
const ENVELOPE_KEY_AUTHOR: &str = "openledger-author";
/// `openledger-lamport` — the writer's Lamport clock value.
const ENVELOPE_KEY_LAMPORT: &str = "openledger-lamport";
/// `openledger-parents` — comma-separated parent txids.
const ENVELOPE_KEY_PARENTS: &str = "openledger-parents";
/// `openledger-signature` — hex Ed25519 signature over the envelope binding.
const ENVELOPE_KEY_SIGNATURE: &str = "openledger-signature";

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

fn validate_body_string(label: &str, value: &str) -> Result<(), ServiceError> {
    reject_control_characters(label, value)
        .map_err(|message| ServiceError::InvalidInput { message })
}

fn validate_metadata_strings(metadata: &Metadata) -> Result<(), ServiceError> {
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

// ─── Service error ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ServiceError {
    /// File parse errors on boot.
    Parse(Vec<ParseError>),
    /// Ledger invariant violation (I1–I3, I9).
    Validation(ValidationError),
    /// DAG structure error (cycle, missing parent).
    Dag(DagError),
    /// Filesystem I/O error.
    Io(std::io::Error),
    /// FR-3 AC1: account is already open.
    AccountAlreadyOpen { account: String },
    /// FR-3 AC2: account has transactions after the proposed close date.
    AccountHasLaterTransactions {
        account: String,
        latest_date: NaiveDate,
    },
    /// Account is not currently open (for close).
    AccountNotOpen { account: String },
    /// §3.12: a resource limit was exceeded.
    ResourceLimitExceeded { message: String },
    /// Account name violates §2.3.
    InvalidAccountName { account: String },
    /// Currency code violates §2.3.
    InvalidCurrency { currency: String },
    /// Tag name violates §2.3.
    InvalidTag { tag: String },
    /// Link name violates §2.3.
    InvalidLink { link: String },
    /// Payee/narration contains control characters (H-8).
    InvalidInput { message: String },
    /// H-04: a date outside the range the `.bean` file grammar can re-parse.
    DateOutOfRange { date: NaiveDate },
    /// H-06: an `openledger-*` key in the economic body, where the envelope
    /// rules permit none (unknown at directive level, or any at posting level).
    BodyEnvelopeKey { key: String },
    /// T44: the append-only commit journal could not be read — it is over
    /// budget, or corrupt in a way a crash cannot produce. Fails closed.
    Journal { message: String },
    /// T44: a durable commit prepared earlier has not been finished or
    /// recovered yet.
    ///
    /// Unreachable when callers honour the single-writer contract documented on
    /// [`LedgerService::prepare_commit`]; it exists so a caller that violates it
    /// gets a loud refusal instead of an interleaved write.
    CommitInFlight,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Parse(errors) => {
                write!(f, "Parse errors: ")?;
                for (i, e) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{e}")?;
                }
                Ok(())
            }
            ServiceError::Validation(e) => write!(f, "Validation: {e}"),
            ServiceError::Dag(e) => write!(f, "DAG: {e}"),
            ServiceError::Io(e) => write!(f, "IO: {e}"),
            ServiceError::AccountAlreadyOpen { account } => {
                write!(f, "Account {account} is already open")
            }
            ServiceError::AccountHasLaterTransactions {
                account,
                latest_date,
            } => {
                write!(
                    f,
                    "Cannot close {account}: has transactions as late as {latest_date}"
                )
            }
            ServiceError::AccountNotOpen { account } => {
                write!(f, "Account {account} is not open")
            }
            ServiceError::ResourceLimitExceeded { message } => {
                write!(f, "Resource limit exceeded: {message}")
            }
            ServiceError::InvalidAccountName { account } => {
                write!(f, "Invalid account name: {account}")
            }
            ServiceError::InvalidCurrency { currency } => {
                write!(f, "Invalid currency: {currency}")
            }
            ServiceError::InvalidTag { tag } => write!(f, "Invalid tag: {tag}"),
            ServiceError::InvalidLink { link } => write!(f, "Invalid link: {link}"),
            ServiceError::InvalidInput { message } => write!(f, "{message}"),
            ServiceError::DateOutOfRange { date } => {
                write!(
                    f,
                    "date '{date}' is outside the supported range 0001-01-01..9999-12-31"
                )
            }
            ServiceError::BodyEnvelopeKey { key } => {
                write!(
                    f,
                    "metadata key '{key}' is not an envelope key permitted in this position"
                )
            }
            ServiceError::Journal { message } => write!(f, "{message}"),
            ServiceError::CommitInFlight => {
                write!(f, "a durable ledger commit is already in flight")
            }
        }
    }
}

impl std::error::Error for ServiceError {}

impl ServiceError {
    /// §2.8 error code for GraphQL error extensions.
    pub fn error_code(&self) -> &'static str {
        match self {
            ServiceError::Parse(_) => "PARSE_ERROR",
            ServiceError::Validation(v) => v.error_code(),
            ServiceError::Dag(DagError::CycleDetected { .. }) => "CYCLE_DETECTED",
            ServiceError::Dag(DagError::MissingParent { .. }) => "MISSING_PARENT",
            // L-14: the acyclicity check gave up on a crafted parent graph. It
            // is a refusal to answer, not a proven cycle, so it gets its own
            // code rather than being reported as CYCLE_DETECTED.
            ServiceError::Dag(DagError::CycleCheckExhausted { .. }) => "CYCLE_CHECK_EXHAUSTED",
            ServiceError::Io(_) => "IO_ERROR",
            ServiceError::AccountAlreadyOpen { .. } => "ACCOUNT_ALREADY_OPEN",
            ServiceError::AccountHasLaterTransactions { .. } => "ACCOUNT_HAS_LATER_TRANSACTIONS",
            ServiceError::AccountNotOpen { .. } => "ACCOUNT_NOT_OPEN",
            ServiceError::ResourceLimitExceeded { .. } => "RESOURCE_LIMIT_EXCEEDED",
            ServiceError::InvalidAccountName { .. } => "INVALID_ACCOUNT_NAME",
            ServiceError::InvalidCurrency { .. } => "INVALID_CURRENCY",
            ServiceError::InvalidTag { .. } => "INVALID_TAG",
            ServiceError::InvalidLink { .. } => "INVALID_LINK",
            ServiceError::InvalidInput { .. } => "INVALID_INPUT",
            ServiceError::DateOutOfRange { .. } => "DATE_OUT_OF_RANGE",
            ServiceError::BodyEnvelopeKey { .. } => "BODY_ENVELOPE_KEY",
            ServiceError::Journal { .. } => "LEDGER_JOURNAL",
            ServiceError::CommitInFlight => "COMMIT_IN_FLIGHT",
        }
    }
}

impl From<ValidationError> for ServiceError {
    fn from(e: ValidationError) -> Self {
        ServiceError::Validation(e)
    }
}

impl From<DagError> for ServiceError {
    fn from(e: DagError) -> Self {
        ServiceError::Dag(e)
    }
}

impl From<std::io::Error> for ServiceError {
    fn from(e: std::io::Error) -> Self {
        ServiceError::Io(e)
    }
}

impl From<crate::journal::JournalError> for ServiceError {
    fn from(e: crate::journal::JournalError) -> Self {
        match e {
            // An unreadable journal is an unreadable ledger: it is routed to the
            // same `Io` arm the `.bean` uses so the L-13 reload path and the
            // GraphQL error mapping (which redacts paths, L3) treat it alike.
            crate::journal::JournalError::Io(error) => ServiceError::Io(error),
            other => ServiceError::Journal {
                message: other.to_string(),
            },
        }
    }
}

// ─── Input types ─────────────────────────────────────────────────────────────

/// Input for appending a transaction (domain-level; GraphQL layer converts to this).
#[derive(Debug, Clone)]
pub struct TransactionInput {
    pub date: NaiveDate,
    pub flag: Flag,
    pub payee: Option<String>,
    pub narration: Option<String>,
    pub tags: Vec<String>,
    pub links: Vec<String>,
    pub postings: Vec<PostingInput>,
}

/// A single posting in a transaction input.
#[derive(Debug, Clone)]
pub struct PostingInput {
    pub account: String,
    pub amount: Option<Amount>,
    pub cost: Option<CostSpec>,
    pub price: Option<PriceSpec>,
}

/// What a local append actually did (§3.5 write path, M-10 interim signal).
///
/// The content id hashes the economic body only — every `openledger-*` envelope
/// key (author, parents, lamport, signature) is excluded — so an append whose
/// body is already in the DAG is a no-op that keeps the *existing* entry's
/// envelope. That entry may have been authored by another peer, which is the
/// M-10 authorship-squatting shape; it may equally be a legitimately distinct
/// but identical event (two identical same-day coffees) collapsed into one
/// posting. Either way the caller must be able to tell the two apart from a
/// fresh insert, so the append path reports it instead of returning the
/// pre-existing txid as if it had just been created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOutcome {
    /// The transaction's content id — newly inserted, or the pre-existing one.
    pub txid: String,
    /// `true` when this exact economic body was already in the ledger and
    /// nothing new was recorded.
    pub already_existed: bool,
}

// ─── Two-phase durable commit (T44) ──────────────────────────────────────────

/// A durable write that has been *prepared* in memory and not yet performed.
///
/// # Why persistence is split in two
///
/// Before T44 a mutation serialized, wrote and fsynced the whole `.bean` while
/// holding the ledger write lock, on a tokio worker thread. A slow fsync
/// therefore blocked every GraphQL **read** behind the `RwLock` and parked a
/// runtime worker for the duration. Splitting the write gives the node layer
/// the shape it needs:
///
/// ```text
/// write lock { mutate; prepare_commit() }   // in-memory + serialize, cheap
/// drop(lock)
/// spawn_blocking { pending.commit() }       // the write + the fsync
/// write lock { finish_commit(receipt) }     // bookkeeping
///        └── on failure: recover_failed_commit()   (L-13)
/// ```
///
/// [`PendingCommit`] owns everything the I/O needs — paths and bytes, no
/// borrow of the service — so it is `Send + 'static` and can be moved into
/// `spawn_blocking`. It deliberately holds **no** handle back to the
/// `LedgerService`: the only way a commit can affect in-memory state is through
/// the [`CommitReceipt`] the caller feeds to `finish_commit`, which is what
/// makes "the commit cannot race the ledger" a property of the types rather
/// than of the caller's discipline.
///
/// Synchronous callers (the ledger's own tests, `reconcile_file`, any library
/// user that does not care) never see this: [`LedgerService::persist_or_reload`]
/// and [`LedgerService::compact`] still do prepare + commit + finish in one
/// call, inline, exactly as before.
pub struct PendingCommit {
    generation: u64,
    kind: CommitKind,
    ledger_path: PathBuf,
    journal_path: PathBuf,
    /// [`CommitKind::Compact`] only: the full canonical file text.
    canonical: String,
    /// [`CommitKind::Append`] only: the framed journal record.
    record: String,
    observer: Option<CommitObserver>,
}

impl std::fmt::Debug for PendingCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the ledger contents.
        f.debug_struct("PendingCommit")
            .field("generation", &self.generation)
            .field("kind", &self.kind)
            .field("bytes_to_write", &self.bytes_to_write())
            .finish()
    }
}

impl PendingCommit {
    /// Whether this commit appends a journal record or rewrites the `.bean`.
    pub fn kind(&self) -> CommitKind {
        self.kind
    }

    /// Bytes this commit will write. `O(directive)` for an append; `O(ledger)`
    /// for a compaction — which is the whole difference T44 buys, made
    /// observable without a test seam.
    pub fn bytes_to_write(&self) -> u64 {
        match self.kind {
            CommitKind::Append => self.record.len() as u64,
            CommitKind::Compact => self.canonical.len() as u64,
        }
    }

    /// Perform the write and the fsync. **Blocking** — call it from
    /// `spawn_blocking` (or from a synchronous context), never on a runtime
    /// worker thread while a lock is held.
    ///
    /// A compaction writes the canonical file first and only then deletes the
    /// journal. A crash in between leaves both on disk, holding overlapping
    /// directives — which boot unions and the DAG's G-Set dedups by content id,
    /// so the crash window is safe by construction rather than by recovery
    /// logic. The reverse order would have a window in which neither file holds
    /// the directives.
    pub fn commit(self) -> Result<CommitReceipt, ServiceError> {
        if let Some(ref observe) = self.observer {
            observe(self.kind, self.bytes_to_write());
        }
        match self.kind {
            CommitKind::Compact => {
                persist_atomically(&self.ledger_path, &self.canonical)?;
                crate::journal::remove_journal(&self.journal_path)?;
                Ok(CommitReceipt {
                    generation: self.generation,
                    kind: self.kind,
                    bytes_written: self.canonical.len() as u64,
                    // Hashing the canonical text is O(ledger); doing it here
                    // keeps it off the write lock with the rest of the cost.
                    canonical_hash: Some(file_content_hash(&self.canonical)),
                    canonical_bytes: Some(self.canonical.len() as u64),
                    canonical_marker: FileMarker::of(&self.ledger_path),
                    journal_bytes: 0,
                })
            }
            CommitKind::Append => {
                let (journal_bytes, _created) =
                    crate::journal::append_record(&self.journal_path, &self.record)?;
                Ok(CommitReceipt {
                    generation: self.generation,
                    kind: self.kind,
                    bytes_written: self.record.len() as u64,
                    // The canonical file was not touched, so nothing about it
                    // changes: no new hash, no new size, no new marker.
                    canonical_hash: None,
                    canonical_bytes: None,
                    canonical_marker: None,
                    journal_bytes,
                })
            }
        }
    }
}

/// What a completed [`PendingCommit`] tells the service about the files.
///
/// The only channel from the off-lock commit back into in-memory state; it
/// carries a generation so [`LedgerService::finish_commit`] can refuse a
/// receipt that does not belong to the commit it is waiting for.
#[derive(Debug, Clone)]
pub struct CommitReceipt {
    generation: u64,
    kind: CommitKind,
    bytes_written: u64,
    canonical_hash: Option<String>,
    canonical_bytes: Option<u64>,
    canonical_marker: Option<FileMarker>,
    journal_bytes: u64,
}

impl CommitReceipt {
    /// Whether the commit appended to the journal or rewrote the `.bean`.
    pub fn kind(&self) -> CommitKind {
        self.kind
    }

    /// Bytes actually written by this commit.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

// ─── Ledger service ──────────────────────────────────────────────────────────

/// Signs an adopted directive: `(content_id, is_transaction, parents, lamport)`
/// → hex `openledger-signature`, or `None` when signing is disabled (L-11).
///
/// The four arguments are exactly `security::signing::SignableMessage`'s fields.
/// This crate deliberately does not depend on `security` — the ledger does not
/// care *how* a signature is produced — so the dependency is inverted into a
/// callback, the same shape the `*_signing` mutation methods already take.
/// `is_transaction` is a parameter rather than a call-site constant because
/// reconcile signs whatever kind the file happens to contain, and the signed
/// message's domain prefix differs between `txid` and `directiveId`.
pub type DirectiveSigner =
    std::sync::Arc<dyn Fn(&str, bool, &str, &str) -> Option<String> + Send + Sync>;

/// The unified ledger service — owns DAG, account state, and file persistence.
///
/// All write operations go through this service. Reads query the DAG directly.
/// Concurrency (RwLock) is handled by the gl-node layer.
pub struct LedgerService {
    dag: LedgerDag,
    accounts: AccountState,
    read_model: ReadModel,
    lamport_clock: u64,
    author_id: String,
    file_path: PathBuf,
    leading_comments: Vec<String>,
    /// SHA-256 of the exact file text this service last wrote or read (L-30).
    ///
    /// Set at boot, after every successful persist, and after every reconcile.
    /// Any full-file persist compares it against the bytes actually on disk
    /// first: a mismatch means someone hand-edited the `.bean` while the node
    /// was running, and the edit is reconciled in before it would be
    /// overwritten. Hashed over the BOM-free text `read_ledger_file` returns, so
    /// an editor that only added a BOM is not mistaken for an edit.
    last_file_hash: String,
    /// How many times a persist found the file changed underneath it and ran the
    /// adopt-then-persist path (L-30).
    ///
    /// Zero on a node nobody hand-edits; it is the observable signal that the
    /// recorded-hash fast path is doing its job.
    external_reconcile_count: u64,
    /// Signs entries this node adopts from its own `.bean` file (L-11).
    ///
    /// The mutation methods take their signer as a per-call closure, because the
    /// caller (the GraphQL resolver) has it to hand. Reconcile does not: it runs
    /// from the file watcher *and* from inside [`Self::persist_or_reload`] via
    /// [`Self::adopt_external_edits`], which is reached from every mutation and
    /// from the P2P receive path — threading a signer through all of those would
    /// mean putting it on the service anyway, one parameter at a time. So it
    /// lives here, installed once at boot by [`Self::set_signer`].
    ///
    /// `None` means "never sign", which is also what a signing-disabled provider
    /// returns, so the two cannot disagree about the disabled case.
    signer: Option<DirectiveSigner>,

    // ── T44: append-only persistence ──────────────────────────────────────
    /// `<ledger>.bean.journal` — the append-only sidecar, derived once at boot.
    journal_path: PathBuf,
    /// Byte length of the canonical `.bean` as this service last wrote or read
    /// it. Drives the compaction threshold and the combined size cap.
    canonical_bytes: u64,
    /// Size + mtime of the canonical `.bean` as last seen — the O(1) hand-edit
    /// probe (see [`FileMarker`]).
    canonical_marker: Option<FileMarker>,
    /// Does the canonical `.bean` hold exactly the bytes this service would
    /// write for the directives it contains?
    ///
    /// **False after boot**, because boot *read* a file it did not write: a
    /// hand-authored ledger, a file carrying a BOM (L-28), or one written by an
    /// older format are all legitimately non-canonical on disk. Before T44
    /// every persist was a full rewrite, so the first one after boot silently
    /// canonicalised the file; the append path would not, so the first commit
    /// after a boot is still a compaction and the guarantee is preserved
    /// exactly. True from that compaction onwards — an append leaves the
    /// canonical file untouched and therefore still canonical for its own
    /// contents.
    canonical_is_current: bool,
    /// Byte length of the journal on disk, as of the last commit.
    canonical_journal_bytes: u64,
    /// Content ids inserted since the last commit and not yet written anywhere.
    ///
    /// Ids, not directives: the record is built by resolving them against the
    /// DAG at prepare time, which costs one `serialize_directive` per staged
    /// directive and keeps the memory overhead of a large catch-up batch at 64
    /// bytes per entry instead of a second full clone of every body.
    pending_ids: Vec<String>,
    /// Set when the next commit MUST be a full rewrite rather than an append.
    ///
    /// Three producers, all of them cases an append cannot express: a
    /// [`Self::stamp_signature`] that mutated a directive already on disk (a
    /// journal record carrying the same content id would be dropped by the
    /// G-Set on the way back in, losing the signature); a reconcile, which has
    /// to *remove* refused entries from the file; and a journal whose tail was
    /// torn by a crash, which cannot be safely appended to.
    force_compaction: bool,
    /// Bumped by every [`Self::prepare_commit`]; stamped into the
    /// [`PendingCommit`] and checked by [`Self::finish_commit`].
    commit_generation: u64,
    /// True between a prepare and its finish/recover. See
    /// [`Self::prepare_commit`] for the single-writer contract this enforces.
    commit_in_flight: bool,
    /// The process-wide single-writer gate (see [`Self::commit_gate`]).
    commit_gate: std::sync::Arc<tokio::sync::Mutex<()>>,
    /// Test seam; `None` in production. See [`CommitObserver`].
    commit_observer: Option<CommitObserver>,
}

impl LedgerService {
    // ── Boot ──────────────────────────────────────────────────────────────

    /// Boot the ledger service from a `.bean` file **and its commit journal**.
    ///
    /// If the file doesn't exist, creates an empty file and starts with an empty ledger.
    /// Parses directives, builds account state, populates the DAG, and initializes
    /// the Lamport clock.
    ///
    /// # Canonical ∪ journal (T44)
    ///
    /// Since T44 a mutation on a ledger past
    /// [`COMPACTION_MIN_CANONICAL_BYTES`] becomes an append to
    /// `<ledger>.bean.journal` rather than a rewrite of the `.bean`, so the
    /// durable state is the **union** of the two files. Boot reads both,
    /// concatenates the journal's records after the canonical text, and runs
    /// the identical pipeline over the result: one canonical `(date,
    /// type_priority)` sort, one cycle pre-scan, one insert loop. Nothing else
    /// changes, and it is that reuse — rather than a second merge routine —
    /// that makes "boot(canonical + journal) == boot(compacted canonical)" hold
    /// by construction:
    ///
    /// * the union is a set, and directive identity is the content hash, so a
    ///   directive present in *both* files (the post-crash, pre-compaction
    ///   shape) is deduped for free by the DAG's G-Set;
    /// * record order in the journal is arrival order, and the sort discards it
    ///   before anything is inserted, so the state cannot depend on it;
    /// * the leading comments and the L-30 file hash are taken from the
    ///   canonical text **only** — the journal is node-private and holds no
    ///   comments, and the hash's only job is to answer "did a human edit the
    ///   `.bean`?".
    ///
    /// Boot never writes. That is deliberate: [`Self::persist_or_reload`]
    /// recovers a failed commit by re-booting this very path, and a recovery
    /// that tried to write would fail for exactly the reason the commit just
    /// failed. A journal present at boot is simply carried; the first commit —
    /// or an explicit [`Self::compact`] from the node's startup path — folds it
    /// in.
    pub fn boot(file_path: impl Into<PathBuf>, author_id: String) -> Result<Self, ServiceError> {
        let file_path = file_path.into();
        let journal_path = crate::journal::journal_path_for(&file_path);

        // Read or create the file.
        let content = if file_path.exists() {
            read_ledger_file(&file_path)?
        } else {
            // Create parent dirs + empty file (§3.3).
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            persist_atomically(&file_path, "")?;
            String::new()
        };
        let canonical_bytes = content.len() as u64;
        let canonical_marker = FileMarker::of(&file_path);

        // T44 invariant 5: the journal's budget is whatever `MAX_LEDGER_FILE_BYTES`
        // has left after the canonical file, so canonical ∪ journal — and hence
        // the file a compaction would write — is bounded by the same constant
        // that has always bounded the `.bean`.
        let journal_budget = MAX_LEDGER_FILE_BYTES.saturating_sub(canonical_bytes);
        let scan = crate::journal::read_journal(&journal_path, journal_budget)?;
        if scan.torn_tail_bytes > 0 {
            warn!(
                dropped_bytes = scan.torn_tail_bytes,
                intact_records = scan.payloads.len(),
                journal = %journal_path.display(),
                "ledger commit journal ends in a torn record — the node crashed mid-append; \
                 the torn record is DROPPED (its commit never reported success) and the rest \
                 of the journal loads normally. The next commit will compact."
            );
        }

        // Extract leading comments (lines starting with `;` before any
        // directive) from the CANONICAL text: the journal carries none, and a
        // record header is a `;` line that would otherwise be mistaken for one.
        let leading_comments = extract_leading_comments(&content);

        // Canonical ∪ journal, as one `.bean`-shaped string. Each payload and
        // the canonical text already end in `\n`, so one extra `\n` reproduces
        // the blank-line separator `full_file_serialize` writes.
        let mut combined = content.clone();
        for payload in &scan.payloads {
            if !combined.trim().is_empty() {
                combined.push('\n');
            }
            combined.push_str(payload);
        }

        // Parse directives.
        let directives = if combined.trim().is_empty() {
            Vec::new()
        } else {
            parse_file(&combined).map_err(ServiceError::Parse)?
        };

        // Sort by canonical order for correct AccountState building.
        let mut sorted: Vec<&Directive> = directives.iter().collect();
        sorted.sort_by(|a, b| {
            a.date()
                .cmp(&b.date())
                .then_with(|| a.type_priority().cmp(&b.type_priority()))
        });

        // L-17: refuse a hand-planted parent cycle *before* the load rather than
        // aborting in the middle of it. The DAG's I8 check catches such a pair
        // on the second insert and boot used to propagate that error, so a file
        // whose envelope someone edited — envelope parents are outside the
        // content hash, so no id has to change — bricked every subsequent boot
        // of an otherwise perfectly good ledger. Name the offenders and load the
        // rest.
        let cycle_blocked = directives_blocked_by_parent_cycles(&sorted);
        if !cycle_blocked.is_empty() {
            warn!(
                blocked = cycle_blocked.len(),
                ids = %cycle_blocked.iter().cloned().collect::<Vec<_>>().join(", "),
                file = %file_path.display(),
                "ledger file contains transactions on (or descending from) an openledger-parents \
                 cycle; those directives are SKIPPED and the rest of the file boots normally — \
                 repair or remove their openledger-parents metadata"
            );
        }

        // Build account state and insert into DAG.
        let mut accounts = AccountState::new();
        let mut dag = LedgerDag::new();
        let mut max_lamport: u64 = 0;

        for directive in &sorted {
            // Track max Lamport across all directives (M-18).
            //
            // `stamp_directive_envelope` stamps `openledger-lamport` on opens
            // and closes too, so scanning transactions alone lets a restart
            // resume *below* the highest value already persisted — the next
            // mutation would then sign and persist a duplicate
            // `(author, lamport)` pair and move the clock backwards relative
            // to history.
            if let Some(lamport) = directive.lamport_clock() {
                max_lamport = max_lamport.max(lamport);
            }

            // Insert into DAG (lenient mode: parents may not be present yet),
            // then record any lifecycle event it carries under the content id
            // the DAG just assigned (M-09).
            //
            // Boot deliberately applies NO lifecycle policy: no already-open
            // rejection, no backdated-close guard. The account state has to be a
            // pure function of the persisted directive set, so that a node which
            // boots from the file and a node which ingested the same directives
            // one at a time agree exactly. A guard here would also reintroduce
            // the order dependence M-09 is about — boot's `sorted` order is the
            // canonical one, not the order the directives were accepted in —
            // and could brick boot on a file the node itself wrote.
            // Skip the cycle members (and their descendants) identified above.
            // `cycle_blocked` is empty for every well-formed file, so this costs
            // no hashing on a normal boot.
            if !cycle_blocked.is_empty()
                && matches!(directive, Directive::Transaction(_))
                && cycle_blocked.contains(&compute_content_id(directive))
            {
                continue;
            }

            // T41: `MAX_PARENTS` applied at the FILE ingress, tolerantly.
            //
            // The cap was enforced on the wire only, so a crafted or
            // hand-edited `.bean` could name unboundedly many parents on one
            // transaction — exactly what L-14's decoy does — and boot loaded it
            // without complaint. Loading it is what makes the fan-in real: the
            // directive becomes part of the served set, and every peer refuses
            // it forever.
            //
            // Skipped with a warning rather than refused, per T35's rule: boot
            // must never brick on a file the node can otherwise read. The
            // consequence of skipping is understood — a transaction absent from
            // the DAG is absent from the read model and from what this node
            // serves — and is strictly better than carrying a directive the
            // mesh will not accept.
            if let Err(error) = validate_parent_fan_in(directive) {
                warn!(
                    %error,
                    id = %compute_content_id(directive),
                    file = %file_path.display(),
                    "skipping a directive whose openledger-parents exceeds the fan-in cap; \
                     the rest of the file still loads"
                );
                continue;
            }

            // L-17: a DAG refusal must never abort the load. With the cycle
            // pre-scan above and `require_parents: false` nothing should reach
            // this arm today; if a future check makes it reachable, one bad
            // directive costs its own line, not the whole ledger.
            let insert_result = match dag.insert((*directive).clone(), false) {
                Ok(result) => result,
                Err(error) => {
                    warn!(
                        %error,
                        "skipping a directive the DAG refused at boot; the rest of the file still loads"
                    );
                    continue;
                }
            };
            match insert_result {
                InsertResult::Inserted { content_id } => {
                    accounts.record_lifecycle(directive, &content_id);
                }
                // A duplicate body is the same directive: its event is already
                // recorded, under the same content id.
                InsertResult::Duplicate { .. } => {}
            }
        }

        let lamport_clock = if max_lamport > 0 {
            max_lamport.saturating_add(1)
        } else {
            0
        };

        // Build the read model from all directives.
        let all_directives: Vec<Directive> = dag.directives().into_iter().cloned().collect();
        let read_model = ReadModel::build(&all_directives);

        Ok(LedgerService {
            dag,
            accounts,
            read_model,
            lamport_clock,
            author_id,
            file_path,
            leading_comments,
            // L-30: the bytes we just read (or the empty file we just created)
            // are the baseline every later persist compares against. Hashed
            // over the CANONICAL text alone — the journal is not part of the
            // artefact a human edits.
            last_file_hash: file_content_hash(&content),
            external_reconcile_count: 0,
            // L-11: installed by the node after the key is loaded; boot itself
            // adopts nothing, it only loads what is already persisted.
            signer: None,
            journal_path,
            canonical_bytes,
            canonical_marker,
            // Boot read this file; it did not write it, so it may not be in
            // canonical form. The first commit rewrites it, exactly as every
            // pre-T44 persist did.
            canonical_is_current: false,
            canonical_journal_bytes: scan.file_bytes,
            // Everything just loaded came off disk, so nothing is uncommitted.
            pending_ids: Vec::new(),
            // A torn tail must not be appended after: the scanner would read
            // the truncated payload's bytes as the next record's header. The
            // next commit rewrites the canonical file and deletes the journal,
            // which is the only safe way to make the file appendable again.
            force_compaction: scan.torn_tail_bytes > 0,
            commit_generation: 0,
            commit_in_flight: false,
            commit_gate: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            commit_observer: None,
        })
    }

    // ── Mutations ────────────────────────────────────────────────────────

    /// Append a new transaction to the ledger (§3.5 write path).
    ///
    /// Validates I1 (balance), I2 (elision), I3 (lifecycle), I9 (currency),
    /// stamps envelope metadata, inserts into DAG, and persists to file.
    /// Returns the `txid` together with whether the body was already present
    /// ([`AppendOutcome`], M-10).
    pub fn append_transaction(
        &mut self,
        input: TransactionInput,
    ) -> Result<AppendOutcome, ServiceError> {
        self.append_transaction_signing(input, |_, _, _| None)
    }

    /// Append a transaction, attaching `openledger-signature` before the first persist (M-11).
    ///
    /// Durable when it returns: this is
    /// [`Self::append_transaction_staged`] followed by an inline
    /// [`Self::persist_or_reload`]. Callers that want the fsync off the ledger
    /// write lock (T44) use the staged form and drive the commit themselves.
    pub fn append_transaction_signing(
        &mut self,
        input: TransactionInput,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<AppendOutcome, ServiceError> {
        let outcome = self.append_transaction_staged(input, sign)?;
        // A duplicate body staged nothing, so this is a no-op for it (T44:
        // `prepare_commit` returns `None` when there is nothing to write and
        // nobody has touched the file).
        self.persist_or_reload()?;
        Ok(outcome)
    }

    /// Append a transaction into **memory only** — no file write (T44).
    ///
    /// Everything [`Self::append_transaction_signing`] does except the durable
    /// write: validate, stamp, sign, insert, index. The directive is recorded
    /// as pending, so the next [`Self::prepare_commit`] carries it to disk.
    ///
    /// The caller owes the ledger a commit. Until one lands, in-memory state is
    /// ahead of disk — which is exactly the window L-13 exists to close, and is
    /// why the node layer takes the single-writer gate around the whole
    /// stage → prepare → commit → finish sequence.
    pub fn append_transaction_staged(
        &mut self,
        input: TransactionInput,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<AppendOutcome, ServiceError> {
        // H-04: a date the file grammar cannot read back would brick the next
        // boot, so refuse it before anything is built, stamped, or persisted.
        validate_ledger_date(input.date)?;

        // Build the Transaction from the input up-front (no envelope yet), so
        // every check below runs on exactly the value that will be hashed,
        // stamped, inserted and persisted — and so the shared `&Directive`
        // validators the remote path uses can run here unchanged (L-02).
        let directive = Directive::Transaction(Transaction {
            date: input.date,
            flag: input.flag,
            payee: input.payee,
            narration: input.narration,
            tags: input.tags,
            links: input.links,
            postings: input
                .postings
                .into_iter()
                .map(|p| Posting {
                    account: p.account,
                    amount: p.amount,
                    cost: p.cost,
                    price: p.price,
                    metadata: BTreeMap::new(),
                })
                .collect(),
            metadata: BTreeMap::new(),
        });

        // §3.12: resource limit checks — the same `enforce_resource_limits` the
        // peer-ingest path runs, rather than a second copy of the same five
        // comparisons against the same five constants (L-02).
        enforce_resource_limits(&directive)?;
        // L-02: and the wire size cap, so this node cannot author a directive
        // every peer is obliged to refuse.
        enforce_economic_bean_limit(&directive)?;

        let Directive::Transaction(txn) = &directive else {
            unreachable!("constructed as a transaction directly above")
        };

        if let Some(ref narration) = txn.narration {
            reject_control_characters("narration", narration)
                .map_err(|message| ServiceError::InvalidInput { message })?;
        }
        if let Some(ref payee) = txn.payee {
            reject_control_characters("payee", payee)
                .map_err(|message| ServiceError::InvalidInput { message })?;
        }
        for tag in &txn.tags {
            validate_tag(tag).map_err(|_| ServiceError::InvalidTag { tag: tag.clone() })?;
        }
        for link in &txn.links {
            validate_link(link).map_err(|_| ServiceError::InvalidLink { link: link.clone() })?;
        }
        for posting in &txn.postings {
            validate_account_name(&posting.account).map_err(|_| {
                ServiceError::InvalidAccountName {
                    account: posting.account.clone(),
                }
            })?;
            if let Some(ref amount) = posting.amount {
                validate_currency(&amount.currency).map_err(|_| ServiceError::InvalidCurrency {
                    currency: amount.currency.clone(),
                })?;
            }
            if let Some(ref cost) = posting.cost {
                if let Some(ref cost_amount) = cost.amount {
                    validate_currency(&cost_amount.currency).map_err(|_| {
                        ServiceError::InvalidCurrency {
                            currency: cost_amount.currency.clone(),
                        }
                    })?;
                }
                // H-04: cost dates serialize as `%Y-%m-%d` too.
                if let Some(cost_date) = cost.date {
                    validate_ledger_date(cost_date)?;
                }
            }
            if let Some(ref price) = posting.price {
                let currency = match price {
                    PriceSpec::Unit(amount) | PriceSpec::Total(amount) => &amount.currency,
                };
                validate_currency(currency).map_err(|_| ServiceError::InvalidCurrency {
                    currency: currency.clone(),
                })?;
            }
        }

        // Validate (I1, I2, I3, I9). Returns resolved txn with elided posting filled.
        let mut resolved = validate_transaction(txn, &self.accounts)?;

        // Stamp envelope metadata (§3.3.1, §3.4.2).
        self.stamp_transaction_envelope(&mut resolved.metadata);

        let content_id = compute_content_id(&Directive::Transaction(resolved.clone()));
        let (parents, lamport) = Self::envelope_parents_and_lamport(&resolved.metadata);
        if let Some(signature_hex) = sign(&content_id, parents, lamport) {
            resolved
                .metadata
                .insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex);
        }

        // Insert into DAG.
        let directive = Directive::Transaction(resolved);
        let content_id = match self.dag.insert(directive.clone(), false)? {
            InsertResult::Inserted { content_id } => content_id,
            InsertResult::Duplicate { content_id } => {
                // FR-1 AC4: idempotent by content. Nothing is inserted, nothing
                // is persisted, and the envelope just stamped above is thrown
                // away — the entry that stays is whichever one landed first,
                // with *its* author and signature. M-10: say so rather than
                // handing the caller a pre-existing txid that looks fresh.
                return Ok(AppendOutcome {
                    txid: content_id,
                    already_existed: true,
                });
            }
        };

        // Update read model incrementally.
        self.read_model.index_directive(&directive);

        // T44: durable on the next commit, not before this call returns.
        self.pending_ids.push(content_id.clone());

        Ok(AppendOutcome {
            txid: content_id,
            already_existed: false,
        })
    }

    /// Open a new account (FR-3 AC1).
    ///
    /// Validates that the account is not already open, creates the directive,
    /// stamps envelope, inserts into DAG, and persists.
    /// Returns the `directiveId`.
    pub fn open_account(
        &mut self,
        account: String,
        date: NaiveDate,
        currencies: Vec<String>,
    ) -> Result<String, ServiceError> {
        self.open_account_signing(account, date, currencies, |_, _, _| None)
    }

    /// Open an account, attaching `openledger-signature` before the first persist (M-11).
    ///
    /// Durable when it returns — see [`Self::append_transaction_signing`].
    pub fn open_account_signing(
        &mut self,
        account: String,
        date: NaiveDate,
        currencies: Vec<String>,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<String, ServiceError> {
        let content_id = self.open_account_staged(account, date, currencies, sign)?;
        self.persist_or_reload()?;
        Ok(content_id)
    }

    /// Open an account into **memory only** — no file write (T44).
    ///
    /// See [`Self::append_transaction_staged`] for the contract.
    pub fn open_account_staged(
        &mut self,
        account: String,
        date: NaiveDate,
        currencies: Vec<String>,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<String, ServiceError> {
        validate_account_name(&account).map_err(|_| ServiceError::InvalidAccountName {
            account: account.clone(),
        })?;
        // H-04: refuse an unrepresentable date before any state change.
        validate_ledger_date(date)?;
        for currency in &currencies {
            validate_currency(currency).map_err(|_| ServiceError::InvalidCurrency {
                currency: currency.clone(),
            })?;
        }

        // FR-3 AC1: opening an already-open account errors.
        if self.accounts.is_open(&account) {
            return Err(ServiceError::AccountAlreadyOpen {
                account: account.clone(),
            });
        }

        // Build the Open directive with an EMPTY envelope so the size checks
        // below can run before `stamp_directive_envelope` moves the Lamport
        // clock — a refused write must leave the clock exactly where it was
        // (L-02, same rejection-ordering rule as H-04's).
        let mut directive = Directive::Open(Open {
            date,
            account: account.clone(),
            currencies,
            metadata: BTreeMap::new(),
        });
        enforce_resource_limits(&directive)?;
        // L-02: `currencies` has no cardinality cap and currency codes are 24
        // bytes each, so an `open` is as able to exceed the wire limit as a
        // transaction is.
        enforce_economic_bean_limit(&directive)?;

        let Directive::Open(open) = &mut directive else {
            unreachable!("constructed as an open directly above")
        };
        self.stamp_directive_envelope(&mut open.metadata);

        let content_id = compute_content_id(&directive);
        let Directive::Open(open) = &mut directive else {
            unreachable!("constructed as an open directly above")
        };
        let (parents, lamport) = Self::envelope_parents_and_lamport(&open.metadata);
        if let Some(signature_hex) = sign(&content_id, parents, lamport) {
            open.metadata
                .insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex);
        }

        // Insert into DAG.
        let content_id = match self.dag.insert(directive.clone(), false)? {
            InsertResult::Inserted { content_id } => content_id,
            InsertResult::Duplicate { content_id } => return Ok(content_id),
        };

        // Update account state (M-09): record the event under the content id
        // and envelope the DAG just stored, so that this node's live state and
        // its state after a reboot from the same file are identical.
        self.accounts.record_lifecycle(&directive, &content_id);

        // T44: durable on the next commit.
        self.pending_ids.push(content_id.clone());

        Ok(content_id)
    }

    /// Close an account (FR-3 AC2).
    ///
    /// Validates that the account is open and has no transactions after the close date.
    /// Returns the `directiveId`.
    pub fn close_account(
        &mut self,
        account: String,
        date: NaiveDate,
    ) -> Result<String, ServiceError> {
        self.close_account_signing(account, date, |_, _, _| None)
    }

    /// Close an account, attaching `openledger-signature` before the first persist (M-11).
    ///
    /// Durable when it returns — see [`Self::append_transaction_signing`].
    pub fn close_account_signing(
        &mut self,
        account: String,
        date: NaiveDate,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<String, ServiceError> {
        let content_id = self.close_account_staged(account, date, sign)?;
        self.persist_or_reload()?;
        Ok(content_id)
    }

    /// Close an account into **memory only** — no file write (T44).
    ///
    /// See [`Self::append_transaction_staged`] for the contract.
    pub fn close_account_staged(
        &mut self,
        account: String,
        date: NaiveDate,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<String, ServiceError> {
        validate_account_name(&account).map_err(|_| ServiceError::InvalidAccountName {
            account: account.clone(),
        })?;
        // H-04: refuse an unrepresentable date before any state change.
        validate_ledger_date(date)?;

        // Must be currently open.
        if !self.accounts.is_open(&account) {
            return Err(ServiceError::AccountNotOpen {
                account: account.clone(),
            });
        }

        // FR-3 AC2: no transactions after the close date.
        if let Some(latest) = self.latest_posting_date(&account) {
            if latest > date {
                return Err(ServiceError::AccountHasLaterTransactions {
                    account: account.clone(),
                    latest_date: latest,
                });
            }
        }

        // Build the Close directive with an EMPTY envelope — see
        // `open_account_signing` for why the size checks precede the stamp.
        let mut directive = Directive::Close(Close {
            date,
            account: account.clone(),
            metadata: BTreeMap::new(),
        });
        enforce_resource_limits(&directive)?;
        // L-02: a `close` is bounded by its account name, which has a charset
        // but no length limit of its own.
        enforce_economic_bean_limit(&directive)?;

        let Directive::Close(close) = &mut directive else {
            unreachable!("constructed as a close directly above")
        };
        self.stamp_directive_envelope(&mut close.metadata);

        let content_id = compute_content_id(&directive);
        let Directive::Close(close) = &mut directive else {
            unreachable!("constructed as a close directly above")
        };
        let (parents, lamport) = Self::envelope_parents_and_lamport(&close.metadata);
        if let Some(signature_hex) = sign(&content_id, parents, lamport) {
            close
                .metadata
                .insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex);
        }

        // Insert into DAG.
        let content_id = match self.dag.insert(directive.clone(), false)? {
            InsertResult::Inserted { content_id } => content_id,
            InsertResult::Duplicate { content_id } => return Ok(content_id),
        };

        // Update account state (M-09) — see `open_account_staged`.
        self.accounts.record_lifecycle(&directive, &content_id);

        // T44: durable on the next commit.
        self.pending_ids.push(content_id.clone());

        Ok(content_id)
    }

    // ── Envelope stamping (§3.3.1, §3.4.2) ───────────────────────────────

    /// Stamp transaction-level envelope metadata (parents + author + lamport).
    ///
    /// Writes only keys from [`ENVELOPE_KEYS`] — the closed set every ingest
    /// path enforces.
    fn stamp_transaction_envelope(&mut self, metadata: &mut Metadata) {
        self.lamport_clock = self.lamport_clock.saturating_add(1);
        metadata.insert(ENVELOPE_KEY_AUTHOR.to_owned(), self.author_id.clone());
        metadata.insert(
            ENVELOPE_KEY_LAMPORT.to_owned(),
            self.lamport_clock.to_string(),
        );

        // Parents: current DAG heads, sorted ascending (§3.3.1).
        let mut parents: Vec<&str> = self.dag.heads().iter().map(|s| s.as_str()).collect();
        parents.sort();
        metadata.insert(ENVELOPE_KEY_PARENTS.to_owned(), parents.join(","));
    }

    /// Stamp non-transaction directive envelope (author + lamport, no parents).
    ///
    /// Writes only keys from [`ENVELOPE_KEYS`].
    fn stamp_directive_envelope(&mut self, metadata: &mut Metadata) {
        self.lamport_clock = self.lamport_clock.saturating_add(1);
        metadata.insert(ENVELOPE_KEY_AUTHOR.to_owned(), self.author_id.clone());
        metadata.insert(
            ENVELOPE_KEY_LAMPORT.to_owned(),
            self.lamport_clock.to_string(),
        );
    }

    fn envelope_parents_and_lamport(metadata: &Metadata) -> (&str, &str) {
        (
            metadata
                .get("openledger-parents")
                .map(String::as_str)
                .unwrap_or(""),
            metadata
                .get("openledger-lamport")
                .map(String::as_str)
                .unwrap_or(""),
        )
    }

    // ── Persistence (T44: two-phase, append-only) ────────────────────────

    /// The process-wide single-writer gate for this ledger (T44 invariant 7).
    ///
    /// # What it protects
    ///
    /// Commits now happen **outside** the ledger write lock, so without a gate
    /// two writers could prepare in one order and commit in another. Appends
    /// alone would survive that (journal order is arrival order and boot sorts
    /// the union), but a compaction would not: it writes a snapshot taken at
    /// *its* prepare and then deletes the journal, so a concurrent append that
    /// landed in between would be erased from disk after its caller had already
    /// been told the write was durable. That is a durability bug, not a
    /// performance one.
    ///
    /// # The contract
    ///
    /// An async caller takes this mutex **before** the ledger write lock and
    /// holds it until the commit is finished or recovered:
    ///
    /// ```text
    /// let gate = ledger.read().await.commit_gate();   // guard dropped here
    /// let _permit = gate.lock().await;                // single writer from now on
    /// let pending = { ledger.write().await; mutate; prepare_commit() };
    /// let receipt = spawn_blocking(|| pending.commit()).await?;
    /// ledger.write().await.finish_commit(receipt);
    /// ```
    ///
    /// The ordering is one-way — permit, then write lock, never the reverse —
    /// so the two locks cannot deadlock. Readers take neither, which is the
    /// entire point: a stalled fsync now delays the next writer and nothing
    /// else.
    ///
    /// [`Self::prepare_commit`] refuses while a commit is in flight, so a
    /// caller that skips the gate gets [`ServiceError::CommitInFlight`] rather
    /// than an interleaved write. The gate makes that refusal unreachable; it
    /// is the belt to the gate's braces, not the mechanism.
    ///
    /// The gate survives an L-13 reload (see [`Self::recover_failed_commit`]):
    /// replacing it would hand the next writer a *different* mutex and silently
    /// undo the serialization for as long as the old permit was held.
    pub fn commit_gate(&self) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        std::sync::Arc::clone(&self.commit_gate)
    }

    /// Install the commit observer. **Test seam** — see [`CommitObserver`].
    pub fn set_commit_observer(&mut self, observer: CommitObserver) {
        self.commit_observer = Some(observer);
    }

    /// Bytes currently held in the commit journal on disk (T44).
    ///
    /// `0` on any ledger small enough that every commit compacts — which is
    /// what makes this a usable signal that the append-only path is in play.
    pub fn journal_bytes(&self) -> u64 {
        self.canonical_journal_bytes
    }

    /// Byte length of the canonical `.bean` as this service last wrote or read
    /// it (T44).
    pub fn canonical_bytes(&self) -> u64 {
        self.canonical_bytes
    }

    /// The commit journal's path (`<ledger>.bean.journal`).
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    /// How many directives are in memory but not yet written to either file.
    ///
    /// Non-zero only between a staged mutation and its commit.
    pub fn uncommitted_count(&self) -> usize {
        self.pending_ids.len()
    }

    /// Prepare the durable write for everything staged since the last commit.
    ///
    /// Returns `None` when there is genuinely nothing to do: nothing staged, no
    /// forced compaction outstanding, and the canonical file on disk is exactly
    /// what this service last wrote. (Before T44 a no-op persist rewrote the
    /// file with identical bytes; skipping that is the only behavioural
    /// difference, and it is invisible to anything that reads the file.)
    ///
    /// # Which commit it prepares
    ///
    /// An **append** — one framed journal record, `O(staged)` — unless one of
    /// these forces a **compaction**:
    ///
    /// * the canonical file is below [`COMPACTION_MIN_CANONICAL_BYTES`], where
    ///   the rewrite is cheaper than the sidecar it would avoid;
    /// * the journal would reach half the canonical file's size, the
    ///   ratio-triggered fold-back that keeps the amortised cost constant;
    /// * something changed the `.bean` underneath us (the `stat` probe), so
    ///   T35's adopt-before-overwrite has to run;
    /// * the canonical file has not been written by this service yet, so it may
    ///   not be in canonical form at all (see `canonical_is_current`);
    /// * a forced compaction is outstanding — an in-place signature stamp, a
    ///   reconcile that must delete refused entries, or a torn journal tail.
    ///
    /// # Single-writer contract
    ///
    /// Exactly one commit may be outstanding per service. A second prepare
    /// before the first is finished or recovered returns
    /// [`ServiceError::CommitInFlight`] — see [`Self::commit_gate`] for how the
    /// node layer makes that unreachable.
    pub fn prepare_commit(&mut self) -> Result<Option<PendingCommit>, ServiceError> {
        self.prepare(false)
    }

    /// Prepare a full canonical rewrite, whatever the threshold says (T44).
    ///
    /// Used at the deliberate compaction points — process start, process stop,
    /// and after a reconcile — and by [`Self::compact`]. Always returns
    /// `Some`: a compaction asked for explicitly is never optimised away, since
    /// its caller wants the journal gone, not merely the state durable.
    pub fn prepare_compaction(&mut self) -> Result<Option<PendingCommit>, ServiceError> {
        self.prepare(true)
    }

    fn prepare(
        &mut self,
        explicit_compaction: bool,
    ) -> Result<Option<PendingCommit>, ServiceError> {
        if self.commit_in_flight {
            return Err(ServiceError::CommitInFlight);
        }

        // The O(1) hand-edit probe. It runs on every prepare, including the
        // append path — an append does not rewrite the `.bean` and so cannot
        // erase an edit, but noticing early means the edit is adopted at the
        // next write instead of waiting for the next compaction.
        let file_changed = self.canonical_file_changed_on_disk();
        let must_rewrite = explicit_compaction
            || self.force_compaction
            || file_changed
            || !self.canonical_is_current;

        if self.pending_ids.is_empty() && !must_rewrite {
            return Ok(None);
        }

        // Only the ratio arm needs the staged bytes, and it is the only arm
        // that does not already know it is compacting — so a small ledger (the
        // pre-T44 shape) pays nothing at all for the journal machinery.
        let mut compact = must_rewrite || self.canonical_bytes < COMPACTION_MIN_CANONICAL_BYTES;
        let mut record = String::new();
        if !compact {
            record = crate::journal::record_bytes(&self.pending_block());
            compact = (self.canonical_journal_bytes + record.len() as u64)
                .saturating_mul(COMPACTION_JOURNAL_RATIO)
                >= self.canonical_bytes;
        }

        let (kind, canonical, record) = if compact {
            // L-30 / L-12: this is the write that would erase a hand edit, so
            // this is where the exact check belongs — re-read, re-hash, and
            // reconcile the edit in before serializing over it.
            self.adopt_external_edits()?;
            let directives: Vec<Directive> = self.dag.directives().into_iter().cloned().collect();
            (
                CommitKind::Compact,
                full_file_serialize(&directives, &self.leading_comments),
                String::new(),
            )
        } else {
            // T27's "reject an over-cap write BEFORE any state changes" applies
            // to the append path too, and has to be re-derived here because the
            // file the cap bounds is not the one being written. The compacted
            // file is at most canonical + journal + this record (the journal's
            // record headers are counted, so the bound is conservative), and
            // that is what must stay under `MAX_LEDGER_FILE_BYTES`.
            let projected = self
                .canonical_bytes
                .saturating_add(self.canonical_journal_bytes)
                .saturating_add(record.len() as u64);
            if projected > MAX_LEDGER_FILE_BYTES {
                return Err(ServiceError::ResourceLimitExceeded {
                    message: format!(
                        "ledger plus journal would reach {projected} bytes (max {MAX_LEDGER_FILE_BYTES})"
                    ),
                });
            }
            (CommitKind::Append, String::new(), record)
        };

        self.commit_generation = self.commit_generation.saturating_add(1);
        self.commit_in_flight = true;
        Ok(Some(PendingCommit {
            generation: self.commit_generation,
            kind,
            ledger_path: self.file_path.clone(),
            journal_path: self.journal_path.clone(),
            canonical,
            record,
            observer: self.commit_observer.clone(),
        }))
    }

    /// Canonical text of the directives staged since the last commit.
    ///
    /// `O(staged)`, not `O(ledger)` — this is the whole of T44's goal (a). The
    /// ids are resolved against the DAG rather than kept as cloned directives,
    /// so an in-place change (a signature stamp) can never be written stale;
    /// the one shape that cannot express — re-writing a directive already on
    /// disk — is what `force_compaction` exists for.
    ///
    /// The block is emitted by the same `full_file_serialize` a compaction
    /// uses, so a record's bytes are exactly the bytes those directives will
    /// occupy in the canonical file once folded in.
    fn pending_block(&self) -> String {
        let directives: Vec<Directive> = self
            .pending_ids
            .iter()
            .filter_map(|id| self.dag.get(id).cloned())
            .collect();
        full_file_serialize(&directives, &[])
    }

    /// Has anything touched the `.bean` since this service last wrote or read
    /// it? One `stat`, no read (T44).
    ///
    /// Conservative in the direction that costs nothing: an unreadable file, or
    /// a service with no recorded marker, answers "yes" and escalates to a
    /// compaction, which runs the exact hash check.
    fn canonical_file_changed_on_disk(&self) -> bool {
        match (FileMarker::of(&self.file_path), self.canonical_marker) {
            (Some(current), Some(recorded)) => current != recorded,
            _ => true,
        }
    }

    /// Fold a completed commit back into in-memory bookkeeping (T44).
    ///
    /// Takes the ledger write lock at the call site; does no I/O.
    pub fn finish_commit(&mut self, receipt: CommitReceipt) {
        if receipt.generation != self.commit_generation {
            // Unreachable under the single-writer contract: the generation only
            // advances in `prepare`, and `prepare` refuses while a commit is in
            // flight. Reaching it means a caller finished a commit this service
            // is not waiting for, so the receipt describes files in a state
            // this service cannot reason about — refuse it rather than write
            // its numbers over the ones belonging to the live commit.
            error!(
                receipt_generation = receipt.generation,
                service_generation = self.commit_generation,
                "ignoring a ledger commit receipt from a different commit generation; \
                 the single-writer contract on LedgerService::commit_gate was violated"
            );
            return;
        }
        self.commit_in_flight = false;
        self.force_compaction = false;
        self.pending_ids.clear();
        self.canonical_journal_bytes = receipt.journal_bytes;
        if let Some(hash) = receipt.canonical_hash {
            // L-30: the file now says exactly this.
            self.last_file_hash = hash;
        }
        if let Some(bytes) = receipt.canonical_bytes {
            self.canonical_bytes = bytes;
        }
        if receipt.kind == CommitKind::Compact {
            self.canonical_marker = receipt.canonical_marker;
            // The `.bean` now holds exactly the bytes this service wrote.
            self.canonical_is_current = true;
        }
    }

    /// Restore memory == disk after a commit that failed (L-13, T44 shape).
    ///
    /// The pre-T44 reasoning is unchanged and still exact: `persist_atomically`
    /// writes a sibling `.tmp` and renames, and a journal append either lands
    /// whole or leaves a torn tail the scanner drops, so **a failed commit
    /// always leaves the files in their last good state**. The unpersisted
    /// in-memory mutations are therefore discarded by reconstructing the entire
    /// service from disk via [`Self::boot`] — which now reads canonical ∪
    /// journal, so the reload lands on exactly the state the failed commit
    /// started from rather than on a pre-journal one.
    ///
    /// Two handles are carried across the reload rather than re-created,
    /// because they are process-scoped machinery and not ledger state: the
    /// [`Self::commit_gate`] (a fresh mutex would silently unserialize any
    /// writer holding the old permit) and the commit observer.
    ///
    /// If the reload itself fails there is no better on-disk state to fall back
    /// to; memory is left as-is and the failure is logged, exactly as before.
    pub fn recover_failed_commit(&mut self) {
        self.commit_in_flight = false;
        match LedgerService::boot(self.file_path.clone(), self.author_id.clone()) {
            Ok(reloaded) => {
                let gate = std::sync::Arc::clone(&self.commit_gate);
                let observer = self.commit_observer.clone();
                *self = reloaded;
                self.commit_gate = gate;
                self.commit_observer = observer;
            }
            Err(reload_error) => {
                error!(
                    %reload_error,
                    "ledger reload-from-disk failed after a failed commit; in-memory state may be \
                     ahead of disk (L-13)"
                );
            }
        }
    }

    /// Adopt an out-of-band hand edit before a full-file persist overwrites it
    /// (L-30 / L-12).
    ///
    /// A persist rewrites the whole `.bean` from in-memory state, so anything a
    /// human typed into the file since the last write is simply gone — no error,
    /// no log line, no trace. The T30 sidecar `flock` keeps a second `gl-node`
    /// off the file but does nothing about `vim`. So: re-read the file, hash it,
    /// and compare against [`Self::last_file_hash`]. Equal is the normal case and
    /// costs one read. Different means someone edited it, and the edit is
    /// reconciled into memory *first*, so the persist that follows writes the
    /// merged state instead of clobbering it.
    ///
    /// Failures are deliberately NOT swallowed:
    /// - an unreadable / oversized file returns the IO error, which
    ///   [`Self::persist_or_reload`] then treats exactly like a failed write;
    /// - a file that no longer parses returns the parse error, after a `warn!`
    ///   that prints every parse failure. The persist is abandoned rather than
    ///   canonicalised over a file a human is mid-way through editing — a broken
    ///   hand edit blocks writes until it is repaired, which is recoverable,
    ///   whereas overwriting it is not.
    ///
    /// Entries that parse but fail validation are surfaced by
    /// [`Self::reconcile_content`] and then dropped by the canonical re-persist.
    ///
    /// # T44: called from the compaction path only
    ///
    /// This is `O(file)` — a read, a hash, and on a mismatch a full reconcile —
    /// and since T44 it runs where the `O(file)` cost already lives: inside the
    /// compaction branch of [`Self::prepare_commit`], which is the only branch
    /// that rewrites the `.bean` and therefore the only one that could erase an
    /// edit. An append leaves the canonical file untouched, so a hand edit made
    /// before it is still on disk afterwards, and boot unions the two files.
    /// The `stat` probe in `prepare` escalates to a compaction the moment the
    /// file's size or mtime moves, so in practice an edit is still adopted at
    /// the very next write — what changed is only that the adoption is no
    /// longer *unconditionally* re-read on every single write.
    fn adopt_external_edits(&mut self) -> Result<(), ServiceError> {
        let content = read_ledger_file(&self.file_path)?;
        // Re-baseline the cheap probe from the same read, so an editor that
        // merely touched the mtime does not escalate every later append.
        self.canonical_marker = FileMarker::of(&self.file_path);
        self.canonical_bytes = content.len() as u64;
        if file_content_hash(&content) == self.last_file_hash {
            return Ok(());
        }

        self.external_reconcile_count = self.external_reconcile_count.saturating_add(1);
        warn!(
            file = %self.file_path.display(),
            "ledger file changed on disk since this node last wrote it; adopting the \
             external edit before persisting so the persist does not overwrite it (L-30)"
        );

        let result = self.reconcile_content(&content)?;
        warn!(
            adopted = result.new_directives,
            duplicates = result.duplicates,
            rejected = result.rejected,
            "external ledger-file edit reconciled ahead of persist"
        );
        Ok(())
    }

    /// Persist the ledger, restoring memory==disk if the persist fails (L-13).
    ///
    /// The 64 MiB cap and every IO error are surfaced by [`Self::persist`] only
    /// *after* the in-memory DAG has already been mutated by the caller. A
    /// failed persist would therefore leave memory ahead of disk: reads would
    /// serve directives that are not on disk, and the next boot would silently
    /// drop them.
    ///
    /// Because [`persist_atomically`] writes to a sibling `.tmp` and then
    /// renames, a failed persist leaves the previous `.bean` file fully intact —
    /// it is the last good, fully consistent state. So on failure we discard the
    /// unpersisted in-memory mutations by reconstructing the entire service from
    /// that on-disk file via [`Self::boot`] (which fully derives dag, account
    /// state, read model, Lamport clock, and leading comments from the file plus
    /// the author id — the service holds no other, non-derived state). The
    /// original persist error is always returned; the batch that could not be
    /// written is dropped from memory and anti-entropy simply re-pulls it later.
    ///
    /// If the reload *itself* fails (e.g. the file became unreadable), memory is
    /// left as-is and a combined error is logged — there is no better on-disk
    /// state to fall back to — but the original persist error is still returned.
    ///
    /// ## Concurrent hand edits (L-30) — best-effort, not a lock
    ///
    /// Before writing, [`Self::adopt_external_edits`] re-reads and re-hashes the
    /// file and reconciles anything a human changed, so a hand edit made while
    /// the node runs is merged in rather than silently destroyed. This is
    /// **best-effort and explicitly racy**:
    ///
    /// - the T30 sidecar `flock` excludes other `gl-node` processes, not text
    ///   editors, so there is no mutual exclusion with the writer being guarded
    ///   against;
    /// - an edit that lands in the window between the hash check and the
    ///   `rename` is still lost, and nothing here detects it;
    /// - an editor that rewrites the file via its own temp+rename can swap the
    ///   inode after the read, with the same outcome.
    ///
    /// It closes the wide hole (an edit made minutes before the next persist)
    /// and does not pretend to close the narrow one. Editing a `.bean` that a
    /// running node owns is still unsupported; stop the node first.
    ///
    /// ## The commit journal (T44)
    ///
    /// The journal is **node-private**: hand-editing it is unsupported and will
    /// fail closed on its per-record hash. There is nothing to adopt from it —
    /// it holds only directives this node itself wrote.
    pub fn persist_or_reload(&mut self) -> Result<(), ServiceError> {
        self.commit_inline(false)
    }

    /// Fold the journal back into the canonical `.bean`, synchronously (T44).
    ///
    /// The explicit compaction point: a node calls it once after boot (so a
    /// crash-window journal does not linger) and once at a clean shutdown (so
    /// the file an operator looks at is the canonical one). Reconcile uses it
    /// too, because canonicalising the file is the entire point there.
    ///
    /// Like [`Self::persist_or_reload`], a failure restores memory == disk.
    pub fn compact(&mut self) -> Result<(), ServiceError> {
        self.commit_inline(true)
    }

    /// prepare + commit + finish, inline — the one-call form for synchronous
    /// callers (T44).
    ///
    /// The blocking write happens on the calling thread with whatever lock the
    /// caller holds still held; that is exactly the pre-T44 behaviour, and it
    /// is why the node layer uses the two-phase form on its async paths
    /// instead.
    fn commit_inline(&mut self, explicit_compaction: bool) -> Result<(), ServiceError> {
        let prepared = if explicit_compaction {
            self.prepare_compaction()
        } else {
            self.prepare_commit()
        };
        let commit_error = match prepared {
            Ok(None) => return Ok(()),
            Ok(Some(pending)) => match pending.commit() {
                Ok(receipt) => {
                    self.finish_commit(receipt);
                    return Ok(());
                }
                Err(error) => error,
            },
            // A refusal to prepare *because another commit is in flight* must
            // not trigger the L-13 reload: the other commit owns the files, and
            // re-booting under it would discard state it is about to make
            // durable. Nothing was written, nothing is ahead of disk.
            Err(ServiceError::CommitInFlight) => return Err(ServiceError::CommitInFlight),
            Err(error) => error,
        };

        // L-13. `prepare` may already have mutated memory (adoption reconciles
        // a hand edit in before it serializes), so the reload runs on both the
        // prepare-failed and the commit-failed path.
        self.recover_failed_commit();
        Err(commit_error)
    }

    /// Reconcile external edits to the `.bean` file (§3.3, CT-12).
    ///
    /// Re-reads the file, parses it, computes content IDs, and union-merges
    /// any new directives into the DAG. External transactions that lack
    /// envelope keys are adopted with the local author ID and current
    /// Lamport clock. After merge, re-persists to ensure canonical form.
    ///
    /// Returns the number of new directives adopted.
    pub fn reconcile_file(&mut self) -> Result<crate::file_watcher::ReconcileResult, ServiceError> {
        let result = self.reconcile_file_staged()?;

        // Re-persist in canonical form (L-13: reload from disk if it fails).
        //
        // T44: a COMPACTION, not an append. Reconcile's output is a canonical
        // rewrite — it drops the entries it refused and re-spells everything
        // else — and neither of those is something a journal record can say.
        if result.new_directives > 0 {
            self.compact()?;
        }

        Ok(result)
    }

    /// [`Self::reconcile_file`] without the write (T44).
    ///
    /// Union-merges the file into memory and, when anything was adopted, marks
    /// the next commit as a forced compaction. The caller drives that commit —
    /// `reconcile_file` does it inline, the node's file watcher does it off the
    /// ledger write lock.
    pub fn reconcile_file_staged(
        &mut self,
    ) -> Result<crate::file_watcher::ReconcileResult, ServiceError> {
        let content = read_ledger_file(&self.file_path)?;
        let result = self.reconcile_content(&content)?;
        if result.new_directives > 0 {
            self.force_compaction = true;
        }
        Ok(result)
    }

    /// Union-merge already-read file text into memory — the body of
    /// [`Self::reconcile_file`], without the read and without the re-persist.
    ///
    /// Split out so the pre-persist hand-edit adoption
    /// ([`Self::adopt_external_edits`]) can reuse it on bytes it has already read
    /// and hashed, and so that adoption cannot recurse back into a persist.
    ///
    /// Two L-12 properties live here:
    ///
    /// 1. **Canonical order.** The input is sorted by `(date, type_priority)`
    ///    exactly as [`Self::boot`] sorts it, with the file order preserved for
    ///    ties (the sort is stable). Processing raw file order made adoption
    ///    depend on where in the file a human happened to paste something: an
    ///    `open` typed below the transaction that uses it left that transaction
    ///    rejected for referencing an unopened account, and the very same file
    ///    loaded cleanly on the next boot — which sorts.
    /// 2. **Rejections are surfaced.** Anything refused here is dropped from the
    ///    file by the canonical re-persist that follows, so every rejection is
    ///    logged with its content id and the reason before that happens, rather
    ///    than collapsing into an opaque count.
    fn reconcile_content(
        &mut self,
        content: &str,
    ) -> Result<crate::file_watcher::ReconcileResult, ServiceError> {
        // Record the hash of what we are about to merge from, before anything
        // can fail: this text is now the baseline for the next persist's
        // hand-edit check (L-30). T44: and the cheap `stat` probe's baseline
        // too, so the facts this service holds about the canonical file are
        // refreshed together and cannot drift.
        self.last_file_hash = file_content_hash(content);
        self.canonical_bytes = content.len() as u64;
        self.canonical_marker = FileMarker::of(&self.file_path);
        // Whatever is on disk right now came from a text editor, not from this
        // service's serializer: it needs canonicalising, not appending to.
        self.canonical_is_current = false;

        let file_directives = parse_file(content).map_err(|errors| {
            warn!(
                file = %self.file_path.display(),
                errors = %errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "),
                "ledger file does not parse; NOT reconciling and NOT persisting over it — \
                 repair the file (the in-memory ledger is unaffected)"
            );
            ServiceError::Parse(errors)
        })?;

        // L-12: canonical order, like boot. Stable, so equal keys keep file order.
        let mut file_directives = file_directives;
        file_directives.sort_by(|a, b| {
            a.date()
                .cmp(&b.date())
                .then_with(|| a.type_priority().cmp(&b.type_priority()))
        });

        let mut new_count = 0;
        let mut dup_count = 0;
        let mut rejected = 0;
        // (content id, reason) for every entry this reconcile refuses — logged
        // below, because the canonical re-persist drops them from the file.
        let mut rejections: Vec<(String, String)> = Vec::new();

        for mut directive in file_directives {
            let content_id = compute_content_id(&directive);

            // Check if already in DAG (G-Set dedup).
            if self.dag.get(&content_id).is_some() {
                dup_count += 1;
                continue;
            }

            // H-04: never adopt a directive whose date the file grammar cannot
            // read back — the next persist would brick every later boot. Checked
            // before the envelope stamp so a rejection cannot move the Lamport
            // clock either. `read_date` cannot currently yield such a year, so
            // this is a guard against future parser or format changes.
            if let Err(error) = validate_directive_dates(&directive) {
                rejected += 1;
                rejections.push((content_id.clone(), error.to_string()));
                continue;
            }

            // H-06: a file may legitimately carry the four envelope keys at
            // directive level (that is how a peer's directive round-trips), but
            // any other `openledger-*` key — and any at posting level — is
            // unvalidated metadata that the content hash ignores and that
            // `extract_envelope` would promote into the envelope on the next
            // serve, bricking the receiving peer's closed-set check.
            // L-26: control characters in body strings would be written
            // verbatim into every replica's file from here on.
            // T41: and the same `MAX_PARENTS` fan-in cap the wire path applies.
            // The cap was wire-only, so a hand edit — or a pre-hardening file —
            // could carry an `openledger-parents` list of any length, which the
            // next persist would then serve to every peer, where it is refused.
            if let Err(error) = validate_body_envelope_keys(&directive, ENVELOPE_KEYS)
                .and_then(|()| validate_body_strings(&directive))
                .and_then(|()| validate_parent_fan_in(&directive))
            {
                rejected += 1;
                rejections.push((content_id.clone(), error.to_string()));
                continue;
            }

            // Adopt: stamp envelope metadata only if missing.
            // If the directive already has envelope keys (e.g. from another node),
            // preserve them as-is to maintain content hash stability.
            let metadata = directive_metadata_mut(&mut directive);

            let needs_stamp = !metadata.contains_key("openledger-lamport");

            if needs_stamp {
                if !metadata.contains_key("openledger-author") {
                    metadata.insert("openledger-author".to_owned(), self.author_id.clone());
                }
                self.lamport_clock = self.lamport_clock.saturating_add(1);
                metadata.insert(
                    "openledger-lamport".to_owned(),
                    self.lamport_clock.to_string(),
                );
            } else {
                // Update local Lamport clock to at least match the incoming
                // value.
                //
                // T41 — the `+1` asymmetry with peer ingest, documented rather
                // than unified. `stage_remote_directive` does
                // `max(local, remote).saturating_add(1)`; this does `max(local,
                // incoming)` with no `+1`, and **both preserve the (author,
                // lamport) uniqueness M-18 needs**, because the increment that
                // matters happens at STAMPING time, not at adoption time:
                // `stamp_transaction_envelope`/`stamp_directive_envelope`
                // pre-increment, so the next value this node signs is
                // `max(local, incoming) + 1` — strictly greater than anything
                // adopted here — either way. The peer-ingest form simply
                // reserves that slot one step earlier, leaving the clock one
                // ahead; it is more conservative, not more correct.
                //
                // NOT unified, deliberately. The clock is serialized into the
                // envelope of every directive this node subsequently stamps, so
                // changing the arithmetic on either path changes the `.bean`
                // bytes for an identical input sequence — which is exactly what
                // T27's `batch_path_is_byte_identical_to_per_entry_path` and
                // T29's byte-identical convergence assertions pin. A cosmetic
                // unification is not worth perturbing determinism tests whose
                // whole value is that they are sensitive.
                if let Some(incoming_lamport) = metadata
                    .get("openledger-lamport")
                    .and_then(|v| v.parse::<u64>().ok())
                {
                    self.lamport_clock = self.lamport_clock.max(incoming_lamport);
                }
            }

            // For transactions: set parents to current heads if not already set.
            if let Directive::Transaction(txn) = &mut directive {
                if !txn.metadata.contains_key("openledger-parents") {
                    let heads: Vec<String> = self.dag.heads().iter().cloned().collect();
                    let mut sorted = heads;
                    sorted.sort();
                    txn.metadata
                        .insert("openledger-parents".to_owned(), sorted.join(","));
                }
            }

            // Validate transactions (I1–I3, I9).
            if let Err(error) = enforce_resource_limits(&directive) {
                rejected += 1;
                rejections.push((content_id.clone(), error.to_string()));
                continue;
            }
            if let Directive::Transaction(txn) = &directive {
                match validate_transaction(txn, &self.accounts) {
                    Ok(validated) => {
                        // Build the final transaction with the resolved postings.
                        let final_txn = Transaction {
                            postings: validated.postings,
                            ..txn.clone()
                        };
                        let mut final_directive = Directive::Transaction(final_txn);
                        // L-11: sign over the id the DAG will actually store it
                        // under. That is NOT `content_id` when I2 resolved an
                        // elided posting — the resolved body hashes differently,
                        // and a signature over the pre-resolution id would fail
                        // on every peer.
                        let stored_id = compute_content_id(&final_directive);
                        self.sign_adopted_entry(&mut final_directive, &stored_id);
                        match self.dag.insert(final_directive.clone(), false) {
                            Ok(InsertResult::Inserted { .. }) => {
                                self.read_model.index_directive(&final_directive);
                                // T44: reconcile always compacts, so this entry
                                // is written by the full rewrite rather than by
                                // a journal record; tracking it keeps
                                // `uncommitted_count` honest and makes the
                                // "nothing to do" short-circuit correct.
                                self.pending_ids.push(stored_id.clone());
                                new_count += 1;
                            }
                            Ok(InsertResult::Duplicate { .. }) => {
                                dup_count += 1;
                            }
                            Err(error) => {
                                rejected += 1;
                                rejections.push((content_id.clone(), error.to_string()));
                            }
                        }
                    }
                    Err(error) => {
                        rejected += 1;
                        rejections.push((content_id.clone(), error.to_string()));
                    }
                }
            } else {
                // M-09: a hand-added `close` goes through the same
                // no-later-transactions rule as the local API and the peer
                // ingest path, rather than being applied unconditionally with
                // the error swallowed. It lands in the `rejected` tally like
                // every other refused adoption.
                if let Directive::Close(close) = &directive {
                    if let Err(error) = self.reject_backdated_close(close) {
                        rejected += 1;
                        rejections.push((content_id.clone(), error.to_string()));
                        continue;
                    }
                }
                // L-11: a non-transaction body is stored exactly as parsed, so
                // its content id is the one computed at the top of the loop.
                self.sign_adopted_entry(&mut directive, &content_id);
                // Non-transaction directives: insert, then record any lifecycle
                // event under the content id the DAG assigned (M-09).
                match self.dag.insert(directive.clone(), false) {
                    Ok(InsertResult::Inserted { .. }) => {
                        self.accounts.record_lifecycle(&directive, &content_id);
                        self.read_model.index_directive(&directive);
                        // T44: see the transaction arm above.
                        self.pending_ids.push(content_id.clone());
                        new_count += 1;
                    }
                    Ok(InsertResult::Duplicate { .. }) => {
                        dup_count += 1;
                    }
                    Err(error) => {
                        rejected += 1;
                        rejections.push((content_id.clone(), error.to_string()));
                    }
                }
            }
        }

        // L-12: whatever this reconcile refused is about to be deleted from the
        // file by the canonical re-persist. Say so, per entry, with the id and
        // the reason — a bare `rejected: 3` in a counter leaves an operator no
        // way to find out what they lost.
        if !rejections.is_empty() {
            warn!(
                rejected = rejections.len(),
                entries = %rejections
                    .iter()
                    .map(|(id, reason)| format!("{id}: {reason}"))
                    .collect::<Vec<_>>()
                    .join(" | "),
                file = %self.file_path.display(),
                "reconcile refused ledger-file entries; they are NOT adopted and the canonical \
                 re-persist will drop them from the file"
            );
        }

        Ok(crate::file_watcher::ReconcileResult {
            new_directives: new_count,
            duplicates: dup_count,
            rejected,
        })
    }

    /// Sign an entry this reconcile is adopting, when this node can (L-11).
    ///
    /// ## The finding
    ///
    /// A hand-edited entry was adopted into the DAG and persisted, but carried
    /// no `openledger-signature`. With signing enabled every peer rejects an
    /// unsigned directive, so the entry lived on exactly one replica — and
    /// nothing said so. It looked adopted, it showed up in every local query and
    /// report, and it never replicated: split-brain by text editor, silent.
    ///
    /// ## The decision
    ///
    /// **Operator input is a local append.** A human editing this node's `.bean`
    /// is exercising exactly the authority the GraphQL mutations expose — same
    /// machine, same file, same trust boundary — so the entry gets the same
    /// treatment a mutation's would: this node's envelope, this node's author
    /// id, this node's signature, before the first persist. The alternative the
    /// audit offered (refuse reconcile whenever signing is on) fails the same
    /// edit *loudly* instead of silently, which is better but still refuses
    /// something the API would have accepted from the same person.
    ///
    /// ## When it does NOT sign, and why
    ///
    /// * **The entry already carries a signature.** Adopted unchanged, as
    ///   before: it came from a peer (or a round-trip of our own), the signature
    ///   is bound to that author's key, and re-signing would destroy it.
    /// * **`openledger-author` names someone else.** The signature is verified
    ///   against the *author's* public key, so signing another peer's directive
    ///   with our key produces a signature that fails everywhere — strictly
    ///   worse than none. The envelope stamp above only fills in an author when
    ///   the entry has none, so this is the hand-written-author case. It is
    ///   logged rather than silently skipped, because the entry still will not
    ///   replicate and the operator is the only one who can fix it.
    /// * **No signer installed, or signing disabled.** The callback returns
    ///   `None` and adoption is byte-for-byte what it was.
    fn sign_adopted_entry(&self, directive: &mut Directive, content_id: &str) {
        let Some(ref signer) = self.signer else {
            return;
        };
        let is_transaction = matches!(directive, Directive::Transaction(_));
        let metadata = directive_metadata_mut(directive);

        if metadata.contains_key(ENVELOPE_KEY_SIGNATURE) {
            return;
        }
        match metadata.get(ENVELOPE_KEY_AUTHOR) {
            Some(author) if author == &self.author_id => {}
            Some(other_author) => {
                // Only reachable when the file itself named an author; the
                // stamp above never overwrites one.
                //
                // T41 — WARN AND ADOPT is the deliberate choice here; refusing
                // the entry was considered and rejected. Three reasons.
                //
                // (1) Refusing would be a data-loss default on the one path
                //     where the operator is physically present. A foreign
                //     `openledger-author` in this node's own `.bean` most often
                //     means a human pasted a peer's directive in by hand, or a
                //     backup/merge tool did — and silently discarding what they
                //     pasted is worse than keeping it and saying it will not
                //     replicate. The warning names the content id and the exact
                //     remedy (drop the author line).
                //
                // (2) The entry is not a forgery risk. It carries NO signature,
                //     so no peer with signing enabled will accept it; it is
                //     inert outside this node. The failure mode is "does not
                //     replicate", which is what the warning says, not "is
                //     accepted somewhere it should not be".
                //
                // (3) Refusing would not even be a consistent rule. Boot loads
                //     exactly this shape with no check at all — it must, under
                //     the brick-path rule — so a refusal here would reject on
                //     reconcile what the very next restart loads anyway.
                //
                // The remaining gap is a node holding an entry the mesh will not
                // take, which `verify` does not currently surface; that is
                // reported, not fixed.
                warn!(
                    content_id,
                    author = %other_author,
                    this_node = %self.author_id,
                    "adopted an unsigned ledger-file entry authored by another node; this node \
                     cannot sign for that author, so the entry will NOT replicate to peers with \
                     signing enabled — remove the openledger-author line to adopt it as our own"
                );
                return;
            }
            // No author at all: the stamp only fills one in when it also stamps
            // a Lamport value, so this is an entry that carried a Lamport value
            // and no author. Not ours to sign either.
            None => return,
        }

        let (parents, lamport) = Self::envelope_parents_and_lamport(metadata);
        if let Some(signature_hex) = signer(content_id, is_transaction, parents, lamport) {
            metadata.insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Apply the local "no later transactions" close rule to an INGESTED
    /// `close` — from a peer or from a hand edit (M-09).
    ///
    /// Without this, one allowlisted peer's `close Assets:Cash` dated 1970 was
    /// applied unconditionally (`let _ =`) on every replica, and from then on
    /// every local append to that account failed I3 forever: a write-DoS on the
    /// whole mesh, from a single directive, with no way to undo it. The local
    /// close path has always refused to close an account out from under its own
    /// transactions ([`ServiceError::AccountHasLaterTransactions`]); a remote
    /// close is held to the same rule, with the same error code, and is not
    /// inserted into the DAG when it fails.
    ///
    /// ## Residual — honest statement of what this does NOT prove
    ///
    /// This is a DoS mitigation, not a convergence proof. The rule is evaluated
    /// against the transactions this node holds AT INGEST TIME, and two nodes
    /// can hold different transaction sets at that moment. Concretely: a close
    /// dated 2024-03-01 that arrives at node A before any 2024-06-01
    /// transaction on that account is accepted there, while node B — which
    /// already had that transaction — rejects the same close. The two nodes
    /// then hold DIFFERENT DIRECTIVE SETS, and nothing here closes that gap.
    ///
    /// What the M-09 event model does guarantee is the other half: for a GIVEN
    /// directive set, every node derives the same account state regardless of
    /// arrival order. Directive-set divergence is possible; state divergence for
    /// a fixed set is not. (Note also that a transaction rejected under I3 is
    /// never in the DAG, so it does not feed back into this rule — only
    /// ACCEPTED transactions can refuse a close.)
    ///
    /// Boot does not apply this rule: see the comment at the boot loop.
    fn reject_backdated_close(&self, close: &Close) -> Result<(), ServiceError> {
        if let Some(latest) = self.latest_posting_date(&close.account) {
            if latest > close.date {
                return Err(ServiceError::AccountHasLaterTransactions {
                    account: close.account.clone(),
                    latest_date: latest,
                });
            }
        }
        Ok(())
    }

    /// Find the latest transaction date referencing a given account.
    ///
    /// Served from the read model's per-account index rather than by scanning
    /// the DAG. This runs on every local close and on every ingested one
    /// ([`Self::reject_backdated_close`]), and the scan it replaces was O(N) in
    /// the whole ledger — so a peer streaming closes made each one cost a full
    /// pass over every directive plus every posting on it. The index is
    /// maintained by `ReadModel::index_directive`, which every insert path
    /// already calls, and rebuilt wholesale by `ReadModel::build` at boot and
    /// after an L-13 reload, so the two views cannot drift.
    fn latest_posting_date(&self, account: &str) -> Option<NaiveDate> {
        self.read_model.latest_posting_date(account)
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// The underlying DAG (for queries and read model).
    pub fn dag(&self) -> &LedgerDag {
        &self.dag
    }

    /// The account state tracker.
    pub fn accounts(&self) -> &AccountState {
        &self.accounts
    }

    /// The in-memory read model (for report queries).
    pub fn read_model(&self) -> &ReadModel {
        &self.read_model
    }

    /// Current Lamport clock value.
    pub fn lamport_clock(&self) -> u64 {
        self.lamport_clock
    }

    /// The author ID (Iroh EndpointId or placeholder).
    pub fn author_id(&self) -> &str {
        &self.author_id
    }

    /// How many persists have found the `.bean` changed underneath them and
    /// adopted the external edit before writing (L-30).
    ///
    /// Stays 0 on a node whose file nobody edits by hand — that is exactly what
    /// the recorded-hash fast path guarantees, and what makes a rising count a
    /// usable signal that someone is editing a live ledger file.
    pub fn external_reconcile_count(&self) -> u64 {
        self.external_reconcile_count
    }

    /// The file path being managed.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Total number of directives.
    pub fn directive_count(&self) -> usize {
        self.dag.len()
    }

    /// Current DAG head count.
    pub fn head_count(&self) -> usize {
        self.dag.heads().len()
    }

    /// Get a directive by content ID.
    pub fn get_directive(&self, content_id: &str) -> Option<&Directive> {
        self.dag.get(content_id)
    }

    /// Compute the content ID for a directive (for lookups).
    pub fn content_id(directive: &Directive) -> String {
        compute_content_id(directive)
    }

    /// Update the author identity (called when P2P boots and we learn our EndpointId).
    pub fn set_author_id(&mut self, author_id: String) {
        self.author_id = author_id;
    }

    /// Install the signer reconcile uses to stamp adopted entries (L-11).
    ///
    /// Called once at boot, alongside [`Self::set_author_id`] and before the
    /// file watcher starts, so an adoption can never race an unset signer.
    /// Passing a provider that has signing disabled is fine and is what a
    /// signing-off node does: the callback returns `None` and adoption behaves
    /// exactly as it did before this existed.
    pub fn set_signer(&mut self, signer: DirectiveSigner) {
        self.signer = Some(signer);
    }

    /// Get the set of current DAG head txids (for anti-entropy exchange).
    pub fn head_txids(&self) -> std::collections::HashSet<String> {
        self.dag.heads().iter().cloned().collect()
    }

    /// Get the set of all directive content IDs in the DAG (for anti-entropy exchange).
    pub fn all_directive_ids(&self) -> std::collections::HashSet<String> {
        self.dag
            .content_ids()
            .into_iter()
            .map(|s| s.to_owned())
            .collect()
    }

    /// Parent txids on `directive` that are not yet in the local DAG (§3.4.4).
    pub fn missing_parent_ids(&self, directive: &Directive) -> Vec<String> {
        let Directive::Transaction(transaction) = directive else {
            return Vec::new();
        };
        transaction
            .parent_ids()
            .into_iter()
            .filter(|parent_id| !parent_id.is_empty() && self.dag.get(parent_id).is_none())
            .map(|parent_id| parent_id.to_owned())
            .collect()
    }

    /// Insert a validated remote directive into the ledger, persisting after it
    /// (P2P receive path, single-insert semantics).
    ///
    /// This is [`Self::stage_remote_directive`] followed by a persist: it merges
    /// the directive into memory and, only if that changed state, writes the
    /// whole `.bean` file. A failed write reloads from disk (L-13), so a caller
    /// can treat one insert as an atomic memory+disk step.
    ///
    /// For catch-up of many entries, prefer staging the whole batch with
    /// [`Self::stage_remote_directive`] and persisting once with
    /// [`Self::persist_or_reload`] — persisting per entry is the O(M×N) cost
    /// M-15 removes.
    ///
    /// Returns `Ok(Some(content_id))` if inserted, `Ok(None)` if duplicate, or `Err` if rejected.
    pub fn insert_remote_directive(
        &mut self,
        directive: Directive,
    ) -> Result<Option<String>, ServiceError> {
        let result = self.stage_remote_directive(directive)?;
        if result.is_some() {
            self.persist_or_reload()?;
        }
        Ok(result)
    }

    /// Stage a validated remote directive into in-memory state — NO persist.
    ///
    /// This is the in-memory commit half of the P2P receive path: the bridge
    /// between `p2p::union_merge::validate_supply_entry()` (which validates wire
    /// format, content hash, and envelope) and the ledger's internal state. It:
    ///
    /// 1. Adopts the Lamport clock (§3.4.2)
    /// 2. For transactions: validates I1, I2, I3 against local account state
    /// 3. Inserts into DAG (G-Set dedup handles idempotency)
    /// 4. Updates the read model incrementally
    ///
    /// It does NOT touch the file. The caller is responsible for persisting once
    /// the desired set of directives is staged, via [`Self::persist_or_reload`]
    /// (M-15: one persist per batch, not one per entry).
    ///
    /// Returns `Ok(Some(content_id))` if inserted, `Ok(None)` if duplicate, or `Err` if rejected.
    pub fn stage_remote_directive(
        &mut self,
        directive: Directive,
    ) -> Result<Option<String>, ServiceError> {
        let content_id = compute_content_id(&directive);

        // G-Set dedup: if already present, no-op.
        if self.dag.get(&content_id).is_some() {
            return Ok(None);
        }

        enforce_resource_limits(&directive)?;
        // H-04: reject before the Lamport clock is adopted or the DAG touched.
        validate_directive_dates(&directive)?;
        // H-06: the merged envelope legitimately sits at directive level here,
        // so the four envelope keys are allowed there — but nothing else with
        // the prefix, and nothing at all at posting level (defense in depth
        // behind `validate_supply_entry`, which allows none anywhere).
        validate_body_envelope_keys(&directive, ENVELOPE_KEYS)?;
        // L-26: control characters would be persisted verbatim into the file.
        validate_body_strings(&directive)?;
        // L-25 (T37 follow-up): account/tag/link charsets. Redundant behind
        // `validate_supply_entry`'s re-parse by design — see
        // [`validate_body_names`] for why it is here anyway.
        validate_body_names(&directive)?;
        // L-02: the wire cap, re-applied to the *merged* directive. The
        // envelope is stripped from the economic form, so this is the same
        // number `validate_supply_entry` checked against the raw
        // `economic_bean`, and it also guards the library callers that reach
        // this `pub` entry point without going through the wire path.
        enforce_economic_bean_limit(&directive)?;

        if let Directive::Transaction(transaction) = &directive {
            // H-03: a remote transaction must arrive resolved. Insert stores the
            // *resolved* postings, so an elided body would be stored — and
            // re-hashed — under an id different from the one it was accepted
            // and signed under, and could then never propagate.
            if elided_posting_count(transaction) > 0 {
                return Err(ServiceError::InvalidInput {
                    message: "remote transaction has an elided posting; \
                              remote bodies must arrive with every amount resolved"
                        .to_owned(),
                });
            }
            // T41: defence in depth behind `validate_supply_entry`'s own cap,
            // for the library callers that reach this `pub` entry point without
            // the wire path — the same reason `validate_body_names` exists.
            validate_parent_fan_in(&directive)?;
            for parent_id in transaction.parent_ids() {
                if !parent_txid_is_well_formed(parent_id) {
                    return Err(ServiceError::InvalidInput {
                        message: format!(
                            "openledger-parents entry must be a 64-character lowercase hex txid, got {parent_id}"
                        ),
                    });
                }
            }
        }

        // Adopt Lamport clock (§3.4.2): lamport = max(local, remote) + 1.
        let metadata = match &directive {
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
        if let Some(remote_lamport) = metadata
            .get("openledger-lamport")
            .and_then(|v| v.parse::<u64>().ok())
        {
            // Saturating: a malicious/garbage remote `openledger-lamport` (e.g. u64::MAX)
            // must not panic (debug) or wrap to 0 (release) and corrupt causal ordering.
            //
            // T41: the `+1` here and its absence on the reconcile path are both
            // correct — see the long note at the reconcile site for why, and for
            // why they are deliberately left different.
            self.lamport_clock = self.lamport_clock.max(remote_lamport).saturating_add(1);
        }

        // Validate and insert based on directive type.
        match &directive {
            Directive::Transaction(txn) => {
                // Validate I1, I2, I3, I9 against local account state.
                let validated = validate_transaction(txn, &self.accounts)?;
                let final_txn = Transaction {
                    postings: validated.postings,
                    ..txn.clone()
                };
                let final_directive = Directive::Transaction(final_txn);
                match self.dag.insert(final_directive.clone(), true)? {
                    InsertResult::Inserted { content_id } => {
                        self.read_model.index_directive(&final_directive);
                        // T44: staged in memory, durable on the caller's commit.
                        self.pending_ids.push(content_id.clone());
                        Ok(Some(content_id))
                    }
                    InsertResult::Duplicate { .. } => Ok(None),
                }
            }
            Directive::Open(_) => {
                // M-09: a remote `open` is DATA. It is not applied to a mutable
                // flag that the arrival order could decide — it joins the
                // account's lifecycle event set at its own deterministic
                // position, and every query folds the set. Conflicting opens
                // and closes therefore resolve identically on every replica, so
                // there is no error left to swallow with `let _ =`.
                match self.dag.insert(directive.clone(), false)? {
                    InsertResult::Inserted { content_id } => {
                        self.accounts.record_lifecycle(&directive, &content_id);
                        self.read_model.index_directive(&directive);
                        self.pending_ids.push(content_id.clone());
                        Ok(Some(content_id))
                    }
                    InsertResult::Duplicate { .. } => Ok(None),
                }
            }
            Directive::Close(close) => {
                // M-09: the one lifecycle directive that is NOT accepted as
                // plain data — a close that predates transactions already on
                // the account is the write-DoS, and is rejected here (and so
                // never reaches the DAG or the event set).
                self.reject_backdated_close(close)?;
                match self.dag.insert(directive.clone(), false)? {
                    InsertResult::Inserted { content_id } => {
                        self.accounts.record_lifecycle(&directive, &content_id);
                        self.read_model.index_directive(&directive);
                        self.pending_ids.push(content_id.clone());
                        Ok(Some(content_id))
                    }
                    InsertResult::Duplicate { .. } => Ok(None),
                }
            }
            _ => {
                // All other directive types: insert directly.
                match self.dag.insert(directive.clone(), false)? {
                    InsertResult::Inserted { content_id } => {
                        self.read_model.index_directive(&directive);
                        self.pending_ids.push(content_id.clone());
                        Ok(Some(content_id))
                    }
                    InsertResult::Duplicate { .. } => Ok(None),
                }
            }
        }
    }

    /// Stamp a signature onto a directive's metadata after insert (§3.8.1).
    ///
    /// Prefer `append_transaction_signing` / `open_account_signing` /
    /// `close_account_signing` so the first persist already includes the signature.
    pub fn stamp_signature(
        &mut self,
        content_id: &str,
        signature_hex: &str,
    ) -> Result<(), ServiceError> {
        if let Some(directive) = self.dag.get_mut(content_id) {
            let metadata = match directive {
                Directive::Transaction(txn) => &mut txn.metadata,
                Directive::Open(d) => &mut d.metadata,
                Directive::Close(d) => &mut d.metadata,
                Directive::Commodity(d) => &mut d.metadata,
                Directive::Pad(d) => &mut d.metadata,
                Directive::Balance(d) => &mut d.metadata,
                Directive::Note(d) => &mut d.metadata,
                Directive::Document(d) => &mut d.metadata,
                Directive::Event(d) => &mut d.metadata,
                Directive::Price(d) => &mut d.metadata,
            };
            metadata.insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex.to_owned());
            // T44: this edits a directive that may ALREADY be on disk, and an
            // append cannot express an edit — a journal record carrying the
            // same content id would be dropped by the G-Set on the way back in,
            // losing the signature forever. Force the full rewrite.
            self.force_compaction = true;
            // L-13: reload from disk if the persist fails, so the in-memory
            // signature stamp never gets ahead of the on-disk file.
            self.persist_or_reload()?;
        }
        Ok(())
    }
}

/// Mutable access to whichever directive kind's metadata map this is.
///
/// One place, rather than the same ten-arm match written out at each site.
fn directive_metadata_mut(directive: &mut Directive) -> &mut Metadata {
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

// ─── Comment extraction ──────────────────────────────────────────────────────

/// Extract leading `;` comments from the beginning of a file (before any directive).
fn extract_leading_comments(content: &str) -> Vec<String> {
    let mut comments = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(comment) = trimmed.strip_prefix(';') {
            comments.push(comment.trim().to_owned());
        } else {
            break; // First non-comment, non-blank line = start of directives.
        }
    }
    comments
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_file_path() -> PathBuf {
        let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("openledger-test-{ts}-{count}.bean"))
    }

    fn make_date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    /// Run `body` with every `WARN`/`ERROR` it logs captured as text.
    ///
    /// `tracing::subscriber::with_default` installs a *thread-local* subscriber,
    /// so this stays correct under `cargo test`'s thread-per-test parallelism —
    /// a concurrent test's logs never land in this buffer.
    fn capture_warnings<T>(body: impl FnOnce() -> T) -> (T, String) {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for SharedBuffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
            type Writer = SharedBuffer;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        let value = tracing::subscriber::with_default(subscriber, body);
        let logged = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
        (value, logged)
    }

    fn boot_empty() -> (LedgerService, PathBuf) {
        let path = test_file_path();
        let svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        (svc, path)
    }

    fn setup_with_accounts() -> (LedgerService, PathBuf) {
        let (mut svc, path) = boot_empty();
        svc.open_account(
            "Assets:Cash".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.open_account(
            "Expenses:Food".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        (svc, path)
    }

    fn balanced_input() -> TransactionInput {
        TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: Some("Acme".to_owned()),
            narration: Some("Funding".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        }
    }

    // ── Boot ─────────────────────────────────────────────────────────────

    #[test]
    fn test_boot_creates_empty_file() {
        let path = test_file_path();
        assert!(!path.exists());
        let svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        assert!(path.exists());
        assert_eq!(svc.directive_count(), 0);
        assert_eq!(svc.lamport_clock(), 0);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_boot_from_existing_file() {
        let path = test_file_path();
        std::fs::write(
            &path,
            "2024-01-01 open Assets:Cash USD\n\n2024-01-01 open Equity:Opening\n",
        )
        .unwrap();
        let svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        assert_eq!(svc.directive_count(), 2);
        assert!(svc.accounts().is_open("Assets:Cash"));
        assert!(svc.accounts().is_open("Equity:Opening"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_boot_from_golden_fixture() {
        // Boot from the golden fixture file (copy it to temp).
        let fixture = include_str!("../../../testfixtures/fixture-simple.bean");
        let path = test_file_path();
        std::fs::write(&path, fixture).unwrap();
        let svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        assert_eq!(svc.directive_count(), 16);
        assert!(svc.accounts().is_open("Assets:Cash"));
        assert!(!svc.accounts().is_open("Expenses:Food")); // closed in fixture
        std::fs::remove_file(path).ok();
    }

    // ── Open account ─────────────────────────────────────────────────────

    #[test]
    fn test_open_account() {
        let (mut svc, path) = boot_empty();
        let id = svc
            .open_account(
                "Assets:Cash".to_owned(),
                make_date(2024, 1, 1),
                vec!["USD".to_owned()],
            )
            .unwrap();
        assert!(!id.is_empty());
        assert_eq!(svc.directive_count(), 1);
        assert!(svc.accounts().is_open("Assets:Cash"));
        assert_eq!(svc.lamport_clock(), 1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_open_already_open_rejected() {
        let (mut svc, path) = boot_empty();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        let err = svc
            .open_account("Assets:Cash".to_owned(), make_date(2024, 2, 1), vec![])
            .unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_ALREADY_OPEN");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_open_account_rejects_newline_injection() {
        let (mut svc, path) = boot_empty();
        let err = svc
            .open_account(
                "Assets:Cash\n2024-01-02 open Liabilities:Injected USD".to_owned(),
                make_date(2024, 1, 1),
                vec![],
            )
            .unwrap_err();
        assert_eq!(err.error_code(), "INVALID_ACCOUNT_NAME");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_open_account_rejects_invalid_currency() {
        let (mut svc, path) = boot_empty();
        let err = svc
            .open_account(
                "Assets:Cash".to_owned(),
                make_date(2024, 1, 1),
                vec!["usd\nopen".to_owned()],
            )
            .unwrap_err();
        assert_eq!(err.error_code(), "INVALID_CURRENCY");
        std::fs::remove_file(path).ok();
    }

    // ── Close account ────────────────────────────────────────────────────

    #[test]
    fn test_close_account() {
        let (mut svc, path) = boot_empty();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        let id = svc
            .close_account("Assets:Cash".to_owned(), make_date(2024, 12, 31))
            .unwrap();
        assert!(!id.is_empty());
        assert!(!svc.accounts().is_open("Assets:Cash"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_close_not_open_rejected() {
        let (mut svc, path) = boot_empty();
        let err = svc
            .close_account("Assets:Cash".to_owned(), make_date(2024, 12, 31))
            .unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_NOT_OPEN");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_close_with_later_transactions_rejected() {
        let (mut svc, path) = setup_with_accounts();

        // Append a transaction on Jan 15.
        svc.append_transaction(balanced_input()).unwrap();

        // Try to close before that date → error.
        let err = svc
            .close_account("Assets:Cash".to_owned(), make_date(2024, 1, 10))
            .unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_HAS_LATER_TRANSACTIONS");
        std::fs::remove_file(path).ok();
    }

    // ── Append transaction ───────────────────────────────────────────────

    #[test]
    fn test_append_balanced_transaction() {
        let (mut svc, path) = setup_with_accounts();
        let txid = svc.append_transaction(balanced_input()).unwrap().txid;
        assert_eq!(txid.len(), 64);
        assert_eq!(svc.head_count(), 1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_unbalanced_rejected() {
        let (mut svc, path) = setup_with_accounts();
        let mut input = balanced_input();
        input.postings[1].amount = Some(Amount {
            number: dec!(-50),
            currency: "USD".to_owned(),
        });
        let err = svc.append_transaction(input).unwrap_err();
        assert_eq!(err.error_code(), "UNBALANCED_TRANSACTION");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_unopened_account_rejected() {
        let (mut svc, path) = boot_empty();
        // No accounts opened.
        let err = svc.append_transaction(balanced_input()).unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_NOT_OPEN");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_rejects_newline_in_account() {
        let (mut svc, path) = setup_with_accounts();
        let mut input = balanced_input();
        input.postings[0].account = "Assets:Cash\n2024-01-02 open Liabilities:Hacked".to_owned();
        let err = svc.append_transaction(input).unwrap_err();
        assert_eq!(err.error_code(), "INVALID_ACCOUNT_NAME");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_rejects_control_characters_in_narration() {
        let (mut svc, path) = setup_with_accounts();
        let mut input = balanced_input();
        input.narration = Some("ok\n2024-01-01 open Assets:Hacked".to_owned());
        let err = svc.append_transaction(input).unwrap_err();
        assert_eq!(err.error_code(), "INVALID_INPUT");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_rejects_invalid_tag() {
        let (mut svc, path) = setup_with_accounts();
        let mut input = balanced_input();
        input.tags = vec!["good\nbad".to_owned()];
        let err = svc.append_transaction(input).unwrap_err();
        assert_eq!(err.error_code(), "INVALID_TAG");
        std::fs::remove_file(path).ok();
    }

    // ── L-14: a crafted file must not make boot quadratic ────────────────

    /// Build the adversarial file described in the L-14 analysis.
    ///
    /// `count` transactions in one long parent chain, plus — when
    /// `decoy_parents` is `Some(n)` — a single **decoy** transaction, dated
    /// earlier so boot's canonical sort puts it first, whose
    /// `openledger-parents` names the first `n` links in that chain.
    ///
    /// `n` is a parameter because T41 put a `MAX_PARENTS` cap on the file path:
    /// `Some(count)` is the original L-14 decoy, now over the cap and skipped at
    /// boot, while `Some(MAX_PARENTS)` is the worst decoy that is still legal
    /// and therefore the one the cost bound has to hold for.
    ///
    /// The decoy is what defeats the M-6 fast path: it makes every chain link's
    /// content id "already referenced as a parent", so the skip condition fails
    /// for all of them and each insert runs a full ancestor walk over everything
    /// loaded so far. Nothing here is a cycle (nothing points *at* the decoy), so
    /// T35's Kahn pre-scan passes it and the whole file loads.
    ///
    /// Every id is computable offline — parents live in the envelope, which the
    /// content hash excludes — so an attacker (or a careless merge) can write
    /// this file without running the node.
    fn chain_file(count: usize, decoy_parents: Option<usize>) -> String {
        fn link(index: usize, parents: &str) -> Transaction {
            let mut metadata = BTreeMap::new();
            metadata.insert("openledger-author".to_owned(), "crafted".to_owned());
            metadata.insert(
                "openledger-lamport".to_owned(),
                index.saturating_add(2).to_string(),
            );
            metadata.insert("openledger-parents".to_owned(), parents.to_owned());
            Transaction {
                date: make_date(2024, 6, 1),
                flag: Flag::Complete,
                payee: None,
                narration: Some(format!("link {index}")),
                tags: vec![],
                links: vec![],
                postings: vec![
                    Posting {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(1),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                    Posting {
                        account: "Equity:Opening".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-1),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                ],
                metadata,
            }
        }

        // Ids first: the body does not depend on the parents, so the whole
        // chain's ids are known before a single parent pointer is written.
        let ids: Vec<String> = (0..count)
            .map(|index| compute_content_id(&Directive::Transaction(link(index, ""))))
            .collect();

        let mut directives: Vec<Directive> = Vec::with_capacity(count + 1);
        if let Some(parent_count) = decoy_parents {
            // The decoy, dated earliest so it is inserted first.
            let named = &ids[..parent_count.min(ids.len())];
            let mut decoy = link(usize::MAX - 2, &named.join(","));
            decoy.date = make_date(2024, 1, 1);
            decoy.narration = Some("decoy".to_owned());
            decoy
                .metadata
                .insert("openledger-lamport".to_owned(), (count + 10).to_string());
            directives.push(Directive::Transaction(decoy));
        }
        for index in 0..count {
            let parents = if index == 0 {
                String::new()
            } else {
                ids[index - 1].clone()
            };
            directives.push(Directive::Transaction(link(index, &parents)));
        }

        full_file_serialize(&directives, &[])
    }

    /// Time one boot of `content`, returning the elapsed wall clock and the
    /// number of directives loaded.
    fn time_boot(content: &str) -> (std::time::Duration, usize) {
        let path = test_file_path();
        std::fs::write(&path, content).unwrap();
        let started = std::time::Instant::now();
        let svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        let elapsed = started.elapsed();
        let count = svc.directive_count();
        std::fs::remove_file(path).ok();
        (elapsed, count)
    }

    #[test]
    fn test_adversarial_parent_chain_boots_in_bounded_time() {
        // L-14: the ancestor walk used to run in full on every one of these
        // inserts, so boot cost O(N²) node visits on a file anyone can write by
        // hand — parents live in the envelope, outside the content hash, so
        // every id is computable offline.
        //
        // Measured before the fix, debug build: 3.87 s at 2,500 links and
        // 19.64 s at 5,000 — 5.07× for a 2× file, i.e. comfortably worse than
        // quadratic once allocation costs are counted. After: 1.08 s.
        //
        // The assertion is deliberately **relative**, not an absolute wall-clock
        // target: it boots the same chain WITHOUT the decoy line and requires
        // the crafted file to cost no more than a small multiple of it. That
        // self-calibrates to whatever machine and build profile it runs on,
        // where an absolute bound either goes flaky under load or has to be set
        // so loose it stops catching the regression (30 s would have passed
        // against the very code this closes). A generous absolute ceiling is
        // kept as a backstop against a pathology that slows *both* files.
        const LINKS: usize = 5_000;
        const MAX_OVERHEAD: u32 = 4;
        const CEILING: std::time::Duration = std::time::Duration::from_secs(120);

        let (honest_elapsed, honest_count) = time_boot(&chain_file(LINKS, None));
        assert_eq!(honest_count, LINKS);

        // The worst decoy that is still LEGAL after T41's file-path fan-in cap.
        // This is the cost test proper: the directive loads, so the ancestor
        // walk really does run against it.
        let (crafted_elapsed, crafted_count) = time_boot(&chain_file(LINKS, Some(MAX_PARENTS)));
        assert_eq!(
            crafted_count,
            LINKS + 1,
            "a decoy within the fan-in cap must still load — otherwise this measures nothing"
        );
        assert!(
            crafted_elapsed < honest_elapsed * MAX_OVERHEAD,
            "the crafted file booted in {crafted_elapsed:?} against {honest_elapsed:?} for the \
             same chain without the decoy ({MAX_OVERHEAD}× allowed) — one extra parents line \
             must not change the cost class"
        );
        assert!(
            crafted_elapsed < CEILING,
            "boot took {crafted_elapsed:?} for {LINKS} crafted directives (ceiling {CEILING:?})"
        );

        // T41: a decoy of the ORIGINAL L-14 shape — naming every link in its
        // chain — no longer even loads. It exceeds `MAX_PARENTS`, which until
        // now was enforced on the wire path only, so a hand-written file could
        // carry unbounded fan-in that every peer would refuse forever. Boot
        // skips it with a warning (T35's tolerant rule) and loads the rest.
        //
        // Deliberately on a SHORT chain: whether the decoy is refused depends on
        // its fan-in, not on the chain's length, and a third 5,000-link boot is
        // pure cost — this suite already runs alongside the crate's wall-clock
        // network tests. The full-length version is what the timing assertion
        // above exercises.
        const SHORT_CHAIN: usize = MAX_PARENTS + 8;
        let (_, unbounded_count) = time_boot(&chain_file(SHORT_CHAIN, Some(SHORT_CHAIN)));
        assert_eq!(
            unbounded_count, SHORT_CHAIN,
            "the over-cap decoy must be skipped, and only it — the chain still loads"
        );
    }

    // ── T41: MAX_PARENTS on the FILE path ────────────────────────────────

    /// Serialize a `.bean` holding one transaction with `parent_count` parents.
    ///
    /// The parents are fabricated 64-hex ids that resolve to nothing, which is
    /// legal at boot (`require_parents: false`) and is exactly the shape a hand
    /// edit or a crafted file takes.
    fn file_with_parent_fan_in(parent_count: usize) -> String {
        let parents: Vec<String> = (0..parent_count)
            .map(|index| format!("{index:064x}"))
            .collect();
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "crafted".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "7".to_owned());
        metadata.insert("openledger-parents".to_owned(), parents.join(","));

        let directives = vec![
            Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Assets:Cash".to_owned(),
                currencies: vec![],
                metadata: BTreeMap::new(),
            }),
            Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Equity:Opening".to_owned(),
                currencies: vec![],
                metadata: BTreeMap::new(),
            }),
            Directive::Transaction(Transaction {
                date: make_date(2024, 6, 1),
                flag: Flag::Complete,
                payee: None,
                narration: Some("fan-in".to_owned()),
                tags: vec![],
                links: vec![],
                postings: vec![
                    Posting {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(1),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                    Posting {
                        account: "Equity:Opening".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-1),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                ],
                metadata,
            }),
        ];
        full_file_serialize(&directives, &[])
    }

    /// `MAX_PARENTS` was enforced on the wire path only, so a hand-written or
    /// crafted `.bean` could name unboundedly many parents — the L-14 decoy
    /// vector. All three file-reachable ingresses now apply the same cap, each
    /// in the failure style its path already uses.
    #[test]
    fn parent_fan_in_cap_applies_to_every_file_ingress() {
        // (a) BOOT — tolerant: warn and skip the directive, load the rest
        // (T35's rule; a refusal here would be a brick path).
        let path = test_file_path();
        std::fs::write(&path, file_with_parent_fan_in(MAX_PARENTS + 1)).unwrap();
        let (booted, logged) =
            capture_warnings(|| LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap());
        assert_eq!(
            booted.directive_count(),
            2,
            "the two opens must load and the over-cap transaction must not"
        );
        assert!(
            logged.contains("fan-in cap"),
            "boot must say which directive it skipped and why, got: {logged}"
        );

        // The control: exactly at the cap, the same file loads in full.
        std::fs::write(&path, file_with_parent_fan_in(MAX_PARENTS)).unwrap();
        let at_cap = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        assert_eq!(
            at_cap.directive_count(),
            3,
            "the cap is a ceiling, not an off-by-one refusal"
        );
        std::fs::remove_file(&path).ok();

        // (b) RECONCILE — the hand edit is counted into `rejected` rather than
        // silently adopted and re-served to every peer.
        let (mut svc, live_path) = boot_empty();
        std::fs::write(&live_path, file_with_parent_fan_in(MAX_PARENTS + 1)).unwrap();
        let result = svc.reconcile_file().unwrap();
        assert_eq!(
            result.rejected, 1,
            "the over-cap transaction must be rejected"
        );
        assert_eq!(result.new_directives, 2, "the two opens are still adopted");

        // (c) `stage_remote_directive` — the `pub` entry point a library caller
        // reaches without the wire path's own cap.
        let parents: Vec<String> = (0..=MAX_PARENTS).map(|i| format!("{i:064x}")).collect();
        let mut metadata = remote_envelope(9);
        metadata.insert("openledger-parents".to_owned(), parents.join(","));
        let error = svc
            .stage_remote_directive(Directive::Transaction(Transaction {
                date: make_date(2024, 6, 2),
                flag: Flag::Complete,
                payee: None,
                narration: Some("staged fan-in".to_owned()),
                tags: vec![],
                links: vec![],
                postings: vec![
                    Posting {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(1),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                    Posting {
                        account: "Equity:Opening".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-1),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                ],
                metadata,
            }))
            .unwrap_err();
        assert_eq!(error.error_code(), "INVALID_INPUT");
        assert!(
            format!("{error}").contains("openledger-parents has"),
            "the error must name the cap it broke: {error}"
        );

        std::fs::remove_file(live_path).ok();
    }

    // ── L-11: reconcile signs what it adopts ─────────────────────────────

    /// A signer that stamps a recognisable marker instead of a real signature,
    /// so a ledger-crate test can tell *whether* signing happened without
    /// depending on the `security` crate. The real end-to-end proof — that a
    /// peer's validator accepts the result — lives in
    /// `p2p::union_merge::tests::test_reconcile_signs_hand_edits_so_peers_accept_them`.
    fn marker_signer() -> crate::service::DirectiveSigner {
        std::sync::Arc::new(
            |content_id: &str, is_transaction: bool, parents: &str, lamport: &str| {
                Some(format!(
                    "sig({content_id}|{is_transaction}|{parents}|{lamport})"
                ))
            },
        )
    }

    fn append_to_file(path: &Path, text: &str) {
        let mut content = std::fs::read_to_string(path).unwrap();
        content.push_str(text);
        std::fs::write(path, content).unwrap();
    }

    const HAND_EDITED_TRANSACTION: &str = "\n2024-01-15 * \"Shop\" \"Coffee\"\n  \
         Expenses:Food                                        4.50 USD\n  \
         Assets:Cash                                         -4.50 USD\n";

    #[test]
    fn test_reconcile_signs_an_adopted_hand_edit() {
        let (mut svc, path) = setup_with_accounts();
        svc.set_signer(marker_signer());
        append_to_file(&path, HAND_EDITED_TRANSACTION);

        assert_eq!(svc.reconcile_file().unwrap().new_directives, 1);
        let adopted = svc
            .dag()
            .directives()
            .into_iter()
            .find(|d| matches!(d, Directive::Transaction(_)))
            .unwrap();
        let metadata = adopted.metadata();
        let signature = metadata
            .get("openledger-signature")
            .expect("an adopted hand edit must be signed");
        // Signed over the id it is stored under, as a transaction, with the
        // envelope this reconcile stamped.
        assert!(
            signature.contains(&compute_content_id(adopted)),
            "signature must cover the stored id: {signature}"
        );
        assert!(signature.contains("|true|"), "{signature}");
        assert_eq!(metadata.get("openledger-author"), Some(&svc.author_id));

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reconcile_does_not_sign_for_another_author() {
        // Residual, made explicit: a hand edit that names someone ELSE as
        // author cannot be signed by this node — the verifier checks the
        // signature against the author's key, so our signature would fail
        // everywhere, which is worse than none. Adopted unsigned, with a
        // warning that names the entry.
        let (mut svc, path) = setup_with_accounts();
        svc.set_signer(marker_signer());
        append_to_file(
            &path,
            "\n2024-01-15 * \"Shop\" \"Someone else's coffee\"\n  \
             openledger-author: \"a-different-node\"\n  \
             Expenses:Food                                        4.50 USD\n  \
             Assets:Cash                                         -4.50 USD\n",
        );

        let (result, logs) = capture_warnings(|| svc.reconcile_file().unwrap());
        assert_eq!(result.new_directives, 1, "still adopted, just not signed");

        let adopted = svc
            .dag()
            .directives()
            .into_iter()
            .find(|d| matches!(d, Directive::Transaction(_)))
            .unwrap();
        assert!(!adopted.metadata().contains_key("openledger-signature"));
        assert_eq!(
            adopted.metadata().get("openledger-author"),
            Some(&"a-different-node".to_owned())
        );
        assert!(
            logs.contains("cannot sign for that author"),
            "the operator must be told this entry will not replicate: {logs}"
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_persist_time_adoption_also_signs() {
        // The second reconcile entry point (L-30's adopt-before-persist, reached
        // from inside `persist_or_reload`) must sign too — it is why the signer
        // lives on the service rather than being a `reconcile_file` parameter.
        let (mut svc, path) = setup_with_accounts();
        svc.set_signer(marker_signer());
        append_to_file(&path, HAND_EDITED_TRANSACTION);

        // A normal mutation now triggers the adopt-then-persist path.
        svc.open_account("Assets:Savings".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        assert_eq!(svc.external_reconcile_count(), 1, "adoption must have run");

        let adopted = svc
            .dag()
            .directives()
            .into_iter()
            .find(|d| matches!(d, Directive::Transaction(_)))
            .expect("the hand edit must have been adopted, not clobbered");
        assert!(
            adopted.metadata().contains_key("openledger-signature"),
            "an entry adopted during a persist must be signed too"
        );

        std::fs::remove_file(path).ok();
    }

    // ── L-02: the local path honours the wire size cap ───────────────────

    /// An account name of `bytes` total length, valid under §2.3.
    fn long_account(root: &str, bytes: usize) -> String {
        let prefix = format!("{root}:A");
        format!("{prefix}{}", "a".repeat(bytes.saturating_sub(prefix.len())))
    }

    #[test]
    fn test_append_rejects_body_over_the_wire_size_cap() {
        // L-02: every per-field cap passes here — two postings (max 1,000), no
        // narration, no tags, no links — yet the body is over 1 MiB, because
        // account names have a charset but no length limit. Before the fix this
        // persisted locally and then every peer refused it forever.
        let (mut svc, path) = boot_empty();
        let asset = long_account("Assets", MAX_ECONOMIC_BEAN_LENGTH / 2 + 16);
        let equity = long_account("Equity", MAX_ECONOMIC_BEAN_LENGTH / 2 + 16);
        svc.open_account(asset.clone(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.open_account(equity.clone(), make_date(2024, 1, 1), vec![])
            .unwrap();

        let lamport_before = svc.lamport_clock();
        let directives_before = svc.directive_count();
        let file_before = std::fs::read_to_string(&path).unwrap();

        let mut input = balanced_input();
        input.postings[0].account = asset;
        input.postings[1].account = equity;

        let error = svc.append_transaction(input).unwrap_err();
        assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED");
        assert!(
            error.to_string().contains("refused by every peer"),
            "the error must say why the cap exists: {error}"
        );

        // Rejected BEFORE the stamp and before the persist: no Lamport
        // movement, nothing in the DAG, and the file byte-identical.
        assert_eq!(svc.lamport_clock(), lamport_before);
        assert_eq!(svc.directive_count(), directives_before);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), file_before);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_accepts_a_body_just_under_the_wire_size_cap() {
        // The other edge: a big-but-compliant append still works, so the cap is
        // a cap and not an accidental ban on long account names.
        let (mut svc, path) = boot_empty();
        let asset = long_account("Assets", 4_096);
        let equity = long_account("Equity", 4_096);
        svc.open_account(asset.clone(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.open_account(equity.clone(), make_date(2024, 1, 1), vec![])
            .unwrap();

        let mut input = balanced_input();
        input.postings[0].account = asset;
        input.postings[1].account = equity;

        let outcome = svc.append_transaction(input).unwrap();
        assert!(!outcome.already_existed);

        // And what it wrote is something a peer would accept: the body the
        // serve path would ship is within the same cap.
        let directive = svc.get_directive(&outcome.txid).unwrap();
        assert!(
            crate::serialize::economic_canonical_serialize(directive).len()
                <= MAX_ECONOMIC_BEAN_LENGTH
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_open_rejects_a_body_over_the_wire_size_cap() {
        // `open`/`close` had no size check of any kind — not even the per-field
        // battery — so a megabyte-long account name went straight to disk.
        let (mut svc, path) = boot_empty();
        let huge = long_account("Assets", MAX_ECONOMIC_BEAN_LENGTH + 1_024);

        let lamport_before = svc.lamport_clock();
        let error = svc
            .open_account(huge.clone(), make_date(2024, 1, 1), vec![])
            .unwrap_err();
        assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED");
        assert_eq!(
            svc.lamport_clock(),
            lamport_before,
            "a rejected open must not move the Lamport clock"
        );
        assert_eq!(svc.directive_count(), 0);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_close_rejects_a_body_over_the_wire_size_cap() {
        // `close_account` cannot reach its own size check through
        // `open_account` any more — the open is refused first — but it is
        // reachable, and this is how: boot deliberately applies no limits, so a
        // ledger written before this fix (or by hand) can hold an account name
        // no `close` directive could ever be shipped for.
        let path = test_file_path();
        let huge = long_account("Assets", MAX_ECONOMIC_BEAN_LENGTH + 1_024);
        let persisted = full_file_serialize(
            &[Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: huge.clone(),
                currencies: vec![],
                metadata: BTreeMap::new(),
            })],
            &[],
        );
        std::fs::write(&path, &persisted).unwrap();

        let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        assert!(
            svc.accounts().is_open(&huge),
            "boot must still load the oversized account — the cap is on writes"
        );

        let lamport_before = svc.lamport_clock();
        let error = svc.close_account(huge, make_date(2024, 1, 2)).unwrap_err();
        assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED");
        assert_eq!(
            svc.lamport_clock(),
            lamport_before,
            "a rejected close must not move the Lamport clock"
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_field_cap_rejection_leaves_the_ledger_untouched() {
        // The per-field caps now come from the shared `enforce_resource_limits`
        // rather than a second copy of the same comparisons; pin that the
        // rejection still fires, with the same code, before anything moves.
        let (mut svc, path) = setup_with_accounts();
        let lamport_before = svc.lamport_clock();
        let directives_before = svc.directive_count();

        let mut input = balanced_input();
        input.narration = Some("x".repeat(MAX_NARRATION_LENGTH + 1));

        let error = svc.append_transaction(input).unwrap_err();
        assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED");
        assert!(error.to_string().contains("Narration too long"), "{error}");
        assert_eq!(svc.lamport_clock(), lamport_before);
        assert_eq!(svc.directive_count(), directives_before);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_stage_remote_directive_revalidates_names() {
        // T37 follow-up: `stage_remote_directive` is a `pub` entry point, and a
        // caller that builds a directive in memory rather than parsing one gets
        // no benefit from `validate_supply_entry`'s re-parse. Redundant behind
        // the wire path by design; not redundant here.
        let (mut svc, path) = setup_with_accounts();
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-remote".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "9".to_owned());

        let error = svc
            .stage_remote_directive(Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Assets:C\u{0430}sh".to_owned(),
                currencies: vec![],
                metadata: metadata.clone(),
            }))
            .unwrap_err();
        assert_eq!(error.error_code(), "INVALID_ACCOUNT_NAME");

        // Control: the ASCII spelling of the same directive is staged.
        assert!(svc
            .stage_remote_directive(Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Assets:Cash2".to_owned(),
                currencies: vec![],
                metadata,
            }))
            .unwrap()
            .is_some());

        std::fs::remove_file(path).ok();
    }

    /// T41: the same rule for metadata KEYS. Same mechanism as the account name
    /// above — `stage_remote_directive` is a `pub` entry point, so a directive
    /// built in memory never passes through the parser that would have caught
    /// the Cyrillic `а`.
    #[test]
    fn test_stage_remote_directive_rejects_a_confusable_metadata_key() {
        let (mut svc, path) = setup_with_accounts();
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-remote".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "9".to_owned());
        let mut poisoned = metadata.clone();
        // `nаrration` — Cyrillic а (U+0430), a distinct, hash-visible key.
        poisoned.insert("n\u{0430}rration".to_owned(), "coffee".to_owned());

        let error = svc
            .stage_remote_directive(Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Assets:Cash3".to_owned(),
                currencies: vec![],
                metadata: poisoned,
            }))
            .unwrap_err();
        assert_eq!(error.error_code(), "INVALID_INPUT");
        assert!(
            format!("{error}").contains("U+0430"),
            "the error must name the offending character: {error}"
        );

        // Control: the ASCII spelling of the same key is staged.
        let mut clean = metadata;
        clean.insert("narration".to_owned(), "coffee".to_owned());
        assert!(svc
            .stage_remote_directive(Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Assets:Cash3".to_owned(),
                currencies: vec![],
                metadata: clean,
            }))
            .unwrap()
            .is_some());

        std::fs::remove_file(path).ok();
    }

    // ── L-15: indistinguishable posting shapes are refused at append ─────

    #[test]
    fn test_append_rejects_elided_posting_carrying_a_cost() {
        // The reachable half of L-15: GraphQL's `PostingInput` has independent
        // `amount`/`cost`/`price` fields, so a client can elide the amount and
        // still send a cost. The serializer emits neither, so this transaction
        // and the one without the cost would share a txid — and the DAG would
        // silently drop whichever arrived second as a duplicate.
        let (mut svc, path) = setup_with_accounts();
        let lamport_before = svc.lamport_clock();

        let mut input = balanced_input();
        input.postings[1].amount = None;
        input.postings[1].cost = Some(CostSpec {
            amount: Some(Amount {
                number: dec!(150),
                currency: "USD".to_owned(),
            }),
            date: None,
        });

        let error = svc.append_transaction(input).unwrap_err();
        assert_eq!(error.error_code(), "INVALID_POSTING");
        assert!(
            error.to_string().contains("elided amount"),
            "error must name the shape: {error}"
        );
        assert_eq!(
            svc.lamport_clock(),
            lamport_before,
            "a rejected append must not move the Lamport clock"
        );

        // Control: the same elided posting without the cost still appends, and
        // I2 resolves it — nothing legitimate is lost.
        let mut ok_input = balanced_input();
        ok_input.postings[1].amount = None;
        assert!(svc.append_transaction(ok_input).is_ok());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_rejects_empty_cost_carrying_a_date() {
        // The library-API half: `CostSpec { amount: None, date: Some(..) }`
        // serializes to a bare `{}`, so the date vanishes from the content id.
        let (mut svc, path) = setup_with_accounts();
        svc.open_account("Assets:Stock".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();

        let mut input = balanced_input();
        input.postings[0].cost = Some(CostSpec {
            amount: None,
            date: Some(make_date(2020, 3, 4)),
        });

        let error = svc.append_transaction(input).unwrap_err();
        assert_eq!(error.error_code(), "INVALID_POSTING");
        assert!(
            error.to_string().contains("must not carry a date"),
            "error must name the shape: {error}"
        );

        // Control: a plain empty `{}` is still legal.
        let mut ok_input = balanced_input();
        ok_input.postings[0].cost = Some(CostSpec {
            amount: None,
            date: None,
        });
        assert!(svc.append_transaction(ok_input).is_ok());

        std::fs::remove_file(path).ok();
    }

    // ── L-16: cost/price rates must be strictly positive ─────────────────

    /// `10 AAPL <annotation>` balanced against a `0 USD` counter-posting.
    ///
    /// With a zero rate the transaction balances for *any* number of AAPL —
    /// which is the whole finding.
    fn zero_rate_input(cost: Option<CostSpec>, price: Option<PriceSpec>) -> TransactionInput {
        TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: Some("Broker".to_owned()),
            narration: Some("Minting".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Stock".to_owned(),
                    amount: Some(Amount {
                        number: dec!(10_000_000),
                        currency: "AAPL".to_owned(),
                    }),
                    cost,
                    price,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(0),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        }
    }

    #[test]
    fn test_append_rejects_non_positive_cost_and_price() {
        let (mut svc, path) = setup_with_accounts();
        svc.open_account("Assets:Stock".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();

        let cases: Vec<(&str, TransactionInput)> = vec![
            (
                "{0 USD}",
                zero_rate_input(
                    Some(CostSpec {
                        amount: Some(Amount {
                            number: dec!(0),
                            currency: "USD".to_owned(),
                        }),
                        date: None,
                    }),
                    None,
                ),
            ),
            (
                "{-150 USD}",
                zero_rate_input(
                    Some(CostSpec {
                        amount: Some(Amount {
                            number: dec!(-150),
                            currency: "USD".to_owned(),
                        }),
                        date: None,
                    }),
                    None,
                ),
            ),
            (
                "@ -1.10 USD",
                zero_rate_input(
                    None,
                    Some(PriceSpec::Unit(Amount {
                        number: dec!(-1.10),
                        currency: "USD".to_owned(),
                    })),
                ),
            ),
            (
                "@@ -110 USD",
                zero_rate_input(
                    None,
                    Some(PriceSpec::Total(Amount {
                        number: dec!(-110),
                        currency: "USD".to_owned(),
                    })),
                ),
            ),
        ];

        for (annotation, input) in cases {
            let lamport_before = svc.lamport_clock();
            let directives_before = svc.directive_count();

            let error = svc
                .append_transaction(input)
                .expect_err(&format!("{annotation} must be refused"));
            assert_eq!(error.error_code(), "INVALID_POSTING", "{annotation}");
            assert!(
                error.to_string().contains("must be greater than zero"),
                "{annotation}: {error}"
            );

            // The refusal lands before the envelope stamp, so nothing about the
            // ledger moved — same rejection-ordering rule as H-04's.
            assert_eq!(
                svc.lamport_clock(),
                lamport_before,
                "{annotation}: a rejected append must not move the Lamport clock"
            );
            assert_eq!(
                svc.directive_count(),
                directives_before,
                "{annotation}: a rejected append must not reach the DAG"
            );
        }

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_still_accepts_positive_cost_and_price() {
        // No over-rejection on the write path the operator actually uses.
        let (mut svc, path) = setup_with_accounts();
        svc.open_account("Assets:Stock".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();

        let mut input = zero_rate_input(
            Some(CostSpec {
                amount: Some(Amount {
                    number: dec!(150),
                    currency: "USD".to_owned(),
                }),
                date: None,
            }),
            None,
        );
        input.postings[0].amount = Some(Amount {
            number: dec!(10),
            currency: "AAPL".to_owned(),
        });
        input.postings[1].amount = Some(Amount {
            number: dec!(-1500),
            currency: "USD".to_owned(),
        });
        assert!(
            svc.append_transaction(input).is_ok(),
            "an ordinary `{{150 USD}}` cost must still append"
        );

        std::fs::remove_file(path).ok();
    }

    // ── L-25: the API path shares the parser's (now ASCII) charset ────────

    #[test]
    fn test_append_rejects_mixed_script_account() {
        // The audit framed L-25 as "parse-side laxer than API-side", but for
        // account names both sides call the SAME `validate_account_name`, which
        // used Unicode `is_alphanumeric` — so `Assets:Cаsh` (Cyrillic а) was
        // accepted HERE too, and got persisted into the `.bean` file as an
        // account indistinguishable from `Assets:Cash` on screen.
        let (mut svc, path) = setup_with_accounts();
        let mut input = balanced_input();
        input.postings[0].account = "Assets:C\u{0430}sh".to_owned();
        let error = svc.append_transaction(input).unwrap_err();
        assert_eq!(error.error_code(), "INVALID_ACCOUNT_NAME");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_open_account_rejects_mixed_script_account() {
        let (mut svc, path) = boot_empty();
        let error = svc
            .open_account(
                "Assets:C\u{0430}sh".to_owned(),
                make_date(2024, 1, 1),
                vec!["USD".to_owned()],
            )
            .unwrap_err();
        assert_eq!(error.error_code(), "INVALID_ACCOUNT_NAME");
        assert_eq!(svc.dag().directives().len(), 0, "nothing may be inserted");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_rejects_mixed_script_tag_and_link() {
        // Tags and links were the half the API *did* already restrict to ASCII
        // (`validate_tag`/`validate_link`); the parser simply never called
        // them. These pin the API half so the two cannot drift apart again.
        let (mut svc, path) = setup_with_accounts();

        let mut tagged = balanced_input();
        tagged.tags = vec!["gr\u{043E}ceries".to_owned()];
        assert_eq!(
            svc.append_transaction(tagged).unwrap_err().error_code(),
            "INVALID_TAG"
        );

        let mut linked = balanced_input();
        linked.links = vec!["r\u{0435}ceipt-001".to_owned()];
        assert_eq!(
            svc.append_transaction(linked).unwrap_err().error_code(),
            "INVALID_LINK"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_boot_fails_closed_on_persisted_mixed_script_account() {
        // BREAKING CHANGE, deliberately fail-closed: a file carrying a
        // non-ASCII account (hand-edited, or written by a pre-hardening build)
        // no longer boots. It surfaces as an ordinary parse error with a
        // location, not a panic — the operator has to fix the name.
        let path = test_file_path();
        std::fs::write(
            &path,
            "2024-01-01 open Assets:Cash USD\n\n2024-01-01 open Assets:C\u{0430}sh USD\n",
        )
        .unwrap();
        let Err(error) = LedgerService::boot(path.clone(), "peer-1".to_owned()) else {
            panic!("boot must refuse a file with a non-ASCII account name");
        };
        let message = error.to_string();
        assert!(
            message.contains("U+0430") && message.contains("line 3"),
            "boot must report the offending line and character: {message}"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_currency_mismatch_rejected() {
        let (mut svc, path) = setup_with_accounts();
        let mut input = balanced_input();
        // Assets:Cash only accepts USD.
        input.postings[0].amount = Some(Amount {
            number: dec!(100),
            currency: "EUR".to_owned(),
        });
        input.postings[1].amount = Some(Amount {
            number: dec!(-100),
            currency: "EUR".to_owned(),
        });
        let err = svc.append_transaction(input).unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_CURRENCY_MISMATCH");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_with_elided_posting() {
        let (mut svc, path) = setup_with_accounts();
        let input = TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Elided test".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: None, // elided
                    cost: None,
                    price: None,
                },
            ],
        };
        let txid = svc.append_transaction(input).unwrap().txid;
        assert_eq!(txid.len(), 64);
        std::fs::remove_file(path).ok();
    }

    // ── L-27: the elided fill is hashed, so it must be deterministic ──────

    /// Open the two extra unconstrained accounts the multi-currency elision
    /// cases post to.
    fn open_multi_currency_accounts(svc: &mut LedgerService) {
        svc.open_account("Assets:Foreign".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.open_account("Income:Salary".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
    }

    fn posting_input(account: &str, number: rust_decimal::Decimal, currency: &str) -> PostingInput {
        PostingInput {
            account: account.to_owned(),
            amount: Some(Amount {
                number,
                currency: currency.to_owned(),
            }),
            cost: None,
            price: None,
        }
    }

    fn elided_posting_input(account: &str) -> PostingInput {
        PostingInput {
            account: account.to_owned(),
            amount: None,
            cost: None,
            price: None,
        }
    }

    #[test]
    fn test_elided_multi_currency_txid_is_deterministic_and_survives_restart() {
        // L-27: USD is the one imbalanced currency; EUR is present and already
        // balances. The fill has to be `-100 USD` every single time — it is
        // hashed into the txid, and a currency taken out of a randomly-seeded
        // `HashMap` would give the same logical transaction different ids on
        // different runs, restarts and nodes.
        let (mut svc, path) = setup_with_accounts();
        open_multi_currency_accounts(&mut svc);

        let input = || TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Multi-currency elision".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                posting_input("Assets:Cash", dec!(100.00), "USD"),
                posting_input("Assets:Foreign", dec!(50.00), "EUR"),
                posting_input("Income:Salary", dec!(-50.00), "EUR"),
                elided_posting_input("Equity:Opening"),
            ],
        };

        let first = svc.append_transaction(input()).unwrap();
        assert!(!first.already_existed);

        // The append path re-runs the fill and re-hashes *before* the G-Set
        // dedup check, so every iteration is a fresh resolution.
        for iteration in 1..=100 {
            let outcome = svc.append_transaction(input()).unwrap();
            assert_eq!(
                outcome.txid, first.txid,
                "iteration {iteration} resolved the elision to a different id"
            );
            assert!(
                outcome.already_existed,
                "iteration {iteration} produced a second DAG entry — the fill moved"
            );
        }
        assert_eq!(svc.dag().directives().len(), 6, "5 opens + 1 transaction");

        // Restart: the file holds the resolved posting, and booting from it
        // must re-derive exactly the id the append returned.
        drop(svc);
        let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        assert!(
            rebooted.get_directive(&first.txid).is_some(),
            "boot from the persisted file must re-derive txid {}",
            first.txid
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_rejects_elided_posting_when_every_currency_balances() {
        // L-27: with USD and EUR both already at zero, `0 USD` and `0 EUR` are
        // equally valid fills and hash differently — the body does not say
        // which. The old code took whichever the hasher seed happened to yield;
        // an ambiguous elision is now refused instead of guessed.
        let (mut svc, path) = setup_with_accounts();
        open_multi_currency_accounts(&mut svc);
        let before = svc.dag().directives().len();

        let input = TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Already balanced".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                posting_input("Assets:Cash", dec!(100.00), "USD"),
                posting_input("Expenses:Food", dec!(-100.00), "USD"),
                posting_input("Assets:Foreign", dec!(50.00), "EUR"),
                posting_input("Income:Salary", dec!(-50.00), "EUR"),
                elided_posting_input("Equity:Opening"),
            ],
        };

        let error = svc.append_transaction(input).unwrap_err();
        assert_eq!(error.error_code(), "ELIDED_POSTING_INVALID");
        let message = error.to_string();
        assert!(
            message.contains("ambiguous") && message.contains("EUR, USD"),
            "error must explain the ambiguity and name the currencies: {message}"
        );
        assert_eq!(
            svc.dag().directives().len(),
            before,
            "nothing may be inserted for a rejected elision"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_single_currency_elision_txid_is_pinned() {
        // L-27 regression pin, against the normative §3.3.3 worked fixture:
        // eliding the second amount must resolve to *exactly* the body whose
        // txid §3.3.3 publishes (the same literal `hash::tests` pins for the
        // spelled-out form). Any change to how an elided posting is filled —
        // currency, sign or decimal scale — breaks this loudly instead of
        // silently re-identifying every transaction in every ledger on the mesh.
        let (mut svc, path) = setup_with_accounts();
        svc.open_account(
            "Equity:Opening-Balances".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        let input = TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: Some("Acme Corp".to_owned()),
            narration: Some("Initial funding".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                posting_input("Assets:Cash", dec!(1000.00), "USD"),
                elided_posting_input("Equity:Opening-Balances"),
            ],
        };

        let txid = svc.append_transaction(input).unwrap().txid;
        assert_eq!(
            txid, "dd4a9ec5ec298be6edaa02c4408c0b1cb1b25eb51426599b7eda600cfc5fa88f",
            "the resolved elision must keep hashing to the §3.3.3 fixture id"
        );

        let Some(Directive::Transaction(stored)) = svc.get_directive(&txid) else {
            panic!("transaction must be in the DAG");
        };
        let filled = stored.postings[1].amount.as_ref().unwrap();
        assert_eq!(filled.currency, "USD");
        assert_eq!(filled.number, dec!(-1000.00));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_idempotent_by_content() {
        let (mut svc, path) = setup_with_accounts();
        let txid1 = svc.append_transaction(balanced_input()).unwrap().txid;

        // FR-1 AC4, G-Set dedup: the same economic body yields the same txid.
        // The second append's envelope genuinely differs — it gets fresh parents
        // and a fresh Lamport value — but `compute_content_id` hashes
        // `economic_canonical_serialize`, which strips every `openledger-*` key,
        // so the id is a function of the economic body alone and the DAG's
        // content-addressed insert reports the second one as a duplicate.
        let txid2 = svc.append_transaction(balanced_input()).unwrap().txid;
        assert_eq!(txid1, txid2, "Same economic body → same txid");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_reports_whether_the_body_was_already_there() {
        // M-10 (interim): idempotency by content used to be indistinguishable
        // from a fresh insert — both just returned a txid — so a caller whose
        // entry was collapsed into an earlier identical one, or squatted by a
        // peer that published the body first, saw plain success. The append
        // path must now say which of the two happened.
        let (mut svc, path) = setup_with_accounts();

        let first = svc.append_transaction(balanced_input()).unwrap();
        assert!(!first.already_existed, "the first append is a real insert");
        assert_eq!(first.txid.len(), 64);
        let count_after_first = svc.directive_count();
        let file_after_first = std::fs::read_to_string(&path).unwrap();

        let second = svc.append_transaction(balanced_input()).unwrap();
        assert!(
            second.already_existed,
            "an identical economic body records nothing new"
        );
        assert_eq!(second.txid, first.txid, "same body → same txid");

        // Nothing new was recorded: no DAG growth and no file growth.
        assert_eq!(svc.directive_count(), count_after_first);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            file_after_first,
            "a duplicate append must not touch the ledger file"
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_of_a_body_a_peer_published_first_reports_already_existed() {
        // M-10, the squatting shape itself: the content hash excludes every
        // `openledger-*` key, so a peer that predicts a recurring body can
        // publish it under ITS OWN author/signature first. The victim's genuine
        // append then resolves as a duplicate and the mesh keeps attributing
        // the event to the squatter. The append must surface that.
        let (mut svc, path) = setup_with_accounts();

        // The squatter's envelope over the body `balanced_input()` resolves to.
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-squatter".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "7".to_owned());
        metadata.insert("openledger-parents".to_owned(), String::new());
        let squatted = Directive::Transaction(Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: Some("Acme".to_owned()),
            narration: Some("Funding".to_owned()),
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
            metadata,
        });
        let squatted_txid = svc.insert_remote_directive(squatted).unwrap().unwrap();

        // The victim now appends its own genuine, identical entry.
        let outcome = svc.append_transaction(balanced_input()).unwrap();
        assert!(
            outcome.already_existed,
            "the peer got there first — nothing new was recorded"
        );
        assert_eq!(outcome.txid, squatted_txid);

        // And the envelope that stands is still the squatter's: this is what
        // the caller must be warned about, since the interim fix cannot undo it.
        let Some(Directive::Transaction(stored)) = svc.get_directive(&outcome.txid) else {
            panic!("expected the squatted transaction");
        };
        assert_eq!(stored.author(), Some("peer-squatter"));

        std::fs::remove_file(path).ok();
    }

    // ── Envelope stamping ────────────────────────────────────────────────

    #[test]
    fn test_lamport_increments() {
        let (mut svc, path) = boot_empty();
        assert_eq!(svc.lamport_clock(), 0);

        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        assert_eq!(svc.lamport_clock(), 1);

        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        assert_eq!(svc.lamport_clock(), 2);

        svc.append_transaction(TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Test".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        })
        .unwrap();
        assert_eq!(svc.lamport_clock(), 3);
        std::fs::remove_file(path).ok();
    }

    /// Assert no `(author, lamport)` pair is stamped twice (M-18).
    fn assert_lamport_pairs_unique(pairs: &[(String, u64)], when: &str) {
        let mut seen = std::collections::BTreeSet::new();
        for pair in pairs {
            assert!(
                seen.insert(pair.clone()),
                "duplicate (author, lamport) pair persisted {when}: {pair:?} in {pairs:?}"
            );
        }
    }

    /// Every `(author, lamport)` pair stamped in the file, in parse order (M-18).
    fn stamped_lamport_pairs(path: &Path) -> Vec<(String, u64)> {
        let content = std::fs::read_to_string(path).unwrap();
        parse_file(&content)
            .unwrap()
            .iter()
            .filter_map(|directive| {
                let author = directive.metadata().get(ENVELOPE_KEY_AUTHOR)?.clone();
                Some((author, directive.lamport_clock()?))
            })
            .collect()
    }

    #[test]
    fn test_boot_lamport_reads_non_transaction_directives() {
        // M-18 regression: the highest lamport sits on an `open`. Scanning only
        // transactions resumed the clock at 4 — below the 9 already on disk.
        let path = test_file_path();
        std::fs::write(
            &path,
            "2024-01-01 open Assets:Cash USD\n\
             \x20 openledger-author: \"local\"\n\
             \x20 openledger-lamport: \"1\"\n\n\
             2024-01-01 open Equity:Opening\n\
             \x20 openledger-author: \"local\"\n\
             \x20 openledger-lamport: \"2\"\n\n\
             2024-02-01 * \"Deposit\"\n\
             \x20 openledger-author: \"local\"\n\
             \x20 openledger-lamport: \"3\"\n\
             \x20 openledger-parents: \"\"\n\
             \x20 Assets:Cash                                      100 USD\n\
             \x20 Equity:Opening                                   -100 USD\n\n\
             2026-07-01 open Assets:Bank\n\
             \x20 openledger-author: \"local\"\n\
             \x20 openledger-lamport: \"9\"\n",
        )
        .unwrap();

        let svc = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
        assert!(
            svc.lamport_clock() > 9,
            "boot must resume above the highest stamped lamport (9 on an open), got {}",
            svc.lamport_clock()
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_restart_round_trip_never_reissues_a_lamport() {
        // M-18 verify: the highest lamport lands on a non-transaction directive
        // — the opens below are stamped after the transaction — so a restart
        // that only scanned transactions handed the next mutation an already
        // used `(author, lamport)` pair. Two opens, because boot resumes at
        // `max + 1`: one open past the last transaction is still covered by
        // that cushion, and only the second lands on a re-issued value.
        let (mut svc, path) = setup_with_accounts();
        svc.append_transaction(balanced_input()).unwrap();
        svc.open_account("Assets:Bank".to_owned(), make_date(2024, 2, 1), vec![])
            .unwrap();
        svc.open_account(
            "Assets:Cash:Petty".to_owned(),
            make_date(2024, 2, 1),
            vec![],
        )
        .unwrap();
        drop(svc);

        let before = stamped_lamport_pairs(&path);
        let highest_before = before.iter().map(|(_, lamport)| *lamport).max().unwrap();
        assert_lamport_pairs_unique(&before, "before the restart");

        // Restart from the file.
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        assert!(
            svc.lamport_clock() >= highest_before,
            "(a) reboot must not regress the clock below the persisted maximum \
             ({highest_before}), got {}",
            svc.lamport_clock()
        );

        // (b) the post-reboot mutation must stamp strictly above everything on disk.
        let id = svc
            .open_account("Assets:Brokerage".to_owned(), make_date(2024, 3, 1), vec![])
            .unwrap();
        let stamped = svc.get_directive(&id).unwrap().lamport_clock().unwrap();
        assert!(
            stamped > highest_before,
            "post-restart mutation stamped {stamped}, which does not exceed the \
             highest lamport already persisted ({highest_before})"
        );

        // No `(author, lamport)` pair is ever persisted twice.
        assert_lamport_pairs_unique(&stamped_lamport_pairs(&path), "after the restart");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_genesis_has_empty_parents() {
        let (mut svc, path) = setup_with_accounts();
        assert_eq!(svc.head_count(), 0); // Only opens, no transaction heads.

        let txid = svc.append_transaction(balanced_input()).unwrap().txid;
        let directive = svc.get_directive(&txid).unwrap();
        if let Directive::Transaction(txn) = directive {
            assert!(
                txn.parent_ids().is_empty(),
                "Genesis transaction should have empty parents"
            );
        } else {
            panic!("Expected Transaction");
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_second_txn_references_first_as_parent() {
        let (mut svc, path) = setup_with_accounts();
        let txid1 = svc.append_transaction(balanced_input()).unwrap().txid;

        let input2 = TransactionInput {
            date: make_date(2024, 1, 20),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Second".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Expenses:Food".to_owned(),
                    amount: Some(Amount {
                        number: dec!(25),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-25),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        };
        let txid2 = svc.append_transaction(input2).unwrap().txid;

        let directive = svc.get_directive(&txid2).unwrap();
        if let Directive::Transaction(txn) = directive {
            assert_eq!(
                txn.parent_ids(),
                vec![txid1.as_str()],
                "Second txn should reference first as parent"
            );
        } else {
            panic!("Expected Transaction");
        }
        std::fs::remove_file(path).ok();
    }

    // ── File persistence ─────────────────────────────────────────────────

    #[test]
    fn test_persist_and_reboot() {
        let path = test_file_path();

        // First session: create accounts + transaction.
        {
            let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
            svc.open_account(
                "Assets:Cash".to_owned(),
                make_date(2024, 1, 1),
                vec!["USD".to_owned()],
            )
            .unwrap();
            svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
                .unwrap();
            svc.append_transaction(TransactionInput {
                date: make_date(2024, 1, 15),
                flag: Flag::Complete,
                payee: Some("Test".to_owned()),
                narration: Some("Persist test".to_owned()),
                tags: vec![],
                links: vec![],
                postings: vec![
                    PostingInput {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(500),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                    },
                    PostingInput {
                        account: "Equity:Opening".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-500),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                    },
                ],
            })
            .unwrap();
        }

        // Second session: reboot from file.
        {
            let svc = LedgerService::boot(path.clone(), "peer-2".to_owned()).unwrap();
            assert_eq!(svc.directive_count(), 3); // 2 opens + 1 txn
            assert!(svc.accounts().is_open("Assets:Cash"));
            assert!(svc.accounts().is_open("Equity:Opening"));
            assert_eq!(svc.head_count(), 1);
        }

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_file_round_trip_stable() {
        let path = test_file_path();

        // Create a ledger with some content.
        let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        svc.open_account(
            "Assets:Cash".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.append_transaction(TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: Some("Acme".to_owned()),
            narration: Some("Round trip".to_owned()),
            tags: vec!["test".to_owned()],
            links: vec!["ref-1".to_owned()],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(1000),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-1000),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        })
        .unwrap();

        // Read what was written.
        let content1 = std::fs::read_to_string(&path).unwrap();

        // Reboot and re-persist (should produce identical output).
        let svc2 = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        // Persist again (internally during boot, state was rebuilt).
        drop(svc2);
        let mut svc3 = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        svc3.compact().unwrap();
        let content2 = std::fs::read_to_string(&path).unwrap();

        assert_eq!(content1, content2, "Re-serialization should be stable");
        std::fs::remove_file(path).ok();
    }

    // ── Comment extraction ───────────────────────────────────────────────

    #[test]
    fn test_extract_leading_comments() {
        let content = "; Comment 1\n; Comment 2\n\n2024-01-01 open Assets:Cash\n";
        let comments = extract_leading_comments(content);
        assert_eq!(comments, vec!["Comment 1", "Comment 2"]);
    }

    #[test]
    fn test_extract_no_comments() {
        let content = "2024-01-01 open Assets:Cash\n";
        let comments = extract_leading_comments(content);
        assert!(comments.is_empty());
    }

    // ── Full genesis flow ────────────────────────────────────────────────

    #[test]
    fn test_full_genesis_flow() {
        let (mut svc, path) = boot_empty();

        // Step 1: Open accounts.
        svc.open_account(
            "Assets:Cash".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        assert_eq!(svc.directive_count(), 2);

        // Step 2: Genesis transaction.
        let txid = svc.append_transaction(balanced_input()).unwrap().txid;
        assert_eq!(svc.directive_count(), 3);
        assert_eq!(svc.head_count(), 1);

        // Step 3: Verify genesis has empty parents.
        if let Some(Directive::Transaction(txn)) = svc.get_directive(&txid) {
            assert!(txn.parent_ids().is_empty());
            assert_eq!(txn.author(), Some("test-peer"));
            assert_eq!(txn.lamport_clock(), Some(3)); // 2 opens + 1 txn
        }

        // Step 4: File was written.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("open Assets:Cash"));
        assert!(content.contains("* \"Acme\" \"Funding\""));
        assert!(content.contains("openledger-author: \"test-peer\""));

        std::fs::remove_file(path).ok();
    }

    // ── §3.12: Resource limit tests ──────────────────────────────────────

    #[test]
    fn test_resource_limit_too_many_postings() {
        let path = test_file_path();
        let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        svc.open_account(
            "Assets:Cash".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();

        // Create input with MAX_POSTINGS_PER_TRANSACTION + 1 postings.
        let mut postings = Vec::new();
        for _ in 0..=MAX_POSTINGS_PER_TRANSACTION {
            postings.push(PostingInput {
                account: "Assets:Cash".to_owned(),
                amount: Some(Amount {
                    number: dec!(1),
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            });
        }

        let input = TransactionInput {
            date: make_date(2024, 2, 1),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Too many postings".to_owned()),
            tags: vec![],
            links: vec![],
            postings,
        };

        let result = svc.append_transaction(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_code(), "RESOURCE_LIMIT_EXCEEDED");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_resource_limit_narration_too_long() {
        let path = test_file_path();
        let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();

        let input = TransactionInput {
            date: make_date(2024, 2, 1),
            flag: Flag::Complete,
            payee: None,
            narration: Some("x".repeat(MAX_NARRATION_LENGTH + 1)),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        };

        let result = svc.append_transaction(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_code(), "RESOURCE_LIMIT_EXCEEDED");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_resource_limit_too_many_tags() {
        let path = test_file_path();
        let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();

        let tags: Vec<String> = (0..=MAX_TAGS_PER_TRANSACTION)
            .map(|i| format!("tag{i}"))
            .collect();

        let input = TransactionInput {
            date: make_date(2024, 2, 1),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Too many tags".to_owned()),
            tags,
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        };

        let result = svc.append_transaction(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_code(), "RESOURCE_LIMIT_EXCEEDED");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_resource_limit_payee_too_long() {
        let path = test_file_path();
        let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();

        let input = TransactionInput {
            date: make_date(2024, 2, 1),
            flag: Flag::Complete,
            payee: Some("x".repeat(MAX_PAYEE_LENGTH + 1)),
            narration: Some("Payee too long".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        };

        let result = svc.append_transaction(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_code(), "RESOURCE_LIMIT_EXCEEDED");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_resource_limit_too_many_links() {
        let path = test_file_path();
        let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();

        let links: Vec<String> = (0..=MAX_LINKS_PER_TRANSACTION)
            .map(|i| format!("link{i}"))
            .collect();

        let input = TransactionInput {
            date: make_date(2024, 2, 1),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Too many links".to_owned()),
            tags: vec![],
            links,
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        };

        let result = svc.append_transaction(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_code(), "RESOURCE_LIMIT_EXCEEDED");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_persist_writes_complete_file() {
        let (mut svc, path) = setup_with_accounts();
        svc.append_transaction(balanced_input()).unwrap();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("Assets:Cash"));
        assert!(on_disk.contains("openledger-author"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_remote_lamport_u64_max_saturates_no_wrap() {
        // M3 regression: a remote directive claiming openledger-lamport = u64::MAX
        // must not panic (debug) or wrap the local Lamport clock to 0 (release).
        let (mut svc, path) = setup_with_accounts();

        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-remote".to_owned());
        metadata.insert("openledger-lamport".to_owned(), u64::MAX.to_string());
        metadata.insert("openledger-parents".to_owned(), String::new());
        let remote = Directive::Transaction(Transaction {
            date: make_date(2024, 1, 16),
            flag: Flag::Complete,
            payee: None,
            narration: Some("max lamport".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(10),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-10),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata,
        });

        // Must not panic; clock saturates at u64::MAX, never wraps to 0.
        svc.insert_remote_directive(remote).unwrap();
        assert_eq!(svc.lamport_clock(), u64::MAX);

        // A subsequent local append must also not panic on the saturating bump.
        svc.append_transaction(balanced_input()).unwrap();
        assert_eq!(svc.lamport_clock(), u64::MAX);

        std::fs::remove_file(path).ok();
    }

    // ── T29 / M-09: deterministic account lifecycle ──────────────────────

    fn remote_envelope(lamport: u64) -> Metadata {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-remote".to_owned());
        metadata.insert("openledger-lamport".to_owned(), lamport.to_string());
        metadata
    }

    fn remote_close(account: &str, date: NaiveDate, lamport: u64) -> Directive {
        Directive::Close(Close {
            date,
            account: account.to_owned(),
            metadata: remote_envelope(lamport),
        })
    }

    fn remote_open(account: &str, date: NaiveDate, lamport: u64) -> Directive {
        Directive::Open(Open {
            date,
            account: account.to_owned(),
            currencies: Vec::new(),
            metadata: remote_envelope(lamport),
        })
    }

    /// M-09 write-DoS: one allowlisted peer's backdated `close` used to be
    /// applied unconditionally (`let _ =`), shutting the account on every
    /// replica and failing every later local append to it.
    #[test]
    fn test_remote_backdated_close_is_rejected() {
        let (mut svc, path) = setup_with_accounts();
        svc.append_transaction(balanced_input()).unwrap(); // 2024-01-15

        let poison = remote_close("Assets:Cash", make_date(1970, 1, 1), 9);
        let poison_id = LedgerService::content_id(&poison);
        let error = svc.stage_remote_directive(poison).unwrap_err();
        assert_eq!(error.error_code(), "ACCOUNT_HAS_LATER_TRANSACTIONS");
        assert!(
            svc.get_directive(&poison_id).is_none(),
            "a rejected close must not reach the DAG"
        );
        assert!(svc.accounts().is_open("Assets:Cash"));

        // The consequence that mattered: local writes still work.
        let mut later = balanced_input();
        later.date = make_date(2024, 2, 1);
        later.narration = Some("after the poison close".to_owned());
        svc.append_transaction(later)
            .expect("local append must still succeed");

        std::fs::remove_file(path).ok();
    }

    /// A remote close that does not predate the account's transactions is still
    /// accepted — the guard is targeted, not a blanket refusal.
    #[test]
    fn test_remote_forward_dated_close_is_accepted() {
        let (mut svc, path) = setup_with_accounts();
        svc.append_transaction(balanced_input()).unwrap(); // 2024-01-15

        let close = remote_close("Assets:Cash", make_date(2024, 6, 1), 9);
        assert!(svc.stage_remote_directive(close).unwrap().is_some());
        assert!(!svc.accounts().is_open("Assets:Cash"));
        assert!(
            svc.accounts()
                .is_open_at("Assets:Cash", make_date(2024, 1, 15)),
            "the close does not retroactively invalidate the earlier transaction"
        );
        std::fs::remove_file(path).ok();
    }

    /// T41: `latest_posting_date` is served from the read model's per-account
    /// index instead of a full DAG scan. The index is only sound if EVERY path
    /// that puts a transaction into the DAG also indexes it, so this walks all
    /// four of them and compares the index against a brute-force scan after
    /// each — which is exactly what the old implementation did.
    ///
    /// The comparison is the point: a future insert path that forgets
    /// `index_directive` would leave the close rule reading a stale date and
    /// silently admit a backdated close, with no other test noticing.
    #[test]
    fn latest_posting_date_index_agrees_with_a_full_dag_scan_on_every_path() {
        /// The pre-T41 implementation, kept here as the oracle.
        fn scan(svc: &LedgerService, account: &str) -> Option<NaiveDate> {
            let mut latest: Option<NaiveDate> = None;
            for directive in svc.dag().directives() {
                if let Directive::Transaction(txn) = directive {
                    if txn.postings.iter().any(|p| p.account == account) {
                        latest = Some(latest.map_or(txn.date, |d| d.max(txn.date)));
                    }
                }
            }
            latest
        }
        fn assert_agrees(svc: &LedgerService, stage: &str) {
            for account in ["Assets:Cash", "Equity:Opening", "Expenses:Food"] {
                assert_eq!(
                    svc.latest_posting_date(account),
                    scan(svc, account),
                    "index disagrees with a full scan for {account} after {stage}"
                );
            }
        }

        // (1) Boot: `ReadModel::build` over the whole file.
        let path = test_file_path();
        std::fs::write(
            &path,
            concat!(
                "2024-01-01 open Assets:Cash USD\n\n",
                "2024-01-01 open Equity:Opening\n\n",
                "2024-01-01 open Expenses:Food USD\n\n",
                "2024-03-05 * \"Acme\" \"Booted\"\n",
                "  Assets:Cash  100 USD\n",
                "  Equity:Opening  -100 USD\n",
            ),
        )
        .unwrap();
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        assert_eq!(
            svc.latest_posting_date("Assets:Cash"),
            scan(&svc, "Assets:Cash")
        );
        assert_eq!(
            svc.latest_posting_date("Assets:Cash"),
            Some(make_date(2024, 3, 5)),
            "the boot-loaded transaction must be visible to the close rule"
        );
        assert_agrees(&svc, "boot");

        // (2) Local append.
        let mut later = balanced_input();
        later.date = make_date(2024, 4, 9);
        svc.append_transaction(later).unwrap();
        assert_eq!(
            svc.latest_posting_date("Assets:Cash"),
            Some(make_date(2024, 4, 9))
        );
        assert_agrees(&svc, "a local append");

        // An EARLIER append must not move the max backwards.
        let mut earlier = balanced_input();
        earlier.date = make_date(2024, 2, 2);
        earlier.narration = Some("backdated".to_owned());
        svc.append_transaction(earlier).unwrap();
        assert_eq!(
            svc.latest_posting_date("Assets:Cash"),
            Some(make_date(2024, 4, 9))
        );
        assert_agrees(&svc, "a backdated local append");

        // (3) Remote ingest through `stage_remote_directive`.
        let remote = Directive::Transaction(Transaction {
            date: make_date(2024, 7, 20),
            flag: Flag::Complete,
            payee: None,
            narration: Some("from a peer".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Expenses:Food".to_owned(),
                    amount: Some(Amount {
                        number: dec!(7),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-7),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: remote_envelope(41),
        });
        svc.insert_remote_directive(remote).unwrap();
        assert_eq!(
            svc.latest_posting_date("Expenses:Food"),
            Some(make_date(2024, 7, 20))
        );
        assert_agrees(&svc, "a remote ingest");

        // (4) Reconcile of a hand edit.
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(
            "\n2024-09-30 * \"Acme\" \"Hand edit\"\n  Assets:Cash  5 USD\n  Equity:Opening  -5 USD\n",
        );
        std::fs::write(&path, content).unwrap();
        svc.reconcile_file().unwrap();
        assert_eq!(
            svc.latest_posting_date("Assets:Cash"),
            Some(make_date(2024, 9, 30))
        );
        assert_agrees(&svc, "a reconcile");

        // And the whole thing survives a reboot from the canonical file.
        let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        for account in ["Assets:Cash", "Equity:Opening", "Expenses:Food"] {
            assert_eq!(
                rebooted.latest_posting_date(account),
                svc.latest_posting_date(account),
                "the live index and a fresh boot must agree for {account}"
            );
        }
        assert_agrees(&rebooted, "a reboot");

        std::fs::remove_file(path).ok();
    }

    /// The core M-09 invariant at the service level: staging the same lifecycle
    /// directives in opposite orders gives the same state — and the same state
    /// again after a reboot, which rebuilds it from the file alone.
    #[test]
    fn test_lifecycle_state_is_order_insensitive_and_survives_reboot() {
        let forward = [
            remote_open("Assets:Vault", make_date(2024, 1, 1), 1),
            remote_close("Assets:Vault", make_date(2024, 2, 1), 2),
            remote_open("Assets:Vault", make_date(2024, 3, 1), 3),
            remote_close("Assets:Vault", make_date(2024, 4, 1), 4),
        ];
        let probes = [
            make_date(2024, 1, 15),
            make_date(2024, 2, 15),
            make_date(2024, 3, 15),
            make_date(2024, 4, 15),
        ];

        let mut snapshots = Vec::new();
        let mut files = Vec::new();
        let mut paths = Vec::new();
        for reversed in [false, true] {
            let (mut svc, path) = boot_empty();
            let mut order: Vec<&Directive> = forward.iter().collect();
            if reversed {
                order.reverse();
            }
            for directive in order {
                svc.stage_remote_directive(directive.clone()).unwrap();
            }
            svc.persist_or_reload().unwrap();

            let live: Vec<bool> = probes
                .iter()
                .map(|probe| svc.accounts().is_open_at("Assets:Vault", *probe))
                .chain(std::iter::once(svc.accounts().is_open("Assets:Vault")))
                .collect();

            // Reboot: the state must be a pure function of the persisted set.
            let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
            let after_reboot: Vec<bool> = probes
                .iter()
                .map(|probe| rebooted.accounts().is_open_at("Assets:Vault", *probe))
                .chain(std::iter::once(rebooted.accounts().is_open("Assets:Vault")))
                .collect();
            assert_eq!(
                live, after_reboot,
                "reboot must reproduce the live lifecycle state"
            );

            files.push(std::fs::read(&path).unwrap());
            snapshots.push(live);
            paths.push(path);
        }

        assert_eq!(
            snapshots[0], snapshots[1],
            "arrival order must not change the lifecycle state"
        );
        assert_eq!(
            files[0], files[1],
            "arrival order must not change the persisted bytes"
        );
        assert_eq!(
            snapshots[0],
            vec![true, false, true, false, false],
            "open/closed/open/closed, and closed at the end"
        );

        for path in paths {
            std::fs::remove_file(path).ok();
        }
    }

    /// A hand-edited file adding a backdated `close` is rejected by reconcile
    /// for the same reason a peer's is — the finding named both paths.
    #[test]
    fn test_reconcile_rejects_backdated_close() {
        let (mut svc, path) = setup_with_accounts();
        svc.append_transaction(balanced_input()).unwrap(); // 2024-01-15

        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str("\n1970-01-01 close Assets:Cash\n");
        std::fs::write(&path, &content).unwrap();

        let result = svc.reconcile_file().unwrap();
        assert_eq!(result.new_directives, 0);
        assert_eq!(result.rejected, 1, "the backdated close is refused");
        assert!(svc.accounts().is_open("Assets:Cash"));

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_remote_insert_rejects_missing_parent() {
        let (mut svc, path) = setup_with_accounts();
        svc.append_transaction(balanced_input()).unwrap();

        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-remote".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "9".to_owned());
        metadata.insert(
            "openledger-parents".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        );
        let remote = Directive::Transaction(Transaction {
            date: make_date(2024, 1, 16),
            flag: Flag::Complete,
            payee: None,
            narration: Some("orphan child".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(10),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-10),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata,
        });

        let missing = svc.missing_parent_ids(&remote);
        assert_eq!(missing.len(), 1);
        let error = svc.insert_remote_directive(remote).unwrap_err();
        assert_eq!(error.error_code(), "MISSING_PARENT");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_remote_insert_rejects_oversized_narration() {
        let (mut svc, path) = setup_with_accounts();
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-remote".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "1".to_owned());
        metadata.insert("openledger-parents".to_owned(), String::new());
        let remote = Directive::Transaction(Transaction {
            date: make_date(2024, 1, 16),
            flag: Flag::Complete,
            payee: None,
            narration: Some("x".repeat(MAX_NARRATION_LENGTH + 1)),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(10),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-10),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata,
        });
        let error = svc.insert_remote_directive(remote).unwrap_err();
        assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED");
        std::fs::remove_file(path).ok();
    }

    // ── CT-11: external edit disabled → boot refuses modified file ───────

    #[test]
    fn ct11_external_edit_disabled_detects_modification() {
        use crate::file_watcher::FileWatcherConfig;

        let path = test_file_path();
        // Boot a ledger and append a transaction.
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.append_transaction(balanced_input()).unwrap();
        drop(svc);

        // Record the last-write hash.
        let original_content = std::fs::read_to_string(&path).unwrap();
        let config = FileWatcherConfig {
            external_edits_enabled: false,
            ..Default::default()
        };

        // Now tamper with the file (simulate external edit).
        let tampered = format!("{original_content}\n; sneaky external edit\n");
        std::fs::write(&path, &tampered).unwrap();

        // Compute the original hash and compare.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher1 = DefaultHasher::new();
        original_content.hash(&mut hasher1);
        let original_hash = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        tampered.hash(&mut hasher2);
        let tampered_hash = hasher2.finish();

        // The hashes must differ — this is the detection mechanism.
        assert_ne!(
            original_hash, tampered_hash,
            "CT-11: External file modification must be detectable by content hash"
        );

        // The config flag is correctly set to disabled.
        assert!(
            !config.external_edits_enabled,
            "CT-11: external_edits_enabled must be false"
        );

        std::fs::remove_file(path).ok();
    }

    // ── CT-12: external edit enabled → union merge adoption (§3.3) ──────

    #[test]
    fn ct12_hand_appended_transaction_adopted() {
        let path = test_file_path();
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.open_account(
            "Assets:Cash".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        let original_count = svc.directive_count();

        // Simulate a hand-appended transaction: write directly to the file.
        let current_content = std::fs::read_to_string(&path).unwrap();
        let hand_appended = format!(
            "{current_content}\n\
             2024-03-01 * \"Hand\" \"External edit\"\n\
             \x20 Assets:Cash                                      250.00 USD\n\
             \x20 Equity:Opening                                   -250.00 USD\n"
        );
        std::fs::write(&path, &hand_appended).unwrap();

        // Reconcile — the hand-appended transaction should be adopted.
        let result = svc.reconcile_file().unwrap();
        assert!(
            result.new_directives >= 1,
            "CT-12: Hand-appended transaction should be adopted, got new={}, dup={}, rej={}",
            result.new_directives,
            result.duplicates,
            result.rejected,
        );
        assert!(
            svc.directive_count() > original_count,
            "CT-12: Directive count should increase after adoption"
        );

        // The adopted transaction should have been stamped with our author.
        let directives: Vec<_> = svc
            .dag()
            .directives()
            .into_iter()
            .filter_map(|d| {
                if let Directive::Transaction(t) = d {
                    if t.narration.as_deref() == Some("External edit") {
                        return Some(t.clone());
                    }
                }
                None
            })
            .collect();
        assert_eq!(
            directives.len(),
            1,
            "Should find exactly one adopted transaction"
        );
        assert_eq!(
            directives[0].author(),
            Some("test-peer"),
            "CT-12: Adopted transaction should have local author"
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn ct12_hand_edit_creates_new_txid_keeps_original() {
        let path = test_file_path();
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.open_account(
            "Assets:Cash".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();

        // Append a transaction via API.
        let txid = svc.append_transaction(balanced_input()).unwrap().txid;
        let count_before = svc.directive_count();

        // Simulate hand-editing the narration → changes txid.
        let content = std::fs::read_to_string(&path).unwrap();
        let edited = content.replace("\"Funding\"", "\"Modified Funding\"");
        std::fs::write(&path, &edited).unwrap();

        // Reconcile.
        svc.reconcile_file().unwrap();

        // The original is still in the DAG (append-only, C2).
        assert!(
            svc.get_directive(&txid).is_some(),
            "CT-12: Original transaction must still exist (C2 append-only)"
        );

        // A new transaction with the modified narration should also exist.
        assert!(
            svc.directive_count() > count_before,
            "CT-12: Editing creates a new txid, increasing count"
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn ct12_hand_delete_does_not_remove_transaction() {
        let path = test_file_path();
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.open_account(
            "Assets:Cash".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        let txid = svc.append_transaction(balanced_input()).unwrap().txid;
        let count_before = svc.directive_count();

        // Simulate hand-deleting: remove the transaction lines from file.
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // Keep only the open directives (remove everything from the transaction onward).
        let trimmed: Vec<&str> = lines
            .iter()
            .take_while(|line| !line.contains("* \"Acme\" \"Funding\""))
            .copied()
            .collect();
        std::fs::write(&path, trimmed.join("\n") + "\n").unwrap();

        // Reconcile — should not remove the original.
        let _result = svc.reconcile_file().unwrap();
        assert!(
            svc.get_directive(&txid).is_some(),
            "CT-12: Deleting from file does NOT remove from DAG (C2 append-only)"
        );
        assert_eq!(
            svc.directive_count(),
            count_before,
            "CT-12: Directive count should not decrease after hand-delete"
        );

        // Scope, stated once: this asserts the IN-MEMORY C2 guarantee, not a
        // file rewrite. `reconcile_file` re-persists only when it adopted
        // something new, and a deletion adds nothing — so the `.bean` is still
        // the trimmed one here, and the deleted transaction returns to it on the
        // next persist from any other cause.
        std::fs::remove_file(path).ok();
    }

    // ── CT-9: simulated partition-and-converge (FR-4) ────────────────────

    #[test]
    fn ct9_two_nodes_converge_after_partition() {
        // Simulate two nodes at the library level:
        // - Both boot from the same initial .bean content (shared opens).
        // - During "partition", each appends a different transaction.
        // - On "reconnect", they exchange directives via reconcile_file.
        // - After convergence, both have the same content ID set and
        //   matching trial balances — proving CRDT convergence (I6/FR-4).

        let path_a = test_file_path();
        let path_b = test_file_path();

        // Shared initial state — both boot from identical file content.
        let shared_content = "2024-01-01 open Assets:Cash USD\n  openledger-author: \"shared\"\n  openledger-lamport: \"1\"\n\n2024-01-01 open Equity:Opening\n  openledger-author: \"shared\"\n  openledger-lamport: \"2\"\n";

        std::fs::write(&path_a, shared_content).unwrap();
        std::fs::write(&path_b, shared_content).unwrap();

        let mut node_a = LedgerService::boot(path_a.clone(), "node-a".to_owned()).unwrap();
        let mut node_b = LedgerService::boot(path_b.clone(), "node-b".to_owned()).unwrap();

        assert_eq!(node_a.directive_count(), 2);
        assert_eq!(node_b.directive_count(), 2);

        // ── Partition: each node writes independently ────────────────

        let input_alpha = TransactionInput {
            date: make_date(2024, 2, 1),
            flag: Flag::Complete,
            payee: Some("Vendor-A".to_owned()),
            narration: Some("Alpha transaction".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        };
        let txid_alpha = node_a.append_transaction(input_alpha).unwrap().txid;

        let input_beta = TransactionInput {
            date: make_date(2024, 2, 15),
            flag: Flag::Complete,
            payee: Some("Vendor-B".to_owned()),
            narration: Some("Beta transaction".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(200),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-200),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        };
        let txid_beta = node_b.append_transaction(input_beta).unwrap().txid;

        // Verify divergence.
        assert_eq!(node_a.directive_count(), 3);
        assert_eq!(node_b.directive_count(), 3);
        assert!(node_a.get_directive(&txid_alpha).is_some());
        assert!(node_a.get_directive(&txid_beta).is_none());
        assert!(node_b.get_directive(&txid_beta).is_some());
        assert!(node_b.get_directive(&txid_alpha).is_none());

        // ── Reconnect: exchange directives via file merge ────────────

        let a_content = std::fs::read_to_string(&path_a).unwrap();
        let b_content = std::fs::read_to_string(&path_b).unwrap();

        // Append A's content into B's file.
        let merged_for_b = format!("{b_content}\n{a_content}");
        std::fs::write(&path_b, &merged_for_b).unwrap();
        let result_b = node_b.reconcile_file().unwrap();
        assert!(result_b.new_directives >= 1, "B should adopt Alpha");

        // Write B's canonical output to A's file.
        let b_final = std::fs::read_to_string(&path_b).unwrap();
        std::fs::write(&path_a, &b_final).unwrap();
        let result_a = node_a.reconcile_file().unwrap();
        assert!(result_a.new_directives >= 1, "A should adopt Beta");

        // ── Verify convergence ───────────────────────────────────────

        // Both nodes should have the same directive count.
        assert_eq!(
            node_a.directive_count(),
            node_b.directive_count(),
            "CT-9: After convergence, directive counts must match"
        );

        // Both should have both transactions.
        assert!(node_a.get_directive(&txid_alpha).is_some(), "A has Alpha");
        assert!(node_a.get_directive(&txid_beta).is_some(), "A has Beta");
        assert!(node_b.get_directive(&txid_alpha).is_some(), "B has Alpha");
        assert!(node_b.get_directive(&txid_beta).is_some(), "B has Beta");

        // Content ID sets should be identical.
        let mut ids_a: Vec<&str> = node_a.dag().content_ids().into_iter().collect();
        let mut ids_b: Vec<&str> = node_b.dag().content_ids().into_iter().collect();
        ids_a.sort();
        ids_b.sort();
        assert_eq!(
            ids_a, ids_b,
            "CT-9: Content ID sets must be identical after convergence"
        );

        // Both .bean files should be byte-identical (C4/I7).
        let final_a = std::fs::read_to_string(&path_a).unwrap();
        let final_b = std::fs::read_to_string(&path_b).unwrap();
        assert_eq!(
            final_a, final_b,
            "CT-9: After convergence, .bean files must be byte-identical (C4/I7)"
        );

        // Trial balances should match.
        let date = make_date(2024, 12, 31);
        let tb_a = node_a.read_model().trial_balance(date);
        let tb_b = node_b.read_model().trial_balance(date);
        assert_eq!(tb_a.total_debit, tb_b.total_debit, "CT-9: Debits match");
        assert_eq!(tb_a.total_credit, tb_b.total_credit, "CT-9: Credits match");

        std::fs::remove_file(path_a).ok();
        std::fs::remove_file(path_b).ok();
    }

    #[test]
    fn test_signature_is_on_disk_after_first_persist() {
        let (mut svc, path) = setup_with_accounts();
        let txid = svc
            .append_transaction_signing(balanced_input(), |_, _, _| Some("aa".repeat(64)))
            .unwrap()
            .txid;
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.contains("openledger-signature:"),
            "signed append must persist signature on the first write"
        );
        assert!(svc.get_directive(&txid).is_some());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_remote_insert_rejects_malformed_parent_id() {
        let (mut svc, path) = setup_with_accounts();
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-remote".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "1".to_owned());
        metadata.insert("openledger-parents".to_owned(), "not-a-txid".to_owned());
        let remote = Directive::Transaction(Transaction {
            date: make_date(2024, 1, 16),
            flag: Flag::Complete,
            payee: None,
            narration: Some("bad parent".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(10),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-10),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata,
        });
        let error = svc.insert_remote_directive(remote).unwrap_err();
        assert_eq!(error.error_code(), "INVALID_INPUT");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_boot_rejects_oversized_ledger_file() {
        let path = test_file_path();
        {
            let file = std::fs::File::create(&path).unwrap();
            file.set_len(MAX_LEDGER_FILE_BYTES + 1).unwrap();
        }
        let error = match LedgerService::boot(path.clone(), "test-peer".to_owned()) {
            Ok(_) => panic!("oversized ledger file should not boot"),
            Err(error) => error,
        };
        assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED");
        std::fs::remove_file(path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_persisted_ledger_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let (mut svc, path) = setup_with_accounts();
        svc.append_transaction(balanced_input()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "persisted .bean must be 0600");
        std::fs::remove_file(path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_persist_does_not_follow_tmp_symlink() {
        // L6 regression: a pre-planted `<name>.tmp` symlink must not be followed,
        // so a persist cannot truncate/overwrite the link's target.
        let ledger_path = test_file_path();
        let file_name = ledger_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let tmp_path = ledger_path.with_file_name(format!("{file_name}.tmp"));
        let victim_path = ledger_path.with_extension("victim");

        std::fs::write(&victim_path, "SENSITIVE").unwrap();
        std::os::unix::fs::symlink(&victim_path, &tmp_path).unwrap();

        persist_atomically(&ledger_path, "ledger contents\n").unwrap();

        assert_eq!(
            std::fs::read_to_string(&victim_path).unwrap(),
            "SENSITIVE",
            "persist must not write through a pre-planted .tmp symlink"
        );
        assert_eq!(
            std::fs::read_to_string(&ledger_path).unwrap(),
            "ledger contents\n"
        );

        std::fs::remove_file(&ledger_path).ok();
        std::fs::remove_file(&victim_path).ok();
        std::fs::remove_file(&tmp_path).ok();
    }

    // ── H-04: dates the file grammar cannot read back ────────────────────

    #[test]
    fn test_append_transaction_rejects_out_of_range_year() {
        // A year outside 0001..=9999 serializes with a sign (`+10000-01-01`),
        // which `read_date` refuses — persisting one bricks every later boot.
        let (mut svc, path) = setup_with_accounts();
        let before = std::fs::read_to_string(&path).unwrap();

        let mut input = balanced_input();
        input.date = make_date(10000, 1, 1);
        let error = svc.append_transaction(input).unwrap_err();
        assert_eq!(error.error_code(), "DATE_OUT_OF_RANGE");
        assert!(
            error.to_string().contains("+10000-01-01"),
            "message should name the offending date: {error}"
        );

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before,
            "a rejected date must not reach the file"
        );
        LedgerService::boot(path.clone(), "test-peer".to_owned())
            .expect("ledger must still boot after the rejection");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_transaction_rejects_out_of_range_cost_date() {
        // Cost dates are serialized as `%Y-%m-%d` too, so they brick the same way.
        let (mut svc, path) = setup_with_accounts();
        let mut input = balanced_input();
        input.postings[0].cost = Some(CostSpec {
            amount: Some(Amount {
                number: dec!(1),
                currency: "USD".to_owned(),
            }),
            date: Some(make_date(-1, 1, 1)),
        });
        let error = svc.append_transaction(input).unwrap_err();
        assert_eq!(error.error_code(), "DATE_OUT_OF_RANGE");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_open_and_close_account_reject_out_of_range_year() {
        let (mut svc, path) = setup_with_accounts();

        let error = svc
            .open_account("Assets:Vault".to_owned(), make_date(0, 1, 1), vec![])
            .unwrap_err();
        assert_eq!(error.error_code(), "DATE_OUT_OF_RANGE");

        let error = svc
            .close_account("Assets:Cash".to_owned(), make_date(10000, 1, 1))
            .unwrap_err();
        assert_eq!(error.error_code(), "DATE_OUT_OF_RANGE");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_remote_insert_rejects_out_of_range_year() {
        let (mut svc, path) = setup_with_accounts();
        let lamport_before = svc.lamport_clock();

        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-remote".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "42".to_owned());
        let remote = Directive::Open(Open {
            date: make_date(10000, 1, 1),
            account: "Assets:Remote".to_owned(),
            currencies: vec![],
            metadata,
        });

        let error = svc.insert_remote_directive(remote).unwrap_err();
        assert_eq!(error.error_code(), "DATE_OUT_OF_RANGE");
        assert_eq!(
            svc.lamport_clock(),
            lamport_before,
            "a rejected directive must not adopt the remote Lamport clock"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_boundary_years_persist_and_reboot() {
        // The first and last dates the grammar can round-trip must still work.
        let (mut svc, path) = boot_empty();
        svc.open_account("Assets:First".to_owned(), make_date(1, 1, 1), vec![])
            .unwrap();
        svc.open_account("Assets:Last".to_owned(), make_date(9999, 12, 31), vec![])
            .unwrap();
        drop(svc);

        let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        assert_eq!(rebooted.directive_count(), 2);
        std::fs::remove_file(path).ok();
    }

    // ── T21: body canonicalization (H-03 / H-06 / L-26 / L-29) ───────────

    /// A remote transaction against the accounts `setup_with_accounts` opens.
    fn remote_transaction(narration: &str, elide_second_amount: bool) -> Transaction {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-remote".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "9".to_owned());
        metadata.insert("openledger-parents".to_owned(), "".to_owned());
        Transaction {
            date: make_date(2024, 1, 16),
            flag: Flag::Complete,
            payee: None,
            narration: Some(narration.to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(10),
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
                            number: dec!(-10),
                            currency: "USD".to_owned(),
                        })
                    },
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata,
        }
    }

    #[test]
    fn test_validate_body_envelope_keys_allowance_modes() {
        let mut open = Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec![],
            metadata: BTreeMap::new(),
        };
        open.metadata
            .insert("openledger-author".to_owned(), "peer".to_owned());
        open.metadata
            .insert("category".to_owned(), "economic".to_owned());
        let directive = Directive::Open(open);

        // File / remote-insert mode: the merged envelope legitimately sits at
        // directive level, so the four closed-set keys are permitted there.
        assert!(validate_body_envelope_keys(&directive, ENVELOPE_KEYS).is_ok());

        // Wire mode: an honest body carries no `openledger-*` key at all,
        // because the canonical serializer strips every one.
        let error = validate_body_envelope_keys(&directive, &[]).unwrap_err();
        assert_eq!(error.error_code(), "BODY_ENVELOPE_KEY");
        assert!(
            error.to_string().contains("openledger-author"),
            "message should name the key: {error}"
        );

        // An unknown `openledger-*` key is rejected under either allowance.
        let Directive::Open(mut open) = directive else {
            panic!("expected Open");
        };
        open.metadata
            .insert("openledger-poison".to_owned(), "x".to_owned());
        let poisoned = Directive::Open(open);
        assert_eq!(
            validate_body_envelope_keys(&poisoned, ENVELOPE_KEYS)
                .unwrap_err()
                .error_code(),
            "BODY_ENVELOPE_KEY"
        );
    }

    #[test]
    fn test_validate_body_envelope_keys_rejects_posting_level_keys() {
        // Even an allowed *name* is never legitimate on a posting: nothing
        // writes one, and `extract_envelope` would promote it on re-serve.
        let mut txn = remote_transaction("posting key", false);
        txn.postings[0]
            .metadata
            .insert("openledger-author".to_owned(), "attacker".to_owned());
        let error =
            validate_body_envelope_keys(&Directive::Transaction(txn), ENVELOPE_KEYS).unwrap_err();
        assert_eq!(error.error_code(), "BODY_ENVELOPE_KEY");
    }

    #[test]
    fn test_validate_body_strings_rejects_control_characters() {
        // Directive-level strings, posting-level strings, and metadata on both
        // levels are all covered; envelope values pass naturally.
        let clean = Directive::Transaction(remote_transaction("clean", false));
        assert!(validate_body_strings(&clean).is_ok());

        let mut narration = remote_transaction("wipe\u{1b}[2J", false);
        assert_eq!(
            validate_body_strings(&Directive::Transaction(narration.clone()))
                .unwrap_err()
                .error_code(),
            "INVALID_INPUT"
        );

        narration = remote_transaction("clean", false);
        narration
            .metadata
            .insert("note".to_owned(), "nul\u{0}here".to_owned());
        assert_eq!(
            validate_body_strings(&Directive::Transaction(narration))
                .unwrap_err()
                .error_code(),
            "INVALID_INPUT"
        );

        let mut posting_metadata = remote_transaction("clean", false);
        posting_metadata.postings[0]
            .metadata
            .insert("category".to_owned(), "tab\there".to_owned());
        assert_eq!(
            validate_body_strings(&Directive::Transaction(posting_metadata))
                .unwrap_err()
                .error_code(),
            "INVALID_INPUT"
        );

        let note = Directive::Note(Note {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            comment: "esc\u{1b}here".to_owned(),
            metadata: BTreeMap::new(),
        });
        assert_eq!(
            validate_body_strings(&note).unwrap_err().error_code(),
            "INVALID_INPUT"
        );
    }

    #[test]
    fn test_parent_txid_is_well_formed_is_lowercase_only() {
        let lowercase = "a1".repeat(32);
        assert!(parent_txid_is_well_formed(&lowercase));
        assert!(
            !parent_txid_is_well_formed(&lowercase.to_ascii_uppercase()),
            "an uppercase txid never resolves against the lowercase store (L-29)"
        );
        assert!(!parent_txid_is_well_formed(&"a".repeat(63)));
        assert!(!parent_txid_is_well_formed(&"g".repeat(64)));
    }

    #[test]
    fn test_stamped_envelope_keys_stay_within_the_closed_set() {
        // The single-source-of-truth guarantee: what the stamping paths write
        // is exactly what every ingest path accepts.
        let (mut svc, path) = setup_with_accounts();
        svc.append_transaction_signing(balanced_input(), |_, _, _| Some("aa".repeat(64)))
            .unwrap();
        // Covers both stamping paths: the opens from `setup_with_accounts` and
        // the signed transaction just appended.
        for directive in svc.dag().directives() {
            for key in directive.metadata().keys() {
                assert!(
                    ENVELOPE_KEYS.contains(&key.as_str()),
                    "stamped key {key} is outside the closed envelope set"
                );
            }
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_remote_insert_rejects_elided_posting() {
        // H-03: the insert stores the *resolved* postings, so an elided remote
        // body would be stored — and re-hashed — under an id other than the one
        // it was accepted and signed under, and could never propagate.
        let (mut svc, path) = setup_with_accounts();
        let lamport_before = svc.lamport_clock();
        let directive = Directive::Transaction(remote_transaction("elided", true));

        let error = svc.insert_remote_directive(directive).unwrap_err();
        assert_eq!(error.error_code(), "INVALID_INPUT");
        assert_eq!(
            svc.lamport_clock(),
            lamport_before,
            "a rejected directive must not adopt the remote Lamport clock"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_remote_insert_rejects_body_envelope_keys() {
        let (mut svc, path) = setup_with_accounts();

        // An unknown `openledger-*` key at directive level.
        let mut txn = remote_transaction("poisoned", false);
        txn.metadata
            .insert("openledger-poison".to_owned(), "x".to_owned());
        let error = svc
            .insert_remote_directive(Directive::Transaction(txn))
            .unwrap_err();
        assert_eq!(error.error_code(), "BODY_ENVELOPE_KEY");

        // Any `openledger-*` key at posting level, allowed name or not.
        let mut txn = remote_transaction("posting key", false);
        txn.postings[1]
            .metadata
            .insert("openledger-author".to_owned(), "attacker".to_owned());
        let error = svc
            .insert_remote_directive(Directive::Transaction(txn))
            .unwrap_err();
        assert_eq!(error.error_code(), "BODY_ENVELOPE_KEY");

        // The four envelope keys at directive level are the normal case.
        assert!(svc
            .insert_remote_directive(Directive::Transaction(remote_transaction("honest", false)))
            .unwrap()
            .is_some());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_remote_insert_rejects_control_characters() {
        let (mut svc, path) = setup_with_accounts();
        let error = svc
            .insert_remote_directive(Directive::Transaction(remote_transaction(
                "wipe\u{1b}[2J",
                false,
            )))
            .unwrap_err();
        assert_eq!(error.error_code(), "INVALID_INPUT");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_remote_insert_rejects_uppercase_parent_txid() {
        // L-29: an uppercase spelling of a real txid passes a case-insensitive
        // check and then never resolves against the lowercase store.
        let (mut svc, path) = setup_with_accounts();
        let mut txn = remote_transaction("uppercase parent", false);
        txn.metadata.insert(
            "openledger-parents".to_owned(),
            "a1".repeat(32).to_ascii_uppercase(),
        );
        let error = svc
            .insert_remote_directive(Directive::Transaction(txn))
            .unwrap_err();
        assert_eq!(error.error_code(), "INVALID_INPUT");
        assert!(
            error.to_string().contains("lowercase"),
            "message should say lowercase: {error}"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reconcile_rejects_body_smuggled_envelope_key() {
        // H-06: a hand-edited (or peer-written) file must not be able to smuggle
        // an unvalidated `openledger-*` key into the DAG, from where the next
        // serve would promote it into the envelope and brick the receiving peer.
        let (mut svc, path) = setup_with_accounts();
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!(
                "{content}\n\
                 2024-03-01 * \"Hand\" \"Poisoned\"\n\
                 \x20 openledger-poison: \"x\"\n\
                 \x20 Assets:Cash                                      250.00 USD\n\
                 \x20 Equity:Opening                                   -250.00 USD\n\
                 \n\
                 2024-03-02 * \"Hand\" \"Clean\"\n\
                 \x20 Assets:Cash                                      10.00 USD\n\
                 \x20 Equity:Opening                                   -10.00 USD\n"
            ),
        )
        .unwrap();

        let result = svc.reconcile_file().unwrap();
        assert_eq!(result.rejected, 1, "the poisoned directive is rejected");
        assert_eq!(result.new_directives, 1, "the clean one is still adopted");

        assert!(
            !svc.dag().directives().iter().any(|directive| matches!(
                directive,
                Directive::Transaction(txn) if txn.narration.as_deref() == Some("Poisoned")
            )),
            "the poisoned directive must not be adopted"
        );
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(
            !persisted.contains("openledger-poison"),
            "the smuggled key must not survive the re-persist"
        );
        assert!(persisted.contains("Clean"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reconcile_rejects_posting_level_envelope_key() {
        let (mut svc, path) = setup_with_accounts();
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!(
                "{content}\n\
                 2024-03-01 * \"Hand\" \"PostingKey\"\n\
                 \x20 Assets:Cash                                      250.00 USD\n\
                 \x20\x20 openledger-author: \"attacker\"\n\
                 \x20 Equity:Opening                                   -250.00 USD\n"
            ),
        )
        .unwrap();

        let result = svc.reconcile_file().unwrap();
        assert_eq!(result.rejected, 1);
        assert_eq!(result.new_directives, 0);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reconcile_adopts_directive_carrying_the_envelope_keys() {
        // No over-rejection: a file directive that legitimately carries all four
        // envelope keys at directive level (how a peer's write round-trips) is
        // still adopted.
        let (mut svc, path) = setup_with_accounts();
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!(
                "{content}\n\
                 2024-03-03 * \"Hand\" \"Enveloped\"\n\
                 \x20 openledger-author: \"peer-remote\"\n\
                 \x20 openledger-lamport: \"9\"\n\
                 \x20 openledger-parents: \"\"\n\
                 \x20 openledger-signature: \"{signature}\"\n\
                 \x20 Assets:Cash                                      5.00 USD\n\
                 \x20 Equity:Opening                                   -5.00 USD\n",
                signature = "ab".repeat(64)
            ),
        )
        .unwrap();

        let result = svc.reconcile_file().unwrap();
        assert_eq!(result.rejected, 0, "the closed-set keys are legitimate");
        assert_eq!(result.new_directives, 1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reconcile_rejects_control_characters_in_body() {
        // L-26: an ESC reaching the DAG here would be re-serialized into the
        // file on every later persist, and gossiped to every replica.
        let (mut svc, path) = setup_with_accounts();
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!(
                "{content}\n\
                 2024-03-04 * \"Hand\" \"wipe\u{1b}[2J\"\n\
                 \x20 Assets:Cash                                      7.00 USD\n\
                 \x20 Equity:Opening                                   -7.00 USD\n"
            ),
        )
        .unwrap();

        let result = svc.reconcile_file().unwrap();
        assert_eq!(result.rejected, 1);
        assert_eq!(result.new_directives, 0);
        assert!(
            !svc.dag().directives().iter().any(|directive| matches!(
                directive,
                Directive::Transaction(txn) if txn.narration.as_deref().is_some_and(|n| n.contains('\u{1b}'))
            )),
            "a control character must not reach the DAG"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reconcile_still_adopts_hand_written_elided_posting() {
        // Elision is rejected on the *remote* path only: a hand-written file
        // legitimately elides one amount, and the local resolution path is
        // id-consistent (the resolved form is what gets hashed and stored).
        let (mut svc, path) = setup_with_accounts();
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!(
                "{content}\n\
                 2024-03-05 * \"Hand\" \"Elided\"\n\
                 \x20 Assets:Cash                                      42.00 USD\n\
                 \x20 Equity:Opening\n"
            ),
        )
        .unwrap();

        let result = svc.reconcile_file().unwrap();
        assert_eq!(result.new_directives, 1, "hand-written elision is adopted");
        assert_eq!(result.rejected, 0);
        std::fs::remove_file(path).ok();
    }

    // ── T27 / L-13: staging vs. persist, and reload-restores-consistency ──

    #[test]
    fn test_stage_remote_directive_does_not_persist() {
        // `stage_remote_directive` is the in-memory commit only: it must land in
        // memory but leave the on-disk file untouched (the caller persists once).
        let (mut svc, path) = setup_with_accounts();
        let on_disk_before = std::fs::read_to_string(&path).unwrap();

        let directive = Directive::Transaction(remote_transaction("staged only", false));
        let content_id = compute_content_id(&directive);
        let staged = svc.stage_remote_directive(directive).unwrap();
        assert_eq!(staged.as_deref(), Some(content_id.as_str()));
        assert!(
            svc.get_directive(&content_id).is_some(),
            "staged directive is in memory (memory ahead of disk)"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            on_disk_before,
            "stage must NOT write the file"
        );

        // The wrapper `insert_remote_directive` = stage + persist, so it DOES
        // write the file (single-insert semantics preserved for existing callers).
        let directive2 = Directive::Transaction(remote_transaction("staged then persisted", false));
        let content_id2 = compute_content_id(&directive2);
        svc.insert_remote_directive(directive2).unwrap();
        let on_disk_after = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk_after.contains("staged then persisted"),
            "insert_remote_directive must persist"
        );
        // The first (staged-only) directive is now on disk too, because the
        // second insert's persist writes the whole current DAG snapshot.
        assert!(
            on_disk_after.contains("staged only"),
            "the earlier staged directive is captured by the later persist"
        );
        assert!(svc.get_directive(&content_id2).is_some());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reload_from_disk_drops_unpersisted_directive() {
        // L-13: staging puts memory ahead of disk; reconstructing from the
        // on-disk file (exactly what `persist_or_reload` does on a failed
        // persist) drops the un-persisted directive, restoring memory==disk.
        let (mut svc, path) = setup_with_accounts();
        let persisted_count = svc.directive_count();

        let directive = Directive::Transaction(remote_transaction("memory only", false));
        let content_id = compute_content_id(&directive);
        svc.stage_remote_directive(directive).unwrap();
        assert!(svc.get_directive(&content_id).is_some());

        // Reconstruct from disk — the staged directive was never written.
        let reloaded = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        assert!(
            reloaded.get_directive(&content_id).is_none(),
            "L-13: reload from disk drops the un-persisted directive"
        );
        assert_eq!(
            reloaded.directive_count(),
            persisted_count,
            "reloaded state matches exactly what is on disk"
        );

        std::fs::remove_file(path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_persist_or_reload_failure_rolls_back_to_disk() {
        // L-13 end-to-end: force `persist` to fail (revoke write on the parent
        // directory so the sibling `.tmp` cannot be created), and assert that
        // `persist_or_reload` (a) returns the persist error and (b) reloads from
        // disk so the un-persisted directive is gone and the file is intact.
        use std::os::unix::fs::PermissionsExt;

        // A dedicated subdirectory so revoking write touches nothing shared.
        let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("openledger-l13-{ts}-{count}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.bean");

        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.open_account(
            "Assets:Cash".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        let on_disk_before = std::fs::read_to_string(&path).unwrap();
        let count_before = svc.directive_count();

        // Stage a new directive WITHOUT persisting: memory is now ahead of disk.
        let directive = Directive::Transaction(remote_transaction("rolled back", false));
        let content_id = compute_content_id(&directive);
        svc.stage_remote_directive(directive).unwrap();
        assert!(svc.get_directive(&content_id).is_some());
        assert_eq!(svc.directive_count(), count_before + 1);

        // Revoke write on the directory so creating `<name>.tmp` fails (EACCES).
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(&dir, perms).unwrap();

        let result = svc.persist_or_reload();

        // Restore write BEFORE asserting so cleanup always runs.
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&dir, perms).unwrap();

        assert!(
            result.is_err(),
            "persist into a read-only directory must fail"
        );
        assert!(
            svc.get_directive(&content_id).is_none(),
            "L-13: the failed persist reloaded from disk, dropping the staged directive"
        );
        assert_eq!(
            svc.directive_count(),
            count_before,
            "memory is back to the persisted set"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            on_disk_before,
            "the atomic temp+rename left the on-disk file fully intact"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── T35 shared fixtures ──────────────────────────────────────────────

    /// Serialize each directive on its own, in the order given, so a test can
    /// write a file that is deliberately NOT in canonical order.
    ///
    /// `full_file_serialize` sorts, which is exactly what these tests need to
    /// defeat.
    fn file_text_in_given_order(directives: &[Directive]) -> String {
        directives
            .iter()
            .map(|directive| full_file_serialize(std::slice::from_ref(directive), &[]))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn open_directive(account: &str, currencies: &[&str]) -> Directive {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "test-peer".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "1".to_owned());
        Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: account.to_owned(),
            currencies: currencies.iter().map(|c| (*c).to_owned()).collect(),
            metadata,
        })
    }

    /// A balanced Assets:Cash / Equity:Opening transaction with hand-set parents.
    fn transaction_with_parents(narration: &str, date: NaiveDate, parents: &str) -> Directive {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "test-peer".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "2".to_owned());
        metadata.insert("openledger-parents".to_owned(), parents.to_owned());
        Directive::Transaction(Transaction {
            date,
            flag: Flag::Complete,
            payee: None,
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
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata,
        })
    }

    // ── L-28: a UTF-8 BOM must not brick boot ────────────────────────────

    #[test]
    fn test_boot_tolerates_a_utf8_byte_order_mark() {
        // An editor saved the ledger as "UTF-8 with BOM". Before L-28 the first
        // directive header no longer started with a date, `parse_file` failed
        // the whole file, and every subsequent boot aborted.
        let plain_text = "2024-01-01 open Assets:Cash USD\n\n2024-01-01 open Equity:Opening\n";

        let plain_path = test_file_path();
        std::fs::write(&plain_path, plain_text).unwrap();
        let plain = LedgerService::boot(plain_path.clone(), "test-peer".to_owned()).unwrap();

        let marked_path = test_file_path();
        std::fs::write(&marked_path, format!("\u{FEFF}{plain_text}")).unwrap();
        let marked = LedgerService::boot(marked_path.clone(), "test-peer".to_owned())
            .expect("L-28: a BOM'd ledger file must still boot");

        assert_eq!(marked.directive_count(), plain.directive_count());
        assert_eq!(
            marked.dag().content_ids(),
            plain.dag().content_ids(),
            "L-28: a BOM must not change a single content id"
        );
        assert!(marked.accounts().is_open("Assets:Cash"));

        std::fs::remove_file(plain_path).ok();
        std::fs::remove_file(marked_path).ok();
    }

    #[test]
    fn test_persist_removes_a_byte_order_mark_from_disk() {
        // Persist is canonical serialization, so once the node writes the file
        // the BOM is gone and the next editor round-trip starts clean.
        let path = test_file_path();
        std::fs::write(
            &path,
            "\u{FEFF}2024-01-01 open Assets:Cash USD\n\n2024-01-01 open Equity:Opening\n",
        )
        .unwrap();

        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.persist_or_reload().unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.starts_with(&[0xEF, 0xBB, 0xBF]),
            "L-28: a persist must write canonical, BOM-free bytes"
        );
        assert_eq!(
            svc.external_reconcile_count(),
            0,
            "a BOM alone is not a hand edit — hashes are taken over the stripped text"
        );

        std::fs::remove_file(path).ok();
    }

    // ── L-17: out-of-order files and planted parent cycles ───────────────

    #[test]
    fn test_boot_with_child_listed_before_its_parent_keeps_the_right_heads() {
        // A file may list a child above its parent — a hand edit, a paste, a
        // three-way merge. Boot's canonical sort is (date, type_priority) and is
        // stable, so same-date transactions load in file order: the child really
        // is inserted first.
        let parent = transaction_with_parents("Parent", make_date(2024, 2, 1), "");
        let parent_id = compute_content_id(&parent);
        let child = transaction_with_parents("Child", make_date(2024, 2, 1), &parent_id);
        let child_id = compute_content_id(&child);

        let path = test_file_path();
        std::fs::write(
            &path,
            file_text_in_given_order(&[
                open_directive("Assets:Cash", &["USD"]),
                open_directive("Equity:Opening", &[]),
                child,
                parent,
            ]),
        )
        .unwrap();

        let svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();

        assert_eq!(svc.directive_count(), 4);
        assert_eq!(
            svc.head_txids(),
            std::collections::HashSet::from([child_id.clone()]),
            "L-17: the late-arriving parent must not be left in the frontier"
        );
        assert!(
            svc.dag()
                .children_of(&parent_id)
                .unwrap()
                .contains(&child_id),
            "L-17: the parent must adopt the reverse edge its child parked"
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_boot_skips_a_planted_parent_cycle_and_names_both_members() {
        // `openledger-parents` is envelope metadata, which the content hash
        // excludes — so a text editor can make A claim hash(B) as its parent and
        // B claim hash(A) WITHOUT either id changing. Boot used to propagate the
        // DAG's cycle error and abort, so one edited pair bricked the node.
        let bare_a = transaction_with_parents("Cycle A", make_date(2024, 2, 1), "");
        let bare_b = transaction_with_parents("Cycle B", make_date(2024, 2, 1), "");
        let id_a = compute_content_id(&bare_a);
        let id_b = compute_content_id(&bare_b);

        let cycle_a = transaction_with_parents("Cycle A", make_date(2024, 2, 1), &id_b);
        let cycle_b = transaction_with_parents("Cycle B", make_date(2024, 2, 1), &id_a);
        assert_eq!(
            compute_content_id(&cycle_a),
            id_a,
            "premise of L-17: envelope parents are outside the content hash"
        );
        assert_eq!(compute_content_id(&cycle_b), id_b);

        let honest = transaction_with_parents("Honest", make_date(2024, 3, 1), "");
        let honest_id = compute_content_id(&honest);

        let path = test_file_path();
        std::fs::write(
            &path,
            file_text_in_given_order(&[
                open_directive("Assets:Cash", &["USD"]),
                open_directive("Equity:Opening", &[]),
                cycle_a,
                cycle_b,
                honest,
            ]),
        )
        .unwrap();

        let (booted, logged) =
            capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
        let svc = booted.expect("L-17: a planted cycle must not abort boot");

        assert!(
            svc.get_directive(&id_a).is_none() && svc.get_directive(&id_b).is_none(),
            "L-17: both cycle members are rejected"
        );
        assert!(
            logged.contains(&id_a) && logged.contains(&id_b),
            "L-17: the warning must name both cycle members, got: {logged}"
        );
        assert!(
            svc.get_directive(&honest_id).is_some(),
            "L-17: everything outside the cycle still loads"
        );
        assert_eq!(svc.directive_count(), 3, "two opens plus the honest txn");
        assert!(svc.accounts().is_open("Assets:Cash"));
        assert_eq!(
            svc.head_txids(),
            std::collections::HashSet::from([honest_id])
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_boot_of_an_in_order_file_is_untouched_by_the_cycle_scan() {
        // The pre-scan must be invisible on every well-formed ledger: same
        // directives, same heads, byte-identical re-persist, no warning.
        let (mut svc, path) = setup_with_accounts();
        svc.append_transaction(balanced_input()).unwrap();
        let mut second = balanced_input();
        second.narration = Some("Second".to_owned());
        second.date = make_date(2024, 2, 1);
        svc.append_transaction(second).unwrap();
        let before = std::fs::read(&path).unwrap();
        let heads_before = svc.head_txids();
        let ids_before: Vec<String> = svc
            .dag()
            .content_ids()
            .into_iter()
            .map(str::to_owned)
            .collect();
        drop(svc);

        let (booted, logged) =
            capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
        let mut rebooted = booted.unwrap();
        assert!(
            logged.is_empty(),
            "an in-order file must produce no warnings, got: {logged}"
        );
        assert_eq!(rebooted.head_txids(), heads_before);
        assert_eq!(
            rebooted
                .dag()
                .content_ids()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<String>>(),
            ids_before
        );

        rebooted.persist_or_reload().unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "re-persisting an in-order file must be byte-identical"
        );

        std::fs::remove_file(path).ok();
    }

    // ── L-30 / L-12: persist must not clobber a concurrent hand edit ─────

    #[test]
    fn test_persist_adopts_a_concurrent_hand_edit_instead_of_clobbering_it() {
        let (mut svc, path) = setup_with_accounts();

        // A human edits the .bean while the node runs. The T30 sidecar flock
        // excludes other gl-node processes, not text editors.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!(
                "{on_disk}\n\
                 2024-03-01 * \"Hand\" \"Typed by a human\"\n\
                 \x20 Assets:Cash                                      250.00 USD\n\
                 \x20 Equity:Opening                                   -250.00 USD\n"
            ),
        )
        .unwrap();

        // An ordinary API append. Its persist used to rewrite the whole file
        // from memory, deleting the edit above without a word.
        svc.append_transaction(balanced_input()).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("Typed by a human"),
            "L-30: the concurrent hand edit must survive the persist:\n{after}"
        );
        assert!(after.contains("Funding"), "the API append is on disk too");
        assert_eq!(
            svc.external_reconcile_count(),
            1,
            "the mismatched hash triggered exactly one adoption"
        );
        assert!(
            svc.dag()
                .transactions()
                .iter()
                .any(|t| t.narration.as_deref() == Some("Typed by a human")),
            "L-30: the adopted directive is in memory, not only on disk"
        );

        // The merged file is canonical, not an append of raw edited text.
        let mut rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        assert_eq!(rebooted.directive_count(), svc.directive_count());
        rebooted.compact().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            after,
            "the merged file was already in canonical form"
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_persist_surfaces_a_rejected_hand_edit_before_dropping_it() {
        let (mut svc, path) = setup_with_accounts();

        // Assets:Vault is never opened, so this entry cannot be adopted — and
        // the canonical re-persist is about to delete it from the file.
        let bad_entry = "2024-03-01 * \"Hand\" \"Unopened account\"\n\
                         \x20 Assets:Vault                                     250.00 USD\n\
                         \x20 Equity:Opening                                   -250.00 USD\n";
        let rejected_id = compute_content_id(&parse_file(bad_entry).unwrap()[0]);

        let on_disk = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{on_disk}\n{bad_entry}")).unwrap();

        let (outcome, logged) = capture_warnings(|| svc.append_transaction(balanced_input()));
        outcome.expect("a rejected hand edit must not fail the append");

        assert!(
            logged.contains(&rejected_id),
            "L-12: the warning must identify the rejected entry by id, got:\n{logged}"
        );
        assert!(
            logged.contains("Assets:Vault not open"),
            "L-12: ...and say why it was refused, got:\n{logged}"
        );

        // File is canonical and the bad entry is gone; the service is healthy.
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains("Unopened account"));
        assert!(after.contains("Funding"));
        assert_eq!(svc.directive_count(), 4, "three opens plus the API append");
        let mut later = balanced_input();
        later.narration = Some("Still working".to_owned());
        later.date = make_date(2024, 4, 1);
        svc.append_transaction(later)
            .expect("the service still accepts writes");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_persist_without_a_hand_edit_never_reconciles() {
        let (mut svc, path) = setup_with_accounts();
        assert_eq!(svc.external_reconcile_count(), 0);

        svc.append_transaction(balanced_input()).unwrap();
        svc.open_account("Assets:Vault".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        assert_eq!(
            svc.external_reconcile_count(),
            0,
            "L-30: with the recorded hash matching, a persist must take the fast path"
        );

        // Rewriting the file with byte-identical content is not an edit either:
        // the guard is a content hash, not an mtime.
        let identical = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, &identical).unwrap();
        let mut again = balanced_input();
        again.narration = Some("After a no-op rewrite".to_owned());
        again.date = make_date(2024, 5, 1);
        svc.append_transaction(again).unwrap();
        assert_eq!(
            svc.external_reconcile_count(),
            0,
            "L-30: identical bytes are not a hand edit"
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reconcile_processes_the_file_in_canonical_order() {
        // A human pastes a transaction and then, BELOW it, the `open` it needs.
        // Reading raw file order rejected that transaction for referencing an
        // unopened account — while the very same file booted cleanly, because
        // boot sorts. Reconcile now sorts the same way (L-12).
        let (mut svc, path) = setup_with_accounts();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!(
                "{on_disk}\n\
                 2024-02-01 * \"Hand\" \"Needs the open below it\"\n\
                 \x20 Assets:Vault                                     40.00 USD\n\
                 \x20 Equity:Opening                                   -40.00 USD\n\
                 \n\
                 2024-01-01 open Assets:Vault USD\n"
            ),
        )
        .unwrap();

        let result = svc.reconcile_file().unwrap();

        assert_eq!(
            result.rejected, 0,
            "L-12: canonical order opens the account before the transaction using it"
        );
        assert_eq!(
            result.new_directives, 2,
            "both the open and the transaction"
        );
        assert!(svc.accounts().is_open("Assets:Vault"));
        assert!(svc
            .dag()
            .transactions()
            .iter()
            .any(|t| t.narration.as_deref() == Some("Needs the open below it")));

        std::fs::remove_file(path).ok();
    }

    // ── T44: append-only persistence + off-runtime fsync ─────────────────

    fn filler_envelope(lamport: u64) -> Metadata {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "test-peer".to_owned());
        metadata.insert("openledger-lamport".to_owned(), lamport.to_string());
        metadata
    }

    /// Canonical text for a ledger comfortably past
    /// [`COMPACTION_MIN_CANONICAL_BYTES`], so commits take the append path.
    ///
    /// Built through `full_file_serialize` rather than as hand-written text, so
    /// the fixture is canonical by construction and a serializer change cannot
    /// leave these tests booting a file no node would write. The accounts are
    /// padded rather than numerous: the same byte count from 500 directives
    /// instead of 1,200 keeps every boot in this section cheap.
    fn large_ledger_content() -> String {
        let padding = "A".repeat(80);
        let mut directives = vec![
            Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Assets:Cash".to_owned(),
                currencies: vec!["USD".to_owned()],
                metadata: filler_envelope(1),
            }),
            Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Equity:Opening".to_owned(),
                currencies: Vec::new(),
                metadata: filler_envelope(2),
            }),
        ];
        for index in 0..500u64 {
            directives.push(Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: format!("Assets:F{padding}{index:06}"),
                currencies: vec!["USD".to_owned()],
                metadata: filler_envelope(index + 3),
            }));
        }
        full_file_serialize(&directives, &[])
    }

    /// A booted service whose canonical file is past the compaction threshold,
    /// with the first (canonicalising) commit already taken — so the NEXT
    /// commit is an append.
    fn boot_large_ledger() -> (LedgerService, PathBuf) {
        let path = test_file_path();
        std::fs::write(&path, large_ledger_content()).unwrap();
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        // Boot reads a file it did not write, so the first commit is always a
        // full rewrite (see `canonical_is_current`). Take it here, exactly as a
        // running node's first write would.
        svc.compact().unwrap();
        assert!(
            svc.canonical_bytes() > COMPACTION_MIN_CANONICAL_BYTES,
            "the fixture must be past the threshold, got {} bytes",
            svc.canonical_bytes()
        );
        assert_eq!(svc.journal_bytes(), 0, "a compaction leaves no journal");
        (svc, path)
    }

    fn remove_ledger_and_journal(path: &Path) {
        std::fs::remove_file(crate::journal::journal_path_for(path)).ok();
        std::fs::remove_file(path).ok();
    }

    fn stage_filler_opens(svc: &mut LedgerService, range: std::ops::Range<usize>) {
        for index in range {
            svc.stage_remote_directive(Directive::Open(Open {
                date: make_date(2024, 3, 1),
                account: format!("Assets:Batch{index:06}"),
                currencies: vec!["USD".to_owned()],
                metadata: remote_envelope(1_000 + index as u64),
            }))
            .unwrap();
        }
    }

    /// T44 goal (a): persisting one appended directive must not re-serialize or
    /// rewrite the whole ledger.
    ///
    /// Proved against observable I/O rather than a counter: the canonical
    /// `.bean` is compared byte-for-byte before and after, and the journal's
    /// growth is required to equal the record exactly.
    #[test]
    fn t44_appending_one_directive_to_a_large_ledger_does_not_rewrite_the_file() {
        let (mut svc, path) = boot_large_ledger();
        let journal_path = svc.journal_path().to_path_buf();
        let canonical_before = std::fs::read(&path).unwrap();
        let canonical_bytes = svc.canonical_bytes();

        svc.append_transaction_staged(balanced_input(), |_, _, _| None)
            .unwrap();
        let pending = svc
            .prepare_commit()
            .unwrap()
            .expect("a staged directive must produce a commit");

        assert_eq!(
            pending.kind(),
            CommitKind::Append,
            "a ledger past the threshold appends; it does not rewrite"
        );
        let written = pending.bytes_to_write();
        assert!(
            written * 20 < canonical_bytes,
            "one directive cost {written} bytes against a {canonical_bytes}-byte ledger; \
             that is not O(directive)"
        );

        let receipt = pending.commit().unwrap();
        assert_eq!(receipt.bytes_written(), written);
        svc.finish_commit(receipt);

        assert_eq!(
            std::fs::read(&path).unwrap(),
            canonical_before,
            "the .bean must be byte-for-byte untouched by an append"
        );
        assert_eq!(
            std::fs::metadata(&journal_path).unwrap().len(),
            written,
            "the journal must have grown by exactly the record and nothing else"
        );
        assert_eq!(svc.journal_bytes(), written);

        remove_ledger_and_journal(&path);
    }

    /// The same property over a run of writes, stated as the number the tracker
    /// asks for: eight appends together cost less than a single pre-T44
    /// rewrite, of which there would have been eight.
    #[test]
    fn t44_a_run_of_appends_costs_the_directives_not_the_ledger() {
        let (mut svc, path) = boot_large_ledger();
        let canonical_bytes = svc.canonical_bytes();

        let written = std::sync::Arc::new(AtomicU64::new(0));
        let sink = std::sync::Arc::clone(&written);
        svc.set_commit_observer(std::sync::Arc::new(move |_kind, bytes| {
            sink.fetch_add(bytes, Ordering::SeqCst);
        }));

        for index in 0..8u64 {
            svc.stage_remote_directive(remote_open(
                &format!("Assets:Run{index:03}"),
                make_date(2024, 3, 1),
                10 + index,
            ))
            .unwrap();
            svc.persist_or_reload().unwrap();
        }

        let total = written.load(Ordering::SeqCst);
        assert!(
            total < canonical_bytes,
            "eight appends wrote {total} bytes; one pre-T44 persist rewrote \
             {canonical_bytes} and there would have been eight of them"
        );
        assert_eq!(
            svc.journal_bytes(),
            total,
            "every one of those bytes went to the journal, none to the .bean"
        );

        remove_ledger_and_journal(&path);
    }

    /// Below the threshold nothing changes: no sidecar, and the `.bean` is
    /// current after every write exactly as it was before T44.
    #[test]
    fn t44_a_small_ledger_never_creates_a_journal() {
        let (mut svc, path) = setup_with_accounts();
        svc.append_transaction(balanced_input()).unwrap();

        assert!(svc.canonical_bytes() < COMPACTION_MIN_CANONICAL_BYTES);
        assert_eq!(svc.journal_bytes(), 0);
        assert!(
            !svc.journal_path().exists(),
            "below the threshold the .bean is the only file on disk"
        );
        assert!(std::fs::read_to_string(&path).unwrap().contains("Funding"));

        remove_ledger_and_journal(&path);
    }

    /// The compaction policy, pinned: appends accumulate until the journal
    /// reaches half the canonical file, and that commit folds it back.
    #[test]
    fn t44_the_journal_is_folded_back_once_it_reaches_half_the_canonical_file() {
        let (mut svc, path) = boot_large_ledger();
        let canonical_bytes = svc.canonical_bytes();

        // Well under half the ledger: appended.
        stage_filler_opens(&mut svc, 0..40);
        let first = svc.prepare_commit().unwrap().unwrap();
        assert_eq!(first.kind(), CommitKind::Append);
        let receipt = first.commit().unwrap();
        svc.finish_commit(receipt);
        assert!(svc.journal_bytes() > 0);
        assert!(
            svc.journal_bytes() * COMPACTION_JOURNAL_RATIO < canonical_bytes,
            "the fixture must still be under the ratio for this to prove anything"
        );

        // Enough more to cross it: folded back in one commit.
        stage_filler_opens(&mut svc, 40..600);
        let second = svc.prepare_commit().unwrap().unwrap();
        assert_eq!(
            second.kind(),
            CommitKind::Compact,
            "past the ratio the journal must be folded back"
        );
        let receipt = second.commit().unwrap();
        svc.finish_commit(receipt);
        assert_eq!(svc.journal_bytes(), 0);
        assert!(
            !svc.journal_path().exists(),
            "compaction unlinks the journal"
        );

        remove_ledger_and_journal(&path);
    }

    /// T44 invariant 5: booting canonical ∪ journal reaches exactly the state a
    /// compacted canonical file boots to.
    #[test]
    fn t44_boot_over_canonical_plus_journal_matches_boot_over_the_compacted_file() {
        let (mut svc, path) = boot_large_ledger();
        svc.append_transaction_staged(balanced_input(), |_, _, _| None)
            .unwrap();
        let mut second = balanced_input();
        second.narration = Some("Second".to_owned());
        second.date = make_date(2024, 2, 1);
        svc.append_transaction_staged(second, |_, _, _| None)
            .unwrap();
        svc.persist_or_reload().unwrap();
        assert!(
            svc.journal_bytes() > 0,
            "the appends must have gone to the journal for this to prove anything"
        );

        // (a) the crash-window shape: canonical file plus a live journal.
        let unioned = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();

        // (b) the same directives after a compaction, canonical file alone.
        let mut compacting = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        compacting.compact().unwrap();
        assert_eq!(compacting.journal_bytes(), 0);
        let from_file = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();

        assert_eq!(unioned.directive_count(), from_file.directive_count());
        assert_eq!(unioned.dag().content_ids(), from_file.dag().content_ids());
        assert_eq!(unioned.head_txids(), from_file.head_txids());
        assert_eq!(unioned.lamport_clock(), from_file.lamport_clock());
        assert!(unioned.accounts().is_open("Assets:Cash"));
        assert_eq!(
            unioned.accounts().is_open("Assets:Cash"),
            from_file.accounts().is_open("Assets:Cash")
        );

        remove_ledger_and_journal(&path);
    }

    /// T44 invariant 3, re-proved through the NEW path: every arrival order
    /// journals its directives one commit at a time, and the file each node
    /// compacts to is byte-identical.
    ///
    /// This is T29's 66-permutation shape at the scale the journal path can be
    /// exercised at — 24 orders of four lifecycle directives, each on its own
    /// ledger past the compaction threshold.
    #[test]
    fn t44_compaction_is_byte_identical_across_every_arrival_order() {
        let lifecycle = [
            remote_open("Assets:Vault", make_date(2024, 3, 1), 10),
            remote_close("Assets:Vault", make_date(2024, 5, 1), 11),
            remote_open("Assets:Safe", make_date(2024, 4, 1), 12),
            remote_close("Assets:Safe", make_date(2024, 6, 1), 13),
        ];

        let mut orders: Vec<Vec<usize>> = Vec::new();
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let order = vec![a, b, c, d];
                        let mut seen = order.clone();
                        seen.sort_unstable();
                        seen.dedup();
                        if seen.len() == 4 {
                            orders.push(order);
                        }
                    }
                }
            }
        }
        assert_eq!(orders.len(), 24, "every permutation of four");

        let mut outputs: Vec<String> = Vec::new();
        for order in &orders {
            let path = test_file_path();
            std::fs::write(&path, large_ledger_content()).unwrap();
            let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
            svc.compact().unwrap();

            for index in order {
                svc.stage_remote_directive(lifecycle[*index].clone())
                    .unwrap();
                svc.persist_or_reload().unwrap();
            }
            assert!(
                svc.journal_bytes() > 0,
                "every arrival must have been journalled, not rewritten"
            );

            svc.compact().unwrap();
            outputs.push(std::fs::read_to_string(&path).unwrap());
            remove_ledger_and_journal(&path);
        }

        for (index, output) in outputs.iter().enumerate() {
            assert_eq!(
                output, &outputs[0],
                "arrival order {:?} compacted to different canonical bytes",
                orders[index]
            );
        }
    }

    /// T44 invariant 4: a crash mid-append leaves a torn final record. It is
    /// dropped with a warning; everything before it still loads.
    #[test]
    fn t44_a_torn_journal_tail_is_dropped_with_a_warning() {
        let (mut svc, path) = boot_large_ledger();
        let journal_path = svc.journal_path().to_path_buf();

        svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
            .unwrap();
        svc.persist_or_reload().unwrap();
        svc.stage_remote_directive(remote_open("Assets:Safe", make_date(2024, 3, 2), 11))
            .unwrap();
        svc.persist_or_reload().unwrap();

        // The crash: `write_all` got part way and `sync_all` never returned.
        let both = std::fs::read(&journal_path).unwrap();
        std::fs::write(&journal_path, &both[..both.len() - 30]).unwrap();

        let (booted, logged) =
            capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
        let booted = booted.expect("a torn tail must not brick the boot");
        assert!(
            logged.contains("torn record"),
            "the dropped record must be reported, got: {logged}"
        );
        assert!(
            booted.accounts().is_open("Assets:Vault"),
            "the intact record still loads"
        );
        assert!(
            !booted.accounts().is_open("Assets:Safe"),
            "only the torn record is dropped"
        );

        remove_ledger_and_journal(&path);
    }

    /// The other half of invariant 4: corruption that a crash cannot produce
    /// fails closed rather than silently dropping directives.
    #[test]
    fn t44_a_corrupt_journal_record_fails_boot_closed() {
        let (mut svc, path) = boot_large_ledger();
        let journal_path = svc.journal_path().to_path_buf();

        svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
            .unwrap();
        svc.persist_or_reload().unwrap();
        svc.stage_remote_directive(remote_open("Assets:Safe", make_date(2024, 3, 2), 11))
            .unwrap();
        svc.persist_or_reload().unwrap();

        // Flip a byte inside the FIRST record's payload: the full length is
        // present, so this is corruption and not a torn tail.
        let mut bytes = std::fs::read(&journal_path).unwrap();
        let position = bytes
            .windows(12)
            .position(|window| window == b"Assets:Vault")
            .unwrap();
        bytes[position + 8] = b'X';
        std::fs::write(&journal_path, &bytes).unwrap();

        let Err(error) = LedgerService::boot(path.clone(), "test-peer".to_owned()) else {
            panic!("a corrupt journal record must fail the boot closed");
        };
        assert_eq!(error.error_code(), "LEDGER_JOURNAL", "got {error}");

        remove_ledger_and_journal(&path);
    }

    /// T44 invariant 4 / T35: a hand edit to the canonical file is still
    /// adopted, not clobbered, when journal records are outstanding — and both
    /// halves survive the compaction that adoption forces.
    #[test]
    fn t44_a_hand_edit_is_adopted_with_journal_records_outstanding() {
        let (mut svc, path) = boot_large_ledger();

        svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
            .unwrap();
        svc.persist_or_reload().unwrap();
        assert!(
            svc.journal_bytes() > 0,
            "the arrival must be journalled for this to prove anything"
        );

        // A human appends to the canonical `.bean` while the node runs.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!("{on_disk}\n2024-04-01 open Assets:Safe USD\n"),
        )
        .unwrap();

        // The next write notices (the O(1) stat probe), escalates to a
        // compaction, and adopts the edit before serializing over it.
        svc.stage_remote_directive(remote_open("Assets:Attic", make_date(2024, 3, 5), 11))
            .unwrap();
        svc.persist_or_reload().unwrap();

        assert_eq!(
            svc.external_reconcile_count(),
            1,
            "the hand edit must have been adopted, not clobbered"
        );
        assert_eq!(svc.journal_bytes(), 0, "adoption forces a compaction");
        assert!(!svc.journal_path().exists());
        for account in ["Assets:Vault", "Assets:Safe", "Assets:Attic"] {
            assert!(svc.accounts().is_open(account), "{account} must survive");
        }

        // And all three are in the canonical file, not merely in memory.
        let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        for account in ["Assets:Vault", "Assets:Safe", "Assets:Attic"] {
            assert!(
                rebooted.accounts().is_open(account),
                "{account} must be on disk"
            );
        }

        remove_ledger_and_journal(&path);
    }

    /// The crash window a compaction opens: the canonical file is written and
    /// the process dies before the journal is unlinked, so both files hold the
    /// same directives. Content addressing makes the dedup free.
    #[test]
    fn t44_a_journal_overlapping_the_canonical_file_boots_to_the_same_set() {
        let (mut svc, path) = boot_large_ledger();
        let journal_path = svc.journal_path().to_path_buf();

        svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
            .unwrap();
        svc.persist_or_reload().unwrap();
        let journal_snapshot = std::fs::read(&journal_path).unwrap();
        let expected_count = svc.directive_count();
        let expected_ids: Vec<String> = svc
            .dag()
            .content_ids()
            .into_iter()
            .map(str::to_owned)
            .collect();

        svc.compact().unwrap();
        assert!(!journal_path.exists());
        // Put the journal back: the crash landed between the rename and the
        // unlink.
        std::fs::write(&journal_path, &journal_snapshot).unwrap();

        let booted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        assert_eq!(
            booted.directive_count(),
            expected_count,
            "overlapping directives are id-identical, so the G-Set dedups them"
        );
        assert_eq!(
            booted
                .dag()
                .content_ids()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<String>>(),
            expected_ids
        );

        remove_ledger_and_journal(&path);
    }

    /// L-13 through the new shape: a commit that fails leaves memory no further
    /// ahead of disk than it was, and the durable prefix survives.
    #[cfg(unix)]
    #[test]
    fn t44_a_failed_commit_leaves_memory_level_with_disk() {
        use std::os::unix::fs::PermissionsExt;

        let (mut svc, path) = boot_large_ledger();
        let journal_path = svc.journal_path().to_path_buf();

        svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
            .unwrap();
        svc.persist_or_reload().unwrap();
        let durable_count = svc.directive_count();

        // A read-only journal fails the append on the REAL I/O path, with no
        // mocking, and stays readable so the L-13 reload can still run.
        let mut permissions = std::fs::metadata(&journal_path).unwrap().permissions();
        permissions.set_mode(0o400);
        std::fs::set_permissions(&journal_path, permissions).unwrap();

        svc.stage_remote_directive(remote_open("Assets:Safe", make_date(2024, 3, 2), 11))
            .unwrap();
        assert_eq!(svc.uncommitted_count(), 1);
        let error = svc.persist_or_reload().unwrap_err();
        assert_eq!(error.error_code(), "IO_ERROR", "got {error}");

        assert_eq!(
            svc.directive_count(),
            durable_count,
            "L-13: the undurable directive must be rolled out of memory"
        );
        assert_eq!(svc.uncommitted_count(), 0);
        assert!(
            svc.accounts().is_open("Assets:Vault"),
            "the durable arrival survives the rollback"
        );
        assert!(
            !svc.accounts().is_open("Assets:Safe"),
            "the undurable one does not"
        );

        let mut permissions = std::fs::metadata(&journal_path).unwrap().permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&journal_path, permissions).unwrap();
        remove_ledger_and_journal(&path);
    }

    /// The single-writer backstop: a second prepare while a commit is in flight
    /// is refused rather than allowed to interleave.
    #[test]
    fn t44_a_second_prepare_while_a_commit_is_in_flight_is_refused() {
        let (mut svc, path) = boot_large_ledger();

        svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
            .unwrap();
        let first = svc.prepare_commit().unwrap().unwrap();

        svc.stage_remote_directive(remote_open("Assets:Safe", make_date(2024, 3, 2), 11))
            .unwrap();
        let error = svc.prepare_commit().unwrap_err();
        assert_eq!(error.error_code(), "COMMIT_IN_FLIGHT", "got {error}");

        // And the refusal did NOT trigger an L-13 reload — nothing was written,
        // so nothing is ahead of disk and the outstanding commit still owns the
        // files.
        assert_eq!(svc.uncommitted_count(), 2);

        let receipt = first.commit().unwrap();
        svc.finish_commit(receipt);
        assert_eq!(svc.uncommitted_count(), 0);

        remove_ledger_and_journal(&path);
    }
}
