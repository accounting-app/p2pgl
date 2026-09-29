//! Ledger service — the unified write + boot layer (§3.5).
//!
//! Ties together parser, serializer, DAG, validation, and file persistence.
//! This is the single entry point for all ledger mutations.

use chrono::{Datelike, NaiveDate};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

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
use crate::validate::{
    validate_transaction, validate_transaction_as_author, validate_transaction_as_data,
    AccountState, ValidationError,
};

mod access;
mod authoring;
mod blocks;
mod boot;
mod commit;
mod envelope;
mod error;
mod file_io;
mod lamport;
mod quarantine;
mod reconcile;
mod recovery;
mod remote;
mod resource_limits;
mod verify;

pub use self::authoring::*;
use self::blocks::*;
pub use self::commit::*;
pub use self::envelope::*;
pub use self::error::*;
pub use self::file_io::*;
pub use self::lamport::*;
use self::reconcile::*;
pub use self::remote::*;
pub use self::resource_limits::*;

/// What decides which records this node withholds from peers (T100 / L-148,
/// L-154): the DAG's size, how many file-adopted lines await their rewrite,
/// and how many writes are staged with the last one's id. The DAG only grows
/// between rebuilds, which reset every snapshot keyed by this.
type WithheldKey = (usize, usize, usize, Option<String>);

/// `(key, the served ids)` — see `LedgerService::served_id_snapshot`.
type ServedIdSnapshot = (WithheldKey, std::sync::Arc<[String]>);

/// `((staged count, last staged id), (the staged ids, the committed records
/// they name))` — see `LedgerService::staged_frontier`.
type StagedFrontier = (
    (usize, Option<String>),
    std::sync::Arc<(HashSet<String>, Vec<String>)>,
);

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

/// Verifies the signature a file directive carries (H-20).
///
/// Arguments, in order: `content_id`, `is_transaction`, `parents`, `lamport`
/// — the four `SignableMessage` fields, exactly as [`DirectiveSigner`] takes
/// them — then `author` (the public key the signature must verify against;
/// the author id *is* the key) and `signature` (the hex value on the
/// envelope). Returns `true` only when the signature verifies. The same
/// dependency inversion as the signer: this crate does not depend on
/// `security`, so `gl-node` builds this from
/// `security::signing::verify_signature` and installs it with
/// [`LedgerService::set_verifier`].
pub type DirectiveVerifier =
    std::sync::Arc<dyn Fn(&str, bool, &str, &str, &str, &str) -> bool + Send + Sync>;

/// What [`LedgerService::verify_history_directive`] concluded about one
/// directive's signature (H-20).
enum HistoryVerdict {
    /// The signature verifies, or the directive carries no envelope.
    Verified,
    /// This service has no means to check it: no verifier, and either no
    /// signer or a foreign author, or a signer that has signing disabled.
    Unverifiable,
    /// Refused, with the reason the operator sees.
    Refused(String),
}

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
    /// Directives the file holds that [`Self::boot`] deliberately refused to
    /// load — kept so the next compaction writes them back (H-08).
    ///
    /// # The bug this closes
    ///
    /// T35 replaced L-17's boot *brick* with a *skip*: a file carrying a
    /// hand-planted parent cycle (or, since T41, an over-cap
    /// `openledger-parents` fan-in) no longer aborts the load — the offending
    /// directives are left out of the DAG and the operator is told to repair
    /// them. The operator never got the chance. A compaction serializes
    /// `dag.directives()` over the whole `.bean` and then deletes the journal,
    /// so the very first write after such a boot — and `gl-node` runs one
    /// unconditionally, immediately, to fold in the crash-window journal —
    /// **erased every skipped record from disk**. `openledger-parents` is
    /// envelope metadata that the content hash excludes, so pointing the oldest
    /// transaction at the newest closes a cycle over the whole parent chain
    /// without changing a single content id or breaking a single signature:
    /// one edited line, and the next boot + compaction destroyed the ledger.
    /// That is strictly worse than the brick T35 removed — a brick is
    /// recoverable by editing the file back.
    ///
    /// # What this is
    ///
    /// Everything boot skipped, keyed by content id, held **outside** the DAG.
    /// It is not part of the ledger: not in the read model, not in the account
    /// state, not in the heads, never served to a peer, never counted by
    /// [`Self::directive_count`] — exactly as before, because the DAG is still
    /// the ledger. Its one and only consumer is
    /// [`Self::compaction_directives`], which re-serializes these entries
    /// alongside the DAG's so a full rewrite is **lossless with respect to the
    /// file it replaces**. The fail-closed rule the fix rests on: a lossy boot
    /// must never reach a rewrite.
    ///
    /// # Why re-serialized rather than kept as raw text
    ///
    /// The quarantine holds parsed [`Directive`]s and they go through the same
    /// `full_file_serialize` as everything else, rather than a saved byte slice
    /// of the original file. Three reasons:
    ///
    /// * `parse_file` returns directives, not spans, so a verbatim slice would
    ///   need a second parser contract purely for this path;
    /// * a compaction canonicalises every *other* directive, so splicing raw
    ///   text back in would put two spellings in one file and break the
    ///   "the `.bean` holds exactly the bytes this service would write"
    ///   invariant that `canonical_is_current` asserts;
    /// * what has to survive is the **record**, and `parse ∘ serialize == id`
    ///   is the round-trip the crate already stakes every persisted directive
    ///   on (`tests/property.rs`). The envelope — `openledger-parents`,
    ///   `openledger-signature` — is emitted in full, so the quarantined entry
    ///   re-reads as the same content id with the same signature and the same
    ///   (still broken) parent pointers the operator has to repair.
    ///
    /// # How an entry leaves
    ///
    /// Only by being represented in the DAG, or by being gone from the file.
    /// [`Self::compaction_directives`] drops any id the DAG has since acquired
    /// (a peer supplying the same body, or a reconcile adopting a repaired
    /// copy), so a record is never written twice; and a reboot re-derives the
    /// whole set from the file, so an operator who stops the node and deletes
    /// the bad lines is obeyed. A node that is *running* keeps writing them
    /// back, which is the correct reading of L-30's standing rule that editing
    /// a `.bean` a live node owns is unsupported: the node's job is to lose
    /// nothing, and repair-by-restart is the supported path. Repair *is*
    /// adopted live, via the ordinary reconcile: a fixed `openledger-parents`
    /// leaves the content id untouched, so the directive enters the DAG and
    /// drops out of the quarantine on the spot.
    quarantined: BTreeMap<String, Directive>,
    /// The exact source text of every file block [`Self::boot`] could not
    /// **parse** — kept, like [`Self::quarantined`], so the next compaction
    /// writes it back (L-45, H-08).
    ///
    /// # Why this cannot be a `Directive`
    ///
    /// [`Self::quarantined`] holds parsed directives and re-serializes them,
    /// and its own doc comment argues at length that this is the right
    /// representation. It is — for everything that parses. An
    /// `Assets:Cаsh` with a Cyrillic `а` never becomes a [`Directive`] at all:
    /// `parse_file` refuses it, so there is nothing to key by content id,
    /// nothing to re-serialize, and no `parse ∘ serialize == id` round-trip to
    /// lean on. The choice is between keeping the bytes and losing the record.
    ///
    /// So this is the deliberately narrow second half of the quarantine: raw
    /// text, spliced verbatim into the tail of every full rewrite by
    /// [`Self::compaction_text`]. It is NOT canonicalised, because
    /// canonicalising it is exactly the thing this node cannot do.
    ///
    /// # The invariant it preserves, and the one it gives up
    ///
    /// Preserved — the one H-08 is about: **a lossy boot never reaches a
    /// destructive rewrite.** Without this field, L-45's fix (boot skips what
    /// it cannot parse instead of exiting) would be the precise shape T47
    /// closed: skip at boot, compact at startup, record gone from disk seconds
    /// later.
    ///
    /// Given up: `canonical_is_current`'s "the `.bean` holds exactly the bytes
    /// this service would write" no longer holds byte-for-byte over the tail.
    /// That is accepted knowingly and is bounded — the tail is only ever text
    /// this node *read from that same file* and could not interpret, it is
    /// never served, never hashed into anything, and never re-ordered.
    ///
    /// # How an entry leaves
    ///
    /// Only by ceasing to be in the file, and the only party that can do that
    /// is the operator. [`Self::reconcile_content`] re-derives the whole set
    /// from the text it just read, so a repaired block (which then parses, and
    /// is adopted as an ordinary directive) or a deleted one drops out on the
    /// spot — the raw-text analogue of
    /// [`Self::release_quarantined_now_in_dag`]. Nothing else mutates it.
    quarantined_text: BTreeSet<String>,
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
    ///
    /// Installed once, it stays installed: it is carried across every L-13
    /// reload by [`Self::adopt_reloaded`] (T44b).
    signer: Option<DirectiveSigner>,
    /// Verifies the signatures of the history [`Self::boot`] loaded (H-20).
    ///
    /// # The finding
    ///
    /// Boot classified anything carrying an author and a lamport as history
    /// and loaded it after the *form* checks alone — never the signature.
    /// The README's supported stop → edit → start workflow therefore had two
    /// doors: an operator who corrected a narration or an amount in a line
    /// the node wrote booted it under a **new** content id with the **old**
    /// signature, zero WARN, and the startup compaction persisted it; and a
    /// stray dedent, BOM or word inside a node-written transaction let the
    /// salvage load the parsable head as a *complete* transaction — one
    /// posting, the counter-posting gone — under the original envelope.
    /// Every signing peer refused either shape (`InvalidSignature`, cached),
    /// the node's next write named it as a parent, and everything this node
    /// authored afterwards was orphaned mesh-wide; an amount edit diverged
    /// balances between this node and the mesh.
    ///
    /// # What this closes
    ///
    /// [`Self::verify_own_history`] checks every enveloped directive in the
    /// DAG against this verifier — own author or foreign, since the author id
    /// is the key — and **quarantines** what fails (decision (3): never
    /// dropped, never refuse-to-boot; the compaction keeps it in the file,
    /// H-08). A truncated fragment fails the same check because its signature
    /// was made over the original id. Installed by [`Self::set_verifier`]
    /// right after the signer; carried across every L-13 reload like the
    /// signer, and re-run there because a reload re-derives everything from
    /// the file.
    ///
    /// Without a verifier the pass still covers **this node's own** records
    /// through the signer: Ed25519 is deterministic (RFC 8032), so re-signing
    /// the same message with the same key must reproduce the same bytes, and
    /// a record the file attributes to this node whose signature is not the
    /// one this node would produce was not written by this node as it stands.
    verifier: Option<DirectiveVerifier>,
    /// Content ids of enveloped DAG directives whose signature has not been
    /// checked yet (H-20).
    ///
    /// Filled by boot's history loop, drained by
    /// [`Self::verify_own_history`] as soon as a signer or verifier gives it
    /// the means; empty on a running node, so every later call costs one
    /// `is_empty`. Each directive is verified exactly once even when the
    /// signer and the verifier are installed in two steps: the signer's pass
    /// drains this node's own records, the verifier's the rest.
    unverified_history: BTreeSet<String>,
    /// How many directives the signature pass has quarantined in this
    /// service's life, across every pass (T80, 0924 §5): the setters,
    /// `finalize_operator_input` and `verify_own_history` each run the pass,
    /// and a caller that reports only the last one's return misses what the
    /// earlier ones quarantined.
    signature_quarantined_total: usize,
    /// Signatures the pass has checked and accepted, across every pass (T89 /
    /// L-98): the "every signature failed" judgement is made once, over all
    /// passes, not per pass — the signer's pass sees only this node's own
    /// records, so two edited own records made it fire while every foreign
    /// record verified a moment later.
    signature_verified_total: usize,
    /// Refusals whose reason is "signature does not verify", across every
    /// pass (T89 / L-98).
    signature_failed_total: usize,
    /// Operator input `finalize_operator_input` has just signed, awaiting the
    /// pass that checks it (T92 / L-114, decision (41)). The pass still checks
    /// each (a signer and a verifier bound to different mesh ids is what it
    /// catches), but a signature this node made moments ago says nothing about
    /// whether the HISTORY verifies, so it does not count towards
    /// `signature_verified_total`: before T92 one hand line in the same boot —
    /// or one write before the next — hid the "every signature failed / do not
    /// author" verdict on a `meshId` or key mismatch, and released the clock
    /// the verdict had put on hold.
    signed_by_finalize: HashSet<String>,
    /// Edited records whose clock release is on hold because every signature
    /// checked so far has failed (T89 / L-99, decision (32)) — see
    /// [`Self::verify_history_pass`].
    release_on_hold: BTreeSet<String>,
    /// History boot refused under a content rule every peer holds it to,
    /// and everything that descends from it (T81 / M-51, M-52) — see
    /// [`Self::quarantine_descendants_of_refused_history`]. Kept so the live
    /// reconcile, which re-reads the whole file after any hand edit, refuses
    /// a descendant again instead of re-adopting it: it is a valid record
    /// whose only fault is its parent — and, since T85 (M-56), so the wire
    /// (`stage_remote_directive`) refuses the same set, permanently. Seeded by
    /// the two T75 ceilings, the amount cap and (T85, L-101) the body cap.
    /// Re-derived by every boot and reload.
    refused_history_closure: BTreeSet<String>,
    /// The other enveloped copies of a record boot met in the file (T99 /
    /// M-72, decision (58)): a content id hashes the body alone, so the
    /// canonical file and the journal can spell one record under two
    /// envelopes — the file's copy held by the closure or the signature pass,
    /// and the journal's copy re-entered through the API or adopted from a
    /// peer. Kept until the node has judged which copy it serves: every step
    /// that is about to hold a record first tries these
    /// ([`Self::choose_servable_copies`]). A copy displaced by another joins
    /// the list. Re-derived by every boot and reload.
    alternative_copies: BTreeMap<String, Vec<Directive>>,
    /// Envelope-less copies of a record the DAG held as history when boot met
    /// them, keyed by the stored id (T99 / L-143, decision (59)): an operator
    /// retyping a held record beside it. Adopted as operator input the moment
    /// the history copy is held — by the served-set rule or the signature
    /// pass ([`Self::adopt_typed_copies_of_held_records`]) — as the in-place
    /// strip remedy would be; dropped by `finalize_operator_input` otherwise
    /// (the history copy is served, and the typed one is a duplicate).
    typed_copies: BTreeMap<String, Directive>,
    /// A typed spelling of a record held beside an enveloped copy of the same
    /// id (T99 / L-145, decision (59)): the quarantine keeps the enveloped copy
    /// (L-76), and this keeps the operator's block too, so the compaction
    /// writes both back and "kept in the file as written" is true.
    quarantined_typed: BTreeMap<String, Directive>,
    /// The content ids of the entries the live reconcile in progress is
    /// adopting (T85): a complete-envelope record whose parent is not yet in
    /// the DAG may name one that comes later in canonical (date) order in the
    /// same file. Empty outside [`Self::reconcile_content`]'s adoption loop.
    reconcile_batch_ids: HashSet<String>,
    /// Content ids of the directives [`Self::boot`] adopted as **operator
    /// input** whose envelope is not final yet (H-13).
    ///
    /// # The finding
    ///
    /// The README's only supported edit workflow is *stop the node, edit the
    /// file, start it again* — and boot treated whatever it read as history:
    /// a hand-typed block was inserted with the metadata it had (none), the
    /// file's hash became the baseline, the startup compaction found nothing
    /// to adopt and rewrote the record **without an envelope**, and the signer
    /// was installed after all of that anyway. Every peer refused the record
    /// (`EnvelopeMissing`), the node's next transaction named it as a parent,
    /// and everything this node authored from then on lived on this node
    /// alone. The operator had done exactly what the README said.
    ///
    /// # The decision: envelope-less file directives are operator input
    ///
    /// Boot has one signal to tell history from input, and it is exact: a
    /// node never writes a directive without `openledger-author` and
    /// `openledger-lamport`, so a directive carrying **neither** was typed by
    /// a human (or written by a build older than M-18, which stamped only
    /// transactions — the README's standing policy, *operator input is a
    /// local append*, covers those too: they are adopted as this node's own,
    /// once, and canonicalised by the compaction that follows). Such a
    /// directive goes through the same adoption
    /// [`Self::reconcile_content`] applies to a live hand edit —
    /// [`Self::adopt_file_directive`]: the validators, the author/lamport
    /// stamp, parents via `heads_admissible_as_parents_of`, the resolved-body
    /// cap, the insert — and a refusal is **quarantined**, not dropped: boot's
    /// standing rule is that it loses nothing, so the raw text stays in the
    /// file and out of the DAG until the operator repairs it (H-08).
    ///
    /// # Why the signature is deferred, and only the signature
    ///
    /// This crate does not depend on `security`; the signer reaches the
    /// service through [`Self::set_signer`] after the node has loaded its key
    /// — after `boot`, and after `set_author_id` has replaced the placeholder
    /// author `gl-node` boots with. So boot adopts (the DAG, the account
    /// state and the parents are fixed here, where every caller that asserts
    /// on `directive_count` after boot expects them; the lamport written here
    /// is a placeholder that does not move the clock) and records the stored
    /// ids; [`Self::finalize_operator_input`] then, once the identity is known
    /// and the signature pass has settled the clock, stamps the lamport (T84 /
    /// M-57, decision (16)), writes the real author id over the placeholder
    /// and signs. The parents may be re-chosen in between by the H-22 rebase;
    /// the signature covers what finalisation leaves.
    ///
    /// `gl-node` calls `finalize_operator_input` right after `set_signer` and
    /// before the startup compaction and the P2P tasks; [`Self::prepare`]
    /// calls it before any compaction for library callers, which is where a
    /// service with no signer installed adopts unsigned — exactly as a
    /// reconcile with no signer does today. An L-13 reload re-derives this
    /// set from the file (the raw entries are still there until a compaction
    /// succeeds) and [`Self::finish_recovery`] finalises it again with the
    /// carried signer.
    unsigned_operator_input: Vec<String>,
    /// The subset of [`Self::unsigned_operator_input`] whose
    /// `openledger-author` the FILE spelled (M-47).
    ///
    /// Since M-47 a half envelope is operator input, so an adopted entry may
    /// carry an author the operator typed rather than the one boot stamped.
    /// `finalize_operator_input` writes this node's id only over the stamp;
    /// since T79 (M-54) a file-spelled author that names another node is
    /// refused there — quarantined as the file spelled it — because this node
    /// cannot sign for it and every peer refuses it unsigned.
    operator_input_with_file_author: BTreeSet<String>,
    /// Each entry of [`Self::unsigned_operator_input`] as the FILE spelled it,
    /// keyed by its stored id, with the file's content id (they differ when
    /// I2 resolved an elided posting) (T79 / H-22).
    ///
    /// Boot adopts operator input before the node's identity is complete, so
    /// a later step can still refuse an entry it already stamped: the
    /// signature pass can quarantine the parent it was stamped against, and
    /// `finalize_operator_input` refuses a foreign author. A refused entry is
    /// quarantined as written — never a half-stamped copy, which the next
    /// boot would mistake for history. Cleared by `finalize_operator_input`.
    operator_input_as_written: BTreeMap<String, (String, Directive)>,
    /// The highest lamport per author among the records boot saw that did
    /// NOT reach the DAG (L-67, T78) — see [`BootLamportHigh`]. Boot folds
    /// only its own author's entry into the clock; `gl-node` boots under a
    /// placeholder author, so [`Self::set_author_id`] folds the real one's.
    /// One entry per distinct author outside the DAG; re-derived by every
    /// boot, so an L-13 reload replaces it.
    boot_outside_dag_lamports: BTreeMap<String, u64>,
    /// The clock value boot resumed from (L-67, T78): what
    /// [`Self::set_author_id`] compares the new author's out-of-DAG high
    /// against, raising the clock exactly as a boot under the new author would
    /// have. Operator input is stamped from the result at finalisation (T84).
    boot_clock_base: u64,

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
    /// The canonical form of this ledger — what every compaction writes — is
    /// larger than [`MAX_LEDGER_FILE_BYTES`] (T82 / L-80).
    ///
    /// Set where the canonical size is measured — boot, the finalisation of
    /// boot's operator input, a reconcile of a hand edit — and cleared by a
    /// compaction that succeeded (which proves the canonical form fits). While
    /// it is set every write would need a compaction that `persist_atomically`
    /// refuses, so [`Self::append_headroom`] reports 0 — `gl-node` then refuses
    /// a mutation and defers a peer batch before staging, with no reload — and
    /// `prepare`'s compaction arm refuses with `ResourceLimitExceeded` instead
    /// of building the text and failing at the write.
    canonical_over_cap: bool,
    /// Byte length of the journal on disk, as of the last commit.
    canonical_journal_bytes: u64,
    /// Content ids inserted since the last commit and not yet written anywhere.
    ///
    /// Ids, not directives: the record is built by resolving them against the
    /// DAG at prepare time, which costs one `serialize_directive` per staged
    /// directive and keeps the memory overhead of a large catch-up batch at 64
    /// bytes per entry instead of a second full clone of every body.
    ///
    /// Only what this node STAGED — its own writes and peer arrivals. What it
    /// adopted from the `.bean` is on disk already and lives in
    /// [`Self::adopted_from_file`] (M-46).
    pending_ids: Vec<String>,
    /// Content ids adopted FROM the `.bean` — boot's operator input (H-13)
    /// and a live reconcile's inserts — since the last compaction (M-46).
    ///
    /// Not staged: the file holds every one of them, in the operator's
    /// spelling. They used to be pushed onto `pending_ids`, and the L-13
    /// floor subtracts `pending_ids` as "never on disk", so each adopted line
    /// lowered the floor by one: a backup copied over the live file (M acked
    /// records out, N ≥ M others in) plus one failed commit installed the
    /// replacement over memory, and the next write made the loss durable.
    /// Kept apart, they are what [`Self::finish_recovery`] may see absent
    /// *only* because the operator removed their own raw lines before the
    /// rewrite that would have canonicalised them. Non-empty forces the next
    /// commit to be a compaction (an append cannot re-spell a raw line);
    /// cleared by that compaction's receipt.
    adopted_from_file: HashSet<String>,
    /// Set when the next commit MUST be a full rewrite rather than an append.
    ///
    /// Three producers, all of them cases an append cannot express: a
    /// [`Self::stamp_signature`] that mutated a directive already on disk (a
    /// journal record carrying the same content id would be dropped by the
    /// G-Set on the way back in, losing the signature); a reconcile, which has
    /// to *remove* refused entries from the file; and a journal whose tail was
    /// torn by a crash, which cannot be safely appended to.
    force_compaction: bool,
    /// The boot that built this service dropped a torn journal tail (M-43) —
    /// or an L-13 reload since then saw one, or could not read the files at
    /// all (M-49).
    ///
    /// The compaction that folds that journal renames it to
    /// `<journal>.torn-<unix-seconds>` instead of deleting it
    /// ([`crate::journal::retire_torn_journal`]): "torn" is a judgement about
    /// bytes, and the bytes it dropped are never destroyed on the strength of
    /// it. Cleared by the first compaction's receipt; re-derived by every
    /// boot, so an L-13 reload of a still-torn journal sets it again — and a
    /// *refused* or *failed* reload ORs it in, see [`Self::finish_recovery`].
    journal_torn_at_boot: bool,
    /// Bumped by every [`Self::prepare_commit`]; stamped into the
    /// [`PendingCommit`] and checked by [`Self::finish_commit`].
    commit_generation: u64,
    /// The generation of the commit currently outstanding, or
    /// [`IDLE_COMMIT_GENERATION`] when none is (H-11).
    ///
    /// Was a plain `bool` until H-11 showed that a flag whose only clears live
    /// after an `await` is a flag a cancelled future leaks forever. It is now
    /// owned by a [`CommitInFlightGuard`] that [`Self::prepare`] hands out
    /// inside the [`PendingCommit`]; behind an `Arc` because that guard has to
    /// be able to release it from a `Drop`, which cannot take the ledger lock.
    /// See [`Self::prepare_commit`] for the single-writer contract it enforces
    /// and [`CommitInFlightGuard`] for the leak it closes.
    commit_in_flight: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// The process-wide single-writer gate (see [`Self::commit_gate`]).
    commit_gate: std::sync::Arc<tokio::sync::Mutex<()>>,
    /// Test seam; `None` in production. See [`CommitObserver`].
    commit_observer: Option<CommitObserver>,
    /// The last [`Self::sorted_directive_ids`] snapshot, keyed by the DAG size
    /// it was taken at (L-35).
    ///
    /// The DAG is a grow-only set for the life of a service — nothing removes
    /// a node, and an L-13 reload replaces the whole service, this field
    /// included — so "same size" means "same set" and the size is a complete
    /// invalidation key. Behind a `Mutex` because the snapshot is taken under
    /// the ledger's READ lock, by any number of concurrent readers.
    directive_id_snapshot: std::sync::Mutex<Option<(usize, std::sync::Arc<[String]>)>>,
    /// The last [`Self::served_sorted_directive_ids`] snapshot, keyed by the
    /// DAG size and the number of held-back file-adopted lines it was taken at
    /// (T95, the L-116 advert cost): without it, a node whose compaction kept
    /// failing cloned every id on every anti-entropy advert. The held-back set
    /// only grows (adoption) or empties (a successful rewrite) between
    /// rebuilds, and `rebuild_dag` resets this with the other snapshot.
    served_id_snapshot: std::sync::Mutex<Option<ServedIdSnapshot>>,
    /// The ids this node withholds from peers, cached under their
    /// [`WithheldKey`] (T100) — see [`Self::withheld_ids`].
    withheld_snapshot: std::sync::Mutex<Option<(WithheldKey, std::sync::Arc<HashSet<String>>)>>,
    /// The staged ids and the committed records they name, cached under the
    /// staged count and last id (T100 / L-149) — see
    /// [`Self::choose_committed_parents`].
    staged_frontier: std::sync::Mutex<Option<StagedFrontier>>,
    /// The join window (H-19): while open, a directive the caller marks as
    /// from the node's join peer ([`RemoteSource::JoinPeer`]) is adopted
    /// without the adoption ratchet — see [`Self::open_join_trust`].
    join_trust: bool,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
