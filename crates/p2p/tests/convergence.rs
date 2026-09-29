//! Multi-replica convergence harness — the standing test of the mesh invariant
//! **"same available directive set ⇒ same committed state on every replica"**
//! (0923 decisions: built before T72 so that the H-19 and H-21 shapes are on
//! record failing at HEAD, and stay as regressions once T72 lands).
//!
//! # What "converged" means here (wave brief rule 5)
//!
//! Equal DAG membership (sorted content ids), equal heads and equal balances —
//! the `trial_balance` text plus every account's all-time balance — across
//! every replica at a fixed point, and equal to a single *oracle* service that
//! ingested the whole authored pool in causal order. A failure names the first
//! divergent id, which replicas hold it, and what the others last said about it.
//!
//! # What "intake" means here
//!
//! The real ALPN path, not a proxy: [`validate_supply_entry`] →
//! [`verify_author_allowlisted`] → [`verify_remote_signature`] (signing on,
//! real Ed25519 keys, author id = the verifying key's hex) → missing parents
//! and account waits buffered in the real [`OrphanBuffer`] and drained like
//! `gl-node`'s `drain_orphans` → [`LedgerService::stage_remote_directive`] →
//! `prepare_commit` / `commit` / `finish_commit`. Refusals are classified
//! exactly as `gl-node`'s `intake_refusal_is_permanent` /
//! `stage_refusal_is_permanent` (mirrored below, those two are private):
//! permanent ones are remembered (the L-34 cache) and never re-`Want`ed;
//! everything else is dropped and re-offered next round.
//!
//! # Delivery
//!
//! Two feeds. **Pool-fed:** a replica is offered pool entries — exactly the
//! `SupplyEntry` the author's node would emit ([`make_supply_entry`]) — in a
//! chosen subset and [`Order`]; this models a serving peer (honest or
//! adversarial) that holds everything. **Anti-entropy:** each replica is offered,
//! from every other replica, the ids it lacks by membership, produced from the
//! holder's own DAG through [`build_supply`]; this models the mesh after the
//! adversarial peer is gone. Rounds run to a fixed point (no replica changes in
//! a full round), bounded.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::NaiveDate;
use ledger::hash::compute_content_id;
use ledger::model::{Amount, Directive, Flag, Open, Posting, Transaction};
use ledger::service::{
    DirectiveSigner, LedgerService, PostingInput, RemoteSource, ServiceError, TransactionInput,
    MAX_LAMPORT_ADVANCE, MAX_PARENTS,
};
use ledger::validate::ValidationError;
use p2p::allowlist::PeerAllowlist;
use p2p::anti_entropy::{build_supply, order_want_ancestors_first};
use p2p::gossip::make_supply_entry;
use p2p::orphan_buffer::{OrphanBuffer, OrphanEntry};
use p2p::protocol::{SupplyEntry, WireMessage};
use p2p::union_merge::{
    validate_supply_entry, verify_author_allowlisted, verify_remote_signature, MergeError,
};
use proptest::prelude::*;
use rust_decimal::Decimal;
use security::signing::{PeerKeySignatureProvider, SignableMessage, SignatureProvider};

/// Every key in the harness signs for this mesh (L2 / L-23 binding).
const MESH_ID: &str = "convergence-harness";
/// Signing is on: intake refuses an unsigned or mis-signed envelope.
const SIGNING_ENABLED: bool = true;
/// Bound on rounds to a fixed point. The DAG is monotone and the pool finite,
/// so a mesh still changing after this many rounds is a harness bug.
const MAX_ROUNDS: usize = 40;

fn day(d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(2024, 1, d).expect("valid date")
}

fn far_future() -> NaiveDate {
    NaiveDate::from_ymd_opt(2999, 12, 31).expect("valid date")
}

// ─── Deterministic randomness (no `rand` dependency needed) ─────────────────

/// xorshift64* — deterministic per seed, good enough to pick subsets and orders.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng((seed ^ 0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `0..n`; `n` must be non-zero.
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(n).expect("usize fits u64"))
            .expect("bounded by n")
    }

    fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }

    fn subset<T: Clone>(&mut self, items: &[T]) -> Vec<T> {
        items.iter().filter(|_| self.coin()).cloned().collect()
    }
}

// ─── Keys and hand-built (attacker / pre-T63) directives ────────────────────

/// A real Ed25519 key, deterministic from a one-byte seed.
fn key(seed: u8) -> Arc<PeerKeySignatureProvider> {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let i = u8::try_from(index).expect("32 < 256");
        *byte = seed.wrapping_mul(31).wrapping_add(i).wrapping_mul(7) ^ 0x5C;
    }
    Arc::new(PeerKeySignatureProvider::from_bytes(
        &bytes,
        MESH_ID.to_owned(),
    ))
}

fn sign(key: &PeerKeySignatureProvider, message: &SignableMessage<'_>) -> String {
    key.sign(message)
        .expect("PeerKeySignatureProvider always signs")
}

/// The reconcile-path signer a node installs at boot (`set_signer`).
fn signer(key: &Arc<PeerKeySignatureProvider>) -> DirectiveSigner {
    let key = Arc::clone(key);
    Arc::new(move |content_id, is_transaction, parents, lamport| {
        key.sign(&SignableMessage {
            content_id,
            is_transaction,
            parents,
            lamport,
        })
    })
}

fn usd(amount: i64) -> Amount {
    Amount {
        number: Decimal::from(amount),
        currency: "USD".to_owned(),
    }
}

fn posting(account: &str, amount: i64) -> Posting {
    Posting {
        account: account.to_owned(),
        amount: Some(usd(amount)),
        cost: None,
        price: None,
        metadata: BTreeMap::new(),
    }
}

/// A balanced two-posting body: `account` +amount, `Equity:Opening` −amount.
fn transaction_body(narration: &str, amount: i64, account: &str) -> Transaction {
    Transaction {
        date: day(15),
        flag: Flag::Complete,
        payee: None,
        narration: Some(narration.to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![posting(account, amount), posting("Equity:Opening", -amount)],
        metadata: BTreeMap::new(),
    }
}

/// An `open` stamped and signed by hand with `key` at `lamport` — what an
/// allowlisted-but-hostile node, or a pre-T63 node, would have emitted.
fn hand_open(key: &PeerKeySignatureProvider, account: &str, lamport: u64) -> Directive {
    let mut open = Open {
        date: day(1),
        account: account.to_owned(),
        currencies: vec![],
        metadata: BTreeMap::new(),
    };
    let content_id = compute_content_id(&Directive::Open(open.clone()));
    let lamport = lamport.to_string();
    let signature = sign(
        key,
        &SignableMessage {
            content_id: &content_id,
            is_transaction: false,
            parents: "",
            lamport: &lamport,
        },
    );
    open.metadata
        .insert("openledger-author".to_owned(), key.public_key_hex());
    open.metadata
        .insert("openledger-lamport".to_owned(), lamport);
    open.metadata
        .insert("openledger-signature".to_owned(), signature);
    Directive::Open(open)
}

/// A transaction stamped and signed by hand with `key`, naming `parents`
/// (canonical: sorted, comma-joined; empty = parentless).
fn hand_transaction(
    key: &PeerKeySignatureProvider,
    narration: &str,
    amount: i64,
    parents: &[String],
    lamport: u64,
) -> Directive {
    let mut parents: Vec<String> = parents.to_vec();
    parents.sort();
    let parents = parents.join(",");
    let mut txn = transaction_body(narration, amount, "Assets:Cash");
    let content_id = compute_content_id(&Directive::Transaction(txn.clone()));
    let lamport = lamport.to_string();
    let signature = sign(
        key,
        &SignableMessage {
            content_id: &content_id,
            is_transaction: true,
            parents: &parents,
            lamport: &lamport,
        },
    );
    txn.metadata
        .insert("openledger-author".to_owned(), key.public_key_hex());
    txn.metadata
        .insert("openledger-lamport".to_owned(), lamport);
    txn.metadata
        .insert("openledger-parents".to_owned(), parents);
    txn.metadata
        .insert("openledger-signature".to_owned(), signature);
    Directive::Transaction(txn)
}

// ─── Refusal classification (mirrors gl-node's private classifiers) ─────────

/// `gl-node::anti_entropy_alpn::intake_refusal_is_permanent`, verbatim.
fn intake_refusal_is_permanent(error: &MergeError) -> bool {
    match error {
        MergeError::ContentHashMismatch { .. }
        | MergeError::ParseError(_)
        | MergeError::ValidationError(_)
        | MergeError::EnvelopeMissing(_)
        | MergeError::InvalidSignature(_)
        | MergeError::ResourceLimitExceeded(_)
        | MergeError::CycleDetected
        | MergeError::InvalidEnvelope(_)
        | MergeError::BodyEnvelopeKey(_)
        | MergeError::BodyControlCharacter(_)
        | MergeError::ElidedPosting => true,
    }
}

/// `gl-node::anti_entropy_alpn::stage_refusal_is_permanent`, verbatim.
fn stage_refusal_is_permanent(error: &ServiceError) -> bool {
    match error {
        ServiceError::Validation(validation) => match validation {
            ValidationError::UnbalancedTransaction { .. }
            | ValidationError::InvalidElision { .. }
            | ValidationError::InvalidPosting { .. } => true,
            ValidationError::AccountNotOpen { .. }
            | ValidationError::AccountClosed { .. }
            | ValidationError::AccountCurrencyMismatch { .. } => false,
        },
        ServiceError::AccountHasLaterTransactions { .. }
        | ServiceError::ResourceLimitExceeded { .. }
        | ServiceError::InvalidAccountName { .. }
        | ServiceError::InvalidCurrency { .. }
        | ServiceError::InvalidTag { .. }
        | ServiceError::InvalidLink { .. }
        | ServiceError::InvalidInput { .. }
        | ServiceError::DateOutOfRange { .. }
        | ServiceError::BodyEnvelopeKey { .. } => true,
        ServiceError::AccountNotOpen { .. }
        | ServiceError::AccountAlreadyOpen { .. }
        | ServiceError::Dag(_)
        | ServiceError::LamportCeiling { .. }
        | ServiceError::LamportAdvance { .. }
        | ServiceError::Io(_)
        | ServiceError::Journal { .. }
        | ServiceError::CommitInFlight
        | ServiceError::Parse(_) => false,
        // L-114: only this node's own stamp refuses so — never a peer's record.
        ServiceError::SignatureVerdict { .. } => false,
    }
}

/// `gl-node::anti_entropy_alpn::account_wait_target`, verbatim (M-09).
fn account_wait_target(error: &ServiceError) -> Option<String> {
    let ServiceError::Validation(validation) = error else {
        return None;
    };
    match validation {
        ValidationError::AccountNotOpen { account, .. }
        | ValidationError::AccountClosed { account, .. }
        | ValidationError::AccountCurrencyMismatch { account, .. } => Some(account.clone()),
        _ => None,
    }
}

// ─── One replica ────────────────────────────────────────────────────────────

static FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_bean(name: &str) -> PathBuf {
    let n = FILE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ol-convergence-{}-{ts}-{n}-{name}.bean",
        std::process::id()
    ))
}

/// What one admitted entry became under the write lock.
enum Staged {
    Inserted,
    Duplicate,
    /// In the orphan buffer, waiting on this (parent id or account).
    Buffered(String),
    Refused,
}

/// A `LedgerService` booted on its own `.bean`, with a real key, the real
/// orphan buffer and an L-34-shaped memory of permanent refusals.
struct Replica {
    name: String,
    key: Arc<PeerKeySignatureProvider>,
    path: PathBuf,
    svc: LedgerService,
    orphans: OrphanBuffer,
    /// L-34: ids refused for a content-determined reason, with the reason.
    permanent: BTreeMap<String, String>,
    /// The last retryable refusal per id — diagnostics for the divergence report.
    retryable: BTreeMap<String, String>,
    /// A1 (0924): a replica "stopped" by [`Replica::stop`] leaves its `.bean`
    /// on disk for a later boot (the README's stop → edit → start).
    keep_files: bool,
    /// H-19: the replica this one joins from (`p2p.joinFrom`), by name.
    join_from: Option<String>,
    /// The replica serving the batch `intake_from` is staging, by name.
    delivering: Option<String>,
}

impl Replica {
    fn boot(name: &str, key: Arc<PeerKeySignatureProvider>) -> Self {
        Self::boot_at(name, key, temp_bean(name))
    }

    /// The trusted-bootstrap join: copy a peer's `.bean` and boot on the copy
    /// under this replica's own key.
    fn boot_from_copy_of(name: &str, key: Arc<PeerKeySignatureProvider>, source: &Path) -> Self {
        let path = temp_bean(name);
        std::fs::copy(source, &path).expect("copy the peer's ledger file");
        Self::boot_at(name, key, path)
    }

    fn boot_at(name: &str, key: Arc<PeerKeySignatureProvider>, path: PathBuf) -> Self {
        let mut svc = LedgerService::boot(path.clone(), key.public_key_hex())
            .unwrap_or_else(|error| panic!("{name}: boot: {error}"));
        svc.set_signer(signer(&key));
        Replica {
            name: name.to_owned(),
            key,
            path,
            svc,
            orphans: OrphanBuffer::new(),
            permanent: BTreeMap::new(),
            retryable: BTreeMap::new(),
            keep_files: false,
            join_from: None,
            delivering: None,
        }
    }

    fn author(&self) -> String {
        self.key.public_key_hex()
    }

    fn open(&mut self, account: &str) -> Directive {
        let key = Arc::clone(&self.key);
        let id = self
            .svc
            .open_account_signing(
                account.to_owned(),
                day(1),
                vec![],
                |content_id, parents, lamport| {
                    key.sign(&SignableMessage {
                        content_id,
                        is_transaction: false,
                        parents,
                        lamport,
                    })
                },
            )
            .unwrap_or_else(|error| panic!("{}: open {account}: {error}", self.name));
        self.svc.get_directive(&id).expect("just opened").clone()
    }

    fn append(&mut self, narration: &str, amount: i64, account: &str) -> Directive {
        let key = Arc::clone(&self.key);
        let input = TransactionInput {
            date: day(15),
            flag: Flag::Complete,
            payee: None,
            narration: Some(narration.to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: account.to_owned(),
                    amount: Some(usd(amount)),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(usd(-amount)),
                    cost: None,
                    price: None,
                },
            ],
        };
        let outcome = self
            .svc
            .append_transaction_signing(input, |content_id, parents, lamport| {
                key.sign(&SignableMessage {
                    content_id,
                    is_transaction: true,
                    parents,
                    lamport,
                })
            })
            .unwrap_or_else(|error| panic!("{}: append {narration}: {error}", self.name));
        assert!(
            !outcome.already_existed,
            "{}: append {narration}: body already in the ledger (bodies must be distinct)",
            self.name
        );
        self.svc
            .get_directive(&outcome.txid)
            .expect("just appended")
            .clone()
    }

    /// The two-phase durable commit the node layer drives (T44).
    fn commit(&mut self) {
        if let Some(pending) = self
            .svc
            .prepare_commit()
            .unwrap_or_else(|error| panic!("{}: prepare_commit: {error}", self.name))
        {
            let receipt = pending
                .commit()
                .unwrap_or_else(|error| panic!("{}: commit: {error}", self.name));
            self.svc.finish_commit(receipt);
        }
    }

    fn note_intake_refusal(&mut self, id: &str, error: &MergeError) {
        if intake_refusal_is_permanent(error) {
            self.permanent
                .insert(id.to_owned(), format!("intake: {error}"));
        } else {
            self.retryable
                .insert(id.to_owned(), format!("intake: {error}"));
        }
    }

    fn note_stage_refusal(&mut self, id: &str, error: &ServiceError) {
        let reason = format!("{} ({error})", error.error_code());
        if stage_refusal_is_permanent(error) {
            self.permanent.insert(id.to_owned(), reason);
        } else {
            self.retryable.insert(id.to_owned(), reason);
        }
    }

    /// One batch through the real intake: `apply_supply_entries_from` phase 1
    /// (validators off the lock) and phase 2 (`stage_and_commit_batch`), the
    /// post-batch drain, and one commit for the batch. Returns what was staged.
    fn intake(&mut self, entries: Vec<SupplyEntry>, allowlist: &PeerAllowlist) -> usize {
        self.intake_from(entries, allowlist, None)
    }

    /// [`Self::intake`] of a batch `from` served — gl-node's
    /// `apply_supply_entries_from` names the delivering peer, and the join
    /// peer's directives skip the ratchet while the join window is open (H-19).
    fn intake_from(
        &mut self,
        entries: Vec<SupplyEntry>,
        allowlist: &PeerAllowlist,
        from: Option<&str>,
    ) -> usize {
        self.delivering = from.map(str::to_owned);
        let staged = self.intake_batch(entries, allowlist);
        self.delivering = None;
        staged
    }

    fn intake_batch(&mut self, entries: Vec<SupplyEntry>, allowlist: &PeerAllowlist) -> usize {
        // Phase 1 — dedup before validate (M-14), then the wire validators.
        let mut admitted: Vec<(String, Directive)> = Vec::new();
        for entry in entries {
            if self.svc.contains_directive(&entry.id) || self.permanent.contains_key(&entry.id) {
                continue;
            }
            let directive = match validate_supply_entry(&entry) {
                Ok(directive) => directive,
                Err(error) => {
                    self.note_intake_refusal(&entry.id, &error);
                    continue;
                }
            };
            if let Err(error) = verify_author_allowlisted(&directive, allowlist) {
                self.note_intake_refusal(&entry.id, &error);
                continue;
            }
            if let Err(error) = verify_remote_signature(&directive, SIGNING_ENABLED, MESH_ID) {
                self.note_intake_refusal(&entry.id, &error);
                continue;
            }
            admitted.push((entry.id, directive));
        }

        // Phase 2 — under the (notional) write lock, in arrival order.
        let mut staged = 0;
        for (id, directive) in admitted {
            if matches!(self.stage(&id, directive), Staged::Inserted) {
                staged += 1;
            }
        }
        if staged > 0 {
            staged += self.drain(allowlist);
        }
        self.commit();
        staged
    }

    /// `stage_and_commit_batch`'s per-entry body: missing parents → orphan
    /// buffer; stage; an account-lifecycle refusal → buffer awaiting the open
    /// (M-09); anything else → a refusal, permanent or retryable.
    fn stage(&mut self, id: &str, directive: Directive) -> Staged {
        if self.svc.contains_directive(id) {
            return Staged::Duplicate;
        }
        // H-19: the join peer's copies are buffered under its name, so a
        // freed one is staged as the join peer's; any other peer's under one.
        let from_join_peer = self.delivering.is_some() && self.delivering == self.join_from;
        let buffered_as = if from_join_peer {
            self.delivering.clone()
        } else {
            Some("peer".to_owned())
        };
        let source = if from_join_peer {
            RemoteSource::JoinPeer
        } else {
            RemoteSource::Peer
        };
        let missing = self.svc.missing_parent_ids(&directive);
        if let Some(first) = missing.first().cloned() {
            self.orphans
                .insert(id.to_owned(), directive, missing, buffered_as);
            return Staged::Buffered(format!("parent {first}"));
        }
        match self
            .svc
            .stage_remote_directive_from(directive.clone(), source)
        {
            Ok(Some(_)) => Staged::Inserted,
            Ok(None) => Staged::Duplicate,
            Err(error) => match account_wait_target(&error) {
                Some(account) => {
                    self.orphans.insert_awaiting_accounts(
                        id.to_owned(),
                        directive,
                        vec![account.clone()],
                        buffered_as,
                    );
                    Staged::Buffered(format!("account {account}"))
                }
                None => {
                    self.note_stage_refusal(id, &error);
                    Staged::Refused
                }
            },
        }
    }

    /// `drain_orphans`, to the letter: re-validate and stage every freed entry,
    /// loop while something real happens.
    fn drain(&mut self, allowlist: &PeerAllowlist) -> usize {
        let mut staged = 0;
        let mut attempted: HashSet<(String, String)> = HashSet::new();
        let mut resolved_any = true;
        while resolved_any {
            resolved_any = false;
            for parent in self.orphans.wanted_parent_ids() {
                if !self.svc.contains_directive(&parent) {
                    continue;
                }
                for entry in self.orphans.parent_arrived(&parent) {
                    resolved_any |= self.restage(entry, allowlist, &mut attempted, &mut staged);
                }
            }
            for account in self.orphans.wanted_accounts() {
                if !self.svc.accounts().has_open(&account) {
                    continue;
                }
                for entry in self.orphans.account_opened(&account) {
                    resolved_any |= self.restage(entry, allowlist, &mut attempted, &mut staged);
                }
            }
        }
        staged
    }

    /// `restage_freed_entry` + `made_progress`.
    fn restage(
        &mut self,
        entry: OrphanEntry,
        allowlist: &PeerAllowlist,
        attempted: &mut HashSet<(String, String)>,
        staged: &mut usize,
    ) -> bool {
        if let Err(error) = verify_author_allowlisted(&entry.directive, allowlist) {
            self.note_intake_refusal(&entry.id, &error);
            return false;
        }
        if let Err(error) = verify_remote_signature(&entry.directive, SIGNING_ENABLED, MESH_ID) {
            self.note_intake_refusal(&entry.id, &error);
            return false;
        }
        // A freed entry is staged as its delivering peer's (H-19).
        self.delivering = entry.from_peer.clone();
        let outcome = self.stage(&entry.id, entry.directive);
        self.delivering = None;
        match outcome {
            Staged::Inserted => {
                *staged += 1;
                true
            }
            Staged::Buffered(reason) => attempted.insert((entry.id, reason)),
            Staged::Duplicate | Staged::Refused => false,
        }
    }

    fn snapshot(&self) -> Snapshot {
        let ids: BTreeSet<String> = self.svc.all_directive_ids().into_iter().collect();
        let heads: BTreeSet<String> = self.svc.head_txids().into_iter().collect();
        let balances = balances_text(&self.svc);
        let mut notes: BTreeMap<String, String> = BTreeMap::new();
        for (id, reason) in &self.permanent {
            notes.insert(id.clone(), format!("refused for good: {reason}"));
        }
        for (id, reason) in &self.retryable {
            notes
                .entry(id.clone())
                .or_insert_with(|| format!("last retryable refusal: {reason}"));
        }
        let mut waiting: Vec<String> = self.orphans.wanted_parent_ids().into_iter().collect();
        waiting.sort();
        Snapshot {
            ids,
            heads,
            balances,
            clock: self.svc.lamport_clock(),
            notes,
            orphans: self.orphans.len(),
            waiting_on_parents: waiting,
        }
    }
}

impl Drop for Replica {
    fn drop(&mut self) {
        if self.keep_files {
            return;
        }
        let _ = std::fs::remove_file(self.svc.journal_path());
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Every balance view a report reads, as text: the trial balance at a far
/// date plus each account's all-time balance.
fn balances_text(svc: &LedgerService) -> String {
    let report = svc.read_model().trial_balance(far_future());
    let mut text = String::new();
    for row in &report.rows {
        writeln!(
            text,
            "{} debit={} credit={}",
            row.account, row.debit, row.credit
        )
        .expect("write to String");
    }
    writeln!(
        text,
        "total debit={} credit={}",
        report.total_debit, report.total_credit
    )
    .expect("write to String");
    for row in &report.rows {
        let entry = svc.read_model().account_balance(&row.account, None);
        writeln!(text, "{} all-time={entry:?}", row.account).expect("write to String");
    }
    text
}

/// What "converged" compares across replicas: membership, heads and balances.
///
/// L-86 (0924, documented in T83): heads are compared on purpose, and one
/// honest shape differs in heads only — a local write whose commit failed
/// after a peer had already fetched it, then retried by the caller: same
/// content id, a different envelope (lamport, parents, signature), and each
/// node keeps the copy it got first. Membership and balances agree; the head
/// sets do not. The harness never produces a failed commit, so it never meets
/// that shape; a case that does must compare membership and balances only.
struct Snapshot {
    ids: BTreeSet<String>,
    heads: BTreeSet<String>,
    balances: String,
    clock: u64,
    notes: BTreeMap<String, String>,
    orphans: usize,
    waiting_on_parents: Vec<String>,
}

/// `None` when every snapshot agrees (membership modulo `excluded`, heads and
/// balances exactly); otherwise a report naming the first divergent id, who
/// holds it, and what the others last said about it.
fn divergence_report(
    snapshots: &[(String, Snapshot)],
    excluded: &BTreeSet<String>,
) -> Option<String> {
    let names: Vec<&str> = snapshots.iter().map(|(name, _)| name.as_str()).collect();
    let union: BTreeSet<&String> = snapshots
        .iter()
        .flat_map(|(_, snapshot)| snapshot.ids.iter())
        .filter(|id| !excluded.contains(*id))
        .collect();
    let mut report = String::new();
    let mut divergent = 0;
    for id in &union {
        let holders: Vec<&str> = snapshots
            .iter()
            .filter(|(_, snapshot)| snapshot.ids.contains(*id))
            .map(|(name, _)| name.as_str())
            .collect();
        if holders.len() == snapshots.len() {
            continue;
        }
        divergent += 1;
        if divergent == 1 {
            let missing: Vec<&str> = names
                .iter()
                .copied()
                .filter(|name| !holders.contains(name))
                .collect();
            writeln!(
                report,
                "  first divergent id {id}: held by {holders:?}, missing from {missing:?}"
            )
            .expect("write to String");
            for (name, snapshot) in snapshots {
                if holders.contains(&name.as_str()) {
                    continue;
                }
                let note = snapshot
                    .notes
                    .get(*id)
                    .map(String::as_str)
                    .unwrap_or("never refused — never offered, or still orphaned");
                writeln!(
                    report,
                    "    {name}: {note}; orphan buffer holds {} waiting on parents {:?}",
                    snapshot.orphans, snapshot.waiting_on_parents
                )
                .expect("write to String");
            }
        }
    }
    if divergent > 0 {
        let counts: Vec<String> = snapshots
            .iter()
            .map(|(name, snapshot)| {
                format!("{name}={} @clock {}", snapshot.ids.len(), snapshot.clock)
            })
            .collect();
        report.insert_str(
            0,
            &format!("DIVERGENT DAG membership: {divergent} id(s) differ; sizes {counts:?}\n"),
        );
    }
    let (first_name, first) = &snapshots[0];
    for (name, snapshot) in &snapshots[1..] {
        if snapshot.heads != first.heads {
            writeln!(
                report,
                "  heads differ: {first_name}={:?} vs {name}={:?}",
                first.heads, snapshot.heads
            )
            .expect("write to String");
        }
        if snapshot.balances != first.balances {
            writeln!(
                report,
                "  balances differ:\n--- {first_name}\n{}--- {name}\n{}",
                first.balances, snapshot.balances
            )
            .expect("write to String");
        }
    }
    (!report.is_empty()).then_some(report)
}

// ─── The mesh ───────────────────────────────────────────────────────────────

/// The order in which one round offers a set of ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    Ascending,
    Descending,
    Random,
    /// Pool (authoring) order — every parent before its child.
    Causal,
    AntiCausal,
}

const ORDERS: [Order; 5] = [
    Order::Ascending,
    Order::Descending,
    Order::Random,
    Order::Causal,
    Order::AntiCausal,
];

struct Mesh {
    replicas: Vec<Replica>,
    /// Every directive anyone authored, as the author's node would serve it.
    pool: Vec<SupplyEntry>,
    pool_index: HashMap<String, usize>,
    allowed: BTreeSet<String>,
    allowlist: PeerAllowlist,
    rng: Rng,
}

impl Mesh {
    fn new(seed: u64) -> Self {
        Mesh {
            replicas: Vec::new(),
            pool: Vec::new(),
            pool_index: HashMap::new(),
            allowed: BTreeSet::new(),
            allowlist: PeerAllowlist::default(),
            rng: Rng::new(seed),
        }
    }

    fn rebuild_allowlist(&mut self) {
        let authors: Vec<String> = self.allowed.iter().cloned().collect();
        self.allowlist =
            PeerAllowlist::parse(&authors).expect("hex verifying keys are EndpointIds");
    }

    /// Allowlist exactly these authors (an operator's remedy removes one).
    fn allow_exactly(&mut self, authors: &[String]) {
        self.allowed = authors.iter().cloned().collect();
        self.rebuild_allowlist();
    }

    fn allow_also(&mut self, author: &str) {
        self.allowed.insert(author.to_owned());
        self.rebuild_allowlist();
    }

    fn push(&mut self, replica: Replica) -> usize {
        self.allow_also(&replica.author());
        self.replicas.push(replica);
        self.replicas.len() - 1
    }

    /// Boot a fresh, empty replica and allowlist its key.
    fn add(&mut self, name: &str, key_seed: u8) -> usize {
        self.push(Replica::boot(name, key(key_seed)))
    }

    /// Boot a replica on an existing file (a hand-written history) and record
    /// what it loaded into the pool.
    fn add_on_file(&mut self, name: &str, key_seed: u8, path: PathBuf) -> usize {
        let replica = Replica::boot_at(name, key(key_seed), path);
        let loaded: Vec<Directive> = replica
            .svc
            .dag()
            .directives()
            .into_iter()
            .cloned()
            .collect();
        for directive in &loaded {
            self.record(directive);
        }
        self.push(replica)
    }

    /// The trusted-bootstrap join: compact `from`, copy its `.bean`, boot the
    /// copy under a new key, allowlist that key.
    fn add_bootstrapped_from(&mut self, name: &str, key_seed: u8, from: usize) -> usize {
        self.replicas[from]
            .svc
            .compact()
            .expect("compaction before the copy");
        let source = self.replicas[from].path.clone();
        self.push(Replica::boot_from_copy_of(name, key(key_seed), &source))
    }

    /// Boot a fresh, empty replica that joins from `from` (`p2p.joinFrom`,
    /// H-19): its join window is open until `from` has nothing left to give.
    fn add_joining_from(&mut self, name: &str, key_seed: u8, from: usize) -> usize {
        let mut replica = Replica::boot(name, key(key_seed));
        replica.join_from = Some(self.replicas[from].name.clone());
        assert!(
            replica.svc.open_join_trust(),
            "a fresh node opens its join window"
        );
        self.push(replica)
    }

    /// Add a directive to the pool exactly as its author's node would serve it.
    fn record(&mut self, directive: &Directive) -> String {
        let entry = make_supply_entry(directive);
        let id = entry.id.clone();
        if !self.pool_index.contains_key(&id) {
            self.pool_index.insert(id.clone(), self.pool.len());
            self.pool.push(entry);
        }
        id
    }

    fn open(&mut self, replica: usize, account: &str) -> String {
        let directive = self.replicas[replica].open(account);
        self.record(&directive)
    }

    fn append(&mut self, replica: usize, narration: &str, amount: i64, account: &str) -> String {
        let directive = self.replicas[replica].append(narration, amount, account);
        self.record(&directive)
    }

    fn pool_ids(&self) -> Vec<String> {
        self.pool.iter().map(|entry| entry.id.clone()).collect()
    }

    fn order_ids(&mut self, mut ids: Vec<String>, order: Order) -> Vec<String> {
        let position = |index: &HashMap<String, usize>, id: &String| {
            index.get(id).copied().unwrap_or(usize::MAX)
        };
        match order {
            Order::Ascending => ids.sort(),
            Order::Descending => {
                ids.sort();
                ids.reverse();
            }
            Order::Random => self.rng.shuffle(&mut ids),
            Order::Causal => ids.sort_by_key(|id| position(&self.pool_index, id)),
            Order::AntiCausal => {
                ids.sort_by_key(|id| position(&self.pool_index, id));
                ids.reverse();
            }
        }
        ids
    }

    /// Pool-fed delivery of `ids` to one replica in `order` — a serving peer
    /// that holds them all. Returns what the replica staged.
    fn deliver(&mut self, to: usize, ids: Vec<String>, order: Order) -> usize {
        let ids = self.order_ids(ids, order);
        let entries: Vec<SupplyEntry> = ids
            .iter()
            .map(|id| self.pool[self.pool_index[id]].clone())
            .collect();
        let allowlist = &self.allowlist;
        self.replicas[to].intake(entries, allowlist)
    }

    /// Pool-fed delivery of the whole pool, every replica, until no replica
    /// changes in a round. Returns the rounds taken.
    fn deliver_pool_to_fixed_point(&mut self, order: Order) -> usize {
        let mut rounds = 0;
        loop {
            rounds += 1;
            let before = self.counts();
            for to in 0..self.replicas.len() {
                let ids = self.pool_ids();
                self.deliver(to, ids, order);
            }
            if self.counts() == before {
                return rounds;
            }
            assert!(
                rounds < MAX_ROUNDS,
                "no fixed point within {MAX_ROUNDS} pool rounds"
            );
        }
    }

    /// Anti-entropy from `from` to `to`: the ids `to` lacks by membership (and
    /// has not refused for good — L-34 keeps them out of the Want), produced
    /// from `from`'s own DAG through the real `build_supply`.
    fn serve(&mut self, from: usize, to: usize, order: Order) -> usize {
        let wanted: Vec<String> = {
            let holder = &self.replicas[from];
            let receiver = &self.replicas[to];
            holder
                .svc
                .all_directive_ids()
                .into_iter()
                .filter(|id| {
                    !receiver.svc.contains_directive(id) && !receiver.permanent.contains_key(id)
                })
                .collect()
        };
        let from_name = self.replicas[from].name.clone();
        // H-19: the join window closes once the join peer has nothing this
        // replica lacks and has not refused for good — gl-node's Want session.
        if wanted.is_empty() && self.replicas[to].join_from.as_deref() == Some(from_name.as_str()) {
            self.replicas[to].svc.close_join_trust();
        }
        let wanted = self.order_ids(wanted, order);
        let holder = &self.replicas[from].svc;
        let entries = match build_supply(&wanted, |id| {
            holder.get_directive(id).map(make_supply_entry)
        }) {
            WireMessage::Supply { entries, .. } => entries,
            other => panic!("build_supply returned {other:?}"),
        };
        let allowlist = &self.allowlist;
        self.replicas[to].intake_from(entries, allowlist, Some(&from_name))
    }

    fn counts(&self) -> Vec<usize> {
        self.replicas
            .iter()
            .map(|replica| replica.svc.directive_count())
            .collect()
    }

    /// One full anti-entropy round: every replica served by every other.
    fn anti_entropy_round(&mut self, order: Order) -> bool {
        let before = self.counts();
        for to in 0..self.replicas.len() {
            for from in 0..self.replicas.len() {
                if from != to {
                    self.serve(from, to, order);
                }
            }
        }
        self.counts() != before
    }

    /// Anti-entropy rounds until a full round changes no replica. Returns the
    /// rounds taken (the last one is the quiet one).
    fn run_to_fixed_point(&mut self, order: Order) -> usize {
        let mut rounds = 0;
        loop {
            rounds += 1;
            if !self.anti_entropy_round(order) {
                return rounds;
            }
            assert!(
                rounds < MAX_ROUNDS,
                "no fixed point within {MAX_ROUNDS} anti-entropy rounds"
            );
        }
    }

    /// A single service that ingested the whole pool in causal order, through
    /// the same intake, to its own fixed point.
    fn oracle(&self) -> Replica {
        let mut oracle = Replica::boot("oracle", key(250));
        for round in 1..=MAX_ROUNDS {
            let before = oracle.svc.directive_count();
            oracle.intake(self.pool.clone(), &self.allowlist);
            if oracle.svc.directive_count() == before {
                break;
            }
            assert!(
                round < MAX_ROUNDS,
                "oracle: no fixed point within {MAX_ROUNDS} rounds"
            );
        }
        oracle
    }

    fn snapshots(&self, among: &[usize]) -> Vec<(String, Snapshot)> {
        among
            .iter()
            .map(|&index| {
                let replica = &self.replicas[index];
                (replica.name.clone(), replica.snapshot())
            })
            .collect()
    }

    fn all(&self) -> Vec<usize> {
        (0..self.replicas.len()).collect()
    }

    /// The report for `among` (membership modulo `excluded`), or `None`.
    fn divergence_among(&self, among: &[usize], excluded: &[String]) -> Option<String> {
        let excluded: BTreeSet<String> = excluded.iter().cloned().collect();
        divergence_report(&self.snapshots(among), &excluded)
    }

    /// The report for every replica plus the oracle, exact.
    fn divergence_with_oracle(&self) -> Option<String> {
        let mut snapshots = self.snapshots(&self.all());
        let oracle = self.oracle();
        snapshots.push((oracle.name.clone(), oracle.snapshot()));
        divergence_report(&snapshots, &BTreeSet::new())
    }

    fn assert_converged(&self, label: &str) {
        if let Some(report) = self.divergence_with_oracle() {
            panic!("{label}: replicas did not converge\n{report}");
        }
        self.print_fixed_point(label);
    }

    fn assert_converged_among(&self, label: &str, among: &[usize], excluded: &[String]) {
        if let Some(report) = self.divergence_among(among, excluded) {
            panic!("{label}: replicas did not converge\n{report}");
        }
        self.print_fixed_point(label);
    }

    fn print_fixed_point(&self, label: &str) {
        let first = self.replicas[0].snapshot();
        eprintln!(
            "{label}: converged — {} replicas, {} directives, {} heads, clocks {:?}",
            self.replicas.len(),
            first.ids.len(),
            first.heads.len(),
            self.replicas
                .iter()
                .map(|replica| replica.svc.lamport_clock())
                .collect::<Vec<_>>()
        );
    }

    fn held(&self, replica: usize, ids: &[String]) -> usize {
        ids.iter()
            .filter(|id| self.replicas[replica].svc.contains_directive(id))
            .count()
    }
}

// ─── Scenario builders ──────────────────────────────────────────────────────

/// `n` replicas, all allowlisted, sharing three opens authored by replica 0.
fn seeded_mesh(seed: u64, n: usize) -> Mesh {
    let mut mesh = Mesh::new(seed);
    for i in 0..n {
        mesh.add(&format!("R{i}"), u8::try_from(i + 1).expect("small"));
    }
    mesh.open(0, "Assets:Cash");
    mesh.open(0, "Equity:Opening");
    mesh.open(0, "Expenses:Food");
    mesh.run_to_fixed_point(Order::Ascending);
    mesh
}

fn account_for(k: usize) -> &'static str {
    if k.is_multiple_of(3) {
        "Expenses:Food"
    } else {
        "Assets:Cash"
    }
}

fn amount_for(k: usize) -> i64 {
    i64::try_from(k % 97 + 1).expect("small")
}

/// `count` transactions authored by random replicas, each author having
/// ingested a random subset of the pool first, so parent sets interleave.
fn author_dense_history(mesh: &mut Mesh, count: usize) {
    for k in 0..count {
        let author = mesh.rng.below(mesh.replicas.len());
        if mesh.rng.coin() {
            let ids = mesh.pool_ids();
            let subset = mesh.rng.subset(&ids);
            mesh.deliver(author, subset, Order::Random);
        }
        mesh.append(author, &format!("t{k}"), amount_for(k), account_for(k));
    }
}

/// `count` parentless transactions signed by `attacker` (an allowlisted peer),
/// distinct bodies, lamports inside the ratchet. Returns their ids in order.
fn parentless_flood(
    mesh: &mut Mesh,
    attacker: &PeerKeySignatureProvider,
    count: usize,
) -> Vec<String> {
    (0..count)
        .map(|i| {
            let lamport = 100 + u64::try_from(i).expect("small");
            let directive = hand_transaction(attacker, &format!("flood{i}"), 1, &[], lamport);
            mesh.record(&directive)
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum Jump {
    /// X's directive is an `open`: honest history is stamped above it but
    /// never names it.
    Open,
    /// X's directive is a transaction naming A's heads: honest history names
    /// it as a parent.
    Transaction,
}

/// The H-19 mesh: A and B with history, X allowlisted, X's one directive at
/// `min(clock) + MAX_LAMPORT_ADVANCE − 1` adopted by both, honest authoring on
/// top, A↔B synced, then X removed from the allowlist. Returns the mesh, X's
/// id, the transactions authored after the jump (every one names X's
/// directive, directly or through A's chain, when it is a transaction) and the
/// one parentless `open` authored after it.
fn h19_mesh(seed: u64, jump: Jump) -> (Mesh, String, Vec<String>, String) {
    let mut mesh = seeded_mesh(seed, 2);
    let (a, b) = (0, 1);
    let attacker = key(201);
    mesh.allow_also(&attacker.public_key_hex());
    mesh.append(a, "pre-1", 10, "Assets:Cash");
    mesh.append(a, "pre-2", 20, "Expenses:Food");
    mesh.run_to_fixed_point(Order::Ascending);

    let local = mesh.replicas[a]
        .svc
        .lamport_clock()
        .min(mesh.replicas[b].svc.lamport_clock());
    let lamport = local + MAX_LAMPORT_ADVANCE - 1;
    let directive = match jump {
        Jump::Open => hand_open(&attacker, "Assets:Jump", lamport),
        Jump::Transaction => {
            let mut heads: Vec<String> = mesh.replicas[a].svc.head_txids().into_iter().collect();
            heads.sort();
            hand_transaction(&attacker, "x-bridge", 1, &heads, lamport)
        }
    };
    let jump_id = mesh.record(&directive);
    for replica in [a, b] {
        mesh.deliver(replica, vec![jump_id.clone()], Order::Causal);
        assert!(
            mesh.replicas[replica].svc.contains_directive(&jump_id),
            "{}: the maximal legal jump ({lamport}) must be adopted: {:?}",
            mesh.replicas[replica].name,
            mesh.replicas[replica].retryable.get(&jump_id)
        );
    }
    let mut after = Vec::new();
    for k in 0..3 {
        after.push(mesh.append(a, &format!("post-{k}"), 5 + k, "Assets:Cash"));
    }
    let after_open = mesh.open(b, "Assets:Bank");
    after.push(mesh.append(b, "post-b", 7, "Assets:Bank"));
    mesh.run_to_fixed_point(Order::Ascending);
    assert!(mesh.divergence_among(&[a, b], &[]).is_none());

    // The operator's remedy: X leaves the allowlist.
    let honest = [mesh.replicas[a].author(), mesh.replicas[b].author()];
    mesh.allow_exactly(&honest);
    (mesh, jump_id, after, after_open)
}

/// A pre-T63 lamport well past one ratchet step above the pre-jump history.
const PRE_T63_JUMP: u64 = 5_000_000_000;
const _: () = assert!(
    PRE_T63_JUMP - 2 >= MAX_LAMPORT_ADVANCE,
    "the jump must be at least one ratchet step above the history before it"
);

/// A signed history file carrying one hand-typed jump: opens at 1 and 2 by
/// `peer`, the jump by `jumper`, two more opens by `peer` above it.
fn pre_t63_history(peer: &PeerKeySignatureProvider, jumper: &PeerKeySignatureProvider) -> PathBuf {
    let history = [
        hand_open(peer, "Assets:Cash", 1),
        hand_open(peer, "Equity:Opening", 2),
        hand_open(jumper, "Assets:Jump", PRE_T63_JUMP),
        hand_open(peer, "Assets:After1", PRE_T63_JUMP + 2),
        hand_open(peer, "Assets:After2", PRE_T63_JUMP + 3),
    ];
    let path = temp_bean("pre-t63");
    std::fs::write(&path, ledger::serialize::full_file_serialize(&history, &[]))
        .expect("write the history file");
    path
}

// ─── Case 1 ─────────────────────────────────────────────────────────────────

/// A dense honest history — 4 authors interleaving on random subsets — plus a
/// fresh joiner, delivered in every order: ascending, descending, random and
/// child-before-parent. Passes at HEAD.
#[test]
fn honest_history_converges_in_any_delivery_order() {
    for (i, order) in [
        Order::Ascending,
        Order::Descending,
        Order::Random,
        Order::AntiCausal,
    ]
    .into_iter()
    .enumerate()
    {
        let mut mesh = seeded_mesh(100 + u64::try_from(i).expect("small"), 4);
        author_dense_history(&mut mesh, 40);
        mesh.add("F", 9);
        let pool_rounds = mesh.deliver_pool_to_fixed_point(order);
        let gossip_rounds = mesh.run_to_fixed_point(order);
        eprintln!(
            "case 1 / {order:?}: pool rounds {pool_rounds}, anti-entropy rounds {gossip_rounds}"
        );
        mesh.assert_converged(&format!("case 1 / {order:?}"));
    }
}

// ─── Case 2 (X2 probe 3) ────────────────────────────────────────────────────

/// One author's `MAX_PARENTS + 1` parentless transactions, served whole to a
/// passive and an active replica. Since T72 (H-21) there is no remote head
/// bound: each replica holds all of them at once (at HEAD before T72 each
/// refused the last one at its per-replica cap and the passive one's cap only
/// cleared once the active one's local append propagated). The active
/// replica's append still names at most `MAX_PARENTS` of them and propagates.
#[test]
fn single_subset_delivery_converges_once_any_local_append_propagates() {
    let mut mesh = seeded_mesh(2, 2);
    let (passive, active) = (0, 1);
    let attacker = key(200);
    mesh.allow_also(&attacker.public_key_hex());
    let flood = parentless_flood(&mut mesh, &attacker, MAX_PARENTS + 1);
    for replica in [passive, active] {
        mesh.deliver(replica, flood.clone(), Order::Causal);
        assert_eq!(
            mesh.held(replica, &flood),
            flood.len(),
            "T72 / H-21: no remote head bound — every replica holds the whole flood"
        );
    }
    mesh.append(active, "active-local", 5, "Assets:Cash");
    // The flooding peer keeps serving; the honest replicas gossip.
    let pool_rounds = mesh.deliver_pool_to_fixed_point(Order::Causal);
    let gossip_rounds = mesh.run_to_fixed_point(Order::Ascending);
    eprintln!("case 2: pool rounds {pool_rounds}, anti-entropy rounds {gossip_rounds}");
    assert_eq!(mesh.held(passive, &flood), flood.len());
    mesh.assert_converged("case 2");
}

// ─── Case 3 (H-21, X2 probe 3b) ─────────────────────────────────────────────

/// The same flood, but the peer serves A `{0..255}` and B `{1..256}`; then A
/// and B run anti-entropy with each other and nobody authors. Same available
/// set, so the DAGs must be equal. Failed at HEAD before T72: each refused the
/// one it was not given first at its own per-replica cap
/// (`UNMERGED_HEAD_LIMIT`), forever. T72 (H-21) dropped the bound: one
/// anti-entropy round and both hold all 257, with equal heads and balances.
#[test]
fn h21_disjoint_subset_delivery_of_a_parentless_flood_converges_without_local_authoring() {
    let mut mesh = seeded_mesh(3, 2);
    let (a, b) = (0, 1);
    let attacker = key(200);
    mesh.allow_also(&attacker.public_key_hex());
    let flood = parentless_flood(&mut mesh, &attacker, MAX_PARENTS + 1);
    let last = flood.len() - 1;
    mesh.deliver(a, flood[..last].to_vec(), Order::Causal);
    mesh.deliver(b, flood[1..].to_vec(), Order::Causal);
    assert_eq!(mesh.held(a, &flood), MAX_PARENTS, "A was served 256");
    assert_eq!(mesh.held(b, &flood), MAX_PARENTS, "B was served 256");
    let rounds = mesh.run_to_fixed_point(Order::Ascending);
    eprintln!("case 3 (H-21): anti-entropy rounds {rounds}, no local authoring");
    assert_eq!(mesh.held(a, &flood), flood.len(), "A adopted B's one");
    assert_eq!(mesh.held(b, &flood), flood.len(), "B adopted A's one");
    mesh.assert_converged_among("case 3 (H-21)", &[a, b], &[]);
}

// ─── Case 4 (H-19, hunt.rs h1b) ─────────────────────────────────────────────

/// X's maximal legal jump, honest authoring on top, X de-allowlisted; a fresh
/// F joins by anti-entropy from A, its join peer (`p2p.joinFrom`), once per
/// delivery order. X's directive itself can never reach F (the allowlist is a
/// policy verdict, not a divergence), so membership is compared modulo it;
/// heads and balances exactly.
///
/// With no join peer the verdict depended on the order: served the pre-jump
/// history in causal (ascending-lamport) order, F's clock landed exactly one
/// below the bridge and the first post-jump honest directive was a full
/// ratchet step above it — stuck, the `h1b` shape, and no per-directive bound
/// repairs that (decision (1)). Since the join window, F adopts A's history
/// without the ratchet, as boot adopts a copy of A's `.bean`, and converges in
/// every order; B's copies of the same records are still ratcheted.
///
/// Bug-catch: stage the join peer's directives with the ratchet
/// (`RemoteSource::Peer`) and F is stuck under the causal orders.
#[test]
fn h19_fresh_node_converges_after_a_maximal_legal_jump_and_allowlist_removal() {
    let mut stuck: Vec<String> = Vec::new();
    for (i, order) in ORDERS.into_iter().enumerate() {
        let (mut mesh, jump_id, _after, _open) =
            h19_mesh(40 + u64::try_from(i).expect("small"), Jump::Open);
        let f = mesh.add_joining_from("F", 10, 0);
        let rounds = mesh.run_to_fixed_point(order);
        eprintln!(
            "case 4 (H-19) / {order:?}: anti-entropy rounds {rounds}, F clock {} holds {} of {}",
            mesh.replicas[f].svc.lamport_clock(),
            mesh.replicas[f].svc.directive_count(),
            mesh.replicas[0].svc.directive_count()
        );
        if let Some(report) = mesh.divergence_among(&mesh.all(), &[jump_id]) {
            stuck.push(format!("{order:?}:\n{report}"));
        }
    }
    assert!(
        stuck.is_empty(),
        "case 4 (H-19): the join from A is stuck under {} of {} delivery orders\n{}",
        stuck.len(),
        ORDERS.len(),
        stuck.join("\n")
    );
}

/// The remedy the 2026-09-23 decision prescribes: F boots on a copy of A's
/// `.bean` under its own key (boot loads X's directive as history, no
/// allowlist check), then anti-entropy carries what was authored after the
/// copy, including F's own writes. Both jump kinds.
#[test]
fn h19_fresh_node_bootstrapped_from_a_peers_file_converges() {
    for (i, jump) in [Jump::Open, Jump::Transaction].into_iter().enumerate() {
        let label = format!("H-19 bootstrap / {jump:?}");
        let (mut mesh, jump_id, _after, _open) =
            h19_mesh(5 + u64::try_from(i).expect("small"), jump);
        let (a, b) = (0, 1);
        let f = mesh.add_bootstrapped_from("F", 10, a);
        assert_eq!(
            mesh.replicas[f].svc.directive_count(),
            mesh.replicas[a].svc.directive_count(),
            "{label}: the copy boots with A's whole history"
        );
        assert!(
            mesh.replicas[f].svc.contains_directive(&jump_id),
            "{label}: boot loads the removed author's directive as history"
        );
        // History authored after the copy, by everyone including F.
        mesh.append(a, "after-copy-a", 3, "Assets:Cash");
        mesh.append(b, "after-copy-b", 4, "Assets:Bank");
        mesh.open(b, "Assets:Savings");
        mesh.append(b, "after-copy-b2", 6, "Assets:Savings");
        let own = mesh.append(f, "after-copy-f", 8, "Assets:Cash");
        let rounds = mesh.run_to_fixed_point(Order::Random);
        eprintln!(
            "{label}: anti-entropy rounds {rounds}, clocks {:?}",
            mesh.counts()
        );
        for replica in [a, b] {
            assert!(
                mesh.replicas[replica].svc.contains_directive(&own),
                "{label}: the mesh accepts the bootstrapped node's own directive"
            );
        }
        let among = mesh.all();
        mesh.assert_converged_among(&label, &among, &[]);
    }
}

/// When X's directive is a transaction, honest history names it as a parent,
/// so an anti-entropy-only join is partitioned by `MissingParent` whatever the
/// lamport rule says — the honest post-jump directives sit in F's orphan
/// buffer waiting on an id F refuses for good. Inherent; the bootstrap join
/// above is the way in. Passes at HEAD (it pins the mechanism, not a fix).
#[test]
fn h19_removed_authors_transaction_partitions_an_anti_entropy_join_by_missing_parent() {
    let (mut mesh, jump_id, after, after_open) = h19_mesh(7, Jump::Transaction);
    let f = mesh.add("F", 10);
    let rounds = mesh.run_to_fixed_point(Order::Ascending);
    let fresh = &mesh.replicas[f];
    eprintln!(
        "H-19 / transaction: anti-entropy rounds {rounds}, F holds {} of {} pool entries",
        fresh.svc.directive_count(),
        mesh.pool.len()
    );
    assert!(!fresh.svc.contains_directive(&jump_id));
    let refusal = fresh
        .permanent
        .get(&jump_id)
        .expect("X's directive is refused for good at intake");
    assert!(
        refusal.contains("not on the peer allowlist"),
        "refused as not allowlisted: {refusal}"
    );
    assert!(
        fresh.orphans.wanted_parent_ids().contains(&jump_id),
        "the honest post-jump transactions wait on X's id as a parent"
    );
    for id in &after {
        assert!(
            !fresh.svc.contains_directive(id),
            "no transaction authored after the jump reaches F"
        );
    }
    // The parentless post-jump `open` is subject only to the ratchet, whose
    // verdict on a fresh node depends on delivery order (see case 4).
    eprintln!(
        "H-19 / transaction: the parentless post-jump open reached F: {}",
        fresh.svc.contains_directive(&after_open)
    );
    let report = mesh
        .divergence_among(&mesh.all(), &[jump_id])
        .expect("the harness reports the partition");
    eprintln!("{report}");
}

// ─── Case 5 (H-19, hunt.rs h1a) ─────────────────────────────────────────────

/// A history file carrying one hand-typed jump ≥ `MAX_LAMPORT_ADVANCE` (a
/// pre-T63 mesh). A boots on it and authors; a fresh F joins by anti-entropy
/// from A, its join peer, with both authors allowlisted. With no join peer F
/// adopted the two opens below the jump and nothing above it, and no rule
/// could tell the jump from an attack (decision (1)); the join window adopts
/// A's history past it, and then closes — the ratchet applies again.
///
/// Bug-catch: stage the join peer's directives with the ratchet and F holds
/// only the opens below the jump.
#[test]
fn h19_pre_t63_history_with_one_large_jump_is_joinable() {
    let mut mesh = Mesh::new(8);
    let jumper = key(202);
    let path = pre_t63_history(&key(1), &jumper);
    let a = mesh.add_on_file("A", 1, path);
    mesh.allow_also(&jumper.public_key_hex());
    assert_eq!(mesh.replicas[a].svc.directive_count(), 5);
    assert_eq!(mesh.replicas[a].svc.lamport_clock(), PRE_T63_JUMP + 4);
    mesh.append(a, "a-after-boot", 3, "Assets:Cash");
    let f = mesh.add_joining_from("F", 10, a);
    let rounds = mesh.run_to_fixed_point(Order::Ascending);
    eprintln!(
        "case 5 (H-19 pre-T63): anti-entropy rounds {rounds}, F clock {} holds {}",
        mesh.replicas[f].svc.lamport_clock(),
        mesh.replicas[f].svc.directive_count()
    );
    let among = mesh.all();
    mesh.assert_converged_among("case 5 (H-19 pre-T63)", &among, &[]);
    assert!(
        !mesh.replicas[f].svc.join_trust_open(),
        "the join window closed once A had nothing left to give"
    );
}

/// The same pre-T63 file, joined by bootstrap: F boots on a copy of A's file
/// and anti-entropy carries the rest.
#[test]
fn h19_pre_t63_history_is_joinable_by_bootstrap() {
    let mut mesh = Mesh::new(9);
    let jumper = key(202);
    let path = pre_t63_history(&key(1), &jumper);
    let a = mesh.add_on_file("A", 1, path);
    mesh.allow_also(&jumper.public_key_hex());
    mesh.append(a, "a-after-boot", 3, "Assets:Cash");
    let f = mesh.add_bootstrapped_from("F", 10, a);
    mesh.append(a, "a-after-copy", 4, "Assets:Cash");
    let own = mesh.append(f, "f-own", 2, "Assets:Cash");
    let rounds = mesh.run_to_fixed_point(Order::Descending);
    eprintln!("H-19 pre-T63 bootstrap: anti-entropy rounds {rounds}");
    assert!(mesh.replicas[a].svc.contains_directive(&own));
    let among = mesh.all();
    mesh.assert_converged_among("H-19 pre-T63 bootstrap", &among, &[]);
}

// ─── Case 6 (X2 probe 4) ────────────────────────────────────────────────────

/// A stepped history — opens one ratchet step apart up to 12 × 10⁹ and a
/// transaction on top — fed to three replicas in ascending, descending and
/// random order. Ratchet refusals are retried, and the fixed point (DAG and
/// clock) does not depend on the order. Passes at HEAD.
#[test]
fn ratchet_refusals_are_order_independent_on_a_dense_history() {
    let mut mesh = Mesh::new(10);
    let author = key(203);
    mesh.allow_also(&author.public_key_hex());
    for i in 0..3u8 {
        mesh.add(&format!("R{i}"), i + 1);
    }
    let steps: [u64; 4] = [3_000_000_000, 6_000_000_000, 9_000_000_000, 12_000_000_000];
    assert!(
        steps.windows(2).all(|w| w[1] - w[0] < MAX_LAMPORT_ADVANCE)
            && steps[0] < MAX_LAMPORT_ADVANCE,
        "every step is inside one ratchet advance"
    );
    let top = steps[3] + 1;
    mesh.record(&hand_open(&author, "Assets:Cash", 1));
    mesh.record(&hand_open(&author, "Equity:Opening", 2));
    for (i, lamport) in steps.iter().enumerate() {
        mesh.record(&hand_open(&author, &format!("Assets:S{i}"), *lamport));
    }
    mesh.record(&hand_transaction(&author, "top", 1, &[], top));

    for (replica, order) in [Order::Ascending, Order::Descending, Order::Random]
        .into_iter()
        .enumerate()
    {
        let mut rounds = 0;
        loop {
            rounds += 1;
            let before = mesh.replicas[replica].svc.directive_count();
            let ids = mesh.pool_ids();
            mesh.deliver(replica, ids, order);
            if mesh.replicas[replica].svc.directive_count() == before {
                break;
            }
            assert!(rounds < MAX_ROUNDS);
        }
        eprintln!(
            "case 6 / {order:?}: {rounds} rounds, clock {}",
            mesh.replicas[replica].svc.lamport_clock()
        );
    }
    // Honest authoring on top of the stepped history, then gossip.
    mesh.append(0, "on-top", 9, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Random);
    mesh.assert_converged("case 6");
    // Clocks are transient, not committed state: adoption sets
    // `max(local, remote) + 1`, so each replica's clock drifts by its own
    // adoption order. Every clock is above everything held; that is all.
    for replica in &mesh.replicas {
        assert!(
            replica.svc.lamport_clock() > top,
            "{}: clock {} above the highest lamport held {top}",
            replica.name,
            replica.svc.lamport_clock()
        );
    }
}

// ─── Case 7 ─────────────────────────────────────────────────────────────────

/// Same pool, different local-authoring interleavings per replica: R0 authors
/// before it reads, R1 after, R2 every other round, R3 never (an observer).
/// Passes at HEAD.
#[test]
fn no_replica_state_depends_on_which_replica_authored() {
    let mut mesh = seeded_mesh(11, 4);
    let mut authored = [0usize; 4];
    for round in 0..12 {
        let deliver = |mesh: &mut Mesh, replica: usize| {
            let ids = mesh.pool_ids();
            let subset = mesh.rng.subset(&ids);
            let order = ORDERS[mesh.rng.below(ORDERS.len())];
            mesh.deliver(replica, subset, order);
        };
        mesh.append(
            0,
            &format!("r0-{round}"),
            amount_for(round),
            account_for(round),
        );
        authored[0] += 1;
        deliver(&mut mesh, 0);
        deliver(&mut mesh, 1);
        mesh.append(
            1,
            &format!("r1-{round}"),
            amount_for(round + 1),
            account_for(round + 1),
        );
        authored[1] += 1;
        deliver(&mut mesh, 2);
        if round.is_multiple_of(2) {
            mesh.append(
                2,
                &format!("r2-{round}"),
                amount_for(round + 2),
                account_for(round + 2),
            );
            authored[2] += 1;
        }
        deliver(&mut mesh, 3);
    }
    assert_eq!(authored, [12, 12, 6, 0]);
    let rounds = mesh.run_to_fixed_point(Order::Random);
    eprintln!("case 7: anti-entropy rounds {rounds}");
    mesh.assert_converged("case 7");
}

// ─── The standing property ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 8,
        max_shrink_iters: 4,
        .. ProptestConfig::default()
    })]

    /// Honest histories with random authorship, random per-round subsets and
    /// random delivery orders converge — the invariant T72 must preserve.
    #[test]
    fn honest_histories_converge_under_random_authorship_subsets_and_orders(
        replicas in 2usize..=5,
        authors in prop::collection::vec(0usize..5, 1..=60),
        rounds in 1usize..=6,
        seed in any::<u64>(),
    ) {
        let mut mesh = seeded_mesh(seed, replicas);
        for (k, author) in authors.iter().enumerate() {
            let author = author % replicas;
            if mesh.rng.coin() {
                let ids = mesh.pool_ids();
                let subset = mesh.rng.subset(&ids);
                let order = ORDERS[mesh.rng.below(ORDERS.len())];
                mesh.deliver(author, subset, order);
            }
            mesh.append(author, &format!("p{k}"), amount_for(k), account_for(k));
        }
        for _ in 0..rounds {
            for replica in 0..replicas {
                let ids = mesh.pool_ids();
                let subset = mesh.rng.subset(&ids);
                let order = ORDERS[mesh.rng.below(ORDERS.len())];
                mesh.deliver(replica, subset, order);
            }
        }
        mesh.run_to_fixed_point(Order::Random);
        let report = mesh.divergence_with_oracle();
        prop_assert!(report.is_none(), "{}", report.unwrap_or_default());
    }
}

// ─── Case T76: exact balances over mixed-scale dust and cap-sized amounts ───

/// Append a transaction moving each `(account, amount)` against
/// `Equity:Opening`, authored and signed by `replica`, and record it in the
/// pool. Decimal amounts at any scale (the harness's own `append` is integral).
fn append_decimal(
    mesh: &mut Mesh,
    replica: usize,
    narration: &str,
    account: &str,
    amount: Decimal,
) {
    let key = Arc::clone(&mesh.replicas[replica].key);
    let usd = |number: Decimal| Amount {
        number,
        currency: "USD".to_owned(),
    };
    let input = TransactionInput {
        date: day(15),
        flag: Flag::Complete,
        payee: None,
        narration: Some(narration.to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            PostingInput {
                account: account.to_owned(),
                amount: Some(usd(amount)),
                cost: None,
                price: None,
            },
            PostingInput {
                account: "Equity:Opening".to_owned(),
                amount: Some(usd(-amount)),
                cost: None,
                price: None,
            },
        ],
    };
    let outcome = mesh.replicas[replica]
        .svc
        .append_transaction_signing(input, |content_id, parents, lamport| {
            key.sign(&SignableMessage {
                content_id,
                is_transaction: true,
                parents,
                lamport,
            })
        })
        .unwrap_or_else(|error| panic!("append {narration} ({amount}): {error}"));
    let directive = mesh.replicas[replica]
        .svc
        .get_directive(&outcome.txid)
        .expect("just appended")
        .clone();
    mesh.record(&directive);
}

/// T76 (M-50, L-79): replicas holding a history of amounts at the cap
/// (`±10^21`, inclusive, also spelled with trailing zeros), `Decimal::MAX`'s
/// mantissa at scale 8 (in cap: `7.9 × 10^20`) and mixed-scale dust
/// (`10^-28`, `0.5` at scale 1) — so `Assets:Cash`'s exact total does not fit
/// a `Decimal` at its printed scale and is reported rounded once — reach
/// equal DAGs AND equal printed balances, the `exact` flags included
/// (`balances_text` renders each `AccountBalanceEntry` whole), equal to the
/// oracle, in every delivery order.
#[test]
fn t76_cap_sized_amounts_and_mixed_scale_dust_converge_to_equal_exact_balances() {
    let cap = Decimal::from_i128_with_scale(
        i128::try_from(ledger::limits::MAX_AMOUNT_MAGNITUDE).expect("fits"),
        0,
    );
    let amounts: Vec<(&str, Decimal)> = vec![
        ("Assets:Cash", cap),
        ("Assets:Cash", Decimal::from_i128_with_scale(1, 28)),
        ("Expenses:Food", -cap),
        (
            "Assets:Cash",
            Decimal::from_str_exact("1000000000000000000000.0000000").expect("literal"),
        ),
        ("Expenses:Food", Decimal::new(5, 1)),
        (
            "Assets:Cash",
            Decimal::from_i128_with_scale(Decimal::MAX.mantissa(), 8),
        ),
        ("Expenses:Food", Decimal::from_i128_with_scale(-7, 28)),
        ("Assets:Cash", Decimal::new(100_000, 2)),
    ];
    for (i, order) in ORDERS.into_iter().enumerate() {
        let mut mesh = seeded_mesh(7600 + u64::try_from(i).expect("small"), 3);
        for (k, (account, amount)) in amounts.iter().enumerate() {
            let author = mesh.rng.below(mesh.replicas.len());
            if mesh.rng.coin() {
                let ids = mesh.pool_ids();
                let subset = mesh.rng.subset(&ids);
                mesh.deliver(author, subset, order);
            }
            append_decimal(&mut mesh, author, &format!("t76-{k}"), account, *amount);
        }
        mesh.add("F", 9);
        mesh.deliver_pool_to_fixed_point(order);
        mesh.run_to_fixed_point(order);
        mesh.assert_converged(&format!("case T76 / {order:?}"));

        // What converged is rule R's figure, flagged: with the dust,
        // `Assets:Cash` does not fit a `Decimal` at scale 28 and is rounded
        // once to scale 7 (the independent value, by Python's `decimal`:
        // `2792281625142643376935.43950335 + 10^-28` → `…935.4395034`), and
        // every replica says so identically.
        let entries: Vec<_> = mesh
            .replicas
            .iter()
            .map(|replica| {
                replica
                    .svc
                    .read_model()
                    .account_balance("Assets:Cash", None)
                    .expect("cash has postings")
            })
            .collect();
        assert!(
            entries.iter().all(|entry| !entry.exact),
            "case T76 / {order:?}: the dust-carrying cash balance must be flagged inexact"
        );
        assert!(entries.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(
            entries[0].balances["USD"].to_string(),
            "2792281625142643376935.4395034",
            "case T76 / {order:?}: rounded once, half to even"
        );
        let trial = mesh.replicas[0]
            .svc
            .read_model()
            .trial_balance(far_future());
        assert!(
            !trial.exact,
            "case T76 / {order:?}: the trial balance says so too"
        );
    }
}

// ═══ A1 (0924 re-audit of T72): rules on content, not on the replica ════════
//
// The cases below probe the T72 mechanisms as a *mesh* property: parent choice
// under a multi-author flood with local authoring everywhere, its determinism
// across replicas, the trusted-bootstrap join through `gl-node`'s real boot
// order with the H-20 verifier installed, a fresh join under the orphan-buffer
// caps, a pre-T75 over-cap record in one replica's file, and the H-19
// clock-versus-history warning on an honest mesh with repeated fresh joins.

use ledger::service::{DirectiveVerifier, LAMPORT_GAP_WARN};
use p2p::anti_entropy::compute_want_by_membership;
use p2p::orphan_buffer::MAX_ORPHANS_PER_PEER;
use p2p::protocol::MAX_SUPPLY_ENTRIES;

/// A real Ed25519 key signing for `mesh_id` (see [`key`], which signs for
/// [`MESH_ID`]).
fn key_for_mesh(seed: u8, mesh_id: &str) -> Arc<PeerKeySignatureProvider> {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let i = u8::try_from(index).expect("32 < 256");
        *byte = seed.wrapping_mul(31).wrapping_add(i).wrapping_mul(7) ^ 0x5C;
    }
    Arc::new(PeerKeySignatureProvider::from_bytes(
        &bytes,
        mesh_id.to_owned(),
    ))
}

/// The verifier `gl-node`'s `main.rs` installs (H-20 / T73):
/// `security::signing::verify_signature` over the wire's `SignableMessage`
/// and the node's mesh id — the same check `verify_remote_signature` applies
/// to a peer's directive.
fn verifier(mesh_id: &str) -> DirectiveVerifier {
    let mesh_id = mesh_id.to_owned();
    Arc::new(
        move |content_id: &str,
              is_transaction: bool,
              parents: &str,
              lamport: &str,
              author: &str,
              signature: &str| {
            security::signing::verify_signature(
                &SignableMessage {
                    content_id,
                    is_transaction,
                    parents,
                    lamport,
                },
                signature,
                author,
                &mesh_id,
            )
            .is_ok()
        },
    )
}

/// What `gl-node`'s boot sequence reported (`main.rs`: H-13 finalisation and
/// the H-20 pass).
#[derive(Debug)]
struct GlNodeBoot {
    finalized: usize,
    quarantined_by_signature: usize,
}

fn author_of(directive: &Directive) -> Option<String> {
    let metadata = match directive {
        Directive::Transaction(txn) => &txn.metadata,
        Directive::Open(open) => &open.metadata,
        _ => return None,
    };
    metadata.get("openledger-author").cloned()
}

impl Replica {
    /// Boot exactly as `gl-node` does (`main.rs`, T73 order): `boot` under the
    /// `"local"` placeholder → `set_author_id` (the P2P identity) →
    /// `set_signer` → `set_verifier` → `finalize_operator_input` →
    /// `verify_own_history` → the startup compaction. `mesh_id` is what the
    /// key signs for and what the verifier checks against.
    fn boot_like_gl_node(
        name: &str,
        key: Arc<PeerKeySignatureProvider>,
        path: PathBuf,
        mesh_id: &str,
    ) -> (Self, GlNodeBoot) {
        let mut svc = LedgerService::boot(path.clone(), "local".to_owned())
            .unwrap_or_else(|error| panic!("{name}: boot: {error}"));
        svc.set_author_id(key.public_key_hex());
        svc.set_signer(signer(&key));
        svc.set_verifier(verifier(mesh_id));
        let finalized = if svc.unsigned_operator_input_count() > 0 {
            svc.finalize_operator_input()
        } else {
            0
        };
        let quarantined_by_signature = svc.verify_own_history();
        svc.compact()
            .unwrap_or_else(|error| panic!("{name}: startup compaction: {error}"));
        let replica = Replica {
            name: name.to_owned(),
            key,
            path,
            svc,
            orphans: OrphanBuffer::new(),
            permanent: BTreeMap::new(),
            retryable: BTreeMap::new(),
            keep_files: false,
            join_from: None,
            delivering: None,
        };
        (
            replica,
            GlNodeBoot {
                finalized,
                quarantined_by_signature,
            },
        )
    }

    /// Stop this replica cleanly (compact, so the `.bean` is canonical and
    /// the journal is gone) and hand back the file for an edit and a re-boot.
    fn stop(mut self) -> PathBuf {
        self.svc.compact().expect("compaction at shutdown");
        self.keep_files = true;
        self.path.clone()
    }

    /// The `openledger-parents` a transaction this replica holds names.
    fn parents_of(&self, id: &str) -> Vec<String> {
        let Some(Directive::Transaction(txn)) = self.svc.get_directive(id) else {
            panic!(
                "{}: {id} is not a transaction this replica holds",
                self.name
            );
        };
        txn.metadata
            .get("openledger-parents")
            .map(|parents| {
                parents
                    .split(',')
                    .filter(|p| !p.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Current heads with their authors.
    fn heads_with_authors(&self) -> Vec<(String, Option<String>)> {
        let mut heads: Vec<(String, Option<String>)> = self
            .svc
            .head_txids()
            .into_iter()
            .map(|head| {
                let author = self.svc.get_directive(&head).and_then(author_of);
                (head, author)
            })
            .collect();
        heads.sort();
        heads
    }
}

impl Mesh {
    /// Boot a replica on `path` through the `gl-node` order and allowlist it.
    fn add_like_gl_node(
        &mut self,
        name: &str,
        key: Arc<PeerKeySignatureProvider>,
        path: PathBuf,
        mesh_id: &str,
    ) -> (usize, GlNodeBoot) {
        let (replica, report) = Replica::boot_like_gl_node(name, key, path, mesh_id);
        (self.push(replica), report)
    }

    /// Stop replica `index` (its slot keeps a placeholder so indices stay
    /// stable) and return its canonical `.bean`.
    fn stop(&mut self, index: usize) -> PathBuf {
        let name = self.replicas[index].name.clone();
        let key = Arc::clone(&self.replicas[index].key);
        let placeholder = Replica::boot(&name, key);
        let replica = std::mem::replace(&mut self.replicas[index], placeholder);
        replica.stop()
    }

    /// Re-boot slot `index` on `path` through the `gl-node` order.
    fn restart_like_gl_node(&mut self, index: usize, path: PathBuf, mesh_id: &str) -> GlNodeBoot {
        let name = self.replicas[index].name.clone();
        let key = Arc::clone(&self.replicas[index].key);
        let (replica, report) = Replica::boot_like_gl_node(&name, key, path, mesh_id);
        self.replicas[index] = replica;
        report
    }

    /// Anti-entropy from `from` to `to` exactly as `gl-node` runs one Want
    /// session: the Want is `compute_want_by_membership` over the holder's
    /// advert (heads first, then every id in hex order), fetched in chunks of
    /// `MAX_SUPPLY_ENTRIES`, each chunk staged, drained and committed before
    /// the next (`fetch_want_chunk` → `apply_supply_entries_from`). `order`
    /// `None` is the advert order; `Some` re-sorts the Want (an adversarial
    /// server that ignores the Want's order).
    fn serve_like_gl_node(&mut self, from: usize, to: usize, order: Option<Order>) -> usize {
        let wanted: Vec<String> = {
            let holder = &self.replicas[from];
            let receiver = &self.replicas[to];
            let mut heads: Vec<String> = holder.svc.head_txids().into_iter().collect();
            heads.sort();
            let mut ids: Vec<String> = holder.svc.all_directive_ids().into_iter().collect();
            ids.sort();
            let mut want = compute_want_by_membership(
                |id| receiver.svc.contains_directive(id) || receiver.permanent.contains_key(id),
                &heads,
                &ids,
            );
            // gl-node's Want path since T83 (L-95): known ancestors first.
            order_want_ancestors_first(&mut want, |id| receiver.orphans.known_missing_parents(id));
            want
        };
        let wanted = match order {
            Some(order) => self.order_ids(wanted, order),
            None => wanted,
        };
        let mut staged = 0;
        for chunk in wanted.chunks(MAX_SUPPLY_ENTRIES) {
            let holder = &self.replicas[from].svc;
            let entries =
                match build_supply(chunk, |id| holder.get_directive(id).map(make_supply_entry)) {
                    WireMessage::Supply { entries, .. } => entries,
                    other => panic!("build_supply returned {other:?}"),
                };
            let allowlist = &self.allowlist;
            staged += self.replicas[to].intake(entries, allowlist);
        }
        staged
    }

    /// Ticks of `serve_like_gl_node` from `from` to `to` until one changes
    /// nothing, bounded by `max_ticks`. Returns the ticks taken (the last one
    /// is the quiet one) or `None` if the bound was hit first.
    fn join_like_gl_node(
        &mut self,
        from: usize,
        to: usize,
        order: Option<Order>,
        max_ticks: usize,
    ) -> Option<usize> {
        for tick in 1..=max_ticks {
            let before = self.replicas[to].svc.directive_count();
            self.serve_like_gl_node(from, to, order);
            if self.replicas[to].svc.directive_count() == before {
                return Some(tick);
            }
        }
        None
    }
}

/// `count` parentless transactions signed by `attacker` whose content ids
/// all start with `prefix` — the L-68 id-grinder: a narration is free text,
/// so the attacker tries bodies until the SHA-256 lands where it wants (here
/// below every honest id). Only the winners are signed. Returns the ids.
fn ground_parentless_flood(
    mesh: &mut Mesh,
    attacker: &PeerKeySignatureProvider,
    count: usize,
    tag: &str,
    prefix: &str,
) -> Vec<String> {
    let mut ids = Vec::with_capacity(count);
    let mut attempt = 0u64;
    while ids.len() < count {
        let narration = format!("{tag}-ground{attempt}");
        attempt += 1;
        let body = Directive::Transaction(transaction_body(&narration, 1, "Assets:Cash"));
        if !compute_content_id(&body).starts_with(prefix) {
            continue;
        }
        let lamport = 100 + u64::try_from(ids.len()).expect("small");
        let directive = hand_transaction(attacker, &narration, 1, &[], lamport);
        ids.push(mesh.record(&directive));
    }
    ids
}

/// An `open` with `currencies`, stamped and signed by hand with `key`.
fn hand_open_with_currencies(
    key: &PeerKeySignatureProvider,
    account: &str,
    currencies: Vec<String>,
    lamport: u64,
) -> Directive {
    let mut open = Open {
        date: day(1),
        account: account.to_owned(),
        currencies,
        metadata: BTreeMap::new(),
    };
    let content_id = compute_content_id(&Directive::Open(open.clone()));
    let lamport = lamport.to_string();
    let signature = sign(
        key,
        &SignableMessage {
            content_id: &content_id,
            is_transaction: false,
            parents: "",
            lamport: &lamport,
        },
    );
    open.metadata
        .insert("openledger-author".to_owned(), key.public_key_hex());
    open.metadata
        .insert("openledger-lamport".to_owned(), lamport);
    open.metadata
        .insert("openledger-signature".to_owned(), signature);
    Directive::Open(open)
}

// ─── A1 / L-68: multi-author flood, local authoring on every replica ────────

/// Two allowlisted flooders serve 400 parentless transactions each, ids
/// ground to start with `00` so every flooded head sorts below every honest
/// one (the L-68 attack); every replica is served a random subset (≈ 400
/// heads), then authors twice under `select_parents`. Pins (T72 / L-68) that
/// every honest author's head is named by every local append while the flood
/// is over `MAX_PARENTS` (author diversity: `max(1, 256 / A)` per author, so
/// no flooder's share can crowd an honest head out), that no append names
/// more than `MAX_PARENTS`, and that the mesh — the flooders still serving —
/// converges to the oracle. Smallest-id-only choice (T64) fails this.
#[test]
fn l68_multi_author_flood_with_local_authoring_on_every_replica_converges() {
    let mut mesh = seeded_mesh(9241, 3);
    let flooders = [key(210), key(211)];
    let flooder_ids: BTreeSet<String> = flooders.iter().map(|k| k.public_key_hex()).collect();
    for flooder in &flooders {
        mesh.allow_also(&flooder.public_key_hex());
    }
    let mut flood: Vec<String> = Vec::new();
    for (i, flooder) in flooders.iter().enumerate() {
        flood.extend(ground_parentless_flood(
            &mut mesh,
            flooder,
            400,
            &format!("x{i}"),
            "00",
        ));
    }
    // One honest head per replica before the flood, concurrent, then synced.
    for replica in 0..3 {
        mesh.append(replica, &format!("pre-{replica}"), 2, "Assets:Cash");
    }
    mesh.run_to_fixed_point(Order::Ascending);
    for replica in 0..3 {
        let subset = mesh.rng.subset(&flood);
        mesh.deliver(replica, subset, Order::Random);
    }
    let mut appends = 0usize;
    for round in 0..2 {
        for replica in 0..3 {
            let heads = mesh.replicas[replica].heads_with_authors();
            if round == 0 {
                assert!(
                    heads.len() > MAX_PARENTS,
                    "R{replica}: the flood must be over the cap ({} heads)",
                    heads.len()
                );
            }
            let id = mesh.append(
                replica,
                &format!("local-{replica}-{round}"),
                3,
                "Expenses:Food",
            );
            let parents = mesh.replicas[replica].parents_of(&id);
            let after = mesh.replicas[replica].svc.head_count();
            // The cost of one honest append under a flood: it merges
            // `MAX_PARENTS − honest heads` flooded heads, so the frontier
            // shrinks by ~255 per honest append and grows only as fast as the
            // flooders author (the T72 residual: bounded by the file cap).
            eprintln!(
                "A1 / L-68 flood: R{replica} round {round}: heads {} → {after}, named {}",
                heads.len(),
                parents.len()
            );
            assert_eq!(
                parents.len(),
                heads.len().min(MAX_PARENTS),
                "R{replica} round {round}: names every head up to the cap"
            );
            for (head, author) in &heads {
                let honest = author
                    .as_ref()
                    .is_some_and(|author| !flooder_ids.contains(author));
                if honest {
                    assert!(
                        parents.contains(head),
                        "R{replica} round {round}: honest head {head} (author {author:?}) \
                         was not named — L-68 diversity broken"
                    );
                }
            }
            appends += 1;
        }
    }
    assert_eq!(appends, 6);
    let pool_rounds = mesh.deliver_pool_to_fixed_point(Order::Random);
    let gossip_rounds = mesh.run_to_fixed_point(Order::Random);
    eprintln!("A1 / L-68 flood: pool rounds {pool_rounds}, anti-entropy rounds {gossip_rounds}");
    mesh.assert_converged("A1 / L-68 multi-author flood");
}

/// Two replicas holding the same head set — 300 flooded heads ground below
/// every honest id, plus one honest head from each replica — name
/// byte-identical parents when each authors (T72 / L-68: `select_parents` is
/// a pure function of the head set; nothing replica-local, no `HashMap`
/// order, no own-author preference — "own heads first, then smallest" would
/// name `pre-a` on one replica and `pre-b` on the other). The mesh then
/// converges with the flooder still serving.
#[test]
fn l68_replicas_holding_identical_heads_name_identical_parents() {
    let mut mesh = seeded_mesh(9242, 2);
    let attacker = key(200);
    mesh.allow_also(&attacker.public_key_hex());
    let pre_a = mesh.append(0, "pre-a", 2, "Assets:Cash");
    let pre_b = mesh.append(1, "pre-b", 4, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let flood = ground_parentless_flood(&mut mesh, &attacker, 300, "g", "00");
    assert!(
        flood.iter().all(|id| id < &pre_a && id < &pre_b),
        "every ground id sorts below both honest heads"
    );
    for replica in [0, 1] {
        mesh.deliver(replica, flood.clone(), Order::Random);
    }
    let heads_a = mesh.replicas[0].heads_with_authors();
    let heads_b = mesh.replicas[1].heads_with_authors();
    assert_eq!(heads_a, heads_b, "both replicas hold the same heads");
    assert_eq!(heads_a.len(), 302);
    let a_id = mesh.append(0, "a-local", 5, "Expenses:Food");
    let b_id = mesh.append(1, "b-local", 6, "Expenses:Food");
    let parents_a = mesh.replicas[0].parents_of(&a_id);
    let parents_b = mesh.replicas[1].parents_of(&b_id);
    assert_eq!(parents_a.len(), MAX_PARENTS);
    assert_eq!(
        parents_a, parents_b,
        "the same head set must name the same parents on every replica"
    );
    assert!(parents_a.contains(&pre_a) && parents_a.contains(&pre_b));
    assert!(parents_a.windows(2).all(|w| w[0] < w[1]), "ascending");
    mesh.deliver_pool_to_fixed_point(Order::Random);
    mesh.run_to_fixed_point(Order::Random);
    mesh.assert_converged("A1 / L-68 determinism");
}

// ─── A1 / H-19 + H-20: the bootstrap join through gl-node's real boot order ─

/// The README's join, run through `gl-node`'s actual sequence (`boot("local")`
/// → `set_author_id` → `set_signer` → `set_verifier` → `finalize_operator_input`
/// → `verify_own_history` → compaction) on a copy of A's `.bean`, after A
/// itself was stopped, its file edited as `edit` says, and restarted the same
/// way (the README's stop → edit → start); B never stops. `hand_line` appends
/// one transaction with no envelope (operator input, H-13); `edit_record`
/// changes the narration of a record A signed (H-20). Everyone then authors
/// and anti-entropy runs in the real advert order. Returns the harness's
/// divergence report at the fixed point, or `None` when converged, plus the
/// ids of what B is still waiting on.
fn bootstrap_join_scenario(
    seed: u64,
    hand_line: bool,
    edit_record: bool,
) -> (Option<String>, Vec<String>) {
    let (mut mesh, jump_id, _after, _open) = h19_mesh(seed, Jump::Transaction);
    let (a, b) = (0, 1);
    let signed = mesh.append(a, "to-be-edited", 11, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    assert!(mesh.replicas[b].svc.contains_directive(&signed));

    let path = mesh.stop(a);
    let mut text = std::fs::read_to_string(&path).expect("read A's .bean");
    assert!(text.contains("\"to-be-edited\""));
    if edit_record {
        text = text.replace("\"to-be-edited\"", "\"to-be-edited (typo fixed)\"");
    }
    if hand_line {
        text.push_str(
            "\n2024-01-15 * \"hand-typed by the operator\"\n  Assets:Cash  9 USD\n  Equity:Opening  -9 USD\n",
        );
    }
    std::fs::write(&path, &text).expect("write the edited .bean");

    // A restarts on its file, gl-node order. The H-20 pass runs inside
    // `set_signer` / `set_verifier`, so `verify_own_history` itself reports 0
    // here (A1 report §4); the quarantine is observed via `quarantined_count`.
    let a_report = mesh.restart_like_gl_node(a, path.clone(), MESH_ID);
    let a_quarantined = mesh.replicas[a].svc.quarantined_count();
    eprintln!("A1 / bootstrap: A restarted: {a_report:?}, quarantined {a_quarantined}");
    // What `main.rs` logs its H-20 banner from: the LAST pass's count, which
    // is 0 whenever the setters' passes already did the quarantining.
    assert_eq!(a_report.quarantined_by_signature, 0);
    assert_eq!(
        a_report.finalized,
        usize::from(hand_line),
        "the hand line is operator input"
    );
    assert_eq!(
        a_quarantined,
        usize::from(edit_record),
        "the edited record is quarantined (H-20)"
    );
    assert_eq!(
        mesh.replicas[a].svc.contains_directive(&signed),
        !edit_record
    );

    // F joins by bootstrap from A's file (post-restart compaction).
    let copy = temp_bean("F-copy");
    std::fs::copy(&path, &copy).expect("copy A's compacted .bean");
    let (f, f_report) = mesh.add_like_gl_node("F", key(10), copy, MESH_ID);
    eprintln!(
        "A1 / bootstrap: F booted: {f_report:?}, holds {} quarantined {}",
        mesh.replicas[f].svc.directive_count(),
        mesh.replicas[f].svc.quarantined_count()
    );
    assert!(
        mesh.replicas[f].svc.contains_directive(&jump_id),
        "the removed author's transaction loads as history"
    );
    assert_eq!(
        f_report.finalized, 0,
        "A's compaction already finalised the hand line under A"
    );
    assert_eq!(
        mesh.replicas[f].svc.quarantined_count(),
        usize::from(edit_record)
    );
    assert_eq!(
        mesh.replicas[f].svc.directive_count(),
        mesh.replicas[a].svc.directive_count(),
        "the copy boots with A's whole history"
    );

    mesh.append(a, "after-a", 3, "Assets:Cash");
    mesh.append(b, "after-b", 4, "Assets:Bank");
    let own = mesh.append(f, "after-f", 8, "Assets:Cash");
    let mut ticks = 0;
    loop {
        ticks += 1;
        let before = mesh.counts();
        for to in 0..mesh.replicas.len() {
            for from in 0..mesh.replicas.len() {
                if from != to {
                    mesh.serve_like_gl_node(from, to, None);
                }
            }
        }
        if mesh.counts() == before {
            break;
        }
        assert!(ticks < MAX_ROUNDS);
    }
    eprintln!(
        "A1 / bootstrap: anti-entropy ticks {ticks}, counts {:?}, F's own write on A {} on B {}",
        mesh.counts(),
        mesh.replicas[a].svc.contains_directive(&own),
        mesh.replicas[b].svc.contains_directive(&own)
    );
    let report = mesh.divergence_among(&mesh.all(), &[]);
    let mut waiting: Vec<String> = mesh.replicas[b]
        .orphans
        .wanted_parent_ids()
        .into_iter()
        .collect();
    waiting.sort();
    let _ = std::fs::remove_file(&path);
    (report, waiting)
}

/// A hand-typed line only (no edit): the operator input is adopted under A's
/// identity at A's restart, the copy carries it finalised, and the join
/// converges with F's own write accepted everywhere. Passes at HEAD.
#[test]
fn h19_bootstrap_join_through_gl_node_order_with_operator_input_converges() {
    let (report, _) = bootstrap_join_scenario(9243, true, false);
    assert!(
        report.is_none(),
        "A1 / bootstrap (hand line): {}",
        report.unwrap_or_default()
    );
}

/// An edited signed record only (no hand line): A's restart and F's boot both
/// quarantine it (H-20), B still serves the original and both re-adopt it,
/// and the join converges. Passes at HEAD.
#[test]
fn h19_bootstrap_join_through_gl_node_order_with_a_quarantined_block_converges() {
    let (report, _) = bootstrap_join_scenario(9248, false, true);
    assert!(
        report.is_none(),
        "A1 / bootstrap (edit): {}",
        report.unwrap_or_default()
    );
}

/// Both at once — the README's stop → edit → start with a typo fixed in a
/// signed record AND a line appended. Boot stamps the operator input's
/// parents (`adopt_operator_input_at_boot` → `adopt_file_directive` →
/// `choose_parents`) against the heads it holds at that moment, which
/// include the edited record; the H-20 pass runs later, inside `set_signer`.
/// Before T79 `quarantine_out_of_dag` rebuilt the survivors without
/// re-parenting them, so the hand line — signed by A and served — named a
/// parent that existed only in A's (and the copy's) quarantine, B buffered it
/// forever, and so every write A and F made afterwards (H-22; failed at
/// `3d64a16` with B three short, waiting on the quarantined id). The rebuild
/// now re-chooses the parents of still-unsigned operator input, so the mesh
/// converges through the bootstrap join.
#[test]
fn h20_operator_input_stamped_at_boot_must_not_name_a_record_the_h20_pass_quarantines() {
    let (report, waiting) = bootstrap_join_scenario(9249, true, true);
    eprintln!("A1 / bootstrap (edit + hand line): B waits on {waiting:?}");
    assert!(
        report.is_none(),
        "A1 / bootstrap (edit + hand line): {}",
        report.unwrap_or_default()
    );
}

/// A joiner whose key and verifier are for a different `meshId` boots on the
/// copy: every signature in the file is over another mesh's domain, so the
/// H-20 pass quarantines the ENTIRE history at boot. Pins that the
/// misconfiguration is total and visible in the counts (nothing loads into
/// the DAG, nothing half-joins). The harness's intake signs and verifies for
/// [`MESH_ID`] on every replica, so the wire side of the mismatch is not
/// modelled here; the boot side is what the bootstrap join adds.
#[test]
fn h19_bootstrap_join_with_the_wrong_mesh_id_quarantines_everything_at_boot() {
    let (mut mesh, _jump_id, _after, _open) = h19_mesh(9244, Jump::Open);
    let a = 0;
    let held_by_a = mesh.replicas[a].svc.directive_count();
    let path = mesh.stop(a);
    let copy = temp_bean("F-wrong-mesh");
    std::fs::copy(&path, &copy).expect("copy A's compacted .bean");
    let (f, report) =
        mesh.add_like_gl_node("F", key_for_mesh(10, "another-mesh"), copy, "another-mesh");
    eprintln!(
        "A1 / wrong meshId: {report:?}, A held {held_by_a}, F holds {} quarantined {}",
        mesh.replicas[f].svc.directive_count(),
        mesh.replicas[f].svc.quarantined_count()
    );
    assert_eq!(
        mesh.replicas[f].svc.quarantined_count(),
        held_by_a,
        "every record is quarantined"
    );
    assert_eq!(mesh.replicas[f].svc.directive_count(), 0);
    let _ = std::fs::remove_file(&path);
}

// ─── A1 / T75 residual: pre-cap history in one replica's file ───────────────

/// M-51 (0924 A1-2), closed by T81: A's file (pre-T75 history) holds an `open`
/// with `MAX_CURRENCIES_PER_OPEN + 1` currencies; A boots on it and posts to
/// that account. Before T81 a fresh F joining by anti-entropy refused the
/// `open` at intake (`ResourceLimitExceeded`, cached for good) and buffered
/// every transaction on that account forever — the M-50 shape for the T75
/// caps (failed at `3d64a16` with F holding 2 of 4). The wire, staging and
/// boot now hold history to the legacy ceilings (decision (6)), so the join
/// converges.
#[test]
fn t75_over_cap_open_loaded_from_a_file_partitions_anti_entropy_joiners() {
    let mut mesh = Mesh::new(9245);
    let peer = key(1);
    let mut currencies: Vec<String> = (0..ledger::limits::MAX_CURRENCIES_PER_OPEN)
        .map(|i| format!("C{i:03}"))
        .collect();
    currencies.push("USD".to_owned());
    let history = [
        hand_open(&peer, "Assets:Cash", 1),
        hand_open(&peer, "Equity:Opening", 2),
        hand_open_with_currencies(&peer, "Assets:Multi", currencies, 3),
    ];
    let path = temp_bean("pre-t75");
    std::fs::write(&path, ledger::serialize::full_file_serialize(&history, &[]))
        .expect("write the history file");
    let a = mesh.add_on_file("A", 1, path);
    assert_eq!(
        mesh.replicas[a].svc.directive_count(),
        3,
        "boot loads the over-cap open"
    );
    let posted = mesh.append(a, "into-multi", 5, "Assets:Multi");
    let f = mesh.add("F", 10);
    let rounds = mesh.run_to_fixed_point(Order::Ascending);
    let fresh = &mesh.replicas[f];
    eprintln!(
        "A1 / T75: anti-entropy rounds {rounds}; F holds {} of {}, permanent {:?}, orphans {}",
        fresh.svc.directive_count(),
        mesh.replicas[a].svc.directive_count(),
        fresh.permanent,
        fresh.orphans.len()
    );
    assert!(
        fresh.svc.contains_directive(&posted),
        "F must hold the posting on Assets:Multi"
    );
    let among = mesh.all();
    mesh.assert_converged_among("A1 / T75 over-cap open", &among, &[]);
}

// ─── A1 / H-19: the clock-versus-history warning on an honest mesh ──────────

/// No jump anywhere: a two-replica mesh with `opens` accounts (parentless, so
/// a joiner adopts them in advert order, i.e. hex order) and two
/// transactions; then `joiners` fresh nodes join by anti-entropy, each
/// authoring one directive — an `open` when `joiner_opens`, else a
/// transaction. Every adoption of a value below the clock still adds one
/// (`max(local, remote) + 1`), so a join inflates the joiner's clock by its
/// inversions, its own directive stamps that clock into the history, and the
/// next joiner starts from there: clocks compound across joins whenever the
/// highest-lamport directive is parentless (a transaction at the tip is
/// drained last, after its parents, so it does not compound). Returns R0's
/// clock and count and whether the H-19 predicate fired on any node — since
/// T83 (L-94) the history's lamport gap against `LAMPORT_GAP_WARN`, the exact
/// comparison behind the boot and adoption WARN.
fn honest_mesh_clock_after_fresh_joins(
    opens: usize,
    joiners: usize,
    order: Option<Order>,
    joiner_opens: bool,
) -> (u64, usize, bool) {
    let mut mesh = seeded_mesh(9246, 2);
    for i in 0..opens {
        mesh.open(0, &format!("Assets:Acct{i:04}"));
    }
    mesh.append(0, "t-0", 1, "Assets:Cash");
    mesh.append(1, "t-1", 2, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let mut fired = false;
    for j in 0..joiners {
        let f = mesh.add(&format!("J{j}"), u8::try_from(20 + j).expect("small"));
        let ticks = mesh
            .join_like_gl_node(0, f, order, MAX_ROUNDS)
            .expect("joins");
        if joiner_opens {
            mesh.open(f, &format!("Assets:Joiner{j}"));
        } else {
            mesh.append(f, &format!("j{j}"), 3, "Assets:Cash");
        }
        mesh.run_to_fixed_point(Order::Ascending);
        let clock = mesh.replicas[f].svc.lamport_clock();
        let count = mesh.replicas[f].svc.directive_count();
        let gap = mesh.replicas[f].svc.lamport_gap();
        let far = gap >= LAMPORT_GAP_WARN;
        eprintln!(
            "A1 / H-19 warn: joiner {j}: ticks {ticks}, clock {clock}, count {count}, \
             gap {gap}, fires {far}"
        );
        fired |= far;
    }
    let clock = mesh.replicas[0].svc.lamport_clock();
    let count = mesh.replicas[0].svc.directive_count();
    (
        clock,
        count,
        fired || mesh.replicas[0].svc.lamport_gap() >= LAMPORT_GAP_WARN,
    )
}

/// L-94 (0924 A1-1), closed by T83: T72's `4 × count + 1024` was not a bound
/// on honest clocks — they compound across fresh joins — so a 300-account
/// ledger with twelve fresh nodes joining by anti-entropy in the real advert
/// order, each opening an account, ended with R0's clock above it with no jump
/// in the history, and the WARN prescribed the bootstrap join (failed at
/// `3d64a16`: clock 2,314 over 317 directives, threshold 2,292). The warning
/// is now judged on the lamport gap (decision (12)), which honest joins
/// cannot compound.
#[test]
fn h19_clock_warning_is_silent_on_an_honest_mesh_with_repeated_fresh_joins() {
    let (clock, count, fired) = honest_mesh_clock_after_fresh_joins(300, 12, None, true);
    eprintln!("A1 / H-19 warn: R0 clock {clock}, count {count}, fires {fired}");
    assert!(
        !fired,
        "the H-19 warning fired on an honest mesh: clock {clock} over {count} directives"
    );
}

/// A single fresh join of the same ledger, in advert order and newest-first,
/// and eight joins that each author a transaction, stay silent (they did
/// under T72's ratio too; kept as the control).
#[test]
fn h19_clock_warning_is_silent_after_one_fresh_join_or_transaction_authoring_joins() {
    for (joiners, order, joiner_opens) in [
        (1usize, None, true),
        (1, Some(Order::AntiCausal), true),
        (8, None, false),
    ] {
        let (clock, count, fired) =
            honest_mesh_clock_after_fresh_joins(300, joiners, order, joiner_opens);
        eprintln!(
            "A1 / H-19 warn: joiners {joiners}, order {order:?}, joiner opens {joiner_opens}: \
             R0 clock {clock}, count {count}, fires {fired}"
        );
        assert!(
            !fired,
            "joiners {joiners} order {order:?} opens {joiner_opens}"
        );
    }
}

// ─── A1: a long chain under the orphan-buffer caps ──────────────────────────

/// One author's chain of `n` transactions (every append names the previous
/// head — the ordinary honest shape), held by A; a fresh F joins from A alone
/// through the real Want session (advert order — heads first, then every id
/// in hex order — 256-entry chunks, drain per chunk) or from a server that
/// ignores the Want's order and serves newest-first. Returns the ticks to
/// the fixed point within `max_ticks`, or `None`, and asserts convergence
/// when it was reached.
fn chain_join_ticks(n: usize, order: Option<Order>, max_ticks: usize) -> Option<usize> {
    let mut mesh = seeded_mesh(9247, 1);
    for k in 0..n {
        mesh.append(0, &format!("c{k}"), amount_for(k), account_for(k));
    }
    let f = mesh.add("F", 10);
    let ticks = mesh.join_like_gl_node(0, f, order, max_ticks);
    eprintln!(
        "A1 / chain n={n} order {order:?}: ticks {ticks:?}, F holds {} of {}, orphans {}",
        mesh.replicas[f].svc.directive_count(),
        mesh.replicas[0].svc.directive_count(),
        mesh.replicas[f].orphans.len()
    );
    if ticks.is_some() {
        let among = mesh.all();
        mesh.assert_converged_among(&format!("A1 / chain n={n} {order:?}"), &among, &[]);
    }
    ticks
}

/// A chain that fits the per-peer orphan budget (`MAX_ORPHANS_PER_PEER`)
/// joins in a tick or two in either order: everything that arrives before
/// its parent is buffered and drained as the chain resolves. Passes at HEAD.
#[test]
fn chain_under_the_orphan_cap_joins_in_two_ticks_in_advert_and_reverse_order() {
    let n = MAX_ORPHANS_PER_PEER - 200;
    let advert = chain_join_ticks(n, None, 4).expect("joins within the bound");
    let reverse = chain_join_ticks(n, Some(Order::AntiCausal), 4).expect("joins within the bound");
    eprintln!("A1 / chain under cap: advert order {advert} ticks, newest-first {reverse} ticks");
    assert!(advert <= 3 && reverse <= 3);
}

/// L-95 (0924 A1-4), closed by T83: a chain longer than the per-peer orphan
/// budget. The buffer refuses (never evicts) what arrives past 1,000 entries,
/// and the Want was in hex order, so each tick staged only what happened to
/// percolate through the buffer (at `3d64a16`: 1,300 transactions took
/// exactly 30 ticks, 3,000 held 83 of 3,003 after 30). The buffer now keeps
/// the parent links of what it drops, and the Want is ordered ancestors-first
/// (decision (13)), so the chain arrives parent before child: 3 ticks. A peer
/// that ignores the Want's order and serves newest-first is not helped.
#[test]
fn chain_over_the_orphan_cap_joins_within_thirty_ticks_in_advert_order() {
    let n = 3 * MAX_ORPHANS_PER_PEER;
    let ticks = chain_join_ticks(n, None, 30);
    assert!(
        ticks.is_some(),
        "a {n}-transaction chain did not join in 30 ticks"
    );
}

// ─── A6 (0925): T83 — L-95 ancestors-first under hostile hints, L-94 gap, L-87 release ───

use ledger::service::largest_lamport_gap;
use p2p::orphan_buffer::{OrphanInsert, MAX_PARENT_HINT_IDS};

/// A hostile allowlisted peer's records, delivered to `to` before an honest
/// join, each one leaving a parent hint in `to`'s orphan buffer: a hint
/// cycle (two transactions naming each other — the id ignores the envelope,
/// so both can be built), a transaction naming a parent that exists nowhere,
/// and one that names `holder`'s current heads (delivered to `holder` too, so
/// it is served with the chain and resolves on `to` once the heads arrive).
/// Returns the four ids; the first three stage nowhere.
fn hostile_parent_hints(
    mesh: &mut Mesh,
    attacker: &PeerKeySignatureProvider,
    holder: usize,
    to: usize,
) -> Vec<String> {
    let body_b = Directive::Transaction(transaction_body("x-cycle-b", 1, "Assets:Cash"));
    let id_b = compute_content_id(&body_b);
    let cycle_a = hand_transaction(attacker, "x-cycle-a", 1, std::slice::from_ref(&id_b), 500);
    let id_a = compute_content_id(&cycle_a);
    let cycle_b = hand_transaction(attacker, "x-cycle-b", 1, &[id_a], 501);
    assert_eq!(
        compute_content_id(&cycle_b),
        id_b,
        "the id ignores the envelope"
    );
    let phantom = hand_transaction(attacker, "x-phantom", 1, &["f".repeat(64)], 502);
    let mut heads: Vec<String> = mesh.replicas[holder].svc.head_txids().into_iter().collect();
    heads.sort();
    let piggyback = hand_transaction(attacker, "x-piggyback", 1, &heads, 503);
    let ids: Vec<String> = [cycle_a, cycle_b, phantom, piggyback]
        .iter()
        .map(|directive| mesh.record(directive))
        .collect();
    let staged = mesh.deliver(to, ids.clone(), Order::Causal);
    assert_eq!(
        staged, 0,
        "every hostile record waits on a parent the joiner lacks"
    );
    for id in &ids {
        assert!(
            !mesh.replicas[to]
                .orphans
                .known_missing_parents(id)
                .is_empty(),
            "{id} must leave a parent hint"
        );
    }
    let staged = mesh.deliver(holder, vec![ids[3].clone()], Order::Causal);
    assert_eq!(staged, 1, "the holder has the piggyback's parents");
    ids
}

/// L-95 (T83, decision (13)) under threat (c): the parent hints that order
/// the Want are filled from each record's signed `openledger-parents` line as
/// the receiver saw it, so an allowlisted peer chooses what they say. A hint
/// cycle, a parent that exists nowhere and a record riding on the honest
/// heads are all in F's buffer and hint table before F joins A's chain of
/// `MAX_ORPHANS_PER_PEER + 300` (30 ticks at `3d64a16`, 3 with hints); the
/// ordering is stable, cycle-safe and moves only wanted ids, so the join is
/// as fast as without them and the mesh converges modulo the three records
/// that stage nowhere. Passes at HEAD.
#[test]
fn l95_ancestors_first_join_converges_under_a_hostile_peers_parent_hints() {
    let n = MAX_ORPHANS_PER_PEER + 300;
    let mut mesh = seeded_mesh(9250, 1);
    for k in 0..n {
        mesh.append(0, &format!("c{k}"), amount_for(k), account_for(k));
    }
    let f = mesh.add("F", 10);
    let attacker = key(202);
    mesh.allow_also(&attacker.public_key_hex());
    let hostile = hostile_parent_hints(&mut mesh, &attacker, 0, f);
    let ticks = mesh
        .join_like_gl_node(0, f, None, 30)
        .expect("joins within 30 ticks");
    let joiner = &mesh.replicas[f];
    eprintln!(
        "A6 / L-95 hostile hints: {n}-chain joined in {ticks} ticks; F holds {} of {}, \
         orphans {} waiting on {:?}",
        joiner.svc.directive_count(),
        mesh.replicas[0].svc.directive_count(),
        joiner.orphans.len(),
        joiner.orphans.wanted_parent_ids().len()
    );
    assert!(
        ticks <= 5,
        "the hostile hints slowed the join to {ticks} ticks"
    );
    assert!(
        joiner.svc.contains_directive(&hostile[3]),
        "the piggyback resolved once the heads arrived"
    );
    let excluded: Vec<String> = hostile[..3].to_vec();
    let among = mesh.all();
    mesh.assert_converged_among("A6 / L-95 hostile hints", &among, &excluded);
}

/// A6-2 (0925): the parent-hint table is one global budget
/// (`MAX_PARENT_HINT_IDS`, keys and parents counted), pruned only when full
/// and only of hints older than `MAX_ORPHAN_AGE`. One allowlisted peer whose
/// records name parents nobody holds fills its per-peer share of F's orphan
/// buffer (1,000) and leaves a two-id hint for every record refused after it:
/// 32,768 of them fill the table. A refused honest orphan then records
/// nothing, so an honest chain longer than the buffer joins at the pre-T83
/// speed (the L-95 crawl) for as long as the hostile hints are renewed. The
/// Done note's residual says "one extra round per lost hint"; it is the whole
/// join. Failed at `45014e9`: the chain that joins in 3 ticks with a free
/// table did not join in 30 with a full one. Since T88 (decision (28)) the
/// hostile peer's hints stop at its share of the table; the premise below
/// changed with that decision.
#[test]
fn l95_a_peer_that_fills_the_parent_hint_table_restores_the_crawl_for_honest_joins() {
    let n = MAX_ORPHANS_PER_PEER + 300;
    let mut mesh = seeded_mesh(9251, 1);
    for k in 0..n {
        mesh.append(0, &format!("c{k}"), amount_for(k), account_for(k));
    }
    let f = mesh.add("F", 10);
    let attacker = key(203);
    mesh.allow_also(&attacker.public_key_hex());
    // gl-node's stage, keyed by the remote: X's share of F's buffer fills at
    // `MAX_ORPHANS_PER_PEER`, and every record after it is refused with a
    // hint costing two ids (its own and its one parent). Each record is what
    // intake admits — signed by an allowlisted key, a well-formed parent id.
    let flood = MAX_ORPHANS_PER_PEER + MAX_PARENT_HINT_IDS / 2;
    let (mut buffered, mut refused) = (0usize, 0usize);
    let mut last = String::new();
    for i in 0..flood {
        let lamport = 1_000 + u64::try_from(i).expect("small");
        let directive = hand_transaction(
            &attacker,
            &format!("x-fill{i}"),
            1,
            &[format!("{i:064x}")],
            lamport,
        );
        let id = compute_content_id(&directive);
        let missing = mesh.replicas[f].svc.missing_parent_ids(&directive);
        assert_eq!(missing.len(), 1);
        match mesh.replicas[f].orphans.insert(
            id.clone(),
            directive,
            missing,
            Some(attacker.public_key_hex()),
        ) {
            OrphanInsert::Buffered => buffered += 1,
            OrphanInsert::BudgetExhausted => refused += 1,
            OrphanInsert::Duplicate => panic!("distinct bodies"),
        }
        last = id;
    }
    assert_eq!(buffered, MAX_ORPHANS_PER_PEER);
    assert_eq!(refused, MAX_PARENT_HINT_IDS / 2);
    // T88 / L-107 (decision (28)): the hostile peer's hints stop at its share
    // of the table; before T88 the last one fitted exactly and the table was
    // full for everyone.
    assert!(
        mesh.replicas[f]
            .orphans
            .known_missing_parents(&last)
            .is_empty(),
        "the hostile peer's hints stop at its share"
    );
    let ticks = mesh.join_like_gl_node(0, f, None, 30);
    let joiner = &mesh.replicas[f];
    eprintln!(
        "A6-2 / hint table full ({buffered} buffered, {refused} refused by X): {n}-chain ticks \
         {ticks:?}; F holds {} of {}, orphans {}",
        joiner.svc.directive_count(),
        mesh.replicas[0].svc.directive_count(),
        joiner.orphans.len()
    );
    assert!(
        ticks.is_some_and(|ticks| ticks <= 5),
        "an honest chain join must not depend on a hostile peer's hint budget: ticks {ticks:?}"
    );
}

/// L-94 (T83, decision (12)): the gap is a content property, so the
/// trusted-bootstrap join — the remedy the warning prescribes — cannot open
/// one. Three honest replicas with a dense history; F boots on a copy of R0's
/// compacted file, G on a copy of F's, both author, everyone syncs: no
/// replica's history holds a gap near `LAMPORT_GAP_WARN` and the mesh
/// converges. Passes at HEAD.
#[test]
fn h19_gap_warning_stays_silent_when_honest_nodes_bootstrap_from_a_copy() {
    let mut mesh = seeded_mesh(9252, 3);
    author_dense_history(&mut mesh, 150);
    mesh.run_to_fixed_point(Order::Ascending);
    let f = mesh.add_bootstrapped_from("F", 11, 0);
    mesh.open(f, "Assets:F");
    mesh.append(f, "after-f", 8, "Assets:F");
    let g = mesh.add_bootstrapped_from("G", 12, f);
    mesh.append(g, "after-g", 9, "Assets:Cash");
    for k in 0..50 {
        let author = mesh.rng.below(mesh.replicas.len());
        mesh.append(author, &format!("u{k}"), amount_for(k), account_for(k));
    }
    mesh.run_to_fixed_point(Order::Ascending);
    let gaps: Vec<u64> = mesh
        .replicas
        .iter()
        .map(|replica| replica.svc.lamport_gap())
        .collect();
    eprintln!(
        "A6 / L-94 bootstrap copies: gaps {gaps:?} (threshold {LAMPORT_GAP_WARN}), clocks {:?}",
        mesh.replicas
            .iter()
            .map(|replica| replica.svc.lamport_clock())
            .collect::<Vec<_>>()
    );
    assert!(gaps.iter().all(|gap| *gap < LAMPORT_GAP_WARN), "{gaps:?}");
    mesh.assert_converged("A6 / L-94 bootstrap copies");
}

/// A and B with history, X allowlisted, X's one `open` at
/// `min(clock) + LAMPORT_GAP_WARN` — one ratchet-legal step of 2^28, a
/// sixteenth of `MAX_LAMPORT_ADVANCE` — adopted by both, honest authoring on
/// top, A↔B synced, then X removed from the allowlist. Returns the mesh, X's
/// id and X's key.
fn gap_warn_jump_mesh(seed: u64) -> (Mesh, String, Arc<PeerKeySignatureProvider>) {
    let mut mesh = seeded_mesh(seed, 2);
    let (a, b) = (0, 1);
    let attacker = key(204);
    mesh.allow_also(&attacker.public_key_hex());
    mesh.append(a, "pre-1", 10, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let local = mesh.replicas[a]
        .svc
        .lamport_clock()
        .min(mesh.replicas[b].svc.lamport_clock());
    let jump_id = mesh.record(&hand_open(
        &attacker,
        "Assets:Jump",
        local + LAMPORT_GAP_WARN,
    ));
    for replica in [a, b] {
        mesh.deliver(replica, vec![jump_id.clone()], Order::Causal);
        assert!(
            mesh.replicas[replica].svc.contains_directive(&jump_id),
            "a 2^28 step is under the ratchet"
        );
    }
    mesh.append(a, "post-a", 5, "Assets:Cash");
    mesh.open(b, "Assets:Bank");
    mesh.append(b, "post-b", 7, "Assets:Bank");
    mesh.run_to_fixed_point(Order::Ascending);
    assert!(mesh.divergence_among(&[a, b], &[]).is_none());
    let honest = [mesh.replicas[a].author(), mesh.replicas[b].author()];
    mesh.allow_exactly(&honest);
    (mesh, jump_id, attacker)
}

/// L-94 / H-19 at `LAMPORT_GAP_WARN` exactly: a peer's single 2^28 jump is
/// diagnosed on every node that holds the history (A, B, a fresh joiner and a
/// bootstrap copy — the gap is content, so forever), and yet, the step being
/// far below `MAX_LAMPORT_ADVANCE`, a fresh node still joins by anti-entropy
/// after X's removal: the honest records above the gap sit within one ratchet
/// step of the joiner's clock. Pins the fact the warning's remedy text is
/// judged against (A6, 0925 §3). Passes at HEAD.
#[test]
fn h19_a_peers_2_28_jump_is_diagnosed_everywhere_yet_a_fresh_node_still_joins_by_anti_entropy() {
    let (mut mesh, jump_id, _attacker) = gap_warn_jump_mesh(9253);
    let (a, b) = (0, 1);
    for replica in [a, b] {
        assert!(mesh.replicas[replica].svc.lamport_gap() >= LAMPORT_GAP_WARN);
    }
    let f = mesh.add("F", 13);
    let rounds = mesh.run_to_fixed_point(Order::Ascending);
    eprintln!(
        "A6 / L-94 2^28 jump: F joined by anti-entropy in {rounds} rounds, holds {} of {}, \
         gaps {:?}",
        mesh.replicas[f].svc.directive_count(),
        mesh.replicas[a].svc.directive_count(),
        mesh.replicas
            .iter()
            .map(|replica| replica.svc.lamport_gap())
            .collect::<Vec<_>>()
    );
    assert!(!mesh.replicas[f].svc.contains_directive(&jump_id));
    mesh.assert_converged_among("A6 / L-94 2^28 jump", &[a, b, f], &[jump_id]);
    assert!(mesh.replicas[f].svc.lamport_gap() >= LAMPORT_GAP_WARN);
    let g = mesh.add_bootstrapped_from("G", 14, a);
    assert!(mesh.replicas[g].svc.lamport_gap() >= LAMPORT_GAP_WARN);
}

/// A6-3 (0925), as decision (33) resolved it (T89 / L-111, L-113): the gap
/// warning named "the author of the directive at the top of the gap" as the
/// one that jumped the clock. On a node that holds the history above a
/// removed author's jump but not the jump itself — one that joined by
/// anti-entropy after the remedy, or a copy from which the operator deleted
/// the jumping directive — that directive is the first HONEST record stamped
/// above it, so every boot accused an honest author. The node cannot know
/// which it is, so the warning now says so: it names the author at the top of
/// the gap as the jumper OR the first honest record above a removed one; and
/// a gap under 2^32 is "diagnosed, not uncrossable" — anti-entropy still
/// crosses it — with no bootstrap join prescribed. The warning is F's own,
/// from `verify_own_history` (T89 / L-100).
///
/// Failed at `45014e9`: the text named the jumper outright and prescribed the
/// bootstrap join.
#[test]
fn h19_the_gap_warning_on_a_node_without_the_jump_names_the_removed_author() {
    let (mut mesh, _jump_id, attacker) = gap_warn_jump_mesh(9256);
    let f = mesh.add("F", 13);
    mesh.run_to_fixed_point(Order::Ascending);
    let (gap, top) = largest_lamport_gap(
        mesh.replicas[f]
            .svc
            .dag()
            .directives()
            .into_iter()
            .filter_map(Directive::lamport_clock),
    );
    let named = mesh.replicas[f]
        .svc
        .dag()
        .directives()
        .into_iter()
        .find(|directive| directive.lamport_clock() == Some(top))
        .and_then(author_of);
    assert!(gap >= LAMPORT_GAP_WARN);
    assert_ne!(
        named.as_deref(),
        Some(attacker.public_key_hex().as_str()),
        "premise: F does not hold the jump, so the top of its gap is an honest record"
    );
    let (_, logged) = capture_warnings(|| mesh.replicas[f].svc.verify_own_history());
    eprintln!("A6-3: F's gap {gap} (top {top}, author {named:?}); logged:\n{logged}");
    assert!(
        logged.contains("lamport gap")
            && logged.contains("first honest record stamped above it")
            && logged.contains("diagnosed, not uncrossable"),
        "the warning must not call the author at the top the jumper outright, and must say a \
         gap under 2^32 is crossed by anti-entropy: {logged}"
    );
    assert!(
        !logged.contains("compacted .bean"),
        "no bootstrap join is prescribed for a crossable gap: {logged}"
    );
}

/// A process-wide default subscriber that records nothing but is interested in
/// every callsite (T96 / L-135). Tracing caches each callsite's interest; a
/// callsite first hit by a test with no subscriber of its own was cached as
/// "never", and a concurrent capture's rebuild could miss a registration still
/// in flight — the capturing test then lost that one line (the log checks that
/// failed in two gates, and `m51_…` beside the T85 tests, deterministically).
/// With this installed, no callsite is ever "never"; each thread's scoped
/// subscriber decides.
fn ensure_every_callsite_is_interesting() {
    struct Interested;
    impl tracing::Subscriber for Interested {
        fn register_callsite(
            &self,
            _: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            false
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, _: &tracing::Event<'_>) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let _ = tracing::subscriber::set_global_default(Interested);
        tracing::callsite::rebuild_interest_cache();
    });
}

/// Every WARN (and ERROR) `body` logs on this thread, one line per event
/// with its fields (T89; the boot fuzzer's minimal subscriber, so the test
/// needs nothing beyond `tracing`).
fn capture_warnings<T>(body: impl FnOnce() -> T) -> (T, String) {
    ensure_every_callsite_is_interesting();
    use std::fmt::Write as _;
    use std::sync::{Arc, Mutex};

    struct Fields(String);
    impl tracing::field::Visit for Fields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            let _ = write!(self.0, "{}={:?} ", field.name(), value);
        }
    }
    struct Capture(Arc<Mutex<String>>);
    impl tracing::Subscriber for Capture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= tracing::Level::WARN
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            let mut logged = self.0.lock().unwrap();
            logged.push_str(&fields.0);
            logged.push('\n');
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    let logged = Arc::new(Mutex::new(String::new()));
    let value = tracing::subscriber::with_default(Capture(Arc::clone(&logged)), body);
    let text = logged.lock().unwrap().clone();
    (value, text)
}

/// A writes r1 and r2 (signed), B writes one record A adopts — the ordinary
/// mesh shape, and the one that matters: adoption sets the clock to
/// `max(local, remote) + 1`, a value nobody stamped — then A writes r3, B
/// syncs; A stops, `edit` rewrites its file (given the issued lamports of r2
/// and r3), A restarts in gl-node order and writes r4; anti-entropy to a
/// fixed point. Returns A's clock after the restart, r3's issued lamport,
/// r4's lamport, and every `(author, lamport)` pair B holds more than once.
fn edited_own_record_scenario(
    seed: u64,
    edit: impl Fn(&str, u64, u64) -> String,
) -> (u64, u64, u64, Vec<(String, u64)>) {
    let mut mesh = seeded_mesh(seed, 2);
    let (a, b) = (0, 1);
    mesh.append(a, "r1", 1, "Assets:Cash");
    let r2 = mesh.append(a, "r2", 2, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    mesh.append(b, "b1", 5, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let r3 = mesh.append(a, "r3", 3, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let lamport_of = |mesh: &Mesh, replica: usize, id: &str| {
        mesh.replicas[replica]
            .svc
            .get_directive(id)
            .and_then(Directive::lamport_clock)
            .expect("held with an envelope")
    };
    let l2 = lamport_of(&mesh, b, &r2);
    let l3 = lamport_of(&mesh, b, &r3);
    let path = mesh.stop(a);
    let text = std::fs::read_to_string(&path).expect("read A's .bean");
    let edited = edit(&text, l2, l3);
    assert_ne!(text, edited, "the edit must change the file");
    std::fs::write(&path, edited).expect("write the edited .bean");
    let report = mesh.restart_like_gl_node(a, path.clone(), MESH_ID);
    let quarantined = mesh.replicas[a].svc.quarantined_count();
    // T84 / H-23 (decision (15)): with, when the edited record is not the
    // latest, what names its original id — held until B re-supplies it.
    assert!(
        quarantined >= 1,
        "the edited record is quarantined (H-20): {report:?}"
    );
    // T96 / L-135, decision (52): and nothing else. Every held id is the
    // edited copy (the only one B cannot hold) or r2 / a record descending
    // from it in B's DAG — the edited record's original and what names it.
    let mut descendants: BTreeSet<String> = BTreeSet::from([r2.clone()]);
    let mut frontier = vec![r2.clone()];
    while let Some(id) = frontier.pop() {
        for child in mesh.replicas[b]
            .svc
            .dag()
            .children_of(&id)
            .unwrap_or_default()
        {
            if descendants.insert(child.clone()) {
                frontier.push(child.clone());
            }
        }
    }
    let held = mesh.replicas[a].svc.quarantined_ids();
    let unknown_to_b = held
        .iter()
        .filter(|id| !mesh.replicas[b].svc.contains_directive(id))
        .count();
    assert!(
        unknown_to_b <= 1
            && held.iter().all(|id| {
                !mesh.replicas[b].svc.contains_directive(id) || descendants.contains(*id)
            }),
        "held beyond the edited record and what descends from it: {held:?}"
    );
    let clock = mesh.replicas[a].svc.lamport_clock();
    let r4 = mesh.append(a, "r4", 4, "Assets:Cash");
    let l4 = lamport_of(&mesh, a, &r4);
    mesh.run_to_fixed_point(Order::Ascending);
    assert!(mesh.replicas[b].svc.contains_directive(&r4), "B adopts r4");
    let mut counts: BTreeMap<(String, u64), usize> = BTreeMap::new();
    for directive in mesh.replicas[b].svc.dag().directives() {
        if let (Some(author), Some(lamport)) = (author_of(directive), directive.lamport_clock()) {
            *counts.entry((author, lamport)).or_insert(0) += 1;
        }
    }
    let duplicates: Vec<(String, u64)> = counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(pair, _)| pair)
        .collect();
    eprintln!(
        "A6 / L-87 edit: A restarted at clock {clock} (r3 issued at {l3}); r4 stamped {l4}; \
         B's duplicate pairs {duplicates:?}"
    );
    let _ = std::fs::remove_file(&path);
    (clock, l3, l4, duplicates)
}

/// L-87 (T83) where it holds: the edited record is not the latest own
/// record. Its body edited, or its lamport line edited to 4,000,000,000, r2
/// is quarantined, the clock resumes above r3 (still held, still counted),
/// the next write carries neither the edit nor a lamport a peer already holds
/// under A's key. Passes at HEAD.
#[test]
fn l87_an_edit_of_a_middle_own_record_neither_carries_the_clock_nor_reissues_a_pair() {
    for (label, huge) in [("body", false), ("lamport", true)] {
        let (clock, l3, l4, duplicates) = edited_own_record_scenario(9255, |text, l2, _| {
            if huge {
                text.replace(
                    &format!("openledger-lamport: \"{l2}\""),
                    "openledger-lamport: \"4000000000\"",
                )
            } else {
                text.replace("\"r2\"", "\"r2 (typo fixed)\"")
            }
        });
        assert!(
            clock < 4_000_000_000,
            "{label}: the clock carried the edit: {clock}"
        );
        assert!(l4 > l3, "{label}: r4 at {l4} is not above r3's {l3}");
        assert!(
            duplicates.is_empty(),
            "{label}: B holds duplicate pairs {duplicates:?}"
        );
    }
}

/// A6-1 (0925): `release_clock_carried_by_edited_records` resumes the clock
/// at `max(what remains) + 1`, reasoning that the edited record was stamped
/// above what remains "so the next stamp stays above it". That holds only
/// when the edited record's lamport is exactly one above what remains. Every
/// adoption sets the clock to `max(local, remote) + 1` — one value nobody
/// stamped — so an own record written after any adoption sits TWO above the
/// highest surviving lamport; a body edit of it (its lamport line intact and
/// issued, held by every peer) then resumes the clock one below it, and the
/// node's next write re-issues that `(author, lamport)` pair (M-18): B holds
/// `(A, l3)` twice. Before T83 the clock resumed above the file's lamport.
/// Failed at `45014e9`. Since T84 the release counts an edited record's own
/// lamport unless it lies 2^28 or more above what remains (decision (17)).
#[test]
fn l87_the_clock_release_does_not_reissue_a_pair_a_peer_holds_after_a_body_edit() {
    let (clock, l3, l4, duplicates) = edited_own_record_scenario(9254, |text, _, _| {
        text.replace("\"r3\"", "\"r3 (typo fixed)\"")
    });
    eprintln!("A6-1: clock {clock}, r3 issued {l3}, r4 stamped {l4}, duplicates {duplicates:?}");
    assert!(
        l4 > l3,
        "A's next write re-issued lamport {l4}; r3 was issued at {l3}"
    );
    assert!(
        duplicates.is_empty(),
        "B holds duplicate (author, lamport) pairs: {duplicates:?}"
    );
}

// ─── A6 (0926): T89 across replicas ─────────────────────────────────────────
//
// The placeholder in every own lookup (L-96), the "every signature failed"
// judgement and its held release (L-98, L-99), the gap verdict (L-111, L-113),
// hand-parented lines (L-108) and the stray-key strip on both paths (L-109,
// L-112), each judged on what the other replicas end up holding.

use ledger::serialize::full_file_serialize;

/// Replica `index`'s `.bean` with `text` appended (the operator's editor).
fn append_to_bean(path: &Path, text: &str) {
    let mut content = std::fs::read_to_string(path).expect("read the .bean");
    content.push_str(text);
    std::fs::write(path, content).expect("write the .bean");
}

/// A hand line: `body` as the file spells it, with no envelope except the
/// `openledger-parents` the operator typed, if any.
fn hand_line(body: &Transaction, parents: Option<&str>) -> String {
    let mut body = body.clone();
    if let Some(parents) = parents {
        body.metadata
            .insert("openledger-parents".to_owned(), parents.to_owned());
    }
    format!(
        "\n{}",
        full_file_serialize(&[Directive::Transaction(body)], &[])
    )
}

/// An L-13 reload of replica `index` exactly as `gl-node` drives one after a
/// failed commit: `begin_recovery` → `RecoveryReload::load` →
/// `finish_recovery` (which re-runs `verify_own_history` and finalises what
/// the rebuild read as operator input). Returns every WARN it logged.
fn l13_reload(mesh: &mut Mesh, index: usize) -> String {
    let svc = &mut mesh.replicas[index].svc;
    let reload = svc.begin_recovery();
    let loaded = reload.load();
    let ((), logged) = capture_warnings(|| svc.finish_recovery(reload, loaded));
    logged
}

/// Every `(author, lamport)` pair replica `index` holds more than once.
fn duplicate_pairs(mesh: &Mesh, index: usize) -> Vec<(String, u64)> {
    let mut counts: BTreeMap<(String, u64), usize> = BTreeMap::new();
    for directive in mesh.replicas[index].svc.dag().directives() {
        if let (Some(author), Some(lamport)) = (author_of(directive), directive.lamport_clock()) {
            *counts.entry((author, lamport)).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(pair, _)| pair)
        .collect()
}

/// L-96 (T89, decision (31)) across a boot and an L-13 reload: A's file holds
/// a pre-T80 history A signed under the placeholder `"local"` plus one more
/// `"local"` record at lamport 7 held as unparsable text (the H-20 salvage
/// shape). The gl-node boot runs under the placeholder, so it counted that
/// record as A's own; the L-13 reload boots under A's real id and, before
/// T89, did not — the same file resumed at two clocks (X1 `c5a`: 9 vs 6), and
/// the reloaded node's next write could land at or below a lamport its own
/// file already spells. Now both resume above it, A's next write is stamped
/// above 7, and B, joining by anti-entropy, converges with no duplicate pair.
///
/// Bug-catch: make `is_own_author` compare the id alone and the reload
/// resumes at 4.
#[test]
fn l96_a_placeholder_history_resumes_at_one_clock_on_a_boot_and_an_l13_reload() {
    let key_a = key(1);
    let path = temp_bean("A-placeholder");
    {
        let mut svc = LedgerService::boot(path.clone(), "local".to_owned()).expect("boot");
        svc.set_signer(signer(&key_a));
        let mut a = Replica {
            name: "pre-T80 A".to_owned(),
            key: Arc::clone(&key_a),
            path: path.clone(),
            svc,
            orphans: OrphanBuffer::new(),
            permanent: BTreeMap::new(),
            retryable: BTreeMap::new(),
            keep_files: true,
            join_from: None,
            delivering: None,
        };
        a.open("Assets:Cash");
        a.open("Equity:Opening");
        a.append("pre-signing", 3, "Assets:Cash");
        a.svc.compact().expect("compact");
    }
    let written = std::fs::read_to_string(&path).expect("read");
    assert_eq!(
        written.matches("openledger-author: \"local\"").count(),
        3,
        "premise: every record carries the placeholder"
    );
    append_to_bean(
        &path,
        "\n2024-01-26 * \"Junk\" \"held as text\"\n  openledger-author: \"local\"\n  \
         openledger-lamport: \"7\"\n  this line does not parse\n",
    );
    let mut mesh = Mesh::new(9261);
    let (a, report) = mesh.add_like_gl_node("A", Arc::clone(&key_a), path, MESH_ID);
    let fresh = mesh.replicas[a].svc.lamport_clock();
    for directive in mesh.replicas[a]
        .svc
        .dag()
        .directives()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>()
    {
        mesh.record(&directive);
    }
    let logged = l13_reload(&mut mesh, a);
    let reloaded = mesh.replicas[a].svc.lamport_clock();
    eprintln!(
        "A6 / L-96: {report:?}; clock after the gl-node boot {fresh}, after the L-13 reload \
         {reloaded}; reload logged:\n{logged}"
    );
    assert!(fresh > 7, "the boot resumes above the text-held record");
    assert_eq!(
        reloaded, fresh,
        "a boot and an L-13 reload of one file resume at one clock"
    );
    let written = mesh.append(a, "after-reload", 4, "Assets:Cash");
    let stamped = mesh.replicas[a]
        .svc
        .get_directive(&written)
        .and_then(Directive::lamport_clock)
        .expect("stamped");
    assert!(
        stamped > 7,
        "A's next write is stamped {stamped}, not above 7"
    );
    let b = mesh.add("B", 2);
    mesh.run_to_fixed_point(Order::Ascending);
    assert!(duplicate_pairs(&mesh, b).is_empty());
    mesh.assert_converged("A6 / L-96 placeholder history");
}

/// A and B with history, then X (allowlisted) serves a 2^30 jump — a peer's
/// ratchet-legal step every node adopts — and A authors on top of it, so
/// every record from then on is 2^28 or more above the history before it.
/// Returns the mesh and A's canonical `.bean` (A stopped).
fn jumped_history_then_stop_a(seed: u64) -> (Mesh, PathBuf) {
    let mut mesh = seeded_mesh(seed, 2);
    let (a, b) = (0, 1);
    let x = key(206);
    mesh.allow_also(&x.public_key_hex());
    mesh.append(a, "pre-1", 10, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let clock = mesh.replicas[a]
        .svc
        .lamport_clock()
        .max(mesh.replicas[b].svc.lamport_clock());
    let jump = mesh.record(&hand_open(&x, "Assets:Jump", clock + (1 << 30)));
    for replica in [a, b] {
        mesh.deliver(replica, vec![jump.clone()], Order::Causal);
    }
    mesh.append(a, "post-1", 5, "Assets:Cash");
    mesh.append(a, "post-2", 6, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    assert!(mesh.divergence_among(&[a, b], &[]).is_none());
    let path = mesh.stop(a);
    (mesh, path)
}

/// Restart slot `index` on `path` in gl-node order under `mesh_id` — key and
/// verifier both for that domain, as `main.rs` builds them from one config —
/// and return the WARNs the boot logged.
fn restart_under_mesh_id(mesh: &mut Mesh, index: usize, path: PathBuf, mesh_id: &str) -> String {
    let name = mesh.replicas[index].name.clone();
    let seed = u8::try_from(index + 1).expect("seeded_mesh keys");
    let ((replica, report), logged) = capture_warnings(|| {
        Replica::boot_like_gl_node(&name, key_for_mesh(seed, mesh_id), path, mesh_id)
    });
    eprintln!("A6 / {name} restarted under {mesh_id:?}: {report:?}");
    mesh.replicas[index] = replica;
    logged
}

/// L-98 + L-99 (T89, decision (32)) through gl-node's boot order: A restarts
/// under the wrong `meshId` — key and verifier both for another domain. Every
/// signature in its file fails, across the signer's and the verifier's
/// passes; the "EVERY signature" WARN is logged exactly once, says not to
/// author, and the clock stays where the history put it — above the 2^30
/// jump the history carries, which the L-87 release would otherwise walk it
/// back past (every record is quarantined, so nothing "remains"). An L-13
/// reload under the same config re-derives the same verdict and the same
/// clock. Restarted under the right `meshId`, A quarantines nothing and the
/// mesh converges.
///
/// Bug-catch: release regardless of the verdict and the clock falls below
/// the jump.
#[test]
fn l99_a_wrong_mesh_id_keeps_the_clock_and_warns_once_on_boot_and_reload() {
    let (mut mesh, path) = jumped_history_then_stop_a(9262);
    let (a, b) = (0, 1);
    let history_top = mesh.replicas[b]
        .svc
        .dag()
        .directives()
        .into_iter()
        .filter_map(Directive::lamport_clock)
        .max()
        .expect("history");
    let logged = restart_under_mesh_id(&mut mesh, a, path.clone(), "another-mesh");
    let clock = mesh.replicas[a].svc.lamport_clock();
    eprintln!("A6 / L-99: history top {history_top}, A's clock {clock}\n{logged}");
    assert_eq!(mesh.replicas[a].svc.directive_count(), 0, "all quarantined");
    assert_eq!(logged.matches("EVERY signature").count(), 1, "{logged}");
    assert!(logged.contains("Do not author"), "{logged}");
    assert!(
        clock >= history_top,
        "the clock ({clock}) was released below the history ({history_top})"
    );
    let reload = l13_reload(&mut mesh, a);
    assert_eq!(mesh.replicas[a].svc.lamport_clock(), clock, "{reload}");
    assert_eq!(reload.matches("EVERY signature").count(), 1, "{reload}");
    let path = mesh.stop(a);
    let logged = restart_under_mesh_id(&mut mesh, a, path, MESH_ID);
    assert!(!logged.contains("EVERY signature"), "{logged}");
    assert_eq!(mesh.replicas[a].svc.quarantined_count(), 0);
    mesh.run_to_fixed_point(Order::Ascending);
    mesh.assert_converged_among("A6 / L-99 right meshId again", &[a, b], &[]);
}

/// A6-2 (0926): `every_checked_signature_failed` counted what this node signs
/// itself as a verified signature. The README's stop → edit → start with a
/// hand `open` appended, restarted under the wrong `meshId`: every history
/// signature fails in the setters' passes (the release is held), then
/// `finalize_operator_input` signs the hand line under the wrong domain and
/// its own `verify_history_pass` accepted it — `signature_verified_total` = 1,
/// the verdict flipped and `verify_own_history` stayed silent. The operator got
/// one "signature does not verify — was this record edited?" WARN per record
/// of the history instead of "check meshId / do not author" (L-99's remedy).
/// Before T89 the WARN was judged per pass and fired here. Since T92 (L-114,
/// decision (41)) finalize's own fresh signatures are not counted as verified
/// history, so it fires again. (The same flip after one API write under the
/// wrong domain is prevented by refusing the write, decision (41) (b) — see
/// `l114_a_node_refuses_to_write_while_every_signature_fails`.)
#[test]
fn a6_2_a_hand_line_in_the_same_boot_does_not_hide_a_wrong_mesh_id() {
    let (mut mesh, path) = jumped_history_then_stop_a(9263);
    let a = 0;
    // A hand `open` of a new account: it validates without any of the
    // history, so the rebase keeps it (a hand transaction on a history
    // account would be refused with its `open` and change nothing here).
    append_to_bean(&path, "\n2024-01-02 open Assets:Hand\n");
    let logged = restart_under_mesh_id(&mut mesh, a, path, "another-mesh");
    assert_eq!(
        mesh.replicas[a].svc.directive_count(),
        1,
        "premise: every history record quarantined, the hand line served"
    );
    assert!(
        logged.contains("EVERY signature"),
        "every history signature failed under the wrong meshId, yet the WARN that says so (and \
         says not to author) is missing with a hand line in the boot; logged:\n{logged}"
    );
}

/// L-114 (T92, decision (41) (b)): a node restarted under the wrong
/// `meshId` WARNs that every signature failed and not to author. Before, the
/// advice was only advice (decision (32)): it authored once anyway, and at the
/// next boot that write was history signed under the domain in use — it
/// verified, so not EVERY signature failed, and the history was reported
/// record by record as "edited". Now the API write is refused
/// (`EVERY_SIGNATURE_FAILED`), so the next boot says what the first did. The
/// operator's override (`signing.allowWritesWhenEverySignatureFails`) lets the
/// write through, knowing that cost.
///
/// Bug-catch: drop the verdict check from `next_stamp` and the write goes
/// through and the next boot has no EVERY WARN; ignore the override and the
/// last write is refused.
#[test]
fn l114_a_node_refuses_to_write_while_every_signature_fails() {
    let a = 0;
    let (mut mesh, path) = jumped_history_then_stop_a(9270);
    let first = restart_under_mesh_id(&mut mesh, a, path, "another-mesh");
    assert!(first.contains("EVERY signature"), "premise: {first}");
    let open_written = |replica: &mut Replica| {
        let key = Arc::clone(&replica.key);
        replica.svc.open_account_signing(
            "Assets:Written".to_owned(),
            day(1),
            vec![],
            move |content_id, parents, lamport| {
                key.sign(&SignableMessage {
                    content_id,
                    is_transaction: false,
                    parents,
                    lamport,
                })
            },
        )
    };
    let error = open_written(&mut mesh.replicas[a]).expect_err("refused under the verdict");
    assert_eq!(error.error_code(), "EVERY_SIGNATURE_FAILED", "{error}");
    let path = mesh.stop(a);
    let after_write = restart_under_mesh_id(&mut mesh, a, path, "another-mesh");
    assert!(
        after_write.contains("EVERY signature"),
        "the refused write leaves the verdict to the next boot; logged:\n{after_write}"
    );
    mesh.replicas[a]
        .svc
        .set_write_despite_signature_verdict(true);
    open_written(&mut mesh.replicas[a]).expect("the operator's override writes anyway");
}

/// A and B with history; X (allowlisted) serves two `open`s in a row, each
/// one ratchet-legal step of 2^31 + 2^30 — under 2^32 — above the clock
/// before it, with no honest record between them; honest authoring on top;
/// A↔B synced; X removed from the allowlist (the remedy the gap WARN points
/// at). Returns the mesh and X's two ids.
fn two_step_jump_mesh(seed: u64) -> (Mesh, Vec<String>) {
    let mut mesh = seeded_mesh(seed, 2);
    let (a, b) = (0, 1);
    let x = key(207);
    mesh.allow_also(&x.public_key_hex());
    mesh.append(a, "pre-1", 10, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let step = (1u64 << 31) + (1 << 30);
    let mut jumps = Vec::new();
    for account in ["Assets:JumpOne", "Assets:JumpTwo"] {
        let clock = mesh.replicas[a]
            .svc
            .lamport_clock()
            .max(mesh.replicas[b].svc.lamport_clock());
        let id = mesh.record(&hand_open(&x, account, clock + step));
        for replica in [a, b] {
            mesh.deliver(replica, vec![id.clone()], Order::Causal);
            assert!(
                mesh.replicas[replica].svc.contains_directive(&id),
                "a step under 2^32 is adopted"
            );
        }
        jumps.push(id);
    }
    mesh.append(a, "post-a", 5, "Assets:Cash");
    mesh.open(b, "Assets:Bank");
    mesh.append(b, "post-b", 7, "Assets:Bank");
    mesh.run_to_fixed_point(Order::Ascending);
    assert!(mesh.divergence_among(&[a, b], &[]).is_none());
    let honest = [mesh.replicas[a].author(), mesh.replicas[b].author()];
    mesh.allow_exactly(&honest);
    (mesh, jumps)
}

/// L-113's verdict (T89, decision (33)) held to the join it predicts, single
/// step: a peer's one 2^31 + 2^30 jump, the jumper removed. A's and B's
/// served-history WARN says "diagnosed, not uncrossable" and prescribes no
/// bootstrap join — and a fresh F does join by anti-entropy alone, the honest
/// records above the gap one ratchet step from its clock. Passes at HEAD.
#[test]
fn l113_a_single_sub_2_32_jump_is_called_crossable_and_a_fresh_node_crosses_it() {
    let mut mesh = seeded_mesh(9264, 2);
    let (a, b) = (0, 1);
    let x = key(208);
    mesh.allow_also(&x.public_key_hex());
    mesh.append(a, "pre-1", 10, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let clock = mesh.replicas[a].svc.lamport_clock();
    let jump = mesh.record(&hand_open(&x, "Assets:Jump", clock + (1 << 31) + (1 << 30)));
    for replica in [a, b] {
        mesh.deliver(replica, vec![jump.clone()], Order::Causal);
    }
    mesh.append(a, "post-a", 5, "Assets:Cash");
    mesh.append(b, "post-b", 7, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let honest = [mesh.replicas[a].author(), mesh.replicas[b].author()];
    mesh.allow_exactly(&honest);
    for replica in [a, b] {
        let (_, logged) = capture_warnings(|| mesh.replicas[replica].svc.verify_own_history());
        assert!(
            logged.contains("diagnosed, not uncrossable") && !logged.contains("compacted .bean"),
            "{logged}"
        );
    }
    let f = mesh.add("F", 13);
    mesh.run_to_fixed_point(Order::Ascending);
    mesh.assert_converged_among("A6 / L-113 single step", &[a, b, f], &[jump]);
}

/// A6-1 (0926): the verdict is judged over the history this node serves,
/// which still holds the removed author's records; a joiner refuses them
/// (not allowlisted), so the gap IT must cross is the sum of that author's
/// consecutive steps. Two steps of 2^31 + 2^30 by X with nothing honest in
/// between: every node's largest gap is under 2^32 and its WARN says
/// "diagnosed, not uncrossable … no bootstrap join is needed" — yet once X is
/// removed a fresh F cannot adopt any honest record above the second step
/// (2^32 + 2^31 above its clock, `LamportAdvance`, deferred forever). Before
/// T89 the WARN prescribed the bootstrap join for every gap ≥ 2^28, which was
/// right here. (Steps under 2^28 each, 17 or more of them, are the same
/// shape with no WARN at all — the metric's blind spot since T83.)
#[test]
fn a6_1_a_removed_authors_two_sub_2_32_steps_are_called_crossable_yet_block_a_join() {
    let (mut mesh, jumps) = two_step_jump_mesh(9265);
    let (a, b) = (0, 1);
    let (_, logged) = capture_warnings(|| mesh.replicas[a].svc.verify_own_history());
    assert!(
        logged.contains("lamport gap"),
        "premise: diagnosed: {logged}"
    );
    let says_crossable =
        logged.contains("diagnosed, not uncrossable") && !logged.contains("compacted .bean");
    let f = mesh.add("F", 13);
    let rounds = mesh.run_to_fixed_point(Order::Ascending);
    let report = mesh.divergence_among(&[a, b, f], &jumps);
    eprintln!(
        "A6-1: A's WARN says crossable: {says_crossable}; F after {rounds} rounds holds {} of \
         {}, clock {}\n{logged}",
        mesh.replicas[f].svc.directive_count(),
        mesh.replicas[a].svc.directive_count(),
        mesh.replicas[f].svc.lamport_clock()
    );
    assert!(
        !(says_crossable && report.is_some()),
        "A's WARN says no bootstrap join is needed for its gap, yet a fresh node joining by \
         anti-entropy after X's removal is stuck:\n{}",
        report.unwrap_or_default()
    );
}

/// L-108 (T89) across replicas and restarts: the operator appends two hand
/// lines to A's stopped file, the child — its `openledger-parents` spelling
/// the parent's id — placed before its hand parent on the same date, the
/// parent itself spelling its parent (A's r1), so the two sort among
/// themselves (a hand parent without a parents line goes first anyway). A's
/// gl-node boot adopts both (hand-parented lines go last), B adopts both from
/// A, the mesh converges with the oracle, and a second stop → start of A is a
/// fixed point (same served set, nothing quarantined). Before T89 the child
/// was refused at the first boot and adopted at the second.
///
/// Bug-catch: adopt in plain canonical order and the first boot quarantines
/// the child.
#[test]
fn l108_hand_lines_child_first_are_served_in_one_boot_and_replicate() {
    let mut mesh = seeded_mesh(9266, 2);
    let a = 0;
    let r1 = mesh.append(a, "r1", 1, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let path = mesh.stop(a);
    let parent = transaction_body("hand parent", 4, "Assets:Cash");
    let child = transaction_body("hand child", 2, "Assets:Cash");
    let parent_id = compute_content_id(&Directive::Transaction(parent.clone()));
    let child_id = compute_content_id(&Directive::Transaction(child.clone()));
    append_to_bean(
        &path,
        &format!(
            "{}{}",
            hand_line(&child, Some(&parent_id)),
            hand_line(&parent, Some(&r1))
        ),
    );
    let report = mesh.restart_like_gl_node(a, path, MESH_ID);
    let quarantined = mesh.replicas[a].svc.quarantined_count();
    eprintln!("A6 / L-108: {report:?}, quarantined {quarantined}");
    assert_eq!(quarantined, 0, "nothing refused at the first boot");
    assert_eq!(report.finalized, 2);
    assert_eq!(
        mesh.replicas[a].parents_of(&child_id),
        vec![parent_id.clone()]
    );
    for id in [&parent_id, &child_id] {
        let directive = mesh.replicas[a]
            .svc
            .get_directive(id)
            .expect("served")
            .clone();
        mesh.record(&directive);
    }
    mesh.run_to_fixed_point(Order::Ascending);
    mesh.assert_converged("A6 / L-108 hand lines");
    let held = mesh.replicas[a].svc.all_directive_ids();
    let path = mesh.stop(a);
    mesh.restart_like_gl_node(a, path, MESH_ID);
    assert_eq!(
        mesh.replicas[a].svc.all_directive_ids(),
        held,
        "fixed point"
    );
    assert_eq!(mesh.replicas[a].svc.quarantined_count(), 0);
}

/// A6-3 (0926): `hand_parented_last` orders the hand-parented group by the
/// id each line has AS THE FILE SPELLS IT, but a child names its parent by
/// the id the parent is STORED under, which differs when the parent elides a
/// posting (I2 resolves it; L-11). With an elided-posting hand parent that
/// spells its own parents (so both lines are in the hand-parented group) the
/// dependency is invisible to the sort, the child keeps file order, and
/// L-108's shape is back: refused at the first boot ("exists nowhere"),
/// adopted at the second — served set and file bytes change across a
/// restart with nothing edited — and, pasted under the running node, refused
/// by the live reconcile and deleted from the file by the re-persist.
#[test]
fn a6_3_a_hand_child_of_an_elided_posting_hand_parent_is_served_in_one_boot() {
    let mut mesh = seeded_mesh(9267, 2);
    let a = 0;
    let r1 = mesh.append(a, "r1", 1, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let path = mesh.stop(a);
    let resolved = transaction_body("elided hand parent", 4, "Assets:Cash");
    let stored_id = compute_content_id(&Directive::Transaction(resolved.clone()));
    let mut elided = resolved;
    elided.postings[1].amount = None;
    let child = transaction_body("hand child of elided", 2, "Assets:Cash");
    let child_id = compute_content_id(&Directive::Transaction(child.clone()));
    append_to_bean(
        &path,
        &format!(
            "{}{}",
            hand_line(&child, Some(&stored_id)),
            hand_line(&elided, Some(&r1))
        ),
    );
    mesh.restart_like_gl_node(a, path, MESH_ID);
    let parent_served = mesh.replicas[a].svc.contains_directive(&stored_id);
    let first = mesh.replicas[a].svc.contains_directive(&child_id);
    let path = mesh.stop(a);
    mesh.restart_like_gl_node(a, path.clone(), MESH_ID);
    let second = mesh.replicas[a].svc.contains_directive(&child_id);
    // The live path: the same shape pasted under the running node. What the
    // reconcile refuses there is deleted from the file by the re-persist.
    let resolved = transaction_body("elided hand parent, live", 3, "Assets:Cash");
    let live_parent_id = compute_content_id(&Directive::Transaction(resolved.clone()));
    let mut elided = resolved;
    elided.postings[1].amount = None;
    let child = transaction_body("hand child of elided, live", 1, "Assets:Cash");
    let live_child_id = compute_content_id(&Directive::Transaction(child.clone()));
    append_to_bean(
        &path,
        &format!(
            "{}{}",
            hand_line(&child, Some(&live_parent_id)),
            hand_line(&elided, Some(&r1))
        ),
    );
    let result = mesh.replicas[a].svc.reconcile_file().expect("reconcile");
    let live = mesh.replicas[a].svc.contains_directive(&live_child_id);
    mesh.replicas[a].svc.compact().expect("compact");
    let kept = std::fs::read_to_string(&path)
        .expect("read")
        .contains("hand child of elided, live");
    eprintln!(
        "A6-3: parent stored under {stored_id} served {parent_served}; child served at boot 1 \
         {first}, at boot 2 {second}; live reconcile {result:?}: child served {live}, still in \
         the file {kept}"
    );
    assert!(
        parent_served,
        "premise: the parent is stored under the resolved id"
    );
    assert!(
        first && live,
        "the child of an elided-posting hand parent is refused: at the first boot {} (served \
         at the second: {second}); on the live path {} (still in the file: {kept})",
        !first,
        !live
    );
}

/// L-109 + L-112 (T89, decision (34)) across the wire: a record B signed,
/// carrying a stray `openledger-*` key at directive level AND at posting
/// level, reaches A's `.bean` twice — pasted under the running node (the
/// live reconcile) and, a second record, typed in while A is stopped (boot).
/// A serves both, stripped, under their ids; a fresh C that hears of them
/// ONLY from A adopts both through the real intake (B's signature still
/// verifies — neither key is hashed or signed); the mesh converges with the
/// oracle and no file keeps a stray key. Before T89 the live reconcile
/// refused the pasted block (H-06) and the re-persist deleted it.
///
/// Bug-catch: drop the live strip and the pasted record is refused.
#[test]
fn l109_stray_keyed_records_are_stripped_on_both_paths_and_cross_the_wire_intact() {
    let mut mesh = seeded_mesh(9268, 2);
    let (a, b) = (0, 1);
    mesh.append(a, "r1", 1, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let annotate = |directive: &Directive| {
        let mut annotated = directive.clone();
        if let Directive::Transaction(txn) = &mut annotated {
            txn.metadata
                .insert("openledger-note".to_owned(), "hand annotation".to_owned());
            txn.postings[0]
                .metadata
                .insert("openledger-memo".to_owned(), "posting note".to_owned());
        }
        format!("\n{}", full_file_serialize(&[annotated], &[]))
    };
    // Boot path: A stopped, B's record typed in with both keys.
    let at_boot = mesh.replicas[b].append("from b, read at boot", 6, "Assets:Cash");
    let at_boot_id = mesh.record(&at_boot);
    let path = mesh.stop(a);
    append_to_bean(&path, &annotate(&at_boot));
    mesh.restart_like_gl_node(a, path.clone(), MESH_ID);
    assert!(mesh.replicas[a].svc.contains_directive(&at_boot_id));
    // Live path: B's next record pasted under the running A.
    let live = mesh.replicas[b].append("from b, pasted live", 7, "Assets:Cash");
    let live_id = mesh.record(&live);
    append_to_bean(&path, &annotate(&live));
    let result = mesh.replicas[a].svc.reconcile_file().expect("reconcile");
    eprintln!("A6 / L-109: live reconcile {result:?}");
    assert_eq!(result.new_directives, 1, "{result:?}");
    for id in [&at_boot_id, &live_id] {
        let served = mesh.replicas[a].svc.get_directive(id).expect("served");
        let Directive::Transaction(txn) = served else {
            panic!("a transaction");
        };
        assert!(!txn.metadata.contains_key("openledger-note"));
        assert!(txn
            .postings
            .iter()
            .all(|posting| posting.metadata.is_empty()));
    }
    let c = mesh.add("C", 12);
    mesh.serve(a, c, Order::Causal);
    for id in [&at_boot_id, &live_id] {
        assert!(
            mesh.replicas[c].svc.contains_directive(id),
            "C adopts {id} from A alone: {:?}",
            mesh.replicas[c].permanent.get(id.as_str())
        );
    }
    mesh.run_to_fixed_point(Order::Ascending);
    mesh.assert_converged("A6 / L-109 stray keys");
    mesh.replicas[a].svc.compact().expect("compact");
    let on_disk = std::fs::read_to_string(&path).expect("read A's .bean");
    assert!(
        !on_disk.contains("openledger-note") && !on_disk.contains("openledger-memo"),
        "{on_disk}"
    );
}

/// A6-4 (0926, Info): the verdict's boundary is one off. Adoption sets the
/// clock to `max(local, remote) + 1` and the ratchet refuses only when
/// `remote − clock ≥ 2^32`, so a joiner that has adopted the record at the
/// bottom of a gap crosses one of exactly 2^32. Built on the L-111 shape: X
/// (allowlisted) serves one `open` at `m + 2^32 − 2` (m = the top of the
/// history), A authors on top of it, X is removed; a fresh F joins by
/// anti-entropy — it lacks X's record, so its largest gap is exactly 2^32,
/// topped by A's honest record — and F converges. F's own WARN then calls
/// the gap F just crossed "uncrossable by anti-entropy" and prescribes the
/// bootstrap join.
#[test]
fn a6_4_a_gap_of_exactly_2_32_is_called_uncrossable_by_a_node_that_just_crossed_it() {
    let mut mesh = seeded_mesh(9269, 2);
    let (a, b) = (0, 1);
    let x = key(209);
    mesh.allow_also(&x.public_key_hex());
    mesh.append(a, "pre-1", 10, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let top = mesh.replicas[a]
        .svc
        .dag()
        .directives()
        .into_iter()
        .filter_map(Directive::lamport_clock)
        .max()
        .expect("history");
    let jump = mesh.record(&hand_open(&x, "Assets:Jump", top + MAX_LAMPORT_ADVANCE - 2));
    for replica in [a, b] {
        mesh.deliver(replica, vec![jump.clone()], Order::Causal);
        assert!(mesh.replicas[replica].svc.contains_directive(&jump));
    }
    mesh.append(a, "post-a", 5, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    let honest = [mesh.replicas[a].author(), mesh.replicas[b].author()];
    mesh.allow_exactly(&honest);
    let f = mesh.add("F", 13);
    mesh.run_to_fixed_point(Order::Ascending);
    let crossed = mesh
        .divergence_among(&[a, b, f], std::slice::from_ref(&jump))
        .is_none();
    let (_, logged) = capture_warnings(|| mesh.replicas[f].svc.verify_own_history());
    eprintln!(
        "A6-4: F's gap {} (MAX_LAMPORT_ADVANCE {MAX_LAMPORT_ADVANCE}); F crossed it: \
         {crossed}\n{logged}",
        mesh.replicas[f].svc.lamport_gap()
    );
    assert_eq!(mesh.replicas[f].svc.lamport_gap(), MAX_LAMPORT_ADVANCE);
    assert!(
        !(crossed && logged.contains("uncrossable by anti-entropy")),
        "F crossed the gap by anti-entropy, and its own WARN calls it uncrossable:\n{logged}"
    );
}

// ─── A6 (0927): T93's served views and T95's Want filters, as gl-node runs them ───
//
// The harness's `serve` diffs `all_directive_ids` and supplies `get_directive`,
// so it never saw T93's hidden lines (a line adopted from the `.bean` is served
// only after its rewrite) nor T95's filters on the receiver's side of the
// Want. `a6_0927_serve_like_gl_node` runs `run_head_exchange`'s pipeline to the
// letter: the holder's `served_head_txids` / `served_sorted_directive_ids`
// advert, `compute_want_by_membership`, the refusal filter, `filter_want_for`
// (both T95 filters, with the ledger's `contains_directive` as `holds`, T102),
// `order_want_ancestors_first` by the peer's own copies (T102), then
// `served_directive` for the Supply.

use p2p::orphan_buffer::MAX_ORPHAN_AGE;

/// The Want `receiver` sends `holder`, as gl-node's `run_head_exchange` builds
/// it. `peer` is the name the receiver's orphan buffer knows the holder by
/// (the harness's intake buffers everything from `"peer"`).
fn a6_0927_gl_node_want(receiver: &Replica, holder: &Replica, peer: &str) -> Vec<String> {
    let mut heads: Vec<String> = holder.svc.served_head_txids().into_iter().collect();
    heads.sort_unstable();
    let ids = holder.svc.served_sorted_directive_ids();
    let mut want =
        compute_want_by_membership(|id| receiver.svc.contains_directive(id), &heads, &ids);
    want.retain(|id| !receiver.permanent.contains_key(id));
    let now = std::time::Instant::now();
    receiver
        .orphans
        .refusals()
        .retain_wanted(peer, &mut want, now);
    // T102: both filters in one call, with the ledger as `holds` (L-151),
    // then ordered by this peer's own copies and hints (M-76) — gl-node's
    // `run_head_exchange` since T102.
    receiver
        .orphans
        .filter_want_for(peer, &mut want, now, |id| {
            receiver.svc.contains_directive(id)
        });
    order_want_ancestors_first(&mut want, |id| {
        receiver.orphans.known_missing_parents_from(peer, id)
    });
    want
}

/// One gl-node exchange: `to` Wants from `from` (see
/// [`a6_0927_gl_node_want`]) and ingests what `from` serves for it through
/// `served_directive`. Returns what `to` staged.
fn a6_0927_serve_like_gl_node(mesh: &mut Mesh, from: usize, to: usize) -> usize {
    let want = a6_0927_gl_node_want(&mesh.replicas[to], &mesh.replicas[from], "peer");
    let holder = &mesh.replicas[from].svc;
    let entries = match build_supply(&want, |id| {
        holder.served_directive(id).map(make_supply_entry)
    }) {
        WireMessage::Supply { entries, .. } => entries,
        other => panic!("build_supply returned {other:?}"),
    };
    let allowlist = &mesh.allowlist;
    mesh.replicas[to].intake(entries, allowlist)
}

/// What `svc` serves, derived without any cache: every DAG id
/// `served_directive` answers for, sorted.
fn a6_0927_served_ids_uncached(svc: &LedgerService) -> Vec<String> {
    let mut ids: Vec<String> = svc
        .all_directive_ids()
        .into_iter()
        .filter(|id| svc.served_directive(id).is_some())
        .collect();
    ids.sort_unstable();
    ids
}

/// T95 (the L-116 advert cost) and T93 (L-116) at the mesh level: while a
/// line typed into A's `.bean` waits for its rewrite, A's advert is the cached
/// served-id list — and it must still track the ledger. A record staged from
/// a peer before A's next commit is not advertised until that commit succeeds
/// (T100 / L-148, decision (63): a staged write is withheld, since a failed
/// commit rolls it back), the hand line is neither advertised nor supplied
/// until the rewrite, and a fresh node that hears of everything only from A
/// through gl-node's own pipeline holds exactly what A serves at each step —
/// the staged record once A has committed it.
///
/// Why the shape matters: gl-node's two-phase commit stages under the write
/// lock and commits outside it, so adverts run between a stage and the
/// compaction that clears the held-back set. A cache that outlived a change of
/// the DAG there would advertise a stale set to every peer until the next
/// change — the T95 unit test (`l116_the_served_id_list_is_shared…`) pins that
/// the list is shared, not that it is invalidated.
///
/// Bug-catch (T95, before T100): return the cached list whatever its key and
/// the advert taken after B's record was staged omitted it. Since decision
/// (63) the served set changes only at a commit, which empties the withheld
/// set and bypasses the cache, so this case no longer catches that revert.
#[test]
fn a6_0927_1_the_cached_advert_tracks_a_record_staged_while_a_line_waits_for_its_rewrite() {
    let mut mesh = seeded_mesh(9271, 2);
    let (a, b) = (0, 1);
    mesh.append(a, "r1", 1, "Assets:Cash");
    mesh.run_to_fixed_point(Order::Ascending);
    mesh.replicas[a].svc.compact().expect("compact");
    let path = mesh.replicas[a].path.clone();
    append_to_bean(
        &path,
        "\n2024-01-20 * \"Hand\" \"typed while A runs\"\n  Assets:Cash  3 USD\n  \
         Equity:Opening  -3 USD\n",
    );
    let result = mesh.replicas[a]
        .svc
        .reconcile_file_staged()
        .expect("the live reconcile");
    assert_eq!(result.new_directives, 1, "{result:?}");
    let hand: Vec<String> = mesh.replicas[a]
        .svc
        .all_directive_ids()
        .into_iter()
        .filter(|id| mesh.replicas[a].svc.served_directive(id).is_none())
        .collect();
    assert_eq!(hand.len(), 1, "premise: exactly the hand line is held back");
    let advert = |mesh: &Mesh| mesh.replicas[a].svc.served_sorted_directive_ids().to_vec();
    assert_eq!(
        advert(&mesh),
        a6_0927_served_ids_uncached(&mesh.replicas[a].svc)
    );

    // B writes; A stages B's record through the remote path, before any
    // commit — the window gl-node's adverts run in.
    let from_b = mesh.append(b, "from b", 5, "Assets:Cash");
    let directive = mesh.replicas[b]
        .svc
        .get_directive(&from_b)
        .expect("B's own record")
        .clone();
    assert!(matches!(
        mesh.replicas[a].stage(&from_b, directive),
        Staged::Inserted
    ));
    let staged_advert = advert(&mesh);
    assert!(
        !staged_advert.contains(&from_b),
        "A advertises a record it has only staged (T100 / L-148)"
    );
    assert!(
        !staged_advert.contains(&hand[0]),
        "the hand line is held back"
    );
    assert_eq!(
        staged_advert,
        a6_0927_served_ids_uncached(&mesh.replicas[a].svc)
    );

    // A fresh node that hears only from A, through gl-node's pipeline.
    let c = mesh.add("C", 14);
    for _ in 0..3 {
        a6_0927_serve_like_gl_node(&mut mesh, a, c);
    }
    let mut at_c: Vec<String> = mesh.replicas[c]
        .svc
        .all_directive_ids()
        .into_iter()
        .collect();
    at_c.sort_unstable();
    assert_eq!(
        at_c,
        a6_0927_served_ids_uncached(&mesh.replicas[a].svc),
        "C holds exactly what A serves while the line waits"
    );

    // The rewrite: A's next commit is the compaction that spells the hand
    // line canonically; it is served from then on.
    mesh.replicas[a].commit();
    assert!(mesh.replicas[a].svc.served_directive(&hand[0]).is_some());
    assert!(
        advert(&mesh).contains(&from_b),
        "the staged record is advertised once committed"
    );
    assert_eq!(
        advert(&mesh),
        a6_0927_served_ids_uncached(&mesh.replicas[a].svc)
    );
    for _ in 0..3 {
        a6_0927_serve_like_gl_node(&mut mesh, a, c);
    }
    assert!(
        mesh.replicas[c].svc.contains_directive(&hand[0]),
        "C adopts the hand line after A's rewrite"
    );
    let hand_line = mesh.replicas[a]
        .svc
        .get_directive(&hand[0])
        .expect("served")
        .clone();
    mesh.record(&hand_line);
    mesh.run_to_fixed_point(Order::Ascending);
    mesh.assert_converged("A6 (0927) / T95 cached advert");
}

/// A6-2 (0927): T95's `retain_not_buffered_from` (L-130) drops from the Want
/// an id buffered from the asked peer whose missing parent is not in that
/// Want — and a parent this node now HOLDS is never in it. So when the parent
/// arrives by a path that does not drain the orphan buffer (the watcher's live
/// reconcile of a `.bean` edit: a pasted record, a restored backup), the child
/// is neither staged nor asked for again: it waits for the next batch that
/// stages something (whose drain frees it) or for its orphan TTL
/// (`MAX_ORPHAN_AGE`, an hour). `retain_not_doomed` asks `holds`; this filter
/// has no such argument. Before T95 the child was re-Wanted each exchange and
/// staged at once, its parent being present.
///
/// The shape: A writes x then c (c names x). V hears of c alone first (buffered
/// on x, from A), then x reaches V through its `.bean`. A is V's only peer and
/// writes nothing more; gl-node's exchanges run. Since T102 (L-151, decision
/// (67)) the filter asks `holds` too, and the child is asked for again.
///
/// Bug-catch: give the filter no `holds` again and V never asks for c.
#[test]
fn a6_0927_2_a_buffered_record_whose_parent_arrived_through_the_file_is_asked_for_again() {
    let mut mesh = seeded_mesh(9272, 2);
    let (a, v) = (0, 1);
    let x = mesh.append(a, "x", 1, "Assets:Cash");
    let c = mesh.append(a, "c", 2, "Assets:Cash");
    mesh.deliver(v, vec![c.clone()], Order::Ascending);
    assert!(
        !mesh.replicas[v].svc.contains_directive(&c)
            && mesh.replicas[v].orphans.known_missing_parents(&c) == vec![x.clone()],
        "premise: c is buffered at V on x"
    );
    let x_directive = mesh.replicas[a]
        .svc
        .get_directive(&x)
        .expect("A's record")
        .clone();
    let path = mesh.replicas[v].path.clone();
    append_to_bean(
        &path,
        &format!("\n{}", full_file_serialize(&[x_directive], &[])),
    );
    let result = mesh.replicas[v].svc.reconcile_file().expect("reconcile");
    assert_eq!(result.new_directives, 1, "premise: x adopted from the file");
    assert!(mesh.replicas[v].svc.contains_directive(&x));
    let mut wants = Vec::new();
    for _ in 0..3 {
        wants.push(a6_0927_gl_node_want(
            &mesh.replicas[v],
            &mesh.replicas[a],
            "peer",
        ));
        a6_0927_serve_like_gl_node(&mut mesh, a, v);
    }
    assert!(
        mesh.replicas[v].svc.contains_directive(&c),
        "V holds c's parent, c is buffered from A, and A serves c — yet after 3 exchanges V \
         lacks c: Wants {wants:?}, still buffered {}",
        mesh.replicas[v].orphans.len()
    );
}

/// A6-1 (0927): T95's hint queue (L-134) compacts itself once it passes twice
/// the table's bound — AFTER pushing the new hint's entry and BEFORE inserting
/// the hint, so the compaction's "still recorded at this time?" test drops the
/// entry it just pushed. That hint then has no queue entry: expiry never
/// reaches it and it outlives `MAX_ORPHAN_AGE` (until its id is buffered or
/// arrives, which for an id that never does is forever), holding its share of
/// the peer's and the table's hint budget.
///
/// The shape: one peer at its orphan quota whose refused-for-room records keep
/// arriving (each hint recorded, then forgotten as the record lands) — the
/// churn of a large catch-up — until the queue passes 2 × `MAX_PARENT_HINT_IDS`.
/// Since T102 (L-150) the hint is inserted before the queue is compacted.
///
/// Bug-catch: compact before inserting the hint again and it never expires.
#[test]
fn a6_0927_3_a_hint_recorded_as_the_hint_queue_is_compacted_still_ages_out() {
    let mut buffer = OrphanBuffer::new();
    let peer = Some("peer".to_owned());
    let id = |tag: &str, index: usize| {
        let tag: u64 = tag.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        });
        format!("{tag:016x}{index:048x}")
    };
    let body = hand_transaction(&key(40), "hinted", 1, &[], 1);
    for index in 0..MAX_ORPHANS_PER_PEER {
        let outcome = buffer.insert(
            id("full", index),
            body.clone(),
            vec![id("away", index)],
            peer.clone(),
        );
        assert_eq!(outcome, OrphanInsert::Buffered);
    }
    for index in 0..2 * MAX_PARENT_HINT_IDS {
        let churn = id("churn", index);
        let outcome = buffer.insert(
            churn.clone(),
            body.clone(),
            vec![id("churn-parent", index)],
            peer.clone(),
        );
        assert_eq!(outcome, OrphanInsert::BudgetExhausted);
        // The record lands: its hint is forgotten, its queue entry stays.
        let _ = buffer.parent_arrived(&churn);
    }
    let victim = id("victim", 0);
    let outcome = buffer.insert(
        victim.clone(),
        body.clone(),
        vec![id("victim-parent", 0)],
        peer.clone(),
    );
    assert_eq!(outcome, OrphanInsert::BudgetExhausted);
    assert_eq!(
        buffer.known_missing_parents(&victim),
        vec![id("victim-parent", 0)],
        "premise: the victim is hinted"
    );
    let _ = buffer.evict_expired(std::time::Instant::now() + MAX_ORPHAN_AGE * 2);
    assert!(
        buffer.known_missing_parents(&victim).is_empty(),
        "a hint twice MAX_ORPHAN_AGE old is still held"
    );
}

/// X3-1 (0927): T93 / L-115 (decision (44)) floors the recovery reload's clock
/// at the lamport of the staged write the failed commit discards — that write
/// was served while staged (L-86: gl-node's advert and Supply read
/// `served_sorted_directive_ids` / `served_directive`, which hide only lines
/// awaiting their rewrite), so a peer may hold it. The floor lives in memory
/// only: the operator who answers the failed write (disk full, a read-only
/// mount) by fixing the disk and restarting gets a process start whose clock
/// is the file's `max + 1`, and the first write after it is stamped with the
/// discarded write's lamport — the same `(author, lamport)` pair under another
/// id (M-18). Every shape of X3's 0927 differential re-issues it (52 of 52
/// boot shapes, 12 of 12 live shapes). Failed at `a5313a1`; since T100 (L-148,
/// decision (63)) a staged write is withheld from peers until its commit
/// succeeds, so nothing a peer holds carries the pair the restart reissues.
#[cfg(unix)]
#[test]
fn x3_0927_1_a_restart_after_a_failed_commit_never_reuses_the_served_writes_lamport() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_bean("x3-0927-1").with_extension("d");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("ledger.bean");
    let usd = |n: i64| Amount {
        number: Decimal::from(n),
        currency: "USD".to_owned(),
    };
    let write = |narration: &str, day: u32, n: i64| TransactionInput {
        date: NaiveDate::from_ymd_opt(2024, 2, day).expect("date"),
        flag: Flag::Complete,
        payee: None,
        narration: Some(narration.to_owned()),
        tags: Vec::new(),
        links: Vec::new(),
        postings: vec![
            PostingInput {
                account: "Assets:Cash".to_owned(),
                amount: Some(usd(n)),
                cost: None,
                price: None,
            },
            PostingInput {
                account: "Equity:Opening".to_owned(),
                amount: Some(usd(-n)),
                cost: None,
                price: None,
            },
        ],
    };
    let mut node = LedgerService::boot(&path, "nodeA".to_owned()).expect("boot");
    for account in ["Assets:Cash", "Equity:Opening"] {
        node.open_account(
            account.to_owned(),
            NaiveDate::from_ymd_opt(2024, 1, 1).expect("date"),
            vec![],
        )
        .expect("open");
    }
    node.append_transaction(write("acked", 1, 100))
        .expect("acked");
    node.compact().expect("compact");
    drop(node);
    // A process start; the first write's commit fails (the disk is full).
    let mut node = LedgerService::boot(&path, "nodeA".to_owned()).expect("start");
    let staged = node
        .append_transaction_staged(write("failed", 2, 7), |_, _, _| None)
        .expect("stage");
    let served_while_staged = node.served_sorted_directive_ids().contains(&staged.txid)
        && node.served_directive(&staged.txid).is_some();
    let discarded = node
        .get_directive(&staged.txid)
        .and_then(Directive::lamport_clock)
        .expect("stamped");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).expect("chmod");
    let failed = node.persist_or_reload();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(failed.is_err(), "premise: the commit failed");
    assert!(
        !node.contains_directive(&staged.txid),
        "premise: rolled back"
    );
    // The operator fixes the disk and restarts the node.
    drop(node);
    let mut node = LedgerService::boot(&path, "nodeA".to_owned()).expect("restart");
    let next = node
        .append_transaction_staged(write("after the restart", 3, 9), |_, _, _| None)
        .expect("next write");
    let stamped = node
        .get_directive(&next.txid)
        .and_then(Directive::lamport_clock)
        .expect("stamped");
    node.persist_or_reload().expect("commit");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !(served_while_staged && stamped == discarded),
        "the first write after the restart re-issued (nodeA, {discarded}), the pair of the write \
         the failed commit discarded after serving it"
    );
}
