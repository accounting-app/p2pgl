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
    DirectiveSigner, LedgerService, PostingInput, ServiceError, TransactionInput,
    MAX_LAMPORT_ADVANCE, MAX_PARENTS,
};
use ledger::validate::ValidationError;
use p2p::allowlist::PeerAllowlist;
use p2p::anti_entropy::build_supply;
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
        let missing = self.svc.missing_parent_ids(&directive);
        if let Some(first) = missing.first().cloned() {
            self.orphans
                .insert(id.to_owned(), directive, missing, Some("peer".to_owned()));
            return Staged::Buffered(format!("parent {first}"));
        }
        match self.svc.stage_remote_directive(directive.clone()) {
            Ok(Some(_)) => Staged::Inserted,
            Ok(None) => Staged::Duplicate,
            Err(error) => match account_wait_target(&error) {
                Some(account) => {
                    self.orphans.insert_awaiting_accounts(
                        id.to_owned(),
                        directive,
                        vec![account.clone()],
                        Some("peer".to_owned()),
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
        match self.stage(&entry.id, entry.directive) {
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
        let wanted = self.order_ids(wanted, order);
        let holder = &self.replicas[from].svc;
        let entries = match build_supply(&wanted, |id| {
            holder.get_directive(id).map(make_supply_entry)
        }) {
            WireMessage::Supply { entries, .. } => entries,
            other => panic!("build_supply returned {other:?}"),
        };
        let allowlist = &self.allowlist;
        self.replicas[to].intake(entries, allowlist)
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
/// F joins by anti-entropy alone, once per delivery order. X's directive
/// itself can never reach F (the allowlist is a policy verdict, not a
/// divergence), so membership is compared modulo it; heads and balances
/// exactly.
///
/// At HEAD the verdict depends on the order: served the pre-jump history in
/// causal (ascending-lamport) order, F's clock lands exactly one below the
/// bridge and the first post-jump honest directive is a full ratchet step
/// above it — stuck, the `h1b` shape. Served in any other order, every
/// adoption below the local clock still moves the clock by one
/// (`max(local, remote) + 1`), so a couple of lamport inversions inflate F's
/// clock past the gap and it converges by luck. The test asserts convergence
/// in every order and lists the stuck ones.
#[test]
#[ignore = "documented limitation (H-19, T72 decision (1) revised): the ratchet is judged against the joiner's own clock and no per-directive bound repairs that, so anti-entropy alone cannot join past a removed author's jump; the fix is the trusted-bootstrap join (README §Mesh identity, 'Joining a mesh / removing a peer'), pinned by h19_fresh_node_bootstrapped_from_a_peers_file_converges, plus the boot/adoption warning that names the jump's author"]
fn h19_fresh_node_converges_after_a_maximal_legal_jump_and_allowlist_removal() {
    let mut stuck: Vec<String> = Vec::new();
    for (i, order) in ORDERS.into_iter().enumerate() {
        let (mut mesh, jump_id, _after, _open) =
            h19_mesh(40 + u64::try_from(i).expect("small"), Jump::Open);
        let f = mesh.add("F", 10);
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
        "case 4 (H-19): the anti-entropy-only join is stuck under {} of {} delivery orders\n{}",
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
/// with both authors allowlisted. Stuck at HEAD: F adopts the two opens below
/// the jump and nothing above it.
#[test]
#[ignore = "documented limitation (H-19, T72 decision (1) revised): a pre-T63 history with one jump ≥ 2^32 cannot be joined by anti-entropy alone, with or without the jump's author on the allowlist; the fix is the trusted-bootstrap join (README §Mesh identity, 'Joining a mesh / removing a peer'), pinned by h19_pre_t63_history_is_joinable_by_bootstrap; boot on such a history now warns, naming the jump's author"]
fn h19_pre_t63_history_with_one_large_jump_is_joinable() {
    let mut mesh = Mesh::new(8);
    let jumper = key(202);
    let path = pre_t63_history(&key(1), &jumper);
    let a = mesh.add_on_file("A", 1, path);
    mesh.allow_also(&jumper.public_key_hex());
    assert_eq!(mesh.replicas[a].svc.directive_count(), 5);
    assert_eq!(mesh.replicas[a].svc.lamport_clock(), PRE_T63_JUMP + 4);
    mesh.append(a, "a-after-boot", 3, "Assets:Cash");
    let f = mesh.add("F", 10);
    let rounds = mesh.run_to_fixed_point(Order::Ascending);
    eprintln!(
        "case 5 (H-19 pre-T63): anti-entropy rounds {rounds}, F clock {} holds {}",
        mesh.replicas[f].svc.lamport_clock(),
        mesh.replicas[f].svc.directive_count()
    );
    let among = mesh.all();
    mesh.assert_converged_among("case 5 (H-19 pre-T63)", &among, &[]);
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
