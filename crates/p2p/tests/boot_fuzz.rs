//! Boot file-edit fuzzer (0923 decision: the harness lands before T73).
//!
//! The standing invariant this file pins:
//!
//! > After boot (+ signer install + finalize + startup compaction), every
//! > directive this node serves would be accepted by a signing peer, and
//! > nothing boot loaded contradicts what the file's node-written records said.
//!
//! A node writes a canonical `.bean` with a real Ed25519 signer; the operator
//! then edits that file with the node stopped (the README's supported workflow)
//! and starts the node again. The mutation operators below are the edits an
//! operator, an editor or a copy-paste actually makes: a narration typo fix, an
//! amount fix, a dedent, a BOM, a stray word, a dropped envelope line, a
//! hand-appended record, a duplicated block, a deleted block, CRLF.
//!
//! **Peer acceptance is the real wire path**, not a proxy (wave rule 5):
//! [`validate_supply_entry`] + [`verify_remote_signature`] +
//! [`verify_author_allowlisted`] on the `SupplyEntry` the node would build
//! ([`make_supply_entry`]), under a signing peer whose allowlist holds this
//! node's id, plus the peer's DAG rule (parents resolve) and I1.
//!
//! The pipeline under test mirrors `gl-node/src/main.rs`: `boot` with the
//! placeholder author `"local"` → `set_author_id(real)` → `set_signer` →
//! `finalize_operator_input` → startup compaction → and a second run of the
//! same pipeline, which must serve exactly the same set (the fixed point).
//!
//! ## What this pins
//!
//! The per-operator tests pin H-20 (doors (a) edited record and (b) split
//! record), M-47 (half envelope), L-74 (stale read model), L-75 (hand parents
//! honoured verbatim), L-76 (raw copy replaces a quarantined signed record) and
//! L-77 (re-open adopted). They failed at HEAD `48665b8`, each naming the
//! served-but-refused id and the wire error, and T73 made them pass:
//! [`OPERATORS_ENABLED`] holds every operator and `boot_fuzz_all_operators`
//! runs each one under every check.
//!
//! ## A2 (0924 re-audit of T73)
//!
//! The pipeline now also installs the verifier `main.rs` installs right
//! after the signer, and runs `verify_own_history` before the compaction.
//! The `op_q`–`op_ab` operators probe what the signature covers (parents,
//! lamport, a duplicated envelope line), journal replay, the salvage of an
//! unparsable head, a pasted block signed by another peer, and the
//! compositions the 0924 hunt found: an edited own record plus a hand
//! append in the same session (A2-1), a foreign-author half envelope (A2-2),
//! a hand parent naming the quarantined id (A2-3) and a lamport edit that
//! moves the clock (A2-4). `boot_fuzz_all_operators_including_a2` sweeps
//! every green operator.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::NaiveDate;
use ledger::hash::compute_content_id;
use ledger::journal::{append_record, journal_path_for};
use ledger::model::{Amount, Directive, Flag, Transaction};
use ledger::parse::parse_file;
use ledger::read_model::CurrencyBalances;
use ledger::service::{
    DirectiveSigner, DirectiveVerifier, LedgerService, PostingInput, TransactionInput,
};
use p2p::allowlist::PeerAllowlist;
use p2p::gossip::make_supply_entry;
use p2p::protocol::SupplyEntry;
use p2p::union_merge::{validate_supply_entry, verify_author_allowlisted, verify_remote_signature};
use proptest::prelude::*;
use rust_decimal::Decimal;
use security::signing::{PeerKeySignatureProvider, SignableMessage, SignatureProvider};
use sha2::{Digest, Sha256};

// ─── Constants ───────────────────────────────────────────────────────────────

/// The mesh id every signature in this harness is bound to (L-23).
const MESH_ID: &str = "mesh-bootfuzz";

/// Accounts the fixture opens, with their currency constraints.
const ACCOUNTS: [(&str, &[&str]); 5] = [
    ("Assets:Cash", &["USD"]),
    ("Equity:Opening", &[]),
    ("Expenses:Food", &[]),
    ("Expenses:Rent", &[]),
    ("Expenses:Travel", &[]),
];

const EXPENSE_ACCOUNTS: [&str; 3] = ["Expenses:Food", "Expenses:Rent", "Expenses:Travel"];
const WORDS: [&str; 8] = [
    "coffee",
    "groceries",
    "taxi",
    "lunch",
    "rent",
    "train",
    "dinner",
    "stationery",
];
const PAYEES: [&str; 4] = ["Corner Shop", "Metro", "Landlord", "Cafe Zed"];

/// A hand-typed parent that exists nowhere (L-75's shape).
const NOWHERE_PARENT: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Envelope keys, spelled once.
const KEY_AUTHOR: &str = "openledger-author";
const KEY_LAMPORT: &str = "openledger-lamport";
const KEY_PARENTS: &str = "openledger-parents";
const KEY_SIGNATURE: &str = "openledger-signature";

// ─── Deterministic RNG (no `rand` dependency needed) ─────────────────────────

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng((seed ^ 0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

// ─── Scratch paths ───────────────────────────────────────────────────────────

static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn fresh_dir(label: &str) -> PathBuf {
    let count = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "openledger-bootfuzz-{}-{nanos}-{count}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ymd(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).unwrap()
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

// ─── Signer plumbing ─────────────────────────────────────────────────────────

fn signer_for(provider: &Arc<PeerKeySignatureProvider>) -> DirectiveSigner {
    let provider = Arc::clone(provider);
    Arc::new(
        move |content_id: &str, is_transaction: bool, parents: &str, lamport: &str| {
            provider.sign(&SignableMessage {
                content_id,
                is_transaction,
                parents,
                lamport,
            })
        },
    )
}

/// The verifier `main.rs` installs right after the signer: the wire's
/// `verify_signature` over the same message and the same mesh id (A2).
fn verifier() -> DirectiveVerifier {
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
                MESH_ID,
            )
            .is_ok()
        },
    )
}

/// A second, allowlisted peer of the same mesh, derived from the fixture's
/// author so a case is reproducible from its seed (A2).
fn foreign_provider(truth: &Truth) -> Arc<PeerKeySignatureProvider> {
    let mut key = [0u8; 32];
    for (slot, byte) in key.iter_mut().zip(truth.author.as_bytes()) {
        *slot = byte ^ 0x5a;
    }
    Arc::new(PeerKeySignatureProvider::from_bytes(
        &key,
        MESH_ID.to_owned(),
    ))
}

fn sign_kind(
    provider: &Arc<PeerKeySignatureProvider>,
    is_transaction: bool,
) -> impl Fn(&str, &str, &str) -> Option<String> {
    let provider = Arc::clone(provider);
    move |content_id: &str, parents: &str, lamport: &str| {
        provider.sign(&SignableMessage {
            content_id,
            is_transaction,
            parents,
            lamport,
        })
    }
}

// ─── The truth: a node-written file and what a peer accepted from it ─────────

/// A canonical `.bean` the node itself wrote, and the served set a signing
/// peer accepted from it before the operator touched anything.
struct Truth {
    /// The canonical bytes the node wrote.
    text: String,
    author: String,
    provider: Arc<PeerKeySignatureProvider>,
    /// id → the `SupplyEntry` the node served (body + four-key envelope).
    entries: BTreeMap<String, SupplyEntry>,
    /// Signature value → id, to map a file block back to its record.
    ids_by_signature: BTreeMap<String, String>,
    balances: BTreeMap<String, CurrencyBalances>,
    /// Kept alive so the directory survives as long as the truth does.
    _dir: PathBuf,
}

fn random_transaction(rng: &mut Rng, date: NaiveDate, index: usize) -> TransactionInput {
    let legs = 1 + rng.below(3) as usize; // 2–4 postings
    let mut postings = Vec::new();
    let mut total = Decimal::ZERO;
    for leg in 0..legs {
        let cents = 100 + rng.below(9_900) as i64;
        let number = Decimal::new(cents, 2);
        total += number;
        postings.push(PostingInput {
            account: EXPENSE_ACCOUNTS[(index + leg) % EXPENSE_ACCOUNTS.len()].to_owned(),
            amount: Some(Amount {
                number,
                currency: "USD".to_owned(),
            }),
            cost: None,
            price: None,
        });
    }
    postings.push(PostingInput {
        account: "Assets:Cash".to_owned(),
        amount: Some(Amount {
            number: -total,
            currency: "USD".to_owned(),
        }),
        cost: None,
        price: None,
    });
    let word = *rng.pick(&WORDS);
    TransactionInput {
        date,
        flag: if rng.below(4) == 0 {
            Flag::Incomplete
        } else {
            Flag::Complete
        },
        payee: if rng.below(2) == 0 {
            Some((*rng.pick(&PAYEES)).to_owned())
        } else {
            None
        },
        narration: Some(format!("{word} {index}")),
        tags: if rng.below(3) == 0 {
            vec!["fuzz".to_owned()]
        } else {
            vec![]
        },
        links: if rng.below(3) == 0 {
            vec![format!("ref{index}")]
        } else {
            vec![]
        },
        postings,
    }
}

/// The hand-typed record every fixture carries, adopted through the boot
/// pipeline at generation time so the fixture also holds a record with body
/// metadata that the node signed as operator input.
const FIXTURE_HAND_RECORD: &str = "\n2024-01-28 * \"Hand\" \"typed with a note\"\n  note: \"operator input\"\n  Expenses:Food                                      5.00 USD\n  Assets:Cash                                       -5.00 USD\n";

/// Generate a node-written fixture from `seed`.
fn generate_fixture(seed: u64) -> Truth {
    let mut rng = Rng::new(seed);
    let dir = fresh_dir("fixture");
    let path = dir.join("ledger.bean");

    let mut key = [0u8; 32];
    for chunk in key.chunks_mut(8) {
        let bytes = rng.next().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    let provider = Arc::new(PeerKeySignatureProvider::from_bytes(
        &key,
        MESH_ID.to_owned(),
    ));
    let author = provider.public_key_hex();

    // The honest node authors its history through its own API.
    let mut svc = LedgerService::boot(path.clone(), author.clone()).unwrap();
    svc.set_signer(signer_for(&provider));
    let open_date = ymd(2024, 1, 1);
    for (account, currencies) in ACCOUNTS {
        svc.open_account_signing(
            account.to_owned(),
            open_date,
            currencies.iter().map(|c| (*c).to_owned()).collect(),
            sign_kind(&provider, false),
        )
        .unwrap();
    }
    let count = 3 + rng.below(4) as usize;
    let mut day = 2;
    for index in 0..count {
        day += 1 + rng.below(3) as u32;
        let input = random_transaction(&mut rng, ymd(2024, 1, day), index);
        svc.append_transaction_signing(input, sign_kind(&provider, true))
            .unwrap();
    }
    svc.close_account_signing(
        "Expenses:Travel".to_owned(),
        ymd(2024, 2, 1),
        sign_kind(&provider, false),
    )
    .unwrap();
    svc.compact().unwrap();
    drop(svc);

    // One hand-typed record with body metadata, adopted, signed and written by
    // the node's own boot pipeline — so it too is node-written history.
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str(FIXTURE_HAND_RECORD);
    std::fs::write(&path, text).unwrap();
    let svc = run_pipeline(&path, &provider).expect("fixture pipeline");
    drop(svc);

    // The truth is what the honest node serves from its own canonical file.
    let text = std::fs::read_to_string(&path).unwrap();
    let svc = LedgerService::boot(path.clone(), author.clone()).unwrap();
    assert_eq!(
        svc.unsigned_operator_input_count(),
        0,
        "fixture is canonical"
    );
    assert_eq!(svc.quarantined_count(), 0, "fixture is clean");
    let mut entries = BTreeMap::new();
    let mut ids_by_signature = BTreeMap::new();
    for id in svc.all_directive_ids() {
        let directive = svc.get_directive(&id).unwrap();
        let entry = make_supply_entry(directive);
        assert_eq!(entry.id, id);
        let signature = entry
            .envelope
            .get(KEY_SIGNATURE)
            .unwrap_or_else(|| panic!("fixture record {id} is unsigned"))
            .clone();
        ids_by_signature.insert(signature, id.clone());
        entries.insert(id, entry);
    }
    let balances = balances_of(&svc);
    let truth = Truth {
        text,
        author,
        provider,
        entries,
        ids_by_signature,
        balances,
        _dir: dir,
    };
    // A fixture must pass its own oracle, or the harness is broken.
    let snapshot = snapshot_of(&svc);
    let failures = audit(&snapshot, &truth, &Effect::default(), Checks::ALL);
    assert!(
        failures.is_empty(),
        "fixture fails its own oracle: {failures:#?}"
    );
    truth
}

// ─── The pipeline under test (mirrors gl-node main.rs) ───────────────────────

fn run_pipeline(
    path: &Path,
    provider: &Arc<PeerKeySignatureProvider>,
) -> Result<LedgerService, String> {
    run_pipeline_until(path, provider, true)
}

/// [`run_pipeline`], optionally stopping before the startup compaction — the
/// crash window between `finalize_operator_input` and the rewrite (A2).
fn run_pipeline_until(
    path: &Path,
    provider: &Arc<PeerKeySignatureProvider>,
    compact: bool,
) -> Result<LedgerService, String> {
    let mut svc = LedgerService::boot(path.to_path_buf(), "local".to_owned())
        .map_err(|error| format!("boot refused the file: {error}"))?;
    svc.set_author_id(provider.public_key_hex());
    svc.set_signer(signer_for(provider));
    // A2: `main.rs` installs the verifier right after the signer (signing is
    // on), so a foreign-authored record is judged by its author's key.
    svc.set_verifier(verifier());
    if svc.unsigned_operator_input_count() > 0 {
        svc.finalize_operator_input();
    }
    svc.verify_own_history();
    if compact {
        svc.compact()
            .map_err(|error| format!("startup compaction failed: {error}"))?;
    }
    Ok(svc)
}

// ─── Snapshot of what a booted node serves ───────────────────────────────────

struct Snapshot {
    served: BTreeMap<String, Directive>,
    quarantined_ids: BTreeSet<String>,
    quarantined_count: usize,
    /// `journal`-style listing: txid → the read model's copy.
    journal: BTreeMap<String, Transaction>,
    balances: BTreeMap<String, CurrencyBalances>,
}

fn balances_of(svc: &LedgerService) -> BTreeMap<String, CurrencyBalances> {
    ACCOUNTS
        .iter()
        .map(|(account, _)| {
            let balances = svc
                .read_model()
                .account_balance(account, None)
                .map(|entry| entry.balances)
                .unwrap_or_default();
            ((*account).to_owned(), balances)
        })
        .collect()
}

fn snapshot_of(svc: &LedgerService) -> Snapshot {
    let served = svc
        .all_directive_ids()
        .into_iter()
        .map(|id| {
            let directive = svc.get_directive(&id).unwrap().clone();
            (id, directive)
        })
        .collect();
    let journal = svc
        .read_model()
        .journal(None, None, None, usize::MAX, 0)
        .into_iter()
        .map(|indexed| (indexed.txid.clone(), indexed.transaction.clone()))
        .collect();
    Snapshot {
        served,
        quarantined_ids: svc
            .quarantined_ids()
            .into_iter()
            .map(str::to_owned)
            .collect(),
        quarantined_count: svc.quarantined_count(),
        journal,
        balances: balances_of(svc),
    }
}

impl Snapshot {
    fn entries(&self) -> BTreeMap<String, SupplyEntry> {
        self.served
            .iter()
            .map(|(id, directive)| (id.clone(), make_supply_entry(directive)))
            .collect()
    }
}

// ─── The oracle ──────────────────────────────────────────────────────────────

/// What a mutation did to the node-written records, so the oracle knows which
/// ones must survive untouched.
#[derive(Default, Clone, Debug)]
struct Effect {
    /// Truth ids whose block the mutation edited in place.
    touched: Vec<String>,
    /// Truth ids whose block the mutation removed entirely.
    deleted: Vec<String>,
}

/// Which optional checks run. Everything else always runs.
#[derive(Clone, Copy, Debug)]
struct Checks {
    /// L-74: the read model (`journal`) must agree with `get_directive` on the
    /// envelope of every served transaction. Failed at HEAD for every operator
    /// that adopts operator input; T73 re-indexes the finalised copy.
    read_model_parity: bool,
}

impl Checks {
    const ALL: Checks = Checks {
        read_model_parity: true,
    };
}

fn envelope_summary(directive: &Directive) -> String {
    let metadata = directive.metadata();
    let get = |key: &str| {
        metadata
            .get(key)
            .map(|value| short(value).to_owned())
            .unwrap_or_else(|| "-".to_owned())
    };
    format!(
        "author={} lamport={} parents={} signature={}",
        get(KEY_AUTHOR),
        get(KEY_LAMPORT),
        get(KEY_PARENTS),
        get(KEY_SIGNATURE)
    )
}

/// The peer's view of one served record: the real wire validators, the DAG
/// parent rule and I1.
fn peer_would_accept(
    id: &str,
    directive: &Directive,
    known_ids: &BTreeSet<String>,
    allowlist: &PeerAllowlist,
) -> Result<(), String> {
    let entry = make_supply_entry(directive);
    if entry.id != id {
        return Err(format!(
            "served under id {} but its body hashes to {}",
            short(id),
            short(&entry.id)
        ));
    }
    validate_supply_entry(&entry).map_err(|error| format!("validate_supply_entry: {error}"))?;
    verify_remote_signature(directive, true, MESH_ID)
        .map_err(|error| format!("verify_remote_signature: {error}"))?;
    verify_author_allowlisted(directive, allowlist)
        .map_err(|error| format!("verify_author_allowlisted: {error}"))?;
    if let Directive::Transaction(txn) = directive {
        for parent in txn.parent_ids() {
            if !known_ids.contains(parent) {
                return Err(format!(
                    "DAG: names parent {} that exists nowhere (L-75 shape)",
                    short(parent)
                ));
            }
        }
        let mut sums: BTreeMap<&str, Decimal> = BTreeMap::new();
        for posting in &txn.postings {
            let Some(amount) = &posting.amount else {
                return Err("I1: an elided posting is served unresolved".to_owned());
            };
            *sums.entry(amount.currency.as_str()).or_default() += amount.number;
        }
        for (currency, sum) in sums {
            if !sum.is_zero() {
                return Err(format!(
                    "I1: {} postings sum to {sum} {currency}",
                    txn.postings.len()
                ));
            }
        }
    }
    Ok(())
}

/// Replay the records the node adopted (ids not in the truth) through a
/// replica's local API: what the file path adopts, the API must accept too.
fn replay_through_local_api(snapshot: &Snapshot, truth: &Truth) -> Vec<String> {
    let mut new_records: Vec<(&String, &Directive)> = snapshot
        .served
        .iter()
        .filter(|(id, _)| !truth.entries.contains_key(*id))
        .collect();
    if new_records.is_empty() {
        return Vec::new();
    }
    new_records.sort_by_key(|(id, directive)| (directive.date(), directive.type_priority(), *id));

    let dir = fresh_dir("replica");
    let path = dir.join("ledger.bean");
    std::fs::write(&path, &truth.text).unwrap();
    let mut replica = LedgerService::boot(path, truth.author.clone()).unwrap();
    let mut failures = Vec::new();
    for (id, directive) in new_records {
        let result = match directive {
            Directive::Open(open) => replica
                .open_account(open.account.clone(), open.date, open.currencies.clone())
                .map(|_| ()),
            Directive::Close(close) => replica
                .close_account(close.account.clone(), close.date)
                .map(|_| ()),
            Directive::Transaction(txn) => replica
                .append_transaction(TransactionInput {
                    date: txn.date,
                    flag: txn.flag,
                    payee: txn.payee.clone(),
                    narration: txn.narration.clone(),
                    tags: txn.tags.clone(),
                    links: txn.links.clone(),
                    postings: txn
                        .postings
                        .iter()
                        .map(|posting| PostingInput {
                            account: posting.account.clone(),
                            amount: posting.amount.clone(),
                            cost: posting.cost.clone(),
                            price: posting.price.clone(),
                        })
                        .collect(),
                })
                .map(|_| ()),
            _ => Ok(()),
        };
        if let Err(error) = result {
            failures.push(format!(
                "adopted record {} that the local API refuses: {error} ({})",
                short(id),
                envelope_summary(directive)
            ));
        }
    }
    std::fs::remove_dir_all(dir).ok();
    failures
}

/// The invariant, as a list of violations (empty = holds).
fn audit(snapshot: &Snapshot, truth: &Truth, effect: &Effect, checks: Checks) -> Vec<String> {
    audit_with(snapshot, truth, effect, checks, &[])
}

/// [`audit`] under a peer whose allowlist also holds `extra_authors`: a block
/// signed by another allowlisted peer of the mesh must be accepted (A2).
fn audit_with(
    snapshot: &Snapshot,
    truth: &Truth,
    effect: &Effect,
    checks: Checks,
    extra_authors: &[String],
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut authors = vec![truth.author.clone()];
    authors.extend(extra_authors.iter().cloned());
    let allowlist = PeerAllowlist::parse(&authors).expect("authors are EndpointIds");

    // A parent is resolvable on a peer if the node serves it or the mesh
    // already holds it (the truth): a deleted line is re-supplied by peers.
    let known_ids: BTreeSet<String> = snapshot
        .served
        .keys()
        .chain(truth.entries.keys())
        .cloned()
        .collect();

    // 1. Everything served is peer-acceptable.
    for (id, directive) in &snapshot.served {
        if let Err(error) = peer_would_accept(id, directive, &known_ids, &allowlist) {
            failures.push(format!(
                "served-but-refused {}: {error} ({})",
                short(id),
                envelope_summary(directive)
            ));
        }
    }

    // 2. Unmodified node-written records survive with their original id and
    //    envelope (or sit in the quarantine, still on disk).
    for (id, entry) in &truth.entries {
        if effect.deleted.contains(id) || effect.touched.contains(id) {
            continue;
        }
        match snapshot.served.get(id) {
            Some(directive) => {
                let now = make_supply_entry(directive);
                if now.envelope != entry.envelope {
                    failures.push(format!(
                        "node-written record {} is served with a changed envelope: was {:?}, now {:?}",
                        short(id),
                        summarise_envelope(&entry.envelope),
                        summarise_envelope(&now.envelope)
                    ));
                }
                if now.economic_bean != entry.economic_bean {
                    failures.push(format!(
                        "node-written record {} is served with a changed body",
                        short(id)
                    ));
                }
            }
            None if snapshot.quarantined_ids.contains(id) => {}
            None => failures.push(format!(
                "node-written record {} vanished: not served, not quarantined",
                short(id)
            )),
        }
    }

    // 3. An edited record is served under its id, or something was quarantined
    //    — it never leaves the served set silently (the H-20 signal).
    for id in &effect.touched {
        let present = snapshot.served.contains_key(id) || snapshot.quarantined_ids.contains(id);
        if !present && snapshot.quarantined_count == 0 {
            failures.push(format!(
                "edited record {} left the served set silently: not served, nothing quarantined",
                short(id)
            ));
        }
    }

    // 4. What the file path adopted, the local API would have accepted.
    failures.extend(replay_through_local_api(snapshot, truth));

    // 5. L-74: the read model and the DAG agree on every served transaction.
    if checks.read_model_parity {
        for (id, directive) in &snapshot.served {
            let Directive::Transaction(dag_copy) = directive else {
                continue;
            };
            match snapshot.journal.get(id) {
                None => failures.push(format!(
                    "served transaction {} is absent from the journal listing",
                    short(id)
                )),
                Some(journal_copy) => {
                    for key in [KEY_AUTHOR, KEY_LAMPORT, KEY_PARENTS, KEY_SIGNATURE] {
                        if journal_copy.metadata.get(key) != dag_copy.metadata.get(key) {
                            failures.push(format!(
                                "journal and get_directive disagree on {} {key}: journal={:?} dag={:?} (L-74)",
                                short(id),
                                journal_copy.metadata.get(key).map(|v| short(v)),
                                dag_copy.metadata.get(key).map(|v| short(v))
                            ));
                        }
                    }
                }
            }
        }
        for id in snapshot.journal.keys() {
            if !snapshot.served.contains_key(id) {
                failures.push(format!("journal lists {} which is not served", short(id)));
            }
        }
    }

    failures
}

fn summarise_envelope(envelope: &BTreeMap<String, String>) -> BTreeMap<&str, String> {
    envelope
        .iter()
        .map(|(key, value)| (key.as_str(), short(value).to_owned()))
        .collect()
}

/// The reboot must serve exactly what the first boot served.
fn fixed_point(first: &Snapshot, second: &Snapshot) -> Vec<String> {
    let mut failures = Vec::new();
    let (a, b) = (first.entries(), second.entries());
    for id in a.keys().filter(|id| !b.contains_key(*id)) {
        failures.push(format!(
            "fixed point: {} served after the first boot but not after the reboot",
            short(id)
        ));
    }
    for id in b.keys().filter(|id| !a.contains_key(*id)) {
        failures.push(format!(
            "fixed point: {} served after the reboot but not after the first boot ({})",
            short(id),
            envelope_summary(&second.served[id])
        ));
    }
    for (id, entry) in &a {
        if let Some(other) = b.get(id) {
            if entry != other {
                failures.push(format!(
                    "fixed point: {} changed envelope or body across the reboot",
                    short(id)
                ));
            }
        }
    }
    if first.quarantined_ids != second.quarantined_ids {
        failures.push(format!(
            "fixed point: quarantine changed across the reboot: {:?} -> {:?}",
            first
                .quarantined_ids
                .iter()
                .map(|id| short(id))
                .collect::<Vec<_>>(),
            second
                .quarantined_ids
                .iter()
                .map(|id| short(id))
                .collect::<Vec<_>>()
        ));
    }
    if first.balances != second.balances {
        failures.push(format!(
            "fixed point: balances changed across the reboot: {:?} -> {:?}",
            first.balances, second.balances
        ));
    }
    failures
}

// ─── File-text helpers ───────────────────────────────────────────────────────

/// Blocks of a canonical file, each without its trailing newline.
fn split_blocks(text: &str) -> Vec<String> {
    text.split("\n\n")
        .map(|block| block.trim_end_matches('\n').to_owned())
        .filter(|block| !block.is_empty())
        .collect()
}

fn join_blocks(blocks: &[String]) -> String {
    let mut text = blocks.join("\n\n");
    text.push('\n');
    text
}

fn is_transaction_block(block: &str) -> bool {
    let header = block.lines().next().unwrap_or("").as_bytes();
    header.len() > 11 && header[10] == b' ' && matches!(header[11], b'*' | b'!')
}

fn is_signed_block(block: &str) -> bool {
    block
        .lines()
        .any(|line| line.trim_start().starts_with(KEY_SIGNATURE))
}

fn envelope_value(block: &str, key: &str) -> Option<String> {
    block.lines().find_map(|line| {
        let trimmed = line.trim_start();
        let rest = trimmed.strip_prefix(key)?.strip_prefix(": \"")?;
        Some(rest.trim_end_matches('"').to_owned())
    })
}

/// Line indices (within the block) of the posting lines.
fn posting_lines(block: &str) -> Vec<usize> {
    block
        .lines()
        .enumerate()
        .filter(|(index, line)| {
            *index > 0
                && line.starts_with("  ")
                && line
                    .trim_start()
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_uppercase())
        })
        .map(|(index, _)| index)
        .collect()
}

fn set_lines(block: &str, edit: impl FnOnce(&mut Vec<String>)) -> String {
    let mut lines: Vec<String> = block.lines().map(str::to_owned).collect();
    edit(&mut lines);
    lines.join("\n")
}

/// `prefix NUMBER CURRENCY` → the same line with `NUMBER + delta`.
fn shift_amount(line: &str, delta: Decimal) -> Option<String> {
    let (head, currency) = line.rsplit_once(' ')?;
    let (prefix, number) = head.rsplit_once(' ')?;
    let number: Decimal = number.parse().ok()?;
    Some(format!("{prefix} {} {currency}", number + delta))
}

fn strip_envelope(block: &str) -> String {
    set_lines(block, |lines| {
        lines.retain(|line| !line.trim_start().starts_with("openledger-"));
    })
}

/// The truth id of a signed block, by its signature.
fn truth_id_of(truth: &Truth, block: &str) -> Option<String> {
    let signature = envelope_value(block, KEY_SIGNATURE)?;
    truth.ids_by_signature.get(&signature).cloned()
}

// ─── Mutation operators ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operator {
    /// (a) edit the narration of a signed transaction.
    EditNarration,
    /// (b) edit an amount of a signed transaction on two legs (still balanced).
    EditAmountBalanced,
    /// (b') edit one amount only (unbalanced).
    EditAmountUnbalanced,
    /// (c) dedent one posting line of a signed transaction.
    DedentPosting,
    /// (d) a BOM glued to the front of a posting line.
    BomBeforePosting,
    /// (e) a stray word line inside a signed block.
    StrayWordLine,
    /// (f) delete the `openledger-lamport` line (half envelope).
    DeleteLamportLine,
    /// (g) delete the `openledger-author` line (half envelope).
    DeleteAuthorLine,
    /// (h) delete the `openledger-signature` line.
    DeleteSignatureLine,
    /// (i) append an envelope-less hand transaction (honest operator input).
    AppendHandTransaction,
    /// (j) append an envelope-less `open` of an already-open account.
    AppendReopen,
    /// (k) append a hand transaction with hand-typed parents naming nothing.
    AppendHandTransactionDanglingParent,
    /// (l0) duplicate a signed transaction block as an envelope-less copy.
    DuplicateSignedBlockRaw,
    /// (l) the L-76 shape: a signed record quarantined by the cycle arm, plus
    /// an envelope-less copy of it appended.
    DuplicateRawOfCycleMember,
    /// (m) delete a whole signed block.
    DeleteSignedBlock,
    /// (n) CRLF line endings.
    Crlf,
    /// (o) a BOM at offset 0.
    LeadingBom,
    /// (p) identity (control).
    Identity,
    // ── A2 (0924 re-audit) ──
    /// (q) edit the `openledger-parents` line of a signed transaction — a
    /// signed field, so the record must be quarantined.
    EditParentsLine,
    /// (r) edit the `openledger-lamport` line of a signed transaction (+1).
    EditLamportLine,
    /// (s) duplicate the lamport line: the original spelling, then an edited
    /// one — the parser keeps the LAST spelling, which is the edited value.
    DuplicateLamportLineEdited,
    /// (t) the commit journal holds an edited copy of a signed record under
    /// a recomputed checksum; the `.bean` is untouched.
    JournalEditedCopy,
    /// (u) a stray word right after the header line: the head is the bare
    /// header (0 postings, no envelope), the tail unparsable.
    StrayWordAfterHeader,
    /// (v) a block signed by another allowlisted peer of the mesh, pasted in.
    PasteSignedForeignBlock,
    /// (w) the same block with a forged signature.
    PasteForgedForeignBlock,
    /// (x) A2-1: an edited signed record plus a hand-appended transaction in
    /// the same stop → edit → start session.
    EditNarrationPlusAppendHand,
    /// (y) A2-1 by paste: a hand header pasted between the envelope and the
    /// postings of a signed block (no blank line).
    PasteHeaderInsideSignedBlock,
    /// (z) A2-3: a hand transaction whose hand-typed parent is the id the
    /// edited record is quarantined under.
    AppendHandTransactionQuarantinedParent,
    /// (aa) A2-2: a hand transaction carrying `openledger-author: <another
    /// allowlisted peer>` and no lamport.
    ForeignAuthorHalfEnvelope,
    /// (ab) A2-4: the lamport line of a signed record edited to a value near
    /// 2^32.
    EditLamportLineHuge,
}

/// Every operator that is green at HEAD `3d64a16`: [`OPERATORS_ENABLED`] plus
/// the A2 operators that pin an existing mechanism. The four finding-pinning
/// operators (x, y, z, aa) and (ab) are excluded — their tests are
/// `#[ignore]`d with the finding id.
const OPERATORS_ALL: [Operator; 25] = [
    Operator::EditNarration,
    Operator::EditAmountBalanced,
    Operator::EditAmountUnbalanced,
    Operator::DedentPosting,
    Operator::BomBeforePosting,
    Operator::StrayWordLine,
    Operator::DeleteLamportLine,
    Operator::DeleteAuthorLine,
    Operator::DeleteSignatureLine,
    Operator::AppendHandTransaction,
    Operator::AppendReopen,
    Operator::AppendHandTransactionDanglingParent,
    Operator::DuplicateSignedBlockRaw,
    Operator::DuplicateRawOfCycleMember,
    Operator::DeleteSignedBlock,
    Operator::Crlf,
    Operator::LeadingBom,
    Operator::Identity,
    Operator::EditParentsLine,
    Operator::EditLamportLine,
    Operator::DuplicateLamportLineEdited,
    Operator::JournalEditedCopy,
    Operator::StrayWordAfterHeader,
    Operator::PasteSignedForeignBlock,
    Operator::PasteForgedForeignBlock,
];

/// A signed foreign block: the body signed by `provider` over parents `""`
/// and lamport `"1"`, as a peer's genesis-era transaction would be (A2).
fn signed_foreign_block(provider: &PeerKeySignatureProvider, forged: bool) -> String {
    let body = "2024-01-30 * \"Peer\" \"pasted from another node's ledger\"\n  Expenses:Rent                                     20.00 USD\n  Assets:Cash                                      -20.00 USD";
    let directive = parse_file(&format!("{body}\n"))
        .expect("foreign body parses")
        .remove(0);
    let id = compute_content_id(&directive);
    let mut signature = provider
        .sign(&SignableMessage {
            content_id: &id,
            is_transaction: true,
            parents: "",
            lamport: "1",
        })
        .expect("signing enabled");
    if forged {
        let flipped = if signature.starts_with('0') { '1' } else { '0' };
        signature.replace_range(0..1, &flipped.to_string());
    }
    set_lines(body, |lines| {
        lines.insert(
            1,
            format!("  {KEY_AUTHOR}: \"{}\"", provider.public_key_hex()),
        );
        lines.insert(2, format!("  {KEY_LAMPORT}: \"1\""));
        lines.insert(3, format!("  {KEY_PARENTS}: \"\""));
        lines.insert(4, format!("  {KEY_SIGNATURE}: \"{signature}\""));
    })
}

/// `;;olj <len> <sha256>\n<payload>` — the journal's record format, with the
/// checksum recomputed over the (edited) payload (A2).
fn journal_record(payload: &str) -> String {
    format!(
        ";;olj {} {:x}\n{payload}",
        payload.len(),
        Sha256::digest(payload.as_bytes())
    )
}

/// The narration edit of operator (a), as a helper for the compositions.
fn edit_narration(block: &str) -> String {
    set_lines(block, |lines| {
        let header = &lines[0];
        lines[0] = match header.rfind('"') {
            Some(quote) => format!("{} (edited){}", &header[..quote], &header[quote..]),
            None => format!("{} \"edited\"{}", &header[..12], &header[12..]),
        };
    })
}

/// What [`mutate`] produced: the file text, what it did to the node-written
/// records, an optional commit-journal record to write beside the file, and
/// the authors a peer's allowlist must also hold (A2).
struct Mutation {
    text: String,
    effect: Effect,
    journal: Option<String>,
    extra_authors: Vec<String>,
}

impl Mutation {
    fn text(text: String, effect: Effect) -> Self {
        Mutation {
            text,
            effect,
            journal: None,
            extra_authors: Vec::new(),
        }
    }
}

/// Every operator, under every check (T73: H-20 (a)–(e), (h); M-47 (f), (g);
/// L-74 (i); L-75 (k); L-76 (l); L-77 (j)). Nothing is gated any more.
const OPERATORS_ENABLED: [Operator; 18] = [
    Operator::EditNarration,
    Operator::EditAmountBalanced,
    Operator::EditAmountUnbalanced,
    Operator::DedentPosting,
    Operator::BomBeforePosting,
    Operator::StrayWordLine,
    Operator::DeleteLamportLine,
    Operator::DeleteAuthorLine,
    Operator::DeleteSignatureLine,
    Operator::AppendHandTransaction,
    Operator::AppendReopen,
    Operator::AppendHandTransactionDanglingParent,
    Operator::DuplicateSignedBlockRaw,
    Operator::DuplicateRawOfCycleMember,
    Operator::DeleteSignedBlock,
    Operator::Crlf,
    Operator::LeadingBom,
    Operator::Identity,
];

const HAND_TRANSACTION: &str = "2024-01-29 * \"Hand\" \"appended while the node was stopped\"\n  Expenses:Food                                      7.50 USD\n  Assets:Cash                                       -7.50 USD";

/// Apply `operator` to the node-written `text`; `position` picks the target
/// block/line. `None` means the operator does not apply to this fixture.
fn mutate(truth: &Truth, operator: Operator, position: usize) -> Option<Mutation> {
    let text = &truth.text;
    let mut blocks = split_blocks(text);
    let mut journal: Option<String> = None;
    let mut extra_authors: Vec<String> = Vec::new();
    let signed_txns: Vec<usize> = blocks
        .iter()
        .enumerate()
        .filter(|(_, block)| is_transaction_block(block) && is_signed_block(block))
        .map(|(index, _)| index)
        .collect();
    let signed_any: Vec<usize> = blocks
        .iter()
        .enumerate()
        .filter(|(_, block)| is_signed_block(block))
        .map(|(index, _)| index)
        .collect();
    let pick = |candidates: &[usize]| candidates[position % candidates.len()];

    let mut effect = Effect::default();
    let touch = |effect: &mut Effect, block: &str| {
        effect
            .touched
            .push(truth_id_of(truth, block).expect("signed block has a truth id"));
    };

    match operator {
        Operator::EditNarration => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            blocks[index] = set_lines(&blocks[index], |lines| {
                let header = &lines[0];
                lines[0] = match header.rfind('"') {
                    Some(quote) => format!("{} (edited){}", &header[..quote], &header[quote..]),
                    None => format!("{} \"edited\"{}", &header[..12], &header[12..]),
                };
            });
        }
        Operator::EditAmountBalanced | Operator::EditAmountUnbalanced => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            let postings = posting_lines(&blocks[index]);
            let balanced = operator == Operator::EditAmountBalanced;
            blocks[index] = set_lines(&blocks[index], |lines| {
                let first = postings[0];
                lines[first] = shift_amount(&lines[first], Decimal::ONE).expect("amount line");
                if balanced {
                    let last = *postings.last().unwrap();
                    lines[last] = shift_amount(&lines[last], -Decimal::ONE).expect("amount line");
                }
            });
        }
        Operator::DedentPosting | Operator::BomBeforePosting | Operator::StrayWordLine => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            let postings = posting_lines(&blocks[index]);
            let line = postings[position % postings.len()];
            blocks[index] = set_lines(&blocks[index], |lines| match operator {
                Operator::DedentPosting => lines[line] = lines[line].trim_start().to_owned(),
                Operator::BomBeforePosting => lines[line] = format!("\u{feff}{}", lines[line]),
                _ => lines.insert(line, "oops".to_owned()),
            });
        }
        Operator::DeleteLamportLine
        | Operator::DeleteAuthorLine
        | Operator::DeleteSignatureLine => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            let key = match operator {
                Operator::DeleteLamportLine => KEY_LAMPORT,
                Operator::DeleteAuthorLine => KEY_AUTHOR,
                _ => KEY_SIGNATURE,
            };
            blocks[index] = set_lines(&blocks[index], |lines| {
                lines.retain(|line| !line.trim_start().starts_with(key));
            });
        }
        Operator::AppendHandTransaction => blocks.push(HAND_TRANSACTION.to_owned()),
        Operator::AppendReopen => blocks.push("2024-01-01 open Assets:Cash EUR".to_owned()),
        Operator::AppendHandTransactionDanglingParent => blocks
            .push(set_lines(HAND_TRANSACTION, |lines| {
                lines.insert(1, format!("  {KEY_PARENTS}: \"{NOWHERE_PARENT}\""))
            })),
        Operator::DuplicateSignedBlockRaw => {
            let index = pick(&signed_txns);
            blocks.push(strip_envelope(&blocks[index]));
        }
        Operator::DuplicateRawOfCycleMember => {
            // T1 = a signed transaction; T2 = a later one that names T1 as a
            // parent (the fixture is a chain, so the next one does). Point
            // T1's parents at T2 — a cycle — and append a raw copy of T2.
            let slot = position % signed_txns.len();
            let (first, second) = signed_txns[slot..]
                .windows(2)
                .map(|pair| (pair[0], pair[1]))
                .find(|(t1, t2)| {
                    let t1_id = truth_id_of(truth, &blocks[*t1]).unwrap();
                    envelope_value(&blocks[*t2], KEY_PARENTS)
                        .is_some_and(|parents| parents.contains(&t1_id))
                })?;
            let t2_id = truth_id_of(truth, &blocks[second]).unwrap();
            touch(&mut effect, &blocks[first]);
            blocks[first] = set_lines(&blocks[first], |lines| {
                for line in lines.iter_mut() {
                    if line.trim_start().starts_with(KEY_PARENTS) {
                        *line = format!("  {KEY_PARENTS}: \"{t2_id}\"");
                    }
                }
            });
            blocks.push(strip_envelope(&blocks[second]));
        }
        Operator::DeleteSignedBlock => {
            let index = pick(&signed_any);
            effect
                .deleted
                .push(truth_id_of(truth, &blocks[index]).unwrap());
            blocks.remove(index);
        }
        Operator::Crlf => return Some(Mutation::text(text.replace('\n', "\r\n"), effect)),
        Operator::LeadingBom => return Some(Mutation::text(format!("\u{feff}{text}"), effect)),
        Operator::Identity => return Some(Mutation::text(text.clone(), effect)),
        // ── A2 ──
        Operator::EditParentsLine => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            blocks[index] = set_lines(&blocks[index], |lines| {
                for line in lines.iter_mut() {
                    if line.trim_start().starts_with(KEY_PARENTS) {
                        *line = format!("  {KEY_PARENTS}: \"{NOWHERE_PARENT}\"");
                    }
                }
            });
        }
        Operator::EditLamportLine | Operator::EditLamportLineHuge => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            let lamport: u64 = envelope_value(&blocks[index], KEY_LAMPORT)
                .expect("signed block has a lamport")
                .parse()
                .expect("decimal lamport");
            let value = if operator == Operator::EditLamportLine {
                lamport + 1
            } else {
                4_000_000_000
            };
            blocks[index] = set_lines(&blocks[index], |lines| {
                for line in lines.iter_mut() {
                    if line.trim_start().starts_with(KEY_LAMPORT) {
                        *line = format!("  {KEY_LAMPORT}: \"{value}\"");
                    }
                }
            });
        }
        Operator::DuplicateLamportLineEdited => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            let lamport: u64 = envelope_value(&blocks[index], KEY_LAMPORT)
                .expect("signed block has a lamport")
                .parse()
                .expect("decimal lamport");
            blocks[index] = set_lines(&blocks[index], |lines| {
                for line in lines.iter_mut() {
                    if line.trim_start().starts_with(KEY_LAMPORT) {
                        *line = format!("{line}\n  {KEY_LAMPORT}: \"{}\"", lamport + 1000);
                    }
                }
            });
        }
        Operator::JournalEditedCopy => {
            let index = pick(&signed_txns);
            let edited = edit_narration(&blocks[index]);
            journal = Some(journal_record(&format!("{edited}\n")));
            // The `.bean` is untouched; the record is edited in the journal.
        }
        Operator::StrayWordAfterHeader => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            blocks[index] = set_lines(&blocks[index], |lines| lines.insert(1, "oops".to_owned()));
        }
        Operator::PasteSignedForeignBlock | Operator::PasteForgedForeignBlock => {
            let provider = foreign_provider(truth);
            extra_authors.push(provider.public_key_hex());
            blocks.push(signed_foreign_block(
                &provider,
                operator == Operator::PasteForgedForeignBlock,
            ));
        }
        Operator::EditNarrationPlusAppendHand => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            blocks[index] = edit_narration(&blocks[index]);
            blocks.push(HAND_TRANSACTION.to_owned());
        }
        Operator::PasteHeaderInsideSignedBlock => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            let first_posting = posting_lines(&blocks[index])[0];
            blocks[index] = set_lines(&blocks[index], |lines| {
                lines.insert(
                    first_posting,
                    "2024-01-29 * \"Hand\" \"pasted without a blank line\"".to_owned(),
                )
            });
        }
        Operator::AppendHandTransactionQuarantinedParent => {
            let index = pick(&signed_txns);
            touch(&mut effect, &blocks[index]);
            blocks[index] = edit_narration(&blocks[index]);
            let quarantined_id = compute_content_id(
                &parse_file(&format!("{}\n", blocks[index]))
                    .expect("edited block parses")
                    .remove(0),
            );
            blocks.push(set_lines(HAND_TRANSACTION, |lines| {
                lines.insert(1, format!("  {KEY_PARENTS}: \"{quarantined_id}\""))
            }));
        }
        Operator::ForeignAuthorHalfEnvelope => {
            let provider = foreign_provider(truth);
            extra_authors.push(provider.public_key_hex());
            blocks.push(set_lines(HAND_TRANSACTION, |lines| {
                lines.insert(
                    1,
                    format!("  {KEY_AUTHOR}: \"{}\"", provider.public_key_hex()),
                )
            }));
        }
    }
    Some(Mutation {
        text: join_blocks(&blocks),
        effect,
        journal,
        extra_authors,
    })
}

// ─── One fuzz case ───────────────────────────────────────────────────────────

struct CaseReport {
    applied: bool,
    failures: Vec<String>,
    /// Ids adopted by the first boot that the truth did not hold.
    adopted: BTreeMap<String, Directive>,
    first: Option<Snapshot>,
}

fn run_case(truth: &Truth, operator: Operator, position: usize, checks: Checks) -> CaseReport {
    let Some(Mutation {
        text: mutated,
        effect,
        journal,
        extra_authors,
    }) = mutate(truth, operator, position)
    else {
        return CaseReport {
            applied: false,
            failures: Vec::new(),
            adopted: BTreeMap::new(),
            first: None,
        };
    };
    let dir = fresh_dir("case");
    let path = dir.join("ledger.bean");
    std::fs::write(&path, &mutated).unwrap();
    if let Some(record) = &journal {
        append_record(&journal_path_for(&path), record).expect("journal record written");
    }

    let mut failures = Vec::new();
    let mut adopted = BTreeMap::new();
    let mut first_snapshot = None;
    match run_pipeline(&path, &truth.provider) {
        Err(error) => failures.push(format!("first boot: {error}")),
        Ok(svc) => {
            let first = snapshot_of(&svc);
            drop(svc);
            failures.extend(
                audit_with(&first, truth, &effect, checks, &extra_authors)
                    .into_iter()
                    .map(|failure| format!("first boot: {failure}")),
            );
            adopted = first
                .served
                .iter()
                .filter(|(id, _)| !truth.entries.contains_key(*id))
                .map(|(id, directive)| (id.clone(), directive.clone()))
                .collect();
            match run_pipeline(&path, &truth.provider) {
                Err(error) => failures.push(format!("reboot: {error}")),
                Ok(svc) => {
                    let second = snapshot_of(&svc);
                    drop(svc);
                    failures.extend(
                        audit_with(&second, truth, &effect, checks, &extra_authors)
                            .into_iter()
                            .map(|failure| format!("reboot: {failure}")),
                    );
                    failures.extend(fixed_point(&first, &second));
                }
            }
            first_snapshot = Some(first);
        }
    }
    std::fs::remove_dir_all(dir).ok();
    CaseReport {
        applied: true,
        failures,
        adopted,
        first: first_snapshot,
    }
}

fn assert_holds(operator: Operator, seed: u64, position: usize, checks: Checks) -> CaseReport {
    let truth = generate_fixture(seed);
    let report = run_case(&truth, operator, position, checks);
    assert!(
        report.applied,
        "{operator:?} does not apply to fixture seed {seed}"
    );
    assert!(
        report.failures.is_empty(),
        "{operator:?} (seed {seed}, position {position}) breaks the boot invariant:\n  {}",
        report.failures.join("\n  ")
    );
    report
}

// ─── Per-operator tests (named failures) ─────────────────────────────────────

#[test]
fn op_a_edit_narration_of_signed_record() {
    assert_holds(Operator::EditNarration, 1, 0, Checks::ALL);
}

#[test]
fn op_b_edit_amount_balanced() {
    assert_holds(Operator::EditAmountBalanced, 2, 1, Checks::ALL);
}

#[test]
fn op_b_edit_amount_unbalanced() {
    assert_holds(Operator::EditAmountUnbalanced, 3, 2, Checks::ALL);
}

#[test]
fn op_c_dedent_posting() {
    // `position % postings` picks the dedented line; whichever it is, the head
    // fragment loses at least one leg and is loaded truncated (door (b)).
    assert_holds(Operator::DedentPosting, 4, 3, Checks::ALL);
}

#[test]
fn op_d_bom_before_posting() {
    assert_holds(Operator::BomBeforePosting, 5, 1, Checks::ALL);
}

#[test]
fn op_e_stray_word_line() {
    assert_holds(Operator::StrayWordLine, 6, 1, Checks::ALL);
}

#[test]
fn op_f_delete_lamport_line() {
    assert_holds(Operator::DeleteLamportLine, 7, 0, Checks::ALL);
}

#[test]
fn op_g_delete_author_line() {
    assert_holds(Operator::DeleteAuthorLine, 8, 1, Checks::ALL);
}

#[test]
fn op_h_delete_signature_line() {
    assert_holds(Operator::DeleteSignatureLine, 9, 2, Checks::ALL);
}

#[test]
fn op_i_append_hand_transaction_is_adopted_and_signed() {
    let report = assert_holds(Operator::AppendHandTransaction, 10, 0, Checks::ALL);
    assert_eq!(report.adopted.len(), 1, "exactly the hand record is new");
    let (id, directive) = report.adopted.iter().next().unwrap();
    let Directive::Transaction(txn) = directive else {
        panic!("the hand record is a transaction");
    };
    assert_eq!(
        txn.narration.as_deref(),
        Some("appended while the node was stopped")
    );
    let truth_author = generate_fixture(10).author;
    assert_eq!(txn.author(), Some(truth_author.as_str()), "{}", short(id));
    assert!(txn.signature().is_some(), "signed at finalize");
    assert!(txn.lamport_clock().is_some(), "stamped at boot");
}

#[test]
fn op_i_append_hand_transaction_read_model_agrees() {
    assert_holds(Operator::AppendHandTransaction, 10, 0, Checks::ALL);
}

#[test]
fn op_j_append_reopen_of_open_account() {
    assert_holds(Operator::AppendReopen, 11, 0, Checks::ALL);
}

#[test]
fn op_k_append_hand_transaction_with_dangling_parent() {
    assert_holds(
        Operator::AppendHandTransactionDanglingParent,
        12,
        0,
        Checks::ALL,
    );
}

#[test]
fn op_l0_duplicate_signed_block_raw_collapses_to_the_signed_copy() {
    let report = assert_holds(Operator::DuplicateSignedBlockRaw, 13, 1, Checks::ALL);
    assert!(report.adopted.is_empty(), "the raw copy is the same record");
}

#[test]
fn op_l_duplicate_raw_of_cycle_member() {
    assert_holds(Operator::DuplicateRawOfCycleMember, 14, 0, Checks::ALL);
}

#[test]
fn op_m_delete_signed_block_drops_only_that_record() {
    for position in 0..8 {
        let report = assert_holds(Operator::DeleteSignedBlock, 15, position, Checks::ALL);
        let first = report.first.unwrap();
        assert!(report.adopted.is_empty(), "position {position}");
        assert_eq!(first.quarantined_count, 0, "position {position}");
    }
}

#[test]
fn op_n_crlf_file() {
    let report = assert_holds(Operator::Crlf, 16, 0, Checks::ALL);
    assert_eq!(
        report.first.unwrap().balances,
        generate_fixture(16).balances
    );
}

#[test]
fn op_o_leading_bom() {
    let report = assert_holds(Operator::LeadingBom, 17, 0, Checks::ALL);
    assert_eq!(
        report.first.unwrap().balances,
        generate_fixture(17).balances
    );
}

#[test]
fn op_p_identity() {
    let truth = generate_fixture(18);
    let report = run_case(&truth, Operator::Identity, 0, Checks::ALL);
    assert!(report.failures.is_empty(), "{:#?}", report.failures);
    let first = report.first.unwrap();
    assert_eq!(first.entries(), truth.entries, "identity serves the truth");
    assert_eq!(first.balances, truth.balances);
}

// ─── A2 (0924 re-audit): what the signature covers, journal replay, salvage ──

/// The signature covers `openledger-parents`: an edited parents line on a
/// node-written record is quarantined, the record is not served.
///
/// Revert-proof: make the verifier arm of `verify_history_directive` (or the
/// `set_verifier`/`set_signer` passes) a no-op and the record is served with
/// a parent no peer resolves.
#[test]
fn op_q_edit_parents_line_of_signed_record_is_quarantined() {
    let report = assert_holds(Operator::EditParentsLine, 31, 1, Checks::ALL);
    assert_eq!(report.first.unwrap().quarantined_ids.len(), 1);
}

/// The signature covers `openledger-lamport`: an edited lamport line is
/// quarantined.
#[test]
fn op_r_edit_lamport_line_of_signed_record_is_quarantined() {
    let report = assert_holds(Operator::EditLamportLine, 32, 2, Checks::ALL);
    assert_eq!(report.first.unwrap().quarantined_ids.len(), 1);
}

/// A duplicated envelope line resolves last-wins in the parser
/// (`parse.rs` inserts into a `BTreeMap`), so "original, then edited" is the
/// edited value: the signature does not verify and the record is quarantined
/// rather than served under a lamport nobody signed.
#[test]
fn op_s_duplicated_lamport_line_resolves_to_the_last_spelling() {
    let report = assert_holds(Operator::DuplicateLamportLineEdited, 33, 0, Checks::ALL);
    assert_eq!(report.first.unwrap().quarantined_ids.len(), 1);
}

/// A record replayed from the commit journal takes the same loop as the
/// `.bean` (canonical ∪ journal is one text), so an edited copy with a
/// recomputed checksum is verified and quarantined; the canonical record is
/// served; the compaction folds the journal and the reboot is a fixed point.
///
/// Revert-proof: a no-op verify pass serves the journal copy under a new id
/// with the old signature.
#[test]
fn op_t_journal_edited_copy_is_verified_and_quarantined() {
    let report = assert_holds(Operator::JournalEditedCopy, 34, 1, Checks::ALL);
    assert!(report.adopted.is_empty(), "nothing new is served");
    assert_eq!(report.first.unwrap().quarantined_ids.len(), 1);
}

/// A stray word right after the header line leaves a head that is the bare
/// header (a 0-posting, envelope-less transaction) and an unparsable tail:
/// the salvage demotes the head into the same raw block, nothing is adopted.
///
/// Revert-proof: drop the demotion in `salvage_unparsable_blocks` and the
/// bare header is adopted as operator input — a 0-posting transaction
/// signed by this node.
#[test]
fn op_u_stray_word_after_header_holds_the_block_whole() {
    let report = assert_holds(Operator::StrayWordAfterHeader, 35, 0, Checks::ALL);
    assert!(report.adopted.is_empty(), "the bare header is not adopted");
    let first = report.first.unwrap();
    assert_eq!(
        first.quarantined_ids.len(),
        0,
        "held as raw text, not by id"
    );
    assert_eq!(first.quarantined_count, 1);
}

/// A block signed by another allowlisted peer, pasted in, is verified with
/// its author's key and served untouched: the pipeline installs the
/// verifier as `main.rs` does.
#[test]
fn op_v_pasted_block_signed_by_another_allowlisted_peer_is_served() {
    let truth = generate_fixture(36);
    let foreign = foreign_provider(&truth).public_key_hex();
    let report = run_case(&truth, Operator::PasteSignedForeignBlock, 0, Checks::ALL);
    assert!(report.failures.is_empty(), "{:#?}", report.failures);
    assert_eq!(report.adopted.len(), 1);
    let (_, directive) = report.adopted.iter().next().unwrap();
    assert_eq!(
        directive.metadata().get(KEY_AUTHOR),
        Some(&foreign),
        "served under the peer's authorship"
    );
}

/// The same block with a forged signature is quarantined by the verifier —
/// the author id is the key.
///
/// Revert-proof: remove `set_verifier` from the pipeline (or make the
/// verifier arm a no-op) and the forged block is served as loaded.
#[test]
fn op_w_pasted_block_with_a_forged_signature_is_quarantined() {
    let report = assert_holds(Operator::PasteForgedForeignBlock, 37, 0, Checks::ALL);
    assert!(report.adopted.is_empty());
    assert_eq!(report.first.unwrap().quarantined_ids.len(), 1);
}

/// H-22 (0924 A2-1), closed by T79: the operator fixes a typo in a line the
/// node wrote AND appends a transaction in the same stop → edit → start
/// session. Boot adopts the hand record with parents = the heads it sees,
/// which include the edited record's new id; `set_signer` then quarantines
/// that id. Before T79 finalize signed the hand record over that parent,
/// which no peer will ever hold, and every peer refused it and everything
/// this node authored afterwards; the quarantine rebuild now re-chooses its
/// parents from what survives, before it is signed.
#[test]
fn op_x_edited_record_plus_hand_append_in_one_session() {
    assert_holds(Operator::EditNarrationPlusAppendHand, 38, 0, Checks::ALL);
}

/// H-22 by paste (0924 A2-1), closed by T79: a hand header pasted between
/// the envelope and the postings of a signed block. The head (header +
/// envelope, 0 postings) is quarantined by the verify pass; the tail (the
/// hand header + the original's postings) was adopted with the quarantined
/// head as its parent, and is now re-parented onto what survives.
#[test]
fn op_y_hand_header_pasted_inside_a_signed_block() {
    assert_holds(Operator::PasteHeaderInsideSignedBlock, 39, 1, Checks::ALL);
}

/// H-22's second door (0924 A2-3), closed by T79: L-75 resolved a hand-typed
/// parent in DAG ∪ quarantine. An edited own record is quarantined under a
/// new id that no peer holds; a hand line naming it was adopted, signed and
/// served, and orphaned on every peer. A hand parent must now be a record
/// this node serves, so the line is quarantined with its parent.
#[test]
fn op_z_hand_parent_naming_the_quarantined_id() {
    assert_holds(
        Operator::AppendHandTransactionQuarantinedParent,
        40,
        0,
        Checks::ALL,
    );
}

/// M-54 (0924 A2-2), closed by T79: a hand transaction with
/// `openledger-author: <another allowlisted peer>` and no lamport is operator
/// input (M-47). Before T79 it was stamped, kept under the foreign author,
/// unsigned (T41 warn-and-adopt) and served as a head; every peer refused it
/// (`EnvelopeMissing(openledger-signature)`) and the node's next write named
/// it. It is now quarantined as written at finalisation.
#[test]
fn op_aa_foreign_author_half_envelope_is_served_unsigned() {
    assert_holds(Operator::ForeignAuthorHalfEnvelope, 41, 0, Checks::ALL);
}

/// A2-4: a lamport line of an own record edited to 4,000,000,000 is
/// quarantined by the verify pass, yet the clock boot folded from it stays:
/// the node's next write carries ~2^32 and the mesh follows (T72's
/// "far above" WARN fires on every later boot).
#[test]
#[ignore = "A2-4: an own record's edited lamport moves the clock although the record is quarantined"]
fn op_ab_huge_lamport_edit_of_a_quarantined_record_does_not_move_the_clock() {
    let truth = generate_fixture(42);
    let mutation = mutate(&truth, Operator::EditLamportLineHuge, 0).unwrap();
    let dir = fresh_dir("huge");
    let path = dir.join("ledger.bean");
    std::fs::write(&path, &mutation.text).unwrap();
    let svc = run_pipeline(&path, &truth.provider).unwrap();
    assert_eq!(
        svc.quarantined_ids().len(),
        1,
        "the edited record is quarantined"
    );
    let clock = svc.lamport_clock();
    drop(svc);
    std::fs::remove_dir_all(dir).ok();
    assert!(
        clock < 4_000_000_000,
        "the clock ({clock}) follows a lamport the node never served"
    );
}

/// A crash between `finalize_operator_input` and the startup compaction,
/// with a quarantined own record beside the hand record: the next boot
/// derives a byte-identical envelope (same lamport, same parents, same
/// signature), and a second `finalize_operator_input` is a no-op. The
/// 0923 §9 claim, re-checked now that `set_author_id` (T78) may shift
/// lamports and the verify pass may shrink the DAG.
#[test]
fn composite_crash_between_finalize_and_compaction_is_byte_identical() {
    let truth = generate_fixture(43);
    let mutation = mutate(&truth, Operator::EditNarrationPlusAppendHand, 0).unwrap();
    let dir = fresh_dir("crash");
    let path = dir.join("ledger.bean");
    std::fs::write(&path, &mutation.text).unwrap();
    let hand_entry = |svc: &LedgerService| {
        let id = svc
            .all_directive_ids()
            .into_iter()
            .find(|id| !truth.entries.contains_key(id))
            .expect("the hand record is served");
        make_supply_entry(svc.get_directive(&id).unwrap())
    };
    let first = run_pipeline_until(&path, &truth.provider, false).unwrap();
    let entry_first = hand_entry(&first);
    assert_eq!(first.quarantined_ids().len(), 1);
    drop(first);
    let mut second = run_pipeline_until(&path, &truth.provider, false).unwrap();
    let entry_second = hand_entry(&second);
    assert_eq!(entry_first, entry_second, "byte-identical across the crash");
    assert_eq!(second.finalize_operator_input(), 0, "idempotent");
    drop(second);
    std::fs::remove_dir_all(dir).ok();
}

// ─── Bug-catch proofs of the oracle itself ───────────────────────────────────

/// A served record whose signature does not verify is named by the oracle
/// with the wire error — the oracle is not a proxy.
#[test]
fn oracle_detects_a_served_but_refused_record() {
    let truth = generate_fixture(21);
    let mut snapshot = {
        let dir = fresh_dir("oracle");
        let path = dir.join("ledger.bean");
        std::fs::write(&path, &truth.text).unwrap();
        let svc = LedgerService::boot(path, truth.author.clone()).unwrap();
        let snapshot = snapshot_of(&svc);
        drop(svc);
        std::fs::remove_dir_all(dir).ok();
        snapshot
    };
    assert!(audit(&snapshot, &truth, &Effect::default(), Checks::ALL).is_empty());

    // Corrupt one signature by hand: flip its first hex digit.
    let (victim, directive) = snapshot
        .served
        .iter_mut()
        .find(|(_, d)| matches!(d, Directive::Transaction(_)))
        .unwrap();
    let Directive::Transaction(txn) = directive else {
        unreachable!()
    };
    let signature = txn.metadata.get_mut(KEY_SIGNATURE).unwrap();
    let flipped = if signature.starts_with('0') { '1' } else { '0' };
    signature.replace_range(0..1, &flipped.to_string());
    let victim = victim.clone();

    let failures = audit(&snapshot, &truth, &Effect::default(), Checks::ALL);
    let named = failures
        .iter()
        .find(|failure| failure.starts_with(&format!("served-but-refused {}", short(&victim))))
        .unwrap_or_else(|| panic!("oracle missed the corrupted signature: {failures:#?}"));
    assert!(
        named.contains("verify_remote_signature: Invalid signature"),
        "{named}"
    );
    // The same corruption fed straight to the wire validator says the same.
    assert!(matches!(
        verify_remote_signature(&snapshot.served[&victim], true, MESH_ID),
        Err(p2p::union_merge::MergeError::InvalidSignature(_))
    ));
}

/// Deleting one node-written record from the served set fires the "unmodified
/// records survive" check, and only for that record.
#[test]
fn oracle_detects_a_vanished_node_written_record() {
    let truth = generate_fixture(22);
    let mut snapshot = {
        let dir = fresh_dir("oracle");
        let path = dir.join("ledger.bean");
        std::fs::write(&path, &truth.text).unwrap();
        let svc = LedgerService::boot(path, truth.author.clone()).unwrap();
        let snapshot = snapshot_of(&svc);
        drop(svc);
        std::fs::remove_dir_all(dir).ok();
        snapshot
    };
    let victim = snapshot
        .served
        .keys()
        .find(|id| matches!(snapshot.served[*id], Directive::Transaction(_)))
        .unwrap()
        .clone();
    snapshot.served.remove(&victim);
    snapshot.journal.remove(&victim);

    let failures = audit(&snapshot, &truth, &Effect::default(), Checks::ALL);
    let expected = format!(
        "node-written record {} vanished: not served, not quarantined",
        short(&victim)
    );
    assert_eq!(failures, vec![expected]);

    // Declared deleted, the same snapshot is clean: deletion may drop that
    // record and nothing else.
    let effect = Effect {
        touched: vec![],
        deleted: vec![victim.clone()],
    };
    assert!(audit(&snapshot, &truth, &effect, Checks::ALL).is_empty());

    // And a record served with a changed envelope is named too.
    let other = snapshot
        .served
        .iter()
        .find(|(_, d)| matches!(d, Directive::Open(_)))
        .map(|(id, _)| id.clone())
        .unwrap();
    let Some(Directive::Open(open)) = snapshot.served.get_mut(&other) else {
        unreachable!()
    };
    open.metadata
        .insert(KEY_LAMPORT.to_owned(), "999999".to_owned());
    let failures = audit(&snapshot, &truth, &effect, Checks::ALL);
    assert!(
        failures.iter().any(|f| f.starts_with(&format!(
            "node-written record {} is served with a changed envelope",
            short(&other)
        ))),
        "{failures:#?}"
    );
}

/// A fixed point that is not one is reported.
#[test]
fn oracle_detects_a_moving_fixed_point() {
    let truth = generate_fixture(23);
    let dir = fresh_dir("oracle");
    let path = dir.join("ledger.bean");
    std::fs::write(&path, &truth.text).unwrap();
    let svc = LedgerService::boot(path, truth.author.clone()).unwrap();
    let first = snapshot_of(&svc);
    let mut second = snapshot_of(&svc);
    drop(svc);
    std::fs::remove_dir_all(dir).ok();
    assert!(fixed_point(&first, &second).is_empty());
    let victim = second.served.keys().last().unwrap().clone();
    second.served.remove(&victim);
    let failures = fixed_point(&first, &second);
    assert_eq!(
        failures,
        vec![format!(
            "fixed point: {} served after the first boot but not after the reboot",
            short(&victim)
        )]
    );
}

// ─── The fuzz driver ─────────────────────────────────────────────────────────

fn any_operator(operators: &'static [Operator]) -> impl Strategy<Value = Operator> {
    (0..operators.len()).prop_map(move |index| operators[index])
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        max_shrink_iters: 0,
        // Every case is reproducible from its printed (seed, operator,
        // position); no `.proptest-regressions` file next to the sources.
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    /// Every operator, every check.
    #[test]
    fn boot_fuzz_all_operators(
        seed in any::<u64>(),
        operator in any_operator(&OPERATORS_ENABLED),
        position in 0..64usize,
    ) {
        let truth = generate_fixture(seed);
        let report = run_case(&truth, operator, position, Checks::ALL);
        if !report.applied {
            return Ok(());
        }
        prop_assert!(
            report.failures.is_empty(),
            "{operator:?} (seed {seed}, position {position}):\n  {}",
            report.failures.join("\n  ")
        );
    }

    /// Every green operator, including the A2 ones (A2).
    #[test]
    fn boot_fuzz_all_operators_including_a2(
        seed in any::<u64>(),
        operator in any_operator(&OPERATORS_ALL),
        position in 0..64usize,
    ) {
        let truth = generate_fixture(seed);
        let report = run_case(&truth, operator, position, Checks::ALL);
        if !report.applied {
            return Ok(());
        }
        prop_assert!(
            report.failures.is_empty(),
            "{operator:?} (seed {seed}, position {position}):\n  {}",
            report.failures.join("\n  ")
        );
    }
}
