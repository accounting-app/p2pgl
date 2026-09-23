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
//! ## What fails at HEAD
//!
//! The per-operator tests marked `#[ignore = "fails at HEAD: …"]` pin H-20
//! (doors (a) edited record and (b) split record), M-47 (half envelope), L-74
//! (stale read model), L-75 (hand parents honoured verbatim), L-76 (raw copy
//! replaces a quarantined signed record) and L-77 (re-open adopted). Run them
//! with `cargo test -p p2p --test boot_fuzz -- --ignored` to see each one name
//! the served-but-refused id and the wire error. [`OPERATORS_ENABLED_AT_HEAD`]
//! gates the proptest to the operators that hold today; `boot_fuzz_all_operators`
//! (ignored) runs every operator and every check, and is what T73 enables.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::NaiveDate;
use ledger::model::{Amount, Directive, Flag, Transaction};
use ledger::read_model::CurrencyBalances;
use ledger::service::{DirectiveSigner, LedgerService, PostingInput, TransactionInput};
use p2p::allowlist::PeerAllowlist;
use p2p::gossip::make_supply_entry;
use p2p::protocol::SupplyEntry;
use p2p::union_merge::{validate_supply_entry, verify_author_allowlisted, verify_remote_signature};
use proptest::prelude::*;
use rust_decimal::Decimal;
use security::signing::{PeerKeySignatureProvider, SignableMessage, SignatureProvider};

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
    let mut svc = LedgerService::boot(path.to_path_buf(), "local".to_owned())
        .map_err(|error| format!("boot refused the file: {error}"))?;
    svc.set_author_id(provider.public_key_hex());
    svc.set_signer(signer_for(provider));
    if svc.unsigned_operator_input_count() > 0 {
        svc.finalize_operator_input();
    }
    svc.compact()
        .map_err(|error| format!("startup compaction failed: {error}"))?;
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
    /// envelope of every served transaction. Fails at HEAD for every operator
    /// that adopts operator input, so the HEAD-gated proptest turns it off.
    read_model_parity: bool,
}

impl Checks {
    const ALL: Checks = Checks {
        read_model_parity: true,
    };
    /// The checks that hold at HEAD for [`OPERATORS_ENABLED_AT_HEAD`].
    const AT_HEAD: Checks = Checks {
        read_model_parity: false,
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
    let mut failures = Vec::new();
    let allowlist =
        PeerAllowlist::parse(std::slice::from_ref(&truth.author)).expect("author is an EndpointId");

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
}

const ALL_OPERATORS: [Operator; 18] = [
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

/// The operators whose invariant holds at HEAD, under [`Checks::AT_HEAD`].
///
/// Everything else is pinned by an ignored per-operator test below and joins
/// this list when T73 lands (H-20: (a)–(e), (h); M-47: (f), (g); L-75: (k);
/// L-76: (l); L-77: (j)). `AppendHandTransaction` holds at HEAD only without
/// the L-74 read-model check, which is why the HEAD proptest runs
/// [`Checks::AT_HEAD`].
const OPERATORS_ENABLED_AT_HEAD: [Operator; 6] = [
    Operator::AppendHandTransaction,
    Operator::DuplicateSignedBlockRaw,
    Operator::DeleteSignedBlock,
    Operator::Crlf,
    Operator::LeadingBom,
    Operator::Identity,
];

const HAND_TRANSACTION: &str = "2024-01-29 * \"Hand\" \"appended while the node was stopped\"\n  Expenses:Food                                      7.50 USD\n  Assets:Cash                                       -7.50 USD";

/// Apply `operator` to the node-written `text`; `position` picks the target
/// block/line. `None` means the operator does not apply to this fixture.
fn mutate(truth: &Truth, operator: Operator, position: usize) -> Option<(String, Effect)> {
    let text = &truth.text;
    let mut blocks = split_blocks(text);
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
        Operator::Crlf => return Some((text.replace('\n', "\r\n"), effect)),
        Operator::LeadingBom => return Some((format!("\u{feff}{text}"), effect)),
        Operator::Identity => return Some((text.clone(), effect)),
    }
    Some((join_blocks(&blocks), effect))
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
    let Some((mutated, effect)) = mutate(truth, operator, position) else {
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

    let mut failures = Vec::new();
    let mut adopted = BTreeMap::new();
    let mut first_snapshot = None;
    match run_pipeline(&path, &truth.provider) {
        Err(error) => failures.push(format!("first boot: {error}")),
        Ok(svc) => {
            let first = snapshot_of(&svc);
            drop(svc);
            failures.extend(
                audit(&first, truth, &effect, checks)
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
                        audit(&second, truth, &effect, checks)
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
#[ignore = "fails at HEAD: H-20 door (a); enabled by T73"]
fn op_a_edit_narration_of_signed_record() {
    assert_holds(Operator::EditNarration, 1, 0, Checks::ALL);
}

#[test]
#[ignore = "fails at HEAD: H-20 door (a); enabled by T73"]
fn op_b_edit_amount_balanced() {
    assert_holds(Operator::EditAmountBalanced, 2, 1, Checks::ALL);
}

#[test]
#[ignore = "fails at HEAD: H-20 door (a); enabled by T73"]
fn op_b_edit_amount_unbalanced() {
    assert_holds(Operator::EditAmountUnbalanced, 3, 2, Checks::ALL);
}

#[test]
#[ignore = "fails at HEAD: H-20 door (b); enabled by T73"]
fn op_c_dedent_posting() {
    // `position % postings` picks the dedented line; whichever it is, the head
    // fragment loses at least one leg and is loaded truncated (door (b)).
    assert_holds(Operator::DedentPosting, 4, 3, Checks::ALL);
}

#[test]
#[ignore = "fails at HEAD: H-20 door (b); enabled by T73"]
fn op_d_bom_before_posting() {
    assert_holds(Operator::BomBeforePosting, 5, 1, Checks::ALL);
}

#[test]
#[ignore = "fails at HEAD: H-20 door (b); enabled by T73"]
fn op_e_stray_word_line() {
    assert_holds(Operator::StrayWordLine, 6, 1, Checks::ALL);
}

#[test]
#[ignore = "fails at HEAD: M-47; enabled by T73"]
fn op_f_delete_lamport_line() {
    assert_holds(Operator::DeleteLamportLine, 7, 0, Checks::ALL);
}

#[test]
#[ignore = "fails at HEAD: M-47; enabled by T73"]
fn op_g_delete_author_line() {
    assert_holds(Operator::DeleteAuthorLine, 8, 1, Checks::ALL);
}

#[test]
#[ignore = "fails at HEAD: H-20 (an own record missing its signature is served unsigned); enabled by T73"]
fn op_h_delete_signature_line() {
    assert_holds(Operator::DeleteSignatureLine, 9, 2, Checks::ALL);
}

#[test]
fn op_i_append_hand_transaction_is_adopted_and_signed() {
    let report = assert_holds(Operator::AppendHandTransaction, 10, 0, Checks::AT_HEAD);
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
#[ignore = "fails at HEAD: L-74; enabled by T73"]
fn op_i_append_hand_transaction_read_model_agrees() {
    assert_holds(Operator::AppendHandTransaction, 10, 0, Checks::ALL);
}

#[test]
#[ignore = "fails at HEAD: L-77; enabled by T73"]
fn op_j_append_reopen_of_open_account() {
    assert_holds(Operator::AppendReopen, 11, 0, Checks::AT_HEAD);
}

#[test]
#[ignore = "fails at HEAD: L-75; enabled by T73"]
fn op_k_append_hand_transaction_with_dangling_parent() {
    assert_holds(
        Operator::AppendHandTransactionDanglingParent,
        12,
        0,
        Checks::AT_HEAD,
    );
}

#[test]
fn op_l0_duplicate_signed_block_raw_collapses_to_the_signed_copy() {
    let report = assert_holds(Operator::DuplicateSignedBlockRaw, 13, 1, Checks::ALL);
    assert!(report.adopted.is_empty(), "the raw copy is the same record");
}

#[test]
#[ignore = "fails at HEAD: L-76; enabled by T73"]
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

    /// The operators that hold at HEAD, under the checks that hold at HEAD.
    #[test]
    fn boot_fuzz_operators_enabled_at_head(
        seed in any::<u64>(),
        operator in any_operator(&OPERATORS_ENABLED_AT_HEAD),
        position in 0..64usize,
    ) {
        let truth = generate_fixture(seed);
        let report = run_case(&truth, operator, position, Checks::AT_HEAD);
        prop_assert!(report.applied, "{operator:?} did not apply");
        prop_assert!(
            report.failures.is_empty(),
            "{operator:?} (seed {seed}, position {position}):\n  {}",
            report.failures.join("\n  ")
        );
    }

    /// Every operator, every check. Enabled by T73.
    #[test]
    #[ignore = "fails at HEAD: H-20, M-47, L-74, L-75, L-76, L-77; enabled by T73"]
    fn boot_fuzz_all_operators(
        seed in any::<u64>(),
        operator in any_operator(&ALL_OPERATORS),
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
