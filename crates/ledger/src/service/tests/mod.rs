use super::*;
use rust_decimal_macros::dec;
use std::sync::atomic::{AtomicU64, Ordering};

mod authoring;
mod boot;
mod commit;
mod lamport;
mod lifecycle;
mod quarantine;
mod reconcile;
mod recovery;
mod remote;
mod resource_limits;
mod verify;

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

/// Run `body` with every `WARN`/`ERROR` it logs captured as text.
///
/// `tracing::subscriber::with_default` installs a *thread-local* subscriber,
/// so this stays correct under `cargo test`'s thread-per-test parallelism —
/// a concurrent test's logs never land in this buffer.
fn capture_warnings<T>(body: impl FnOnce() -> T) -> (T, String) {
    ensure_every_callsite_is_interesting();
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
/// The two `open`s every [`chain_file`] carries (T84).
const CHAIN_OPENS: usize = 2;

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

    // T84 / H-23: the two accounts the links post to are opened, as on any
    // ledger a peer could adopt (the opens are the only additions; every
    // count below adds CHAIN_OPENS).
    let mut directives: Vec<Directive> = vec![
        open_directive("Assets:Cash", &["USD"]),
        open_directive("Equity:Opening", &[]),
    ];
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

/// A signer that stamps a recognisable marker instead of a real signature,
/// so a ledger-crate test can tell *whether* signing happened without
/// depending on the `security` crate. The real end-to-end proof — that a
/// peer's validator accepts the result — lives in
/// `p2p::union_merge::tests::test_reconcile_signs_hand_edits_so_peers_accept_them`.
fn marker_signer() -> crate::service::DirectiveSigner {
    std::sync::Arc::new(
        |content_id: &str,
         is_transaction: bool,
         parents: &str,
         lamport: &str,
         _format: crate::hash::RecordFormat| {
            Some(format!(
                "sig({content_id}|{is_transaction}|{parents}|{lamport})"
            ))
        },
    )
}

/// The signature [`marker_signer`] produces for `directive` as it stands,
/// so a fixture can be written the way a marker-signing node would have
/// written it (H-20: boot verifies own history once a signer is
/// installed, so an unsigned own record in a fixture is quarantined).
fn marker_signature(directive: &Directive) -> String {
    let metadata = directive.metadata();
    let (parents, lamport) = LedgerService::envelope_parents_and_lamport(metadata);
    format!(
        "sig({}|{}|{parents}|{lamport})",
        compute_content_id(directive),
        matches!(directive, Directive::Transaction(_))
    )
}

/// `directive` with the [`marker_signer`] signature on its envelope.
fn marker_signed(mut directive: Directive) -> Directive {
    let signature = marker_signature(&directive);
    directive_metadata_mut(&mut directive).insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature);
    directive
}

/// The marker signer as the per-call closure the `*_signing` mutation
/// methods take.
fn marker_sign(is_transaction: bool) -> impl Fn(&str, &str, &str) -> Option<String> {
    move |content_id: &str, parents: &str, lamport: &str| {
        Some(format!(
            "sig({content_id}|{is_transaction}|{parents}|{lamport})"
        ))
    }
}

/// [`setup_with_accounts`] as a marker-signing node writes it: signer
/// installed and every `open` signed, so a reboot that installs the same
/// signer verifies the file instead of quarantining it (H-20).
fn setup_with_signed_accounts() -> (LedgerService, PathBuf) {
    let (mut svc, path) = boot_empty();
    svc.set_signer(marker_signer());
    for (account, currencies) in [
        ("Assets:Cash", vec!["USD".to_owned()]),
        ("Equity:Opening", Vec::new()),
        ("Expenses:Food", vec!["USD".to_owned()]),
    ] {
        svc.open_account_signing(
            account.to_owned(),
            make_date(2024, 1, 1),
            currencies,
            marker_sign(false),
        )
        .unwrap();
    }
    (svc, path)
}

fn append_to_file(path: &Path, text: &str) {
    let mut content = std::fs::read_to_string(path).unwrap();
    content.push_str(text);
    std::fs::write(path, content).unwrap();
}

const HAND_EDITED_TRANSACTION: &str = "\n2024-01-15 * \"Shop\" \"Coffee\"\n  \
         Expenses:Food                                        4.50 USD\n  \
         Assets:Cash                                         -4.50 USD\n";

/// An account name of `bytes` total length, valid under §2.3.
fn long_account(root: &str, bytes: usize) -> String {
    let prefix = format!("{root}:A");
    format!("{prefix}{}", "a".repeat(bytes.saturating_sub(prefix.len())))
}

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

/// A pre-T37 ledger: `Assets:Cаsh` with a Cyrillic `а`, which both the old
/// parser and the old `validate_account_name` accepted, so a node could
/// book one — or merely *receive* one from a peer — and persist it.
const UNICODE_ACCOUNT_LEDGER: &str =
    "2024-01-01 open Assets:Cash USD\n\n2024-01-01 open Assets:C\u{0430}sh USD\n";

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

/// A `.bean` whose history already reaches `lamport`: the three opens
/// `setup_with_accounts` makes, authored by `peer-history`, the highest at
/// `lamport`.
///
/// The adoption ratchet (T63) bounds how far one directive may move a
/// clock, so a test that needs a clock near the ceiling gets there the way
/// a real node does — by holding the history, which boot loads without the
/// ratchet — instead of by one remote jump, which is now refused.
fn history_file_at(lamport: u64) -> String {
    format!(
        "2024-01-01 open Assets:Cash USD\n  openledger-author: \"peer-history\"\n  \
             openledger-lamport: \"{a}\"\n\n\
             2024-01-01 open Equity:Opening\n  openledger-author: \"peer-history\"\n  \
             openledger-lamport: \"{b}\"\n\n\
             2024-01-01 open Expenses:Food USD\n  openledger-author: \"peer-history\"\n  \
             openledger-lamport: \"{lamport}\"\n",
        a = lamport - 2,
        b = lamport - 1,
    )
}

fn boot_with_history_at(lamport: u64, author: &str) -> (LedgerService, PathBuf) {
    let path = test_file_path();
    std::fs::write(&path, history_file_at(lamport)).unwrap();
    let svc = LedgerService::boot(path.clone(), author.to_owned()).unwrap();
    assert_eq!(
        svc.lamport_clock(),
        lamport + 1,
        "boot resumes above history"
    );
    (svc, path)
}

/// Within one ratchet step of the ceiling: close enough that the tests
/// below measure the CEILING, far enough that nothing here is already at it.
const NEAR_CEILING: u64 = LAMPORT_CEILING - (1 << 31);

/// A valid remote transaction by `author` naming `parents` (comma-joined),
/// distinct per `index` so every one is a new content id.
fn flood_transaction(author: &str, index: usize, parents: &str) -> Directive {
    let mut metadata = BTreeMap::new();
    metadata.insert("openledger-author".to_owned(), author.to_owned());
    metadata.insert("openledger-lamport".to_owned(), (10 + index).to_string());
    metadata.insert("openledger-parents".to_owned(), parents.to_owned());
    let posting = |account: &str, number| Posting {
        account: account.to_owned(),
        amount: Some(Amount {
            number,
            currency: "USD".to_owned(),
        }),
        cost: None,
        price: None,
        metadata: BTreeMap::new(),
    };
    Directive::Transaction(Transaction {
        date: make_date(2024, 1, 16),
        flag: Flag::Complete,
        payee: None,
        narration: Some(format!("{author} {index}")),
        tags: vec![],
        links: vec![],
        postings: vec![
            posting("Assets:Cash", dec!(1)),
            posting("Equity:Opening", dec!(-1)),
        ],
        metadata,
    })
}

/// Stage the H-16 flood: `MAX_PARENTS` parentless transactions from
/// `peer-a` and one from `peer-b`, so the head set is `MAX_PARENTS + 1` —
/// the audit's 257.
fn stage_parentless_flood(svc: &mut LedgerService) -> Vec<Directive> {
    let mut flood = Vec::new();
    for index in 0..MAX_PARENTS {
        flood.push(flood_transaction("peer-a", index, ""));
    }
    flood.push(flood_transaction("peer-b", 0, ""));
    for directive in &flood {
        svc.stage_remote_directive(directive.clone())
            .unwrap()
            .expect("inserted");
    }
    assert_eq!(svc.head_count(), MAX_PARENTS + 1);
    flood
}

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

/// A signer that records every id it is ASKED to sign.
///
/// The M-20 tests need more than "the entry is not in the DAG": the finding
/// is that a refused entry was being **signed with this node's key** before
/// anything noticed, so the ordering itself is the property under test.
/// This makes it directly observable — a guard that runs after
/// `sign_adopted_entry` leaves the id in this log even when the entry never
/// lands.
fn recording_signer() -> (
    crate::service::DirectiveSigner,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let for_signer = std::sync::Arc::clone(&log);
    let signer: crate::service::DirectiveSigner = std::sync::Arc::new(
        move |content_id: &str,
              _is_transaction: bool,
              _parents: &str,
              _lamport: &str,
              _format: crate::hash::RecordFormat| {
            for_signer.lock().unwrap().push(content_id.to_owned());
            Some(format!("sig({content_id})"))
        },
    );
    (signer, log)
}

/// A reconcile-refused transaction must be out of the DAG **and** must
/// never have been handed to the signer.
///
/// The second half is the ordering property M-20 is actually about: L-11
/// made reconcile sign what it adopts, so a guard placed after
/// `sign_adopted_entry` would still leave this node having signed — and
/// therefore vouched for — an entry every peer refuses.
fn assert_refused_before_signing(
    svc: &LedgerService,
    signed: &std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    narration: &str,
) {
    assert!(
        !svc.dag().directives().iter().any(|directive| matches!(
            directive,
            Directive::Transaction(txn) if txn.narration.as_deref() == Some(narration)
        )),
        "{narration} must not reach the DAG"
    );
    let signed_ids = signed.lock().unwrap().clone();
    assert!(
        signed_ids.is_empty(),
        "{narration}: the guard must refuse BEFORE sign_adopted_entry — nothing may \
             have been signed, got: {signed_ids:?}"
    );
}

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

/// Transactions the `.bean` on disk actually holds, as the parser sees it.
///
/// Deliberately re-parses the file rather than trusting the service: the
/// whole finding is that memory and disk disagreed about what exists.
fn transactions_on_disk(path: &Path) -> Vec<Transaction> {
    let content = std::fs::read_to_string(path).unwrap();
    if content.trim().is_empty() {
        return Vec::new();
    }
    parse_file(&content)
        .unwrap()
        .into_iter()
        .filter_map(|directive| match directive {
            Directive::Transaction(transaction) => Some(transaction),
            _ => None,
        })
        .collect()
}

/// Build the `.bean` that makes boot's I8 check give up (L-14's residual).
///
/// [`DagError::CycleCheckExhausted`] is the one DAG refusal that boot's
/// third skip site really sees: the pre-scan rules out `CycleDetected` and
/// `require_parents: false` rules out `MissingParent`, but the visit budget
/// is a refusal to *answer*, not a proven cycle, and a crafted parent graph
/// can force it. The shape is the one `check_no_cycle` documents — both
/// search frontiers large at once — built here at the production budget
/// rather than through the DAG's test-only budget knob, because what is
/// under test is the FILE's round trip, not the check.
///
/// * `seed` names the not-yet-present `exhaust` as a parent, so inserting
///   `exhaust` finds a non-empty `pending_children` and must search. A chain
///   of `DESCENDANTS` transactions hangs off `seed`, so the downward
///   frontier is deep.
/// * `exhaust`'s ancestry is a chain of `ANCESTORS` transactions, each
///   padding its parents to exactly `MAX_PARENTS` with distinct ids that
///   resolve to nothing, so the upward frontier is wide without needing one
///   transaction per visit.
///
/// Every id is computable offline — parents are envelope metadata the
/// content hash excludes — so the ids below are derived from bodies alone.
fn cycle_check_exhaustion_file() -> (String, String) {
    // The I8 budget is 16,384 node visits and each loop step spends two, so
    // the check survives 8,192 steps and fails on the 8,193rd. Both
    // frontiers must therefore still be non-empty after 8,192 pops.
    const DESCENDANTS: usize = 8_192;
    const ANCESTORS: usize = 32;

    fn body(narration: &str, parents: &str) -> Directive {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "crafted".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "2".to_owned());
        metadata.insert("openledger-parents".to_owned(), parents.to_owned());
        Directive::Transaction(Transaction {
            date: make_date(2024, 6, 1),
            flag: Flag::Complete,
            payee: None,
            narration: Some(narration.to_owned()),
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
        })
    }
    // Parents are outside the content hash, so an id is a function of the
    // narration alone — no chaining needed to compute one.
    let id_of = |narration: &str| compute_content_id(&body(narration, ""));

    let mut fake = 0u64;
    let mut padding = |real: Option<&str>| {
        let mut parents: Vec<String> = real.map(str::to_owned).into_iter().collect();
        while parents.len() < MAX_PARENTS {
            fake += 1;
            parents.push(format!("{fake:064x}"));
        }
        parents.join(",")
    };

    let exhaust_id = id_of("exhaust");
    let mut directives = vec![
        open_directive("Assets:Cash", &["USD"]),
        open_directive("Equity:Opening", &[]),
        // The seed: already inserted, and naming `exhaust` as a parent, so
        // `exhaust`'s insert has somewhere to search downward from.
        body("seed", &exhaust_id),
    ];
    // Deep downward frontier.
    let mut previous = id_of("seed");
    for index in 0..DESCENDANTS {
        let narration = format!("below {index}");
        directives.push(body(&narration, &previous));
        previous = id_of(&narration);
    }
    // Wide upward frontier: each link adds `MAX_PARENTS` fresh ids to the
    // search, only one of which is real.
    let mut above: Option<String> = None;
    for index in 0..ANCESTORS {
        let narration = format!("above {index}");
        let parents = padding(above.as_deref());
        directives.push(body(&narration, &parents));
        above = Some(id_of(&narration));
    }
    // The victim, inserted last so both frontiers are already built.
    let parents = padding(above.as_deref());
    directives.push(body("exhaust", &parents));

    // Written in this exact order: boot's canonical sort is stable and every
    // transaction here shares a date, so file order is insertion order.
    (file_text_in_given_order(&directives), exhaust_id)
}

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
    full_file_serialize(&large_ledger_directives(), &[])
}

/// [`large_ledger_content`] as a marker-signing node would have written
/// it (H-20): a test that installs `marker_signer` over this file verifies
/// it rather than quarantining 502 unsigned own records. Separate from
/// the unsigned fixture because the T44 ratio tests pin that one's byte
/// proportions.
fn large_ledger_content_signed() -> String {
    let directives: Vec<Directive> = large_ledger_directives()
        .into_iter()
        .map(marker_signed)
        .collect();
    full_file_serialize(&directives, &[])
}

fn large_ledger_directives() -> Vec<Directive> {
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
    directives
}

/// A booted service whose canonical file is past the compaction threshold,
/// with the first (canonicalising) commit already taken — so the NEXT
/// commit is an append.
fn boot_large_ledger() -> (LedgerService, PathBuf) {
    boot_large_ledger_from(large_ledger_content())
}

/// [`boot_large_ledger`] over the marker-signed fixture, for a test that
/// goes on to install `marker_signer` (H-20).
fn boot_large_ledger_signed() -> (LedgerService, PathBuf) {
    boot_large_ledger_from(large_ledger_content_signed())
}

fn boot_large_ledger_from(content: String) -> (LedgerService, PathBuf) {
    let path = test_file_path();
    std::fs::write(&path, content).unwrap();
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

/// A second hand edit, distinguishable from [`HAND_EDITED_TRANSACTION`] so
/// the G-Set does not dedupe it away.
const HAND_EDITED_SECOND_TRANSACTION: &str = "\n2024-01-16 * \"Shop\" \"Tea\"\n  \
         Expenses:Food                                        3.25 USD\n  \
         Assets:Cash                                         -3.25 USD\n";

/// A hand-edited transaction whose `openledger-parents` names `victim_id`,
/// which does not exist yet. Well-formed in every respect boot and
/// reconcile check (T47's cycle pre-scan finds no cycle — the id it names
/// is not in the file — and T51's parity checks see a well-formed
/// lowercase txid), so it loads, and it is a head: nothing points at it.
fn planted_dangling_parent(victim_id: &str) -> String {
    format!(
        "\n2024-01-10 * \"Mallory\" \"Planted\"\n  \
             openledger-author: \"mallory\"\n  \
             openledger-lamport: \"5\"\n  \
             openledger-parents: \"{victim_id}\"\n  \
             Assets:Cash                                          1.00 USD\n  \
             Equity:Opening                                      -1.00 USD\n"
    )
}

/// The id the victim's next append will get. Content ids hash the economic
/// body only, so anyone who can guess the body can compute it offline.
fn predicted_txid(input: TransactionInput) -> String {
    let (mut probe, probe_path) = setup_with_accounts();
    let txid = probe.append_transaction(input).unwrap().txid;
    remove_ledger_and_journal(&probe_path);
    txid
}

/// `balanced_input` with its own date and narration, so several distinct
/// transactions can be authored from one fixture.
fn narrated_input(date: NaiveDate, narration: &str) -> TransactionInput {
    TransactionInput {
        date,
        narration: Some(narration.to_owned()),
        ..balanced_input()
    }
}

fn transaction_named<'a>(svc: &'a LedgerService, narration: &str) -> Option<&'a Directive> {
    svc.dag()
        .directives()
        .into_iter()
        .find(|directive| match directive {
            Directive::Transaction(txn) => txn.narration.as_deref() == Some(narration),
            _ => false,
        })
}

/// A hand-typed transaction with no envelope on accounts
/// `setup_with_accounts` opened — the stop-edit-start shape.
const OFFLINE_HAND_EDIT: &str = "\n2024-01-20 * \"Hand\" \"Offline edit\"\n  \
         Assets:Cash                                        250.00 USD\n  \
         Equity:Opening                                    -250.00 USD\n";

/// A hand-typed transaction on an account that was never opened.
const HAND_EDIT_ON_UNOPENED_ACCOUNT: &str = "\n2024-02-01 * \"Hand\" \"unopened\"\n  \
         Assets:Vault                                       250.00 USD\n  \
         Equity:Opening                                    -250.00 USD\n";

/// Run `body` on its own thread and fail — rather than hang the suite — if
/// it has not returned within `seconds` (M-36: every regression here is an
/// `open` parked on a FIFO, so the thread is abandoned, not joined).
fn within<T: Send + 'static>(seconds: u64, body: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(body());
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(seconds))
        .expect("M-36: the call blocked (an open parked on a FIFO?)")
}

#[cfg(unix)]
fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "mkfifo {}", path.display());
}

/// A fresh directory for fixtures that plant things beside the ledger.
fn t67_directory(name: &str) -> PathBuf {
    let directory = test_file_path().with_extension(name);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn boot_error_within(path: PathBuf) -> String {
    within(5, move || {
        match LedgerService::boot(path, "test-peer".to_owned()) {
            Ok(_) => "booted".to_owned(),
            Err(error) => format!("Err: {error}"),
        }
    })
}

/// The author `gl-node` learns from its key after boot.
const L67_REAL: &str = "REALENDPOINTID";

fn l67_envelope(author: &str, lamport: u64) -> Metadata {
    let mut metadata = BTreeMap::new();
    metadata.insert("openledger-author".to_owned(), author.to_owned());
    metadata.insert("openledger-lamport".to_owned(), lamport.to_string());
    metadata
}

/// The 0923 audit's D3 `h5` file: two peer opens (lamports 5, 6) in the
/// DAG and this node's OWN transaction at 12, quarantined at boot for its
/// upper-case parent — still in the file, possibly on every peer. `extra`
/// is appended verbatim (operator input, unparsable text).
fn l67_file(extra: &str) -> PathBuf {
    let mut own = BTreeMap::new();
    own.insert("openledger-author".to_owned(), L67_REAL.to_owned());
    own.insert("openledger-lamport".to_owned(), "12".to_owned());
    own.insert("openledger-parents".to_owned(), "A".repeat(64));
    let directives = vec![
        Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: Vec::new(),
            metadata: l67_envelope("peer-history", 5),
        }),
        Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Equity:Opening".to_owned(),
            currencies: Vec::new(),
            metadata: l67_envelope("peer-history", 6),
        }),
        Directive::Transaction(Transaction {
            date: make_date(2024, 1, 16),
            flag: Flag::Complete,
            payee: None,
            narration: Some("mine".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
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
            metadata: own,
        }),
    ];
    let path = test_file_path();
    std::fs::write(
        &path,
        format!("{}{extra}", full_file_serialize(&directives, &[])),
    )
    .unwrap();
    path
}

/// The `.torn-*` sidecar files beside `journal_path`.
fn torn_sidecars(journal_path: &Path) -> Vec<PathBuf> {
    let prefix = format!(
        "{}{}",
        journal_path.file_name().unwrap().to_string_lossy(),
        crate::journal::TORN_JOURNAL_SUFFIX
    );
    std::fs::read_dir(journal_path.parent().unwrap())
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .map(|entry| entry.path())
        .collect()
}

/// Run `body` with `directory` read-only (0o500) and give write back
/// (0o700) before returning, even if `body` panics — the real-I/O failure
/// injection `test_persist_or_reload_failure_rolls_back_to_disk` uses: a
/// compaction cannot create its sibling `.tmp`, and the L-13 reload can
/// still read both files.
#[cfg(unix)]
fn with_read_only_directory<T>(directory: &Path, body: impl FnOnce() -> T) -> T {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o500)).unwrap();
    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    value.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// Raw opens, one block each — lines an operator types or restores.
fn raw_opens(names: &[&str], date: &str) -> String {
    names
        .iter()
        .map(|name| format!("{date} open {name} USD\n"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Two raw opens appended to [`large_ledger_content`]: 502 history records
/// plus two lines boot adopts as operator input (H-13).
fn large_ledger_with_two_hand_lines() -> String {
    format!(
        "{}\n{}",
        large_ledger_content(),
        raw_opens(&["Assets:HandOne", "Assets:HandTwo"], "2024-04-01")
    )
}

/// A node-written file: three signed opens and one signed transaction
/// ("Funding"), written by a marker-signing node and compacted. Returns
/// the path and the transaction's id.
fn signed_node_written_file() -> (PathBuf, String) {
    let (mut svc, path) = setup_with_signed_accounts();
    let txid = svc
        .append_transaction_signing(balanced_input(), marker_sign(true))
        .unwrap()
        .txid;
    svc.compact().unwrap();
    drop(svc);
    (path, txid)
}

/// Rewrite every line of the block containing `marker` through `edit`.
fn edit_block_lines(path: &Path, marker: &str, edit: impl Fn(&str) -> String) {
    let content = std::fs::read_to_string(path).unwrap();
    let rewritten: Vec<String> = content
        .split("\n\n")
        .map(|block| {
            if !block.contains(marker) {
                return block.to_owned();
            }
            let mut text = block.lines().map(&edit).collect::<Vec<_>>().join("\n");
            if block.ends_with('\n') {
                text.push('\n');
            }
            text
        })
        .collect();
    std::fs::write(path, rewritten.join("\n\n")).unwrap();
}

/// The block of `path` containing `marker`, without its envelope lines.
fn raw_copy_of_block(path: &Path, marker: &str) -> String {
    let content = std::fs::read_to_string(path).unwrap();
    let block = content
        .split("\n\n")
        .find(|block| block.contains(marker))
        .expect("block present");
    block
        .lines()
        .filter(|line| !line.trim_start().starts_with("openledger-"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn cash_balance(svc: &LedgerService) -> crate::read_model::CurrencyBalances {
    svc.read_model()
        .account_balance("Assets:Cash", None)
        .map(|entry| entry.balances)
        .unwrap_or_default()
}

const AUTHOR_ONLY_HAND_EDIT: &str = "\n2024-01-21 * \"Hand\" \"author only\"\n\
         \x20 openledger-author: \"test-peer\"\n\
         \x20 openledger-signature: \"stale\"\n\
         \x20 Assets:Cash                                        10.00 USD\n\
         \x20 Equity:Opening                                    -10.00 USD\n";
const LAMPORT_ONLY_HAND_EDIT: &str = "\n2024-01-22 * \"Hand\" \"lamport only\"\n\
         \x20 openledger-lamport: \"99\"\n\
         \x20 openledger-signature: \"stale\"\n\
         \x20 Assets:Cash                                        11.00 USD\n\
         \x20 Equity:Opening                                    -11.00 USD\n";
const FOREIGN_AUTHOR_ONLY_HAND_EDIT: &str = "\n2024-01-23 * \"Hand\" \"foreign author only\"\n\
         \x20 openledger-author: \"a-different-node\"\n\
         \x20 Assets:Cash                                        12.00 USD\n\
         \x20 Equity:Opening                                    -12.00 USD\n";

/// A node-written file with two signed transactions, "T1" then "T2"
/// (T2 names T1), written by a marker-signing node and compacted.
fn two_signed_transactions_file() -> (PathBuf, String, String) {
    let (mut svc, path) = setup_with_signed_accounts();
    let first = svc
        .append_transaction_signing(
            narrated_input(make_date(2024, 1, 15), "T1"),
            marker_sign(true),
        )
        .unwrap()
        .txid;
    let second = svc
        .append_transaction_signing(
            narrated_input(make_date(2024, 1, 16), "T2"),
            marker_sign(true),
        )
        .unwrap()
        .txid;
    svc.compact().unwrap();
    drop(svc);
    (path, first, second)
}

/// A hand-typed transaction with no envelope, dated after the fixture.
fn h22_hand_line(narration: &str, parents: Option<&str>) -> String {
    let parents = parents
        .map(|parents| format!("\x20 openledger-parents: \"{parents}\"\n"))
        .unwrap_or_default();
    format!(
        "\n2024-01-26 * \"Hand\" \"{narration}\"\n\
             {parents}\
             \x20 Assets:Cash                                         5.00 USD\n\
             \x20 Equity:Opening                                     -5.00 USD\n"
    )
}

/// The content id "T2" is stored under once its narration is edited to
/// "T2 edited" — the id the H-20 pass quarantines.
fn edited_t2_id(path: &Path) -> String {
    let probe = LedgerService::boot(path.to_path_buf(), "test-peer".to_owned()).unwrap();
    let id = compute_content_id(transaction_named(&probe, "T2 edited").expect("loaded"));
    drop(probe);
    id
}

fn parents_of_named(svc: &LedgerService, narration: &str) -> Vec<String> {
    let directive = transaction_named(svc, narration).expect(narration);
    match directive {
        Directive::Transaction(txn) => txn.parent_ids().into_iter().map(str::to_owned).collect(),
        _ => unreachable!(),
    }
}

/// The key [`marker_signer`] models: a signature verifies iff it is the
/// marker signature over the message and the claimed author is
/// `test-peer` — the author id IS the key, as `verify_signature` has it.
fn marker_verifier() -> DirectiveVerifier {
    std::sync::Arc::new(
        |content_id: &str,
         is_transaction: bool,
         parents: &str,
         lamport: &str,
         author: &str,
         signature: &str,
         _format: crate::hash::RecordFormat| {
            author == "test-peer"
                && signature == format!("sig({content_id}|{is_transaction}|{parents}|{lamport})")
        },
    )
}

/// A history written by a node that signed with P2P off before T80: booted
/// under the placeholder, signer installed, author never set — so every
/// record carries `openledger-author: "local"` over the key's signature.
fn pre_t80_placeholder_signed_file() -> PathBuf {
    let path = test_file_path();
    let mut svc = LedgerService::boot(path.clone(), PLACEHOLDER_AUTHOR.to_owned()).unwrap();
    svc.set_signer(marker_signer());
    for (account, currencies) in [
        ("Assets:Cash", vec!["USD".to_owned()]),
        ("Equity:Opening", Vec::new()),
    ] {
        svc.open_account_signing(
            account.to_owned(),
            make_date(2024, 1, 1),
            currencies,
            marker_sign(false),
        )
        .unwrap();
    }
    svc.append_transaction_signing(balanced_input(), marker_sign(true))
        .unwrap();
    svc.compact().unwrap();
    drop(svc);
    let written = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        written.matches("openledger-author: \"local\"").count(),
        3,
        "premise: every record carries the placeholder"
    );
    path
}

/// A pre-T80 placeholder history (lamports 1–3) plus a fourth "local"
/// record at lamport 7 held as unparsable text (T89 / L-96 tests).
fn placeholder_history_with_a_text_held_record() -> PathBuf {
    let path = pre_t80_placeholder_signed_file();
    append_to_file(
        &path,
        "\n2024-01-26 * \"Junk\" \"held as text\"\n\
             \x20 openledger-author: \"local\"\n\
             \x20 openledger-lamport: \"7\"\n\
             \x20 this line does not parse\n",
    );
    path
}

/// Two own transactions whose narrations were edited, beside three
/// foreign records (the accounts' `open`s and one transaction, by
/// `peer-b`) that verify (T89 / L-98, L-99 tests). Returns the path and
/// a verifier that accepts a marker signature from any author.
fn edited_own_records_beside_verifying_foreign_ones() -> (PathBuf, DirectiveVerifier) {
    let path = test_file_path();
    let foreign = |directive: Directive| {
        let mut directive = directive;
        directive_metadata_mut(&mut directive)
            .insert(ENVELOPE_KEY_AUTHOR.to_owned(), "peer-b".to_owned());
        marker_signed(directive)
    };
    let mut cash = open_directive("Assets:Cash", &["USD"]);
    directive_metadata_mut(&mut cash).insert(ENVELOPE_KEY_LAMPORT.to_owned(), "1".to_owned());
    let mut equity = open_directive("Equity:Opening", &[]);
    directive_metadata_mut(&mut equity).insert(ENVELOPE_KEY_LAMPORT.to_owned(), "2".to_owned());
    let other = signed_history_transaction("by peer b", 1, ("Assets:Cash", "USD"), "", 3);
    let own_one = signed_history_transaction("own one", 2, ("Assets:Cash", "USD"), "", 4);
    let own_two = signed_history_transaction("own two", 3, ("Assets:Cash", "USD"), "", 5);
    let text = full_file_serialize(
        &[
            foreign(cash),
            foreign(equity),
            foreign(other),
            own_one,
            own_two,
        ],
        &[],
    )
    .replace("\"own one\"", "\"own one (edited)\"")
    .replace("\"own two\"", "\"own two (edited)\"");
    std::fs::write(&path, text).unwrap();
    let any_author: DirectiveVerifier = std::sync::Arc::new(
        |content_id: &str,
         is_transaction: bool,
         parents: &str,
         lamport: &str,
         _: &str,
         signature: &str,
         _format: crate::hash::RecordFormat| {
            signature == format!("sig({content_id}|{is_transaction}|{parents}|{lamport})")
        },
    );
    (path, any_author)
}

/// A marker-signed history transaction by `test-peer` on two accounts.
fn signed_history_transaction(
    narration: &str,
    day: u32,
    debit: (&str, &str),
    parents: &str,
    lamport: u64,
) -> Directive {
    let posting = |account: &str, number: rust_decimal::Decimal, currency: &str| Posting {
        account: account.to_owned(),
        amount: Some(Amount {
            number,
            currency: currency.to_owned(),
        }),
        cost: None,
        price: None,
        metadata: BTreeMap::new(),
    };
    marker_signed(Directive::Transaction(Transaction {
        date: make_date(2024, 2, day),
        flag: Flag::Complete,
        payee: None,
        narration: Some(narration.to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            posting(debit.0, dec!(5), debit.1),
            posting("Equity:Opening", dec!(-5), debit.1),
        ],
        metadata: BTreeMap::from([
            (ENVELOPE_KEY_AUTHOR.to_owned(), "test-peer".to_owned()),
            (ENVELOPE_KEY_LAMPORT.to_owned(), lamport.to_string()),
            (ENVELOPE_KEY_PARENTS.to_owned(), parents.to_owned()),
        ]),
    }))
}

/// The M-51 flood `open` of `Assets:Flood` (4,097 currencies, over the
/// legacy ceiling) as a signed history record (T85 tests).
fn t85_flood_open() -> Directive {
    marker_signed(Directive::Open(Open {
        date: make_date(2024, 1, 2),
        account: "Assets:Flood".to_owned(),
        currencies: (0..=crate::limits::MAX_CURRENCIES_PER_OPEN_LEGACY)
            .map(|index| format!("C{index:04}"))
            .collect(),
        metadata: BTreeMap::from([
            (ENVELOPE_KEY_AUTHOR.to_owned(), "test-peer".to_owned()),
            (ENVELOPE_KEY_LAMPORT.to_owned(), "10".to_owned()),
        ]),
    }))
}

/// gl-node's order over `path`: boot, signer, finalise.
fn t85_boot(path: &Path) -> LedgerService {
    let mut svc = LedgerService::boot(path.to_path_buf(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    svc.finalize_operator_input();
    svc
}

/// A ledger whose file is just under the cap and whose canonical form is
/// just over it: 64 leading `;x…` comment lines of 1 MiB, each gaining a
/// space when canonicalised (the L-64 fixture).
fn over_cap_canonical_ledger(path: &Path) {
    let line = format!(";{}\n", "x".repeat((1 << 20) - 2));
    let content = line.repeat(64 - 1) + &format!(";{}\n", "x".repeat((1 << 20) - 64));
    assert!(content.len() as u64 <= MAX_LEDGER_FILE_BYTES);
    std::fs::write(path, content).unwrap();
}

/// A ledger whose file is under the cap and whose canonical form is over
/// it only because of the envelopes three hand-typed `open`s gain when
/// finalised (T86 / M-58: the L-64 shape the README names). The comments
/// are already canonical (`; x…`), so nothing else grows.
fn over_cap_by_hand_lines_ledger(path: &Path) {
    let line = format!("; {}\n", "x".repeat((1 << 20) - 3));
    let hand = raw_opens(
        &["Assets:HandA", "Assets:HandB", "Assets:HandC"],
        "2024-01-02",
    );
    let used = line.len() * 63 + hand.len() + 2;
    let last = format!(
        "; {}\n",
        "x".repeat(MAX_LEDGER_FILE_BYTES as usize - used - 3 - 60)
    );
    let content = format!("{}{last}\n{hand}", line.repeat(63));
    assert!(content.len() as u64 <= MAX_LEDGER_FILE_BYTES);
    std::fs::write(path, content).unwrap();
}
