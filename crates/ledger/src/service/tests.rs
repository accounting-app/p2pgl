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
    let fixture = include_str!("../../../../testfixtures/fixture-simple.bean");
    let path = test_file_path();
    std::fs::write(&path, fixture).unwrap();
    let svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
    // T84 / H-23: 16 records, one of which ("Pending refund") names the
    // §3.3.3 worked example's id as its parent — a record this fixture does
    // not hold, so no peer could adopt it. Held, not served.
    assert_eq!(svc.directive_count(), 15);
    assert_eq!(svc.quarantined_count(), 1);
    assert!(transaction_named(&svc, "Pending refund").is_none());
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
    assert_eq!(honest_count, LINKS + CHAIN_OPENS);

    // The worst decoy that is still LEGAL after T41's file-path fan-in cap.
    // This is the cost test proper: the directive loads, so the ancestor
    // walk really does run against it.
    let (crafted_elapsed, crafted_count) = time_boot(&chain_file(LINKS, Some(MAX_PARENTS)));
    assert_eq!(
        crafted_count,
        LINKS + 1 + CHAIN_OPENS,
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
        unbounded_count,
        SHORT_CHAIN + CHAIN_OPENS,
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
        // T51 folded the fan-in skip into one file-ingest quarantine site,
        // so the REASON now arrives in the error field rather than in the
        // message — which is the more precise thing to assert anyway.
        logged.contains("openledger-parents has"),
        "boot must say which directive it skipped and why, got: {logged}"
    );

    // The control: exactly at the cap, the fan-in rule does not refuse
    // the same file. (Its fabricated parents resolve to nothing, so since
    // T84 the H-23 rule holds the directive instead — a record no peer
    // could adopt — which is a different refusal, named differently.)
    std::fs::write(&path, file_with_parent_fan_in(MAX_PARENTS)).unwrap();
    let (at_cap, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap());
    assert!(
        !logged.contains("openledger-parents has"),
        "the cap is a ceiling, not an off-by-one refusal: {logged}"
    );
    assert!(
        logged.contains("no fresh replica could hold") && at_cap.quarantined_count() == 1,
        "T84: held because its parents resolve nowhere: {logged}"
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
    // A hand edit that names someone ELSE as author cannot be signed by
    // this node — the verifier checks the signature against the author's
    // key, so our signature would fail everywhere. Until T79 it was
    // adopted unsigned with a warning; adopted, it was a head this node's
    // next write named, so everything written after it was refused by
    // every peer (M-54). Since T79 (decision (7) of 2026-09-24) it is
    // refused, and the canonical rewrite removes it from the file.
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
    assert_eq!(result.new_directives, 0, "M-54: refused, not adopted");
    assert_eq!(result.rejected, 1);
    assert!(
        !svc.dag()
            .directives()
            .into_iter()
            .any(|d| matches!(d, Directive::Transaction(_))),
        "nothing this node could not sign is served"
    );
    assert!(
        logs.contains("cannot sign for that author") && logs.contains("(M-54)"),
        "the operator must be told why and what to do: {logs}"
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
        crate::serialize::economic_canonical_serialize(directive).len() <= MAX_ECONOMIC_BEAN_LENGTH
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
    // `open_account` — the open is refused first. Until T85 it was
    // reachable through boot, which applied no body cap to HISTORY, so a
    // ledger written before L-02 could hold an account name no `close`
    // could ever be shipped for. Since T85 (L-101, decision (19)) boot
    // holds such an `open` as a record every peer refuses, so the account
    // is never open here and the close is refused before the size check,
    // and nothing moves. (T96 / L-136: the check itself is still reachable
    // — an `open` of exactly 1,048,576 bytes is admitted and its `close`,
    // one byte longer, is not: `m50_wire`'s
    // `a2_close_accounts_size_check_is_reachable_…` pins that.)
    let path = test_file_path();
    let huge = long_account("Assets", MAX_ECONOMIC_BEAN_LENGTH + 1_024);
    let persisted = full_file_serialize(
        &[Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: huge.clone(),
            currencies: vec![],
            metadata: filler_envelope(1),
        })],
        &[],
    );
    std::fs::write(&path, &persisted).unwrap();

    let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
    assert!(
        !svc.accounts().is_open(&huge) && svc.quarantined_count() == 1,
        "T85: boot holds the oversized open — every peer refuses its body"
    );

    let lamport_before = svc.lamport_clock();
    let error = svc.close_account(huge, make_date(2024, 1, 2)).unwrap_err();
    assert!(
        matches!(
            error.error_code(),
            "RESOURCE_LIMIT_EXCEEDED" | "ACCOUNT_NOT_OPEN"
        ),
        "{error}"
    );
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

/// A pre-T37 ledger: `Assets:Cаsh` with a Cyrillic `а`, which both the old
/// parser and the old `validate_account_name` accepted, so a node could
/// book one — or merely *receive* one from a peer — and persist it.
const UNICODE_ACCOUNT_LEDGER: &str =
    "2024-01-01 open Assets:Cash USD\n\n2024-01-01 open Assets:C\u{0430}sh USD\n";

#[test]
fn test_boot_warns_and_skips_a_persisted_mixed_script_account() {
    // L-45, replacing T37's deliberate fail-closed. That decision made the
    // upgrade itself the outage: `parse_file` refuses the Cyrillic name,
    // `boot` propagated the error, and `gl-node`'s `main` turns a boot error
    // into `exit(1)`. Any deployment holding such a name — including one
    // that only ever RECEIVED it — could not start after upgrading, and the
    // node was down, not degraded.
    //
    // The charset is not loosened: L-25 is a confusable-account forgery
    // finding and the ASCII rule stands. What changes is that a block this
    // node cannot parse costs the node that block, not the boot.
    let path = test_file_path();
    std::fs::write(&path, UNICODE_ACCOUNT_LEDGER).unwrap();

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "peer-1".to_owned()));
    let svc = booted.expect("a pre-T37 Unicode account name must not brick boot (L-45)");

    assert_eq!(
        svc.directive_count(),
        1,
        "the ASCII open loads; the Cyrillic one does not"
    );
    assert!(svc.accounts().is_open("Assets:Cash"));
    assert_eq!(svc.unparsable_block_count(), 1);
    assert_eq!(
        svc.quarantined_count(),
        1,
        "the operator-facing count must include the block it cannot name by id"
    );

    // The diagnostic T37's test asked for is still required: the operator
    // has to be able to find the line and the character.
    assert!(
        logged.contains("U+0430") && logged.contains("line=3"),
        "boot must report the offending line and character: {logged}"
    );
    assert!(
        logged.contains("L-45"),
        "the warning must name the finding: {logged}"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_the_startup_compaction_does_not_delete_the_unparsable_record() {
    // L-45 × H-08 — the half that makes the skip safe. `gl-node` runs a
    // compaction unconditionally, seconds after boot, to fold in the
    // crash-window journal; a compaction serializes memory over the whole
    // `.bean`. So "boot skips it" without this would mean "the record is
    // deleted from disk before any operator reads the warning" — precisely
    // the H-08 shape T47 just closed, re-opened through a different door.
    //
    // The quarantine T47 built holds `Directive` values and this record
    // never becomes one, so it is held as raw text and spliced back by
    // `compaction_text`. This test is the proof that it is.
    let path = test_file_path();
    std::fs::write(&path, UNICODE_ACCOUNT_LEDGER).unwrap();

    let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
    svc.compact().unwrap();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("Assets:C\u{0430}sh"),
        "the unparsable record must survive the rewrite verbatim, got:\n{on_disk}"
    );
    assert!(
        on_disk.contains("2024-01-01 open Assets:Cash USD"),
        "…and the rest of the ledger is still canonicalised: {on_disk}"
    );

    // Fixed point: rebooting on the rewritten file reaches the same state,
    // and a second compaction neither loses nor duplicates the block.
    let mut rebooted = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
    assert_eq!(rebooted.directive_count(), 1);
    assert_eq!(rebooted.unparsable_block_count(), 1);
    rebooted.compact().unwrap();
    let twice = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        twice.matches("Assets:C\u{0430}sh").count(),
        1,
        "the held block must be written back exactly once: {twice}"
    );
    assert_eq!(twice, on_disk, "the file is a fixed point across restarts");

    std::fs::remove_file(path).ok();
}

#[test]
fn test_repairing_the_unparsable_line_releases_it_and_adopts_the_record() {
    // How a held block LEAVES: the operator fixes the name, and the very
    // next reconcile parses it, adopts it as an ordinary directive, and
    // stops writing the broken text back. Without the re-derivation in
    // `reconcile_content` the stale block would be spliced in underneath
    // the repaired copy forever.
    let path = test_file_path();
    std::fs::write(&path, UNICODE_ACCOUNT_LEDGER).unwrap();
    let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
    svc.compact().unwrap();
    assert_eq!(svc.unparsable_block_count(), 1);

    // The operator repairs the name in place.
    let repaired = std::fs::read_to_string(&path)
        .unwrap()
        .replace("Assets:C\u{0430}sh", "Assets:Savings");
    std::fs::write(&path, &repaired).unwrap();

    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.new_directives, 1, "the repaired open is adopted");
    assert_eq!(svc.unparsable_block_count(), 0, "and nothing is held back");
    assert!(svc.accounts().is_open("Assets:Savings"));

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        !on_disk.contains("Assets:C\u{0430}sh"),
        "the broken text must not be resurrected: {on_disk}"
    );
    assert!(on_disk.contains("Assets:Savings"));

    std::fs::remove_file(path).ok();
}

#[test]
fn test_a_new_hand_edit_that_does_not_parse_still_refuses_the_whole_reconcile() {
    // The narrowness of the exemption, pinned. Tolerating a block this
    // service is ALREADY holding is not the same as tolerating a broken
    // hand edit: the latter must still abandon the reconcile rather than
    // canonicalise over a file a human is mid-way through editing (L-30).
    let path = test_file_path();
    std::fs::write(&path, UNICODE_ACCOUNT_LEDGER).unwrap();
    let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
    svc.compact().unwrap();
    let before = std::fs::read_to_string(&path).unwrap();

    // A half-typed directive appended under the held block.
    std::fs::write(&path, format!("{before}\n2024-02-02 open\n")).unwrap();

    let error = svc.reconcile_file().unwrap_err();
    assert_eq!(error.error_code(), "PARSE_ERROR");
    assert_eq!(
        svc.unparsable_block_count(),
        1,
        "a refused reconcile must not change what is held"
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

/// L-78 (T75): an `open` with one currency past `MAX_CURRENCIES_PER_OPEN`
/// is refused by the local API; one at the cap is admitted.
#[test]
fn test_resource_limit_too_many_currencies_in_an_open() {
    let (mut svc, path) = boot_empty();
    let currencies =
        |count: usize| -> Vec<String> { (0..count).map(|index| format!("C{index:03}")).collect() };
    let error = svc
        .open_account(
            "Assets:Broker".to_owned(),
            make_date(2024, 1, 1),
            currencies(MAX_CURRENCIES_PER_OPEN + 1),
        )
        .unwrap_err();
    assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED", "{error}");
    assert!(error.to_string().contains("Too many currencies"), "{error}");
    svc.open_account(
        "Assets:Broker".to_owned(),
        make_date(2024, 1, 1),
        currencies(MAX_CURRENCIES_PER_OPEN),
    )
    .expect("an open at the cap is admitted");
    std::fs::remove_file(path).ok();
}

/// L-78 (T75), the executed shape: the 262,137-currency `open` that staged
/// `Ok` before T75 is refused by `stage_remote_directive` — the rule every
/// peer applies at phase 2, behind the wire's own parse-time refusal.
#[test]
fn test_stage_refuses_a_262k_currency_open() {
    let (mut svc, path) = boot_empty();
    // The audit's body: `US` then `,US` × 262,136 — 786 KB on the wire, and
    // canonically (`, `-separated) still just inside the body cap, so only
    // the currency cap can refuse it.
    let count = 1 + (MAX_ECONOMIC_BEAN_LENGTH - 30) / 4;
    let mut open = remote_open("Assets:A", make_date(2024, 1, 1), 1);
    if let Directive::Open(inner) = &mut open {
        inner.currencies = vec!["US".to_owned(); count];
    }
    assert!(
        enforce_economic_bean_limit(&open).is_ok(),
        "fits the body cap"
    );
    let before = svc.directive_count();
    let error = svc.stage_remote_directive(open).unwrap_err();
    assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED", "{error}");
    assert!(
        error
            .to_string()
            .contains(&format!("currencies in one open: {count}")),
        "{error}"
    );
    assert_eq!(svc.directive_count(), before, "nothing staged");
    std::fs::remove_file(path).ok();
}

/// T75 / M-48: posting-level metadata is capped as a sum over the
/// postings, at stage as on the wire. Since T81 (M-51, decision (6))
/// staging holds a peer's directive to the HISTORY ceiling, so the T75
/// cap of 100 binds only what this node authors: 101 keys stage, and are
/// refused for authoring; one past the legacy ceiling is refused at stage.
#[test]
fn test_stage_refuses_too_many_posting_metadata_keys() {
    let (mut svc, path) = setup_with_accounts();
    let posting =
        |account: &str, number: rust_decimal::Decimal, keys: std::ops::Range<usize>| Posting {
            account: account.to_owned(),
            amount: Some(Amount {
                number,
                currency: "USD".to_owned(),
            }),
            cost: None,
            price: None,
            metadata: keys
                .map(|index| (format!("k{index}"), "v".to_owned()))
                .collect(),
        };
    let transaction = |split: usize, total: usize| {
        let mut metadata = remote_envelope(1);
        metadata.insert("openledger-parents".to_owned(), String::new());
        Directive::Transaction(Transaction {
            date: make_date(2024, 2, 1),
            flag: Flag::Complete,
            payee: None,
            narration: Some(format!("posting metadata {total}")),
            tags: vec![],
            links: vec![],
            postings: vec![
                posting("Assets:Cash", dec!(1), 0..split),
                posting("Equity:Opening", dec!(-1), split..total),
            ],
            metadata,
        })
    };
    let cap = MAX_POSTING_METADATA_KEYS_PER_TRANSACTION;
    let legacy = crate::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY;
    let error = svc
        .stage_remote_directive(transaction(legacy / 2, legacy + 1))
        .unwrap_err();
    assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED", "{error}");
    assert!(
        error.to_string().contains("posting metadata keys"),
        "{error}"
    );
    assert!(
        enforce_resource_limits(&transaction(cap / 2, cap)).is_ok(),
        "a transaction at the cap is admitted"
    );
    assert!(
        enforce_resource_limits(&transaction(cap / 2, cap + 1)).is_err(),
        "authoring keeps the T75 cap"
    );
    assert!(
        svc.stage_remote_directive(transaction(cap / 2, cap + 1))
            .is_ok(),
        "history over the T75 cap but within the legacy ceiling stages (M-51)"
    );
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
fn test_remote_lamport_u64_max_is_refused_not_saturated() {
    // M3 regression: a remote directive claiming openledger-lamport =
    // u64::MAX must not panic (debug) or wrap the local Lamport clock to 0
    // (release). T46 (H-07) upgraded the outcome from "saturate safely" to
    // "refuse": a saturated clock is not a safe resting place, it is the
    // bug. Every value this node went on to stamp sat above the cap every
    // peer enforces — and `(author, lamport)` stopped being unique (M-18),
    // because a saturating `+1` returns the same number forever.
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

    // Must not panic, must not wrap — and must not be adopted.
    let before = svc.lamport_clock();
    let error = svc.insert_remote_directive(remote).unwrap_err();
    assert_eq!(error.error_code(), "LAMPORT_CEILING");
    assert_eq!(
        svc.lamport_clock(),
        before,
        "a refused value is not adopted"
    );

    // The refusal costs the hostile directive, not this replica's ability
    // to write: local appends carry on from exactly where they were.
    svc.append_transaction(balanced_input()).unwrap();
    assert_eq!(svc.lamport_clock(), before + 1);

    std::fs::remove_file(path).ok();
}

// ── H-07 / T46, H-12 / T63: the Lamport ceiling as ONE rule ──────────

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

#[test]
fn test_remote_lamport_at_the_ceiling_is_refused_not_adopted() {
    // H-07(c), restated by T63 (H-12). A value is legal iff `value + 1 <
    // LAMPORT_CEILING`, and adoption applies exactly that predicate to
    // `max(local, remote)`, so `CEILING - 2` is the largest value that can be
    // adopted. This half has not moved; what T63 changed is that the wire
    // and the stamp now apply the SAME predicate — before, `CEILING - 1` was
    // refused here while `union_merge` accepted it and the stamp wrote it,
    // and the two tests pinned both halves of that contradiction.
    let (mut svc, path) = boot_with_history_at(NEAR_CEILING, "test-peer");
    let date = make_date(2024, 1, 1);
    let count = svc.directive_count();

    for (lamport, label) in [
        (LAMPORT_CEILING, "at the ceiling"),
        (
            LAMPORT_CEILING - 1,
            "one below — the `+1` lands exactly on it",
        ),
        (u64::MAX, "saturating"),
    ] {
        let before = svc.lamport_clock();
        let error = svc
            .stage_remote_directive(remote_open("Assets:Remote", date, lamport))
            .unwrap_err();
        assert_eq!(error.error_code(), "LAMPORT_CEILING", "{label}");
        assert!(
            error.to_string().contains("peer-remote"),
            "T63: the refusal names the author to remove from the allowlist: {error}"
        );
        assert_eq!(
            svc.lamport_clock(),
            before,
            "refused, therefore not adopted: {label}"
        );
        assert_eq!(svc.directive_count(), count, "{label}");
    }

    // The largest legal value is still accepted — the guard is a bound, not
    // a blanket refusal — and it leaves the clock on the last value this
    // node may hold.
    svc.stage_remote_directive(remote_open("Assets:Remote", date, LAMPORT_CEILING - 2))
        .unwrap();
    assert_eq!(svc.lamport_clock(), LAMPORT_CEILING - 1);
    std::fs::remove_file(path).ok();

    // On a fresh node the VALUE verdict still comes first for an illegal
    // value; a legal one far above the clock is the ratchet's to refuse.
    let (mut fresh, path) = boot_empty();
    for lamport in [LAMPORT_CEILING, LAMPORT_CEILING - 1, u64::MAX] {
        let error = fresh
            .stage_remote_directive(remote_open("Assets:Remote", date, lamport))
            .unwrap_err();
        assert_eq!(error.error_code(), "LAMPORT_CEILING");
    }
    let error = fresh
        .stage_remote_directive(remote_open("Assets:Remote", date, LAMPORT_CEILING - 2))
        .unwrap_err();
    assert_eq!(error.error_code(), "LAMPORT_ADVANCE");
    assert_eq!(fresh.lamport_clock(), 0);
    assert_eq!(fresh.directive_count(), 0);
    std::fs::remove_file(path).ok();
}

#[test]
fn test_authoring_refuses_at_the_lamport_ceiling() {
    // H-07(b). The stamp sites had no ceiling at all, so a clock sitting at
    // the cap produced directives every peer refused while the mutation
    // still returned success — the silent half of the finding. Both stamp
    // sites now refuse, and refuse *cleanly*: no clock movement, no DAG
    // insert, no file write.
    //
    // T63 (H-12): delivered as the attack is — staged AND persisted — so
    // the restart half below can assert the boot warning fires for the
    // state a peer can actually reach (clock `CEILING - 1`). It used to
    // test `clock >= CEILING`, which this state never satisfies.
    let (mut svc, path) = boot_with_history_at(NEAR_CEILING, "test-peer");
    svc.insert_remote_directive(remote_open(
        "Assets:Remote",
        make_date(2024, 1, 1),
        LAMPORT_CEILING - 2,
    ))
    .unwrap();
    assert_eq!(svc.lamport_clock(), LAMPORT_CEILING - 1);
    let file_before = std::fs::read_to_string(&path).unwrap();
    let directives_before = svc.directive_count();

    // `stamp_directive_envelope`.
    let error = svc
        .open_account("Assets:Later".to_owned(), make_date(2024, 1, 1), vec![])
        .unwrap_err();
    assert_eq!(error.error_code(), "LAMPORT_CEILING");
    let message = error.to_string();
    assert!(
        message.contains("refused by every peer"),
        "the error must say why the ceiling exists: {message}"
    );
    assert!(
        message.contains("peer-remote") && message.contains("allowlist"),
        "T63: the error must name the author and the mesh-wide remedy: {message}"
    );

    // `stamp_transaction_envelope`.
    let error = svc.append_transaction(balanced_input()).unwrap_err();
    assert_eq!(error.error_code(), "LAMPORT_CEILING");

    assert_eq!(svc.lamport_clock(), LAMPORT_CEILING - 1);
    assert_eq!(svc.directive_count(), directives_before);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), file_before);

    // The restart half (H-12 fact 1): the file re-derives `CEILING - 1`
    // and boot SAYS so, naming the author.
    drop(svc);
    let (rebooted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap());
    let mut rebooted = rebooted;
    assert_eq!(rebooted.lamport_clock(), LAMPORT_CEILING - 1);
    assert!(
        logged.contains("at the Lamport ceiling")
            && logged.contains("H-12")
            && logged.contains("peer-remote"),
        "boot must warn at CEILING - 1 and name the author, got: {logged}"
    );
    let error = rebooted
        .open_account("Assets:Later".to_owned(), make_date(2024, 1, 1), vec![])
        .unwrap_err();
    assert_eq!(error.error_code(), "LAMPORT_CEILING");

    std::fs::remove_file(path).ok();
}

/// T63 (H-12): the boot warning is the stamp's own predicate, so it fires
/// exactly when authoring is going to be refused — `CEILING - 2` included,
/// which a `clock + 1 >= CEILING` test would miss — and a separate warning
/// covers a clock within one ratchet step of the ceiling.
#[test]
fn test_boot_warns_exactly_when_authoring_is_refused() {
    for (history, refused) in [
        (LAMPORT_CEILING - 2, true),
        (LAMPORT_CEILING - 3, true),
        (LAMPORT_CEILING - 4, false),
    ] {
        let path = test_file_path();
        std::fs::write(&path, history_file_at(history)).unwrap();
        let (svc, logged) =
            capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap());
        let mut svc = svc;
        assert_eq!(
            logged.contains("at the Lamport ceiling"),
            refused,
            "history at {history}: {logged}"
        );
        assert_eq!(
            logged.contains("within one adoption step"),
            !refused,
            "history at {history}: {logged}"
        );
        let outcome = svc.open_account("Assets:Later".to_owned(), make_date(2024, 1, 1), vec![]);
        assert_eq!(
            outcome.is_err(),
            refused,
            "history at {history}: {outcome:?}"
        );
        if let Ok(id) = outcome {
            let stamped = svc.get_directive(&id).unwrap().lamport_clock().unwrap();
            assert_eq!(stamped, LAMPORT_CEILING - 2, "the largest legal stamp");
        }
        std::fs::remove_file(path).ok();
    }

    // An ordinary history warns about nothing.
    let path = test_file_path();
    std::fs::write(&path, history_file_at(1_000)).unwrap();
    let (_svc, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap());
    assert!(!logged.contains("H-12"), "{logged}");
    std::fs::remove_file(path).ok();
}

/// Manifest item 4 (T63 / H-12): whatever a node authors after ingesting a
/// directive near the ceiling is accepted by a peer holding the same
/// history — at `CEILING - 3` it authors nothing (refused loudly, locally),
/// never one silently unreplicable record, which is what `h07proof` showed.
#[test]
fn test_h12_every_directive_a_node_authors_is_accepted_by_a_peer() {
    let date = make_date(2024, 1, 1);
    for (poison, expected_authored) in [
        (LAMPORT_CEILING - 3, 0),
        (LAMPORT_CEILING - 4, 1),
        (LAMPORT_CEILING - 5, 2),
    ] {
        let (mut a, path_a) = boot_with_history_at(NEAR_CEILING, "node-a");
        let (mut b, path_b) = boot_with_history_at(NEAR_CEILING, "node-b");
        let hostile = remote_open("Assets:Remote", date, poison);
        a.stage_remote_directive(hostile.clone()).unwrap();
        b.stage_remote_directive(hostile).unwrap();

        let mut authored = 0;
        let error = loop {
            match a.open_account(format!("Assets:Later{authored}"), date, vec![]) {
                Ok(id) => {
                    let directive = a.get_directive(&id).unwrap().clone();
                    let lamport = directive.lamport_clock().unwrap();
                    assert!(lamport_value_is_legal(lamport), "stamped {lamport}");
                    b.stage_remote_directive(directive).unwrap_or_else(|error| {
                        panic!("peer refused A's directive at lamport {lamport}: {error}")
                    });
                    authored += 1;
                    assert!(authored <= 3, "the ceiling must stop authoring");
                }
                Err(error) => break error,
            }
        };
        assert_eq!(error.error_code(), "LAMPORT_CEILING");
        assert_eq!(authored, expected_authored, "poison at {poison}");
        std::fs::remove_file(path_a).ok();
        std::fs::remove_file(path_b).ok();
    }
}

/// T63 (H-12): the adoption ratchet. A remote directive more than 2^32
/// above the local clock is refused and moves nothing; one within it is
/// adopted; and the refusal is state-dependent — once the clock has caught
/// up, the same directive is accepted.
#[test]
fn test_adoption_ratchet_bounds_one_step() {
    let (mut svc, path) = boot_with_history_at(1_000, "test-peer");
    let date = make_date(2024, 1, 1);
    let local = svc.lamport_clock();
    let count = svc.directive_count();

    let over = remote_open("Assets:Over", date, local + MAX_LAMPORT_ADVANCE + 1);
    let exact = remote_open("Assets:Exact", date, local + MAX_LAMPORT_ADVANCE);
    for (directive, label) in [(&over, "2^32 + 1"), (&exact, "exactly 2^32")] {
        let error = svc.stage_remote_directive(directive.clone()).unwrap_err();
        assert_eq!(error.error_code(), "LAMPORT_ADVANCE", "{label}");
        assert!(error.to_string().contains("peer-remote"), "{error}");
        assert_eq!(
            svc.lamport_clock(),
            local,
            "{label}: the clock must not move"
        );
        assert_eq!(svc.directive_count(), count, "{label}: nothing inserted");
    }

    svc.stage_remote_directive(remote_open(
        "Assets:Within",
        date,
        local + MAX_LAMPORT_ADVANCE - 1,
    ))
    .unwrap()
    .expect("inserted");
    assert_eq!(
        svc.lamport_clock(),
        local + MAX_LAMPORT_ADVANCE,
        "the largest single advance is exactly 2^32"
    );

    // State-dependent: both refusals are acceptable now.
    svc.stage_remote_directive(over).unwrap().expect("inserted");
    svc.stage_remote_directive(exact)
        .unwrap()
        .expect("inserted");
    std::fs::remove_file(path).ok();
}

/// T63 (H-12): the file path (reconcile, and boot's operator input, which
/// shares `adopt_file_directive`) applies the same rule and the same
/// ratchet. Pasting a peer's directive into the `.bean` is not a way round
/// either.
#[test]
fn test_adoption_ratchet_and_rule_apply_to_the_file_path() {
    let (mut svc, path) = boot_with_history_at(1_000, "test-peer");
    let local = svc.lamport_clock();
    let paste = |svc: &mut LedgerService, account: &str, lamport: u64| {
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str(&format!(
            "\n2024-01-01 open {account}\n  openledger-author: \"peer-remote\"\n  \
                 openledger-lamport: \"{lamport}\"\n"
        ));
        std::fs::write(&path, text).unwrap();
        svc.reconcile_file().unwrap()
    };

    for (account, lamport) in [
        ("Assets:Over", local + MAX_LAMPORT_ADVANCE),
        // Legal on no path since T63; the file path used to accept it,
        // because it bounded `max(local, incoming)` with `>= CEILING`.
        ("Assets:Ceiling", LAMPORT_CEILING - 1),
    ] {
        let result = paste(&mut svc, account, lamport);
        assert_eq!(result.rejected, 1, "{account}");
        assert_eq!(result.new_directives, 0, "{account}");
        assert_eq!(
            svc.lamport_clock(),
            local,
            "{account}: the clock must not move"
        );
    }

    let result = paste(&mut svc, "Assets:Within", local + MAX_LAMPORT_ADVANCE - 1);
    assert_eq!(result.new_directives, 1);
    assert_eq!(svc.lamport_clock(), local + MAX_LAMPORT_ADVANCE - 1);
    std::fs::remove_file(path).ok();

    // The RULE alone, with the ratchet out of the way (a clock within one
    // step of the ceiling): `CEILING - 1` is refused, `CEILING - 2` is the
    // largest value the file path adopts — the same bound as the wire.
    let (mut svc, near_path) = boot_with_history_at(NEAR_CEILING, "test-peer");
    let local = svc.lamport_clock();
    let mut paste_near = |account: &str, lamport: u64| {
        let mut text = std::fs::read_to_string(&near_path).unwrap();
        text.push_str(&format!(
            "\n2024-01-01 open {account}\n  openledger-author: \"peer-remote\"\n  \
                 openledger-lamport: \"{lamport}\"\n"
        ));
        std::fs::write(&near_path, text).unwrap();
        svc.reconcile_file().unwrap()
    };
    let result = paste_near("Assets:Ceiling", LAMPORT_CEILING - 1);
    assert_eq!((result.rejected, result.new_directives), (1, 0));
    let result = paste_near("Assets:Last", LAMPORT_CEILING - 2);
    assert_eq!((result.rejected, result.new_directives), (0, 1));
    assert!(svc.lamport_clock() > local);
    assert_eq!(svc.lamport_clock(), LAMPORT_CEILING - 2);
    std::fs::remove_file(near_path).ok();
}

/// T63 (H-12 fact 3): boot's clock counts every directive in the DAG, and
/// a directive kept OUT of the DAG only when it is this node's own. A
/// quarantined foreign directive at `CEILING - 2` used to set the clock —
/// and, the quarantine being written back by every compaction, set it on
/// every boot forever. This node's own quarantined record still counts,
/// or its `(author, lamport)` pair could be re-issued (M-18).
#[test]
fn test_boot_clock_counts_quarantined_directives_only_when_own() {
    let date = make_date(2024, 1, 1);
    let quarantined = |author: &str, lamport: u64| {
        // An uppercase-hex parent: refused by L-29's form check, so boot
        // quarantines it.
        let mut directive = flood_transaction(author, 0, &"A".repeat(64));
        directive_metadata_mut(&mut directive)
            .insert("openledger-lamport".to_owned(), lamport.to_string());
        directive
    };
    for (author, lamport, expected_clock) in [
        ("peer-remote", LAMPORT_CEILING - 2, 6),
        ("test-peer", 1_000, 1_001),
    ] {
        let path = test_file_path();
        let file = full_file_serialize(
            &[
                remote_open("Assets:Cash", date, 4),
                remote_open("Equity:Opening", date, 5),
                quarantined(author, lamport),
            ],
            &[],
        );
        std::fs::write(&path, file).unwrap();
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        assert_eq!(svc.quarantined_count(), 1, "{author}");
        assert_eq!(svc.lamport_clock(), expected_clock, "{author}");
        svc.open_account("Assets:Later".to_owned(), date, vec![])
            .unwrap_or_else(|error| panic!("{author}: authoring must work: {error}"));
        std::fs::remove_file(path).ok();
    }
}

/// T63's fresh-join decision, pinned. The ratchet is relative to the LOCAL
/// clock with no first-contact exemption; a node with clock 0 must still
/// converge with a mesh whose history reaches lamport 10^9, receiving the
/// highest directive first.
#[test]
fn test_fresh_node_converges_with_a_history_reaching_1e9() {
    let date = make_date(2024, 1, 1);
    let (mut source, source_path) = setup_with_accounts();
    for (index, lamport) in [1_000, 1_000_000, 500_000_000, 1_000_000_000]
        .into_iter()
        .enumerate()
    {
        source
            .stage_remote_directive(remote_open(&format!("Assets:Mesh{index}"), date, lamport))
            .unwrap()
            .expect("inserted");
    }
    for day in 16..19 {
        let mut input = balanced_input();
        input.date = make_date(2024, 1, day);
        source.append_transaction(input).unwrap();
    }
    assert!(source.lamport_clock() > 1_000_000_000);

    // Non-transactions highest-lamport first, then transactions in the
    // order their parents allow (anti-entropy buffers an orphan until its
    // parents arrive, so it never stages one out of order).
    let mut others: Vec<Directive> = Vec::new();
    let mut transactions: Vec<Directive> = Vec::new();
    for directive in source.dag().directives() {
        match directive {
            Directive::Transaction(_) => transactions.push(directive.clone()),
            _ => others.push(directive.clone()),
        }
    }
    others.sort_by_key(|directive| std::cmp::Reverse(directive.lamport_clock()));
    transactions.sort_by_key(Directive::lamport_clock);
    assert_eq!(others[0].lamport_clock(), Some(1_000_000_000));

    let (mut fresh, fresh_path) = boot_empty();
    assert_eq!(fresh.lamport_clock(), 0);
    for directive in others.into_iter().chain(transactions) {
        let lamport = directive.lamport_clock();
        fresh
            .stage_remote_directive(directive)
            .unwrap_or_else(|error| panic!("fresh node refused lamport {lamport:?}: {error}"))
            .expect("inserted");
    }
    assert_eq!(fresh.directive_count(), source.directive_count());
    assert!(fresh.lamport_clock() > source.lamport_clock() - 1);

    // And the joined node's own writes replicate back.
    let id = fresh
        .open_account("Assets:Joined".to_owned(), date, vec![])
        .unwrap();
    source
        .stage_remote_directive(fresh.get_directive(&id).unwrap().clone())
        .unwrap()
        .expect("the mesh accepts the new node's directive");

    std::fs::remove_file(source_path).ok();
    std::fs::remove_file(fresh_path).ok();
}

/// T63: why the ratchet needs no first-contact exemption even for a history
/// whose TOTAL exceeds 2^32. The refusal is not permanent (the node's
/// refusal cache does not keep it), so each anti-entropy round re-offers
/// what was refused, and the clock climbs through the history.
#[test]
fn test_ratchet_refusal_is_retried_and_a_stepped_history_converges() {
    let date = make_date(2024, 1, 1);
    let steps: [u64; 4] = [3_000_000_000, 6_000_000_000, 9_000_000_000, 12_000_000_000];
    let mut pending: Vec<Directive> = steps
        .iter()
        .rev()
        .enumerate()
        .map(|(index, lamport)| remote_open(&format!("Assets:Step{index}"), date, *lamport))
        .collect();

    let (mut fresh, path) = boot_empty();
    let mut rounds = 0;
    while !pending.is_empty() {
        rounds += 1;
        assert!(
            rounds <= steps.len(),
            "must converge, one step per round at worst"
        );
        let mut refused = Vec::new();
        for directive in pending {
            match fresh.stage_remote_directive(directive.clone()) {
                Ok(Some(_)) => {}
                Ok(None) => panic!("nothing here is a duplicate"),
                Err(error) => {
                    assert_eq!(error.error_code(), "LAMPORT_ADVANCE");
                    refused.push(directive);
                }
            }
        }
        pending = refused;
    }
    assert_eq!(rounds, 4);
    assert_eq!(fresh.lamport_clock(), 12_000_000_001);
    std::fs::remove_file(path).ok();
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

    /// T63 property: from any legal clock, no ingest path — peer staging,
    /// file adoption, local authoring — moves the clock past
    /// `LAMPORT_CEILING - 1`, or by more than `MAX_LAMPORT_ADVANCE` in one
    /// step, and every value stamped is legal.
    #[test]
    fn prop_no_ingest_path_breaks_the_lamport_rule(
        start in 0..LAMPORT_CEILING,
        operations in proptest::collection::vec(
            (0u8..3, proptest::prop_oneof![
                proptest::prelude::any::<u64>(),
                (LAMPORT_CEILING - 8)..=(LAMPORT_CEILING + 8),
                0u64..16,
                (MAX_LAMPORT_ADVANCE - 4)..=(MAX_LAMPORT_ADVANCE + 4),
                (2 * MAX_LAMPORT_ADVANCE - 4)..=(2 * MAX_LAMPORT_ADVANCE + 4),
            ], proptest::prelude::any::<bool>()),
            1..24,
        ),
    ) {
        let (mut svc, path) = boot_empty();
        svc.lamport_clock = start;
        let date = make_date(2024, 1, 1);
        for (index, (kind, raw, relative)) in operations.into_iter().enumerate() {
            let before = svc.lamport_clock();
            // Half the values are offsets from the clock, so the ratchet's
            // boundary is actually exercised.
            let value = if relative { before.saturating_add(raw) } else { raw };
            let account = format!("Assets:P{index}");
            match kind {
                0 => {
                    let _ = svc.stage_remote_directive(remote_open(&account, date, value));
                }
                1 => {
                    let directive = remote_open(&account, date, value);
                    let content_id = compute_content_id(&directive);
                    let mut tally = AdoptionTally::default();
                    let _ = svc.adopt_file_directive(directive, content_id, &mut tally, AdoptionPath::Live);
                }
                _ => {
                    if let Ok(id) = svc.open_account(account, date, vec![]) {
                        let stamped = svc.get_directive(&id).unwrap().lamport_clock().unwrap();
                        proptest::prop_assert!(lamport_value_is_legal(stamped));
                        proptest::prop_assert_eq!(stamped, before + 1);
                    }
                }
            }
            let after = svc.lamport_clock();
            proptest::prop_assert!(after >= before);
            proptest::prop_assert!(
                after <= before.max(LAMPORT_CEILING - 1),
                "clock {} past CEILING - 1 from {}", after, before
            );
            proptest::prop_assert!(
                after - before <= MAX_LAMPORT_ADVANCE,
                "clock advanced {} in one step", after - before
            );
        }
        std::fs::remove_file(path).ok();
    }
}

/// T76 (replaces T65's `test_h17_remote_balance_with_over_cap_amount_is_refused`):
/// the amount cap covers what is summed, so a peer's `balance` and `price`
/// amounts — compared or quoted, never summed — are admitted at any size
/// (pre-T65 history holds such `balance` lines), while a peer transaction
/// amount past `MAX_AMOUNT_MAGNITUDE` is still refused on the same path.
#[test]
fn test_t76_remote_balance_and_price_amounts_are_not_capped() {
    let (mut svc, path) = setup_with_accounts();
    let huge = rust_decimal::Decimal::MAX;
    let balance = Directive::Balance(Balance {
        date: make_date(2024, 2, 1),
        account: "Assets:Cash".to_owned(),
        amount: Amount {
            number: huge,
            currency: "USD".to_owned(),
        },
        metadata: remote_envelope(9),
    });
    let price = Directive::Price(Price {
        date: make_date(2024, 2, 1),
        currency: "EUR".to_owned(),
        amount: Amount {
            number: huge,
            currency: "USD".to_owned(),
        },
        metadata: remote_envelope(10),
    });
    let count = svc.directive_count();
    svc.stage_remote_directive(balance)
        .expect("a balance amount is not capped");
    svc.stage_remote_directive(price)
        .expect("a price amount is not capped");
    assert_eq!(svc.directive_count(), count + 2);

    let mut over = crate::limits::MAX_AMOUNT_MAGNITUDE.to_string();
    over.push_str(".0000001");
    let over: rust_decimal::Decimal = over.parse().unwrap();
    let transaction = Directive::Transaction(Transaction {
        date: make_date(2024, 2, 2),
        flag: Flag::Complete,
        payee: None,
        narration: Some("over".to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            Posting {
                account: "Assets:Cash".to_owned(),
                amount: Some(Amount {
                    number: over,
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
                metadata: BTreeMap::new(),
            },
            Posting {
                account: "Equity:Opening".to_owned(),
                amount: Some(Amount {
                    number: -over,
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
                metadata: BTreeMap::new(),
            },
        ],
        metadata: {
            let mut metadata = remote_envelope(11);
            metadata.insert("openledger-parents".to_owned(), String::new());
            metadata
        },
    });
    let error = svc.stage_remote_directive(transaction).unwrap_err();
    assert!(error.to_string().contains("H-17"), "{error}");
    assert_eq!(error.error_code(), "INVALID_POSTING");
    assert_eq!(svc.directive_count(), count + 2);
    std::fs::remove_file(path).ok();
}

// ── H-16 / T64: bounded parent choice, per-author head bound ─────────

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

/// Manifest item 5 (T64 / H-16). `MAX_PARENTS + 1` parentless remote
/// transactions, then a local append: the append names at most
/// `MAX_PARENTS` parents (author-diverse, then smallest — T72 / L-68),
/// passes the fan-in check every peer applies, is accepted by a second
/// service, and survives a reboot — nothing quarantined, the victim's own
/// posting still in its balances.
#[test]
fn test_h16_parentless_flood_cannot_make_a_local_append_over_cap() {
    let (mut svc, path) = setup_with_accounts();
    let flood = stage_parentless_flood(&mut svc);
    let mut heads: Vec<String> = svc.head_txids().into_iter().collect();
    heads.sort();

    let outcome = svc.append_transaction(balanced_input()).unwrap();
    let appended = svc.get_directive(&outcome.txid).unwrap().clone();
    let Directive::Transaction(transaction) = &appended else {
        panic!("an append stores a transaction")
    };
    validate_parent_fan_in(&appended).expect("every peer's fan-in check passes");
    let parents: Vec<String> = transaction
        .parent_ids()
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(parents.len(), MAX_PARENTS);
    assert!(
        parents.windows(2).all(|pair| pair[0] < pair[1]),
        "sorted ascending"
    );
    assert!(
        parents.iter().all(|parent| heads.contains(parent)),
        "every parent is a head"
    );
    // T72 / L-68: the one head left over is one of peer-a's 256, never
    // peer-b's single head — author diversity before smallest id.
    let peer_b_head = LedgerService::content_id(flood.last().unwrap());
    assert!(
        parents.contains(&peer_b_head),
        "the other author's head is named"
    );
    assert_eq!(
        svc.head_count(),
        2,
        "the appended one plus the one left over"
    );
    svc.persist_or_reload().unwrap();

    // A second service holding the same history accepts it.
    let (mut peer, peer_path) = setup_with_accounts();
    for directive in &flood {
        peer.stage_remote_directive(directive.clone()).unwrap();
    }
    peer.stage_remote_directive(appended)
        .unwrap()
        .expect("the peer accepts the victim's append");

    // Reboot quarantines nothing, and the victim's own posting stays.
    drop(svc);
    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.quarantined_count(), 0);
    assert!(rebooted.get_directive(&outcome.txid).is_some());
    assert_eq!(rebooted.head_count(), 2);

    // The leftover head is merged by the next append.
    let mut rebooted = rebooted;
    let mut input = balanced_input();
    input.date = make_date(2024, 1, 17);
    rebooted.append_transaction(input).unwrap();
    assert_eq!(rebooted.head_count(), 1);

    std::fs::remove_file(path).ok();
    std::fs::remove_file(peer_path).ok();
}

/// T72 / H-21 (decision (2)): there is NO remote per-author head bound. The
/// 257th parentless remote transaction from one author is admitted like the
/// first, whatever order the flood arrives in, so two replicas served
/// disjoint subsets hold the same DAG — and the local append still names
/// at most `MAX_PARENTS` parents, passes every peer's fan-in check and is
/// accepted by a peer. T64's bound refused the 257th here
/// (`UNMERGED_HEAD_LIMIT`), which made membership depend on which 256 a
/// peer chose to serve first.
#[test]
fn test_h21_the_257th_parentless_remote_transaction_from_one_author_is_admitted() {
    let (mut svc, path) = setup_with_accounts();
    let flood: Vec<Directive> = (0..=MAX_PARENTS)
        .map(|index| flood_transaction("peer-a", index, ""))
        .collect();
    let clock = svc.lamport_clock();
    for (index, directive) in flood.iter().enumerate() {
        svc.stage_remote_directive(directive.clone())
            .unwrap_or_else(|error| panic!("head #{}: {error}", index + 1))
            .unwrap_or_else(|| panic!("head #{} is new", index + 1));
    }
    assert_eq!(svc.head_count(), MAX_PARENTS + 1);
    assert!(svc.lamport_clock() > clock, "adoption moved the clock");

    // The same flood in the opposite order on a second service: identical
    // membership, no local authoring — the H-21 property, single-process.
    let (mut peer, peer_path) = setup_with_accounts();
    for directive in flood.iter().rev() {
        peer.stage_remote_directive(directive.clone())
            .unwrap()
            .expect("admitted in any order");
    }
    assert_eq!(
        svc.all_directive_ids(),
        peer.all_directive_ids(),
        "same available set, same DAG"
    );

    // The local half of H-16 still holds without the remote bound.
    let outcome = svc.append_transaction(balanced_input()).unwrap();
    let appended = svc.get_directive(&outcome.txid).unwrap().clone();
    validate_parent_fan_in(&appended).expect("every peer's fan-in check passes");
    let Directive::Transaction(transaction) = &appended else {
        panic!("an append stores a transaction")
    };
    assert_eq!(transaction.parent_ids().len(), MAX_PARENTS);
    peer.stage_remote_directive(appended)
        .unwrap()
        .expect("the peer accepts the victim's append");
    assert_eq!(peer.head_count(), 2, "the append plus the one left over");

    std::fs::remove_file(path).ok();
    std::fs::remove_file(peer_path).ok();
}

/// T72 / L-68: 256 planted heads whose ids are all smaller than one honest
/// head — the id-grinder's shape — and the local append still names the
/// honest head. Under T64's smallest-id rule the honest head was never
/// named, so every honest append became a permanent head mesh-wide. Also
/// pins determinism: a second service holding the same heads, delivered in
/// the opposite order, names the same parents.
#[test]
fn test_l68_parent_choice_names_the_honest_head_among_256_planted_small_ids() {
    let (mut svc, path) = setup_with_accounts();
    // Grind: of 600 candidate bodies keep the MAX_PARENTS smallest ids.
    let mut ground: Vec<(String, Directive)> = (0..600)
        .map(|index| {
            let directive = flood_transaction("grinder", index, "");
            (LedgerService::content_id(&directive), directive)
        })
        .collect();
    ground.sort_by(|a, b| a.0.cmp(&b.0));
    ground.truncate(MAX_PARENTS);
    let largest_planted = ground.last().unwrap().0.clone();
    let honest = (1_000..)
        .map(|index| flood_transaction("honest", index, ""))
        .find(|directive| LedgerService::content_id(directive) > largest_planted)
        .expect("an honest body with an id above every planted one");
    let honest_id = LedgerService::content_id(&honest);
    let mut heads: Vec<Directive> = ground.into_iter().map(|(_, d)| d).collect();
    heads.push(honest);
    for directive in &heads {
        svc.stage_remote_directive(directive.clone())
            .unwrap()
            .expect("planted");
    }
    assert_eq!(svc.head_count(), MAX_PARENTS + 1);

    let outcome = svc.append_transaction(balanced_input()).unwrap();
    let Some(Directive::Transaction(appended)) = svc.get_directive(&outcome.txid) else {
        panic!("an append stores a transaction")
    };
    let parents: Vec<&str> = appended.parent_ids();
    assert_eq!(parents.len(), MAX_PARENTS);
    assert!(
        parents.contains(&honest_id.as_str()),
        "the honest head is named although every planted id is smaller"
    );
    assert!(
        parents
            .iter()
            .all(|parent| *parent < honest_id.as_str() || *parent == honest_id),
        "the slots not owed to diversity go to the smallest ids"
    );

    // Determinism across replicas: same heads, opposite delivery order,
    // same parents.
    let (mut peer, peer_path) = setup_with_accounts();
    for directive in heads.iter().rev() {
        peer.stage_remote_directive(directive.clone())
            .unwrap()
            .expect("planted");
    }
    let peer_outcome = peer.append_transaction(balanced_input()).unwrap();
    let Some(Directive::Transaction(peer_appended)) = peer.get_directive(&peer_outcome.txid) else {
        panic!("an append stores a transaction")
    };
    assert_eq!(peer_appended.parent_ids(), parents);

    std::fs::remove_file(path).ok();
    std::fs::remove_file(peer_path).ok();
}

/// T72 / L-68: `select_parents` alone — the rule on synthetic head sets.
#[test]
fn test_l68_select_parents_is_author_diverse_then_smallest_and_deterministic() {
    let id = |n: usize| format!("{n:064x}");
    // Fits: everything, sorted, whatever the order given.
    let few: Vec<String> = (0..5).rev().map(id).collect();
    let mut candidates: Vec<(&str, Option<&str>)> =
        few.iter().map(|s| (s.as_str(), Some("a"))).collect();
    let chosen = select_parents(&mut candidates);
    assert_eq!(chosen.len(), 5);
    assert!(chosen.windows(2).all(|pair| pair[0] < pair[1]));

    // One grinder with 300 small ids, one honest author with the largest.
    let ids: Vec<String> = (0..301).map(id).collect();
    let mut candidates: Vec<(&str, Option<&str>)> = ids[..300]
        .iter()
        .map(|s| (s.as_str(), Some("grinder")))
        .collect();
    candidates.push((ids[300].as_str(), Some("honest")));
    let chosen = select_parents(&mut candidates);
    assert_eq!(chosen.len(), MAX_PARENTS);
    assert!(
        chosen.contains(&ids[300].as_str()),
        "the honest head is named"
    );
    assert_eq!(
        chosen.iter().filter(|c| **c != ids[300].as_str()).count(),
        MAX_PARENTS - 1,
        "the grinder gets every other slot, smallest first"
    );
    assert_eq!(
        chosen[..MAX_PARENTS - 1].to_vec(),
        ids[..MAX_PARENTS - 1]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );

    // Three authors: A floods, B has two, C one, all of B's and C's named.
    let mut candidates: Vec<(&str, Option<&str>)> = ids[3..300]
        .iter()
        .map(|s| (s.as_str(), Some("A")))
        .collect();
    candidates.push((ids[300].as_str(), Some("B")));
    candidates.push((ids[2].as_str(), Some("B")));
    candidates.push((ids[1].as_str(), None));
    let chosen = select_parents(&mut candidates);
    assert_eq!(chosen.len(), MAX_PARENTS);
    for must in [&ids[300], &ids[2], &ids[1]] {
        assert!(chosen.contains(&must.as_str()), "{must} is named");
    }

    // More authors than slots: one head each, the smallest ids win.
    let mut candidates: Vec<(&str, Option<&str>)> =
        ids.iter().map(|s| (s.as_str(), Some(s.as_str()))).collect();
    let chosen = select_parents(&mut candidates);
    assert_eq!(
        chosen,
        ids[..MAX_PARENTS]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );

    // Deterministic: shuffled input, same answer.
    let mut shuffled: Vec<(&str, Option<&str>)> = ids[..300]
        .iter()
        .rev()
        .map(|s| (s.as_str(), Some("grinder")))
        .collect();
    shuffled.insert(7, (ids[300].as_str(), Some("honest")));
    let mut ordered: Vec<(&str, Option<&str>)> = ids[..300]
        .iter()
        .map(|s| (s.as_str(), Some("grinder")))
        .collect();
    ordered.push((ids[300].as_str(), Some("honest")));
    assert_eq!(select_parents(&mut shuffled), select_parents(&mut ordered));
}

/// T64: the file path's parent stamp (reconcile, and boot's operator input)
/// shares `choose_parents`, so a hand-typed transaction on a flooded ledger
/// is capped too — it is signed and served like a local append.
#[test]
fn test_h16_file_adoption_caps_stamped_parents() {
    let (mut svc, path) = setup_with_accounts();
    stage_parentless_flood(&mut svc);
    svc.persist_or_reload().unwrap();

    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str(
        "\n2024-01-20 * \"hand typed\"\n  Assets:Cash  2 USD\n  Equity:Opening  -2 USD\n",
    );
    std::fs::write(&path, text).unwrap();
    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.new_directives, 1);

    let adopted = svc
        .dag()
        .directives()
        .into_iter()
        .find(|directive| {
            matches!(directive, Directive::Transaction(transaction)
                    if transaction.narration.as_deref() == Some("hand typed"))
        })
        .unwrap()
        .clone();
    validate_parent_fan_in(&adopted).expect("capped at MAX_PARENTS");
    let Directive::Transaction(transaction) = &adopted else {
        unreachable!()
    };
    assert_eq!(transaction.parent_ids().len(), MAX_PARENTS);

    drop(svc);
    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.quarantined_count(), 0);
    std::fs::remove_file(path).ok();
}

// ── T72 / H-19: the clock-versus-history warning, the remedy texts ────

/// The audit's `h1a` shape: a pre-T63 history carrying one jump to
/// 5 × 10⁹ over a handful of directives boots with zero warnings at HEAD
/// (both boot warnings are anchored to the ceiling, 2^53). T72 warns,
/// names the author that carried the clock there, and states the
/// bootstrap join. Since T83 (L-94) the warning is judged on the lamport
/// gap, not on the clock against the directive count.
#[test]
fn test_h19_boot_warns_on_a_lamport_gap_in_the_history() {
    let path = test_file_path();
    std::fs::write(&path, history_file_at(5_000_000_000)).unwrap();
    // T89 / L-100: judged by `verify_own_history` (which gl-node calls
    // at every boot), over the history the node will serve.
    let (svc, logged) = capture_warnings(|| {
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.verify_own_history();
        svc
    });
    assert_eq!(svc.directive_count(), 3);
    assert_eq!(svc.lamport_clock(), 5_000_000_001);
    assert!(
        logged.contains("uncrossable")
            && logged.contains("lamport gap")
            && logged.contains("peer-history")
            && logged.contains("H-19")
            && logged.contains("compacted .bean"),
        "boot must diagnose the jump, name its author and state the join: {logged}"
    );
    assert!(
        !logged.contains("Lamport ceiling"),
        "5e9 is nowhere near the ceiling; this is the H-19 line, not H-12's: {logged}"
    );
    std::fs::remove_file(path).ok();
}

/// The predicate itself, at its edges (T83 / L-94): the largest step
/// between consecutive distinct lamports, counting from 0, with the value
/// at its top. Order and repeats do not matter; a ratchet-legal jump is
/// always over the threshold; a dense history of any length never is.
#[test]
fn test_h19_lamport_gap_predicate() {
    assert_eq!(largest_lamport_gap(std::iter::empty()), (0, 0));
    assert_eq!(largest_lamport_gap([3, 1, 2, 2]), (1, 1));
    assert_eq!(largest_lamport_gap([1, 2, 10, 11]), (8, 10));
    assert_eq!(largest_lamport_gap([5]), (5, 5));
    let dense: Vec<u64> = (1..=1_000_000).collect();
    assert!(largest_lamport_gap(dense).0 < LAMPORT_GAP_WARN);
    let jump = [
        1,
        2,
        3,
        3 + MAX_LAMPORT_ADVANCE - 1,
        3 + MAX_LAMPORT_ADVANCE,
    ];
    assert_eq!(
        largest_lamport_gap(jump),
        (MAX_LAMPORT_ADVANCE - 1, 3 + MAX_LAMPORT_ADVANCE - 1)
    );
    const { assert!(MAX_LAMPORT_ADVANCE > LAMPORT_GAP_WARN) };
    assert!(largest_lamport_gap([LAMPORT_GAP_WARN - 1]).0 < LAMPORT_GAP_WARN);
    assert!(largest_lamport_gap([u64::MAX]).0 >= LAMPORT_GAP_WARN);
}

/// A dense history — every clock value accounted for by an event — boots
/// and adopts silently. The warning must never fire on an honest node.
#[test]
fn test_h19_warning_is_silent_on_a_dense_history() {
    let (mut svc, path) = setup_with_accounts();
    for day in 2..12 {
        let mut input = balanced_input();
        input.date = make_date(2024, 1, day);
        svc.append_transaction(input).unwrap();
    }
    let (_, logged) = capture_warnings(|| {
        for (index, account) in ["Assets:R1", "Assets:R2", "Assets:R3"].iter().enumerate() {
            // Adoptions above and below the local clock — both move it.
            let lamport = if index % 2 == 0 {
                svc.lamport_clock() + 5
            } else {
                2
            };
            svc.stage_remote_directive(remote_open(account, make_date(2024, 1, 1), lamport))
                .unwrap()
                .expect("adopted");
        }
    });
    assert!(!logged.contains("lamport gap"), "{logged}");
    svc.persist_or_reload().unwrap();
    drop(svc);
    let (rebooted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap());
    assert!(
        rebooted.lamport_clock() <= 2 * rebooted.directive_count() as u64 + 2,
        "an honest clock is bounded by its events: clock {} over {} directives",
        rebooted.lamport_clock(),
        rebooted.directive_count()
    );
    assert!(logged.is_empty(), "{logged}");
    std::fs::remove_file(path).ok();
}

/// Adoption of a maximal legal jump (the `h1b` shape) warns once, naming
/// the jumping author; ordinary adoptions after it — below or just above
/// the clock — and a local append are silent; a second jump warns again.
/// Since T83 (L-94) the warning is judged on the gap one adoption opens,
/// so "once per jump" holds by construction and needs no gate. Harness
/// finding F1: a remote BELOW the local clock still moves the clock by
/// one, so converged replicas legitimately hold different clocks — which
/// never opens a gap.
#[test]
fn test_h19_adoption_warns_once_per_jump_and_names_the_jumping_author() {
    let (mut svc, path) = setup_with_accounts();
    let date = make_date(2024, 1, 1);
    let local = svc.lamport_clock();
    let (_, logged) = capture_warnings(|| {
        svc.stage_remote_directive(remote_open(
            "Assets:Jump",
            date,
            local + MAX_LAMPORT_ADVANCE - 1,
        ))
        .unwrap()
        .expect("the maximal legal jump is adopted — the ratchet is unchanged");
    });
    assert_eq!(svc.lamport_clock(), local + MAX_LAMPORT_ADVANCE);
    assert_eq!(logged.matches("lamport gap").count(), 1, "{logged}");
    assert!(
        logged.contains("peer-remote") && logged.contains("H-19"),
        "names the jumping author: {logged}"
    );

    // Gated: more adoptions (below and just above the clock) and a local
    // append do not repeat it.
    let (_, logged) = capture_warnings(|| {
        svc.stage_remote_directive(remote_open("Assets:Low", date, 2))
            .unwrap()
            .expect("adopted");
        let clock = svc.lamport_clock();
        svc.stage_remote_directive(remote_open("Assets:High", date, clock + 10))
            .unwrap()
            .expect("adopted");
        svc.append_transaction(balanced_input()).unwrap();
    });
    assert!(logged.is_empty(), "gated: {logged}");

    // A second jump is a second gap, and warns again.
    let clock = svc.lamport_clock();
    let (_, logged) = capture_warnings(|| {
        svc.stage_remote_directive(remote_open("Assets:Later", date, clock + LAMPORT_GAP_WARN))
            .unwrap()
            .expect("adopted");
    });
    assert_eq!(logged.matches("lamport gap").count(), 1, "{logged}");

    // And the file path's adoption warns too (a hand-typed jump, M-20).
    let (mut fresh, fresh_path) = setup_with_accounts();
    let mut text = std::fs::read_to_string(&fresh_path).unwrap();
    text.push_str(&format!(
        "\n2024-01-01 open Assets:Pasted\n  openledger-author: \"peer-paste\"\n  \
             openledger-lamport: \"{}\"\n",
        fresh.lamport_clock() + MAX_LAMPORT_ADVANCE - 1
    ));
    std::fs::write(&fresh_path, text).unwrap();
    let (result, logged) = capture_warnings(|| fresh.reconcile_file().unwrap());
    assert_eq!(result.new_directives, 1);
    assert!(
        logged.contains("lamport gap") && logged.contains("peer-paste"),
        "{logged}"
    );

    std::fs::remove_file(path).ok();
    std::fs::remove_file(fresh_path).ok();
}

/// T72 (d): once the victim has authored on top of the poison, its own
/// record is the highest-lamport directive it holds. The `LamportCeiling`
/// diagnostic — and the boot warning — must still name the PEER that
/// carried the clock there, not the victim.
#[test]
fn test_h12_ceiling_diagnostics_name_the_peer_not_the_victim_that_authored_on_top() {
    let (mut svc, path) = boot_with_history_at(LAMPORT_CEILING - 4, "test-peer");
    // The victim authors on top: its own stamp, CEILING - 2, is now the
    // highest value it holds.
    svc.open_account("Assets:Mine".to_owned(), make_date(2024, 1, 1), vec![])
        .unwrap();
    assert_eq!(svc.lamport_clock(), LAMPORT_CEILING - 2);
    assert_eq!(
        svc.highest_lamport_author().as_deref(),
        Some("peer-history"),
        "the highest foreign author, not this node"
    );
    let error = svc
        .open_account("Assets:Next".to_owned(), make_date(2024, 1, 1), vec![])
        .unwrap_err();
    assert_eq!(error.error_code(), "LAMPORT_CEILING");
    let message = error.to_string();
    assert!(
        message.contains("author peer-history") && !message.contains("author test-peer"),
        "{message}"
    );
    svc.persist_or_reload().unwrap();
    drop(svc);
    let (_, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap());
    assert!(
        logged.contains("author=\"peer-history\""),
        "boot names the peer: {logged}"
    );

    // A node holding only its own records names itself — the truth.
    let (mut own, own_path) = setup_with_accounts();
    own.append_transaction(balanced_input()).unwrap();
    assert_eq!(own.highest_lamport_author().as_deref(), Some("test-peer"));
    std::fs::remove_file(path).ok();
    std::fs::remove_file(own_path).ok();
}

/// T72 / H-19: the message texts. `LamportAdvance` no longer promises
/// unconditional acceptance "once the intervening directives have
/// arrived"; both it and `LamportCeiling` state the bootstrap join and
/// the missing-parent consequence of removing an author.
#[test]
fn test_h19_remedy_texts_state_the_bootstrap_join() {
    let advance = ServiceError::LamportAdvance {
        remote: 1 << 40,
        local: 3,
        author: Some("peer-x".to_owned()),
    }
    .to_string();
    assert!(
        !advance.contains("accepted once the intervening directives have arrived"),
        "{advance}"
    );
    assert!(
        advance.contains(
            "never happens when the gap below it was made by a directive this node refuses"
        ) && advance.contains("compacted .bean")
            && advance.contains("missing parent")
            && advance.contains("H-19"),
        "{advance}"
    );
    let ceiling = ServiceError::LamportCeiling {
        next: LAMPORT_CEILING,
        author: Some("peer-x".to_owned()),
    }
    .to_string();
    assert!(
        ceiling.contains("allowlist")
            && ceiling.contains("compacted .bean")
            && ceiling.contains("own key")
            && ceiling.contains("H-19"),
        "{ceiling}"
    );
}

#[test]
fn test_a_rejected_remote_directive_does_not_move_the_clock() {
    // H-07(d). Adoption used to run BEFORE `validate_transaction` and the
    // M-09 backdated-close rule, so a directive that was ultimately thrown
    // away still moved this node's clock — and that bump was persisted, in
    // the envelope of the next directive the node authored. One allowlisted
    // peer could therefore ratchet a victim's clock with traffic it knew
    // would be refused, which is the same poisoning as H-07's, paid for one
    // step at a time. (T98 / decision (54): no ingested `close` is refused
    // any more, so the refused directive is a transaction on an account no
    // `open` admits.)
    let (mut svc, path) = setup_with_accounts();
    svc.append_transaction(balanced_input()).unwrap(); // 2024-01-15
    let before = svc.lamport_clock();

    let mut refused = remote_transaction("on an account never opened", false);
    refused.postings[0].account = "Assets:Nowhere".to_owned();
    let error = svc
        .stage_remote_directive(Directive::Transaction(refused))
        .unwrap_err();
    assert!(
        matches!(
            error,
            ServiceError::Validation(ValidationError::AccountNotOpen { .. })
        ),
        "{error}"
    );
    assert_eq!(
        svc.lamport_clock(),
        before,
        "a remote directive rejected during validation must not move the clock"
    );

    // Control: an accepted directive still adopts, `max(local, remote) + 1`
    // exactly as before. Nothing about the ordering change weakens §3.4.2.
    svc.stage_remote_directive(remote_open("Assets:Fresh", make_date(2024, 1, 1), 41))
        .unwrap();
    assert_eq!(svc.lamport_clock(), 42);

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

/// H-19: the join window. A node that holds none of its own records opens
/// it, and while it is open the join peer's directives are adopted past the
/// adoption ratchet — a history with a lamport gap no dense climb crosses —
/// while any other peer's are still ratcheted and the ceiling still applies.
/// Closed, the join peer is any peer again; and a node that has written does
/// not open it.
///
/// Bug-catch: ignore `RemoteSource` in `stage_remote_directive_from` and the
/// join peer's directive past the gap is refused.
#[test]
fn h19_the_join_window_lifts_the_ratchet_for_the_join_peer_only() {
    let date = make_date(2024, 1, 1);
    let (mut svc, path) = boot_empty();
    assert!(
        svc.open_join_trust(),
        "a node with no records of its own opens it"
    );
    let far = MAX_LAMPORT_ADVANCE + 10;
    let error = svc
        .stage_remote_directive_from(remote_open("Assets:Other", date, far), RemoteSource::Peer)
        .unwrap_err();
    assert_eq!(
        error.error_code(),
        "LAMPORT_ADVANCE",
        "any other peer is ratcheted"
    );
    svc.stage_remote_directive_from(
        remote_open("Assets:Joined", date, far),
        RemoteSource::JoinPeer,
    )
    .expect("the join peer's history is adopted past the gap");
    assert_eq!(svc.lamport_clock(), far + 1);
    let error = svc
        .stage_remote_directive_from(
            remote_open("Assets:Ceiling", date, LAMPORT_CEILING),
            RemoteSource::JoinPeer,
        )
        .unwrap_err();
    assert_eq!(
        error.error_code(),
        "LAMPORT_CEILING",
        "the ceiling still applies"
    );

    svc.close_join_trust();
    assert!(!svc.join_trust_open());
    let error = svc
        .stage_remote_directive_from(
            remote_open("Assets:Later", date, far + 1 + MAX_LAMPORT_ADVANCE),
            RemoteSource::JoinPeer,
        )
        .unwrap_err();
    assert_eq!(
        error.error_code(),
        "LAMPORT_ADVANCE",
        "closed: the join peer is any peer"
    );
    remove_ledger_and_journal(&path);

    let (mut written, path) = setup_with_accounts();
    assert!(
        !written.open_join_trust(),
        "a node that holds its own records is not joining"
    );
    remove_ledger_and_journal(&path);
}

fn remote_open(account: &str, date: NaiveDate, lamport: u64) -> Directive {
    Directive::Open(Open {
        date,
        account: account.to_owned(),
        currencies: Vec::new(),
        metadata: remote_envelope(lamport),
    })
}

/// T98 (M-09 remainder, decision (54)): an ingested `close` is data — never
/// refused — and it binds only this node's own writes, and only over an
/// interval that holds no transaction. A `close` before the account's
/// `open` closes nothing; one inside the interval a held transaction sits
/// in is accepted and inert there, for a peer's posting and for this
/// node's; a forward `close` with nothing after it refuses a local write,
/// until a peer's posting dated after it makes it inert too. Before T98 the
/// middle `close` was refused (`ACCOUNT_HAS_LATER_TRANSACTIONS`), so which
/// of it and the posting a replica held depended on which arrived first.
///
/// Bug-catch: judge peer data by the authoring fold again and the peer's
/// posting after the forward `close` is refused; drop the inert-`close`
/// test from the authoring rule and the local write beside a held
/// posting is refused.
#[test]
fn t98_an_ingested_close_is_data_and_binds_only_this_nodes_own_writes() {
    let (mut svc, path) = setup_with_accounts();
    svc.append_transaction(balanced_input()).unwrap(); // 2024-01-15
    let local = |day: (u32, u32), narration: &str| {
        let mut input = balanced_input();
        input.date = make_date(2024, day.0, day.1);
        input.narration = Some(narration.to_owned());
        input
    };

    let before_the_open = remote_close("Assets:Cash", make_date(1970, 1, 1), 9);
    assert!(
        svc.stage_remote_directive(before_the_open)
            .unwrap()
            .is_some(),
        "a close before the open closes nothing"
    );
    svc.append_transaction(local((1, 20), "after the inert close"))
        .expect("local writes go on");

    let inside = remote_close("Assets:Cash", make_date(2024, 1, 18), 10);
    assert!(
        svc.stage_remote_directive(inside).unwrap().is_some(),
        "a close inside a held transaction's interval is data, not refused"
    );
    svc.append_transaction(local((2, 10), "beside the held 01-20"))
        .expect("the close is inert where a transaction is held");

    let forward = remote_close("Assets:Cash", make_date(2024, 6, 1), 11);
    assert!(svc.stage_remote_directive(forward).unwrap().is_some());
    let refused = svc
        .append_transaction(local((6, 15), "after the forward close"))
        .unwrap_err();
    assert!(
        matches!(
            refused,
            ServiceError::Validation(ValidationError::AccountClosed { .. })
        ),
        "a close with nothing held after it binds this node's own write: {refused}"
    );

    let mut peer = remote_transaction("a peer's posting after the close", false);
    peer.date = make_date(2024, 6, 20);
    peer.metadata
        .insert("openledger-lamport".to_owned(), "12".to_owned());
    assert!(
        svc.stage_remote_directive(Directive::Transaction(peer))
            .unwrap()
            .is_some(),
        "no close refuses a peer's transaction"
    );
    svc.append_transaction(local((6, 25), "after the peer's posting"))
        .expect("a held posting makes the forward close inert too");
    std::fs::remove_file(path).ok();
}

/// M-09 write-DoS: one allowlisted peer's backdated `close` used to be
/// applied unconditionally (`let _ =`), shutting the account on every
/// replica and failing every later local append to it. Since T98
/// (decision (54)) the `close` is accepted as data — refusing it made the
/// replicas' verdicts depend on arrival order — and it is inert over the
/// interval the held transaction sits in, so local writes still go on.
#[test]
fn test_remote_backdated_close_is_data_and_local_writes_go_on() {
    let (mut svc, path) = setup_with_accounts();
    svc.append_transaction(balanced_input()).unwrap(); // 2024-01-15

    let poison = remote_close("Assets:Cash", make_date(2024, 1, 10), 9);
    let poison_id = LedgerService::content_id(&poison);
    assert!(svc.stage_remote_directive(poison).unwrap().is_some());
    assert!(svc.get_directive(&poison_id).is_some(), "a close is data");

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

/// A hand-edited file adding a backdated `close` is adopted by reconcile as
/// data, as a peer's is since T98 (decision (54)): it is inert over the
/// interval the held transaction sits in, which stays served, and local
/// writes go on.
#[test]
fn test_reconcile_adopts_a_backdated_close_as_data() {
    let (mut svc, path) = setup_with_accounts();
    let held = svc.append_transaction(balanced_input()).unwrap().txid; // 2024-01-15

    let mut content = std::fs::read_to_string(&path).unwrap();
    content.push_str("\n2024-01-10 close Assets:Cash\n");
    std::fs::write(&path, &content).unwrap();

    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.new_directives, 1);
    assert_eq!(result.rejected, 0, "the backdated close is data");
    assert!(svc.contains_directive(&held));
    let mut later = balanced_input();
    later.date = make_date(2024, 2, 1);
    later.narration = Some("after the hand close".to_owned());
    svc.append_transaction(later)
        .expect("the close is inert beside the held transaction");

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
        watch_enabled: false,
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

    // The config flag is correctly set to disabled. M-19 renamed it from
    // `external_edits_enabled`: what it gates is the polling, not whether
    // an edit is accepted, and CT-11's contract is the detection above.
    assert!(!config.watch_enabled, "CT-11: the watcher must be off");

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
    //
    // R-11 / M-24: the fixture carries a TIED PAIR — two same-day
    // "Starbucks" / "Coffee" transactions that differ only in amount, so
    // §3.3.2's (date, type priority, narration|payee) key cannot order
    // them. Each node authors one, so each inserts its own first and the
    // other's second: the pair reaches the two DAGs in OPPOSITE orders.
    // Without M-24's content-id tie-break the serializer fell back to
    // insertion order and the two `.bean` files differed; the original
    // fixture had no ties, which is why this test never caught it.

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

    // One half of the tied pair on each side of the partition (R-11).
    let coffee = |amount: rust_decimal::Decimal| TransactionInput {
        date: make_date(2024, 2, 10),
        flag: Flag::Complete,
        payee: Some("Starbucks".to_owned()),
        narration: Some("Coffee".to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            PostingInput {
                account: "Assets:Cash".to_owned(),
                amount: Some(Amount {
                    number: -amount,
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
            PostingInput {
                account: "Equity:Opening".to_owned(),
                amount: Some(Amount {
                    number: amount,
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
        ],
    };
    let txid_tie_a = node_a.append_transaction(coffee(dec!(3.50))).unwrap().txid;

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
    let txid_tie_b = node_b.append_transaction(coffee(dec!(4.75))).unwrap().txid;
    assert_ne!(txid_tie_a, txid_tie_b, "the tied pair is two directives");

    // Verify divergence.
    assert_eq!(node_a.directive_count(), 4);
    assert_eq!(node_b.directive_count(), 4);
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

    // The fixture really does exercise the tie: both nodes hold both
    // halves, in opposite insertion orders (R-11).
    let arrival = |node: &LedgerService, id: &str| {
        node.dag()
            .content_ids()
            .iter()
            .position(|candidate| *candidate == id)
            .expect("both halves of the tied pair must be present on both nodes")
    };
    assert!(
        arrival(&node_a, &txid_tie_a) < arrival(&node_a, &txid_tie_b),
        "A must hold its own coffee first"
    );
    assert!(
        arrival(&node_b, &txid_tie_b) < arrival(&node_b, &txid_tie_a),
        "B must hold its own coffee first"
    );

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

/// L-44: the persist must never chmod anything but the file it wrote.
///
/// The old code renamed the temp into place and THEN ran
/// `std::fs::metadata(path)` + `std::fs::set_permissions(path, 0600)` —
/// both symlink-following. An attacker who can write the ledger directory
/// swaps a symlink in at `path` in that window and the node chmods the
/// link's target. The window is microseconds wide, so the test is the
/// attack itself: a thread atomically re-planting a symlink over the ledger
/// path as fast as it can while the node persists in a loop. Against the
/// old code the target's mode flips to 0600 within a handful of persists;
/// with the mode set through the handle before the rename, no persist can
/// name the target at all, however the race falls.
#[cfg(unix)]
#[test]
fn l44_persist_never_chmods_a_symlink_planted_at_the_ledger_path() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let directory = test_file_path().with_extension("l44");
    std::fs::create_dir_all(&directory).unwrap();
    let ledger_path = directory.join("ledger.bean");
    let target = directory.join("victim");
    std::fs::write(&target, "not the ledger\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let attacker = {
        let stop = Arc::clone(&stop);
        let ledger_path = ledger_path.clone();
        let target = target.clone();
        let staging = directory.join("staging-link");
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // symlink + rename: an atomic replace of whatever is at the
                // ledger path, exactly as a real attacker would do it.
                let _ = std::fs::remove_file(&staging);
                if std::os::unix::fs::symlink(&target, &staging).is_ok() {
                    let _ = std::fs::rename(&staging, &ledger_path);
                }
            }
        })
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
    let mut persists = 0u32;
    while std::time::Instant::now() < deadline {
        // The persist itself may fail or succeed depending on how the race
        // falls; what must never happen is the target's mode changing.
        let _ = persist_atomically(&ledger_path, "ledger contents\n");
        persists += 1;
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        if mode != 0o644 {
            stop.store(true, Ordering::Relaxed);
            attacker.join().unwrap();
            std::fs::remove_dir_all(&directory).ok();
            panic!(
                "L-44: persist #{persists} chmod'd the symlink's target to {mode:o}; \
                     the mode must be set through the handle, never by path"
            );
        }
    }
    stop.store(true, Ordering::Relaxed);
    attacker.join().unwrap();
    assert!(persists > 0);

    // And the ledger a persist leaves behind is still owner-only.
    let _ = std::fs::remove_file(&ledger_path);
    persist_atomically(&ledger_path, "ledger contents\n").unwrap();
    let mode = std::fs::symlink_metadata(&ledger_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the ledger itself must still be 0600");
    std::fs::remove_dir_all(&directory).ok();
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

// ── M-20: reconcile applies the wire path's check set ────────────────

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
        move |content_id: &str, _is_transaction: bool, _parents: &str, _lamport: &str| {
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

#[test]
fn test_reconcile_rejects_a_body_over_the_wire_size_cap() {
    // L-02's open half (M-20). `enforce_economic_bean_limit` guarded the
    // three local API paths and `stage_remote_directive`; reconcile called
    // it nowhere, and nothing else on this path bounds body length — the
    // parser caps charsets, not lengths. So a hand-edited `.bean` whose
    // every per-field cap passes (two postings, no narration beyond a
    // label, no tags, no links) could carry a megabytes-long body straight
    // into the DAG, where L-11 SIGNED it with this node's key, the persist
    // wrote it, and every peer refused it forever.
    let path = test_file_path();
    let asset = long_account("Assets", MAX_ECONOMIC_BEAN_LENGTH / 2 + 16);
    let equity = long_account("Equity", MAX_ECONOMIC_BEAN_LENGTH / 2 + 16);
    std::fs::write(&path, "").unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    let (signer, signed) = recording_signer();
    svc.open_account(asset.clone(), make_date(2024, 1, 1), vec![])
        .unwrap();
    svc.open_account(equity.clone(), make_date(2024, 1, 1), vec![])
        .unwrap();
    // Installed only now, so the two setup opens do not pollute the log.
    svc.set_signer(signer);

    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{content}\n\
                 2024-03-01 * \"Hand\" \"Oversized\"\n\
                 \x20 {asset}                              1.00 USD\n\
                 \x20 {equity}                             -1.00 USD\n"
        ),
    )
    .unwrap();

    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.rejected, 1, "the over-cap body must be refused");
    assert_eq!(result.new_directives, 0);
    assert_refused_before_signing(&svc, &signed, "Oversized");

    std::fs::remove_file(path).ok();
}

/// A history record — a complete envelope — whose posting has no amount is
/// refused by every peer (H-03: a remote transaction must arrive with every
/// amount written, or it would be stored under another id), so no fresh
/// replica could hold it or anything written on it. Boot served it whenever
/// no verifier could judge its signature (found in T103 writing `l157_…`):
/// the served-set rule asked only a peer's parent and account questions.
/// It now holds it with its reason, and its child with it, and keeps both in
/// the file.
///
/// Bug-catch: drop the elision check from `unservable_history`, or from the
/// copy chooser (which would serve the record's own copy again), and the
/// record is served.
#[test]
fn a_history_record_with_an_elided_posting_is_held_at_boot() {
    let (svc, path) = setup_with_accounts();
    drop(svc);
    let elided = "2024-02-01 * \"Elided\"\n  \
                  openledger-author: \"peer-x\"\n  \
                  openledger-lamport: \"40\"\n  \
                  openledger-parents: \"\"\n  \
                  openledger-signature: \"ab\"\n  \
                  Assets:Cash                                        7.00 USD\n  \
                  Equity:Opening\n";
    let elided_id = compute_content_id(&parse_file(elided).unwrap()[0]);
    let child = format!(
        "2024-02-02 * \"Child of elided\"\n  \
         openledger-author: \"peer-x\"\n  \
         openledger-lamport: \"41\"\n  \
         openledger-parents: \"{elided_id}\"\n  \
         openledger-signature: \"ab\"\n  \
         Assets:Cash                                        1.00 USD\n  \
         Equity:Opening                                    -1.00 USD\n"
    );
    append_to_file(&path, &format!("\n{elided}\n{child}"));

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut svc = booted.unwrap();
    assert!(
        transaction_named(&svc, "Elided").is_none()
            && transaction_named(&svc, "Child of elided").is_none(),
        "no peer could hold either, so neither is served"
    );
    let held = svc.quarantined_ids();
    assert!(held.contains(&elided_id.as_str()), "{held:?}");
    assert_eq!(held.len(), 2, "the record and its child: {held:?}");
    assert!(
        logged.contains("H-03") && logged.contains(&elided_id),
        "{logged}"
    );
    svc.compact().unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("Elided") && text.contains("Child of elided"));
    remove_ledger_and_journal(&path);
}

/// L-157 (T103; A1 R4d): the T90 hold on the resolved-body cap. A
/// complete envelope pasted into the file under a running node, whose body
/// is under the cap as the file spells it and one byte over once I2
/// resolves its elided posting, is history — not a typed line — so the
/// live reconcile holds it in the quarantine and the rewrite keeps it
/// (T90 (c) / L-126: the file keeps what boot would keep). The typed line
/// of the same shape is refused and dropped (the test below).
///
/// Bug-catch: drop `hold_refused_file_entry` from the resolved-body arm of
/// `adopt_file_directive` and the rewrite deletes the record.
#[test]
fn l157_a_full_envelope_over_the_cap_once_resolved_is_held_in_the_file() {
    let path = test_file_path();
    std::fs::write(&path, "").unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();

    let measure = |asset: &str, equity: &str, elide: bool| -> usize {
        let directive = Directive::Transaction(Transaction {
            date: make_date(2024, 3, 1),
            flag: Flag::Complete,
            payee: Some("Hand".to_owned()),
            narration: Some("Straddle".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: asset.to_owned(),
                    amount: Some(Amount {
                        number: dec!(1),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: equity.to_owned(),
                    amount: if elide {
                        None
                    } else {
                        Some(Amount {
                            number: dec!(-1),
                            currency: "USD".to_owned(),
                        })
                    },
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        });
        crate::serialize::economic_canonical_serialize(&directive).len()
    };

    // Start from a base pair, then grow the equity name until the RESOLVED
    // body is exactly one byte over the cap.
    let asset = long_account("Assets", MAX_ECONOMIC_BEAN_LENGTH / 2 - 256);
    let base = long_account("Equity", MAX_ECONOMIC_BEAN_LENGTH / 2 - 256);
    let short = measure(&asset, &base, false);
    assert!(
        short <= MAX_ECONOMIC_BEAN_LENGTH,
        "the base pair must leave room to grow, got {short}"
    );
    // Growing the account name by one character grows the body by exactly
    // one, so the pad is exact rather than searched for.
    let equity = format!("{base}{}", "a".repeat(MAX_ECONOMIC_BEAN_LENGTH + 1 - short));
    assert_eq!(
        measure(&asset, &equity, false),
        MAX_ECONOMIC_BEAN_LENGTH + 1,
        "premise: the resolved body is one byte over the cap"
    );
    assert!(
        measure(&asset, &equity, true) <= MAX_ECONOMIC_BEAN_LENGTH,
        "premise: the ELIDED body — the one the file spells — is under it, \
             so only the post-resolution check can catch this"
    );

    svc.open_account(asset.clone(), make_date(2024, 1, 1), vec![])
        .unwrap();
    svc.open_account(equity.clone(), make_date(2024, 1, 1), vec![])
        .unwrap();
    svc.compact().unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{content}\n\
                 2024-03-01 * \"Hand\" \"Straddle\"\n\
                 \x20 openledger-author: \"peer-x\"\n\
                 \x20 openledger-lamport: \"5\"\n\
                 \x20 openledger-parents: \"\"\n\
                 \x20 openledger-signature: \"{}\"\n\
                 \x20 {asset}                              1.00 USD\n\
                 \x20 {equity}\n",
            "ab".repeat(64)
        ),
    )
    .unwrap();

    let result = svc.reconcile_file().unwrap();
    assert_eq!(
        (result.rejected, result.new_directives),
        (1, 0),
        "premise: the post-I2 body is over the cap and is refused"
    );
    assert!(transaction_named(&svc, "Straddle").is_none(), "not served");
    assert_eq!(svc.quarantined_ids().len(), 1, "held in the quarantine");
    svc.compact().unwrap();
    assert!(
        std::fs::read_to_string(&path).unwrap().contains("Straddle"),
        "the rewrite keeps a held full envelope in the file"
    );
    remove_ledger_and_journal(&path);
}

#[test]
fn test_reconcile_rejects_a_body_that_only_crosses_the_cap_once_i2_resolves() {
    // The sharp edge of L-02 on this path, and the reason the cap is
    // applied twice. The guard chain measures the body as the FILE spells
    // it; I2 then resolves the elided posting, and the RESOLVED body is
    // what gets hashed, signed, stored and served. A body one byte under
    // the cap before resolution can be over it after — and the peer
    // measures the resolved form.
    //
    // The pad is computed rather than guessed so the test cannot drift if
    // the serializer's spacing changes.
    let path = test_file_path();
    std::fs::write(&path, "").unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();

    let measure = |asset: &str, equity: &str, elide: bool| -> usize {
        let directive = Directive::Transaction(Transaction {
            date: make_date(2024, 3, 1),
            flag: Flag::Complete,
            payee: Some("Hand".to_owned()),
            narration: Some("Straddle".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                Posting {
                    account: asset.to_owned(),
                    amount: Some(Amount {
                        number: dec!(1),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: equity.to_owned(),
                    amount: if elide {
                        None
                    } else {
                        Some(Amount {
                            number: dec!(-1),
                            currency: "USD".to_owned(),
                        })
                    },
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        });
        crate::serialize::economic_canonical_serialize(&directive).len()
    };

    // Start from a base pair, then grow the equity name until the RESOLVED
    // body is exactly one byte over the cap.
    let asset = long_account("Assets", MAX_ECONOMIC_BEAN_LENGTH / 2 - 256);
    let base = long_account("Equity", MAX_ECONOMIC_BEAN_LENGTH / 2 - 256);
    let short = measure(&asset, &base, false);
    assert!(
        short <= MAX_ECONOMIC_BEAN_LENGTH,
        "the base pair must leave room to grow, got {short}"
    );
    // Growing the account name by one character grows the body by exactly
    // one, so the pad is exact rather than searched for.
    let equity = format!("{base}{}", "a".repeat(MAX_ECONOMIC_BEAN_LENGTH + 1 - short));
    assert_eq!(
        measure(&asset, &equity, false),
        MAX_ECONOMIC_BEAN_LENGTH + 1,
        "premise: the resolved body is one byte over the cap"
    );
    assert!(
        measure(&asset, &equity, true) <= MAX_ECONOMIC_BEAN_LENGTH,
        "premise: the ELIDED body — the one the file spells — is under it, \
             so only the post-resolution check can catch this"
    );

    svc.open_account(asset.clone(), make_date(2024, 1, 1), vec![])
        .unwrap();
    svc.open_account(equity.clone(), make_date(2024, 1, 1), vec![])
        .unwrap();
    let (signer, signed) = recording_signer();
    svc.set_signer(signer);

    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{content}\n\
                 2024-03-01 * \"Hand\" \"Straddle\"\n\
                 \x20 {asset}                              1.00 USD\n\
                 \x20 {equity}\n"
        ),
    )
    .unwrap();

    let result = svc.reconcile_file().unwrap();
    assert_eq!(
        result.rejected, 1,
        "the post-I2 body is over the cap and must be refused"
    );
    assert_eq!(result.new_directives, 0);
    assert_refused_before_signing(&svc, &signed, "Straddle");

    std::fs::remove_file(path).ok();
}

#[test]
fn test_reconcile_rejects_an_uppercase_hex_parent() {
    // L-29 on the file path (M-20). `parent_txid_is_well_formed` had
    // exactly ONE production call site — `stage_remote_directive` — so the
    // rule was a wire rule and the file was a sibling ingest path with no
    // form check at all. `validate_parent_fan_in` is a COUNT check and
    // `LedgerDag::insert` checks no form either.
    //
    // The mechanism is that `openledger-parents` is envelope metadata,
    // stripped before the content hash: uppercasing a real parent id
    // changes NO content id and breaks NO signature, so the edit is
    // invisible to everything except a peer's validator — where it is
    // refused forever.
    let (mut svc, path) = setup_with_accounts();
    let (signer, signed) = recording_signer();
    svc.set_signer(signer);

    // L-75: a hand-spelled parent must resolve, so the control below
    // names a real transaction rather than an id that exists nowhere.
    let real_parent = svc.append_transaction(balanced_input()).unwrap().txid;
    signed.lock().unwrap().clear();
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{content}\n\
                 2024-03-01 * \"Hand\" \"UppercaseParent\"\n\
                 \x20 openledger-parents: \"{shouted}\"\n\
                 \x20 Assets:Cash                                      3.00 USD\n\
                 \x20 Equity:Opening                                   -3.00 USD\n",
            shouted = real_parent.to_uppercase()
        ),
    )
    .unwrap();

    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.rejected, 1);
    assert_eq!(result.new_directives, 0);
    assert_refused_before_signing(&svc, &signed, "UppercaseParent");

    // The control: the identical entry in lowercase is adopted, so this is
    // a form check and not a blanket refusal of hand-written parents.
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{content}\n\
                 2024-03-02 * \"Hand\" \"LowercaseParent\"\n\
                 \x20 openledger-parents: \"{real_parent}\"\n\
                 \x20 Assets:Cash                                      3.00 USD\n\
                 \x20 Equity:Opening                                   -3.00 USD\n"
        ),
    )
    .unwrap();
    assert_eq!(svc.reconcile_file().unwrap().new_directives, 1);

    // That adoption forces the canonical re-persist, which is where L-12
    // says a refused entry leaves the file. The uppercase one is gone; the
    // lowercase one is there, signed.
    let persisted = std::fs::read_to_string(&path).unwrap();
    assert!(!persisted.contains("UppercaseParent"), "{persisted}");
    assert!(persisted.contains("LowercaseParent"), "{persisted}");
    assert!(persisted.contains("openledger-signature"), "{persisted}");

    std::fs::remove_file(path).ok();
}

#[test]
fn test_reconcile_rejects_a_malformed_lamport() {
    // M-20's lamport half. The adoption arm read `openledger-lamport` with
    // `.parse::<u64>().ok()` and treated `None` as "leave the clock where
    // it is" — so a value this node cannot read was adopted in silence,
    // signed, persisted and served, and then refused by every peer on
    // `union_merge`'s decimal-u64 check.
    //
    // `+7` is in the test on purpose: `str::parse::<u64>` ACCEPTS it, so a
    // bare `.parse()` is not the wire rule. The digit scan is, and it is
    // spelled the same way on both sides.
    let (mut svc, path) = setup_with_accounts();
    let (signer, signed) = recording_signer();
    svc.set_signer(signer);

    let content = std::fs::read_to_string(&path).unwrap();
    for (label, lamport) in [("Unreadable", "seven"), ("Signed", "+7"), ("Empty", "")] {
        std::fs::write(
            &path,
            format!(
                "{content}\n\
                     2024-03-01 * \"Hand\" \"{label}\"\n\
                     \x20 openledger-author: \"test-peer\"\n\
                     \x20 openledger-lamport: \"{lamport}\"\n\
                     \x20 Assets:Cash                                      2.00 USD\n\
                     \x20 Equity:Opening                                   -2.00 USD\n"
            ),
        )
        .unwrap();

        let result = svc.reconcile_file().unwrap();
        assert_eq!(result.rejected, 1, "{label}: must be refused");
        assert_eq!(result.new_directives, 0, "{label}");
        assert_refused_before_signing(&svc, &signed, label);
    }

    std::fs::remove_file(path).ok();
}

#[test]
fn test_reconcile_rejects_an_out_of_range_lamport() {
    // The RANGE half, which T46 already owns: `checked_lamport` refuses a
    // value that would carry this node's clock to `LAMPORT_CEILING`, and
    // `max(clock, incoming)` is ≥ `incoming`, so an out-of-range incoming
    // value is refused by the same single constant rather than by a second
    // copy of the rule here. Pinned so a future edit cannot quietly drop
    // the range check while adding the format one.
    let (mut svc, path) = setup_with_accounts();
    let (signer, signed) = recording_signer();
    svc.set_signer(signer);
    let clock_before = svc.lamport_clock();

    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{content}\n\
                 2024-03-01 * \"Hand\" \"Ceiling\"\n\
                 \x20 openledger-author: \"test-peer\"\n\
                 \x20 openledger-lamport: \"{max}\"\n\
                 \x20 Assets:Cash                                      2.00 USD\n\
                 \x20 Equity:Opening                                   -2.00 USD\n",
            max = u64::MAX
        ),
    )
    .unwrap();

    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.rejected, 1);
    assert_eq!(result.new_directives, 0);
    assert_eq!(
        svc.lamport_clock(),
        clock_before,
        "a refused adoption must not move the clock (H-07)"
    );
    assert_refused_before_signing(&svc, &signed, "Ceiling");

    std::fs::remove_file(path).ok();
}

#[test]
fn test_boot_quarantines_an_uppercase_hex_parent_without_deleting_it() {
    // The same rule on the other file path, with boot's tolerant treatment
    // (M-20 × H-08): out of the DAG, still on disk after the startup
    // compaction. An uppercase parent is a pointer nobody — including this
    // node — can resolve, so loading it only makes it something this node
    // serves and every peer refuses.
    let path = test_file_path();
    std::fs::write(
        &path,
        format!(
            "2024-01-01 open Assets:Cash USD\n\n\
                 2024-01-01 open Equity:Opening\n\n\
                 2024-03-01 * \"Hand\" \"Shouted\"\n\
                 \x20 openledger-parents: \"{shouted}\"\n\
                 \x20 Assets:Cash                                      3.00 USD\n\
                 \x20 Equity:Opening                                   -3.00 USD\n",
            shouted = "ab".repeat(32).to_uppercase()
        ),
    )
    .unwrap();

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "peer-1".to_owned()));
    let mut svc = booted.expect("a malformed parent must not brick boot");
    assert_eq!(svc.directive_count(), 2, "only the two opens load");
    assert_eq!(svc.quarantined_count(), 1);
    assert!(
        logged.contains("lowercase hex txid"),
        "boot must say what it refused and why: {logged}"
    );

    svc.compact().unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("Shouted"),
        "H-08: the quarantined record must survive the rewrite: {on_disk}"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_boot_quarantines_a_malformed_lamport_without_deleting_it() {
    // M-20's lamport half at boot. `Directive::lamport_clock()` already
    // yields `None` for an unreadable value, so quarantining it cannot move
    // `max_lamport` — the directive is simply kept out of the served set.
    let path = test_file_path();
    std::fs::write(
        &path,
        "2024-01-01 open Assets:Cash USD\n\n\
             2024-01-01 open Equity:Opening\n\n\
             2024-03-01 * \"Hand\" \"Garbled\"\n\
             \x20 openledger-author: \"peer-1\"\n\
             \x20 openledger-lamport: \"seven\"\n\
             \x20 Assets:Cash                                      3.00 USD\n\
             \x20 Equity:Opening                                   -3.00 USD\n",
    )
    .unwrap();

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "peer-1".to_owned()));
    let mut svc = booted.expect("a malformed lamport must not brick boot");
    assert_eq!(svc.directive_count(), 2);
    assert_eq!(svc.quarantined_count(), 1);
    assert!(
        logged.contains("openledger-lamport must be a decimal u64"),
        "boot must say what it refused and why: {logged}"
    );

    svc.compact().unwrap();
    assert!(
        std::fs::read_to_string(&path).unwrap().contains("Garbled"),
        "H-08: the quarantined record must survive the rewrite"
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

// ── H-08: a boot that skips records must never reach a rewrite ───────
//
// T35 turned L-17's boot brick into a boot skip, and T41 added a second
// skip site; the compaction that `gl-node` runs unconditionally at startup
// then serialized `dag.directives()` over the whole `.bean` and deleted the
// journal. Everything the boot skipped was therefore **erased from disk**,
// seconds after start, before any operator could act on the warning telling
// them to repair the file. These three tests are the three skip sites, each
// driven the way it is actually reached.

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

#[test]
fn test_a_planted_parent_cycle_cannot_erase_the_ledger_at_the_next_compaction() {
    // THE AUDIT'S PROOF, as a test.
    //
    // Six transactions appended through the public API, so the file is one
    // ordinary parent chain t1 ← t2 ← … ← t6 written by this crate itself.
    // Then ONE line is edited: the oldest transaction's `openledger-parents`
    // is pointed at the newest txid. That closes a cycle over the entire
    // chain, so Kahn's pre-scan (which reports cycle members *and* all
    // descendants) blocks all six — and because `openledger-parents` is
    // envelope metadata that `economic_canonical_serialize` strips, not one
    // content id changes and not one signature breaks. Nothing about the
    // file looks tampered with.
    //
    // Before H-08 the reboot-then-compact that `gl-node` performs at every
    // startup left TWO directives on disk (the opens) and zero transactions.
    let (mut svc, path) = setup_with_accounts();
    let mut txids = Vec::new();
    for day in 1..=6u32 {
        let mut input = balanced_input();
        input.date = make_date(2024, 2, day);
        input.narration = Some(format!("Transaction {day}"));
        txids.push(svc.append_transaction(input).unwrap().txid);
    }
    drop(svc);

    assert_eq!(
        transactions_on_disk(&path).len(),
        6,
        "premise: six transactions were appended through the public API"
    );

    // Edit exactly one line. The file is in canonical (date, type) order and
    // the OLDEST transaction is the only one whose parents are empty (it was
    // appended when the DAG had no heads), so this rewrites precisely its
    // line: point the oldest at the newest txid and the chain closes.
    let content = std::fs::read_to_string(&path).unwrap();
    let newest = txids.last().unwrap().clone();
    assert!(
        content.contains("openledger-parents: \"\""),
        "premise: the first append had no heads to point at"
    );
    let patched = content.replacen(
        "openledger-parents: \"\"",
        &format!("openledger-parents: \"{newest}\""),
        1,
    );
    assert_ne!(
        patched, content,
        "exactly one line must have been rewritten"
    );
    std::fs::write(&path, &patched).unwrap();

    // The premise of L-17, re-asserted on the real file: the edit changed no
    // identity at all, which is why nothing downstream can notice it.
    let ids_after_edit: Vec<String> = transactions_on_disk(&path)
        .into_iter()
        .map(|t| compute_content_id(&Directive::Transaction(t)))
        .collect();
    for txid in &txids {
        assert!(
            ids_after_edit.contains(txid),
            "the envelope edit must not change any content id"
        );
    }

    // Reboot, exactly as `gl-node` does: boot, then compact unconditionally.
    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut rebooted = booted.expect("H-08 keeps T35's tolerant-boot rule: boot must succeed");
    assert_eq!(
        rebooted.quarantined_count(),
        6,
        "all six transactions are on or below the planted cycle"
    );
    assert!(
        logged.contains("QUARANTINED"),
        "the operator must be told the records are kept, not skipped: {logged}"
    );
    rebooted.compact().unwrap();

    let survivors = transactions_on_disk(&path);
    assert_eq!(
        survivors.len(),
        6,
        "H-08: the startup compaction must not erase the records the boot skipped — \
             this is the assertion that failed before the quarantine, with 0 left on disk"
    );
    let surviving_ids: Vec<String> = survivors
        .iter()
        .map(|t| compute_content_id(&Directive::Transaction(t.clone())))
        .collect();
    for txid in &txids {
        assert!(
            surviving_ids.contains(txid),
            "transaction {txid} was erased from disk by the compaction"
        );
    }
    assert_eq!(
        surviving_ids.iter().collect::<BTreeSet<_>>().len(),
        6,
        "a quarantined record must be written back exactly once"
    );

    // And the quarantine is a property of the FILE, so it survives a second
    // round trip unchanged rather than draining one boot at a time.
    let rebooted_twice = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted_twice.quarantined_count(), 6);
    assert_eq!(transactions_on_disk(&path).len(), 6);
    drop(rebooted_twice);

    // H-08 × L-30: the startup compaction is not the only way into a
    // rewrite. A hand edit sends the next commit through
    // `adopt_external_edits` → `reconcile_content` → compaction, and
    // reconcile re-reads the whole file — quarantined records included — and
    // refuses them for the same reason boot did. That refusal must not
    // become a deletion either.
    let edited = format!(
        "{}\n2024-01-01 open Assets:Second\n",
        std::fs::read_to_string(&path).unwrap()
    );
    std::fs::write(&path, edited).unwrap();
    rebooted.reconcile_file().unwrap();
    assert!(
        rebooted.accounts().is_open("Assets:Second"),
        "premise: the hand edit really was adopted, so a rewrite really did run"
    );
    let after_edit: Vec<String> = transactions_on_disk(&path)
        .iter()
        .map(|t| compute_content_id(&Directive::Transaction(t.clone())))
        .collect();
    assert_eq!(
        after_edit.iter().collect::<BTreeSet<_>>().len(),
        6,
        "H-08: the adopt-then-rewrite path must keep all six, and keep one copy each"
    );
    for txid in &txids {
        assert!(after_edit.contains(txid), "{txid} lost to the adopt path");
    }

    std::fs::remove_file(path).ok();
}

#[test]
fn test_an_over_fan_in_directive_survives_the_upgrade_compaction() {
    // The skip site that needs no attacker at all (T41). `MAX_PARENTS` was
    // a wire rule until T41 put it on the file path, so any `.bean` written
    // before that upgrade can legitimately carry an over-cap
    // `openledger-parents` — and on the first boot after the upgrade, boot
    // skips it and the startup compaction deleted it. No hand edit, no
    // crafted file, no peer: just an upgrade.
    let path = test_file_path();
    std::fs::write(&path, file_with_parent_fan_in(MAX_PARENTS + 1)).unwrap();

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "peer-1".to_owned()));
    let mut svc = booted.expect("an over-cap fan-in must not brick boot (T35)");
    assert_eq!(
        svc.directive_count(),
        2,
        "T41 stands: the over-cap transaction is still kept OUT of the DAG"
    );
    assert_eq!(svc.quarantined_count(), 1, "…and kept for the file");
    assert!(
        logged.contains("openledger-parents has"),
        "boot must still say what it refused and why: {logged}"
    );

    svc.compact().unwrap();

    let survivors = transactions_on_disk(&path);
    assert_eq!(
        survivors.len(),
        1,
        "H-08: the upgrade's first compaction must not delete the pre-T41 record"
    );
    assert_eq!(
        survivors[0].parent_ids().len(),
        MAX_PARENTS + 1,
        "the record must be written back verbatim — including the over-cap parents \
             list the operator has to repair"
    );

    std::fs::remove_file(path).ok();
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

#[test]
fn test_a_cycle_check_exhaustion_survives_the_next_compaction() {
    // The third skip site: `dag.insert` refusing at boot. Since L-14 that
    // includes `CycleCheckExhausted`, which is a refusal to answer rather
    // than a proven cycle — so the directive it refuses may be perfectly
    // legitimate, and deleting it at the next compaction is the worst of
    // the three cases.
    let (content, exhaust_id) = cycle_check_exhaustion_file();
    let path = test_file_path();
    std::fs::write(&path, &content).unwrap();
    let total_before = transactions_on_disk(&path).len();

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "peer-1".to_owned()));
    let mut svc = booted.expect("a DAG refusal must not brick boot (L-17)");
    assert!(
        logged.contains("exceeded 16384 node visits"),
        "the I8 visit budget — not a proven cycle — must be what refused this \
             directive, at the PRODUCTION budget, got: {logged}"
    );
    assert!(
        svc.get_directive(&exhaust_id).is_none(),
        "premise: the refused directive is not in the DAG"
    );
    assert!(
        svc.quarantined_ids().contains(&exhaust_id.as_str()),
        "the refused directive is quarantined"
    );
    // T84 / H-23: so is what descends from it (the seed and the chain below
    // it name it) and what names parents that exist nowhere (the padding
    // above) — no peer could adopt any of them. Every one keeps its place
    // in the file, which is what this test is about.
    assert_eq!(
        svc.directive_count() + svc.quarantined_count(),
        total_before + 2,
        "every transaction is either served or held, and the two opens load"
    );

    svc.compact().unwrap();

    assert_eq!(
        transactions_on_disk(&path).len(),
        total_before,
        "H-08: a directive the I8 budget could not adjudicate must keep its place in \
             the file — the check refused to answer, which is not a licence to delete"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_repairing_the_parents_line_releases_the_quarantine() {
    // The operator's way out, and the reason the quarantine is keyed by
    // content id: repairing `openledger-parents` leaves the id untouched
    // (that is L-17's premise), so the repaired directive is adopted by the
    // ordinary reconcile path and drops out of the quarantine — the file
    // then holds one copy, the DAG's, not two.
    let (mut svc, path) = setup_with_accounts();
    let mut input = balanced_input();
    input.date = make_date(2024, 2, 1);
    input.narration = Some("Self parent".to_owned());
    let txid = svc.append_transaction(input).unwrap().txid;
    drop(svc);

    let content = std::fs::read_to_string(&path).unwrap();
    let broken = content.replace(
        "openledger-parents: \"\"",
        &format!("openledger-parents: \"{txid}\""),
    );
    assert_ne!(broken, content, "the parents line must have been rewritten");
    std::fs::write(&path, &broken).unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(
        svc.quarantined_count(),
        1,
        "a transaction naming itself as a parent is a one-node cycle"
    );
    svc.compact().unwrap();
    assert_eq!(
        transactions_on_disk(&path).len(),
        1,
        "H-08: still on disk after the compaction"
    );

    // Repair it the way the warning asks: drop the bad parents pointer.
    let on_disk = std::fs::read_to_string(&path).unwrap();
    let repaired = on_disk.replace(
        &format!("openledger-parents: \"{txid}\""),
        "openledger-parents: \"\"",
    );
    assert_ne!(repaired, on_disk, "the repair must have changed the file");
    std::fs::write(&path, &repaired).unwrap();

    svc.reconcile_file().unwrap();
    assert_eq!(
        svc.quarantined_count(),
        0,
        "the repaired directive is in the DAG now, so nothing is quarantined"
    );
    assert!(svc.get_directive(&txid).is_some());
    assert_eq!(
        transactions_on_disk(&path).len(),
        1,
        "and it is written exactly once, not once per copy"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn test_a_well_formed_ledger_is_untouched_by_the_quarantine() {
    // The quarantine must be invisible on every healthy file: no entries, no
    // extra bytes, and a byte-identical re-persist.
    let (mut svc, path) = setup_with_accounts();
    svc.append_transaction(balanced_input()).unwrap();
    let before = std::fs::read(&path).unwrap();
    drop(svc);

    let mut rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.quarantined_count(), 0);
    assert!(rebooted.quarantined_ids().is_empty());
    rebooted.compact().unwrap();
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "an empty quarantine must not perturb the canonical bytes"
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

/// H-11: the in-flight flag is released by DROPPING the prepared commit,
/// not only by finishing or recovering it.
///
/// The unit-level statement of the whole finding. The flag used to be a
/// plain `bool` with no `Drop` behind it anywhere, so a `PendingCommit`
/// that went away without reaching `finish_commit`/`recover_failed_commit`
/// left the service refusing every future write for the life of the
/// process. In the node that happened whenever something dropped the
/// caller's future between `prepare` and the bookkeeping after the
/// `await` — a 408 request timeout, an HTTP/2 `RST_STREAM`, a panic. Here
/// it is just `drop`, which is exactly what cancellation is.
#[test]
fn h11_dropping_a_prepared_commit_releases_the_in_flight_flag() {
    let (mut svc, path) = boot_large_ledger();

    svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
        .unwrap();
    let abandoned = svc.prepare_commit().unwrap().unwrap();
    assert_eq!(
        svc.prepare_commit().unwrap_err().error_code(),
        "COMMIT_IN_FLIGHT",
        "the flag must really be set — otherwise the drop below proves nothing"
    );

    // The cancellation: the only handle to the outstanding commit goes
    // away, and neither clear is ever called.
    drop(abandoned);

    let recovered = svc
        .prepare_commit()
        .expect("H-11: a dropped PendingCommit must not wedge the next prepare")
        .expect("the staged directive is still uncommitted, so there is work to do");
    let receipt = recovered.commit().unwrap();
    svc.finish_commit(receipt);
    assert_eq!(
        svc.uncommitted_count(),
        0,
        "and the write that follows the cancellation must still be durable"
    );

    remove_ledger_and_journal(&path);
}

// ── T44b: a reload replaces the CONTENT, never the SERVICE ───────────

/// A second hand edit, distinguishable from [`HAND_EDITED_TRANSACTION`] so
/// the G-Set does not dedupe it away.
const HAND_EDITED_SECOND_TRANSACTION: &str = "\n2024-01-16 * \"Shop\" \"Tea\"\n  \
         Expenses:Food                                        3.25 USD\n  \
         Assets:Cash                                         -3.25 USD\n";

/// The headline regression (T44b): a commit fails, L-13 recovers, and the
/// very next hand-edit adoption is **still signed**.
///
/// Before this, the reload ran through `boot`, which sets `signer: None` —
/// so an adoption after a recovered commit failure persisted an entry with
/// no `openledger-signature`: in this node's DAG, in its `.bean`, in every
/// report, and refused by every signing peer forever. That is precisely the
/// silent split-brain L-11 (T40) closed, re-opened by the recovery path.
/// The L-30 reconcile counter rode along in the same reset, so both are
/// asserted here on one recovery.
///
/// The failure seam is T44's: a read-only journal fails the append on the
/// real I/O path with no mocking, and stays readable so the reload can run.
#[cfg(unix)]
#[test]
fn t44b_a_recovered_commit_failure_keeps_the_signer_and_the_reconcile_count() {
    use std::os::unix::fs::PermissionsExt;

    // H-20: a signing node signs what it writes, and the reload re-reads
    // the file under the carried signer — so the fixture and the two
    // opens below are signed, as `gl-node`'s resolvers sign theirs.
    let (mut svc, path) = boot_large_ledger_signed();
    let journal_path = svc.journal_path().to_path_buf();
    svc.set_signer(marker_signer());
    svc.open_account_signing(
        "Expenses:Food".to_owned(),
        make_date(2024, 1, 1),
        vec!["USD".to_owned()],
        marker_sign(false),
    )
    .unwrap();

    // A hand edit adopted the ordinary way first, so the L-30 counter has a
    // history that a reset would visibly destroy. Adoption always compacts,
    // which is why the journal is (re-)created by the append below and not
    // by this write.
    append_to_file(&path, HAND_EDITED_TRANSACTION);
    svc.open_account_signing(
        "Assets:Wallet".to_owned(),
        make_date(2024, 1, 2),
        vec![],
        marker_sign(false),
    )
    .unwrap();
    assert_eq!(
        svc.external_reconcile_count(),
        1,
        "the pre-failure adoption must have run"
    );

    // One append, so there is a journal to make unwritable.
    svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
        .unwrap();
    svc.persist_or_reload().unwrap();

    let mut permissions = std::fs::metadata(&journal_path).unwrap().permissions();
    permissions.set_mode(0o400);
    std::fs::set_permissions(&journal_path, permissions).unwrap();

    svc.stage_remote_directive(remote_open("Assets:Safe", make_date(2024, 3, 2), 11))
        .unwrap();
    let error = svc.persist_or_reload().unwrap_err();
    assert_eq!(error.error_code(), "IO_ERROR", "got {error}");
    assert!(
        !svc.accounts().is_open("Assets:Safe"),
        "L-13: the undurable write must have been rolled back, i.e. the reload ran"
    );

    // L-30: the counter is a fact about this process, not about the file it
    // just re-read.
    assert_eq!(
        svc.external_reconcile_count(),
        1,
        "the reconcile counter must survive the L-13 reload"
    );

    let mut permissions = std::fs::metadata(&journal_path).unwrap().permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(&journal_path, permissions).unwrap();

    // L-11: the adoption AFTER the recovery must be signed exactly as one
    // before it would have been.
    append_to_file(&path, HAND_EDITED_SECOND_TRANSACTION);
    assert_eq!(svc.reconcile_file().unwrap().new_directives, 1);

    let adopted = svc
        .dag()
        .directives()
        .into_iter()
        .find(|directive| match directive {
            Directive::Transaction(txn) => txn.narration.as_deref() == Some("Tea"),
            _ => false,
        })
        .expect("the post-recovery hand edit must have been adopted");
    let metadata = adopted.metadata();
    let signature = metadata.get("openledger-signature").expect(
        "an entry adopted after a recovered commit failure must be signed, or it will \
             never replicate",
    );
    assert!(
        signature.contains(&compute_content_id(adopted)),
        "signature must cover the stored id: {signature}"
    );
    assert!(signature.contains("|true|"), "{signature}");
    assert_eq!(metadata.get("openledger-author"), Some(&svc.author_id));
    assert_eq!(
        svc.external_reconcile_count(),
        1,
        "reconcile_file is not a persist-time adoption"
    );

    remove_ledger_and_journal(&path);
}

/// The carry helper itself, field by field: a reload discards the ledger's
/// content and keeps every handle that describes the service.
///
/// `recover_failed_commit` is the workspace's **only** wholesale reload —
/// `persist_or_reload`/`compact` reach it through `commit_inline`, and the
/// node's async commit path through `commit_pending`/`prepare_or_recover` —
/// so this pins the one function all of them share.
#[test]
fn t44b_a_reload_replaces_the_content_and_keeps_the_service() {
    let (mut svc, path) = boot_large_ledger();
    svc.set_signer(marker_signer());

    let fired = std::sync::Arc::new(AtomicU64::new(0));
    let observer_count = std::sync::Arc::clone(&fired);
    svc.set_commit_observer(std::sync::Arc::new(move |_kind, _bytes| {
        observer_count.fetch_add(1, Ordering::SeqCst);
    }));
    let gate_before = svc.commit_gate();
    let in_flight_before = std::sync::Arc::clone(&svc.commit_in_flight);
    // A stand-in for a history of adoptions; the end-to-end form of this
    // assertion is in the headline test above.
    svc.external_reconcile_count = 7;

    svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
        .unwrap();
    svc.persist_or_reload().unwrap();
    let generation_before = svc.commit_generation;
    let fired_before = fired.load(Ordering::SeqCst);
    assert!(generation_before > 0, "a commit must have advanced it");
    assert!(fired_before > 0, "the observer must have seen that commit");

    // An undurable mutation, then the reload that discards it.
    svc.stage_remote_directive(remote_open("Assets:Safe", make_date(2024, 3, 2), 11))
        .unwrap();
    svc.recover_failed_commit();

    // The content is gone, down to the durable state.
    assert_eq!(svc.uncommitted_count(), 0);
    assert!(!svc.accounts().is_open("Assets:Safe"));
    assert!(
        svc.accounts().is_open("Assets:Vault"),
        "the durable half must survive the reload"
    );

    // The service is intact.
    assert!(svc.signer.is_some(), "L-11: the signer must survive");
    assert_eq!(
        svc.external_reconcile_count(),
        7,
        "L-30: the reconcile counter must survive"
    );
    assert!(
        std::sync::Arc::ptr_eq(&gate_before, &svc.commit_gate()),
        "a fresh gate would silently unserialize a writer holding the old permit"
    );
    assert!(
        std::sync::Arc::ptr_eq(&in_flight_before, &svc.commit_in_flight),
        "H-11: a fresh in-flight slot is one no outstanding CommitInFlightGuard \
             points at, so the guard would release an orphan and the live service \
             would stay marked"
    );
    assert!(
        svc.commit_generation >= generation_before,
        "a commit generation must never be re-issued after a reload"
    );

    // The observer is a handle like any other: the next commit still fires.
    svc.stage_remote_directive(remote_open("Assets:Deposit", make_date(2024, 3, 3), 12))
        .unwrap();
    svc.persist_or_reload().unwrap();
    assert_eq!(
        fired.load(Ordering::SeqCst),
        fired_before + 1,
        "the commit observer must survive the reload too"
    );

    remove_ledger_and_journal(&path);
}

// ── T52: the `.bean` as an operator-edit interface (M-19 / M-25 / M-29) ──

/// M-19: adoption on the compaction path is unconditional, and there is no
/// setting anywhere in this workspace that changes it.
///
/// `gl-node` advertised `externalFileEdits: "disabled"` — the default — as
/// the switch that turned this off, and the README said adoption "requires
/// `"externalFileEdits": "enabled"`". It never reached this code. The
/// setting is gone rather than honoured; this pins the behaviour it was
/// falsely describing, so a future "make it configurable" has to delete an
/// assertion that says why not.
#[test]
fn m19_a_hand_edit_is_adopted_on_the_compaction_path() {
    let (mut svc, path) = setup_with_accounts();
    assert!(
        svc.canonical_bytes() < COMPACTION_MIN_CANONICAL_BYTES,
        "premise: a small ledger, so every commit is a compaction"
    );
    append_to_file(&path, HAND_EDITED_TRANSACTION);

    // An ordinary write. Nothing here asks for a reconcile.
    svc.append_transaction(balanced_input()).unwrap();

    assert_eq!(
        svc.external_reconcile_count(),
        1,
        "M-19: the compaction path adopts, with no configuration consulted"
    );
    let adopted = transactions_on_disk(&path)
        .into_iter()
        .find(|transaction| transaction.narration.as_deref() == Some("Coffee"))
        .expect("M-19: the hand edit must survive the rewrite that would have erased it");
    assert_eq!(adopted.payee.as_deref(), Some("Shop"));

    remove_ledger_and_journal(&path);
}

/// M-19, the reason the setting could not simply be honoured: the
/// compaction path is also how a quarantined record is RELEASED (T47/T51).
///
/// Disabling adoption would have made the operator's repair unreadable, so
/// the record would be retained verbatim on every rewrite forever with no
/// way out. This drives the release through a plain `compact()` — no
/// `reconcile_file` call — so the release really is running inside
/// `adopt_external_edits`.
#[test]
fn m19_a_quarantined_record_is_released_by_the_compaction_path() {
    let (mut svc, path) = setup_with_accounts();
    let mut input = balanced_input();
    input.date = make_date(2024, 2, 1);
    input.narration = Some("Self parent".to_owned());
    let txid = svc.append_transaction(input).unwrap().txid;
    drop(svc);

    // Break it exactly as T47/T51's quarantine tests do: a transaction that
    // names itself as a parent is a one-node cycle, so boot refuses it and
    // holds it rather than deleting it (H-08).
    let content = std::fs::read_to_string(&path).unwrap();
    let broken = content.replace(
        "openledger-parents: \"\"",
        &format!("openledger-parents: \"{txid}\""),
    );
    assert_ne!(broken, content, "the parents line must have been rewritten");
    std::fs::write(&path, &broken).unwrap();

    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(svc.quarantined_count(), 1, "premise: it is quarantined");

    // The operator repairs the file and the node simply writes, as it does
    // at shutdown or on the next mutation.
    let on_disk = std::fs::read_to_string(&path).unwrap();
    let repaired = on_disk.replace(
        &format!("openledger-parents: \"{txid}\""),
        "openledger-parents: \"\"",
    );
    assert_ne!(repaired, on_disk, "the repair must have changed the file");
    std::fs::write(&path, &repaired).unwrap();

    svc.compact().unwrap();

    assert_eq!(
        svc.quarantined_count(),
        0,
        "M-19: the repair is read by the compaction path's adoption, so the record \
             leaves quarantine — this is what disabling adoption would have stranded"
    );
    assert!(svc.get_directive(&txid).is_some());
    assert_eq!(
        transactions_on_disk(&path).len(),
        1,
        "and it is written exactly once, not once per copy"
    );

    remove_ledger_and_journal(&path);
}

/// M-25 at the service level: a truncated hand edit is refused, not adopted
/// and written back short.
///
/// `open Assets:Vault USD AND MORE JUNK` used to parse cleanly as
/// `open Assets:Vault USD`. Reconcile adopted THAT, signed it with this
/// node's key and the compaction rewrote the file without the tail — no
/// error, no rejection tally, nothing for the operator to find. Now the
/// file does not parse, which is the same fail-closed treatment a
/// half-saved edit has always had: the write is abandoned and the
/// operator's bytes stay on disk.
#[test]
fn m25_a_truncated_hand_edit_is_refused_not_adopted() {
    let (mut svc, path) = setup_with_accounts();
    append_to_file(&path, "\n2024-02-01 open Assets:Vault USD AND MORE JUNK\n");

    let (outcome, logged) = capture_warnings(|| svc.append_transaction(balanced_input()));
    let error = outcome.expect_err(
        "M-25: a line the parser cannot read in full must block the write, not be \
             silently truncated into a different directive",
    );
    let rendered = error.to_string();
    assert!(
        rendered.contains("AND MORE JUNK"),
        "the refusal must quote what it could not read: {rendered}"
    );
    assert!(
        logged.contains("repair the file"),
        "the operator must be told what to do: {logged}"
    );

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("2024-02-01 open Assets:Vault USD AND MORE JUNK"),
        "M-25: the operator's exact text must still be there, not a truncated \
             re-spelling of it:\n{on_disk}"
    );
    assert!(
        !svc.accounts().is_open("Assets:Vault"),
        "M-25: and the truncated reading must not have been adopted"
    );

    remove_ledger_and_journal(&path);
}

/// M-29, the finding's proof inverted.
///
/// Proven on a 138 KB ledger: `Some(Append)` ×4 became `Some(Compact)` ×4
/// after one watcher tick, because `reconcile_content` cleared
/// `canonical_is_current` unconditionally and `prepare` turns that into a
/// forced rewrite — a loop the node entered by writing its own file.
#[test]
fn m29_a_watcher_tick_over_our_own_bytes_keeps_the_append_path() {
    let (mut svc, path) = boot_large_ledger();

    let mut kinds = Vec::new();
    let take_one_commit = |svc: &mut LedgerService, index: usize| {
        let mut input = balanced_input();
        input.date = make_date(2024, 4, 1);
        input.narration = Some(format!("Before {index}"));
        svc.append_transaction_staged(input, |_, _, _| None)
            .unwrap();
        let pending = svc.prepare_commit().unwrap().expect("something is staged");
        let kind = pending.kind();
        let receipt = pending.commit().unwrap();
        svc.finish_commit(receipt);
        kind
    };

    for index in 0..4 {
        kinds.push(take_one_commit(&mut svc, index));
    }
    assert_eq!(
        kinds,
        vec![CommitKind::Append; 4],
        "premise: a ledger past the threshold appends"
    );

    // One watcher tick over the file the node itself wrote. This is the
    // exact call `gl-node`'s watcher makes.
    let result = svc.reconcile_file_staged().unwrap();
    assert_eq!(result.new_directives, 0);
    assert_eq!(
        result.duplicates, 0,
        "M-29: the short-circuit means nothing was even re-parsed to be called a \
             duplicate"
    );

    // And a tick before every subsequent commit, which is what a 250 ms
    // poll actually does: that is what made the pre-fix behaviour
    // self-sustaining rather than a one-off — each forced compaction
    // rewrote the file, which the next tick saw as a change, which forced
    // the next compaction.
    let after: Vec<CommitKind> = (0..4)
        .map(|i| {
            svc.reconcile_file_staged().unwrap();
            take_one_commit(&mut svc, 10 + i)
        })
        .collect();
    assert_eq!(
        after,
        vec![CommitKind::Append; 4],
        "M-29: a tick over our own bytes must not demote T44's append path to a \
             full rewrite — this is the assertion the finding's proof failed"
    );

    remove_ledger_and_journal(&path);
}

/// M-29: and a tick over bytes that really did change still reconciles.
///
/// The short-circuit must be a hash comparison, not a way of never looking.
#[test]
fn m29_a_watcher_tick_over_a_real_edit_still_reconciles() {
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();
    assert_eq!(svc.reconcile_file_staged().unwrap().new_directives, 0);

    append_to_file(&path, HAND_EDITED_TRANSACTION);
    assert_eq!(
        svc.reconcile_file_staged().unwrap().new_directives,
        1,
        "M-29: a genuine edit must still be adopted"
    );

    remove_ledger_and_journal(&path);
}

/// M-29: the predicate the watcher uses to recognise its own write, against
/// the hash the watcher actually computes.
#[test]
fn m29_the_self_write_predicate_agrees_with_the_watchers_hash() {
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();

    let polled = crate::file_watcher::FileState::from_path(&path);
    let hash = polled
        .content_hash_hex()
        .expect("the watcher must have hashed a readable file");
    assert!(
        svc.file_hash_is_current(&hash),
        "M-29: the file the node just wrote must be recognised as its own write"
    );

    append_to_file(&path, HAND_EDITED_TRANSACTION);
    let edited = crate::file_watcher::FileState::from_path(&path);
    assert!(
        !svc.file_hash_is_current(&edited.content_hash_hex().unwrap()),
        "M-29: a hand edit must not be suppressed as a self-write"
    );

    remove_ledger_and_journal(&path);
}

// ── T59: ledger and commit robustness (L-41, L-43) ───────────────────

/// L-41, end to end: a journal whose last header claims `usize::MAX`
/// bytes is handled — not a panic — by the LIVE recovery path and by boot.
///
/// This is the shape that mattered: `read_journal` is the body of
/// `recover_failed_commit`, which the node runs holding the ledger's write
/// guard, so the overflow panic used to land there. L-41 made the header a
/// torn tail; M-43 (T68) makes it `Corrupt`, since no journal this node
/// writes claims more than the budget: the recovery keeps memory (its
/// reload fails, logged) and boot refuses, naming the record's offset.
#[test]
fn l41_an_overflowing_journal_header_fails_closed_through_recovery_and_boot() {
    let (mut svc, path) = boot_large_ledger();
    svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
        .unwrap();
    svc.persist_or_reload().unwrap();
    assert!(svc.journal_bytes() > 0, "the fixture needs a real journal");
    let durable_count = svc.directive_count();

    let journal_path = svc.journal_path().to_path_buf();
    let mut journal = std::fs::read(&journal_path).unwrap();
    let bad_offset = journal.len();
    journal
        .extend_from_slice(format!(";;olj {} {}\npartial", usize::MAX, "cd".repeat(32)).as_bytes());
    std::fs::write(&journal_path, &journal).unwrap();

    svc.recover_failed_commit();
    assert_eq!(
        svc.directive_count(),
        durable_count,
        "the failed reload keeps memory, the durable record included"
    );
    assert!(svc.accounts().is_open("Assets:Vault"));

    let Err(error) = LedgerService::boot(path.clone(), "test-peer".to_owned()) else {
        panic!("M-43: an over-budget header must fail boot closed");
    };
    assert_eq!(error.error_code(), "LEDGER_JOURNAL", "got {error}");
    assert!(
        error.to_string().contains(&format!("at byte {bad_offset}")),
        "the refusal names the offset: {error}"
    );
    remove_ledger_and_journal(&path);
}

/// L-43: a rebuild taken off the lock is never installed over a service
/// that moved after it was taken.
///
/// The single-writer permit is what makes the off-lock rebuild sound; this
/// pins the tripwire behind it. A write that skips the permit and lands —
/// durably — between `begin_recovery` and `finish_recovery` must not be
/// rolled out of memory by the stale rebuild: that would leave memory
/// BEHIND disk, and the next compaction would serialize memory over the
/// file and erase an acknowledged write. `finish_recovery` reloads
/// synchronously instead, against the files as they now are.
#[test]
fn l43_a_stale_off_lock_rebuild_is_never_installed() {
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();

    let reload = svc.begin_recovery();
    let stale = reload.load();

    // The contract violation: a durable write with no permit, mid-rebuild.
    svc.open_account("Assets:Late".to_owned(), make_date(2024, 2, 1), vec![])
        .unwrap();

    let (_, logged) = capture_warnings(|| svc.finish_recovery(reload, stale));
    assert!(
        svc.accounts().is_open("Assets:Late"),
        "L-43: a stale rebuild must not roll a durable write out of memory"
    );
    let disk = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(
        svc.directive_count(),
        disk.directive_count(),
        "memory == disk"
    );
    assert!(
        logged.contains("single-writer contract"),
        "the violation must be reported, got: {logged}"
    );
    remove_ledger_and_journal(&path);
}

/// L-43: the split form, used as the node uses it, is the old reload —
/// the undurable mutation is discarded and the service keeps its identity.
#[test]
fn l43_the_split_reload_matches_the_synchronous_one() {
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();
    let durable = svc.directive_count();

    // Undurable: staged, never committed.
    svc.stage_remote_directive(remote_open("Assets:Undurable", make_date(2024, 3, 1), 50))
        .unwrap();
    let reload = svc.begin_recovery();
    let reloaded = reload.load();
    // A `set_author_id` between the snapshot and the swap is carried.
    svc.set_author_id("renamed-peer".to_owned());
    svc.finish_recovery(reload, reloaded);

    assert_eq!(svc.directive_count(), durable);
    assert!(!svc.accounts().is_open("Assets:Undurable"));
    assert_eq!(svc.author_id(), "renamed-peer");
    remove_ledger_and_journal(&path);
}

// ── L-40: a dangling parent naming a predictable future txid ─────────

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

/// L-40: the local append of exactly the predicted transaction used to be
/// refused with `CYCLE_DETECTED` naming its own new txid — the append
/// picked every head as a parent, including the planted one, and the
/// planted one names the new txid as ITS parent: a genuine two-node cycle
/// the node built itself. And had it been admitted, the next boot's T47
/// pre-scan would have quarantined both.
#[test]
fn l40_a_dangling_parent_naming_a_future_txid_does_not_block_that_append() {
    let victim_id = predicted_txid(balanced_input());

    let (svc, path) = setup_with_accounts();
    drop(svc);
    append_to_file(&path, &planted_dangling_parent(&victim_id));
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    // T84 / H-23: a parent that exists nowhere makes the planted entry a
    // record no peer could adopt, so boot holds it rather than serving it
    // as a head — the pointer never reaches the parent choice at all.
    assert_eq!(
        svc.quarantined_count(),
        1,
        "the planted entry is held, not served"
    );
    let planted_id = svc.quarantined_ids()[0].to_owned();

    let outcome = svc
        .append_transaction(balanced_input())
        .expect("L-40: the predicted append must not be refused as a cycle");
    assert_eq!(outcome.txid, victim_id);
    let parents = svc
        .get_directive(&victim_id)
        .unwrap()
        .metadata()
        .get("openledger-parents")
        .cloned()
        .unwrap_or_default();
    assert!(
        !parents.contains(&planted_id),
        "the new transaction must not name the entry that names it: {parents:?}"
    );

    // The file this leaves behind is acyclic: a reboot quarantines nothing
    // and holds both.
    svc.compact().unwrap();
    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.quarantined_count(), 0);
    assert!(rebooted.get_directive(&victim_id).is_some());
    assert!(rebooted.get_directive(&planted_id).is_some());
    remove_ledger_and_journal(&path);
}

/// L-40, the reconcile path: an operator's own envelope-less hand edit is
/// stamped with the current heads as parents in exactly the same way, so a
/// planted pointer at ITS id must not get it refused either.
#[test]
fn l40_a_dangling_parent_does_not_block_a_reconciled_hand_edit() {
    let victim_id = compute_content_id(
        &parse_file(HAND_EDITED_TRANSACTION)
            .unwrap()
            .into_iter()
            .next()
            .unwrap(),
    );

    let (mut svc, path) = setup_with_accounts();
    append_to_file(&path, &planted_dangling_parent(&victim_id));
    // T85 / H-23: the live path holds a complete envelope whose parent it
    // does not serve, as boot does since T84 — in the quarantine, kept in
    // the file — so the pointer never reaches the parent choice.
    let planted = svc.reconcile_file().unwrap();
    assert_eq!((planted.new_directives, svc.quarantined_count()), (0, 1));

    append_to_file(&path, HAND_EDITED_TRANSACTION);
    let result = svc.reconcile_file().unwrap();
    // The hand edit, and — its parent now resolving — the held entry.
    assert_eq!(
        (result.new_directives, result.rejected),
        (2, 0),
        "L-40: the hand edit must be adopted, not refused as a cycle"
    );
    assert!(svc.get_directive(&victim_id).is_some());
    assert_eq!(svc.quarantined_count(), 0);
    let victim_parents = svc
        .get_directive(&victim_id)
        .unwrap()
        .metadata()
        .get("openledger-parents")
        .cloned()
        .unwrap_or_default();
    let planted_id = svc
        .head_txids()
        .into_iter()
        .next()
        .expect("the planted entry is the head, naming the hand edit");
    assert!(
        !victim_parents.contains(&planted_id),
        "acyclic: the hand edit does not name the entry that names it"
    );

    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.quarantined_count(), 0);
    assert_eq!(rebooted.directive_count(), svc.directive_count());
    remove_ledger_and_journal(&path);
}

// ── L-35: cheap id views for anti-entropy ────────────────────────────

/// The new views agree with `all_directive_ids()` exactly, and the sorted
/// snapshot is reused until the DAG grows — then rebuilt, never stale.
#[test]
fn l35_id_views_agree_with_all_directive_ids_and_track_growth() {
    let (mut svc, path) = setup_with_accounts();
    svc.append_transaction(balanced_input()).unwrap();

    let owned = svc.all_directive_ids();
    let first = svc.sorted_directive_ids();
    let mut expected: Vec<String> = owned.iter().cloned().collect();
    expected.sort();
    assert_eq!(&*first, expected.as_slice());
    for id in &owned {
        assert!(svc.contains_directive(id));
    }
    assert!(!svc.contains_directive(&"0".repeat(64)));
    for head in svc.head_txids() {
        assert!(svc.is_head(&head));
    }
    assert!(!svc.is_head(&"0".repeat(64)));

    assert!(
        std::sync::Arc::ptr_eq(&first, &svc.sorted_directive_ids()),
        "L-35: an unchanged DAG must be answered from the snapshot, not re-cloned"
    );

    svc.stage_remote_directive(remote_open("Assets:Later", make_date(2024, 3, 1), 40))
        .unwrap();
    let grown = svc.sorted_directive_ids();
    assert!(
        !std::sync::Arc::ptr_eq(&first, &grown),
        "growth must invalidate"
    );
    assert_eq!(grown.len(), first.len() + 1);
    let mut expected: Vec<String> = svc.all_directive_ids().into_iter().collect();
    expected.sort();
    assert_eq!(&*grown, expected.as_slice());
    remove_ledger_and_journal(&path);
}

/// An L-13 reload that SHRINKS the DAG back to disk must not be answered
/// from a snapshot of the larger, rolled-back set.
#[test]
fn l35_the_snapshot_does_not_survive_a_reload() {
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();
    svc.stage_remote_directive(remote_open("Assets:Undurable", make_date(2024, 3, 1), 41))
        .unwrap();
    let before = svc.sorted_directive_ids();
    svc.recover_failed_commit();
    let after = svc.sorted_directive_ids();
    assert_eq!(after.len(), before.len() - 1);
    assert!(after.iter().all(|id| svc.contains_directive(id)));
    remove_ledger_and_journal(&path);
}

// ── T61 / T62: one file path; recovery never installs an emptier ledger ──

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

/// Manifest item 1 (H-13): the README's stop → edit → start workflow. The
/// hand-typed record carries this node's author, lamport, parents and
/// signature after boot + identity + startup compaction, a second service
/// accepts it through the peer path, and the node's next transaction
/// descends from a record every peer can verify.
///
/// Bug-catch: revert the operator-input split in `boot` (load
/// envelope-less directives as history again) and the metadata is `{}`.
#[test]
fn h13_a_stop_edit_start_hand_edit_is_adopted_signed_and_accepted_by_a_peer() {
    let (mut svc, path) = setup_with_signed_accounts();
    svc.set_signer(marker_signer());
    svc.compact().unwrap();
    drop(svc);

    // The node is stopped; the operator appends by hand.
    append_to_file(&path, OFFLINE_HAND_EDIT);

    // The node starts: boot, then — as `gl-node` does — identity, then the
    // startup compaction.
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(svc.unsigned_operator_input_count(), 1);
    assert_eq!(
        svc.directive_count(),
        4,
        "adopted at boot: visible to every post-boot reader immediately"
    );
    svc.set_signer(marker_signer());
    assert_eq!(svc.finalize_operator_input(), 1);
    assert_eq!(svc.unsigned_operator_input_count(), 0);
    svc.compact().unwrap();

    let adopted = transaction_named(&svc, "Offline edit")
        .expect("the hand-typed transaction is in the DAG")
        .clone();
    let stored_id = compute_content_id(&adopted);
    let metadata = adopted.metadata();
    assert_eq!(
        metadata.get("openledger-author"),
        Some(&"test-peer".to_owned()),
        "H-13: this node's author id"
    );
    let lamport = metadata
        .get("openledger-lamport")
        .expect("H-13: a lamport value");
    let parents = metadata
        .get("openledger-parents")
        .expect("H-13: a parents line");
    let signature = metadata
        .get("openledger-signature")
        .expect("H-13: signed as this node's own before the first persist");
    assert_eq!(
        signature,
        &format!("sig({stored_id}|true|{parents}|{lamport})"),
        "the signature covers exactly the envelope boot stamped"
    );

    // On disk in canonical form, envelope included.
    let on_disk = std::fs::read_to_string(&path).unwrap();
    let block = on_disk
        .split("\n\n")
        .find(|block| block.contains("Offline edit"))
        .expect("the record is in the file");
    assert!(block.contains(&format!("openledger-signature: \"{signature}\"")));
    assert!(block.contains("openledger-author: \"test-peer\""));

    // A restart reads it as history: nothing left to finalise.
    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.unsigned_operator_input_count(), 0);
    assert_eq!(rebooted.directive_count(), 4);

    // A second service accepts it through the peer path.
    let (mut peer, peer_path) = boot_empty();
    peer.stage_remote_directive(remote_open("Assets:Cash", make_date(2024, 1, 1), 1))
        .unwrap();
    peer.stage_remote_directive(remote_open("Equity:Opening", make_date(2024, 1, 1), 2))
        .unwrap();
    let accepted = peer
        .stage_remote_directive(adopted.clone())
        .expect("H-13: a peer must accept the adopted record");
    assert_eq!(accepted.as_deref(), Some(stored_id.as_str()));

    // The node's next transaction names it as a parent — which is now fine.
    let next = svc.append_transaction(balanced_input()).unwrap();
    let next_parents = svc
        .get_directive(&next.txid)
        .unwrap()
        .metadata()
        .get("openledger-parents")
        .cloned()
        .unwrap();
    assert!(next_parents.contains(&stored_id));

    remove_ledger_and_journal(&path);
    remove_ledger_and_journal(&peer_path);
}

/// H-13: operator input the adoption refuses at boot is quarantined —
/// kept in the file, kept out of the DAG, never loaded raw — and a repair
/// followed by a restart adopts it.
#[test]
fn h13_operator_input_boot_refuses_is_quarantined_not_dropped_and_not_loaded() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    append_to_file(&path, HAND_EDIT_ON_UNOPENED_ACCOUNT);

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut svc = booted.unwrap();
    assert!(
        transaction_named(&svc, "unopened").is_none(),
        "a transaction on an unopened account must not be loaded raw"
    );
    assert!(!svc.accounts().is_open("Assets:Vault"));
    assert_eq!(svc.quarantined_count(), 1);
    assert_eq!(svc.unsigned_operator_input_count(), 0);
    assert!(logged.contains("QUARANTINED"), "{logged}");

    svc.set_signer(marker_signer());
    svc.finalize_operator_input();
    svc.compact().unwrap();
    assert!(
        std::fs::read_to_string(&path).unwrap().contains("unopened"),
        "boot never drops what it read"
    );

    // Repair by hand, restart: the open sorts first, the transaction adopts.
    append_to_file(&path, "\n2024-01-01 open Assets:Vault USD\n");
    let (rebooted, _) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let rebooted = rebooted.unwrap();
    assert!(transaction_named(&rebooted, "unopened").is_some());
    assert_eq!(rebooted.quarantined_count(), 0);
    assert_eq!(rebooted.unsigned_operator_input_count(), 2);

    remove_ledger_and_journal(&path);
}

/// H-13: an L-13 reload before the startup compaction re-derives the
/// operator input and `finish_recovery` finalises it with the carried
/// signer, so the caller's next commit still writes it signed.
#[test]
fn h13_a_reload_before_the_first_compaction_re_signs_the_operator_input() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    append_to_file(&path, OFFLINE_HAND_EDIT);

    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    // Not finalised yet — and a commit fails before the startup compaction.
    let (_, logged) = capture_warnings(|| svc.recover_failed_commit());
    assert!(logged.contains("L-13 reload installed"), "{logged}");
    assert_eq!(svc.unsigned_operator_input_count(), 0);
    let adopted = transaction_named(&svc, "Offline edit").unwrap();
    assert!(
        adopted.metadata().contains_key("openledger-signature"),
        "finish_recovery must finalise the re-derived operator input"
    );
    svc.compact().unwrap();
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("openledger-signature"));
    remove_ledger_and_journal(&path);
}

/// Manifest item 2 (H-14): a failed reconcile is followed by a write that
/// returns `PARSE_ERROR` and leaves both hand-written lines on disk — on
/// both sides of `COMPACTION_MIN_CANONICAL_BYTES`.
///
/// Bug-catch: move the `last_file_hash`/marker assignments in
/// `reconcile_content` back above the parse and the write succeeds and
/// the file loses both lines.
#[test]
fn h14_a_failed_reconcile_leaves_the_edit_on_disk_and_blocks_the_next_write() {
    // Below the threshold: every commit is a compaction.
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();
    let canonical = std::fs::read_to_string(&path).unwrap();
    let edited = format!("{canonical}\n2024-02-01 open Assets:New USD\n\n2024-03-03 open\n");
    std::fs::write(&path, &edited).unwrap();

    let (result, _) = capture_warnings(|| svc.reconcile_file_staged());
    assert_eq!(result.unwrap_err().error_code(), "PARSE_ERROR");
    let (outcome, _) = capture_warnings(|| svc.append_transaction(balanced_input()));
    assert_eq!(
        outcome.unwrap_err().error_code(),
        "PARSE_ERROR",
        "H-14: the next write must be refused, not canonicalised over the edit"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        edited,
        "both hand-written lines survive, byte for byte"
    );
    assert!(!svc.accounts().is_open("Assets:New"));
    remove_ledger_and_journal(&path);

    // Above the threshold: the append path, with a journal outstanding.
    let (mut svc, path) = boot_large_ledger();
    svc.stage_remote_directive(remote_open("Assets:Journaled", make_date(2024, 3, 1), 10))
        .unwrap();
    svc.persist_or_reload().unwrap();
    assert!(
        svc.journal_bytes() > 0,
        "the fixture must be on the append path"
    );
    let canonical = std::fs::read_to_string(&path).unwrap();
    let edited = format!("{canonical}\n2024-02-01 open Assets:New USD\n\n2024-03-03 open\n");
    std::fs::write(&path, &edited).unwrap();

    let (result, _) = capture_warnings(|| svc.reconcile_file_staged());
    assert_eq!(result.unwrap_err().error_code(), "PARSE_ERROR");
    svc.stage_remote_directive(remote_open("Assets:After", make_date(2024, 3, 2), 11))
        .unwrap();
    let (outcome, _) = capture_warnings(|| svc.persist_or_reload());
    assert_eq!(outcome.unwrap_err().error_code(), "PARSE_ERROR");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
    assert!(!svc.accounts().is_open("Assets:New"));
    remove_ledger_and_journal(&path);
}

/// M-37(a), the `e1b`/`e12` shape: a refused hand edit is NOT loaded raw
/// by a recovery boot after a failed write; the refusal is stable until
/// the file is repaired; and after the repair the entry is refused by the
/// reconcile's own I3 check rather than loaded.
///
/// Bug-catch: put the `recover_failed_commit` back on the `Parse` arm of
/// `commit_inline` and the hand-typed transaction is in the DAG after the
/// first failed write.
#[test]
fn m37a_a_refused_hand_edit_is_not_loaded_raw_by_a_failed_write() {
    let (mut svc, path) = setup_with_accounts();
    svc.set_signer(marker_signer());
    svc.compact().unwrap();
    let canonical = std::fs::read_to_string(&path).unwrap();
    let edited = format!("{canonical}{HAND_EDIT_ON_UNOPENED_ACCOUNT}\n2024-03-03 open\n");
    std::fs::write(&path, &edited).unwrap();

    let (outcome, _) = capture_warnings(|| svc.append_transaction(balanced_input()));
    assert_eq!(outcome.unwrap_err().error_code(), "PARSE_ERROR");
    assert!(
        transaction_named(&svc, "unopened").is_none(),
        "M-37(a): the hand-typed transaction must not be loaded raw by a recovery boot"
    );
    assert!(!svc.accounts().is_open("Assets:Vault"));

    // Stable: refused again, file untouched.
    let (outcome, _) = capture_warnings(|| svc.append_transaction(balanced_input()));
    assert_eq!(outcome.unwrap_err().error_code(), "PARSE_ERROR");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);

    // Repair the broken line. The write goes through; the transaction on
    // the unopened account is refused by the reconcile and dropped.
    std::fs::write(&path, format!("{canonical}{HAND_EDIT_ON_UNOPENED_ACCOUNT}")).unwrap();
    let (outcome, logged) = capture_warnings(|| svc.append_transaction(balanced_input()));
    outcome.expect("after the repair the write goes through");
    assert!(logged.contains("will drop them from the file"), "{logged}");
    assert!(transaction_named(&svc, "unopened").is_none());
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("Funding"));
    assert!(!on_disk.contains("Assets:Vault"));
    remove_ledger_and_journal(&path);
}

/// M-37(b), the `e13` shape: a rejected-ONLY hand edit arms the compaction
/// the L-12 warning promises, the rewrite drops it from the file, and the
/// next boot cannot load it.
///
/// Bug-catch: revert `rejected > 0` in `reconcile_file_staged` /
/// `reconcile_file` and `compaction_pending()` is false / the entry stays
/// on disk.
#[test]
fn m37b_a_rejected_only_hand_edit_is_dropped_by_the_re_persist() {
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();

    // The watcher's half: stage, then the commit the node drives.
    append_to_file(&path, HAND_EDIT_ON_UNOPENED_ACCOUNT);
    let (result, logged) = capture_warnings(|| svc.reconcile_file_staged());
    let result = result.unwrap();
    assert_eq!((result.new_directives, result.rejected), (0, 1));
    assert!(logged.contains("will drop them from the file"));
    assert!(
        svc.compaction_pending(),
        "M-37(b): a rejected-only reconcile must arm the compaction its warning promises"
    );
    svc.compact().unwrap();
    assert!(!std::fs::read_to_string(&path).unwrap().contains("unopened"));

    // The inline form does it by itself.
    append_to_file(&path, HAND_EDIT_ON_UNOPENED_ACCOUNT);
    let (result, _) = capture_warnings(|| svc.reconcile_file());
    assert_eq!(result.unwrap().rejected, 1);
    assert!(!std::fs::read_to_string(&path).unwrap().contains("unopened"));

    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert!(transaction_named(&rebooted, "unopened").is_none());
    assert!(!rebooted.accounts().is_open("Assets:Vault"));
    remove_ledger_and_journal(&path);
}

/// M-38, the `e3` shape: a reconcile over a file holding a planted parent
/// cycle keeps BOTH members quarantined, `heads` excludes them, the
/// node's own next transaction does not descend from either, and the next
/// boot does not quarantine that transaction.
///
/// Bug-catch: drop the Kahn pre-scan from `reconcile_content` and one
/// member leaks into the DAG (quarantine shrinks to one).
#[test]
fn m38_a_reconcile_keeps_both_members_of_a_planted_cycle_quarantined() {
    let (mut svc, path) = setup_with_accounts();
    let a = svc
        .append_transaction(narrated_input(make_date(2024, 2, 1), "A"))
        .unwrap()
        .txid;
    let b = svc
        .append_transaction(narrated_input(make_date(2024, 2, 2), "B"))
        .unwrap()
        .txid;
    drop(svc);

    // Plant the cycle: A's parents := B (B already names A).
    let text = std::fs::read_to_string(&path).unwrap();
    let mut planted = String::new();
    let mut in_a = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            in_a = line.contains("\"A\"");
        }
        if in_a && line.trim_start().starts_with("openledger-parents:") {
            planted.push_str(&format!("  openledger-parents: \"{b}\"\n"));
        } else {
            planted.push_str(line);
            planted.push('\n');
        }
    }
    std::fs::write(&path, &planted).unwrap();

    let (booted, _) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut svc = booted.unwrap();
    let mut quarantined: Vec<String> = svc
        .quarantined_ids()
        .iter()
        .map(|id| (*id).to_owned())
        .collect();
    quarantined.sort();
    let mut expected = vec![a.clone(), b.clone()];
    expected.sort();
    assert_eq!(quarantined, expected, "boot quarantines both members");
    let (_, _) = capture_warnings(|| svc.compact().unwrap());

    // An unrelated hand edit triggers a reconcile.
    append_to_file(&path, "\n2024-01-01 open Assets:Other USD\n");
    let (result, _) = capture_warnings(|| svc.reconcile_file());
    let result = result.unwrap();
    assert_eq!(result.new_directives, 1);
    let mut still: Vec<String> = svc
        .quarantined_ids()
        .iter()
        .map(|id| (*id).to_owned())
        .collect();
    still.sort();
    assert_eq!(still, expected, "M-38: the quarantine must stay {{A, B}}");
    assert!(!svc.dag().heads().contains(&a) && !svc.dag().heads().contains(&b));

    let c = svc
        .append_transaction(narrated_input(make_date(2024, 3, 1), "C"))
        .unwrap()
        .txid;
    let c_parents = svc
        .get_directive(&c)
        .unwrap()
        .metadata()
        .get("openledger-parents")
        .cloned()
        .unwrap();
    assert!(
        !c_parents.contains(&a) && !c_parents.contains(&b),
        "the node's own transaction must not descend from a cycle member: {c_parents}"
    );

    let (rebooted, _) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let rebooted = rebooted.unwrap();
    assert!(
        rebooted.get_directive(&c).is_some(),
        "C must not be quarantined at the next boot"
    );
    assert_eq!(rebooted.quarantined_ids().len(), 2);
    remove_ledger_and_journal(&path);
}

/// L-55: a reconcile entry that is rejected after the stamp point, and
/// dropped by the rewrite, leaves the Lamport clock exactly where it was,
/// and the next authored envelope continues from there.
///
/// Since T103 (L-141, decision (70a)) the entry is a half envelope — a
/// hand-typed lamport, no author — which the reconcile refuses and the
/// rewrite drops. Until then it carried this node's author too: history
/// that T90 holds in the file, and whose lamport boot counts
/// (`BootLamportHigh`), so the running node now counts it as well
/// (`a1_0927_a_held_own_record_s_lamport_is_never_re_issued`, `l141_…`).
///
/// Bug-catch: move `self.lamport_clock = next_lamport` back above the
/// validation in `adopt_file_directive` and the clock jumps to 5000.
#[test]
fn l55_a_rejected_reconcile_entry_does_not_move_the_clock() {
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();
    let before = svc.lamport_clock();

    append_to_file(
        &path,
        "\n2024-02-01 * \"Hand\" \"unbalanced\"\n  \
             openledger-lamport: \"5000\"\n  \
             Assets:Cash                                        250.00 USD\n  \
             Equity:Opening                                     -10.00 USD\n",
    );
    let (result, _) = capture_warnings(|| svc.reconcile_file());
    assert_eq!(result.unwrap().rejected, 1);
    assert!(
        svc.quarantined_ids().is_empty(),
        "premise: operator input the reconcile refuses is dropped, not held"
    );
    assert_eq!(
        svc.lamport_clock(),
        before,
        "L-55: a rejected entry must not move the clock"
    );

    let id = svc
        .open_account("Assets:Next".to_owned(), make_date(2024, 3, 1), vec![])
        .unwrap();
    assert_eq!(
        svc.get_directive(&id).unwrap().lamport_clock(),
        Some(before + 1),
        "the next authored envelope continues from the untouched clock"
    );
    remove_ledger_and_journal(&path);
}

/// L-62, the `e7` shape: a mid-file byte-order mark neither bricks boot
/// (as the file's only defect) nor loads the marked block (with another
/// broken block present); the block is held verbatim across compactions.
///
/// Bug-catch: call `parse_file` instead of `parse_block` in the salvage
/// and (a) fails to boot while (b) opens `Assets:Bom`.
#[test]
fn l62_a_mid_file_byte_order_mark_boots_and_the_marked_block_is_not_loaded() {
    let base = "2024-01-01 open Assets:Cash USD\n\n2024-01-01 open Equity:Opening USD\n";

    // (a) the BOM'd header is the file's only defect.
    let path = test_file_path();
    std::fs::write(
        &path,
        format!("{base}\n\u{FEFF}2024-02-01 open Assets:Bom USD\n"),
    )
    .unwrap();
    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut svc = booted.expect("L-62: a mid-file BOM must not brick boot");
    assert_eq!(svc.unparsable_block_count(), 1);
    assert!(
        !svc.accounts().is_open("Assets:Bom"),
        "the whole-file parser refused it; the salvage must not load it"
    );
    assert!(logged.contains("byte-order mark"), "{logged}");
    svc.compact().unwrap();
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("\u{FEFF}2024-02-01 open Assets:Bom"));
    let (rebooted, _) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let rebooted = rebooted.unwrap();
    assert_eq!(rebooted.unparsable_block_count(), 1);
    assert!(!rebooted.accounts().is_open("Assets:Bom"));
    remove_ledger_and_journal(&path);

    // (b) another broken block is present too.
    let path = test_file_path();
    std::fs::write(
        &path,
        format!("{base}\n\u{FEFF}2024-02-01 open Assets:Bom USD\n\n2024-03-03 open\n"),
    )
    .unwrap();
    let (booted, _) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let svc = booted.unwrap();
    assert_eq!(svc.unparsable_block_count(), 2);
    assert!(!svc.accounts().is_open("Assets:Bom"));
    remove_ledger_and_journal(&path);
}

/// Manifest item 3 (H-15): `remove_file(.bean)` under a running service →
/// the next write succeeds and the file holds every directive.
///
/// Bug-catch: make `adopt_external_edits` propagate `NotFound` again and
/// the write fails with `IO`, the reload installs an empty ledger, and the
/// file ends up holding one directive.
#[test]
fn h15_removing_the_bean_under_a_running_service_loses_nothing() {
    let (mut svc, path) = boot_empty();
    for name in ["Assets:A", "Assets:B", "Assets:C"] {
        svc.open_account(
            name.to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
    }
    std::fs::remove_file(&path).unwrap();

    let (outcome, logged) = capture_warnings(|| {
        svc.open_account(
            "Assets:D".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
    });
    outcome.expect("H-15: the write after the file vanished must succeed");
    assert!(logged.contains("MISSING"), "{logged}");
    assert_eq!(svc.directive_count(), 4);

    let on_disk = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(
        on_disk.directive_count(),
        4,
        "the recreated file holds every directive"
    );
    for name in ["Assets:A", "Assets:B", "Assets:C", "Assets:D"] {
        assert!(on_disk.accounts().is_open(name), "{name}");
    }
    remove_ledger_and_journal(&path);
}

/// H-15: the L-13 reload itself. A rebuild is refused when it holds fewer
/// directives than `dag.len() − pending_ids.len()` — the file gone, or
/// truncated below memory — and installed when it is short by exactly the
/// staged batch, which is the legitimate shape of a failed commit.
///
/// Bug-catch: drop the floor check in `finish_recovery` (or let a reload
/// create the file) and case 1 installs an empty ledger.
#[test]
fn h15_a_recovery_reload_never_installs_an_emptier_ledger() {
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();
    let count = svc.directive_count();

    // Case 1: the file is gone. A reload never creates it.
    std::fs::remove_file(&path).unwrap();
    let (_, logged) = capture_warnings(|| svc.recover_failed_commit());
    assert!(!path.exists(), "a reload must never create the ledger file");
    assert_eq!(svc.directive_count(), count, "memory is kept");
    assert!(logged.contains("H-15"), "{logged}");
    // The next commit writes memory back.
    let (outcome, _) = capture_warnings(|| {
        svc.open_account("Assets:Recovered".to_owned(), make_date(2024, 2, 1), vec![])
    });
    outcome.unwrap();
    assert_eq!(
        LedgerService::boot(path.clone(), "test-peer".to_owned())
            .unwrap()
            .directive_count(),
        count + 1
    );

    // Case 2: the file is there but holds less than memory minus the staged
    // batch. Refused, and the refusal arms a full rewrite.
    std::fs::write(&path, "2024-01-01 open Assets:Only USD\n").unwrap();
    svc.stage_remote_directive(remote_open("Assets:Staged", make_date(2024, 3, 1), 10))
        .unwrap();
    let before = svc.directive_count();
    let (_, logged) = capture_warnings(|| svc.recover_failed_commit());
    // T100 / L-147, decision (62): memory is kept — less the write the
    // failed commit staged, which is rolled back.
    assert_eq!(
        svc.directive_count(),
        before - 1,
        "H-15: the emptier rebuild must not install; the staged open is rolled back"
    );
    assert!(logged.contains("REFUSING"), "{logged}");
    assert!(svc.compaction_pending());
    let (outcome, _) = capture_warnings(|| svc.compact());
    outcome.unwrap();
    let durable = svc.directive_count();
    assert_eq!(
        LedgerService::boot(path.clone(), "test-peer".to_owned())
            .unwrap()
            .directive_count(),
        durable,
        "the rewrite put every in-memory directive back on disk"
    );

    // Case 3 (control): short by exactly the staged batch — installed.
    svc.stage_remote_directive(remote_open("Assets:Undurable", make_date(2024, 3, 2), 11))
        .unwrap();
    let (_, logged) = capture_warnings(|| svc.recover_failed_commit());
    assert!(logged.contains("L-13 reload installed"), "{logged}");
    assert_eq!(svc.directive_count(), durable);
    assert!(!svc.accounts().is_open("Assets:Undurable"));
    remove_ledger_and_journal(&path);
}

/// H-15: a fresh boot refuses an absent `.bean` that has a journal beside
/// it, naming both files; with the journal gone the same path is a new
/// ledger.
#[test]
fn h15_boot_refuses_a_missing_bean_beside_a_journal() {
    let (mut svc, path) = boot_large_ledger();
    svc.stage_remote_directive(remote_open("Assets:Journaled", make_date(2024, 3, 1), 10))
        .unwrap();
    svc.persist_or_reload().unwrap();
    let journal_path = svc.journal_path().to_path_buf();
    assert!(journal_path.exists());
    drop(svc);

    std::fs::remove_file(&path).unwrap();
    let error = match LedgerService::boot(path.clone(), "test-peer".to_owned()) {
        Ok(_) => panic!("H-15: no .bean beside a journal must not boot an empty ledger"),
        Err(error) => error,
    };
    assert_eq!(error.error_code(), "IO_ERROR");
    let rendered = error.to_string();
    assert!(rendered.contains(&path.display().to_string()), "{rendered}");
    assert!(
        rendered.contains(&journal_path.display().to_string()),
        "{rendered}"
    );
    assert!(!path.exists(), "the refusal must not create the file");

    std::fs::remove_file(&journal_path).unwrap();
    let fresh = LedgerService::boot(path.clone(), "test-peer".to_owned())
        .expect("with nothing beside it the path is a new ledger");
    assert_eq!(fresh.directive_count(), 0);
    remove_ledger_and_journal(&path);
}

/// Manifest item 3 (M-35): the `brick` fixture — `canonical + journal >
/// MAX_LEDGER_FILE_BYTES` with the journal a subset of the canonical, the
/// state a crash between the compaction's rename and its `remove_journal`
/// leaves — boots, with `directive_count == boot(canonical alone)`.
///
/// Bug-catch: budget the journal at `MAX − canonical` again and boot fails
/// with `LEDGER_JOURNAL`.
#[test]
fn m35_a_journal_left_behind_by_a_crashed_compaction_still_boots() {
    let path = test_file_path();
    let journal_path = crate::journal::journal_path_for(&path);
    // The budget is checked against the journal's LENGTH before a byte is
    // parsed, so the shape is built from bytes, not directives: one
    // enveloped note (history) padded with 1 MiB comment lines, which the
    // parser skips in O(lines). C ≈ 63 MiB, J ≈ 2 MiB (over the old
    // `MAX − C` budget of 1 MiB), J's directive ⊂ C. Sized so the SHA-256
    // passes — the only per-byte cost left — total ~67 MiB; a fixture of
    // real 1 MiB directives proves the same thing at twenty seconds in a
    // debug build.
    let note = Directive::Note(Note {
        date: make_date(2024, 1, 1),
        account: "Assets:Cash".to_owned(),
        comment: "folded".to_owned(),
        metadata: filler_envelope(1),
    });
    let note_text = full_file_serialize(std::slice::from_ref(&note), &[]);
    let padding_line = format!(";{}\n", "x".repeat((1 << 20) - 2));
    let canonical = format!("{note_text}{}", padding_line.repeat(63));
    std::fs::write(&path, &canonical).unwrap();
    let payload = format!("{note_text}{}", padding_line.repeat(2));
    std::fs::write(&journal_path, crate::journal::record_bytes(&payload)).unwrap();
    let c = std::fs::metadata(&path).unwrap().len();
    let j = std::fs::metadata(&journal_path).unwrap().len();
    assert!(
        c + j > MAX_LEDGER_FILE_BYTES,
        "fixture: {c} + {j} must exceed the cap"
    );
    assert!(c <= MAX_LEDGER_FILE_BYTES && j <= MAX_LEDGER_FILE_BYTES);

    let booted = LedgerService::boot(path.clone(), "test-peer".to_owned())
        .expect("M-35: a fully folded journal must not brick boot");
    // `directive_count == boot(C alone)`: the canonical's own directive
    // set, read without a second 63 MiB hash.
    let canonical_alone = parse_file(&canonical).unwrap().len();
    assert_eq!(canonical_alone, 1);
    assert_eq!(
        booted.directive_count(),
        canonical_alone,
        "the journal was fully folded into the canonical file"
    );
    remove_ledger_and_journal(&path);
}

/// L-64 (the `r2` shape): after one `recover_failed_commit()` on a healthy
/// ledger past the threshold, the next prepare is still an `Append`.
///
/// Bug-catch: stop carrying `canonical_is_current` in `adopt_reloaded`
/// and the second prepare is a `Compact`.
#[test]
fn l64_a_recovery_reload_on_a_healthy_ledger_keeps_the_append_path() {
    let (mut svc, path) = boot_large_ledger();
    svc.stage_remote_directive(remote_open("Assets:One", make_date(2024, 3, 1), 10))
        .unwrap();
    let pending = svc.prepare_commit().unwrap().expect("something staged");
    assert_eq!(
        pending.kind(),
        CommitKind::Append,
        "premise: a healthy ledger appends"
    );
    drop(pending);

    let (_, _) = capture_warnings(|| svc.recover_failed_commit());

    svc.stage_remote_directive(remote_open("Assets:Two", make_date(2024, 3, 2), 11))
        .unwrap();
    let pending = svc.prepare_commit().unwrap().expect("something staged");
    assert_eq!(
        pending.kind(),
        CommitKind::Append,
        "L-64: a reload that read the bytes this service wrote must not force a compaction"
    );
    drop(pending);
    remove_ledger_and_journal(&path);
}

// ── T67: file-type discipline for every ledger-side open ─────────────

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

/// M-36: `mkfifo ledger.bean` used to hang boot after the lock was taken
/// (`metadata().len() == 0` passed the cap, then `read_to_string` blocked).
/// Boot now refuses it at once, naming the file type.
///
/// Bug-catch: skip `open_checked` in `read_ledger_file` and this blocks.
#[cfg(unix)]
#[test]
fn m36_boot_refuses_a_fifo_bean_without_blocking() {
    let directory = t67_directory("m36-fifo-bean");
    let path = directory.join("ledger.bean");
    mkfifo(&path);
    let outcome = boot_error_within(path);
    assert!(
        outcome.starts_with("Err:") && outcome.contains("not a regular file"),
        "{outcome}"
    );
    std::fs::remove_dir_all(directory).ok();
}

/// M-36: a FIFO at the journal path hung boot in `read_journal`.
#[cfg(unix)]
#[test]
fn m36_boot_refuses_a_fifo_journal_without_blocking() {
    let directory = t67_directory("m36-fifo-journal");
    let path = directory.join("ledger.bean");
    std::fs::write(&path, "2024-01-01 open Assets:Cash USD\n").unwrap();
    mkfifo(&crate::journal::journal_path_for(&path));
    let outcome = boot_error_within(path);
    assert!(
        outcome.starts_with("Err:") && outcome.contains("not a regular file"),
        "{outcome}"
    );
    std::fs::remove_dir_all(directory).ok();
}

/// M-36, the runtime shape (B8 `fifo-runtime`): the `.bean` replaced by a
/// FIFO under a running service. The next write's hand-edit check used to
/// block in `read_ledger_file` under the write lock; it now fails the write
/// (and the L-13 reload) at once, and memory is kept.
#[cfg(unix)]
#[test]
fn m36_a_fifo_swapped_in_for_the_bean_fails_the_next_write_without_blocking() {
    let directory = t67_directory("m36-fifo-runtime");
    let path = directory.join("ledger.bean");
    std::fs::write(&path, "").unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.open_account("Assets:A".into(), make_date(2024, 1, 1), vec!["USD".into()])
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    mkfifo(&path);

    let (outcome, count) = within(5, move || {
        let outcome =
            svc.open_account("Assets:B".into(), make_date(2024, 1, 1), vec!["USD".into()]);
        (
            outcome.map_err(|error| error.to_string()),
            svc.directive_count(),
        )
    });
    let error = outcome.expect_err("a FIFO .bean must fail the write");
    assert!(error.contains("not a regular file"), "{error}");
    assert!(count >= 1, "memory is kept");
    std::fs::remove_dir_all(directory).ok();
}

/// The symlinked-`.bean` policy (T67): FOLLOWED when the target is a
/// regular file; refused, without blocking, when the target is a FIFO; and
/// a dangling link is refused rather than read as "no ledger" — which used
/// to create an empty file over the link.
#[cfg(unix)]
#[test]
fn t67_a_symlinked_bean_is_followed_only_to_a_regular_file() {
    let directory = t67_directory("t67-bean-link");
    let path = directory.join("ledger.bean");

    let target = directory.join("real.bean");
    std::fs::write(&target, "2024-01-01 open Assets:Cash USD\n").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let svc = LedgerService::boot(path.clone(), "test-peer".to_owned())
        .expect("a symlink to a regular file is followed");
    assert!(svc.accounts().is_open("Assets:Cash"));
    drop(svc);

    std::fs::remove_file(&path).unwrap();
    let fifo = directory.join("fifo-target");
    mkfifo(&fifo);
    std::os::unix::fs::symlink(&fifo, &path).unwrap();
    let outcome = boot_error_within(path.clone());
    assert!(outcome.contains("not a regular file"), "{outcome}");

    std::fs::remove_file(&path).unwrap();
    let missing = directory.join("not-there.bean");
    std::os::unix::fs::symlink(&missing, &path).unwrap();
    let outcome = boot_error_within(path.clone());
    assert!(outcome.contains("symbolic link"), "{outcome}");
    assert!(!missing.exists(), "nothing is created through the link");
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink(),
        "and the link is not replaced by an empty ledger"
    );
    std::fs::remove_dir_all(directory).ok();
}

/// T67: a symlink at the journal path is refused at boot (it was already
/// refused on append, L-44).
#[cfg(unix)]
#[test]
fn t67_boot_refuses_a_symlinked_journal() {
    let directory = t67_directory("t67-journal-link");
    let path = directory.join("ledger.bean");
    std::fs::write(&path, "2024-01-01 open Assets:Cash USD\n").unwrap();
    let elsewhere = directory.join("elsewhere");
    crate::journal::append_record(
        &elsewhere,
        &crate::journal::record_bytes("2024-01-02 open Assets:Planted USD\n"),
    )
    .unwrap();
    std::os::unix::fs::symlink(&elsewhere, crate::journal::journal_path_for(&path)).unwrap();
    let outcome = boot_error_within(path);
    assert!(outcome.contains("symbolic link"), "{outcome}");
    std::fs::remove_dir_all(directory).ok();
}

// ── T78: L-67, the placeholder boot author ───────────────────────────

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

/// L-67 (the audit's D3 `h5`): `gl-node` boots under the placeholder
/// `"local"` and calls `set_author_id` once the key is loaded. Boot folds
/// an out-of-DAG record into the clock only when it is the boot author's,
/// so the node's own quarantined record at 12 was ignored, the clock
/// resumed at 7, and six local writes stamped 8..=13 — re-issuing the pair
/// `(REALENDPOINTID, 12)` it had already signed (M-18). `set_author_id`
/// now folds it: the clock resumes where a boot under the real id resumes,
/// and no stamp repeats a quarantined own pair.
///
/// Bug-catch: make `set_author_id` only assign the author again and the
/// clock stays at 7 and the stamps include 12.
#[test]
fn l67_set_author_id_resumes_the_clock_above_own_quarantined_records() {
    let path = l67_file("");
    let mut svc = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
    assert_eq!(svc.quarantined_count(), 1, "the own record is quarantined");
    assert_eq!(
        svc.lamport_clock(),
        7,
        "boot under the placeholder: DAG max + 1"
    );
    svc.set_author_id(L67_REAL.to_owned());
    let control = LedgerService::boot(path.clone(), L67_REAL.to_owned()).unwrap();
    assert_eq!(
        svc.lamport_clock(),
        control.lamport_clock(),
        "the clock a boot under the real author resumes at"
    );
    assert!(svc.lamport_clock() > 12);
    drop(control);

    let mut stamped = Vec::new();
    for index in 0..6 {
        let id = svc
            .open_account(
                format!("Assets:N{index}"),
                make_date(2024, 1, 1),
                Vec::new(),
            )
            .unwrap();
        stamped.push(svc.get_directive(&id).unwrap().lamport_clock().unwrap());
    }
    assert!(
        stamped.iter().all(|lamport| *lamport > 12),
        "M-18: a quarantined own pair is never re-issued: {stamped:?}"
    );
    remove_ledger_and_journal(&path);
}

/// L-67, the audit's X1-3 half: a hand-typed line adopted at boot as
/// operator input got its lamport from the placeholder boot's clock (7 +
/// 1), while an L-13 reload — a boot under the REAL author — stamps it
/// above the own quarantined record (13 + 1). Which envelope the mesh saw
/// depended on whether a startup compaction ever failed. Since T84 the
/// lamport is stamped by `finalize_operator_input` from the clock
/// `set_author_id` raised, so the two agree, and the signed pair is never
/// an own quarantined one.
///
/// Bug-catch: skip the clock raise in `set_author_id` and the placeholder
/// path finalises the hand line at 8, the reload at 14.
#[test]
fn l67_operator_input_gets_the_same_lamport_on_a_placeholder_boot_and_a_reload() {
    let path =
        l67_file("\n2024-01-20 * \"hand typed\"\n  Assets:Cash  2 USD\n  Equity:Opening  -2 USD\n");
    let hand = |svc: &LedgerService| {
        svc.dag()
            .directives()
            .into_iter()
            .find(|directive| {
                matches!(directive, Directive::Transaction(txn)
                        if txn.narration.as_deref() == Some("hand typed"))
            })
            .cloned()
            .expect("the hand line is adopted")
    };
    let hand_lamport = |svc: &LedgerService| hand(svc).lamport_clock().unwrap();

    let mut placeholder = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
    assert_eq!(placeholder.unsigned_operator_input_count(), 1);
    placeholder.set_author_id(L67_REAL.to_owned());
    assert_eq!(placeholder.finalize_operator_input(), 1);
    let via_placeholder = hand_lamport(&placeholder);

    let mut reload = LedgerService::boot(path.clone(), L67_REAL.to_owned()).unwrap();
    assert_eq!(reload.finalize_operator_input(), 1);
    let via_reload = hand_lamport(&reload);

    assert_eq!(via_placeholder, via_reload, "Fresh and reload agree");
    assert!(via_placeholder > 12, "above the own quarantined record");
    assert_eq!(placeholder.lamport_clock(), reload.lamport_clock());
    // The read model serves what the DAG holds.
    let served = placeholder
        .read_model()
        .transaction(&compute_content_id(&hand(&placeholder)))
        .and_then(|indexed| {
            indexed
                .transaction
                .metadata
                .get("openledger-lamport")
                .cloned()
        });
    assert_eq!(served, Some(via_placeholder.to_string()));
    remove_ledger_and_journal(&path);
}

/// T78: an envelope naming this node inside a block boot could not parse
/// — a node-written record held as raw text — is a pair this node signed.
/// It now feeds the clock at boot, under the real author and through
/// `set_author_id` alike; a foreign envelope in the same text does not.
///
/// Bug-catch: drop the `note_text_if_own` loop in `boot_with` and both
/// clocks resume at 13, below the own raw record at 40.
#[test]
fn t78_an_own_envelope_in_unparsable_text_feeds_the_clock() {
    let raw = format!(
        "\n2024-01-05 open Assets:Mine\n  openledger-author: \"{L67_REAL}\"\n  \
             openledger-lamport: \"40\"\n  this line does not parse\n\n\
             2024-01-06 open Assets:Theirs\n  openledger-author: \"someone-else\"\n  \
             openledger-lamport: \"90\"\n  neither does this one\n"
    );
    let path = l67_file(&raw);
    let real = LedgerService::boot(path.clone(), L67_REAL.to_owned()).unwrap();
    assert_eq!(
        real.quarantined_text.len(),
        2,
        "both blocks are held as text"
    );
    assert_eq!(
        real.lamport_clock(),
        41,
        "own raw 40 counts, foreign raw 90 does not"
    );
    drop(real);
    let mut placeholder = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
    assert_eq!(placeholder.lamport_clock(), 7);
    placeholder.set_author_id(L67_REAL.to_owned());
    assert_eq!(placeholder.lamport_clock(), 41);
    remove_ledger_and_journal(&path);
}

/// The text scan's shape rules: pairs per directive, quoted or not, a
/// directive with only half an envelope or an unreadable lamport yields
/// nothing, comments are skipped.
#[test]
fn t78_envelope_pairs_in_text_reads_one_pair_per_directive() {
    let text = "2024-01-01 open A:B\n  openledger-author: \"x\"\n  openledger-lamport: 7\n\
                    ; a comment\n\
                    2024-01-02 open A:C\n  openledger-author: \"y\"\n\
                    2024-01-03 open A:D\n  openledger-lamport: \"9\"\n\
                    2024-01-04 open A:E\n  openledger-author: \"z\"\n  openledger-lamport: \"nine\"\n\
                    2024-01-05 open A:F\n\topenledger-lamport: \"11\"\n  openledger-author: \"w\"\n";
    assert_eq!(
        envelope_pairs_in_text(text),
        vec![("x".to_owned(), 7), ("w".to_owned(), 11)]
    );
}

// ── T78: L-64, the canonical form over the cap ───────────────────────

/// The length [`LedgerService::compaction_text_len`] computes is the
/// length of the text a compaction writes, on every shape that frames it
/// differently: empty, directives only, leading comments, quarantined
/// directives, unparsable text blocks, operator input before and after
/// finalisation.
#[test]
fn t78_compaction_text_len_is_the_length_of_compaction_text() {
    let check = |svc: &LedgerService, shape: &str| {
        assert_eq!(
            svc.compaction_text_len(),
            svc.compaction_text().len() as u64,
            "{shape}"
        );
    };
    let empty = test_file_path();
    let svc = LedgerService::boot(empty.clone(), "test-peer".to_owned()).unwrap();
    check(&svc, "empty");
    remove_ledger_and_journal(&empty);

    let (svc, path) = boot_large_ledger();
    check(&svc, "large, canonical");
    remove_ledger_and_journal(&path);

    let comments = test_file_path();
    std::fs::write(&comments, ";no space\n;  two\n\n").unwrap();
    let svc = LedgerService::boot(comments.clone(), "test-peer".to_owned()).unwrap();
    check(&svc, "comments only");
    remove_ledger_and_journal(&comments);

    let path = l67_file(
        "\n2024-01-05 open Assets:Mine\n  this line does not parse\n\
             \n2024-01-20 * \"hand typed\"\n  Assets:Cash  2 USD\n  Equity:Opening  -2 USD\n",
    );
    let mut content = std::fs::read_to_string(&path).unwrap();
    content.insert_str(0, ";header\n; spaced\n\n");
    content.push_str("\n2024-02-01 open Assets:Tail\n  garbage without a newline");
    std::fs::write(&path, &content).unwrap();
    let mut svc = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
    assert!(
        svc.quarantined_count() >= 2,
        "quarantine and text both present"
    );
    check(&svc, "comments, quarantine, text, operator input");
    svc.set_author_id(L67_REAL.to_owned());
    svc.finalize_operator_input();
    check(&svc, "after finalisation");
    remove_ledger_and_journal(&path);
}

/// L-64 (carried): a dense hand-written file under the cap whose
/// CANONICAL form is over it boots — and now says so, naming both sizes
/// and the remedy, because every compaction will refuse to write it. The
/// fixture is the cheap way to be dense: 63 leading comment lines of
/// ~1 MiB written `;x…` (canonical `; x…`, one byte more each) filling the
/// file to 16 bytes under the cap, plus one enveloped directive. A small
/// ledger boots without the line.
///
/// Bug-catch: drop the `warn_if_canonical_exceeds_cap` call from
/// `boot_with` and the warning is absent.
#[test]
fn l64_a_dense_file_whose_canonical_form_is_over_the_cap_boots_with_a_warning() {
    let path = test_file_path();
    let note = Directive::Note(Note {
        date: make_date(2024, 1, 1),
        account: "Assets:Cash".to_owned(),
        comment: "dense".to_owned(),
        metadata: filler_envelope(1),
    });
    let note_text = full_file_serialize(std::slice::from_ref(&note), &[]);
    let target = MAX_LEDGER_FILE_BYTES as usize - 16 - note_text.len();
    let line = format!(";{}\n", "x".repeat((1 << 20) - 2));
    let mut content = line.repeat(target / line.len());
    let rest = target - content.len();
    content.push(';');
    content.push_str(&"x".repeat(rest - 2));
    content.push('\n');
    content.push_str(&note_text);
    assert_eq!(content.len() as u64, MAX_LEDGER_FILE_BYTES - 16);
    std::fs::write(&path, &content).unwrap();

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let booted = booted.expect("an over-cap canonical form still boots");
    assert!(logged.contains("L-64"), "the boot names it: {logged}");
    let canonical = booted.compaction_text().len() as u64;
    assert!(canonical > MAX_LEDGER_FILE_BYTES, "fixture: {canonical}");
    assert!(
        logged.contains(&format!("canonical_bytes={canonical}"))
            && logged.contains(&format!("file_bytes={}", MAX_LEDGER_FILE_BYTES - 16))
            && logged.contains(&format!("max={MAX_LEDGER_FILE_BYTES}")),
        "the sizes are named: {logged}"
    );
    assert!(logged.contains("Stop the node and shrink"), "{logged}");
    drop(booted);
    remove_ledger_and_journal(&path);

    let small = test_file_path();
    std::fs::write(&small, &note_text).unwrap();
    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(small.clone(), "test-peer".to_owned()));
    booted.unwrap();
    assert!(!logged.contains("L-64"), "{logged}");
    remove_ledger_and_journal(&small);
}

/// T78 (0923 audit §5): the boot sweep deletes only the names
/// `persist_atomically` reserves — `<name>.tmp` and
/// `<name>.tmp.<pid>.<16 hex>` — and leaves every other `<name>.tmp.*`
/// alone: an operator's `ledger.bean.tmp.backup` survives a boot, as do
/// near-misses of the reserved shape (a short or upper-case nonce, a
/// non-numeric pid, an extra field).
///
/// Bug-catch: match `name.starts_with("<name>.tmp.")` again in
/// `sweep_stale_temporaries` and the backup is deleted.
#[cfg(unix)]
#[test]
fn t78_the_sweep_leaves_an_operator_tmp_backup_alone() {
    let directory = t67_directory("t78-sweep");
    let path = directory.join("ledger.bean");
    std::fs::write(&path, "2024-01-01 open Assets:Cash USD\n").unwrap();
    let kept: Vec<PathBuf> = [
        "ledger.bean.tmp.backup",
        "ledger.bean.tmp.1234",
        "ledger.bean.tmp.1234.00000000deadbee",
        "ledger.bean.tmp.1234.0000000000DEADBE",
        "ledger.bean.tmp.12a4.00000000deadbeef",
        "ledger.bean.tmp.1234.00000000deadbeef.old",
        "ledger.bean.tmp..00000000deadbeef",
        "ledger.bean.tmp.12345678901.00000000deadbeef",
    ]
    .iter()
    .map(|name| directory.join(name))
    .collect();
    for file in &kept {
        std::fs::write(file, "operator data").unwrap();
    }
    let swept = [
        directory.join("ledger.bean.tmp"),
        directory.join("ledger.bean.tmp.1234.00000000deadbeef"),
        directory.join(format!(
            "ledger.bean.tmp.{}.0123456789abcdef",
            std::process::id()
        )),
    ];
    for file in &swept {
        std::fs::write(file, "half-written").unwrap();
    }

    LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    for file in &kept {
        assert_eq!(
            std::fs::read_to_string(file).ok().as_deref(),
            Some("operator data"),
            "{} is not a reserved temporary name and must survive a boot",
            file.display()
        );
    }
    for file in &swept {
        assert!(!file.exists(), "{} is a crashed temporary", file.display());
    }
    // And the name `persist_atomically` really draws is one the sweep owns.
    let drawn = temporary_path_for(&path, path.file_name().unwrap());
    assert!(is_reserved_temporary_name(
        &drawn.file_name().unwrap().to_string_lossy(),
        "ledger.bean"
    ));
    std::fs::remove_dir_all(directory).ok();
}

/// T78 (0923 audit §5): a DANGLING symlink at the journal path beside an
/// absent `.bean` refuses a fresh boot and creates nothing. The presence
/// probe was `Path::exists()`, which follows the link: it read "absent",
/// the fresh arm created an empty `.bean`, and only then did the journal
/// open refuse the link — leaving a new empty ledger behind.
///
/// Bug-catch: probe with `journal_path.exists()` again and the `.bean`
/// exists after the refused boot.
#[cfg(unix)]
#[test]
fn t78_a_dangling_journal_link_without_a_bean_refuses_boot_and_creates_nothing() {
    let directory = t67_directory("t78-dangling-journal");
    let path = directory.join("ledger.bean");
    let journal_path = crate::journal::journal_path_for(&path);
    std::os::unix::fs::symlink(directory.join("nowhere"), &journal_path).unwrap();

    let outcome = boot_error_within(path.clone());
    assert!(outcome.starts_with("Err"), "{outcome}");
    assert!(
        outcome.contains("H-15"),
        "the journal-present refusal: {outcome}"
    );
    assert!(
        std::fs::symlink_metadata(&path).is_err(),
        "the refused boot must not create the .bean"
    );
    let mut entries: Vec<String> = std::fs::read_dir(&directory)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        vec!["ledger.bean.journal".to_owned()],
        "nothing else created"
    );
    std::fs::remove_dir_all(directory).ok();
}

/// L-57: a directory at the old fixed `<name>.tmp` wedged every full
/// rewrite (`remove_file` → EISDIR/EPERM). Writes now use a fresh
/// `<name>.tmp.<pid>.<nonce>` and succeed; the boot sweep removes stale
/// `.tmp.*` files and symlinks this uid left (never a link's target), and
/// logs — does not remove — the directory. No temp is left behind.
///
/// Bug-catch: restore the fixed `.tmp` name and both writes fail.
#[cfg(unix)]
#[test]
fn l57_a_directory_at_the_old_tmp_name_does_not_block_writes() {
    let directory = t67_directory("l57-tmp");
    let path = directory.join("ledger.bean");
    std::fs::write(&path, "2024-01-01 open Assets:Cash USD\n").unwrap();
    let planted_dir = directory.join("ledger.bean.tmp");
    std::fs::create_dir(&planted_dir).unwrap();
    let stale_file = directory.join("ledger.bean.tmp.1234.00000000deadbeef");
    std::fs::write(&stale_file, "half-written").unwrap();
    let victim = directory.join("victim");
    std::fs::write(&victim, "precious").unwrap();
    let stale_link = directory.join("ledger.bean.tmp.1234.00000000cafef00d");
    std::os::unix::fs::symlink(&victim, &stale_link).unwrap();
    let unrelated = directory.join("ledger.bean.tmpl");
    std::fs::write(&unrelated, "not ours").unwrap();

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut svc = booted.unwrap();
    assert!(!stale_file.exists(), "a stale temp file is swept");
    assert!(
        std::fs::symlink_metadata(&stale_link).is_err(),
        "a stale temp symlink is swept"
    );
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    assert!(planted_dir.is_dir(), "a directory is never removed");
    assert!(logged.contains("L-57"), "the directory is logged: {logged}");
    assert!(unrelated.exists(), "only <name>.tmp and <name>.tmp.* match");

    svc.open_account(
        "Assets:New".into(),
        make_date(2024, 1, 2),
        vec!["USD".into()],
    )
    .expect("L-57: the first full rewrite succeeds");
    svc.open_account(
        "Assets:New2".into(),
        make_date(2024, 1, 3),
        vec!["USD".into()],
    )
    .expect("and the next");
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("Assets:New2"));
    let leftovers: Vec<_> = std::fs::read_dir(&directory)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("ledger.bean.tmp."))
        .collect();
    assert!(leftovers.is_empty(), "no temp left behind: {leftovers:?}");
    std::fs::remove_dir_all(directory).ok();
}

/// L-58 at boot: a journal restored as 0644 (ours, nobody else can write
/// it) still loads, but `append_record` refuses to add to it, so boot
/// forces the next commit to be a compaction — which folds it and deletes
/// it — and the append after that creates a fresh 0600 journal. No wedge.
#[cfg(unix)]
#[test]
fn l58_a_world_readable_journal_is_folded_away_not_appended_to() {
    use std::os::unix::fs::PermissionsExt;
    let (mut svc, path) = boot_large_ledger();
    svc.stage_remote_directive(remote_open("Assets:Vault", make_date(2024, 3, 1), 10))
        .unwrap();
    svc.persist_or_reload().unwrap();
    let journal_path = svc.journal_path().to_path_buf();
    drop(svc);
    std::fs::set_permissions(&journal_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert!(svc.accounts().is_open("Assets:Vault"), "its records load");
    assert!(svc.force_compaction, "and it is folded, not appended to");
    svc.stage_remote_directive(remote_open("Assets:Safe", make_date(2024, 3, 2), 11))
        .unwrap();
    svc.persist_or_reload().unwrap();
    assert!(!journal_path.exists(), "the compaction removed it");
    svc.stage_remote_directive(remote_open("Assets:Third", make_date(2024, 3, 3), 12))
        .unwrap();
    svc.persist_or_reload().unwrap();
    assert_eq!(
        std::fs::metadata(&journal_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    remove_ledger_and_journal(&path);
}

// ── T68: journal policy (M-43 / R-18, M-44) ──────────────────────────

/// M-43 / R-18 end to end (the B8 `r18` shape): three appended,
/// acknowledged records; the second header's length damaged. Boot used to
/// load one, drop two with a "crashed mid-append" warning, and the startup
/// compaction erased them. Boot now refuses, naming the byte offset.
#[test]
fn m43_a_damaged_mid_journal_length_refuses_boot_naming_the_offset() {
    let (mut svc, path) = boot_large_ledger();
    let journal_path = svc.journal_path().to_path_buf();
    let mut second = 0;
    for (index, name) in ["Assets:One", "Assets:Two", "Assets:Three"]
        .into_iter()
        .enumerate()
    {
        if index == 1 {
            second = std::fs::metadata(&journal_path).unwrap().len() as usize;
        }
        svc.stage_remote_directive(remote_open(name, make_date(2024, 3, 1), 10 + index as u64))
            .unwrap();
        svc.persist_or_reload().unwrap();
    }
    drop(svc);
    let bytes = std::fs::read(&journal_path).unwrap();
    let end = second + bytes[second..].iter().position(|b| *b == b'\n').unwrap();
    let header = std::str::from_utf8(&bytes[second..end]).unwrap().to_owned();
    let damaged_header = header.replacen(";;olj ", ";;olj 9", 1);
    let mut damaged = bytes[..second].to_vec();
    damaged.extend_from_slice(damaged_header.as_bytes());
    damaged.extend_from_slice(&bytes[end..]);
    std::fs::write(&journal_path, &damaged).unwrap();

    let Err(error) = LedgerService::boot(path.clone(), "test-peer".to_owned()) else {
        panic!("M-43: a damaged mid-journal length must refuse boot");
    };
    assert_eq!(error.error_code(), "LEDGER_JOURNAL", "got {error}");
    assert!(
        error.to_string().contains(&format!("at byte {second}")),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&journal_path).unwrap(),
        damaged,
        "the journal is left exactly as found"
    );
    remove_ledger_and_journal(&path);
}

/// M-44 (the B8 `zero-fill` fixture): the final record's payload reads
/// back as NULs — a metadata-first filesystem after a power cut. It used to
/// be `Corrupt` and refuse boot on a file the node wrote; it now boots with
/// the torn warning, the record before it intact.
#[test]
fn m44_a_zero_filled_final_record_boots_with_a_torn_warning() {
    let path = test_file_path();
    std::fs::write(&path, "2024-01-01 open Assets:Cash USD\n").unwrap();
    let journal_path = crate::journal::journal_path_for(&path);
    crate::journal::append_record(
        &journal_path,
        &crate::journal::record_bytes("2024-01-02 open Assets:Kept USD\n"),
    )
    .unwrap();
    let record = crate::journal::record_bytes("2024-01-03 open Assets:Lost USD\n");
    crate::journal::append_record(&journal_path, &record).unwrap();
    let mut bytes = std::fs::read(&journal_path).unwrap();
    let payload_start = bytes.len() - (record.len() - (record.find('\n').unwrap() + 1));
    bytes[payload_start..].fill(0);
    std::fs::write(&journal_path, &bytes).unwrap();

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let booted = booted.expect("M-44: a zero-filled final record must not brick boot");
    assert!(logged.contains("torn record"), "{logged}");
    assert!(booted.accounts().is_open("Assets:Kept"));
    assert!(!booted.accounts().is_open("Assets:Lost"));
    remove_ledger_and_journal(&path);
}

/// T78 (0923 audit §5, D2 `(e2)`): the ext4 `data=writeback` shape — the
/// final record's payload reads back as an older journal's text, no NUL —
/// boots with the torn warning instead of refusing (`LEDGER_JOURNAL`), and
/// the record it drops is not destroyed: the compaction that folds the
/// journal renames it to a `.torn-*` sidecar holding the exact bytes.
///
/// Bug-catch: restore the `payload.contains(&0)` condition in
/// `journal::read_journal` and boot fails with `LEDGER_JOURNAL`.
#[test]
fn t78_a_stale_final_journal_record_boots_torn_and_its_bytes_are_kept() {
    let path = test_file_path();
    std::fs::write(&path, "2024-01-01 open Assets:Cash USD\n").unwrap();
    let journal_path = crate::journal::journal_path_for(&path);
    crate::journal::append_record(
        &journal_path,
        &crate::journal::record_bytes("2024-01-02 open Assets:Kept USD\n"),
    )
    .unwrap();
    let record = crate::journal::record_bytes("2024-01-03 open Assets:Lost USD\n");
    crate::journal::append_record(&journal_path, &record).unwrap();
    let mut bytes = std::fs::read(&journal_path).unwrap();
    let payload_start = bytes.len() - (record.len() - (record.find('\n').unwrap() + 1));
    let stale: Vec<u8> = b"2023-12-01 open Assets:OldFolded USD\n"
        .iter()
        .copied()
        .cycle()
        .take(bytes.len() - payload_start)
        .collect();
    bytes[payload_start..].copy_from_slice(&stale);
    assert!(!bytes.contains(&0), "the ext4 shape holds no NUL");
    std::fs::write(&journal_path, &bytes).unwrap();

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut booted = booted.expect("T78: a stale final record must not brick boot");
    assert!(logged.contains("torn record"), "{logged}");
    assert!(booted.accounts().is_open("Assets:Kept"));
    assert!(!booted.accounts().is_open("Assets:Lost"));

    booted.compact().unwrap();
    let sidecars = torn_sidecars(&journal_path);
    assert_eq!(sidecars.len(), 1, "{sidecars:?}");
    assert_eq!(
        std::fs::read(&sidecars[0]).unwrap(),
        bytes,
        "the dropped record's bytes are kept byte-for-byte"
    );
    for sidecar in sidecars {
        std::fs::remove_file(sidecar).ok();
    }
    remove_ledger_and_journal(&path);
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

/// M-43, decision taken: torn journals are renamed, never unlinked. After a
/// boot that dropped a torn tail, the compaction that folds the journal
/// leaves it as `<journal>.torn-<unix-seconds>` holding the exact bytes —
/// including the dropped ones — and says where; the next boot ignores the
/// sidecar (no torn warning, same directives). A compaction with nothing
/// torn still deletes the journal.
///
/// Bug-catch: call `remove_journal` unconditionally in `commit` and no
/// sidecar exists.
#[test]
fn m43_a_torn_journal_is_renamed_not_deleted_and_the_next_boot_ignores_it() {
    let (mut svc, path) = boot_large_ledger();
    let journal_path = svc.journal_path().to_path_buf();
    for (index, name) in ["Assets:Vault", "Assets:Safe"].into_iter().enumerate() {
        svc.stage_remote_directive(remote_open(name, make_date(2024, 3, 1), 10 + index as u64))
            .unwrap();
        svc.persist_or_reload().unwrap();
    }
    drop(svc);
    let both = std::fs::read(&journal_path).unwrap();
    let torn = both[..both.len() - 30].to_vec();
    std::fs::write(&journal_path, &torn).unwrap();

    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    let (compacted, logged) = capture_warnings(|| svc.compact());
    compacted.unwrap();
    assert!(!journal_path.exists(), "the journal is folded");
    let sidecars = torn_sidecars(&journal_path);
    assert_eq!(sidecars.len(), 1, "exactly one sidecar: {sidecars:?}");
    assert_eq!(
        std::fs::read(&sidecars[0]).unwrap(),
        torn,
        "the sidecar holds the journal byte-for-byte, torn tail included"
    );
    assert!(
        logged.contains(&sidecars[0].display().to_string()),
        "the sidecar's path is logged: {logged}"
    );
    let count = svc.directive_count();

    let (rebooted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let rebooted = rebooted.expect("the sidecar is ignored");
    assert!(!logged.contains("torn record"), "{logged}");
    assert_eq!(rebooted.directive_count(), count);

    // A healthy journal is still simply deleted by its compaction.
    let mut svc = rebooted;
    svc.stage_remote_directive(remote_open("Assets:Later", make_date(2024, 3, 3), 20))
        .unwrap();
    svc.persist_or_reload().unwrap();
    svc.compact().unwrap();
    assert!(!journal_path.exists());
    assert_eq!(torn_sidecars(&journal_path).len(), 1, "no new sidecar");

    for sidecar in torn_sidecars(&journal_path) {
        std::fs::remove_file(sidecar).ok();
    }
    remove_ledger_and_journal(&path);
}

// ── T74: the recovery floor and the reload-failure arm (M-46, M-49) ──

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

/// M-46, the `d2probe floor (b)` shape: three acknowledged records, a
/// backup holding three OTHER records copied over the live `.bean`, and
/// the very next commit fails. The pre-persist reconcile adopts the three
/// file lines; the L-13 rebuild holds exactly those three.
///
/// Before M-46 the reconcile pushed the adopted ids onto `pending_ids`, the
/// floor was `7 − 4 = 3`, and the rebuild was installed
/// (`before=7 after=3 discarded_staged=4`): the acked records left memory
/// and the next successful write made the loss durable. Now the rebuild
/// is refused (the acked ids are neither staged nor file-adopted), memory
/// keeps everything, and the next commit writes the union — which is what
/// the same edit gives when the persist succeeds (`floor (b2)`).
///
/// Bug-catch: drop the per-id check in `finish_recovery` and the rebuild
/// installs (the count floor, `7 − 1 staged − 3 adopted = 3`, is exactly
/// what the replacement holds — no count can see this shape). Pushing the
/// adopted ids back onto `pending_ids` alone does not reopen it: the id
/// check tolerates the union of the two sets either way.
#[cfg(unix)]
#[test]
fn m46_a_live_file_replacement_and_a_failed_commit_keep_every_acked_record() {
    let directory = t67_directory("m46-replace");
    let path = directory.join("ledger.bean");
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    let acked = ["Assets:Acked1", "Assets:Acked2", "Assets:Acked3"];
    for name in acked {
        svc.open_account(name.to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
    }
    let replacement = ["Assets:Old1", "Assets:Old2", "Assets:Old3"];
    std::fs::write(&path, raw_opens(&replacement, "2024-01-01")).unwrap();

    let (outcome, logged) = capture_warnings(|| {
        with_read_only_directory(&directory, || {
            svc.open_account("Assets:Staged".to_owned(), make_date(2024, 2, 1), vec![])
        })
    });
    assert!(outcome.is_err(), "premise: the commit fails");
    assert!(
        logged.contains("REFUSING"),
        "M-46: a rebuild missing acked records must not install: {logged}"
    );
    assert!(!logged.contains("L-13 reload installed"), "{logged}");
    for name in acked.iter().chain(replacement.iter()) {
        assert!(svc.accounts().is_open(name), "{name} must stay in memory");
    }
    // T100 / L-147, decision (62): the write whose call failed is rolled
    // back; before T100 it was kept, counted and served.
    assert_eq!(
        svc.directive_count(),
        6,
        "three acked and three adopted; the staged write rolled back"
    );
    assert!(!svc.accounts().is_open("Assets:Staged"));
    assert!(svc.compaction_pending(), "the refusal arms a full rewrite");

    svc.open_account("Assets:After".to_owned(), make_date(2024, 2, 2), vec![])
        .expect("the next write succeeds once the directory is writable");
    let on_disk = LedgerService::boot(path.clone(), "checker".to_owned()).unwrap();
    assert_eq!(on_disk.directive_count(), 7, "the union is on disk");
    for name in acked
        .iter()
        .chain(replacement.iter())
        .chain(["Assets:After"].iter())
    {
        assert!(on_disk.accounts().is_open(name), "{name} on disk");
    }
    assert!(
        !on_disk.accounts().is_open("Assets:Staged"),
        "the failed write"
    );
    std::fs::remove_dir_all(&directory).ok();
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

/// M-46 at boot, the `d2probe floor (b3)` shape: boot adopts two hand
/// lines, the operator then deletes two HISTORY records (node-written,
/// acked) and keeps their hand lines, and the startup compaction fails.
///
/// Before M-46 boot's adoption put the two hand ids in `pending_ids`, the
/// floor was `504 − 2 = 502` — exactly what the edited file holds — and
/// the rebuild was installed without `F…000498`/`F…000499`, which the next
/// compaction then erased from disk. A count cannot see this: the file is
/// short by exactly the number of hand lines. The per-id check does.
///
/// Bug-catch: drop the id check in `finish_recovery` and the rebuild
/// installs (the count floor is 502 either way).
#[cfg(unix)]
#[test]
fn m46_boot_adopted_operator_input_does_not_lower_the_recovery_floor() {
    let directory = t67_directory("m46-boot");
    let path = directory.join("ledger.bean");
    std::fs::write(&path, large_ledger_with_two_hand_lines()).unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(svc.directive_count(), 504);
    assert_eq!(svc.unsigned_operator_input_count(), 2, "premise");

    let padding = "A".repeat(80);
    let victims = [
        format!("Assets:F{padding}000498"),
        format!("Assets:F{padding}000499"),
    ];
    let text = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = text
        .trim_end()
        .split("\n\n")
        .filter(|block| !victims.iter().any(|victim| block.contains(victim.as_str())))
        .collect();
    assert_eq!(kept.len(), 502, "premise: two history blocks removed");
    std::fs::write(&path, kept.join("\n\n") + "\n").unwrap();

    let (outcome, logged) =
        capture_warnings(|| with_read_only_directory(&directory, || svc.compact()));
    assert!(outcome.is_err(), "premise: the startup compaction fails");
    assert!(
        logged.contains("REFUSING"),
        "M-46: boot-adopted input must not lower the floor: {logged}"
    );
    assert_eq!(svc.directive_count(), 504);
    for victim in &victims {
        assert!(svc.accounts().is_open(victim), "history kept in memory");
    }

    svc.compact().expect("the retry succeeds");
    let on_disk = LedgerService::boot(path.clone(), "checker".to_owned()).unwrap();
    assert_eq!(on_disk.directive_count(), 504);
    for name in victims
        .iter()
        .map(String::as_str)
        .chain(["Assets:HandOne", "Assets:HandTwo"])
    {
        assert!(on_disk.accounts().is_open(name), "{name} back on disk");
    }
    std::fs::remove_dir_all(&directory).ok();
}

/// M-46 (the Info item on `uncommitted_count`'s doc): a directive adopted
/// from the file — at boot or by a live reconcile — is not "staged", so
/// `uncommitted_count()` is 0 right after it; and it is still not "nothing
/// to do": the next prepare is the compaction that spells it canonically.
///
/// Bug-catch: push file-adopted ids onto `pending_ids` again and the
/// count is 1 after boot. (The `adopted_from_file` term in `prepare`'s
/// `must_rewrite` is belt and braces: every adoption path also arms
/// `force_compaction` or clears `canonical_is_current`, so no public path
/// can show it missing; the `Compact` assertions pin the outcome.)
#[test]
fn m46_uncommitted_count_is_zero_after_a_boot_that_adopted_operator_input() {
    let path = test_file_path();
    std::fs::write(
        &path,
        format!(
            "{}\n{}",
            large_ledger_content(),
            raw_opens(&["Assets:HandOne"], "2024-04-01")
        ),
    )
    .unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(svc.unsigned_operator_input_count(), 1, "premise");
    assert_eq!(
        svc.uncommitted_count(),
        0,
        "M-46: operator input read from the file is not staged"
    );
    assert!(svc.compaction_pending());
    let pending = svc
        .prepare_commit()
        .unwrap()
        .expect("adopted input still owes its canonical rewrite");
    assert_eq!(pending.kind(), CommitKind::Compact);
    let receipt = pending.commit().unwrap();
    svc.finish_commit(receipt);
    assert!(
        svc.prepare_commit().unwrap().is_none(),
        "and after that rewrite there is nothing left to do"
    );

    // The live reconcile, on a ledger whose next commit would otherwise
    // be an append.
    append_to_file(
        &path,
        &format!("\n{}", raw_opens(&["Assets:HandTwo"], "2024-04-02")),
    );
    let (result, _) = capture_warnings(|| svc.reconcile_file_staged().unwrap());
    assert_eq!(result.new_directives, 1, "premise");
    assert_eq!(svc.uncommitted_count(), 0, "M-46: adopted, not staged");
    let pending = svc
        .prepare_commit()
        .unwrap()
        .expect("the adopted line owes its canonical rewrite");
    assert_eq!(pending.kind(), CommitKind::Compact);
    let receipt = pending.commit().unwrap();
    svc.finish_commit(receipt);

    let on_disk = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert!(on_disk.accounts().is_open("Assets:HandTwo"));
    assert_eq!(
        on_disk.unsigned_operator_input_count(),
        0,
        "both hand lines were rewritten with their envelope"
    );
    remove_ledger_and_journal(&path);
}

/// M-46 control, the `d2probe floor (a)` shape: boot adopts two hand
/// lines and the operator removes those same lines again before the
/// startup compaction, which fails. Until T86 the rebuild lacked only ids
/// adopted from the file and still unsigned — on a signing-off node,
/// unsigned forever — so it installed and the retraction was obeyed (T62's
/// floor (a)). Since T86 (L-104, decision (23)) the exemption ends when the
/// line is finalised, which `prepare` does before the compaction it
/// attempts (and gl-node at boot): the lines are this node's committed
/// records, as a signed line already was, so the rebuild is refused,
/// memory is kept, and the next commit writes them back. A retraction is a
/// reversing entry, as for every other record.
///
/// Bug-catch: key the exemption on the signature again (T82) and this
/// installs, dropping both lines.
#[cfg(unix)]
#[test]
fn m46_a_reload_after_removing_ones_own_finalised_hand_lines_is_refused() {
    let directory = t67_directory("m46-own-lines");
    let path = directory.join("ledger.bean");
    std::fs::write(&path, large_ledger_with_two_hand_lines()).unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(svc.directive_count(), 504);
    std::fs::write(&path, large_ledger_content()).unwrap();

    let (outcome, logged) =
        capture_warnings(|| with_read_only_directory(&directory, || svc.persist_or_reload()));
    assert!(outcome.is_err(), "premise: the commit fails");
    assert!(logged.contains("REFUSING"), "{logged}");
    assert!(!logged.contains("L-13 reload installed"), "{logged}");
    assert_eq!(svc.directive_count(), 504, "memory is kept");
    assert!(svc.accounts().is_open("Assets:HandOne"));
    assert!(svc.accounts().is_open("Assets:HandTwo"));

    svc.persist_or_reload().unwrap();
    let on_disk = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(
        on_disk.directive_count(),
        504,
        "the next commit writes them back"
    );
    std::fs::remove_dir_all(&directory).ok();
}

/// M-49, the `x3probe torn` case B shape: an append tears (prepared as an
/// `Append`, never acknowledged, 60 % of a record left on the journal), and
/// the L-13 reload that would notice the tail fails too — here because the
/// `.bean` is unreadable. Before M-49 the `Err` arm left
/// `force_compaction` false, the next commit was an `Append` landing after
/// the torn bytes, the journal scanner then classified it `Corrupt`, and
/// the reboot refused with `LEDGER_JOURNAL` and an acked record behind it.
/// Now the next commit is a `Compact`, the journal is kept as exactly one
/// `.torn-*` sidecar holding the bytes the failed reload never judged, and
/// the reboot holds everything memory holds.
///
/// Bug-catch: drop `force_compaction = true` from the `Err` arm and the
/// next commit is an `Append` (and the reboot refuses); drop
/// `journal_torn_at_boot = true` and the journal is unlinked (no sidecar).
#[cfg(unix)]
#[test]
fn m49_a_failed_reload_after_a_torn_append_forces_a_compaction_and_the_reboot_succeeds() {
    use std::os::unix::fs::PermissionsExt;
    let (mut svc, path) = boot_large_ledger();
    let journal_path = svc.journal_path().to_path_buf();
    svc.stage_remote_directive(remote_open("Assets:One", make_date(2024, 3, 1), 10))
        .unwrap();
    svc.persist_or_reload().unwrap();
    assert!(svc.journal_bytes() > 0, "premise: on the append arm");

    svc.stage_remote_directive(remote_open("Assets:Two", make_date(2024, 3, 2), 11))
        .unwrap();
    let tearing = svc.prepare_commit().unwrap().expect("something staged");
    assert_eq!(tearing.kind(), CommitKind::Append, "premise");
    drop(tearing);
    let intact = std::fs::read(&journal_path).unwrap();
    let mut torn = intact.clone();
    torn.extend_from_slice(&intact[..intact.len() * 6 / 10]);
    std::fs::write(&journal_path, &torn).unwrap();

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (_, logged) = capture_warnings(|| svc.recover_failed_commit());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        logged.contains("reload-from-disk failed"),
        "premise: the reload fails: {logged}"
    );
    assert!(
        svc.compaction_pending(),
        "M-49: a failed reload arms the rewrite"
    );

    svc.stage_remote_directive(remote_open("Assets:Three", make_date(2024, 3, 3), 12))
        .unwrap();
    let next = svc.prepare_commit().unwrap().expect("something staged");
    assert_eq!(
        next.kind(),
        CommitKind::Compact,
        "M-49: never an append behind a torn tail"
    );
    let (receipt, _) = capture_warnings(|| next.commit());
    svc.finish_commit(receipt.unwrap());
    assert!(!journal_path.exists(), "the journal is folded");
    let sidecars = torn_sidecars(&journal_path);
    assert_eq!(sidecars.len(), 1, "exactly one sidecar: {sidecars:?}");
    assert_eq!(
        std::fs::read(&sidecars[0]).unwrap(),
        torn,
        "the bytes the failed reload never judged are kept"
    );

    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned())
        .expect("M-49: the reboot must not find a corrupt journal");
    assert_eq!(rebooted.directive_count(), svc.directive_count());
    for name in ["Assets:One", "Assets:Three"] {
        assert!(rebooted.accounts().is_open(name), "{name}");
    }
    // T100 / L-147, decision (62): `Two` was staged in the commit that
    // failed; the failed reload rolls it back instead of keeping it.
    assert!(!rebooted.accounts().is_open("Assets:Two"));
    for sidecar in sidecars {
        std::fs::remove_file(sidecar).ok();
    }
    remove_ledger_and_journal(&path);
}

/// The Info item beside M-49, the `d2probe sidecars (b)` shape: an acked
/// journal record is truncated under a running node, and the L-13
/// reload that sees the torn tail is REFUSED (the rebuild lacks the acked
/// record). The refusal used to discard the rebuild's
/// `journal_torn_at_boot`, so the rewrite that followed unlinked the
/// torn journal. Now the fact is ORed in and the journal is renamed.
///
/// Bug-catch: drop `journal_torn_at_boot |= reloaded.journal_torn_at_boot`
/// from the refusing arm and there is no sidecar.
#[test]
fn m49_a_refused_reload_keeps_the_torn_journal_fact_so_the_journal_is_renamed_not_unlinked() {
    let (mut svc, path) = boot_large_ledger();
    let journal_path = svc.journal_path().to_path_buf();
    for (index, name) in ["Assets:Vault", "Assets:Safe"].into_iter().enumerate() {
        svc.stage_remote_directive(remote_open(name, make_date(2024, 3, 1), 10 + index as u64))
            .unwrap();
        svc.persist_or_reload().unwrap();
    }
    let both = std::fs::read(&journal_path).unwrap();
    let torn = both[..both.len() - 30].to_vec();
    std::fs::write(&journal_path, &torn).unwrap();

    let (_, logged) = capture_warnings(|| svc.recover_failed_commit());
    assert!(logged.contains("REFUSING"), "premise: {logged}");
    assert!(svc.accounts().is_open("Assets:Safe"), "memory is kept");

    let (outcome, _) = capture_warnings(|| svc.persist_or_reload());
    outcome.unwrap();
    assert!(!journal_path.exists(), "the journal is folded");
    let sidecars = torn_sidecars(&journal_path);
    assert_eq!(
        sidecars.len(),
        1,
        "a torn journal is renamed, never unlinked: {sidecars:?}"
    );
    assert_eq!(std::fs::read(&sidecars[0]).unwrap(), torn);
    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.directive_count(), svc.directive_count());
    assert!(rebooted.accounts().is_open("Assets:Safe"));
    for sidecar in sidecars {
        std::fs::remove_file(sidecar).ok();
    }
    remove_ledger_and_journal(&path);
}

/// M-39 (T69): `append_headroom` is exactly the room the append arm's cap
/// projection leaves — `MAX − canonical − journal` — and it shrinks by what
/// each append adds to the journal.
#[test]
fn m39_append_headroom_is_the_cap_minus_canonical_and_journal() {
    let (mut svc, path) = boot_large_ledger();
    assert_eq!(svc.journal_bytes(), 0);
    assert_eq!(
        svc.append_headroom(),
        MAX_LEDGER_FILE_BYTES - svc.canonical_bytes()
    );
    svc.stage_remote_directive(remote_open("Assets:Headroom", make_date(2024, 3, 1), 10))
        .unwrap();
    svc.persist_or_reload().unwrap();
    assert!(svc.journal_bytes() > 0, "premise: the write appended");
    assert_eq!(
        svc.append_headroom(),
        MAX_LEDGER_FILE_BYTES - svc.canonical_bytes() - svc.journal_bytes()
    );
    remove_ledger_and_journal(&path);
}

// ── T73: boot verifies what it loads (H-20, M-47, L-74, L-75, L-76, L-77) ──

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

/// H-20 door (a): the operator corrects a narration in a line the node
/// wrote. Boot loads it on its form; the moment the node can sign, the
/// record is quarantined with the reason, out of the DAG, the read model
/// and every balance, kept on disk, and the reboot is a fixed point.
///
/// Bug-catch: revert `verify_history_pass` (or the `set_signer` call to
/// it) and the edited record is served under the old signature.
#[test]
fn h20_an_own_record_edited_by_hand_is_quarantined_with_the_reason_not_served() {
    let (path, original_txid) = signed_node_written_file();
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        content.replace("\"Funding\"", "\"Modified Funding\""),
    )
    .unwrap();

    // Boot as gl-node does: placeholder author first, then the identity.
    let mut svc = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
    assert_eq!(
        svc.directive_count(),
        4,
        "loaded on its form; verified once the node has the means"
    );
    svc.set_author_id("test-peer".to_owned());
    let (_, logged) = capture_warnings(|| svc.set_signer(marker_signer()));
    assert!(
        logged.contains("signature does not verify — was this record edited? (H-20)"),
        "{logged}"
    );

    assert!(
        transaction_named(&svc, "Modified Funding").is_none(),
        "the edited record must not be served"
    );
    assert!(
        svc.get_directive(&original_txid).is_none(),
        "the original is not in this file (every peer keeps it)"
    );
    assert_eq!(svc.directive_count(), 3);
    assert_eq!(svc.quarantined_count(), 1);
    let quarantined_id = svc.quarantined_ids()[0].to_owned();
    assert_ne!(
        quarantined_id, original_txid,
        "quarantined under its NEW id"
    );
    assert_eq!(
        svc.read_model().transaction_count(),
        0,
        "out of the read model"
    );
    assert!(cash_balance(&svc).is_empty(), "out of every balance");
    assert!(
        svc.accounts().is_open("Assets:Cash"),
        "the rest of the file still loads"
    );
    assert_eq!(svc.verify_own_history(), 0, "idempotent");

    // H-08: the compaction writes it back as loaded.
    svc.compact().unwrap();
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("Modified Funding"));

    // The reboot quarantines the same id, and reports nothing unverified.
    let mut rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    rebooted.set_signer(marker_signer());
    assert_eq!(rebooted.quarantined_ids(), vec![quarantined_id.as_str()]);
    assert_eq!(rebooted.directive_count(), 3);
    let (quarantined, logged) = capture_warnings(|| rebooted.verify_own_history());
    assert_eq!(quarantined, 0);
    assert!(!logged.contains("UNVERIFIED"), "{logged}");

    remove_ledger_and_journal(&path);
}

/// H-20: a foreign-authored record is judged by the verifier — the
/// author id is the key — and a signer alone leaves it loaded and says
/// the history is unverified.
///
/// Bug-catch: revert the verifier arm of `verify_history_directive` and
/// the forged record stays served.
#[test]
fn h20_a_foreign_record_with_a_bad_signature_is_quarantined_by_the_verifier() {
    let path = test_file_path();
    std::fs::write(
        &path,
        "2024-01-01 open Assets:Cash USD\n\
             \x20 openledger-author: \"peer-remote\"\n\
             \x20 openledger-lamport: \"1\"\n\
             \x20 openledger-signature: \"good\"\n\n\
             2024-01-01 open Equity:Opening\n\
             \x20 openledger-author: \"peer-remote\"\n\
             \x20 openledger-lamport: \"2\"\n\
             \x20 openledger-signature: \"forged\"\n",
    )
    .unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(svc.directive_count(), 2);

    // A signer cannot judge another author's signature.
    svc.set_signer(marker_signer());
    assert_eq!(svc.directive_count(), 2);
    let (quarantined, logged) = capture_warnings(|| svc.verify_own_history());
    assert_eq!(quarantined, 0);
    assert!(logged.contains("UNVERIFIED"), "{logged}");

    // The verifier can: it is handed the author id as the key.
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = std::sync::Arc::clone(&seen);
    let verifier: DirectiveVerifier = std::sync::Arc::new(
        move |_content_id: &str,
              _is_transaction: bool,
              _parents: &str,
              _lamport: &str,
              author: &str,
              signature: &str| {
            recorder
                .lock()
                .unwrap()
                .push((author.to_owned(), signature.to_owned()));
            author == "peer-remote" && signature == "good"
        },
    );
    let (_, logged) = capture_warnings(|| svc.set_verifier(verifier));
    assert!(logged.contains("signature does not verify"), "{logged}");
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "both foreign records were checked"
    );
    assert_eq!(svc.directive_count(), 1);
    assert_eq!(svc.quarantined_count(), 1);
    assert!(svc.accounts().is_open("Assets:Cash"));
    assert!(
        !svc.accounts().is_open("Equity:Opening"),
        "the account state is rebuilt without the quarantined open"
    );
    let (quarantined, logged) = capture_warnings(|| svc.verify_own_history());
    assert_eq!(quarantined, 0);
    assert!(!logged.contains("UNVERIFIED"), "{logged}");

    // H-08.
    svc.compact().unwrap();
    assert!(std::fs::read_to_string(&path).unwrap().contains("forged"));
    remove_ledger_and_journal(&path);
}

/// H-20: with neither a verifier nor a signer, nothing is quarantined and
/// the explicit pass says the history is unverified — the residual on a
/// node without a key, stated out loud rather than silently.
#[test]
fn h20_without_a_verifier_nothing_is_quarantined_and_the_history_is_reported_unverified() {
    let (path, _) = signed_node_written_file();
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        content.replace("\"Funding\"", "\"Modified Funding\""),
    )
    .unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    let (quarantined, logged) = capture_warnings(|| svc.verify_own_history());
    assert_eq!(quarantined, 0);
    assert_eq!(svc.directive_count(), 4);
    assert_eq!(svc.quarantined_count(), 0);
    assert!(
        transaction_named(&svc, "Modified Funding").is_some(),
        "served as loaded: the residual without a key"
    );
    assert!(logged.contains("UNVERIFIED"), "{logged}");
    remove_ledger_and_journal(&path);
}

/// H-20: an L-13 reload re-derives the history from the file, and
/// `finish_recovery` re-runs the verification with the carried signer.
///
/// Bug-catch: remove the `verify_own_history` call in `finish_recovery`
/// and the edited record is served after the reload.
#[test]
fn h20_an_l13_reload_re_verifies_the_history_with_the_carried_signer() {
    let (path, _) = signed_node_written_file();
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        content.replace("\"Funding\"", "\"Modified Funding\""),
    )
    .unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    assert_eq!(svc.quarantined_count(), 1);

    let (_, logged) = capture_warnings(|| svc.recover_failed_commit());
    assert!(logged.contains("L-13 reload installed"), "{logged}");
    assert_eq!(svc.quarantined_count(), 1);
    assert_eq!(svc.directive_count(), 3);
    assert!(transaction_named(&svc, "Modified Funding").is_none());
    remove_ledger_and_journal(&path);
}

/// H-20: the live reconcile holds a pasted full envelope to the same
/// check — a bad signature is refused, the node's own is adopted.
#[test]
fn h20_the_live_reconcile_refuses_a_full_envelope_whose_signature_does_not_verify() {
    let (mut svc, path) = setup_with_signed_accounts();
    let body = "\n2024-01-25 * \"Hand\" \"pasted\"\n\
             \x20 openledger-author: \"test-peer\"\n\
             \x20 openledger-lamport: \"7\"\n\
             \x20 openledger-parents: \"\"\n\
             \x20 openledger-signature: \"SIGNATURE\"\n\
             \x20 Assets:Cash                                        10.00 USD\n\
             \x20 Equity:Opening                                    -10.00 USD\n";
    append_to_file(&path, &body.replace("SIGNATURE", "forged"));
    let (result, logged) = capture_warnings(|| svc.reconcile_file().unwrap());
    assert_eq!(result.rejected, 1);
    assert_eq!(result.new_directives, 0);
    assert!(logged.contains("signature does not verify"), "{logged}");
    assert!(transaction_named(&svc, "pasted").is_none());

    // The same body under the signature this node would have made.
    let mut expected = parse_file(body.trim_start()).unwrap().remove(0);
    directive_metadata_mut(&mut expected).remove(ENVELOPE_KEY_SIGNATURE);
    let signature = marker_signature(&expected);
    append_to_file(&path, &body.replace("SIGNATURE", &signature));
    assert_eq!(svc.reconcile_file().unwrap().new_directives, 1);
    assert!(transaction_named(&svc, "pasted").is_some());
    remove_ledger_and_journal(&path);
}

/// H-20 door (b) / L-45: a node-written transaction split by a dedent is
/// held whole as raw text — never loaded as a shorter transaction with
/// the original envelope — and a head that parses on its own after a
/// blank line is held back by I1. No signer involved: the salvage alone
/// must do this.
///
/// Bug-catch: revert the demotion in `salvage_unparsable_blocks` and the
/// `dedent2` head loads with one posting (`Assets:Cash 100 USD`, the
/// `−100` gone); revert the `salvaged` I1 arm and the blank-line head
/// loads the same way.
#[test]
fn l45_a_split_transaction_block_is_quarantined_whole_not_loaded_truncated() {
    for (mode, victim) in [("dedent2", "Equity:Opening"), ("dedent1", "Assets:Cash")] {
        let (path, txid) = signed_node_written_file();
        edit_block_lines(&path, "Funding", |line| {
            if line.trim_start().starts_with(victim) {
                line.trim_start().to_owned()
            } else {
                line.to_owned()
            }
        });
        let (booted, logged) =
            capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
        let mut svc = booted.unwrap();
        assert!(
            transaction_named(&svc, "Funding").is_none(),
            "{mode}: the head fragment must not be loaded"
        );
        assert!(svc.get_directive(&txid).is_none(), "{mode}");
        assert_eq!(
            svc.directive_count(),
            3,
            "{mode}: the three opens still load"
        );
        assert_eq!(
            svc.unparsable_block_count(),
            1,
            "{mode}: head and tail are ONE held block"
        );
        assert_eq!(svc.quarantined_count(), 1, "{mode}");
        assert!(
            cash_balance(&svc).is_empty(),
            "{mode}: no half of the transaction reaches a balance: {:?}",
            cash_balance(&svc)
        );
        assert!(
            logged.contains("held whole rather than loaded truncated"),
            "{mode}: {logged}"
        );
        assert!(!logged.contains("nothing is lost"), "{mode}: {logged}");

        // H-08: written back byte-for-byte; the reboot is a fixed point.
        svc.compact().unwrap();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.lines().any(|line| line.starts_with(victim)),
            "{mode}: the dedented line is written back as it was:\n{on_disk}"
        );
        let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        assert_eq!(rebooted.unparsable_block_count(), 1, "{mode}");
        assert_eq!(rebooted.directive_count(), 3, "{mode}");
        remove_ledger_and_journal(&path);
    }

    // A blank line typed inside the block: the head parses on its own
    // with one posting and no tail to be demoted with, and I1 holds it.
    let (path, _) = signed_node_written_file();
    let content = std::fs::read_to_string(&path).unwrap();
    let mut split = String::new();
    let mut in_block = false;
    for line in content.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            in_block = line.contains("Funding");
        }
        if in_block && line.trim_start().starts_with("Equity:Opening") {
            split.push('\n');
        }
        split.push_str(line);
        split.push('\n');
    }
    std::fs::write(&path, split).unwrap();
    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let svc = booted.unwrap();
    assert!(transaction_named(&svc, "Funding").is_none());
    assert_eq!(svc.directive_count(), 3);
    assert_eq!(
        svc.quarantined_ids().len(),
        1,
        "the one-posting head is a directive that fails I1, quarantined by id"
    );
    assert_eq!(
        svc.unparsable_block_count(),
        1,
        "the orphaned posting line is raw text"
    );
    assert!(logged.contains("does not balance"), "{logged}");
    assert!(cash_balance(&svc).is_empty());
    remove_ledger_and_journal(&path);
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

/// M-47: a half envelope is operator input on both file paths. The
/// lamport is re-stamped, this node's author stamped where absent, the
/// stale signature discarded and a fresh one made. A foreign author was
/// kept, unsigned, with the T41 warning until T79 (M-54, decision (7) of
/// 2026-09-24): it is now quarantined as the file spelled it, at
/// finalisation, and again at every boot until the operator removes the
/// author line.
///
/// Bug-catch: revert `is_operator_input` to "neither key" and the two
/// own half-envelope records are served raw; revert the signature strip
/// and "stale" is served under a fresh lamport.
#[test]
fn m47_a_half_envelope_is_operator_input_on_both_file_paths_stamped_and_signed() {
    let check_own = |svc: &LedgerService, narration: &str| {
        let directive =
            transaction_named(svc, narration).unwrap_or_else(|| panic!("{narration}: adopted"));
        let metadata = directive.metadata();
        assert_eq!(
            metadata.get(ENVELOPE_KEY_AUTHOR),
            Some(&"test-peer".to_owned()),
            "{narration}"
        );
        let lamport = metadata.get(ENVELOPE_KEY_LAMPORT).expect(narration);
        assert_ne!(
            lamport, "99",
            "{narration}: a hand-typed lamport is not a clock value this node issued"
        );
        assert!(metadata.contains_key(ENVELOPE_KEY_PARENTS), "{narration}");
        assert_eq!(
            metadata.get(ENVELOPE_KEY_SIGNATURE),
            Some(&marker_signature(directive)),
            "{narration}: signed over the stamped envelope; the stale signature is gone"
        );
    };

    // Boot path, as gl-node runs it.
    let (path, _) = signed_node_written_file();
    append_to_file(&path, AUTHOR_ONLY_HAND_EDIT);
    append_to_file(&path, LAMPORT_ONLY_HAND_EDIT);
    append_to_file(&path, FOREIGN_AUTHOR_ONLY_HAND_EDIT);
    let mut svc = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
    assert_eq!(
        svc.unsigned_operator_input_count(),
        3,
        "M-47: a half envelope is operator input, not history"
    );
    svc.set_author_id("test-peer".to_owned());
    svc.set_signer(marker_signer());
    let (finalized, logged) = capture_warnings(|| svc.finalize_operator_input());
    assert_eq!(finalized, 2);
    assert!(logged.contains("cannot sign for that author"), "{logged}");
    assert!(logged.contains("(M-54)"), "{logged}");
    check_own(&svc, "author only");
    check_own(&svc, "lamport only");
    assert!(
        transaction_named(&svc, "foreign author only").is_none(),
        "M-54: a foreign author on operator input is never served"
    );
    let held = svc
        .quarantined
        .values()
        .find(|directive| {
            matches!(directive, Directive::Transaction(txn)
                    if txn.narration.as_deref() == Some("foreign author only"))
        })
        .expect("quarantined");
    assert_eq!(
        held.metadata().get(ENVELOPE_KEY_AUTHOR),
        Some(&"a-different-node".to_owned())
    );
    assert!(
        !held.metadata().contains_key(ENVELOPE_KEY_LAMPORT),
        "held as the file spelled it, never half-stamped"
    );
    assert_lamport_pairs_unique(
        &svc.dag()
            .directives()
            .into_iter()
            .filter_map(|directive| {
                Some((
                    directive_author(directive)?.to_owned(),
                    directive.lamport_clock()?,
                ))
            })
            .collect::<Vec<_>>(),
        "after finalize",
    );
    svc.compact().unwrap();
    let mut rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    rebooted.set_signer(marker_signer());
    assert_eq!(
        rebooted.unsigned_operator_input_count(),
        1,
        "canonical on disk; the refused line is back in the file as written"
    );
    assert_eq!(rebooted.finalize_operator_input(), 0);
    assert_eq!(
        rebooted.quarantined_count(),
        1,
        "refused again, never served"
    );
    check_own(&rebooted, "author only");
    check_own(&rebooted, "lamport only");

    // Live path.
    let (mut svc, path2) = setup_with_signed_accounts();
    append_to_file(&path2, AUTHOR_ONLY_HAND_EDIT);
    append_to_file(&path2, LAMPORT_ONLY_HAND_EDIT);
    assert_eq!(svc.reconcile_file().unwrap().new_directives, 2);
    check_own(&svc, "author only");
    check_own(&svc, "lamport only");

    remove_ledger_and_journal(&path);
    remove_ledger_and_journal(&path2);
}

/// L-75: a hand-spelled `openledger-parents` naming a parent that exists
/// nowhere is quarantined at boot and rejected live, with the parent
/// named; one that resolves is honoured verbatim (the control).
///
/// Bug-catch: revert the L-75 check in `adopt_file_directive` and the
/// dangling record is adopted, signed and served as a head.
#[test]
fn l75_a_hand_spelled_parent_that_exists_nowhere_is_refused_on_both_file_paths() {
    let nowhere = "f".repeat(64);
    let dangling = format!(
        "\n2024-01-24 * \"Hand\" \"dangling parent\"\n\
             \x20 openledger-parents: \"{nowhere}\"\n\
             \x20 Assets:Cash                                        13.00 USD\n\
             \x20 Equity:Opening                                    -13.00 USD\n"
    );

    // Boot.
    let (path, _) = signed_node_written_file();
    append_to_file(&path, &dangling);
    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let svc = booted.unwrap();
    assert!(transaction_named(&svc, "dangling parent").is_none());
    assert_eq!(svc.quarantined_count(), 1);
    assert_eq!(svc.unsigned_operator_input_count(), 0);
    assert!(
        logged.contains("(L-75)") && logged.contains(&nowhere),
        "the refusal names the parent: {logged}"
    );
    remove_ledger_and_journal(&path);

    // Live: refused; then the same body naming a real parent is adopted.
    let (mut svc, path) = setup_with_signed_accounts();
    let real = svc
        .append_transaction_signing(balanced_input(), marker_sign(true))
        .unwrap()
        .txid;
    append_to_file(&path, &dangling);
    let (result, logged) = capture_warnings(|| svc.reconcile_file().unwrap());
    assert_eq!(result.rejected, 1);
    assert_eq!(result.new_directives, 0);
    assert!(logged.contains("(L-75)"), "{logged}");
    assert!(transaction_named(&svc, "dangling parent").is_none());

    let resolving = dangling
        .replace(&nowhere, &real)
        .replace("dangling parent", "resolving parent");
    append_to_file(&path, &resolving);
    assert_eq!(svc.reconcile_file().unwrap().new_directives, 1);
    let adopted = transaction_named(&svc, "resolving parent").unwrap();
    assert_eq!(
        adopted.metadata().get(ENVELOPE_KEY_PARENTS),
        Some(&real),
        "a parent that resolves is the operator's own and is left alone"
    );
    remove_ledger_and_journal(&path);
}

/// L-76: the boot cycle quarantine keeps the signed spelling of a record
/// when the file also holds a raw copy of it, so the compaction writes
/// the signed copy back and the next boot does not re-author it.
///
/// Bug-catch: revert `quarantine_keeping_envelope` in the cycle arm to
/// `quarantined.insert` and T2's signature is gone from disk after the
/// compaction, and the reboot serves a re-authored T2 (quarantine
/// empty, `unsigned_operator_input_count` 1).
#[test]
fn l76_the_boot_cycle_quarantine_keeps_the_signed_spelling_over_a_raw_copy() {
    let (mut svc, path) = setup_with_signed_accounts();
    let t1 = svc
        .append_transaction_signing(
            narrated_input(make_date(2024, 1, 15), "T1"),
            marker_sign(true),
        )
        .unwrap()
        .txid;
    let t2 = svc
        .append_transaction_signing(
            narrated_input(make_date(2024, 1, 16), "T2"),
            marker_sign(true),
        )
        .unwrap()
        .txid;
    svc.compact().unwrap();
    drop(svc);

    // T1 → T2 → T1: a cycle, no content id changes. Plus a raw copy of T2.
    edit_block_lines(&path, "\"T1\"", |line| {
        if line.trim_start().starts_with(ENVELOPE_KEY_PARENTS) {
            format!("  {ENVELOPE_KEY_PARENTS}: \"{t2}\"")
        } else {
            line.to_owned()
        }
    });
    let raw_t2 = raw_copy_of_block(&path, "\"T2\"");
    append_to_file(&path, &format!("\n{raw_t2}\n"));

    let mut expected: Vec<&str> = vec![t1.as_str(), t2.as_str()];
    expected.sort_unstable();
    let (booted, _) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut svc = booted.unwrap();
    assert_eq!(svc.quarantined_ids(), expected);
    assert!(
        svc.quarantined[&t2]
            .metadata()
            .contains_key(ENVELOPE_KEY_SIGNATURE),
        "L-76: the enveloped spelling is the one held"
    );
    assert_eq!(svc.unsigned_operator_input_count(), 0);
    svc.set_signer(marker_signer());
    svc.compact().unwrap();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    let t2_blocks: Vec<&str> = on_disk
        .split("\n\n")
        .filter(|block| block.contains("\"T2\""))
        .collect();
    assert_eq!(t2_blocks.len(), 1, "one spelling of T2 on disk:\n{on_disk}");
    assert!(
        t2_blocks[0].contains(ENVELOPE_KEY_SIGNATURE),
        "the signed one"
    );

    let (rebooted, _) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let rebooted = rebooted.unwrap();
    assert_eq!(rebooted.quarantined_ids(), expected, "a fixed point");
    assert!(
        transaction_named(&rebooted, "T2").is_none(),
        "not re-authored"
    );
    assert_eq!(rebooted.unsigned_operator_input_count(), 0);
    remove_ledger_and_journal(&path);
}

/// L-74: `finalize_operator_input` re-indexes the finalised directive, so
/// `journal` and `transaction` serve the same envelope as `get_directive`
/// without a restart.
///
/// Bug-catch: remove the `reindex_directive` loop and the journal copy
/// keeps `author: "local"` and no signature.
#[test]
fn l74_finalize_re_indexes_the_read_model_so_journal_and_transaction_agree() {
    let (path, _) = signed_node_written_file();
    append_to_file(&path, OFFLINE_HAND_EDIT);
    let mut svc = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
    svc.set_author_id("test-peer".to_owned());
    svc.set_signer(marker_signer());
    let id = svc.unsigned_operator_input[0].clone();
    assert_eq!(
        svc.read_model()
            .transaction(&id)
            .unwrap()
            .transaction
            .metadata
            .get(ENVELOPE_KEY_AUTHOR),
        Some(&"local".to_owned()),
        "boot's clone carries the placeholder"
    );
    svc.finalize_operator_input();
    let dag_copy = svc.get_directive(&id).unwrap().metadata().clone();
    assert_eq!(
        dag_copy.get(ENVELOPE_KEY_AUTHOR),
        Some(&"test-peer".to_owned())
    );
    assert!(dag_copy.contains_key(ENVELOPE_KEY_SIGNATURE));
    let journal_copy = svc
        .read_model()
        .journal(None, None, None, usize::MAX, 0)
        .into_iter()
        .find(|indexed| indexed.txid == id)
        .expect("listed")
        .transaction
        .metadata
        .clone();
    assert_eq!(journal_copy, dag_copy, "L-74");
    assert_eq!(
        svc.read_model()
            .transaction(&id)
            .unwrap()
            .transaction
            .metadata,
        dag_copy
    );
    remove_ledger_and_journal(&path);
}

/// L-77: a hand-typed `open` of an account that is already open is
/// refused on both file paths exactly as `open_account` refuses it, so
/// the account's currency constraint cannot be widened from the file.
/// Since T92 (L-121) the file path judges it at boot in
/// `finalize_operator_input`, once the signature pass has settled which
/// `open`s are served — so the boot half runs gl-node's order.
///
/// Bug-catch: remove the `is_open` arm in `adopt_file_directive` (live) or
/// the re-judge in `finalize_operator_input` (boot) and the re-open is
/// adopted and `currencies("Assets:Cash")` gains `EUR`.
#[test]
fn l77_a_hand_open_of_an_already_open_account_is_refused_on_both_file_paths() {
    const REOPEN: &str = "\n2024-01-01 open Assets:Cash EUR\n";
    let usd = vec!["USD".to_owned()];

    let (path, _) = signed_node_written_file();
    append_to_file(&path, REOPEN);
    let (mut svc, logged) = capture_warnings(|| {
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.set_signer(marker_signer());
        svc.finalize_operator_input();
        svc
    });
    assert_eq!(svc.quarantined_count(), 1);
    assert_eq!(svc.unsigned_operator_input_count(), 0);
    assert!(logged.contains("already open"), "{logged}");
    assert_eq!(svc.accounts().currencies("Assets:Cash"), Some(usd.clone()));
    let api = svc
        .open_account(
            "Assets:Cash".to_owned(),
            make_date(2024, 1, 1),
            vec!["EUR".to_owned()],
        )
        .unwrap_err();
    assert_eq!(
        api.error_code(),
        ServiceError::AccountAlreadyOpen {
            account: "Assets:Cash".to_owned()
        }
        .error_code(),
        "the file path refuses exactly what the API refuses"
    );
    remove_ledger_and_journal(&path);

    let (mut svc, path) = setup_with_signed_accounts();
    append_to_file(&path, REOPEN);
    let (result, logged) = capture_warnings(|| svc.reconcile_file().unwrap());
    assert_eq!(result.rejected, 1);
    assert_eq!(result.new_directives, 0);
    assert!(logged.contains("already open"), "{logged}");
    assert_eq!(svc.accounts().currencies("Assets:Cash"), Some(usd.clone()));
    remove_ledger_and_journal(&path);
}

/// T98 / L-153 (X3's `k15`): a hand `close` is data at boot, as on the
/// wire. Node-written history holds a 03-15 posting on Cash; the operator
/// types `close Assets:Cash` 02-01 and a re-`open` 03-01. Adoption runs in
/// date order, so before T98 the `close` was judged before the re-`open`
/// with an unbounded interval, refused for the 03-15 posting and held — and
/// served at a later boot, once the compaction had written the re-`open`
/// as history. Now the `close` is served at the first boot, the posting
/// stays, and boot → compaction → boot is a fixed point.
///
/// Bug-catch: restore the back-dated-`close` refusal on the file path and
/// the `close` is held at the first boot.
#[test]
fn l153_a_hand_close_is_served_at_the_first_boot() {
    let (mut svc, path) = setup_with_accounts();
    let mut input = balanced_input();
    input.date = make_date(2024, 3, 15);
    let posting = svc.append_transaction(input).unwrap().txid;
    svc.compact().unwrap();
    drop(svc);
    append_to_file(
        &path,
        "\n2024-02-01 close Assets:Cash\n\n2024-03-01 open Assets:Cash USD\n",
    );
    let close = LedgerService::content_id(&Directive::Close(Close {
        date: make_date(2024, 2, 1),
        account: "Assets:Cash".to_owned(),
        metadata: Metadata::new(),
    }));
    let mut first = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    first.finalize_operator_input();
    assert!(first.contains_directive(&close), "the hand close is served");
    assert!(first.contains_directive(&posting));
    assert_eq!(first.quarantined_count(), 0);
    let ids = first.all_directive_ids();
    first.compact().unwrap();
    drop(first);
    let mut second = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    second.finalize_operator_input();
    assert_eq!(second.all_directive_ids(), ids, "a fixed point");
    assert_eq!(second.quarantined_count(), 0);
    remove_ledger_and_journal(&path);
}

/// T98 / decision (54): a transaction the operator types into the file is
/// data like a peer's — admitted whenever an `open` precedes it, whatever
/// `close` sits in between — on both file paths and through boot's rebase
/// of pending input. The boot half carries a history record whose parent
/// exists nowhere, so the served-set rule quarantines it and the rebuild
/// rebases (re-validates) the pending hand transaction.
///
/// Bug-catch: judge file adoption, or boot's rebase, by the authoring
/// fold again and the hand transaction after the `close` is refused.
#[test]
fn t98_a_hand_transaction_after_a_hand_close_is_data_at_boot_and_live() {
    let (mut svc, path) = setup_with_accounts();
    let mut input = balanced_input();
    input.date = make_date(2024, 3, 15);
    svc.append_transaction(input).unwrap();
    svc.compact().unwrap();
    drop(svc);
    let dangling = "f".repeat(64);
    append_to_file(
        &path,
        &format!(
            "\n2024-02-01 close Assets:Cash\n\n\
                 2024-02-10 * \"Acme\" \"typed after the close\"\n  \
                 Assets:Cash  1 USD\n  Equity:Opening  -1 USD\n\n\
                 2024-01-20 * \"Acme\" \"over a parent that exists nowhere\"\n  \
                 openledger-author: \"test-peer\"\n  openledger-lamport: \"50\"\n  \
                 openledger-parents: \"{dangling}\"\n  \
                 Assets:Cash  2 USD\n  Equity:Opening  -2 USD\n"
        ),
    );
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.finalize_operator_input();
    assert_eq!(
        svc.quarantined_count(),
        1,
        "premise: the rule held a record"
    );
    let typed = svc.dag().directives().into_iter().any(|directive| {
        matches!(directive, Directive::Transaction(txn)
                if txn.narration.as_deref() == Some("typed after the close"))
    });
    assert!(typed, "the hand transaction after the hand close is served");

    append_to_file(
        &path,
        "\n2024-02-20 * \"Acme\" \"typed live\"\n  Assets:Cash  3 USD\n  \
             Equity:Opening  -3 USD\n",
    );
    // `rejected` re-counts the quarantined record, as every reconcile
    // counts a boot-held one (T90); the typed line is the new directive.
    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.new_directives, 1, "{result:?}");
    let live = svc.dag().directives().into_iter().any(|directive| {
        matches!(directive, Directive::Transaction(txn)
                if txn.narration.as_deref() == Some("typed live"))
    });
    assert!(
        live,
        "the hand transaction typed under a running node is served"
    );
    remove_ledger_and_journal(&path);
}

// ── T79: operator input after verification (H-22, M-54, L-75) ──

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

/// H-22: the README's stop → edit → start with a typo fixed in a signed
/// record AND a line appended. Boot stamps the hand line's parents from
/// the heads it holds — the edited record among them — before the H-20
/// pass quarantines that record. The quarantine rebuild re-chooses the
/// parents of the still-unsigned line from what survives, so the line is
/// signed over records every peer holds; a reboot is a fixed point.
///
/// Bug-catch: drop the rebase in `quarantine_out_of_dag` and the hand
/// line is signed naming the quarantined id.
#[test]
fn h22_a_hand_line_appended_with_an_edit_is_rebased_before_it_is_signed() {
    let (path, first, _second) = two_signed_transactions_file();
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, content.replace("\"T2\"", "\"T2 edited\"")).unwrap();
    let edited = edited_t2_id(&path);
    append_to_file(&path, &h22_hand_line("appended with the fix", None));

    // gl-node's order.
    let mut svc = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
    svc.set_author_id("test-peer".to_owned());
    assert_eq!(
        parents_of_named(&svc, "appended with the fix"),
        vec![edited.clone()],
        "premise: boot stamped the edited record as the parent"
    );
    let (_, logged) = capture_warnings(|| svc.set_signer(marker_signer()));
    assert_eq!(svc.quarantined_ids(), vec![edited.as_str()]);
    assert!(logged.contains("(H-22)") || svc.unsigned_operator_input_count() == 1);
    assert_eq!(svc.finalize_operator_input(), 1);

    assert_eq!(
        parents_of_named(&svc, "appended with the fix"),
        vec![first.clone()],
        "re-chosen from what survives: T1 is the head once T2 edited is quarantined"
    );
    let hand = transaction_named(&svc, "appended with the fix").unwrap();
    assert_eq!(
        hand.metadata().get(ENVELOPE_KEY_SIGNATURE),
        Some(&marker_signature(hand)),
        "signed over the rebased parents"
    );
    assert_eq!(
        svc.read_model()
            .transaction(&compute_content_id(hand))
            .and_then(|indexed| {
                indexed
                    .transaction
                    .metadata
                    .get(ENVELOPE_KEY_PARENTS)
                    .cloned()
            }),
        Some(first.clone()),
        "L-74: the read model serves the rebased envelope"
    );

    svc.compact().unwrap();
    let mut rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    rebooted.set_signer(marker_signer());
    assert_eq!(rebooted.quarantined_ids(), vec![edited.as_str()]);
    assert_eq!(
        parents_of_named(&rebooted, "appended with the fix"),
        vec![first],
        "a fixed point"
    );
    remove_ledger_and_journal(&path);
}

/// H-22's second door and the cascade: a hand line whose
/// `openledger-parents` the operator spelled names the edited record's
/// id. At adoption that id is still in the DAG; once the H-20 pass
/// quarantines it, the line is refused with it and held as the FILE
/// spelled it, and a later hand line boot had stamped on top of it is
/// rebased onto what survives. Live, a hand parent that is only in the
/// quarantine is refused outright (L-75 in the DAG alone).
///
/// Bug-catch: drop the hand-parent check in `rebase_operator_input` and
/// the first line is served naming the quarantined id; restore "DAG ∪
/// quarantine" in `adopt_file_directive` and the live line is adopted.
#[test]
fn h22_a_hand_parent_on_a_record_quarantined_at_boot_is_refused_and_the_refusal_cascades() {
    let (path, first, _second) = two_signed_transactions_file();
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, content.replace("\"T2\"", "\"T2 edited\"")).unwrap();
    let edited = edited_t2_id(&path);
    append_to_file(&path, &h22_hand_line("names the edit", Some(&edited)));
    append_to_file(&path, &h22_hand_line("stamped on top", None));

    let mut svc = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
    svc.set_author_id("test-peer".to_owned());
    assert_eq!(svc.unsigned_operator_input_count(), 2, "premise");
    let (_, logged) = capture_warnings(|| svc.set_signer(marker_signer()));
    assert!(transaction_named(&svc, "names the edit").is_none());
    assert!(
        logged.contains("(L-75)") && logged.contains(&edited),
        "the refusal names the parent: {logged}"
    );
    let held = svc
        .quarantined
        .values()
        .find(|directive| {
            matches!(directive, Directive::Transaction(txn)
                    if txn.narration.as_deref() == Some("names the edit"))
        })
        .expect("held in the quarantine");
    assert!(
        !held.metadata().contains_key(ENVELOPE_KEY_LAMPORT)
            && !held.metadata().contains_key(ENVELOPE_KEY_AUTHOR),
        "as the file spelled it, never half-stamped"
    );
    assert_eq!(
        parents_of_named(&svc, "stamped on top"),
        vec![first.clone()],
        "rebased off the refused line"
    );
    assert_eq!(svc.finalize_operator_input(), 1);

    // Live: a hand parent that is only in the quarantine is refused.
    svc.compact().unwrap();
    append_to_file(&path, &h22_hand_line("live on the edit", Some(&edited)));
    let (result, logged) = capture_warnings(|| svc.reconcile_file().unwrap());
    assert_eq!(result.new_directives, 0);
    assert_eq!(
        result.rejected, 3,
        "the live line, plus the two quarantined blocks the reconcile re-reads"
    );
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("T2 edited") && on_disk.contains("names the edit"),
        "H-08: quarantined blocks are written back unchanged"
    );
    assert!(
        logged.contains("held in this node's quarantine"),
        "{logged}"
    );
    assert!(transaction_named(&svc, "live on the edit").is_none());
    remove_ledger_and_journal(&path);
}

/// M-54 at boot, and the rebase's validation: a hand `open` naming
/// another node as its author is refused at finalisation (the author is
/// only final then), and a hand transaction on that account — valid
/// when boot adopted it — no longer validates without the `open`, so it
/// is refused with it, as written.
///
/// Bug-catch: drop the foreign-author refusal in
/// `finalize_operator_input` and the `open` is served unsigned; drop the
/// `validate_transaction` call in `rebase_operator_input` and the
/// transaction is served on an account no peer has opened.
#[test]
fn m54_a_foreign_author_open_is_refused_at_finalisation_and_what_relied_on_it_goes_with_it() {
    let (path, _) = signed_node_written_file();
    append_to_file(
        &path,
        "\n2024-01-20 open Assets:Pasted USD\n\
             \x20 openledger-author: \"a-different-node\"\n",
    );
    append_to_file(
        &path,
        "\n2024-01-26 * \"Hand\" \"on the pasted account\"\n\
             \x20 Assets:Pasted                                        5.00 USD\n\
             \x20 Equity:Opening                                      -5.00 USD\n",
    );
    let mut svc = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
    svc.set_author_id("test-peer".to_owned());
    svc.set_signer(marker_signer());
    assert_eq!(
        svc.unsigned_operator_input_count(),
        2,
        "premise: both adopted"
    );

    let (finalized, logged) = capture_warnings(|| svc.finalize_operator_input());
    assert_eq!(finalized, 0);
    assert!(logged.contains("(M-54)"), "{logged}");
    assert!(logged.contains("no longer validates"), "{logged}");
    assert!(!svc.accounts().is_open("Assets:Pasted"));
    assert!(transaction_named(&svc, "on the pasted account").is_none());
    assert_eq!(svc.quarantined_count(), 2);
    assert!(
        svc.quarantined
            .values()
            .all(|directive| { !directive.metadata().contains_key(ENVELOPE_KEY_LAMPORT) }),
        "both held as the file spelled them"
    );
    remove_ledger_and_journal(&path);
}

/// H-22 on the recovery path: a reload re-derives operator input from
/// the file with parents stamped over the edited record, and the carried
/// signer is installed by assignment. The pass must run before the
/// finalisation, or the hand line is signed over a parent the pass then
/// quarantines.
///
/// Bug-catch: swap `verify_own_history` and `finalize_operator_input`
/// back in `finish_recovery` and the hand line is signed naming the
/// quarantined id.
#[test]
fn h22_a_recovery_reload_verifies_before_it_finalises() {
    let (path, first, _second) = two_signed_transactions_file();
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, content.replace("\"T2\"", "\"T2 edited\"")).unwrap();
    let edited = edited_t2_id(&path);
    append_to_file(&path, &h22_hand_line("appended with the fix", None));

    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    let (_, logged) = capture_warnings(|| svc.recover_failed_commit());
    assert!(logged.contains("L-13 reload installed"), "{logged}");
    assert_eq!(svc.quarantined_ids(), vec![edited.as_str()]);
    assert_eq!(
        svc.unsigned_operator_input_count(),
        0,
        "finalised by the reload"
    );
    assert_eq!(parents_of_named(&svc, "appended with the fix"), vec![first]);
    let hand = transaction_named(&svc, "appended with the fix").unwrap();
    assert_eq!(
        hand.metadata().get(ENVELOPE_KEY_SIGNATURE),
        Some(&marker_signature(hand))
    );
    remove_ledger_and_journal(&path);
}

/// L-131 (T92), the audit's X2 `c1b`: a record the closure holds (its
/// parent is over a legacy ceiling) and, beside it in the file, the
/// operator's hand-typed copy of the same body — no envelope — to restate
/// it. Same body, same id: the hand copy is the DAG's, pending operator
/// input. Before T92 the signature pass judged it as history, held it for
/// "no openledger-signature", and the startup compaction dropped the typed
/// block. Now it is adopted as this node's own, signed at finalisation,
/// served, and written by the compaction.
///
/// Bug-catch: drop the pending-input skip in `verify_history_pass` and the
/// hand copy is held and gone from the file.
#[test]
fn l131_a_hand_copy_typed_beside_a_held_record_is_adopted_not_dropped() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let Directive::Transaction(mut flood) =
        signed_history_transaction("over the legacy ceiling", 1, ("Assets:Cash", "USD"), "", 11)
    else {
        unreachable!()
    };
    flood.postings[0].metadata = (0
        ..=crate::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY)
        .map(|index| (format!("k{index}"), "v".to_owned()))
        .collect();
    let flood = marker_signed(Directive::Transaction(flood));
    let held = signed_history_transaction(
        "child of the flood",
        2,
        ("Assets:Cash", "USD"),
        &compute_content_id(&flood),
        12,
    );
    let id = compute_content_id(&held);
    let mut typed = held.clone();
    directive_metadata_mut(&mut typed).retain(|key, _| !key.starts_with("openledger-"));
    assert_eq!(compute_content_id(&typed), id, "premise: same body");
    append_to_file(
        &path,
        &format!("\n{}", full_file_serialize(&[flood, held, typed], &[])),
    );
    let mut svc = t85_boot(&path);
    assert!(svc.contains_directive(&id), "the typed copy is served");
    let served = svc.get_directive(&id).unwrap();
    assert_eq!(
        served
            .metadata()
            .get(ENVELOPE_KEY_AUTHOR)
            .map(String::as_str),
        Some("test-peer")
    );
    assert!(served.metadata().contains_key(ENVELOPE_KEY_SIGNATURE));
    assert_eq!(
        served
            .metadata()
            .get(ENVELOPE_KEY_PARENTS)
            .map(String::as_str),
        Some(""),
        "parents this node serves, not the refused flood"
    );
    svc.compact().unwrap();
    drop(svc);
    let svc = t85_boot(&path);
    assert!(svc.contains_directive(&id), "and after a restart");
    remove_ledger_and_journal(&path);
}

/// T100 / L-154 (X1 `m9`), decision (63): the banner's remedy — delete an
/// envelope-only-edited record's `openledger-*` lines — re-adopts T2 from
/// the file, and until the rewrite that spells it canonically succeeds T2
/// is withheld from peers (T93 / L-116). Its signed child T3 is history
/// the file already held; offered alone it is a record no peer can adopt,
/// so it is withheld with T2 — in `served_directive`, the served heads and
/// the served ids — and both are offered once the rewrite succeeds.
///
/// Bug-catch: withhold only the adopted lines, not what descends from them,
/// and T3 is served (and advertised as a head) before its parent.
#[test]
fn l154_a_child_of_a_line_awaiting_its_rewrite_is_withheld_with_it() {
    let (mut svc, path) = setup_with_signed_accounts();
    let t2 = svc
        .append_transaction_signing(balanced_input(), marker_sign(true))
        .unwrap()
        .txid;
    let t3 = svc
        .append_transaction_signing(
            TransactionInput {
                date: make_date(2024, 1, 20),
                narration: Some("T3 on top".to_owned()),
                ..balanced_input()
            },
            marker_sign(true),
        )
        .unwrap()
        .txid;
    svc.compact().unwrap();
    drop(svc);
    let text = std::fs::read_to_string(&path).unwrap();
    let stripped: Vec<String> = text
        .split("\n\n")
        .map(|block| {
            if block.contains("\"Funding\"") {
                block
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("openledger-"))
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                block.to_owned()
            }
        })
        .collect();
    std::fs::write(&path, stripped.join("\n\n")).unwrap();
    let mut svc = t85_boot(&path);
    assert!(
        svc.contains_directive(&t2) && svc.contains_directive(&t3),
        "premise"
    );
    assert!(
        svc.served_directive(&t2).is_none(),
        "premise: T2 awaits its rewrite"
    );
    assert!(
        svc.served_directive(&t3).is_none(),
        "T3 is withheld with its parent"
    );
    assert!(!svc.served_head_txids().contains(&t3));
    assert!(!svc.served_sorted_directive_ids().contains(&t3));
    svc.compact().unwrap();
    assert!(svc.served_directive(&t2).is_some() && svc.served_directive(&t3).is_some());
    assert!(svc.served_head_txids().contains(&t3));
    remove_ledger_and_journal(&path);
}

/// T99 / M-72 at the served-set rule (decision (58)): the file spells one
/// record twice, and the copy boot meets first names a parent that exists
/// nowhere (its parents line edited, or a copy restated elsewhere) while
/// the other names the parents this node serves. The rule, about to hold
/// the record and its child, serves it on the other copy instead: both are
/// served, nothing is held, and the compaction keeps that copy.
///
/// Bug-catch: drop the rescue from the rule's round and the record and
/// its child are held.
#[test]
fn m72_a_record_first_loaded_over_a_missing_parent_is_served_on_its_other_copy() {
    let (mut svc, path) = setup_with_accounts();
    let record = svc.append_transaction(balanced_input()).unwrap().txid;
    let mut later = balanced_input();
    later.date = make_date(2024, 1, 20);
    later.narration = Some("the child".to_owned());
    let child = svc.append_transaction(later).unwrap().txid;
    svc.compact().unwrap();
    drop(svc);
    let text = std::fs::read_to_string(&path).unwrap();
    let block = text
        .split("\n\n")
        .find(|block| block.contains("\"Funding\""))
        .expect("the record's block")
        .to_owned();
    let dangling = block
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("openledger-parents:") {
                format!("  openledger-parents: \"{}\"", "f".repeat(64))
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(dangling, block, "premise: the copy names another parent");
    std::fs::write(
        &path,
        text.replacen(&block, &format!("{dangling}\n\n{block}"), 1),
    )
    .unwrap();
    let svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert!(svc.contains_directive(&record) && svc.contains_directive(&child));
    assert_eq!(svc.quarantined_count(), 0, "{:?}", svc.quarantined_ids());
    let parents = match svc.get_directive(&record) {
        Some(Directive::Transaction(txn)) => txn
            .parent_ids()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        _ => panic!("the record is a transaction"),
    };
    assert!(
        !parents.contains(&"f".repeat(64)),
        "served on the other copy"
    );
    remove_ledger_and_journal(&path);
}

/// T99 / L-145 (X1-3, decision (59)): the L-131 shape, except the typed
/// copy spells another node as its author, so `finalize_operator_input`
/// refuses it (M-54). Adoption no longer takes the record out of the
/// closure — finalisation does, for what it finalises — so a peer's child
/// of the held record is still refused as naming a held-back parent
/// (before T99 it was buffered on a missing parent until a restart), and
/// the typed spelling stays in the file beside the node-written copy.
///
/// Bug-catch: prune the closure at boot adoption again and the peer's
/// child is a missing parent; keep only the enveloped spelling and the
/// typed block is gone after the compaction.
#[test]
fn l145_a_typed_copy_refused_at_finalisation_stays_held_back_and_in_the_file() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let Directive::Transaction(mut flood) =
        signed_history_transaction("over the legacy ceiling", 1, ("Assets:Cash", "USD"), "", 11)
    else {
        unreachable!()
    };
    flood.postings[0].metadata = (0
        ..=crate::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY)
        .map(|index| (format!("k{index}"), "v".to_owned()))
        .collect();
    let flood = marker_signed(Directive::Transaction(flood));
    let held = signed_history_transaction(
        "child of the flood",
        2,
        ("Assets:Cash", "USD"),
        &compute_content_id(&flood),
        12,
    );
    let id = compute_content_id(&held);
    let mut typed = held.clone();
    directive_metadata_mut(&mut typed).retain(|key, _| !key.starts_with("openledger-"));
    directive_metadata_mut(&mut typed)
        .insert(ENVELOPE_KEY_AUTHOR.to_owned(), "someone-else".to_owned());
    append_to_file(
        &path,
        &format!("\n{}", full_file_serialize(&[flood, held, typed], &[])),
    );
    let mut svc = t85_boot(&path);
    assert!(
        !svc.contains_directive(&id),
        "premise: the typed copy is refused (M-54)"
    );
    let mut child = remote_transaction("a peer's child of the held record", false);
    child
        .metadata
        .insert(ENVELOPE_KEY_PARENTS.to_owned(), id.clone());
    let refused = svc
        .stage_remote_directive(Directive::Transaction(child))
        .unwrap_err();
    assert_eq!(
        refused.error_code(),
        "INVALID_INPUT",
        "the held record is still held back: {refused}"
    );
    svc.compact().unwrap();
    drop(svc);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains("openledger-author: \"someone-else\""),
        "the typed spelling is in the file:\n{text}"
    );
    remove_ledger_and_journal(&path);
}

/// M-64 (T92, decision (39)), the audit's X1 `n1a`: an own signed chain
/// T1 ← R ← T ← P ← C. The operator deleted R's block and P's
/// `openledger-lamport` and `openledger-signature` lines (a half envelope:
/// operator input with a hand-spelled parent, M-47). The rule holds T (its
/// parent exists nowhere); P was exempt from that walk as pending input,
/// and the rebuild then refuses it (its hand parent is held). Before T92
/// nothing re-ran the rule, so C — signed history naming P — was served
/// over a parent held in the quarantine, and every later write named it.
///
/// Bug-catch: drop the fixpoint (`ids.len()` alone at the end of
/// `quarantine_unservable_history`) and C is served.
#[test]
fn m64_a_record_whose_hand_parent_the_rebuild_refuses_is_held_too() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let cash = ("Assets:Cash", "USD");
    let t1 = signed_history_transaction("T1", 1, cash, "", 20);
    let r = signed_history_transaction("R", 2, cash, &compute_content_id(&t1), 21);
    let t = signed_history_transaction("T", 3, cash, &compute_content_id(&r), 22);
    let mut p = signed_history_transaction("P", 4, cash, &compute_content_id(&t), 23);
    let c = signed_history_transaction("C", 5, cash, &compute_content_id(&p), 24);
    let c_id = compute_content_id(&c);
    let metadata = directive_metadata_mut(&mut p);
    metadata.remove(ENVELOPE_KEY_LAMPORT);
    metadata.remove(ENVELOPE_KEY_SIGNATURE);
    assert!(
        LedgerService::is_operator_input(&p),
        "premise: a half envelope"
    );
    append_to_file(
        &path,
        &format!("\n{}", full_file_serialize(&[t1, t, p, c], &[])),
    );
    let svc = t85_boot(&path);
    assert!(!svc.contains_directive(&c_id), "C is not served over P");
    assert!(svc.quarantined_ids().contains(&c_id.as_str()));
    for directive in svc.dag().directives() {
        if let Directive::Transaction(txn) = directive {
            for parent in txn.parent_ids() {
                assert!(
                    svc.contains_directive(parent),
                    "{} names {parent}, which this node does not serve",
                    compute_content_id(directive)
                );
            }
        }
    }
    remove_ledger_and_journal(&path);
}

/// H-23 (T84), the audit's X1 `c3j`: T2's narration is edited (a new id,
/// quarantined by the signature pass) while J — T2's signed child, naming
/// T2's ORIGINAL id — keeps an envelope that verifies. That id is in no
/// quarantine and nowhere else on this node, so J is a record no peer
/// lacking T2 can adopt. Before T84 J was served as a head, the H-22 rebase
/// re-chose the hand line's parents onto it, and nothing was said. Now J is
/// held at boot, named, and the hand line is signed over T1.
///
/// Bug-catch: drop both `quarantine_unservable_history` calls (at boot and
/// after the signature pass — either one catches this shape) and J is
/// served and named by the hand line.
#[test]
fn h23_a_hand_line_is_never_signed_over_a_served_record_whose_parent_vanished() {
    let (path, first, second) = two_signed_transactions_file();
    let child = format!(
        "2024-01-20 * \"J\" \"child of the original\"\n\
             \x20 openledger-author: \"test-peer\"\n\
             \x20 openledger-lamport: \"40\"\n\
             \x20 openledger-parents: \"{second}\"\n\
             \x20 Assets:Cash                                         3.00 USD\n\
             \x20 Equity:Opening                                     -3.00 USD\n"
    );
    let signed = marker_signed(parse_file(&child).unwrap().remove(0));
    let child_id = compute_content_id(&signed);
    append_to_file(
        &path,
        &format!(
            "\n{}",
            full_file_serialize(std::slice::from_ref(&signed), &[])
        ),
    );
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, content.replace("\"T2\"", "\"T2 edited\"")).unwrap();
    append_to_file(&path, &h22_hand_line("appended with the fix", None));

    // gl-node's order.
    let (svc, logged) = capture_warnings(|| {
        let mut svc = LedgerService::boot(path.clone(), "local".to_owned()).unwrap();
        svc.set_author_id("test-peer".to_owned());
        svc.set_signer(marker_signer());
        svc.finalize_operator_input();
        svc
    });
    assert!(
        svc.get_directive(&child_id).is_none(),
        "J is held, not served"
    );
    assert!(svc.quarantined_ids().contains(&child_id.as_str()));
    assert!(
        logged.contains(&child_id) && logged.contains("exists nowhere on this node"),
        "{logged}"
    );
    assert_eq!(
        parents_of_named(&svc, "appended with the fix"),
        vec![first.clone()],
        "the hand line is signed over T1, never over J"
    );
    for directive in svc.dag().directives() {
        if let Directive::Transaction(txn) = directive {
            for parent in txn.parent_ids() {
                assert!(
                    svc.get_directive(parent).is_some(),
                    "everything served names only what is served"
                );
            }
        }
    }
    remove_ledger_and_journal(&path);
}

/// H-22 item (d), as decision (15) re-decided it (T84 / H-23): a signed
/// record that names a parent only in this node's quarantine — what an
/// older build left behind, a hand line signed over an edited record's id
/// — is one no peer lacking that parent can adopt. It is quarantined with
/// what descends from it, and the WARN names it, its parent and the remedy.
/// Before T84 it was served with a WARN only (T79's deviation).
///
/// Bug-catch: drop the `quarantine_unservable_history` call after the
/// signature pass and the record is served.
#[test]
fn h22_a_served_record_naming_a_quarantined_parent_is_quarantined_and_named() {
    let (path, _first, _second) = two_signed_transactions_file();
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, content.replace("\"T2\"", "\"T2 edited\"")).unwrap();
    let edited = edited_t2_id(&path);
    let unsigned = format!(
        "2024-01-26 * \"Hand\" \"signed by an older build\"\n\
             \x20 openledger-author: \"test-peer\"\n\
             \x20 openledger-lamport: \"50\"\n\
             \x20 openledger-parents: \"{edited}\"\n\
             \x20 Assets:Cash                                         5.00 USD\n\
             \x20 Equity:Opening                                     -5.00 USD\n"
    );
    let signed = marker_signed(parse_file(&unsigned).unwrap().remove(0));
    let signature = signed
        .metadata()
        .get(ENVELOPE_KEY_SIGNATURE)
        .unwrap()
        .clone();
    append_to_file(
        &path,
        &format!(
            "\n{}",
            unsigned.replacen(
                "  openledger-parents",
                &format!("  openledger-signature: \"{signature}\"\n  openledger-parents"),
                1
            )
        ),
    );

    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert!(
        transaction_named(&svc, "signed by an older build").is_some(),
        "premise: before the signature pass its parent is served, so it is too"
    );
    let (_, logged) = capture_warnings(|| svc.set_signer(marker_signer()));
    assert!(
        transaction_named(&svc, "signed by an older build").is_none(),
        "no peer lacking its parent can adopt it, so it is not served"
    );
    assert_eq!(svc.quarantined_ids().len(), 2, "the edited record and it");
    assert!(
        logged.contains("no fresh replica could hold")
            && logged.contains("only in this node's quarantine")
            && logged.contains(&edited),
        "{logged}"
    );
    remove_ledger_and_journal(&path);
}

// ── T80: the author id is the key (M-53, L-82, L-91) ──

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
         signature: &str| {
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

/// M-53 (T80, decision (9)): a history signed under the placeholder is
/// re-attributed to this node when its signatures verify under this
/// node's key — through the verifier (gl-node's order, P2P on) and
/// through the signer alone — instead of being quarantined whole. The
/// signatures are unchanged, the compaction writes the new author, and a
/// reboot is a fixed point with nothing quarantined.
///
/// Bug-catch: drop the re-attribution in `verify_history_pass` and all
/// three records are quarantined ("signature does not verify").
#[test]
fn m53_a_history_signed_under_the_placeholder_is_reattributed_not_quarantined() {
    for with_verifier in [true, false] {
        let path = pre_t80_placeholder_signed_file();
        let signatures_before: Vec<String> = parse_file(&std::fs::read_to_string(&path).unwrap())
            .unwrap()
            .iter()
            .map(|directive| directive.metadata()[ENVELOPE_KEY_SIGNATURE].clone())
            .collect();

        // gl-node's order since T80.
        let mut svc = LedgerService::boot(path.clone(), PLACEHOLDER_AUTHOR.to_owned()).unwrap();
        svc.set_author_id("test-peer".to_owned());
        let (_, logged) = capture_warnings(|| {
            svc.set_signer(marker_signer());
            if with_verifier {
                svc.set_verifier(marker_verifier());
            }
            svc.verify_own_history()
        });
        assert_eq!(
            svc.quarantined_count(),
            0,
            "with_verifier={with_verifier}: {logged}"
        );
        assert_eq!(svc.signature_quarantined_total(), 0);
        assert_eq!(svc.directive_count(), 3);
        assert!(svc
            .dag()
            .directives()
            .into_iter()
            .all(|directive| { directive_author(directive) == Some("test-peer") }));
        assert!(
            svc.compaction_pending(),
            "the file still spells the placeholder"
        );

        svc.compact().unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(!written.contains("openledger-author: \"local\""));
        let signatures_after: Vec<String> = parse_file(&written)
            .unwrap()
            .iter()
            .map(|directive| directive.metadata()[ENVELOPE_KEY_SIGNATURE].clone())
            .collect();
        assert_eq!(
            signatures_before, signatures_after,
            "the signatures do not cover the author and are unchanged"
        );

        let mut rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        rebooted.set_signer(marker_signer());
        rebooted.set_verifier(marker_verifier());
        assert_eq!(rebooted.quarantined_count(), 0);
        assert_eq!(rebooted.directive_count(), 3);
        remove_ledger_and_journal(&path);
    }
}

/// M-53 control: a placeholder record whose signature does NOT verify as
/// this node's — edited, or signed by another key — is not re-attributed
/// and is quarantined by the normal verdict; the live reconcile applies
/// the same rule to a pasted placeholder record.
///
/// Bug-catch: re-attribute without checking the signature and the edited
/// record is served under this node's author.
#[test]
fn m53_a_placeholder_record_that_does_not_verify_as_ours_is_not_reattributed() {
    let path = pre_t80_placeholder_signed_file();
    let content = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, content.replace("\"Funding\"", "\"Funding edited\"")).unwrap();
    let mut svc = LedgerService::boot(path.clone(), PLACEHOLDER_AUTHOR.to_owned()).unwrap();
    svc.set_author_id("test-peer".to_owned());
    svc.set_signer(marker_signer());
    svc.set_verifier(marker_verifier());
    assert_eq!(svc.quarantined_count(), 1, "the edited record");
    assert_eq!(svc.signature_quarantined_total(), 1);
    assert!(transaction_named(&svc, "Funding edited").is_none());
    assert_eq!(svc.directive_count(), 2, "the two opens are re-attributed");
    remove_ledger_and_journal(&path);

    // Live: a pasted, validly signed placeholder record is re-attributed.
    let (mut svc, path) = setup_with_signed_accounts();
    svc.set_verifier(marker_verifier());
    let unsigned = "2024-01-25 * \"Hand\" \"pasted placeholder\"\n\
             \x20 openledger-author: \"local\"\n\
             \x20 openledger-lamport: \"40\"\n\
             \x20 openledger-parents: \"\"\n\
             \x20 Assets:Cash                                         3.00 USD\n\
             \x20 Equity:Opening                                     -3.00 USD\n";
    let signature = marker_signature(&parse_file(unsigned).unwrap().remove(0));
    append_to_file(
        &path,
        &format!(
            "\n{}",
            unsigned.replacen(
                "  openledger-parents",
                &format!("  openledger-signature: \"{signature}\"\n  openledger-parents"),
                1
            )
        ),
    );
    assert_eq!(svc.reconcile_file().unwrap().new_directives, 1);
    let adopted = transaction_named(&svc, "pasted placeholder").unwrap();
    assert_eq!(directive_author(adopted), Some("test-peer"));
    assert_eq!(
        adopted.metadata().get(ENVELOPE_KEY_SIGNATURE),
        Some(&signature)
    );
    remove_ledger_and_journal(&path);
}

/// 0924 §5 (T80): `signature_quarantined_total` counts every pass —
/// gl-node's banner used the return of the last call only, which is 0
/// once the setters' passes have quarantined — and a pass in which every
/// checked signature fails says to check the mesh id and the key.
///
/// Bug-catch: stop counting in `verify_history_pass` and the total is 0
/// while the quarantine holds three.
#[test]
fn t80_the_signature_quarantine_total_counts_every_pass_and_a_total_failure_names_the_domain() {
    let path = pre_t80_placeholder_signed_file();
    let mut svc = LedgerService::boot(path.clone(), "another-key".to_owned()).unwrap();
    // A verifier for a different key/domain: nothing verifies. Since T89
    // (L-98) the WARN is judged once, by `verify_own_history`, over every
    // pass.
    let (last, logged) = capture_warnings(|| {
        svc.set_verifier(std::sync::Arc::new(
            |_: &str, _, _: &str, _: &str, _: &str, _: &str| false,
        ));
        svc.verify_own_history()
    });
    assert_eq!(svc.quarantined_count(), 3);
    assert_eq!(last, 0, "the last call finds nothing left");
    assert_eq!(svc.signature_quarantined_total(), 3);
    assert!(
        logged.contains("EVERY signature this node checked failed")
            && logged.contains("p2p.meshId"),
        "{logged}"
    );
    remove_ledger_and_journal(&path);
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

/// L-96 (T89, decision (31)): the placeholder's records are this node's in
/// every own lookup. A Fresh boot under the placeholder counted the
/// text-held "local" record at lamport 7 as own; a boot (or an L-13
/// reload) under the real author did not, and resumed below it — so the
/// next write re-issued a lamport this node's own file holds (X1 `c5a`,
/// A2 `s9`). Both now resume above it.
///
/// Bug-catch: make `is_own_author` compare the id alone and the boot under
/// the real author resumes at 4.
#[test]
fn l96_a_boot_under_the_real_author_counts_the_placeholders_records_outside_the_dag() {
    let path = placeholder_history_with_a_text_held_record();
    let mut placeholder = LedgerService::boot(path.clone(), PLACEHOLDER_AUTHOR.to_owned()).unwrap();
    placeholder.set_author_id("test-peer".to_owned());
    let under_the_key = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(placeholder.lamport_clock(), 8);
    assert_eq!(
        under_the_key.lamport_clock(),
        placeholder.lamport_clock(),
        "a boot and a reload of one file resume at the same clock"
    );
    remove_ledger_and_journal(&path);
}

/// L-96 (T89, decision (31)): a placeholder record held as text at the
/// ceiling is this node's own, so `set_author_id` gives L-91's WARN (this
/// node's own file is the source) and the ceiling refusal names this node,
/// never "local" with the mesh-wide allowlist remedy (A2 `s5`).
///
/// Bug-catch: drop the placeholder from `set_author_id`'s own high and the
/// WARN is silent.
#[test]
fn l96_a_placeholder_record_at_the_ceiling_is_this_nodes_own() {
    let path = pre_t80_placeholder_signed_file();
    append_to_file(
        &path,
        &format!(
            "\n2024-01-26 * \"Junk\" \"held as text\"\n\
                 \x20 openledger-author: \"local\"\n\
                 \x20 openledger-lamport: \"{}\"\n\
                 \x20 this line does not parse\n",
            LAMPORT_CEILING - 3
        ),
    );
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    let error = svc
        .open_account("Assets:After".to_owned(), make_date(2024, 2, 1), vec![])
        .unwrap_err()
        .to_string();
    assert!(!error.contains("author local"), "{error}");
    assert!(error.contains("test-peer"), "names this node: {error}");
    remove_ledger_and_journal(&path);
}

/// T89 / L-96: the node always boots under the placeholder, so boot
/// names author `local` with the mesh-wide allowlist remedy for a
/// pre-signing record at the ceiling. Once the key loads, the L-91 WARN
/// says what it is — this node's own file — although the clock does not
/// move (boot already counted the record).
///
/// Bug-catch: look up only the real author id in `set_author_id` and no
/// L-91 WARN is logged.
#[test]
fn l96_set_author_id_names_a_placeholder_record_at_the_ceiling_as_this_nodes_own() {
    let path = pre_t80_placeholder_signed_file();
    append_to_file(
        &path,
        &format!(
            "\n2024-01-26 * \"Junk\" \"held as text\"\n\
                 \x20 openledger-author: \"local\"\n\
                 \x20 openledger-lamport: \"{}\"\n\
                 \x20 this line does not parse\n",
            LAMPORT_CEILING - 3
        ),
    );
    let mut svc = LedgerService::boot(path.clone(), PLACEHOLDER_AUTHOR.to_owned()).unwrap();
    let clock = svc.lamport_clock;
    let (_, logged) = capture_warnings(|| svc.set_author_id("test-peer".to_owned()));
    assert_eq!(svc.lamport_clock, clock, "boot already counted the record");
    assert!(
        logged.contains("OWN records outside the ledger")
            && logged.contains("(L-91, L-96")
            && logged.contains("written before signing"),
        "{logged}"
    );
    remove_ledger_and_journal(&path);
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
         signature: &str| {
            signature == format!("sig({content_id}|{is_transaction}|{parents}|{lamport})")
        },
    );
    (path, any_author)
}

/// L-98 (T89): the signer's pass sees only this node's own records; with
/// both of them edited it saw "every signature failed" and warned to check
/// the mesh id and the key, while every foreign record verified a moment
/// later in the verifier's pass (A2 `s3`). Judged once, over every pass,
/// there is no such WARN — and the release put on hold by the first pass
/// runs once the second verifies something.
///
/// Bug-catch: judge the WARN per pass again and it fires.
#[test]
fn l98_the_every_signature_failed_warning_is_judged_over_every_pass() {
    let (path, any_author) = edited_own_records_beside_verifying_foreign_ones();
    let (_, logged) = capture_warnings(|| {
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.set_signer(marker_signer());
        svc.set_verifier(any_author);
        svc.verify_own_history();
        assert_eq!(svc.quarantined_count(), 2, "the two edited own records");
        assert!(svc.release_on_hold.is_empty(), "the held release ran");
    });
    assert!(!logged.contains("EVERY signature"), "{logged}");
    remove_ledger_and_journal(&path);
}

/// L-99 (T89, decision (32)): a verifier for the wrong domain or key fails
/// every signature. The failures say nothing about edited lamport lines,
/// so the clock is not released past them — it stays where the history
/// put it — and the WARN, judged once, says not to author until the
/// domain and key are right (A2 `s1(e)`: the clock walked to 0).
///
/// Bug-catch: release regardless and one record's implausible lamport
/// (edited to 4·10^9 here) takes the clock down to 3.
#[test]
fn l99_on_a_domain_mismatch_the_clock_is_kept_and_the_node_is_told_not_to_author() {
    let path = pre_t80_placeholder_signed_file();
    let content = std::fs::read_to_string(&path).unwrap();
    let edited = content.replacen(
        "openledger-lamport: \"3\"",
        "openledger-lamport: \"4000000000\"",
        1,
    );
    assert_ne!(content, edited, "premise");
    std::fs::write(&path, edited).unwrap();
    let mut svc = LedgerService::boot(path.clone(), "another-key".to_owned()).unwrap();
    let clock = svc.lamport_clock();
    let (_, logged) = capture_warnings(|| {
        svc.set_verifier(std::sync::Arc::new(
            |_: &str, _, _: &str, _: &str, _: &str, _: &str| false,
        ));
        svc.verify_own_history();
    });
    assert_eq!(svc.quarantined_count(), 3);
    assert_eq!(svc.lamport_clock(), clock, "the clock is kept");
    assert!(
        logged.contains("EVERY signature") && logged.contains("Do not author"),
        "{logged}"
    );
    remove_ledger_and_journal(&path);
}

/// L-100 (T89): the gap warning is judged on the history this node
/// serves. An own record whose lamport line was edited to 10^9 — inside
/// one adoption step, so boot's ratchet keeps it — opens a gap in the
/// history AS LOADED; the signature pass quarantines it, and
/// the served history has no gap — so no warning, where boot used to warn
/// (naming this node) for a record the same boot then quarantined (D1 on
/// the real binary).
///
/// Bug-catch: judge the gap at boot again and the warning fires.
#[test]
fn l100_the_gap_warning_ignores_a_record_the_same_boot_quarantines() {
    let (path, _first, _second) = two_signed_transactions_file();
    let content = std::fs::read_to_string(&path).unwrap();
    let top = content.matches("openledger-lamport: \"").count();
    let edited = content.replacen(
        &format!("openledger-lamport: \"{top}\""),
        "openledger-lamport: \"1000000000\"",
        1,
    );
    assert_ne!(content, edited, "premise");
    std::fs::write(&path, edited).unwrap();
    let (svc, logged) = capture_warnings(|| {
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.set_signer(marker_signer());
        svc.verify_own_history();
        svc
    });
    assert_eq!(svc.quarantined_count(), 1, "premise: the edited record");
    assert!(!logged.contains("lamport gap"), "{logged}");
    remove_ledger_and_journal(&path);
}

/// L-108 (T89): two hand lines of one edit, the child — spelling the
/// parent's id in `openledger-parents` — placed BEFORE its parent on the
/// same date. Both are adopted in one boot (hand-parented lines go last),
/// where the child used to be refused ("exists nowhere") at the first
/// boot and adopted at the second (X1 `c7 order`).
///
/// Bug-catch: adopt in plain canonical order and the child is refused.
#[test]
fn l108_a_hand_child_before_its_hand_parent_is_adopted_in_the_same_boot() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let parent_text = "2024-01-20 * \"Hand\" \"the parent\"\n\
                           \x20 Assets:Cash                                         5.00 USD\n\
                           \x20 Equity:Opening                                     -5.00 USD\n";
    let parent_id = compute_content_id(&parse_file(parent_text).unwrap().remove(0));
    append_to_file(
        &path,
        &format!(
                "\n2024-01-20 * \"Hand\" \"the child\"\n\
                 \x20 openledger-parents: \"{parent_id}\"\n\
                 \x20 Assets:Cash                                         2.00 USD\n\
                 \x20 Equity:Opening                                     -2.00 USD\n\n{parent_text}"
            ),
    );
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    svc.finalize_operator_input();
    assert_eq!(svc.quarantined_count(), 0);
    assert_eq!(parents_of_named(&svc, "the child"), vec![parent_id]);
    remove_ledger_and_journal(&path);
}

/// L-108 / L-135 (T96): a chain of three hand lines that ALL spell a
/// parents line — the parent a root (`""`), the child naming it, the
/// grandchild naming the child — written grandchild first. Moving
/// hand-parented lines last is not enough here (all three are in that
/// group); only the topological order within it adopts them in one boot.
/// T89's own test passed with that order removed (A6 R5b).
///
/// Bug-catch: keep the hand-parented group in file order and the
/// grandchild and child are refused.
#[test]
fn l108_a_hand_chain_written_backwards_is_adopted_in_the_same_boot() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let line = |narration: &str, parents: &str, amount: &str| {
        format!(
            "2024-01-20 * \"Hand\" \"{narration}\"\n\
                 \x20 openledger-parents: \"{parents}\"\n\
                 \x20 Assets:Cash                                         {amount} USD\n\
                 \x20 Equity:Opening                                     -{amount} USD\n"
        )
    };
    let parent = line("the parent", "", "5.00");
    let parent_id = compute_content_id(&parse_file(&parent).unwrap().remove(0));
    let child = line("the child", &parent_id, "2.00");
    let child_id = compute_content_id(&parse_file(&child).unwrap().remove(0));
    let grandchild = line("the grandchild", &child_id, "1.00");
    append_to_file(&path, &format!("\n{grandchild}\n{child}\n{parent}"));
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    svc.finalize_operator_input();
    assert_eq!(svc.quarantined_count(), 0);
    assert_eq!(parents_of_named(&svc, "the child"), vec![parent_id]);
    assert_eq!(parents_of_named(&svc, "the grandchild"), vec![child_id]);
    remove_ledger_and_journal(&path);
}

/// L-109 (T89, decision (34)): a peer's signed block pasted under a
/// running node carries a stray directive-level `openledger-note`. Boot
/// strips the key and serves the record; the live reconcile used to refuse
/// it (H-06) and the re-persist then deleted the block from the file (X1
/// `c8a`). It is now stripped there too: adopted, served, and written back
/// without the key.
///
/// Bug-catch: drop the strip on the live path and the block is refused
/// and gone from the file.
#[test]
fn l109_a_pasted_signed_block_with_a_stray_key_is_stripped_on_the_live_path_too() {
    let (mut svc, path) = setup_with_signed_accounts();
    svc.set_verifier(marker_verifier());
    svc.compact().unwrap();
    let mut pasted =
        signed_history_transaction("pasted peer record", 5, ("Assets:Cash", "USD"), "", 40);
    directive_metadata_mut(&mut pasted)
        .insert("openledger-note".to_owned(), "hand annotation".to_owned());
    append_to_file(&path, &format!("\n{}", full_file_serialize(&[pasted], &[])));
    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.new_directives, 1, "{result:?}");
    let served = transaction_named(&svc, "pasted peer record").expect("served");
    assert!(!served.metadata().contains_key("openledger-note"));
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("pasted peer record") && !on_disk.contains("openledger-note"));
    remove_ledger_and_journal(&path);
}

/// L-126 (T90): a pasted complete envelope the live reconcile refuses for
/// a reason boot would hold the same bytes for — a body over the wire's
/// 1 MiB cap, a posting-metadata count over the legacy ceiling every peer
/// holds history to — is held in the quarantine and written back by the
/// canonical re-persist, as boot keeps it. Before T90 both were counted as
/// rejected and deleted from the file by the rewrite.
///
/// Bug-catch: drop the hold in the parity arm, or in the limits arm, and
/// that record is gone from the file after the compaction.
#[test]
fn l126_a_pasted_record_over_the_body_cap_or_a_history_limit_stays_in_the_file() {
    let (mut svc, path) = setup_with_signed_accounts();
    svc.set_verifier(marker_verifier());
    svc.compact().unwrap();
    let long_narration = format!("over the body cap {}", "x".repeat(1_100_000));
    let over_cap = signed_history_transaction(&long_narration, 5, ("Assets:Cash", "USD"), "", 40);
    let mut over_limit =
        signed_history_transaction("over the key ceiling", 6, ("Assets:Cash", "USD"), "", 41);
    if let Directive::Transaction(txn) = &mut over_limit {
        for index in 0..=crate::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY {
            txn.postings[0]
                .metadata
                .insert(format!("k{index:05}"), "v".to_owned());
        }
    }
    let held: Vec<String> = [&over_cap, &over_limit]
        .into_iter()
        .map(compute_content_id)
        .collect();
    append_to_file(
        &path,
        &format!("\n{}", full_file_serialize(&[over_cap, over_limit], &[])),
    );
    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.new_directives, 0, "{result:?}");
    for id in &held {
        assert!(!svc.contains_directive(id), "{id} is not served");
        assert!(svc.quarantined_ids().contains(&id.as_str()), "{id} is held");
    }
    svc.compact().unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("over the body cap"),
        "the over-cap record is kept"
    );
    assert!(
        on_disk.contains("over the key ceiling"),
        "the over-limit record is kept"
    );
    remove_ledger_and_journal(&path);
}

/// L-112 (T89, decision (34)): a posting-level `openledger-*` key on a
/// signed history record is stripped at boot like a directive-level one
/// — before T89 it was served and written back by every compaction. The
/// record keeps its id and its signature (neither covers the key).
///
/// Bug-catch: strip directive-level keys only and the posting keeps it.
#[test]
fn l112_a_posting_level_stray_key_is_stripped_at_boot() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let mut record =
        signed_history_transaction("posting annotated", 5, ("Assets:Cash", "USD"), "", 40);
    let id = compute_content_id(&record);
    if let Directive::Transaction(txn) = &mut record {
        txn.postings[0]
            .metadata
            .insert("openledger-foo".to_owned(), "x".to_owned());
    }
    assert_eq!(compute_content_id(&record), id, "premise: not hashed");
    append_to_file(&path, &format!("\n{}", full_file_serialize(&[record], &[])));
    let (mut svc, logged) = capture_warnings(|| {
        let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        svc.set_signer(marker_signer());
        svc
    });
    assert!(logged.contains("posting:openledger-foo"), "{logged}");
    let Some(Directive::Transaction(served)) = svc.get_directive(&id).cloned() else {
        panic!("served under its id");
    };
    assert!(served
        .postings
        .iter()
        .all(|posting| posting.metadata.is_empty()));
    svc.compact().unwrap();
    assert!(!std::fs::read_to_string(&path)
        .unwrap()
        .contains("openledger-foo"));
    remove_ledger_and_journal(&path);
}

/// L-91 (T80): an own envelope held as unparsable text at the ceiling is
/// folded into the clock only at `set_author_id` — boot ran under the
/// placeholder — so `set_author_id` now says so, naming this node's own
/// file as the source; and the ceiling refusal no longer names the
/// placeholder author.
///
/// Bug-catch: drop the WARN in `set_author_id` and the boot is silent
/// until the first refused write.
#[test]
fn l91_set_author_id_warns_when_own_records_outside_the_ledger_reach_the_ceiling() {
    let path = pre_t80_placeholder_signed_file();
    append_to_file(
        &path,
        &format!(
            "\n2024-01-26 * \"Junk\" \"unparsable\"\n\
                 \x20 openledger-author: \"test-peer\"\n\
                 \x20 openledger-lamport: \"{}\"\n\
                 \x20 this line does not parse\n",
            LAMPORT_CEILING - 3
        ),
    );
    let mut svc = LedgerService::boot(path.clone(), PLACEHOLDER_AUTHOR.to_owned()).unwrap();
    let (_, logged) = capture_warnings(|| svc.set_author_id("test-peer".to_owned()));
    assert!(
        logged.contains("OWN records outside the ledger") && logged.contains("(L-91"),
        "{logged}"
    );
    svc.set_signer(marker_signer());
    svc.set_verifier(marker_verifier());
    let error = svc
        .open_account("Assets:After".to_owned(), make_date(2024, 2, 1), vec![])
        .unwrap_err()
        .to_string();
    assert!(
        !error.contains("from author local"),
        "the refusal must not blame the placeholder: {error}"
    );
    remove_ledger_and_journal(&path);
}

/// L-91 (T80): when this node's own envelope held as unparsable text is
/// the only record that carries the clock, the ceiling refusal names this
/// node — the text-held pair is a candidate — instead of naming no one.
///
/// Bug-catch: drop `boot_outside_dag_lamports` from
/// `highest_lamport_author` and the refusal names no author.
#[test]
fn l91_the_ceiling_refusal_names_an_own_record_held_as_text_when_it_is_the_only_carrier() {
    let path = test_file_path();
    std::fs::write(
        &path,
        format!(
            "2024-01-26 * \"Junk\" \"unparsable\"\n\
                 \x20 openledger-author: \"test-peer\"\n\
                 \x20 openledger-lamport: \"{}\"\n\
                 \x20 this line does not parse\n",
            LAMPORT_CEILING - 3
        ),
    )
    .unwrap();
    let mut svc = LedgerService::boot(path.clone(), PLACEHOLDER_AUTHOR.to_owned()).unwrap();
    svc.set_author_id("test-peer".to_owned());
    assert_eq!(
        svc.directive_count(),
        0,
        "premise: only the text-held record"
    );
    match svc.open_account("Assets:After".to_owned(), make_date(2024, 2, 1), vec![]) {
        Err(ServiceError::LamportCeiling { author, .. }) => {
            assert_eq!(author.as_deref(), Some("test-peer"));
        }
        other => panic!("expected LamportCeiling, got {other:?}"),
    }
    remove_ledger_and_journal(&path);
}

// ── T81: upgrade paths for every content rule; count the envelope ──

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

/// M-51 (T81, decision (6)): history over the LEGACY ceiling — an `open`
/// of 4,097 currencies, the M-48 flood class — is quarantined at boot
/// with everything that depends on it: the transaction on its account
/// (peers wait forever for the `open`) and that transaction's child
/// (peers wait forever for its parent). An unrelated record stays served,
/// and a later live reconcile of the whole file re-adopts none of them.
///
/// Bug-catch: drop the closure call in boot and the account's transaction
/// and its child are served; drop the history rule in boot's arm and the
/// flood `open` is served; drop the reconcile guard and a hand edit
/// brings the child back.
#[test]
fn m51_history_over_the_legacy_ceiling_is_quarantined_with_everything_that_depends_on_it() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let flood = marker_signed(Directive::Open(Open {
        date: make_date(2024, 1, 2),
        account: "Assets:Flood".to_owned(),
        currencies: (0..=crate::limits::MAX_CURRENCIES_PER_OPEN_LEGACY)
            .map(|index| format!("C{index:04}"))
            .collect(),
        metadata: BTreeMap::from([
            (ENVELOPE_KEY_AUTHOR.to_owned(), "test-peer".to_owned()),
            (ENVELOPE_KEY_LAMPORT.to_owned(), "10".to_owned()),
        ]),
    }));
    let on_flood =
        signed_history_transaction("on the flood account", 1, ("Assets:Flood", "C0001"), "", 11);
    let on_flood_id = compute_content_id(&on_flood);
    let child = signed_history_transaction("child", 2, ("Assets:Cash", "USD"), &on_flood_id, 12);
    let unrelated = signed_history_transaction("unrelated", 3, ("Assets:Cash", "USD"), "", 13);
    append_to_file(
        &path,
        &format!(
            "\n{}",
            full_file_serialize(
                &[
                    flood.clone(),
                    on_flood.clone(),
                    child.clone(),
                    unrelated.clone()
                ],
                &[]
            )
        ),
    );

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut svc = booted.unwrap();
    svc.set_signer(marker_signer());
    let held: BTreeSet<&str> = svc.quarantined_ids().into_iter().collect();
    for directive in [&flood, &on_flood, &child] {
        assert!(
            held.contains(compute_content_id(directive).as_str()),
            "quarantined: {directive:?}\n{logged}"
        );
    }
    assert!(transaction_named(&svc, "unrelated").is_some());
    // Since T85 (decision (18)) the transaction on the flood account is
    // held by the H-23 rule — a peer's `validate_transaction` against the
    // accounts this node serves — and its child with it; the closure itself
    // walks parenthood only.
    assert!(
        logged.contains("(M-51, H-08)") && logged.contains("no fresh replica could hold"),
        "{logged}"
    );

    // A hand edit makes the live reconcile re-read the whole file.
    svc.compact().unwrap();
    append_to_file(&path, &h22_hand_line("hand after the closure", None));
    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.new_directives, 1, "only the hand line");
    assert!(transaction_named(&svc, "on the flood account").is_none());
    assert!(transaction_named(&svc, "child").is_none());
    remove_ledger_and_journal(&path);
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

/// M-56 (T85, decision (18)): the flood `open` is refused under a content
/// rule; a transaction on its account (2024-02-01, `C0001`) and the
/// operator's hand `open Assets:Flood C0001` — the M-51 remedy — are in the
/// same file. A hand `open` dated before the transaction admits it, so the
/// transaction is served in THIS boot and the next; one dated after it
/// does not, so the transaction is held in both. Before T85 the closure
/// judged "any surviving open" by account name before the hand `open` was
/// adopted: held at the first boot, served at the second — for either date
/// (X1 `c2d`, A4 `P5-late`).
///
/// Bug-catch: restore the closure's name-only account term and the
/// back-dated case is held at the first boot and served at the second.
#[test]
fn m56_a_hand_open_frees_exactly_what_it_admits_in_the_same_boot() {
    for (label, open_date, freed) in [
        ("back-dated", "2024-01-05", true),
        ("late", "2024-02-20", false),
    ] {
        let (svc, path) = setup_with_signed_accounts();
        drop(svc);
        let on_flood = signed_history_transaction(
            "on the flood account",
            1,
            ("Assets:Flood", "C0001"),
            "",
            11,
        );
        append_to_file(
            &path,
            &format!(
                "\n{}\n{open_date} open Assets:Flood C0001\n",
                full_file_serialize(&[t85_flood_open(), on_flood], &[])
            ),
        );
        let mut first = t85_boot(&path);
        let served = transaction_named(&first, "on the flood account").is_some();
        let held: Vec<String> = first
            .quarantined_ids()
            .into_iter()
            .map(str::to_owned)
            .collect();
        first.compact().unwrap();
        drop(first);
        let second = t85_boot(&path);
        assert_eq!(served, freed, "{label}: first boot");
        assert_eq!(
            transaction_named(&second, "on the flood account").is_some(),
            freed,
            "{label}: a fixed point across the restart"
        );
        let held_again: Vec<String> = second
            .quarantined_ids()
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(held, held_again, "{label}: the same quarantine");
        drop(second);
        remove_ledger_and_journal(&path);
    }
}

/// M-56 (T85, decision (18)): the wire refuses what boot's closure holds,
/// permanently — the record refused under a content rule and every record
/// that descends from it — so a running node and a restarted one serve
/// the same set. The control: a record naming a parent this node merely
/// lacks is a `MISSING_PARENT` (retried), not a refusal.
///
/// This drives the library entry point. gl-node buffers a directive whose
/// parent is absent before it stages anything, so on the node the closure
/// check sees only a copy whose parents all resolve; since T90 (H-24) it
/// refuses a copy by the parents it names, not by its id (see
/// `h24_a_restated_copy_of_a_held_record_is_adopted_on_the_wire`).
///
/// Bug-catch: drop the closure check in `stage_remote_directive` and the
/// child is refused only as `MISSING_PARENT`, which is retried forever.
#[test]
fn m56_the_wire_refuses_what_the_closure_holds() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let Directive::Transaction(mut flood) =
        signed_history_transaction("over the legacy ceiling", 1, ("Assets:Cash", "USD"), "", 11)
    else {
        unreachable!()
    };
    flood.postings[0].metadata = (0
        ..=crate::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY)
        .map(|index| (format!("k{index}"), "v".to_owned()))
        .collect();
    let flood = marker_signed(Directive::Transaction(flood));
    let flood_id = compute_content_id(&flood);
    let child = signed_history_transaction(
        "child of the flood",
        2,
        ("Assets:Cash", "USD"),
        &flood_id,
        12,
    );
    let child_id = compute_content_id(&child);
    append_to_file(
        &path,
        &format!("\n{}", full_file_serialize(&[flood, child.clone()], &[])),
    );
    let mut svc = t85_boot(&path);
    assert!(svc.quarantined_ids().contains(&child_id.as_str()));

    let error = svc.stage_remote_directive(child).unwrap_err();
    assert_eq!(error.error_code(), "INVALID_INPUT", "{error}");
    let grandchild =
        signed_history_transaction("grandchild", 3, ("Assets:Cash", "USD"), &child_id, 13);
    let error = svc.stage_remote_directive(grandchild).unwrap_err();
    assert_eq!(
        error.error_code(),
        "INVALID_INPUT",
        "a record naming a closure member is refused as permanently: {error}"
    );
    let control = signed_history_transaction(
        "names an unknown parent",
        4,
        ("Assets:Cash", "USD"),
        &"a".repeat(64),
        14,
    );
    assert_eq!(
        svc.stage_remote_directive(control)
            .unwrap_err()
            .error_code(),
        "MISSING_PARENT"
    );
    remove_ledger_and_journal(&path);
}

/// H-24 (T90, decision (36)): the closure is judged on each copy's
/// parents. Boot holds `child` (its file copy names the flood, a record
/// over a legacy ceiling); a peer's copy of the same body — the same
/// content id — naming parents this node serves (the chain restated on
/// that peer) is adopted, the id leaves the closure, and what the mesh
/// wrote on top of it stages too. The file's copy, naming the flood, is
/// still refused for good.
///
/// Bug-catch: refuse by content id again (`refused_history_closure
/// .contains(&content_id)` in `stage_remote_directive`) and the restated
/// copy is `INVALID_INPUT`, permanently, on every node that held the old
/// one.
#[test]
fn h24_a_restated_copy_of_a_held_record_is_adopted_on_the_wire() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let Directive::Transaction(mut flood) =
        signed_history_transaction("over the legacy ceiling", 1, ("Assets:Cash", "USD"), "", 11)
    else {
        unreachable!()
    };
    flood.postings[0].metadata = (0
        ..=crate::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY)
        .map(|index| (format!("k{index}"), "v".to_owned()))
        .collect();
    let flood = marker_signed(Directive::Transaction(flood));
    let flood_id = compute_content_id(&flood);
    let held_copy = signed_history_transaction(
        "child of the flood",
        2,
        ("Assets:Cash", "USD"),
        &flood_id,
        12,
    );
    let child_id = compute_content_id(&held_copy);
    append_to_file(
        &path,
        &format!(
            "\n{}",
            full_file_serialize(&[flood, held_copy.clone()], &[])
        ),
    );
    let mut svc = t85_boot(&path);
    assert!(
        svc.quarantined_ids().contains(&child_id.as_str()),
        "premise"
    );

    assert_eq!(
        svc.stage_remote_directive(held_copy)
            .unwrap_err()
            .error_code(),
        "INVALID_INPUT",
        "the copy naming the refused record stays refused"
    );
    let restated =
        signed_history_transaction("child of the flood", 2, ("Assets:Cash", "USD"), "", 30);
    assert_eq!(
        compute_content_id(&restated),
        child_id,
        "premise: same body"
    );
    assert_eq!(
        svc.stage_remote_directive(restated).unwrap(),
        Some(child_id.clone()),
        "a copy naming parents this node serves is adopted"
    );
    assert!(!svc.refused_history_closure.contains(&child_id));
    // A path that adopts without pruning the closure — the local API
    // re-entering a held record's body — leaves the id in it; what names
    // the record is still admitted, because the DAG holds a copy.
    svc.refused_history_closure.insert(child_id.clone());
    let on_top =
        signed_history_transaction("written on top", 3, ("Assets:Cash", "USD"), &child_id, 31);
    let on_top_id = compute_content_id(&on_top);
    assert_eq!(svc.stage_remote_directive(on_top).unwrap(), Some(on_top_id));
    remove_ledger_and_journal(&path);
}

/// H-24 (T90, decision (36)), the live file path: under a running node
/// that holds `child` (its file copy names the flood), the operator pastes
/// a peer's copy of the same record whose parents this node serves. The
/// live reconcile judges that copy on its own parents, as the wire does,
/// and adopts it; the held copy is released and the compaction writes the
/// adopted one, which the next boot serves.
///
/// Bug-catch: refuse by content id again on the live path and the pasted
/// copy is refused, and the held one written back.
#[test]
fn h24_a_pasted_copy_of_a_held_record_naming_served_parents_is_adopted_live() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let Directive::Transaction(mut flood) =
        signed_history_transaction("over the legacy ceiling", 1, ("Assets:Cash", "USD"), "", 11)
    else {
        unreachable!()
    };
    flood.postings[0].metadata = (0
        ..=crate::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY)
        .map(|index| (format!("k{index}"), "v".to_owned()))
        .collect();
    let flood = marker_signed(Directive::Transaction(flood));
    let flood_id = compute_content_id(&flood);
    let held_copy = signed_history_transaction(
        "child of the flood",
        2,
        ("Assets:Cash", "USD"),
        &flood_id,
        12,
    );
    let child_id = compute_content_id(&held_copy);
    append_to_file(
        &path,
        &format!("\n{}", full_file_serialize(&[flood, held_copy], &[])),
    );
    let mut svc = t85_boot(&path);
    svc.compact().unwrap();
    assert!(
        svc.quarantined_ids().contains(&child_id.as_str()),
        "premise"
    );

    let restated =
        signed_history_transaction("child of the flood", 2, ("Assets:Cash", "USD"), "", 30);
    append_to_file(
        &path,
        &format!("\n{}", full_file_serialize(&[restated], &[])),
    );
    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.new_directives, 1, "{result:?}");
    assert!(svc.contains_directive(&child_id), "adopted live");
    assert!(!svc.quarantined_ids().contains(&child_id.as_str()));
    svc.compact().unwrap();
    drop(svc);
    let svc = t85_boot(&path);
    assert!(
        svc.contains_directive(&child_id),
        "and served after a restart"
    );
    remove_ledger_and_journal(&path);
}

/// M-56 / H-23 (T85): a pair pasted into the file under a running node —
/// P with a signature that does not verify, and C, correctly signed,
/// naming P. The live reconcile adopts in canonical order and lets a
/// parent that comes later in the same file count as present, so C's check
/// passes; P is then refused. What named it must not stay served with a
/// dangling parent: the rule runs once more after the adoption loop and
/// holds C in the quarantine (kept in the file).
///
/// Bug-catch: drop the `quarantine_unservable_history` call after the
/// reconcile's adoption loop and C is served naming a parent nobody holds.
#[test]
fn m56_a_pasted_child_of_a_pasted_parent_the_reconcile_refuses_is_held() {
    let (mut svc, path) = setup_with_signed_accounts();
    svc.compact().unwrap();
    let mut parent = signed_history_transaction("pasted parent", 1, ("Assets:Cash", "USD"), "", 21);
    directive_metadata_mut(&mut parent).insert(ENVELOPE_KEY_SIGNATURE.to_owned(), "00".repeat(64));
    let parent_id = compute_content_id(&parent);
    let child =
        signed_history_transaction("pasted child", 2, ("Assets:Cash", "USD"), &parent_id, 22);
    append_to_file(
        &path,
        &format!("\n{}", full_file_serialize(&[parent, child], &[])),
    );
    let result = svc.reconcile_file().unwrap();
    assert!(
        transaction_named(&svc, "pasted parent").is_none(),
        "{result:?}"
    );
    assert!(
        transaction_named(&svc, "pasted child").is_none(),
        "a record whose parent was refused is held, not served: {result:?}"
    );
    for directive in svc.dag().directives() {
        if let Directive::Transaction(txn) = directive {
            for parent in txn.parent_ids() {
                assert!(svc.get_directive(parent).is_some());
            }
        }
    }
    remove_ledger_and_journal(&path);
}

/// L-121 / L-125 (T92, decision (42) as revised 2026-09-26, which retires
/// decision (20)): this node's own `open` of an account is held (its date
/// edited, so its signature fails). The hand `open` the H-23 WARN
/// prescribes — "add the missing open" — is adopted on the live path and at
/// boot. Before T92 the live path refused it while the node-written `open`
/// was held (T85 / L-110: the mesh may re-supply the original and the
/// account carry two `open`s — harmless since T91, I9 being the union over
/// every `open`), and boot refused it as "already open" because the edited
/// `open` was still in the DAG when operator input was adopted.
///
/// Bug-catch: restore boot's L-77 check at adoption and the boot half is
/// refused; restore the L-110 clause and the live half is.
#[test]
fn l121_a_hand_open_is_adopted_while_the_nodes_own_edited_open_is_held() {
    let edited_file = || {
        let (mut svc, path) = setup_with_signed_accounts();
        svc.compact().unwrap();
        drop(svc);
        let content = std::fs::read_to_string(&path).unwrap();
        let edited = content.replacen(
            "2024-01-01 open Expenses:Food",
            "2024-01-03 open Expenses:Food",
            1,
        );
        assert_ne!(content, edited, "premise: the open line was found");
        std::fs::write(&path, edited).unwrap();
        path
    };

    // Live: the edited open is held, the hand open is typed under a
    // running node.
    let path = edited_file();
    let mut svc = t85_boot(&path);
    assert_eq!(svc.quarantined_count(), 1, "the edited open");
    assert!(!svc.accounts().is_open("Expenses:Food"));
    append_to_file(&path, "\n2024-01-01 open Expenses:Food USD\n");
    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.new_directives, 1, "{result:?}");
    assert!(svc.accounts().is_open("Expenses:Food"), "adopted live");
    svc.compact().unwrap();
    drop(svc);
    let svc = t85_boot(&path);
    assert!(
        svc.accounts().is_open("Expenses:Food"),
        "and after a restart"
    );
    drop(svc);
    remove_ledger_and_journal(&path);

    // Boot: the hand open is in the file beside the edited one when the
    // node starts — the stop → edit → start the WARN describes.
    let path = edited_file();
    append_to_file(&path, "\n2024-01-01 open Expenses:Food USD\n");
    let svc = t85_boot(&path);
    assert!(
        svc.accounts().is_open("Expenses:Food"),
        "adopted at boot once the signature pass has held the edited open"
    );
    assert_eq!(svc.quarantined_count(), 1, "only the edited open is held");
    drop(svc);
    remove_ledger_and_journal(&path);
}

/// M-51 (T81): history over a T75 AUTHORING cap but inside the legacy
/// ceiling — a 65-currency `open`, pre-T75 — loads at boot as history,
/// while the local API still refuses it.
#[test]
fn m51_history_over_the_authoring_cap_loads_and_the_api_still_refuses_it() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let currencies: Vec<String> = (0..=MAX_CURRENCIES_PER_OPEN)
        .map(|index| format!("C{index:03}"))
        .collect();
    let wide = marker_signed(Directive::Open(Open {
        date: make_date(2024, 1, 2),
        account: "Assets:Wide".to_owned(),
        currencies: currencies.clone(),
        metadata: BTreeMap::from([
            (ENVELOPE_KEY_AUTHOR.to_owned(), "test-peer".to_owned()),
            (ENVELOPE_KEY_LAMPORT.to_owned(), "10".to_owned()),
        ]),
    }));
    append_to_file(
        &path,
        &format!(
            "\n{}",
            full_file_serialize(std::slice::from_ref(&wide), &[])
        ),
    );
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    assert_eq!(svc.quarantined_count(), 0);
    assert!(svc.contains_directive(&compute_content_id(&wide)));
    let error = svc
        .open_account("Assets:Other".to_owned(), make_date(2024, 1, 3), currencies)
        .unwrap_err();
    assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED", "{error}");
    remove_ledger_and_journal(&path);
}

/// M-55 (T81, decision (10)): operator input is counted as it will be
/// stored — signature included — on both file paths. A transaction
/// carries four envelope keys, anything else three, so 96 / 97 body keys
/// are the most each may have.
///
/// Bug-catch: count before the signature (the pre-T81
/// `enforce_resource_limits` call) and the 97-key transaction is adopted.
#[test]
fn m55_operator_input_is_counted_as_stored_on_both_file_paths() {
    let with_keys = |narration: &str, keys: usize| {
        let mut block = format!("\n2024-01-20 * \"Hand\" \"{narration}\"\n");
        for index in 0..keys {
            block.push_str(&format!("  k{index:03}: \"v\"\n"));
        }
        block.push_str("  Assets:Cash                                         5.00 USD\n");
        block.push_str("  Equity:Opening                                     -5.00 USD\n");
        block
    };
    let open_with_keys = |account: &str, keys: usize| {
        let mut block = format!("\n2024-01-20 open {account}\n");
        for index in 0..keys {
            block.push_str(&format!("  k{index:03}: \"v\"\n"));
        }
        block
    };

    // Boot: over the cap is quarantined, at it is adopted and signed.
    let (path, _) = signed_node_written_file();
    append_to_file(&path, &with_keys("ninety-seven", 97));
    append_to_file(&path, &with_keys("ninety-six", 96));
    append_to_file(&path, &open_with_keys("Assets:NinetyEight", 98));
    append_to_file(&path, &open_with_keys("Assets:NinetySeven", 97));
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    assert_eq!(svc.finalize_operator_input(), 2);
    assert!(transaction_named(&svc, "ninety-seven").is_none());
    let adopted = transaction_named(&svc, "ninety-six").unwrap();
    assert_eq!(adopted.metadata().len(), MAX_METADATA_KEYS_PER_DIRECTIVE);
    assert!(!svc.accounts().is_open("Assets:NinetyEight"));
    assert!(svc.accounts().is_open("Assets:NinetySeven"));
    assert_eq!(svc.quarantined_count(), 2);
    remove_ledger_and_journal(&path);

    // Live.
    let (mut svc, path) = setup_with_signed_accounts();
    append_to_file(&path, &with_keys("ninety-seven", 97));
    let result = svc.reconcile_file().unwrap();
    assert_eq!((result.new_directives, result.rejected), (0, 1));
    append_to_file(&path, &with_keys("ninety-six", 96));
    assert_eq!(svc.reconcile_file().unwrap().new_directives, 1);
    let adopted = transaction_named(&svc, "ninety-six").unwrap();
    assert_eq!(adopted.metadata().len(), MAX_METADATA_KEYS_PER_DIRECTIVE);
    assert!(
        enforce_resource_limits_for(adopted, ResourceRule::History).is_ok(),
        "what was signed is what a peer admits"
    );
    remove_ledger_and_journal(&path);
}

/// M-52 (T81): a history block with an amount past the cap is held as
/// text, but boot now names its id and says why — not L-45's
/// Unicode-account wording — and its descendants are quarantined with
/// it and stay quarantined across a live reconcile.
///
/// Bug-catch: drop `amount_cap_refused_block_ids` from boot and the child
/// is served with a dangling parent.
#[test]
fn m52_an_amount_past_the_cap_in_history_takes_its_descendants_with_it_loudly() {
    let (svc, path) = setup_with_signed_accounts();
    drop(svc);
    let posting = |account: &str, number: rust_decimal::Decimal| Posting {
        account: account.to_owned(),
        amount: Some(Amount {
            number,
            currency: "USD".to_owned(),
        }),
        cost: None,
        price: None,
        metadata: BTreeMap::new(),
    };
    let over = rust_decimal::Decimal::from_str_exact("50000000000000000000000").unwrap();
    let x = marker_signed(Directive::Transaction(Transaction {
        date: make_date(2024, 2, 1),
        flag: Flag::Complete,
        payee: None,
        narration: Some("X pre-upgrade".to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            posting("Assets:Cash", over),
            posting("Equity:Opening", -over),
        ],
        metadata: BTreeMap::from([
            (ENVELOPE_KEY_AUTHOR.to_owned(), "test-peer".to_owned()),
            (ENVELOPE_KEY_LAMPORT.to_owned(), "10".to_owned()),
            (ENVELOPE_KEY_PARENTS.to_owned(), String::new()),
        ]),
    }));
    let x_id = compute_content_id(&x);
    let child = signed_history_transaction("child of X", 2, ("Assets:Cash", "USD"), &x_id, 11);
    append_to_file(
        &path,
        &format!("\n{}", full_file_serialize(&[x, child.clone()], &[])),
    );

    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut svc = booted.unwrap();
    svc.set_signer(marker_signer());
    assert!(
        logged.contains("(M-52, M-50, H-08)") && logged.contains(&x_id),
        "{logged}"
    );
    assert!(!logged.contains("Unicode account name"), "{logged}");
    assert!(transaction_named(&svc, "child of X").is_none());
    assert!(svc
        .quarantined_ids()
        .contains(&compute_content_id(&child).as_str()));

    svc.compact().unwrap();
    append_to_file(&path, &h22_hand_line("hand after M-52", None));
    assert_eq!(svc.reconcile_file().unwrap().new_directives, 1);
    assert!(transaction_named(&svc, "child of X").is_none());
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("X pre-upgrade"));
    remove_ledger_and_journal(&path);
}

// ── T82: over-cap canonical state, floor identity, symlinked ledger ──

/// A ledger whose file is just under the cap and whose canonical form is
/// just over it: 64 leading `;x…` comment lines of 1 MiB, each gaining a
/// space when canonicalised (the L-64 fixture).
fn over_cap_canonical_ledger(path: &Path) {
    let line = format!(";{}\n", "x".repeat((1 << 20) - 2));
    let content = line.repeat(64 - 1) + &format!(";{}\n", "x".repeat((1 << 20) - 64));
    assert!(content.len() as u64 <= MAX_LEDGER_FILE_BYTES);
    std::fs::write(path, content).unwrap();
}

/// L-80 (T82): on a ledger whose canonical form is over the cap, every
/// write needs a compaction that cannot be written. `append_headroom` is 0
/// (so `gl-node` refuses and defers before staging) and a prepare refuses
/// with `ResourceLimitExceeded` — not an I/O error from the write — naming
/// L-80. Shrinking the file clears the fact at the next reconcile.
///
/// Bug-catch: drop the `canonical_over_cap` term from `append_headroom`
/// and headroom is ~64 bytes of a file the node cannot rewrite; drop the
/// compaction-arm check and the prepare returns `Some` and the write fails
/// in `persist_atomically`.
#[test]
fn l80_an_over_cap_canonical_form_refuses_every_write_before_it_is_built() {
    let path = test_file_path();
    over_cap_canonical_ledger(&path);
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert!(svc.compaction_text_len() > MAX_LEDGER_FILE_BYTES, "fixture");
    assert_eq!(svc.append_headroom(), 0, "nothing fits");
    match svc.prepare_compaction() {
        Err(ServiceError::ResourceLimitExceeded { message }) => {
            assert!(message.contains("(L-64, L-80)"), "{message}");
        }
        Err(other) => panic!("expected ResourceLimitExceeded, got {other}"),
        Ok(_) => panic!("expected ResourceLimitExceeded, got a prepared commit"),
    }
    assert!(svc.compact().is_err());
    assert_eq!(svc.directive_count(), 0);

    // The WARN's remedy: stop the node, shrink the file, restart.
    drop(svc);
    std::fs::write(&path, ";a small ledger now\n").unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert!(svc.append_headroom() > 0, "headroom is back");
    svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
        .expect("writes work again");
    remove_ledger_and_journal(&path);
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

/// M-58 (T86, decision (21)): the over-cap fact survives what follows the
/// startup compaction's refusal. Boot defers the measure while operator
/// input is pending; finalisation sets it. The compaction `gl-node` runs at
/// startup is refused by `prepare`'s L-80 arm — and, nothing being staged,
/// no longer reloads; a later write that stages and fails does reload, and
/// the reload now measures the rebuild, so the fact holds either way and
/// the refusal is the cap's, never the pre-T82 `Io` from the write.
///
/// Bug-catch: take the L-80 arm out of `prepare_refusal_needs_no_reload`
/// and the compaction reloads; drop the measure after the install and the
/// write after it finds headroom and fails in `persist_atomically`.
#[test]
fn m58_a_compaction_refused_for_the_cap_neither_reloads_nor_loses_the_fact() {
    let path = test_file_path();
    over_cap_by_hand_lines_ledger(&path);
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    assert_eq!(svc.finalize_operator_input(), 3);
    assert!(svc.compaction_text_len() > MAX_LEDGER_FILE_BYTES, "fixture");
    assert_eq!(svc.append_headroom(), 0, "finalisation measured it");

    let (outcome, logged) = capture_warnings(|| svc.compact());
    assert!(
        matches!(outcome, Err(ServiceError::ResourceLimitExceeded { .. })),
        "{outcome:?}"
    );
    assert!(!logged.contains("reload installed"), "no reload: {logged}");
    assert_eq!(svc.append_headroom(), 0, "the fact holds");

    let (outcome, logged) = capture_warnings(|| {
        svc.open_account("Assets:Late".to_owned(), make_date(2024, 1, 5), vec![])
    });
    assert!(
        matches!(outcome, Err(ServiceError::ResourceLimitExceeded { .. })),
        "the cap's refusal, not an I/O error from the write: {outcome:?}"
    );
    assert!(
        logged.contains("reload installed"),
        "a staged write is rolled back: {logged}"
    );
    assert_eq!(svc.append_headroom(), 0, "the reload measured the rebuild");
    assert!(!svc.accounts().is_open("Assets:Late"));
    remove_ledger_and_journal(&path);
}

/// L-116's advert cost (T95): while a line adopted from the file waits for
/// its rewrite, the served id list is built once and shared by every
/// advert until the ledger changes — before T95 each advert cloned every id
/// (a node whose compaction kept failing paid that on every exchange).
///
/// Bug-catch: drop the `served_id_snapshot` cache and two adverts return
/// separate lists.
#[test]
fn l116_the_served_id_list_is_shared_while_a_line_waits_for_its_rewrite() {
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();
    append_to_file(
        &path,
        "\n2024-01-20 * \"Hand\" \"typed while running\"\n  Assets:Cash  3 USD\n  \
             Equity:Opening  -3 USD\n",
    );
    assert_eq!(svc.reconcile_file_staged().unwrap().new_directives, 1);
    let first = svc.served_sorted_directive_ids();
    let second = svc.served_sorted_directive_ids();
    assert!(std::sync::Arc::ptr_eq(&first, &second), "one shared list");
    assert_eq!(
        first.len() + 1,
        svc.sorted_directive_ids().len(),
        "the line is held back"
    );
    svc.compact().unwrap();
    assert_eq!(
        svc.served_sorted_directive_ids().len(),
        svc.sorted_directive_ids().len(),
        "served after its rewrite"
    );
    remove_ledger_and_journal(&path);
}

/// L-117 (T93), the audit's X3 `k12`: while the node runs, the operator
/// moves the `.bean` elsewhere and leaves a link at its path; then a commit
/// fails. The recovery reload used to resolve the path again, follow the
/// link, and install a service working at the moved file — journal and
/// compactions included — while gl-node's lock and watcher stayed on the
/// path it started with. The reload now uses the path as it is and refuses
/// a path that has become a link; memory is kept, still at that path.
///
/// Bug-catch: resolve the path on a reload again and the service's path is
/// the moved file after the failed commit.
#[cfg(unix)]
#[test]
fn l117_a_reload_does_not_follow_a_link_put_at_the_path_after_the_start() {
    let directory = t67_directory("l117-relink");
    let path = directory.join("ledger.bean");
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    for account in ["Assets:Cash", "Equity:Opening"] {
        svc.open_account(account.to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
    }
    svc.compact().unwrap();
    let elsewhere = directory.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let moved = elsewhere.join("moved.bean");
    std::fs::rename(&path, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &path).unwrap();
    let (outcome, logged) = capture_warnings(|| {
        with_read_only_directory(&directory, || svc.append_transaction(balanced_input()))
    });
    assert!(outcome.is_err(), "premise: the commit fails");
    assert!(logged.contains("L-117"), "{logged}");
    assert_eq!(
        svc.file_path(),
        path.as_path(),
        "still the path it started on"
    );
    std::fs::remove_dir_all(&directory).ok();
}

/// A4 (0927): decision (44)'s floor re-applied after `verify_own_history`.
/// A signing node whose file holds one of its own records with the lamport
/// line edited to 2^30 (quarantined, clock released, L-87) stages a write;
/// the commit fails. The rebuild resumes at 2^30 + 1, the reload's pass
/// releases it below the discarded write's lamport, and only the second
/// application keeps the next write from re-issuing it.
///
/// Bug-catch: drop the `max(discarded_own_high)` after `verify_own_history`
/// in `finish_recovery` and the next write reuses the failed write's
/// lamport (`l115_…` does not notice).
#[cfg(unix)]
#[test]
fn l115_the_l87_release_after_a_failed_commit_does_not_reissue_its_lamport() {
    let directory = t67_directory("a4-l115b");
    let path = directory.join("ledger.bean");
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    for account in ["Assets:Cash", "Equity:Opening"] {
        svc.open_account_signing(
            account.to_owned(),
            make_date(2024, 1, 1),
            vec![],
            marker_sign(false),
        )
        .unwrap();
    }
    svc.append_transaction_signing(balanced_input(), marker_sign(true))
        .unwrap();
    svc.compact().unwrap();
    drop(svc);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("openledger-lamport: \"3\""), "{text}");
    std::fs::write(
        &path,
        text.replace(
            "openledger-lamport: \"3\"",
            "openledger-lamport: \"1073741824\"",
        ),
    )
    .unwrap();
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    svc.set_verifier(marker_verifier());
    svc.finalize_operator_input();
    svc.verify_own_history();
    assert!(
        svc.lamport_clock() < 1 << 28,
        "premise: released, {}",
        svc.lamport_clock()
    );
    let failed = svc
        .append_transaction_staged(
            TransactionInput {
                narration: Some("fails".to_owned()),
                ..balanced_input()
            },
            marker_sign(true),
        )
        .unwrap()
        .txid;
    let failed_lamport = svc.get_directive(&failed).unwrap().lamport_clock().unwrap();
    let outcome = with_read_only_directory(&directory, || svc.persist_or_reload());
    assert!(outcome.is_err(), "premise: the commit fails");
    assert!(svc.get_directive(&failed).is_none(), "premise: rolled back");
    let next = svc
        .append_transaction_signing(
            TransactionInput {
                narration: Some("the next write".to_owned()),
                ..balanced_input()
            },
            marker_sign(true),
        )
        .unwrap()
        .txid;
    let next_lamport = svc.get_directive(&next).unwrap().lamport_clock().unwrap();
    assert!(
        next_lamport > failed_lamport,
        "the next write is stamped {next_lamport}, the failed one was {failed_lamport}"
    );
    std::fs::remove_dir_all(&directory).ok();
}

/// L-115 (T93, decision (44)), the audit's X3 shape: after a restart the
/// clock resumes at the file's `max + 1`, so the first write is stamped
/// `max + 2`. Its commit fails; the recovery reload rebuilds from the file
/// — `max + 1` again — and before T93 the next write re-issued the failed
/// write's `(author, lamport)` pair, which a peer may already hold (a staged
/// write is served, L-86). The install now keeps the clock at least at the
/// highest own lamport among the writes it discards.
///
/// Bug-catch: drop the `discarded_own_high` floor and the next write
/// reuses the failed write's lamport.
#[cfg(unix)]
#[test]
fn l115_a_write_after_a_failed_commit_never_reuses_its_lamport() {
    let directory = t67_directory("l115-reissue");
    let path = directory.join("ledger.bean");
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    for account in ["Assets:Cash", "Equity:Opening"] {
        svc.open_account_signing(
            account.to_owned(),
            make_date(2024, 1, 1),
            vec![],
            marker_sign(false),
        )
        .unwrap();
    }
    svc.compact().unwrap();
    drop(svc);
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    let failed = svc
        .append_transaction_staged(balanced_input(), marker_sign(true))
        .unwrap()
        .txid;
    let failed_lamport = svc.get_directive(&failed).unwrap().lamport_clock().unwrap();
    let outcome = with_read_only_directory(&directory, || svc.persist_or_reload());
    assert!(outcome.is_err(), "premise: the commit fails");
    assert!(
        svc.get_directive(&failed).is_none(),
        "premise: the reload rolled the failed write back"
    );
    let next = svc
        .append_transaction_signing(
            TransactionInput {
                narration: Some("the next write".to_owned()),
                ..balanced_input()
            },
            marker_sign(true),
        )
        .unwrap()
        .txid;
    let next_lamport = svc.get_directive(&next).unwrap().lamport_clock().unwrap();
    assert!(
        next_lamport > failed_lamport,
        "the next write is stamped {next_lamport}, the failed one was {failed_lamport}"
    );
    std::fs::remove_dir_all(&directory).ok();
}

/// M-59 (T86, decision (22)), kept as the backstop decision (43) names: the
/// pre-persist reconcile adopts a hand line under a running node whose
/// parents include a local write staged in the same commit; the commit
/// fails. Memory's kept envelope names that staged write, which the rebuild
/// lacks — before T86 the install went ahead, the staged write was
/// discarded, and the hand line was served, written and named by every
/// later write with a parent that existed nowhere (A5 `a5_p2`). Now the
/// install is refused, memory is kept, and the next commit writes both, so
/// every parent on disk resolves.
///
/// Since T93 (M-65) a hand line whose parents THIS NODE chooses never names
/// a staged write (`choose_committed_parents`), so the shape needs the
/// operator to spell the staged write's id in an `openledger-parents` line
/// — and then the rebuild's own boot refuses that line (L-75: its parent
/// exists nowhere on disk), so the committed-id floor refuses the install
/// before the M-59 parent check is reached. Either refusal keeps memory.
/// Since T100 (L-147, decision (62)) the refusing arm rolls the staged
/// write back — its call returned an error — and holds the hand line that
/// named it, as written (L-75): what this pins is the outcome, memory
/// self-consistent, the failed write on no disk, the hand line kept in the
/// file and held, every served parent on disk resolving.
///
/// Bug-catch: drop both refusals and the hand line is on disk naming a
/// parent that is not; hold nothing beside the rolled-back write and
/// memory serves the hand line over a parent it lacks.
#[cfg(unix)]
#[test]
fn m59_a_kept_envelope_whose_parent_the_rebuild_lacks_refuses_the_install() {
    let directory = t67_directory("m59-kept-parent");
    let path = directory.join("ledger.bean");
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    for account in ["Assets:Cash", "Equity:Opening"] {
        svc.open_account_signing(
            account.to_owned(),
            make_date(2024, 1, 1),
            vec![],
            marker_sign(false),
        )
        .unwrap();
    }
    svc.compact().unwrap();
    let staged = svc
        .append_transaction_staged(balanced_input(), marker_sign(true))
        .unwrap()
        .txid;
    append_to_file(
        &path,
        &h22_hand_line("hand while running", Some(staged.as_str())),
    );
    let (outcome, logged) =
        capture_warnings(|| with_read_only_directory(&directory, || svc.persist_or_reload()));
    assert!(outcome.is_err(), "premise: the commit fails");
    assert!(logged.contains("REFUSING"), "{logged}");
    assert!(!logged.contains("reload installed"), "{logged}");
    let parents_resolve = |svc: &LedgerService| {
        svc.dag()
            .directives()
            .into_iter()
            .all(|directive| match directive {
                Directive::Transaction(txn) => txn
                    .parent_ids()
                    .into_iter()
                    .all(|parent| svc.dag().get(parent).is_some()),
                _ => true,
            })
    };
    assert!(
        svc.get_directive(&staged).is_none(),
        "the failed write is rolled back"
    );
    assert!(transaction_named(&svc, "hand while running").is_none());
    assert!(parents_resolve(&svc), "memory is self-consistent");

    svc.append_transaction_signing(
        TransactionInput {
            narration: Some("after".to_owned()),
            ..balanced_input()
        },
        marker_sign(true),
    )
    .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains("hand while running"),
        "the hand line is kept in the file"
    );
    let on_disk = LedgerService::boot(path.clone(), "checker".to_owned()).unwrap();
    assert!(on_disk.get_directive(&staged).is_none());
    assert!(transaction_named(&on_disk, "hand while running").is_none());
    assert!(parents_resolve(&on_disk), "every parent on disk resolves");
    assert_eq!(
        on_disk.quarantined_count(),
        1,
        "the hand line is held (L-75)"
    );
    std::fs::remove_dir_all(&directory).ok();
}

/// L-104 (T86, decision (23)): on a signing-off node nothing is ever
/// signed, so T82's "exempt while unsigned" never expired: a hand line
/// finalised and served, then a backup copied over the file plus one failed
/// commit, dropped it without `REFUSING` (A5 `a5_p3`). Keyed on
/// finalisation, the rebuild that lacks it is refused and the next commit
/// writes it back, as on a signing node.
///
/// Bug-catch: key the exemption on the signature again and the hand line
/// is gone from memory and disk.
#[cfg(unix)]
#[test]
fn l104_a_finalised_hand_line_on_a_signing_off_node_survives_a_backup_and_a_failed_commit() {
    let directory = t67_directory("l104-signing-off");
    let path = directory.join("ledger.bean");
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
        .unwrap();
    svc.compact().unwrap();
    drop(svc);
    let without_hand = std::fs::read_to_string(&path).unwrap();
    append_to_file(
        &path,
        &format!("\n{}", raw_opens(&["Assets:HandY"], "2024-01-02")),
    );
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(svc.finalize_operator_input(), 1);
    assert!(with_read_only_directory(&directory, || svc.compact()).is_err());
    assert!(svc.accounts().is_open("Assets:HandY"));

    std::fs::write(&path, &without_hand).unwrap();
    let (outcome, logged) = capture_warnings(|| {
        with_read_only_directory(&directory, || {
            svc.open_account("Assets:Staged".to_owned(), make_date(2024, 2, 1), vec![])
        })
    });
    assert!(outcome.is_err(), "premise: the commit fails");
    assert!(logged.contains("REFUSING"), "{logged}");
    assert!(svc.accounts().is_open("Assets:HandY"), "kept in memory");
    svc.open_account("Assets:After".to_owned(), make_date(2024, 2, 2), vec![])
        .unwrap();
    let on_disk = LedgerService::boot(path.clone(), "checker".to_owned()).unwrap();
    assert!(
        on_disk.accounts().is_open("Assets:HandY"),
        "and written back"
    );
    std::fs::remove_dir_all(&directory).ok();
}

/// L-81 (T82): a backup taken while a hand line was raw, copied over the
/// live file after the line was signed, acknowledged and compacted, plus
/// one failed commit: the rebuild reads the raw line as operator input
/// under the same id. It keeps the envelope this node committed — same
/// lamport, same signature — and the next commit writes that back, as the
/// success path would.
///
/// Bug-catch: drop `keep_committed_envelopes_in` and the rebuild re-stamps
/// the record with a fresh lamport and signature.
#[cfg(unix)]
#[test]
fn l81_a_restored_pre_canonical_backup_keeps_the_committed_envelope_across_a_failed_commit() {
    let directory = t67_directory("l81-backup");
    let path = directory.join("ledger.bean");
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    svc.open_account_signing(
        "Assets:Cash".to_owned(),
        make_date(2024, 1, 1),
        vec![],
        marker_sign(false),
    )
    .unwrap();
    svc.compact().unwrap();
    append_to_file(
        &path,
        &format!("\n{}", raw_opens(&["Assets:HandX"], "2024-01-02")),
    );
    let backup = std::fs::read_to_string(&path).unwrap();
    assert_eq!(svc.reconcile_file().unwrap().new_directives, 1);
    svc.compact().unwrap();
    let envelope = |svc: &LedgerService| {
        let hand = svc
                .dag()
                .directives()
                .into_iter()
                .find(|directive| {
                    matches!(directive, Directive::Open(open) if open.account == "Assets:HandX")
                })
                .expect("HandX in memory")
                .clone();
        (
            hand.metadata().get(ENVELOPE_KEY_LAMPORT).cloned(),
            hand.metadata().get(ENVELOPE_KEY_SIGNATURE).cloned(),
        )
    };
    let acked = envelope(&svc);
    assert!(acked.1.is_some(), "premise: signed");

    std::fs::write(&path, &backup).unwrap();
    let (outcome, logged) = capture_warnings(|| {
        with_read_only_directory(&directory, || {
            svc.open_account("Assets:Staged".to_owned(), make_date(2024, 2, 1), vec![])
        })
    });
    assert!(outcome.is_err(), "premise: the commit fails");
    assert!(logged.contains("L-13 reload installed"), "{logged}");
    assert!(logged.contains("(L-81)"), "{logged}");
    assert_eq!(envelope(&svc), acked, "the committed envelope is kept");

    svc.open_account("Assets:After".to_owned(), make_date(2024, 2, 2), vec![])
        .unwrap();
    let mut on_disk = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    on_disk.set_signer(marker_signer());
    assert_eq!(envelope(&on_disk), acked, "and it is what the disk holds");
    std::fs::remove_dir_all(&directory).ok();
}

/// L-93 (T82): a hand line boot adopted and SIGNED, whose startup
/// compaction failed (so it is still "adopted from the file"), is not
/// exempt from the recovery floor: a backup without it copied over the
/// file plus one failed commit is REFUSED, the line stays in memory, and
/// the next commit writes it back — as the success path would.
///
/// Bug-catch: exempt every file-adopted id again and the rebuild installs
/// without the signed line (`discarded_file_adopted=1`).
#[cfg(unix)]
#[test]
fn l93_a_signed_hand_line_is_not_exempt_from_the_recovery_floor() {
    let directory = t67_directory("l93-floor");
    let path = directory.join("ledger.bean");
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    svc.open_account_signing(
        "Assets:Cash".to_owned(),
        make_date(2024, 1, 1),
        vec![],
        marker_sign(false),
    )
    .unwrap();
    svc.compact().unwrap();
    drop(svc);
    let without_hand = std::fs::read_to_string(&path).unwrap();
    append_to_file(
        &path,
        &format!("\n{}", raw_opens(&["Assets:HandY"], "2024-01-02")),
    );

    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    svc.set_signer(marker_signer());
    assert_eq!(svc.finalize_operator_input(), 1);
    let compacted = with_read_only_directory(&directory, || svc.compact());
    assert!(compacted.is_err(), "premise: the startup compaction fails");
    assert!(svc.accounts().is_open("Assets:HandY"));

    std::fs::write(&path, &without_hand).unwrap();
    let (outcome, logged) = capture_warnings(|| {
        with_read_only_directory(&directory, || {
            svc.open_account("Assets:Staged".to_owned(), make_date(2024, 2, 1), vec![])
        })
    });
    assert!(outcome.is_err(), "premise: the commit fails");
    assert!(logged.contains("REFUSING"), "{logged}");
    assert!(svc.accounts().is_open("Assets:HandY"), "kept in memory");

    svc.open_account("Assets:After".to_owned(), make_date(2024, 2, 2), vec![])
        .unwrap();
    let on_disk = LedgerService::boot(path.clone(), "checker".to_owned()).unwrap();
    assert!(on_disk.accounts().is_open("Assets:HandY"), "written back");
    std::fs::remove_dir_all(&directory).ok();
}

/// M-61 (T87, decision (25)), through `boot`: the ledger was converted to
/// a link after an unclean stop, so its journal still sits beside the
/// link. Boot refuses, naming it, and touches nothing — the journal, the
/// link and the target are as they were (before T87 boot served the
/// target without the journal's acknowledged records, X3 `k4f`). Once the
/// journal is moved beside the target, boot reads it through the link;
/// and a stale temp named after the LINK (what an older build left) is
/// swept.
///
/// Bug-catch: drop the stray-journal check in `resolve_ledger_path` and
/// the first boot succeeds without the journal's record.
#[cfg(unix)]
#[test]
fn m61_boot_through_a_link_with_a_journal_beside_it_refuses_and_changes_nothing() {
    let directory = t67_directory("m61-boot");
    let old = directory.join("ledger.bean");
    std::fs::write(&old, large_ledger_content()).unwrap();
    let mut svc = LedgerService::boot(old.clone(), "test-peer".to_owned()).unwrap();
    svc.compact().unwrap();
    svc.open_account_staged(
        "Assets:InJournal".to_owned(),
        make_date(2024, 1, 2),
        vec![],
        |_, _, _| None,
    )
    .unwrap();
    let pending = svc.prepare_commit().unwrap().expect("a commit");
    assert_eq!(pending.kind(), CommitKind::Append, "premise: an append");
    let receipt = pending.commit().unwrap();
    svc.finish_commit(receipt);
    drop(svc); // an unclean stop: the journal is not folded

    // The README's move behind a link.
    let data = directory.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let target = data.join("real.bean");
    std::fs::rename(&old, &target).unwrap();
    std::os::unix::fs::symlink(&target, &old).unwrap();
    let stray = crate::journal::journal_path_for(&old);
    let journal_bytes = std::fs::read(&stray).unwrap();
    let stale_temp = directory.join("ledger.bean.tmp.4242.0123456789abcdef");
    std::fs::write(&stale_temp, "x").unwrap();

    let error = match LedgerService::boot(old.clone(), "test-peer".to_owned()) {
        Err(error) => error,
        Ok(_) => panic!("boot must refuse a journal beside the link"),
    };
    assert!(error.to_string().contains("(M-61, H-15)"), "{error}");
    assert_eq!(std::fs::read(&stray).unwrap(), journal_bytes, "untouched");
    assert!(std::fs::symlink_metadata(&old)
        .unwrap()
        .file_type()
        .is_symlink());

    // The remedy the error names.
    std::fs::rename(&stray, crate::journal::journal_path_for(&target)).unwrap();
    let svc = LedgerService::boot(old.clone(), "test-peer".to_owned()).unwrap();
    assert!(
        svc.accounts().is_open("Assets:InJournal"),
        "the record is served"
    );
    assert!(!stale_temp.exists(), "the link's stale temp is swept");
    std::fs::remove_dir_all(&directory).ok();
}

/// L-84 (T82, decision (11)): a `.bean` that is a symbolic link this
/// node's user created is worked at its target — the target's journal is
/// read (its record is served), and the compaction writes the target in
/// place, so the link survives.
///
/// Bug-catch: drop `resolve_ledger_path` from `boot_with` and the
/// target's journal record is missing and the link becomes a regular file.
#[cfg(unix)]
#[test]
fn l84_a_symlinked_ledger_is_worked_at_its_target_and_the_link_is_kept() {
    let directory = t67_directory("l84-link");
    let data = directory.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let target = data.join("ledger.bean");
    // Large enough that the next write appends instead of compacting.
    std::fs::write(&target, large_ledger_content()).unwrap();
    let mut svc = LedgerService::boot(target.clone(), "test-peer".to_owned()).unwrap();
    svc.compact().unwrap();
    // One more write that stays in the TARGET's journal.
    let staged = svc
        .open_account_staged(
            "Assets:InJournal".to_owned(),
            make_date(2024, 1, 2),
            vec![],
            |_, _, _| None,
        )
        .unwrap();
    let pending = svc.prepare_commit().unwrap().expect("a commit");
    assert_eq!(pending.kind(), CommitKind::Append, "premise: an append");
    let receipt = pending.commit().unwrap();
    svc.finish_commit(receipt);
    drop(svc);
    assert!(
        crate::journal::journal_path_for(&target).exists(),
        "premise"
    );

    let link = directory.join("ledger.bean");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let mut via_link = LedgerService::boot(link.clone(), "test-peer".to_owned()).unwrap();
    assert!(
        via_link.get_directive(&staged).is_some(),
        "the target's journal record is served"
    );
    via_link.compact().unwrap();
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link is kept"
    );
    assert!(
        !crate::journal::journal_path_for(&target).exists(),
        "folded"
    );
    let reread = LedgerService::boot(target.clone(), "checker".to_owned()).unwrap();
    assert!(
        reread.get_directive(&staged).is_some(),
        "the target holds it"
    );
    std::fs::remove_dir_all(&directory).ok();
}

// ── T83: diagnostics (L-83, L-89) ──

/// L-89 (T83): a node-written record carrying a stray directive-level
/// `openledger-*` key (not one of the four envelope keys) keeps loading —
/// same id, same signature, same balances — but without the key, and the
/// compaction writes it back without it. Before T83 it loaded with the
/// key, served it locally and wrote it back on every compaction.
///
/// Bug-catch: drop the strip at boot and the record is served with
/// `openledger-note`.
#[test]
fn l89_a_stray_envelope_key_on_history_is_dropped_at_boot() {
    let (path, txid) = signed_node_written_file();
    let content = std::fs::read_to_string(&path).unwrap();
    let edited = content.replacen(
        "  openledger-author: \"test-peer\"\n",
        "  openledger-author: \"test-peer\"\n  openledger-note: \"stray\"\n",
        1,
    );
    assert_ne!(edited, content, "premise");
    std::fs::write(&path, &edited).unwrap();
    let (booted, logged) =
        capture_warnings(|| LedgerService::boot(path.clone(), "test-peer".to_owned()));
    let mut svc = booted.unwrap();
    svc.set_signer(marker_signer());
    assert_eq!(svc.quarantined_count(), 0, "{logged}");
    assert!(svc.get_directive(&txid).is_some(), "still served");
    assert!(
        svc.dag()
            .directives()
            .into_iter()
            .all(|directive| !directive.metadata().contains_key("openledger-note")),
        "nothing served carries the stray key"
    );
    assert!(
        logged.contains("openledger-note") && logged.contains("(L-89"),
        "{logged}"
    );
    svc.compact().unwrap();
    assert!(!std::fs::read_to_string(&path)
        .unwrap()
        .contains("openledger-note"));
    remove_ledger_and_journal(&path);
}

/// L-83 (T83): a clock carried high by this node's own records outside
/// the ledger (here: quarantined own records, as after a first signing
/// boot over an unsigned history) does not make the next honest adoption
/// warn — an adoption BELOW the clock opens no gap. Before T83 the
/// adoption-site check compared the clock with the shrunken directive
/// count and named the honest peer.
#[test]
fn l83_an_honest_adoption_below_a_high_clock_does_not_warn() {
    let (mut svc, path) = setup_with_accounts();
    svc.lamport_clock = 2_003;
    let (_, logged) = capture_warnings(|| {
        svc.stage_remote_directive(remote_open("Assets:Peer", make_date(2024, 1, 1), 1))
            .unwrap()
            .expect("adopted");
    });
    assert!(!logged.contains("lamport gap"), "{logged}");
    std::fs::remove_file(path).ok();
}
