//! Account lifecycle: opens, closes and their order (T29 / M-09, T98).

use super::*;

// ── T29 / M-09: deterministic account lifecycle ──────────────────────

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
