//! Persistence: the file, the journal, the two-phase commit, file types, the canonical cap.

use super::*;

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

// ── T44: append-only persistence + off-runtime fsync ─────────────────

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

// ── T67: file-type discipline for every ledger-side open ─────────────

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

// ── T82: over-cap canonical state, floor identity, symlinked ledger ──

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
