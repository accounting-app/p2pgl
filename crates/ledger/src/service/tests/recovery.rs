//! Recovery after a failed commit: staging vs. persist, reloads, the recovery floor.

use super::*;

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

// ── T44b: a reload replaces the CONTENT, never the SERVICE ───────────

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

// ── T61 / T62: one file path; recovery never installs an emptier ledger ──

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

// ── T74: the recovery floor and the reload-failure arm (M-46, M-49) ──

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
