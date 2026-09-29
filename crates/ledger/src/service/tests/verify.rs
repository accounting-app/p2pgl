//! The history checks: the signature pass (H-20) and the served-set rule (H-23).

use super::*;

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

// ── T73: boot verifies what it loads (H-20, M-47, L-74, L-75, L-76, L-77) ──

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
