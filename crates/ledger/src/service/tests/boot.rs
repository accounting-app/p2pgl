//! Boot: loading the file, operator input, the placeholder author, diagnostics.

use super::*;

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
    let fixture = include_str!("../../../../../testfixtures/fixture-simple.bean");
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

// ── L-14: a crafted file must not make boot quadratic ────────────────

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

// ── T78: L-67, the placeholder boot author ───────────────────────────

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

// ── T79: operator input after verification (H-22, M-54, L-75) ──

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
