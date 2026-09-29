//! Refused history and its closure: every content rule's upgrade path (T81).

use super::*;

// ── T81: upgrade paths for every content rule; count the envelope ──

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
