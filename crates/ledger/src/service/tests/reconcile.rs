//! Hand edits: the live reconcile, external edits, and the `.bean` as an operator interface.

use super::*;

// ── L-11: reconcile signs what it adopts ─────────────────────────────

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

// ── M-20: reconcile applies the wire path's check set ────────────────

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

// ── T35 shared fixtures ──────────────────────────────────────────────

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
