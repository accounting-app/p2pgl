//! Resource limits, dates, body canonicalization, and the file path's parent cap.

use super::*;

// ── T41: MAX_PARENTS on the FILE path ────────────────────────────────

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

// ── L-02: the local path honours the wire size cap ───────────────────

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

    // The envelope keys at directive level are the normal case.
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
