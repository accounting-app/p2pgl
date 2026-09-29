//! The Lamport clock: the ceiling, the ratchet, and the H-19 warnings and remedy texts.

use super::*;

// ── H-07 / T46, H-12 / T63: the Lamport ceiling as ONE rule ──────────

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
