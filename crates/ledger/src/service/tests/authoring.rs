//! This node's writes: open, close, append, their checks, and envelope stamping.

use super::*;

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

// ── L-27: the elided fill is hashed, so it must be deterministic ──────

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
