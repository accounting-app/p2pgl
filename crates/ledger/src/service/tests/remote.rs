//! Directives from peers: convergence, parent choice, id views, and the join window.

use super::*;

// ── Full genesis flow ────────────────────────────────────────────────

#[test]
fn test_full_genesis_flow() {
    let (mut svc, path) = boot_empty();

    // Step 1: Open accounts.
    svc.open_account(
        "Assets:Cash".to_owned(),
        make_date(2024, 1, 1),
        vec!["USD".to_owned()],
    )
    .unwrap();
    svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
        .unwrap();
    assert_eq!(svc.directive_count(), 2);

    // Step 2: Genesis transaction.
    let txid = svc.append_transaction(balanced_input()).unwrap().txid;
    assert_eq!(svc.directive_count(), 3);
    assert_eq!(svc.head_count(), 1);

    // Step 3: Verify genesis has empty parents.
    if let Some(Directive::Transaction(txn)) = svc.get_directive(&txid) {
        assert!(txn.parent_ids().is_empty());
        assert_eq!(txn.author(), Some("test-peer"));
        assert_eq!(txn.lamport_clock(), Some(3)); // 2 opens + 1 txn
    }

    // Step 4: File was written.
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("open Assets:Cash"));
    assert!(content.contains("* \"Acme\" \"Funding\""));
    assert!(content.contains("openledger-author: \"test-peer\""));

    std::fs::remove_file(path).ok();
}

// ── H-16 / T64: bounded parent choice, per-author head bound ─────────

/// Manifest item 5 (T64 / H-16). `MAX_PARENTS + 1` parentless remote
/// transactions, then a local append: the append names at most
/// `MAX_PARENTS` parents (author-diverse, then smallest — T72 / L-68),
/// passes the fan-in check every peer applies, is accepted by a second
/// service, and survives a reboot — nothing quarantined, the victim's own
/// posting still in its balances.
#[test]
fn test_h16_parentless_flood_cannot_make_a_local_append_over_cap() {
    let (mut svc, path) = setup_with_accounts();
    let flood = stage_parentless_flood(&mut svc);
    let mut heads: Vec<String> = svc.head_txids().into_iter().collect();
    heads.sort();

    let outcome = svc.append_transaction(balanced_input()).unwrap();
    let appended = svc.get_directive(&outcome.txid).unwrap().clone();
    let Directive::Transaction(transaction) = &appended else {
        panic!("an append stores a transaction")
    };
    validate_parent_fan_in(&appended).expect("every peer's fan-in check passes");
    let parents: Vec<String> = transaction
        .parent_ids()
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(parents.len(), MAX_PARENTS);
    assert!(
        parents.windows(2).all(|pair| pair[0] < pair[1]),
        "sorted ascending"
    );
    assert!(
        parents.iter().all(|parent| heads.contains(parent)),
        "every parent is a head"
    );
    // T72 / L-68: the one head left over is one of peer-a's 256, never
    // peer-b's single head — author diversity before smallest id.
    let peer_b_head = LedgerService::content_id(flood.last().unwrap());
    assert!(
        parents.contains(&peer_b_head),
        "the other author's head is named"
    );
    assert_eq!(
        svc.head_count(),
        2,
        "the appended one plus the one left over"
    );
    svc.persist_or_reload().unwrap();

    // A second service holding the same history accepts it.
    let (mut peer, peer_path) = setup_with_accounts();
    for directive in &flood {
        peer.stage_remote_directive(directive.clone()).unwrap();
    }
    peer.stage_remote_directive(appended)
        .unwrap()
        .expect("the peer accepts the victim's append");

    // Reboot quarantines nothing, and the victim's own posting stays.
    drop(svc);
    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.quarantined_count(), 0);
    assert!(rebooted.get_directive(&outcome.txid).is_some());
    assert_eq!(rebooted.head_count(), 2);

    // The leftover head is merged by the next append.
    let mut rebooted = rebooted;
    let mut input = balanced_input();
    input.date = make_date(2024, 1, 17);
    rebooted.append_transaction(input).unwrap();
    assert_eq!(rebooted.head_count(), 1);

    std::fs::remove_file(path).ok();
    std::fs::remove_file(peer_path).ok();
}

/// T72 / H-21 (decision (2)): there is NO remote per-author head bound. The
/// 257th parentless remote transaction from one author is admitted like the
/// first, whatever order the flood arrives in, so two replicas served
/// disjoint subsets hold the same DAG — and the local append still names
/// at most `MAX_PARENTS` parents, passes every peer's fan-in check and is
/// accepted by a peer. T64's bound refused the 257th here
/// (`UNMERGED_HEAD_LIMIT`), which made membership depend on which 256 a
/// peer chose to serve first.
#[test]
fn test_h21_the_257th_parentless_remote_transaction_from_one_author_is_admitted() {
    let (mut svc, path) = setup_with_accounts();
    let flood: Vec<Directive> = (0..=MAX_PARENTS)
        .map(|index| flood_transaction("peer-a", index, ""))
        .collect();
    let clock = svc.lamport_clock();
    for (index, directive) in flood.iter().enumerate() {
        svc.stage_remote_directive(directive.clone())
            .unwrap_or_else(|error| panic!("head #{}: {error}", index + 1))
            .unwrap_or_else(|| panic!("head #{} is new", index + 1));
    }
    assert_eq!(svc.head_count(), MAX_PARENTS + 1);
    assert!(svc.lamport_clock() > clock, "adoption moved the clock");

    // The same flood in the opposite order on a second service: identical
    // membership, no local authoring — the H-21 property, single-process.
    let (mut peer, peer_path) = setup_with_accounts();
    for directive in flood.iter().rev() {
        peer.stage_remote_directive(directive.clone())
            .unwrap()
            .expect("admitted in any order");
    }
    assert_eq!(
        svc.all_directive_ids(),
        peer.all_directive_ids(),
        "same available set, same DAG"
    );

    // The local half of H-16 still holds without the remote bound.
    let outcome = svc.append_transaction(balanced_input()).unwrap();
    let appended = svc.get_directive(&outcome.txid).unwrap().clone();
    validate_parent_fan_in(&appended).expect("every peer's fan-in check passes");
    let Directive::Transaction(transaction) = &appended else {
        panic!("an append stores a transaction")
    };
    assert_eq!(transaction.parent_ids().len(), MAX_PARENTS);
    peer.stage_remote_directive(appended)
        .unwrap()
        .expect("the peer accepts the victim's append");
    assert_eq!(peer.head_count(), 2, "the append plus the one left over");

    std::fs::remove_file(path).ok();
    std::fs::remove_file(peer_path).ok();
}

/// T72 / L-68: 256 planted heads whose ids are all smaller than one honest
/// head — the id-grinder's shape — and the local append still names the
/// honest head. Under T64's smallest-id rule the honest head was never
/// named, so every honest append became a permanent head mesh-wide. Also
/// pins determinism: a second service holding the same heads, delivered in
/// the opposite order, names the same parents.
#[test]
fn test_l68_parent_choice_names_the_honest_head_among_256_planted_small_ids() {
    let (mut svc, path) = setup_with_accounts();
    // Grind: of 600 candidate bodies keep the MAX_PARENTS smallest ids.
    let mut ground: Vec<(String, Directive)> = (0..600)
        .map(|index| {
            let directive = flood_transaction("grinder", index, "");
            (LedgerService::content_id(&directive), directive)
        })
        .collect();
    ground.sort_by(|a, b| a.0.cmp(&b.0));
    ground.truncate(MAX_PARENTS);
    let largest_planted = ground.last().unwrap().0.clone();
    let honest = (1_000..)
        .map(|index| flood_transaction("honest", index, ""))
        .find(|directive| LedgerService::content_id(directive) > largest_planted)
        .expect("an honest body with an id above every planted one");
    let honest_id = LedgerService::content_id(&honest);
    let mut heads: Vec<Directive> = ground.into_iter().map(|(_, d)| d).collect();
    heads.push(honest);
    for directive in &heads {
        svc.stage_remote_directive(directive.clone())
            .unwrap()
            .expect("planted");
    }
    assert_eq!(svc.head_count(), MAX_PARENTS + 1);

    let outcome = svc.append_transaction(balanced_input()).unwrap();
    let Some(Directive::Transaction(appended)) = svc.get_directive(&outcome.txid) else {
        panic!("an append stores a transaction")
    };
    let parents: Vec<&str> = appended.parent_ids();
    assert_eq!(parents.len(), MAX_PARENTS);
    assert!(
        parents.contains(&honest_id.as_str()),
        "the honest head is named although every planted id is smaller"
    );
    assert!(
        parents
            .iter()
            .all(|parent| *parent < honest_id.as_str() || *parent == honest_id),
        "the slots not owed to diversity go to the smallest ids"
    );

    // Determinism across replicas: same heads, opposite delivery order,
    // same parents.
    let (mut peer, peer_path) = setup_with_accounts();
    for directive in heads.iter().rev() {
        peer.stage_remote_directive(directive.clone())
            .unwrap()
            .expect("planted");
    }
    let peer_outcome = peer.append_transaction(balanced_input()).unwrap();
    let Some(Directive::Transaction(peer_appended)) = peer.get_directive(&peer_outcome.txid) else {
        panic!("an append stores a transaction")
    };
    assert_eq!(peer_appended.parent_ids(), parents);

    std::fs::remove_file(path).ok();
    std::fs::remove_file(peer_path).ok();
}

/// T72 / L-68: `select_parents` alone — the rule on synthetic head sets.
#[test]
fn test_l68_select_parents_is_author_diverse_then_smallest_and_deterministic() {
    let id = |n: usize| format!("{n:064x}");
    // Fits: everything, sorted, whatever the order given.
    let few: Vec<String> = (0..5).rev().map(id).collect();
    let mut candidates: Vec<(&str, Option<&str>)> =
        few.iter().map(|s| (s.as_str(), Some("a"))).collect();
    let chosen = select_parents(&mut candidates);
    assert_eq!(chosen.len(), 5);
    assert!(chosen.windows(2).all(|pair| pair[0] < pair[1]));

    // One grinder with 300 small ids, one honest author with the largest.
    let ids: Vec<String> = (0..301).map(id).collect();
    let mut candidates: Vec<(&str, Option<&str>)> = ids[..300]
        .iter()
        .map(|s| (s.as_str(), Some("grinder")))
        .collect();
    candidates.push((ids[300].as_str(), Some("honest")));
    let chosen = select_parents(&mut candidates);
    assert_eq!(chosen.len(), MAX_PARENTS);
    assert!(
        chosen.contains(&ids[300].as_str()),
        "the honest head is named"
    );
    assert_eq!(
        chosen.iter().filter(|c| **c != ids[300].as_str()).count(),
        MAX_PARENTS - 1,
        "the grinder gets every other slot, smallest first"
    );
    assert_eq!(
        chosen[..MAX_PARENTS - 1].to_vec(),
        ids[..MAX_PARENTS - 1]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );

    // Three authors: A floods, B has two, C one, all of B's and C's named.
    let mut candidates: Vec<(&str, Option<&str>)> = ids[3..300]
        .iter()
        .map(|s| (s.as_str(), Some("A")))
        .collect();
    candidates.push((ids[300].as_str(), Some("B")));
    candidates.push((ids[2].as_str(), Some("B")));
    candidates.push((ids[1].as_str(), None));
    let chosen = select_parents(&mut candidates);
    assert_eq!(chosen.len(), MAX_PARENTS);
    for must in [&ids[300], &ids[2], &ids[1]] {
        assert!(chosen.contains(&must.as_str()), "{must} is named");
    }

    // More authors than slots: one head each, the smallest ids win.
    let mut candidates: Vec<(&str, Option<&str>)> =
        ids.iter().map(|s| (s.as_str(), Some(s.as_str()))).collect();
    let chosen = select_parents(&mut candidates);
    assert_eq!(
        chosen,
        ids[..MAX_PARENTS]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );

    // Deterministic: shuffled input, same answer.
    let mut shuffled: Vec<(&str, Option<&str>)> = ids[..300]
        .iter()
        .rev()
        .map(|s| (s.as_str(), Some("grinder")))
        .collect();
    shuffled.insert(7, (ids[300].as_str(), Some("honest")));
    let mut ordered: Vec<(&str, Option<&str>)> = ids[..300]
        .iter()
        .map(|s| (s.as_str(), Some("grinder")))
        .collect();
    ordered.push((ids[300].as_str(), Some("honest")));
    assert_eq!(select_parents(&mut shuffled), select_parents(&mut ordered));
}

/// T64: the file path's parent stamp (reconcile, and boot's operator input)
/// shares `choose_parents`, so a hand-typed transaction on a flooded ledger
/// is capped too — it is signed and served like a local append.
#[test]
fn test_h16_file_adoption_caps_stamped_parents() {
    let (mut svc, path) = setup_with_accounts();
    stage_parentless_flood(&mut svc);
    svc.persist_or_reload().unwrap();

    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str(
        "\n2024-01-20 * \"hand typed\"\n  Assets:Cash  2 USD\n  Equity:Opening  -2 USD\n",
    );
    std::fs::write(&path, text).unwrap();
    let result = svc.reconcile_file().unwrap();
    assert_eq!(result.new_directives, 1);

    let adopted = svc
        .dag()
        .directives()
        .into_iter()
        .find(|directive| {
            matches!(directive, Directive::Transaction(transaction)
                    if transaction.narration.as_deref() == Some("hand typed"))
        })
        .unwrap()
        .clone();
    validate_parent_fan_in(&adopted).expect("capped at MAX_PARENTS");
    let Directive::Transaction(transaction) = &adopted else {
        unreachable!()
    };
    assert_eq!(transaction.parent_ids().len(), MAX_PARENTS);

    drop(svc);
    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.quarantined_count(), 0);
    std::fs::remove_file(path).ok();
}

/// H-19: the join window. A node that holds none of its own records opens
/// it, and while it is open the join peer's directives are adopted past the
/// adoption ratchet — a history with a lamport gap no dense climb crosses —
/// while any other peer's are still ratcheted and the ceiling still applies.
/// Closed, the join peer is any peer again; and a node that has written does
/// not open it.
///
/// Bug-catch: ignore `RemoteSource` in `stage_remote_directive_from` and the
/// join peer's directive past the gap is refused.
#[test]
fn h19_the_join_window_lifts_the_ratchet_for_the_join_peer_only() {
    let date = make_date(2024, 1, 1);
    let (mut svc, path) = boot_empty();
    assert!(
        svc.open_join_trust(),
        "a node with no records of its own opens it"
    );
    let far = MAX_LAMPORT_ADVANCE + 10;
    let error = svc
        .stage_remote_directive_from(remote_open("Assets:Other", date, far), RemoteSource::Peer)
        .unwrap_err();
    assert_eq!(
        error.error_code(),
        "LAMPORT_ADVANCE",
        "any other peer is ratcheted"
    );
    svc.stage_remote_directive_from(
        remote_open("Assets:Joined", date, far),
        RemoteSource::JoinPeer,
    )
    .expect("the join peer's history is adopted past the gap");
    assert_eq!(svc.lamport_clock(), far + 1);
    let error = svc
        .stage_remote_directive_from(
            remote_open("Assets:Ceiling", date, LAMPORT_CEILING),
            RemoteSource::JoinPeer,
        )
        .unwrap_err();
    assert_eq!(
        error.error_code(),
        "LAMPORT_CEILING",
        "the ceiling still applies"
    );

    svc.close_join_trust();
    assert!(!svc.join_trust_open());
    let error = svc
        .stage_remote_directive_from(
            remote_open("Assets:Later", date, far + 1 + MAX_LAMPORT_ADVANCE),
            RemoteSource::JoinPeer,
        )
        .unwrap_err();
    assert_eq!(
        error.error_code(),
        "LAMPORT_ADVANCE",
        "closed: the join peer is any peer"
    );
    remove_ledger_and_journal(&path);

    let (mut written, path) = setup_with_accounts();
    assert!(
        !written.open_join_trust(),
        "a node that holds its own records is not joining"
    );
    remove_ledger_and_journal(&path);
}

// ── CT-9: simulated partition-and-converge (FR-4) ────────────────────

#[test]
fn ct9_two_nodes_converge_after_partition() {
    // Simulate two nodes at the library level:
    // - Both boot from the same initial .bean content (shared opens).
    // - During "partition", each appends a different transaction.
    // - On "reconnect", they exchange directives via reconcile_file.
    // - After convergence, both have the same content ID set and
    //   matching trial balances — proving CRDT convergence (I6/FR-4).
    //
    // R-11 / M-24: the fixture carries a TIED PAIR — two same-day
    // "Starbucks" / "Coffee" transactions that differ only in amount, so
    // §3.3.2's (date, type priority, narration|payee) key cannot order
    // them. Each node authors one, so each inserts its own first and the
    // other's second: the pair reaches the two DAGs in OPPOSITE orders.
    // Without M-24's content-id tie-break the serializer fell back to
    // insertion order and the two `.bean` files differed; the original
    // fixture had no ties, which is why this test never caught it.

    let path_a = test_file_path();
    let path_b = test_file_path();

    // Shared initial state — both boot from identical file content.
    let shared_content = "2024-01-01 open Assets:Cash USD\n  openledger-author: \"shared\"\n  openledger-lamport: \"1\"\n\n2024-01-01 open Equity:Opening\n  openledger-author: \"shared\"\n  openledger-lamport: \"2\"\n";

    std::fs::write(&path_a, shared_content).unwrap();
    std::fs::write(&path_b, shared_content).unwrap();

    let mut node_a = LedgerService::boot(path_a.clone(), "node-a".to_owned()).unwrap();
    let mut node_b = LedgerService::boot(path_b.clone(), "node-b".to_owned()).unwrap();

    assert_eq!(node_a.directive_count(), 2);
    assert_eq!(node_b.directive_count(), 2);

    // ── Partition: each node writes independently ────────────────

    let input_alpha = TransactionInput {
        date: make_date(2024, 2, 1),
        flag: Flag::Complete,
        payee: Some("Vendor-A".to_owned()),
        narration: Some("Alpha transaction".to_owned()),
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
    let txid_alpha = node_a.append_transaction(input_alpha).unwrap().txid;

    // One half of the tied pair on each side of the partition (R-11).
    let coffee = |amount: rust_decimal::Decimal| TransactionInput {
        date: make_date(2024, 2, 10),
        flag: Flag::Complete,
        payee: Some("Starbucks".to_owned()),
        narration: Some("Coffee".to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            PostingInput {
                account: "Assets:Cash".to_owned(),
                amount: Some(Amount {
                    number: -amount,
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
            PostingInput {
                account: "Equity:Opening".to_owned(),
                amount: Some(Amount {
                    number: amount,
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
        ],
    };
    let txid_tie_a = node_a.append_transaction(coffee(dec!(3.50))).unwrap().txid;

    let input_beta = TransactionInput {
        date: make_date(2024, 2, 15),
        flag: Flag::Complete,
        payee: Some("Vendor-B".to_owned()),
        narration: Some("Beta transaction".to_owned()),
        tags: vec![],
        links: vec![],
        postings: vec![
            PostingInput {
                account: "Assets:Cash".to_owned(),
                amount: Some(Amount {
                    number: dec!(200),
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
            PostingInput {
                account: "Equity:Opening".to_owned(),
                amount: Some(Amount {
                    number: dec!(-200),
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            },
        ],
    };
    let txid_beta = node_b.append_transaction(input_beta).unwrap().txid;
    let txid_tie_b = node_b.append_transaction(coffee(dec!(4.75))).unwrap().txid;
    assert_ne!(txid_tie_a, txid_tie_b, "the tied pair is two directives");

    // Verify divergence.
    assert_eq!(node_a.directive_count(), 4);
    assert_eq!(node_b.directive_count(), 4);
    assert!(node_a.get_directive(&txid_alpha).is_some());
    assert!(node_a.get_directive(&txid_beta).is_none());
    assert!(node_b.get_directive(&txid_beta).is_some());
    assert!(node_b.get_directive(&txid_alpha).is_none());

    // ── Reconnect: exchange directives via file merge ────────────

    let a_content = std::fs::read_to_string(&path_a).unwrap();
    let b_content = std::fs::read_to_string(&path_b).unwrap();

    // Append A's content into B's file.
    let merged_for_b = format!("{b_content}\n{a_content}");
    std::fs::write(&path_b, &merged_for_b).unwrap();
    let result_b = node_b.reconcile_file().unwrap();
    assert!(result_b.new_directives >= 1, "B should adopt Alpha");

    // Write B's canonical output to A's file.
    let b_final = std::fs::read_to_string(&path_b).unwrap();
    std::fs::write(&path_a, &b_final).unwrap();
    let result_a = node_a.reconcile_file().unwrap();
    assert!(result_a.new_directives >= 1, "A should adopt Beta");

    // ── Verify convergence ───────────────────────────────────────

    // Both nodes should have the same directive count.
    assert_eq!(
        node_a.directive_count(),
        node_b.directive_count(),
        "CT-9: After convergence, directive counts must match"
    );

    // Both should have both transactions.
    assert!(node_a.get_directive(&txid_alpha).is_some(), "A has Alpha");
    assert!(node_a.get_directive(&txid_beta).is_some(), "A has Beta");
    assert!(node_b.get_directive(&txid_alpha).is_some(), "B has Alpha");
    assert!(node_b.get_directive(&txid_beta).is_some(), "B has Beta");

    // The fixture really does exercise the tie: both nodes hold both
    // halves, in opposite insertion orders (R-11).
    let arrival = |node: &LedgerService, id: &str| {
        node.dag()
            .content_ids()
            .iter()
            .position(|candidate| *candidate == id)
            .expect("both halves of the tied pair must be present on both nodes")
    };
    assert!(
        arrival(&node_a, &txid_tie_a) < arrival(&node_a, &txid_tie_b),
        "A must hold its own coffee first"
    );
    assert!(
        arrival(&node_b, &txid_tie_b) < arrival(&node_b, &txid_tie_a),
        "B must hold its own coffee first"
    );

    // Content ID sets should be identical.
    let mut ids_a: Vec<&str> = node_a.dag().content_ids().into_iter().collect();
    let mut ids_b: Vec<&str> = node_b.dag().content_ids().into_iter().collect();
    ids_a.sort();
    ids_b.sort();
    assert_eq!(
        ids_a, ids_b,
        "CT-9: Content ID sets must be identical after convergence"
    );

    // Both .bean files should be byte-identical (C4/I7).
    let final_a = std::fs::read_to_string(&path_a).unwrap();
    let final_b = std::fs::read_to_string(&path_b).unwrap();
    assert_eq!(
        final_a, final_b,
        "CT-9: After convergence, .bean files must be byte-identical (C4/I7)"
    );

    // Trial balances should match.
    let date = make_date(2024, 12, 31);
    let tb_a = node_a.read_model().trial_balance(date);
    let tb_b = node_b.read_model().trial_balance(date);
    assert_eq!(tb_a.total_debit, tb_b.total_debit, "CT-9: Debits match");
    assert_eq!(tb_a.total_credit, tb_b.total_credit, "CT-9: Credits match");

    std::fs::remove_file(path_a).ok();
    std::fs::remove_file(path_b).ok();
}

#[test]
fn test_signature_is_on_disk_after_first_persist() {
    let (mut svc, path) = setup_with_accounts();
    let txid = svc
        .append_transaction_signing(balanced_input(), |_, _, _| Some("aa".repeat(64)))
        .unwrap()
        .txid;
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("openledger-signature:"),
        "signed append must persist signature on the first write"
    );
    assert!(svc.get_directive(&txid).is_some());
    std::fs::remove_file(path).ok();
}

#[test]
fn test_remote_insert_rejects_malformed_parent_id() {
    let (mut svc, path) = setup_with_accounts();
    let mut metadata = BTreeMap::new();
    metadata.insert("openledger-author".to_owned(), "peer-remote".to_owned());
    metadata.insert("openledger-lamport".to_owned(), "1".to_owned());
    metadata.insert("openledger-parents".to_owned(), "not-a-txid".to_owned());
    let remote = Directive::Transaction(Transaction {
        date: make_date(2024, 1, 16),
        flag: Flag::Complete,
        payee: None,
        narration: Some("bad parent".to_owned()),
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
    assert_eq!(error.error_code(), "INVALID_INPUT");
    std::fs::remove_file(path).ok();
}

#[test]
fn test_boot_rejects_oversized_ledger_file() {
    let path = test_file_path();
    {
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_LEDGER_FILE_BYTES + 1).unwrap();
    }
    let error = match LedgerService::boot(path.clone(), "test-peer".to_owned()) {
        Ok(_) => panic!("oversized ledger file should not boot"),
        Err(error) => error,
    };
    assert_eq!(error.error_code(), "RESOURCE_LIMIT_EXCEEDED");
    std::fs::remove_file(path).ok();
}

#[cfg(unix)]
#[test]
fn test_persisted_ledger_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let (mut svc, path) = setup_with_accounts();
    svc.append_transaction(balanced_input()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "persisted .bean must be 0600");
    std::fs::remove_file(path).ok();
}

#[cfg(unix)]
#[test]
fn test_persist_does_not_follow_tmp_symlink() {
    // L6 regression: a pre-planted `<name>.tmp` symlink must not be followed,
    // so a persist cannot truncate/overwrite the link's target.
    let ledger_path = test_file_path();
    let file_name = ledger_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let tmp_path = ledger_path.with_file_name(format!("{file_name}.tmp"));
    let victim_path = ledger_path.with_extension("victim");

    std::fs::write(&victim_path, "SENSITIVE").unwrap();
    std::os::unix::fs::symlink(&victim_path, &tmp_path).unwrap();

    persist_atomically(&ledger_path, "ledger contents\n").unwrap();

    assert_eq!(
        std::fs::read_to_string(&victim_path).unwrap(),
        "SENSITIVE",
        "persist must not write through a pre-planted .tmp symlink"
    );
    assert_eq!(
        std::fs::read_to_string(&ledger_path).unwrap(),
        "ledger contents\n"
    );

    std::fs::remove_file(&ledger_path).ok();
    std::fs::remove_file(&victim_path).ok();
    std::fs::remove_file(&tmp_path).ok();
}

/// L-44: the persist must never chmod anything but the file it wrote.
///
/// The old code renamed the temp into place and THEN ran
/// `std::fs::metadata(path)` + `std::fs::set_permissions(path, 0600)` —
/// both symlink-following. An attacker who can write the ledger directory
/// swaps a symlink in at `path` in that window and the node chmods the
/// link's target. The window is microseconds wide, so the test is the
/// attack itself: a thread atomically re-planting a symlink over the ledger
/// path as fast as it can while the node persists in a loop. Against the
/// old code the target's mode flips to 0600 within a handful of persists;
/// with the mode set through the handle before the rename, no persist can
/// name the target at all, however the race falls.
#[cfg(unix)]
#[test]
fn l44_persist_never_chmods_a_symlink_planted_at_the_ledger_path() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let directory = test_file_path().with_extension("l44");
    std::fs::create_dir_all(&directory).unwrap();
    let ledger_path = directory.join("ledger.bean");
    let target = directory.join("victim");
    std::fs::write(&target, "not the ledger\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let attacker = {
        let stop = Arc::clone(&stop);
        let ledger_path = ledger_path.clone();
        let target = target.clone();
        let staging = directory.join("staging-link");
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // symlink + rename: an atomic replace of whatever is at the
                // ledger path, exactly as a real attacker would do it.
                let _ = std::fs::remove_file(&staging);
                if std::os::unix::fs::symlink(&target, &staging).is_ok() {
                    let _ = std::fs::rename(&staging, &ledger_path);
                }
            }
        })
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
    let mut persists = 0u32;
    while std::time::Instant::now() < deadline {
        // The persist itself may fail or succeed depending on how the race
        // falls; what must never happen is the target's mode changing.
        let _ = persist_atomically(&ledger_path, "ledger contents\n");
        persists += 1;
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        if mode != 0o644 {
            stop.store(true, Ordering::Relaxed);
            attacker.join().unwrap();
            std::fs::remove_dir_all(&directory).ok();
            panic!(
                "L-44: persist #{persists} chmod'd the symlink's target to {mode:o}; \
                     the mode must be set through the handle, never by path"
            );
        }
    }
    stop.store(true, Ordering::Relaxed);
    attacker.join().unwrap();
    assert!(persists > 0);

    // And the ledger a persist leaves behind is still owner-only.
    let _ = std::fs::remove_file(&ledger_path);
    persist_atomically(&ledger_path, "ledger contents\n").unwrap();
    let mode = std::fs::symlink_metadata(&ledger_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the ledger itself must still be 0600");
    std::fs::remove_dir_all(&directory).ok();
}

// ── L-40: a dangling parent naming a predictable future txid ─────────

/// L-40: the local append of exactly the predicted transaction used to be
/// refused with `CYCLE_DETECTED` naming its own new txid — the append
/// picked every head as a parent, including the planted one, and the
/// planted one names the new txid as ITS parent: a genuine two-node cycle
/// the node built itself. And had it been admitted, the next boot's T47
/// pre-scan would have quarantined both.
#[test]
fn l40_a_dangling_parent_naming_a_future_txid_does_not_block_that_append() {
    let victim_id = predicted_txid(balanced_input());

    let (svc, path) = setup_with_accounts();
    drop(svc);
    append_to_file(&path, &planted_dangling_parent(&victim_id));
    let mut svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    // T84 / H-23: a parent that exists nowhere makes the planted entry a
    // record no peer could adopt, so boot holds it rather than serving it
    // as a head — the pointer never reaches the parent choice at all.
    assert_eq!(
        svc.quarantined_count(),
        1,
        "the planted entry is held, not served"
    );
    let planted_id = svc.quarantined_ids()[0].to_owned();

    let outcome = svc
        .append_transaction(balanced_input())
        .expect("L-40: the predicted append must not be refused as a cycle");
    assert_eq!(outcome.txid, victim_id);
    let parents = svc
        .get_directive(&victim_id)
        .unwrap()
        .metadata()
        .get("openledger-parents")
        .cloned()
        .unwrap_or_default();
    assert!(
        !parents.contains(&planted_id),
        "the new transaction must not name the entry that names it: {parents:?}"
    );

    // The file this leaves behind is acyclic: a reboot quarantines nothing
    // and holds both.
    svc.compact().unwrap();
    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.quarantined_count(), 0);
    assert!(rebooted.get_directive(&victim_id).is_some());
    assert!(rebooted.get_directive(&planted_id).is_some());
    remove_ledger_and_journal(&path);
}

/// L-40, the reconcile path: an operator's own envelope-less hand edit is
/// stamped with the current heads as parents in exactly the same way, so a
/// planted pointer at ITS id must not get it refused either.
#[test]
fn l40_a_dangling_parent_does_not_block_a_reconciled_hand_edit() {
    let victim_id = compute_content_id(
        &parse_file(HAND_EDITED_TRANSACTION)
            .unwrap()
            .into_iter()
            .next()
            .unwrap(),
    );

    let (mut svc, path) = setup_with_accounts();
    append_to_file(&path, &planted_dangling_parent(&victim_id));
    // T85 / H-23: the live path holds a complete envelope whose parent it
    // does not serve, as boot does since T84 — in the quarantine, kept in
    // the file — so the pointer never reaches the parent choice.
    let planted = svc.reconcile_file().unwrap();
    assert_eq!((planted.new_directives, svc.quarantined_count()), (0, 1));

    append_to_file(&path, HAND_EDITED_TRANSACTION);
    let result = svc.reconcile_file().unwrap();
    // The hand edit, and — its parent now resolving — the held entry.
    assert_eq!(
        (result.new_directives, result.rejected),
        (2, 0),
        "L-40: the hand edit must be adopted, not refused as a cycle"
    );
    assert!(svc.get_directive(&victim_id).is_some());
    assert_eq!(svc.quarantined_count(), 0);
    let victim_parents = svc
        .get_directive(&victim_id)
        .unwrap()
        .metadata()
        .get("openledger-parents")
        .cloned()
        .unwrap_or_default();
    let planted_id = svc
        .head_txids()
        .into_iter()
        .next()
        .expect("the planted entry is the head, naming the hand edit");
    assert!(
        !victim_parents.contains(&planted_id),
        "acyclic: the hand edit does not name the entry that names it"
    );

    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
    assert_eq!(rebooted.quarantined_count(), 0);
    assert_eq!(rebooted.directive_count(), svc.directive_count());
    remove_ledger_and_journal(&path);
}

// ── L-35: cheap id views for anti-entropy ────────────────────────────

/// The new views agree with `all_directive_ids()` exactly, and the sorted
/// snapshot is reused until the DAG grows — then rebuilt, never stale.
#[test]
fn l35_id_views_agree_with_all_directive_ids_and_track_growth() {
    let (mut svc, path) = setup_with_accounts();
    svc.append_transaction(balanced_input()).unwrap();

    let owned = svc.all_directive_ids();
    let first = svc.sorted_directive_ids();
    let mut expected: Vec<String> = owned.iter().cloned().collect();
    expected.sort();
    assert_eq!(&*first, expected.as_slice());
    for id in &owned {
        assert!(svc.contains_directive(id));
    }
    assert!(!svc.contains_directive(&"0".repeat(64)));
    for head in svc.head_txids() {
        assert!(svc.is_head(&head));
    }
    assert!(!svc.is_head(&"0".repeat(64)));

    assert!(
        std::sync::Arc::ptr_eq(&first, &svc.sorted_directive_ids()),
        "L-35: an unchanged DAG must be answered from the snapshot, not re-cloned"
    );

    svc.stage_remote_directive(remote_open("Assets:Later", make_date(2024, 3, 1), 40))
        .unwrap();
    let grown = svc.sorted_directive_ids();
    assert!(
        !std::sync::Arc::ptr_eq(&first, &grown),
        "growth must invalidate"
    );
    assert_eq!(grown.len(), first.len() + 1);
    let mut expected: Vec<String> = svc.all_directive_ids().into_iter().collect();
    expected.sort();
    assert_eq!(&*grown, expected.as_slice());
    remove_ledger_and_journal(&path);
}

/// An L-13 reload that SHRINKS the DAG back to disk must not be answered
/// from a snapshot of the larger, rolled-back set.
#[test]
fn l35_the_snapshot_does_not_survive_a_reload() {
    let (mut svc, path) = setup_with_accounts();
    svc.compact().unwrap();
    svc.stage_remote_directive(remote_open("Assets:Undurable", make_date(2024, 3, 1), 41))
        .unwrap();
    let before = svc.sorted_directive_ids();
    svc.recover_failed_commit();
    let after = svc.sorted_directive_ids();
    assert_eq!(after.len(), before.len() - 1);
    assert!(after.iter().all(|id| svc.contains_directive(id)));
    remove_ledger_and_journal(&path);
}
