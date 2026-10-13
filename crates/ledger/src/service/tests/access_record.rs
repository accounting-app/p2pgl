//! Access records (`crate::access_record`, docs/build-log/002-users-and-roles):
//! stored, indexed and persisted like any record; never typed in by hand.

use super::*;

/// A fresh `record` value per call, as the node draws one (the tests need
/// only distinct values).
fn nonce() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    format!(
        "{:032x}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

fn grant_fields(user: &str) -> Metadata {
    BTreeMap::from([
        ("record".to_owned(), nonce()),
        ("user".to_owned(), user.to_owned()),
        ("role".to_owned(), "write".to_owned()),
        ("key-sha256".to_owned(), "a".repeat(64)),
        ("by".to_owned(), "operator".to_owned()),
    ])
}

/// The node writes an access record like its own `open`: stamped, in the
/// DAG's access index (and nowhere else in it), durable across a restart — the
/// index rebuilt from the file at boot. A field with the `openledger-`
/// envelope prefix is refused before anything moves.
///
/// Bug-catch: skip the index on insert and the access list sees no record;
/// drop the envelope-key check and a field can forge an envelope key.
#[test]
fn an_access_record_is_written_indexed_and_survives_a_restart() {
    let (mut svc, path) = boot_empty();
    svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
        .expect("an ordinary record beside it");
    let clock = svc.lamport_clock;
    let mut forged = grant_fields("u_0000000000000001");
    forged.insert("openledger-author".to_owned(), "someone-else".to_owned());
    assert!(matches!(
        svc.record_access_event_staged(make_date(2024, 1, 2), "grant", forged, |_, _, _| None),
        Err(ServiceError::BodyEnvelopeKey { .. })
    ));
    assert_eq!(svc.lamport_clock, clock, "a refusal moves nothing");

    let id = svc
        .record_access_event_staged(
            make_date(2024, 1, 2),
            "grant",
            grant_fields("u_0000000000000001"),
            |_, _, _| None,
        )
        .expect("recorded");
    svc.persist_or_reload().expect("durable");
    let indexed: Vec<&str> = svc.dag().access_records().map(|(id, _)| id).collect();
    assert_eq!(
        indexed,
        vec![id.as_str()],
        "only the access record is indexed"
    );

    let svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).expect("reboot");
    let records: Vec<(&str, &Directive)> = svc.dag().access_records().collect();
    assert_eq!(records.len(), 1, "rebuilt from the file at boot");
    assert_eq!(records[0].0, id);
    let Directive::Event(event) = records[0].1 else {
        panic!("an event")
    };
    assert_eq!(event.description, "grant");
    assert_eq!(event.metadata["user"], "u_0000000000000001");
    assert!(event.metadata.contains_key(ENVELOPE_KEY_AUTHOR), "stamped");
    remove_ledger_and_journal(&path);
}

/// An access record typed into the ledger file by hand is refused — at boot
/// and under a running node — since it would grant access no admin granted;
/// one the node wrote itself (a full envelope) stays, as history.
///
/// Bug-catch: drop the refusal in `adopt_file_non_transaction` and a line
/// typed into the `.bean` grants itself access.
#[test]
fn a_hand_typed_access_record_is_refused_and_a_written_one_kept() {
    let (mut svc, path) = boot_empty();
    svc.record_access_event_staged(
        make_date(2024, 1, 2),
        "grant",
        grant_fields("u_0000000000000001"),
        |_, _, _| None,
    )
    .expect("recorded");
    svc.persist_or_reload().expect("durable");

    let typed = "\n2024-01-03 event \"openledger-access\" \"grant\"\n  record: \"ffffffffffffffffffffffffffffffff\"\n  user: \"u_00000000000000ff\"\n  role: \"admin\"\n  key-sha256: \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n  by: \"operator\"\n";
    append_to_file(&path, typed);
    let result = svc.reconcile_file().expect("reconciles");
    assert_eq!(result.new_directives, 0, "{result:?}");
    assert_eq!(
        svc.dag().access_records().count(),
        1,
        "live: only the written one"
    );

    append_to_file(&path, typed);
    let svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).expect("reboot");
    let users: Vec<String> = svc
        .dag()
        .access_records()
        .filter_map(|(_, directive)| directive.metadata().get("user").cloned())
        .collect();
    assert_eq!(
        users,
        vec!["u_0000000000000001".to_owned()],
        "boot: only the written one"
    );
    remove_ledger_and_journal(&path);
}

/// Every access record is unique (002, review I-1): it needs a fresh `record`
/// value, and one that would duplicate an existing record is refused — never
/// reported as written. So two revocations of one person on one day are two
/// records, and the second is not silently the first. Its strings are held to
/// the peer path's rules (no control characters, the metadata-key charset).
///
/// Bug-catch: return `Ok` on a duplicate and a repeated revoke silently does
/// nothing; drop the `record` requirement and same-day revokes collide.
#[test]
fn every_access_record_is_unique_and_a_duplicate_is_refused() {
    let (mut svc, path) = boot_empty();
    let date = make_date(2024, 1, 2);
    let revoke = |nonce: &str| {
        BTreeMap::from([
            ("record".to_owned(), nonce.to_owned()),
            ("user".to_owned(), "u_0000000000000001".to_owned()),
            ("by".to_owned(), "operator".to_owned()),
        ])
    };
    let mut without = revoke("x");
    without.remove("record");
    for (fields, why) in [
        (without, "no record"),
        (revoke("not-hex"), "a malformed record"),
    ] {
        assert!(
            matches!(
                svc.record_access_event_staged(date, "revoke", fields, |_, _, _| None),
                Err(ServiceError::InvalidInput { .. })
            ),
            "{why}"
        );
    }
    let mut control = revoke(&nonce());
    control.insert("note".to_owned(), "line\u{1b}[2J".to_owned());
    assert!(
        svc.record_access_event_staged(date, "revoke", control, |_, _, _| None)
            .is_err(),
        "a control character"
    );

    let (first, second) = (nonce(), nonce());
    svc.record_access_event_staged(date, "revoke", revoke(&first), |_, _, _| None)
        .expect("the first revoke");
    svc.record_access_event_staged(date, "revoke", revoke(&second), |_, _, _| None)
        .expect("a second revoke the same day is a record of its own");
    assert_eq!(svc.dag().access_records().count(), 2);
    assert!(
        matches!(
            svc.record_access_event_staged(date, "revoke", revoke(&first), |_, _, _| None),
            Err(ServiceError::InvalidInput { .. })
        ),
        "an exact duplicate is refused, not reported as written"
    );
    remove_ledger_and_journal(&path);
}

/// `entered-by` (step 4): a person's write carries their id in the body, so it
/// is stored, in the id and back after a restart; the same person entering
/// the same entry again is the same record, another person's is a second
/// one, and the operator's — no `entered-by` — is exactly the record it was
/// before people had keys. `open` and `close` carry it too. A blank or
/// control-character value is refused before anything moves.
///
/// Bug-catch: drop it from the open and the journal cannot say who opened an
/// account; drop the control-character check and a value that forges a
/// second metadata line reaches the file; drop the blank check and a write
/// is attributed to no one while claiming someone.
#[test]
fn a_persons_write_carries_entered_by_in_its_id() {
    use crate::access_record::ENTERED_BY;
    let (mut svc, path) = setup_with_accounts();
    let operator = svc
        .append_transaction_staged(balanced_input(), |_, _, _| None)
        .expect("the operator's write");
    let ana = svc
        .append_transaction_staged_by(balanced_input(), Some("u_000000000000000a"), |_, _, _| None)
        .expect("Ana's write");
    let again = svc
        .append_transaction_staged_by(balanced_input(), Some("u_000000000000000a"), |_, _, _| None)
        .expect("Ana again");
    let bea = svc
        .append_transaction_staged_by(balanced_input(), Some("u_000000000000000b"), |_, _, _| None)
        .expect("Bea's write");
    assert!(!ana.already_existed && again.already_existed && !bea.already_existed);
    assert_eq!(again.txid, ana.txid, "the same person, the same record");
    assert_ne!(ana.txid, operator.txid);
    assert_ne!(bea.txid, ana.txid, "another person, another record");
    let entered_by = |svc: &LedgerService, id: &str| {
        svc.get_directive(id)
            .and_then(|directive| directive.metadata().get(ENTERED_BY).cloned())
    };
    assert_eq!(entered_by(&svc, &operator.txid), None);
    assert_eq!(
        entered_by(&svc, &ana.txid).as_deref(),
        Some("u_000000000000000a")
    );
    let ana_record = svc.get_directive(&ana.txid).expect("stored").clone();
    assert_eq!(
        LedgerService::content_id(&ana_record),
        ana.txid,
        "it hashes to its id"
    );

    let opened = svc
        .open_account_staged_by(
            "Assets:Bank".to_owned(),
            make_date(2024, 1, 2),
            vec![],
            Some("u_000000000000000a"),
            |_, _, _| None,
        )
        .expect("opened");
    let closed = svc
        .close_account_staged_by(
            "Assets:Bank".to_owned(),
            make_date(2024, 1, 3),
            Some("u_000000000000000b"),
            |_, _, _| None,
        )
        .expect("closed");
    svc.persist_or_reload().expect("durable");

    let rebooted = LedgerService::boot(path, "test-peer".to_owned()).expect("reboot");
    for (id, who) in [
        (&ana.txid, Some("u_000000000000000a")),
        (&bea.txid, Some("u_000000000000000b")),
        (&operator.txid, None),
        (&opened, Some("u_000000000000000a")),
        (&closed, Some("u_000000000000000b")),
    ] {
        assert_eq!(entered_by(&rebooted, id).as_deref(), who, "{id}");
    }

    let clock = svc.lamport_clock;
    for bad in ["", "  ", "u_1\nforged: \"x\""] {
        assert!(
            matches!(
                svc.append_transaction_staged_by(balanced_input(), Some(bad), |_, _, _| None),
                Err(ServiceError::InvalidInput { .. })
            ),
            "{bad:?}"
        );
    }
    assert_eq!(svc.lamport_clock, clock, "a refusal moves nothing");
}

/// An entry typed into the ledger file with `entered-by` is refused (step 4
/// review I-2) — live and at boot — since this node would sign it as that
/// person's; a person's write through the API (a full envelope) round-trips
/// as history.
///
/// Bug-catch: let a typed `entered-by` through and the operator can put
/// anyone's name to an entry, signed by the node.
#[test]
fn a_hand_typed_entered_by_is_refused_and_a_written_one_kept() {
    use crate::access_record::ENTERED_BY;
    let (mut svc, path) = setup_with_accounts();
    let written = svc
        .append_transaction_staged_by(balanced_input(), Some("u_000000000000000a"), |_, _, _| None)
        .expect("Ana's write");
    svc.persist_or_reload().expect("durable");
    let before = svc.dag().len();

    let typed = "\n2024-01-20 * \"Typed\" \"Not by Ana\"\n  entered-by: \"u_000000000000000a\"\n  Assets:Cash  1 USD\n  Equity:Opening\n";
    append_to_file(&path, typed);
    let result = svc.reconcile_file().expect("reconciles");
    assert_eq!(result.new_directives, 0, "{result:?}");
    assert_eq!(svc.dag().len(), before, "live: refused");

    append_to_file(&path, typed);
    let rebooted = LedgerService::boot(path.clone(), "test-peer".to_owned()).expect("reboot");
    assert_eq!(rebooted.dag().len(), before, "boot: refused");
    assert_eq!(
        rebooted
            .get_directive(&written.txid)
            .and_then(|record| record.metadata().get(ENTERED_BY).cloned())
            .as_deref(),
        Some("u_000000000000000a"),
        "the written one stays"
    );
    remove_ledger_and_journal(&path);
}
