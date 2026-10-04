//! Format v2 (T45, `docs/FORMAT_V2_DESIGN.md`): identity v2 (Facet A — the
//! author in the content id, M-10) and signature v4 (Facet B — the
//! length-prefixed signed message, L-06), end to end through the real wire
//! validators (`validate_supply_entry`, `verify_remote_signature`) and the
//! ledger (`stage_remote_directive`, boot, the live reconcile).
//!
//! A node *writes* in the format its boot names (`boot_emitting`) and *accepts*
//! both, so a mesh flips one node at a time. Every test here is about one of
//! the design's obligations: the squatting regression in both directions, the
//! mixed-epoch window converging, history signed under v3 verifying forever,
//! the marker being tamper-evident, and the repairs the WARNs prescribe keeping
//! a record's identity across the epoch.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::NaiveDate;
use ledger::hash::{compute_content_id, RecordFormat, FORMAT_KEY, FORMAT_V2};
use ledger::model::{Amount, Directive, Flag};
use ledger::service::{
    DirectiveSigner, DirectiveVerifier, LedgerService, PostingInput, TransactionInput,
};
use p2p::gossip::make_supply_entry;
use p2p::union_merge::{
    signature_version, validate_supply_entry, verify_remote_signature, MergeError,
};
use rust_decimal::Decimal;
use security::signing::{PeerKeySignatureProvider, SignableMessage, SignatureProvider};

const MESH: &str = "format-v2-tests";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ol-format-v2-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir.join("ledger.bean")
}

fn key(seed: u8) -> Arc<PeerKeySignatureProvider> {
    Arc::new(PeerKeySignatureProvider::from_bytes(
        &[seed; 32],
        MESH.to_owned(),
    ))
}

/// The signer gl-node installs: the record says which message it is signed in.
fn signer(key: &Arc<PeerKeySignatureProvider>) -> DirectiveSigner {
    let key = Arc::clone(key);
    Arc::new(
        move |content_id: &str,
              is_transaction: bool,
              parents: &str,
              lamport: &str,
              format: RecordFormat| {
            key.sign_in(
                signature_version(format),
                &SignableMessage {
                    content_id,
                    is_transaction,
                    parents,
                    lamport,
                },
            )
        },
    )
}

/// The verifier gl-node installs: the wire's check, in the record's format.
fn verifier() -> DirectiveVerifier {
    Arc::new(
        move |content_id: &str,
              is_transaction: bool,
              parents: &str,
              lamport: &str,
              author: &str,
              signature: &str,
              format: RecordFormat| {
            security::signing::verify_signature_in(
                signature_version(format),
                &SignableMessage {
                    content_id,
                    is_transaction,
                    parents,
                    lamport,
                },
                signature,
                author,
                MESH,
            )
            .is_ok()
        },
    )
}

/// A node at `path` writing `format`, booted in gl-node's order: signer,
/// verifier, finalisation, the history check.
fn node_at(
    path: &std::path::Path,
    key: &Arc<PeerKeySignatureProvider>,
    format: RecordFormat,
) -> LedgerService {
    let mut node = LedgerService::boot_emitting(path, key.public_key_hex(), format).expect("boot");
    node.set_signer(signer(key));
    node.set_verifier(verifier());
    node.finalize_operator_input();
    node.verify_own_history();
    node
}

fn date(day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(2024, 1, day).expect("date")
}

/// The API's per-call sign closure: this node's writes are in its own format.
fn api_sign(
    key: &Arc<PeerKeySignatureProvider>,
    format: RecordFormat,
    is_transaction: bool,
) -> impl FnOnce(&str, &str, &str) -> Option<String> {
    let key = Arc::clone(key);
    move |content_id, parents, lamport| {
        key.sign_in(
            signature_version(format),
            &SignableMessage {
                content_id,
                is_transaction,
                parents,
                lamport,
            },
        )
    }
}

fn open(node: &mut LedgerService, key: &Arc<PeerKeySignatureProvider>, account: &str) -> String {
    let format = node.emit_format();
    node.open_account_signing(
        account.to_owned(),
        date(1),
        vec![],
        api_sign(key, format, false),
    )
    .expect("open")
}

fn transfer(narration: &str, amount: i64) -> TransactionInput {
    TransactionInput {
        date: date(5),
        flag: Flag::Complete,
        payee: None,
        narration: Some(narration.to_owned()),
        tags: vec![],
        links: vec![],
        postings: ["Assets:Cash", "Equity:Opening"]
            .into_iter()
            .zip([amount, -amount])
            .map(|(account, number)| PostingInput {
                account: account.to_owned(),
                amount: Some(Amount {
                    number: Decimal::from(number),
                    currency: "USD".to_owned(),
                }),
                cost: None,
                price: None,
            })
            .collect(),
    }
}

fn append(
    node: &mut LedgerService,
    key: &Arc<PeerKeySignatureProvider>,
    narration: &str,
    amount: i64,
) -> String {
    let format = node.emit_format();
    node.append_transaction_signing(transfer(narration, amount), api_sign(key, format, true))
        .expect("append")
        .txid
}

/// Everything `from` serves, offered to `to` through the wire's validators,
/// until a pass stages nothing. Returns how many were staged.
fn deliver(from: &LedgerService, to: &mut LedgerService) -> usize {
    let served: Vec<Directive> = from.dag().directives().into_iter().cloned().collect();
    let mut staged = 0;
    loop {
        let before = staged;
        for directive in &served {
            let entry = make_supply_entry(directive);
            if to.contains_directive(&entry.id) {
                continue;
            }
            let arrived = validate_supply_entry(&entry).expect("a served record validates");
            verify_remote_signature(&arrived, true, MESH).expect("and its signature verifies");
            if matches!(to.stage_remote_directive(arrived), Ok(Some(_))) {
                staged += 1;
            }
        }
        if staged == before {
            return staged;
        }
    }
}

fn author_of(node: &LedgerService, id: &str) -> Option<String> {
    node.get_directive(id)?
        .metadata()
        .get("openledger-author")
        .cloned()
}

fn cash(node: &LedgerService) -> String {
    node.read_model()
        .account_balance("Assets:Cash", None)
        .map(|balance| balance.balances["USD"].to_string())
        .unwrap_or_default()
}

/// A v2 node's writes carry the marker; their ids cover the author; they are
/// signed in v4 and pass the wire's validators on a v1 node, which accepts
/// both formats. Stripping the marker from a served record changes the id it
/// hashes to — the wire refuses it as a content-hash mismatch.
///
/// Bug-catch: hash a v2 record without its author, or check the wire id
/// before the envelope, or verify v4 as v3, and a v2 record does not cross.
#[test]
fn a_v2_record_carries_the_marker_and_crosses_to_a_v1_node() {
    let (a, b) = (key(1), key(2));
    let mut v2 = node_at(&scratch("cross-a"), &a, RecordFormat::V2);
    let mut v1 = node_at(&scratch("cross-b"), &b, RecordFormat::V1);
    for account in ["Assets:Cash", "Equity:Opening"] {
        open(&mut v2, &a, account);
    }
    let id = append(&mut v2, &a, "v2 write", 5);
    let record = v2.get_directive(&id).expect("held").clone();
    assert!(
        v2.dag()
            .directives()
            .into_iter()
            .all(|directive| RecordFormat::of(directive) == RecordFormat::V2),
        "the API's opens and the transaction are all v2"
    );
    assert_eq!(compute_content_id(&record), id);
    assert_eq!(deliver(&v2, &mut v1), 3, "both opens and the transaction");
    assert!(v1.contains_directive(&id));
    assert_eq!(cash(&v1), "5");

    let mut stripped = make_supply_entry(&record);
    stripped.envelope.remove(FORMAT_KEY);
    assert!(matches!(
        validate_supply_entry(&stripped),
        Err(MergeError::ContentHashMismatch { .. })
    ));
}

/// M-10, the squatting regression, pinned in both directions. H writes a
/// transaction; M — allowlisted — takes H's body, puts its own envelope and
/// signature on it, and reaches V first. At v1 the id is the body's, so V
/// holds M's copy under it and H's own copy is a duplicate: H's authorship is
/// gone on V. At v2 the id covers the author, so M's copy is M's own record
/// and H's arrives intact under H's id, authored by H.
///
/// Bug-catch: leave the author out of the v2 id and the v2 arm is squatted
/// exactly as the v1 arm.
#[test]
fn squatting_is_effective_at_v1_and_ineffective_at_v2() {
    for format in [RecordFormat::V1, RecordFormat::V2] {
        let (h, m, v) = (key(10), key(11), key(12));
        let mut honest = node_at(&scratch("squat-h"), &h, format);
        let mut victim = node_at(&scratch("squat-v"), &v, format);
        for account in ["Assets:Cash", "Equity:Opening"] {
            open(&mut honest, &h, account);
        }
        deliver(&honest, &mut victim);
        let id = append(&mut honest, &h, "H's deposit", 7);
        let original = honest.get_directive(&id).expect("held").clone();

        // M's copy: H's body, M's envelope, M's signature.
        let Directive::Transaction(mut txn) = original.clone() else {
            unreachable!()
        };
        txn.metadata
            .insert("openledger-author".to_owned(), m.public_key_hex());
        txn.metadata
            .insert("openledger-lamport".to_owned(), "900".to_owned());
        txn.metadata.remove("openledger-signature");
        let parents = txn
            .metadata
            .get("openledger-parents")
            .cloned()
            .unwrap_or_default();
        let squat_id = compute_content_id(&Directive::Transaction(txn.clone()));
        let signature = m
            .sign_in(
                signature_version(format),
                &SignableMessage {
                    content_id: &squat_id,
                    is_transaction: true,
                    parents: &parents,
                    lamport: "900",
                },
            )
            .expect("signed");
        txn.metadata
            .insert("openledger-signature".to_owned(), signature);
        let squat = Directive::Transaction(txn);
        let arrived = validate_supply_entry(&make_supply_entry(&squat)).expect("valid");
        verify_remote_signature(&arrived, true, MESH).expect("M's own signature");
        victim.stage_remote_directive(arrived).expect("staged");
        deliver(&honest, &mut victim);

        let held_author = author_of(&victim, &id);
        match format {
            RecordFormat::V1 => {
                assert_eq!(squat_id, id, "v1: one body, one id");
                assert_eq!(
                    held_author,
                    Some(m.public_key_hex()),
                    "v1: V holds M's envelope under H's record's id — the squat works"
                );
            }
            RecordFormat::V2 => {
                assert_ne!(squat_id, id, "v2: M's copy is M's record");
                assert_eq!(
                    held_author,
                    Some(h.public_key_hex()),
                    "v2: H's record reaches V under H's id, authored by H"
                );
                assert!(victim.contains_directive(&squat_id));
            }
        }
    }
}

/// History signed under v3 verifies forever: a node that wrote v1 records
/// and restarts writing v2 holds none of them back. The boot signer's own
/// pass re-derives each record's signature in the record's format — signing
/// them as v4 would make every one look edited (H-20) and quarantine the
/// node's history at the first v2 boot. Its next write is v2.
///
/// Bug-catch: hand the signer or the verifier the node's format instead of
/// the record's, and the v1 history is quarantined.
#[test]
fn a_node_that_flips_to_v2_still_verifies_its_v1_history() {
    let a = key(20);
    let path = scratch("flip");
    let mut node = node_at(&path, &a, RecordFormat::V1);
    for account in ["Assets:Cash", "Equity:Opening"] {
        open(&mut node, &a, account);
    }
    let old = append(&mut node, &a, "before the flip", 3);
    node.compact().expect("compact");
    drop(node);

    let mut node = node_at(&path, &a, RecordFormat::V2);
    assert!(
        node.quarantined_ids().is_empty(),
        "v1 history stays served: {:?}",
        node.quarantined_ids()
    );
    assert!(node.contains_directive(&old));
    let new = append(&mut node, &a, "after the flip", 4);
    assert_eq!(
        RecordFormat::of(node.get_directive(&new).expect("held")),
        RecordFormat::V2
    );
    node.compact().expect("compact");
    drop(node);
    let node = node_at(&path, &a, RecordFormat::V2);
    assert!(node.quarantined_ids().is_empty());
    assert_eq!(cash(&node), "7");
}

/// The mixed window: a v2 node and a v1 node each write, exchange both ways,
/// and hold the same records and balances — and the same again after each
/// restarts on its compacted file.
///
/// Bug-catch: refuse the marker on the wire, or recompute a v2 record's id
/// without its envelope on boot, and the two never converge.
#[test]
fn a_mixed_epoch_mesh_converges_and_survives_a_restart() {
    let (a, b) = (key(30), key(31));
    let (path_a, path_b) = (scratch("mixed-a"), scratch("mixed-b"));
    let mut v2 = node_at(&path_a, &a, RecordFormat::V2);
    let mut v1 = node_at(&path_b, &b, RecordFormat::V1);
    for account in ["Assets:Cash", "Equity:Opening"] {
        open(&mut v2, &a, account);
    }
    deliver(&v2, &mut v1);
    append(&mut v2, &a, "v2's", 5);
    append(&mut v1, &b, "v1's", 6);
    for _ in 0..2 {
        deliver(&v2, &mut v1);
        deliver(&v1, &mut v2);
    }
    let ids = |node: &LedgerService| {
        let mut ids: Vec<String> = node.all_directive_ids().into_iter().collect();
        ids.sort();
        ids
    };
    assert_eq!(ids(&v2), ids(&v1));
    assert_eq!((cash(&v2), cash(&v1)), ("11".to_owned(), "11".to_owned()));
    v2.compact().expect("compact");
    v1.compact().expect("compact");
    let before = ids(&v2);
    drop((v2, v1));
    let v2 = node_at(&path_a, &a, RecordFormat::V2);
    let v1 = node_at(&path_b, &b, RecordFormat::V1);
    assert_eq!((ids(&v2), ids(&v1)), (before.clone(), before));
    assert!(v2.quarantined_ids().is_empty() && v1.quarantined_ids().is_empty());
}

/// A typed line keeps v1 identity on a node writing v2. A v1 record of this
/// node's whose lamport line was edited is held at boot (its signature no
/// longer verifies, H-20); the remedy is to delete its `openledger-*` lines so
/// it is re-adopted under the same id. The stripped line is then the record's
/// only copy — nothing tells it from a new line — so were typed lines written
/// in v2 it would come back under a new id, a second record of the same
/// deposit beside the one every peer holds.
///
/// Bug-catch: stamp operator input with the node's format and the
/// re-adopted record is a new v2 id.
#[test]
fn a_repaired_line_keeps_its_id_on_a_v2_node() {
    let a = key(40);
    let path = scratch("epoch");
    let mut node = node_at(&path, &a, RecordFormat::V1);
    for account in ["Assets:Cash", "Equity:Opening"] {
        open(&mut node, &a, account);
    }
    let original = append(&mut node, &a, "the deposit", 9);
    node.compact().expect("compact");
    drop(node);
    let text = std::fs::read_to_string(&path).expect("read");
    let edited = text.replacen("openledger-lamport: \"3\"", "openledger-lamport: \"4\"", 1);
    assert_ne!(edited, text, "premise: the deposit's lamport is 3");
    std::fs::write(&path, &edited).expect("write");
    let node = node_at(&path, &a, RecordFormat::V2);
    assert!(
        node.quarantined_ids().contains(&original.as_str()),
        "premise: the edited record is held (H-20)"
    );
    drop(node);

    // The remedy: delete the held record's openledger-* lines.
    let mut repaired = String::new();
    let mut in_deposit = false;
    for line in edited.lines() {
        if line.contains("\"the deposit\"") {
            in_deposit = true;
        } else if line.trim().is_empty() {
            in_deposit = false;
        }
        if in_deposit && line.trim_start().starts_with("openledger-") {
            continue;
        }
        repaired.push_str(line);
        repaired.push('\n');
    }
    std::fs::write(&path, repaired).expect("write");
    let node = node_at(&path, &a, RecordFormat::V2);
    assert!(
        node.contains_directive(&original),
        "re-adopted under its own id: {:?}",
        node.quarantined_ids()
    );
    assert_eq!(
        RecordFormat::of(node.get_directive(&original).expect("held")),
        RecordFormat::V1
    );
    assert_eq!(cash(&node), "9", "one deposit");
}

/// The marker has one value, and a v2 record names its author: anything else
/// is refused on the wire and held at boot, so no record sits in a format
/// that is neither.
#[test]
fn a_marker_other_than_2_or_without_an_author_is_refused() {
    let a = key(50);
    let mut node = node_at(&scratch("marker"), &a, RecordFormat::V2);
    for account in ["Assets:Cash", "Equity:Opening"] {
        open(&mut node, &a, account);
    }
    let id = append(&mut node, &a, "marked", 2);
    let record = node.get_directive(&id).expect("held");
    let mut wrong = make_supply_entry(record);
    wrong.envelope.insert(FORMAT_KEY.to_owned(), "3".to_owned());
    assert!(matches!(
        validate_supply_entry(&wrong),
        Err(MergeError::InvalidEnvelope(_))
    ));
    let mut anonymous = make_supply_entry(record);
    anonymous.envelope.remove("openledger-author");
    assert!(matches!(
        validate_supply_entry(&anonymous),
        Err(MergeError::InvalidEnvelope(_))
    ));
    assert_eq!(FORMAT_V2, "2");

    // The file path holds the same rule: a marker edited to "3" is held at
    // boot, kept in the file, not served.
    let path = scratch("marker-file");
    let mut node = node_at(&path, &a, RecordFormat::V2);
    for account in ["Assets:Cash", "Equity:Opening"] {
        open(&mut node, &a, account);
    }
    let id = append(&mut node, &a, "to be edited", 2);
    node.compact().expect("compact");
    drop(node);
    let text = std::fs::read_to_string(&path).expect("read");
    let edited = text.replace("openledger-format: \"2\"", "openledger-format: \"3\"");
    assert_ne!(edited, text);
    std::fs::write(&path, edited).expect("write");
    let node = node_at(&path, &a, RecordFormat::V2);
    assert!(!node.contains_directive(&id));
    assert_eq!(
        node.directive_count(),
        0,
        "every record carried the edited marker"
    );
    assert!(std::fs::read_to_string(&path)
        .expect("read")
        .contains("to be edited"));
}

/// On a node writing v2 only its API writes are v2: a new line typed into the
/// `.bean` is adopted as v1 (signed v3), and a line that spells the marker
/// itself (with its author) stays v2 (signed v4) — both verify after a
/// restart and cross the wire.
#[test]
fn typed_lines_are_v1_unless_they_spell_the_marker() {
    let a = key(60);
    let path = scratch("typed");
    let author = a.public_key_hex();
    std::fs::write(
        &path,
        format!(
            "2024-01-01 open Assets:Cash\n\n2024-01-01 open Equity:Opening\n  \
             openledger-author: \"{author}\"\n  openledger-format: \"2\"\n"
        ),
    )
    .expect("write");
    let node = node_at(&path, &a, RecordFormat::V2);
    let formats: Vec<(String, RecordFormat)> = node
        .dag()
        .directives()
        .into_iter()
        .map(|directive| match directive {
            Directive::Open(open) => (open.account.clone(), RecordFormat::of(directive)),
            _ => unreachable!(),
        })
        .collect();
    assert!(formats.contains(&("Assets:Cash".to_owned(), RecordFormat::V1)));
    assert!(formats.contains(&("Equity:Opening".to_owned(), RecordFormat::V2)));
    let mut peer = node_at(&scratch("typed-peer"), &key(61), RecordFormat::V1);
    assert_eq!(deliver(&node, &mut peer), 2);
}

/// On a node with signing off there is no signature to break, so the file
/// path's own marker check is what holds a record whose marker is not "2":
/// served, it would be refused by every peer (the wire refuses it too).
///
/// Bug-catch: drop `validate_envelope_format_form` from the file path and the
/// record is served.
#[test]
fn an_unsigned_node_holds_a_record_whose_marker_is_not_2() {
    let path = scratch("marker-unsigned");
    std::fs::write(
        &path,
        "2024-01-01 open Assets:Cash\n  openledger-author: \"peer-x\"\n  \
         openledger-format: \"3\"\n  openledger-lamport: \"5\"\n",
    )
    .expect("write");
    let node =
        LedgerService::boot_emitting(&path, "local".to_owned(), RecordFormat::V2).expect("boot");
    assert_eq!(node.directive_count(), 0, "not served");
    assert_eq!(node.quarantined_count(), 1, "held, in the file");
}

/// Every ordering of `0..n`.
fn permutations(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![Vec::new()];
    }
    let mut all = Vec::new();
    for shorter in permutations(n - 1) {
        for slot in 0..=shorter.len() {
            let mut order = shorter.clone();
            order.insert(slot, n - 1);
            all.push(order);
        }
    }
    all
}

/// The epoch matrix's ordering half (T29's property, mixed epoch): a set of
/// records in both formats — v2 opens and a v2 transaction by A, a v1
/// transaction by B, and B's v1 copy of the very body A wrote in v2 — reaches
/// a fresh replica in every one of its 120 arrival orders, and every replica
/// ends with the same records and, once compacted, a byte-identical `.bean`.
///
/// Bug-catch: compute an arriving record's id without its envelope, or let a
/// v1 copy of a v2 body collapse into it, and the sets or the bytes differ by
/// order.
#[test]
fn a_mixed_epoch_set_converges_in_every_arrival_order() {
    let (a, b) = (key(80), key(81));
    let mut writer_a = node_at(&scratch("perm-a"), &a, RecordFormat::V2);
    let mut writer_b = node_at(&scratch("perm-b"), &b, RecordFormat::V1);
    for account in ["Assets:Cash", "Equity:Opening"] {
        open(&mut writer_a, &a, account);
    }
    deliver(&writer_a, &mut writer_b);
    append(&mut writer_a, &a, "shared body", 4);
    append(&mut writer_b, &b, "shared body", 4);
    append(&mut writer_b, &b, "b alone", 6);
    deliver(&writer_b, &mut writer_a);
    let records: Vec<Directive> = writer_a.dag().directives().into_iter().cloned().collect();
    assert_eq!(
        records.len(),
        5,
        "two opens, A's v2 copy, B's v1 copy, B's own"
    );
    let orders = permutations(records.len());
    assert_eq!(orders.len(), 120);
    let mut outcome: Option<(Vec<String>, String)> = None;
    for order in &orders {
        let path = scratch("perm-replica");
        let mut replica = node_at(&path, &key(82), RecordFormat::V1);
        let mut pending: Vec<&Directive> = order.iter().map(|index| &records[*index]).collect();
        while !pending.is_empty() {
            let before = pending.len();
            pending.retain(|directive| {
                let arrived = validate_supply_entry(&make_supply_entry(directive)).expect("valid");
                verify_remote_signature(&arrived, true, MESH).expect("verifies");
                !matches!(replica.stage_remote_directive(arrived), Ok(Some(_)))
            });
            assert!(pending.len() < before, "order {order:?} stalled");
        }
        replica.compact().expect("compact");
        let mut ids: Vec<String> = replica.all_directive_ids().into_iter().collect();
        ids.sort();
        let bytes = std::fs::read_to_string(&path).expect("read");
        match &outcome {
            None => outcome = Some((ids, bytes)),
            Some((first_ids, first_bytes)) => {
                assert_eq!(&ids, first_ids, "order {order:?}");
                assert_eq!(&bytes, first_bytes, "order {order:?}");
            }
        }
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
    assert_eq!(
        cash(&writer_a),
        "14",
        "both copies of the shared body count"
    );
}

/// Same-author identical bodies still collapse within v2: an API retry of
/// the same body is the same record (T33's `already_existed`).
#[test]
fn a_same_author_retry_still_dedupes_within_v2() {
    let a = key(70);
    let mut node = node_at(&scratch("retry"), &a, RecordFormat::V2);
    for account in ["Assets:Cash", "Equity:Opening"] {
        open(&mut node, &a, account);
    }
    let first = node
        .append_transaction_signing(transfer("retry", 1), api_sign(&a, RecordFormat::V2, true))
        .expect("first");
    let second = node
        .append_transaction_signing(transfer("retry", 1), api_sign(&a, RecordFormat::V2, true))
        .expect("second");
    assert!(!first.already_existed && second.already_existed);
    assert_eq!(first.txid, second.txid);
}
